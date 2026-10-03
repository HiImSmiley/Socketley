#include "notifier.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/byte_codec.h"
#include "../../shared/logging.h"
#include "../../shared/mutation_journal.h"

namespace socketley::storage
{

namespace
{

// The outbox is rewritten empty once everything in it is delivered and it has grown past this.
constexpr uint64_t rotate_bytes = 1u << 20;
// The most of a webhook's answer that is read, which is only ever its status line and headers.
constexpr size_t response_cap = 64 * 1024;
constexpr uint32_t read_bytes = 16 * 1024;
constexpr size_t record_cap = 8u << 20;
constexpr long tick_ns = 250'000'000;

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

// `http://host[:port][/path]` or `https://...`, a host in brackets for IPv6; false with `why` for anything else.
bool parse_url(std::string_view url, notify_target& t, std::string& why)
{
    std::string_view rest;
    if (url.starts_with("http://"))
        rest = url.substr(7);
    else if (url.starts_with("https://"))
    {
        rest  = url.substr(8);
        t.tls = true;
    }
    else
    {
        why = "a webhook URL starts with http:// or https://";
        return false;
    }
    const size_t slash = rest.find('/');
    std::string_view authority = rest.substr(0, slash);
    t.path = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
    t.port = t.tls ? 443 : 80;
    std::string_view port;
    if (authority.starts_with("["))
    {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos)
        {
            why = "an IPv6 host is closed with ]";
            return false;
        }
        t.host = std::string(authority.substr(1, close - 1));
        if (close + 1 < authority.size())
        {
            if (authority[close + 1] != ':')
            {
                why = "a port follows the host after a colon";
                return false;
            }
            port = authority.substr(close + 2);
        }
    }
    else
    {
        const size_t colon = authority.rfind(':');
        t.host = std::string(authority.substr(0, colon));
        if (colon != std::string_view::npos)
            port = authority.substr(colon + 1);
    }
    if (t.host.empty() || t.host.find('@') != std::string::npos)
    {
        why = "a webhook URL names a host, and no credentials before it";
        return false;
    }
    if (authority.find_first_of(" \t") != std::string_view::npos || t.path.find_first_of(" \t\r\n") != std::string::npos)
    {
        why = "a webhook URL has no spaces";
        return false;
    }
    if (!port.empty() || (slash != std::string_view::npos && authority.ends_with(":")))
    {
        uint32_t p = 0;
        const auto r = std::from_chars(port.data(), port.data() + port.size(), p);
        if (port.empty() || r.ec != std::errc{} || r.ptr != port.data() + port.size() || p == 0 || p > 65535)
        {
            why = "the port is a number from 1 to 65535";
            return false;
        }
        t.port = static_cast<uint16_t>(p);
    }
    return true;
}

}   // namespace

bool parse_notify_targets(std::string_view text, std::vector<notify_target>& out, std::string& why)
{
    out.clear();
    size_t line_no = 0;
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        ++line_no;
        if (const size_t hash = line.find('#'); hash != std::string_view::npos)
            line = line.substr(0, hash);
        line = trim(line);
        if (line.empty())
            continue;
        std::vector<std::string_view> fields;
        while (!line.empty())
        {
            const size_t sp = line.find_first_of(" \t");
            fields.push_back(line.substr(0, sp));
            line = sp == std::string_view::npos ? std::string_view{} : trim(line.substr(sp));
        }
        const std::string where = "line " + std::to_string(line_no) + ": ";
        if (fields.size() < 2 || fields.size() > 3 || (fields.size() == 3 && !fields[2].starts_with("ca=")))
        {
            why = where + "a target is `name url [ca=file]`";
            return false;
        }
        notify_target t;
        t.name = std::string(fields[0]);
        t.url  = std::string(fields[1]);
        if (fields.size() == 3)
            t.ca_file = std::string(fields[2].substr(3));
        for (const char ch : t.name)
            if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_' || ch == '.'))
            {
                why = where + "a target's name is letters, digits, '-', '_' and '.'";
                return false;
            }
        if (std::string err; !parse_url(t.url, t, err))
        {
            why = where + err;
            return false;
        }
        if (!t.ca_file.empty() && !t.tls)
        {
            why = where + "ca= is for an https target";
            return false;
        }
        for (const notify_target& o : out)
            if (o.name == t.name)
            {
                why = where + "the target " + t.name + " is named twice";
                return false;
            }
        out.push_back(std::move(t));
    }
    return true;
}

bool load_notify_targets(const std::string& path, std::vector<notify_target>& out, std::string& why)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        why = "cannot read the notification targets file " + path + ": " + std::strerror(errno);
        return false;
    }
    std::string text;
    char buf[4096];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || text.size() > (1u << 20))
            break;
        text.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    if (!parse_notify_targets(text, out, why))
    {
        why = path + ": " + why;
        return false;
    }
    return true;
}

namespace
{

// `host` as an address literal, false when it is a name.
bool literal_endpoint(const std::string& host, uint16_t port, notify_endpoint& out)
{
    out = notify_endpoint{};
    auto* v4 = reinterpret_cast<struct sockaddr_in*>(&out.addr);
    if (::inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1)
    {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(port);
        out.len        = sizeof(struct sockaddr_in);
        return true;
    }
    auto* v6 = reinterpret_cast<struct sockaddr_in6*>(&out.addr);
    if (::inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) == 1)
    {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
        out.len         = sizeof(struct sockaddr_in6);
        return true;
    }
    return false;
}

}   // namespace

std::vector<notify_endpoint> resolve_notify_host(const std::string& host, uint16_t port, const std::string& hosts_file)
{
    std::vector<notify_endpoint> out;
    if (!hosts_file.empty())
    {
        std::string text;
        if (const int fd = ::open(hosts_file.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0)
        {
            char buf[4096];
            ssize_t n;
            while ((n = ::read(fd, buf, sizeof(buf))) > 0 && text.size() < (1u << 20))
                text.append(buf, static_cast<size_t>(n));
            ::close(fd);
        }
        std::string_view rest = text;
        while (!rest.empty())
        {
            const size_t nl = rest.find('\n');
            std::string_view line = trim(rest.substr(0, nl));
            rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
            const size_t sp = line.find_first_of(" \t");
            if (sp == std::string_view::npos || line.substr(0, sp) != host)
                continue;
            notify_endpoint e;
            if (literal_endpoint(std::string(trim(line.substr(sp))), port, e))
                out.push_back(e);
        }
        if (!out.empty())
            return out;
    }
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const std::string p = std::to_string(port);
    if (::getaddrinfo(host.c_str(), p.c_str(), &hints, &res) != 0 || !res)
        return out;
    for (const struct addrinfo* a = res; a; a = a->ai_next)
    {
        notify_endpoint e;
        e.len = static_cast<socklen_t>(std::min<size_t>(a->ai_addrlen, sizeof(e.addr)));
        std::memcpy(&e.addr, a->ai_addr, e.len);
        out.push_back(e);
    }
    ::freeaddrinfo(res);
    return out;
}

// ─── The notifier ───────────────────────────────────────────────────────────

notifier::notifier(event_loop& loop, file_io& io, io_handler* owner) : m_loop(loop), m_io(io), m_owner(owner)
{
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_NOTIFY_QUEUE"))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && v > 0)
            m_queue_max = static_cast<size_t>(v);
    }
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_NOTIFY_HOSTS"))
        m_hosts_file = e;
}

notifier::~notifier()
{
    *m_alive = false;
    for (auto& l : m_lanes)
        if (l->ssl)
            tls_context::free_ssl(l->ssl);
}

void notifier::set_targets(std::vector<notify_target> targets)
{
    m_lanes.clear();
    for (notify_target& t : targets)
    {
        auto l = std::make_unique<lane>();
        if (t.tls)
        {
            l->tls = std::make_unique<tls_context>();
            if (!l->tls->init_client(t.ca_file))
            {
                LOG_ERROR(("storage: the notification target " + t.name +
                           " has no TLS context, so its events are not delivered").c_str());
                l->tls.reset();
            }
        }
        notify_endpoint e;
        l->literal = literal_endpoint(t.host, t.port, e);
        if (l->literal)
            l->addrs.push_back(e);
        l->target = std::move(t);
        m_lanes.push_back(std::move(l));
    }
    bool names = false;
    for (const auto& l : m_lanes)
        names = names || !l->literal;
    if (names && !m_resolver.attach(m_io))
        LOG_ERROR("storage: the notification resolver cannot be waited for, so webhooks named by a host are not delivered to");
    // Every name is asked for now, so the first event does not wait for its answer.
    for (auto& l : m_lanes)
        if (!l->literal && !resolve(*l)) {}
}

bool notifier::resolve(lane& l)
{
    const auto now = std::chrono::steady_clock::now();
    if (l.literal || m_stopped || !m_resolver.enabled())
        return false;
    if (l.resolving)
        return true;
    if (l.resolved_at != std::chrono::steady_clock::time_point{} &&
        now - l.resolved_at < std::chrono::milliseconds(resolve_floor_ms))
        return false;
    l.resolving = true;
    auto out = std::make_shared<std::vector<notify_endpoint>>();
    auto alive = m_alive;
    lane* lp = &l;
    m_resolver.submit(0,
        [out, host = l.target.host, port = l.target.port, hosts = m_hosts_file]()
        { *out = resolve_notify_host(host, port, hosts); },
        [this, alive, lp, out]()
        {
            if (*alive)
                resolved(*lp, std::move(*out));
        });
    return true;
}

void notifier::resolved(lane& l, std::vector<notify_endpoint> addrs)
{
    l.resolving   = false;
    l.resolved_at = std::chrono::steady_clock::now();
    ++m_c.resolves;
    if (m_stopped)
        return;
    if (addrs.empty())
    {
        LOG_WARN(("storage: the notification target " + l.target.name + " names host " + l.target.host +
                  ", which does not resolve; its events wait and it is asked again").c_str());
        // A host known before keeps its addresses, since a resolver that does not answer says nothing about them.
        if (l.addrs.empty() && !l.q.empty() && !l.busy)
            back_off(l);
        return;
    }
    l.addrs = std::move(addrs);
    l.cur   = 0;
    if (!l.busy && !l.q.empty())
        start(l);
}

bool notifier::has_target(std::string_view name) const
{
    for (const auto& l : m_lanes)
        if (l->target.name == name)
            return true;
    return false;
}

notifier::lane* notifier::find_lane(std::string_view name)
{
    for (auto& l : m_lanes)
        if (l->target.name == name)
            return l.get();
    return nullptr;
}

// ─── The outbox ─────────────────────────────────────────────────────────────

bool notifier::open(const std::string& dir, uint32_t shard, std::string& err)
{
    if (m_lanes.empty())
        return true;
    const std::string nd = dir + "/.notify";
    if (::mkdir(nd.c_str(), 0755) < 0 && errno != EEXIST)
    {
        err = "cannot create " + nd + ": " + std::strerror(errno);
        return false;
    }
    m_dir_fd = ::open(nd.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (m_dir_fd < 0)
    {
        err = "cannot open " + nd + ": " + std::strerror(errno);
        return false;
    }
    m_name = "outbox." + std::to_string(shard);

    std::string text;
    if (const int fd = ::openat(m_dir_fd, m_name.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0)
    {
        char buf[65536];
        for (;;)
        {
            const ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            text.append(buf, static_cast<size_t>(n));
        }
        ::close(fd);
    }

    // Every event with no delivery record, in the order they were made; a torn tail is a change never answered.
    struct held
    {
        uint64_t    id;
        std::string target;
        std::string json;
    };
    std::vector<held> events;
    std::vector<uint64_t> delivered;
    size_t pos = 0;
    while (text.size() - pos >= 8)
    {
        bytes::reader h(std::string_view(text).substr(pos, 8));
        uint32_t len = 0, crc = 0;
        if (!h.u32(len) || !h.u32(crc) || len > record_cap || text.size() - pos - 8 < len)
            break;
        const std::string_view payload = std::string_view(text).substr(pos + 8, len);
        if (journal_detail::crc32(payload) != crc)
            break;
        pos += 8 + len;
        bytes::reader r(payload);
        uint8_t  type = 0;
        uint64_t id   = 0;
        if (!r.u8(type) || !r.u64(id))
            break;
        m_next_id = std::max(m_next_id, id + 1);
        if (type == 'D')
        {
            delivered.push_back(id);
            continue;
        }
        held e{id, {}, {}};
        if (type != 'E' || !r.bytes(e.target, 4096) || !r.bytes(e.json, record_cap))
            break;
        events.push_back(std::move(e));
    }
    std::sort(delivered.begin(), delivered.end());
    std::erase_if(events, [&](const held& e) { return std::binary_search(delivered.begin(), delivered.end(), e.id); });

    // Written again with only what is left to deliver, so the outbox never outgrows its undelivered events.
    const std::string tmp = m_name + ".new";
    const int fd = ::openat(m_dir_fd, tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        err = "cannot write " + nd + "/" + tmp + ": " + std::strerror(errno);
        return false;
    }
    uint64_t dropped = 0;
    for (held& e : events)
    {
        lane* l = find_lane(e.target);
        if (!l || m_queued >= m_queue_max)
        {
            ++dropped;
            continue;
        }
        append_record('E', e.id, e.target, e.json);
        l->q.push_back({e.id, std::move(e.json)});
        ++m_queued;
    }
    m_c.dropped += dropped;
    const bool ok = write_all(fd, m_buf.data(), m_buf.size()) && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || ::renameat(m_dir_fd, tmp.c_str(), m_dir_fd, m_name.c_str()) < 0 || ::fsync(m_dir_fd) < 0)
    {
        err = "cannot write " + nd + "/" + m_name + ": " + std::strerror(errno);
        m_buf.clear();
        return false;
    }
    m_off = m_buf.size();
    m_buf.clear();
    m_fd = ::openat(m_dir_fd, m_name.c_str(), O_WRONLY | O_CLOEXEC);
    if (m_fd < 0)
    {
        err = "cannot open " + nd + "/" + m_name + ": " + std::strerror(errno);
        return false;
    }
    if (dropped)
        LOG_WARN(("storage: " + std::to_string(dropped) +
                  " undelivered event(s) in the outbox name a target that is gone or overflow the queue, and are dropped")
                     .c_str());
    if (m_queued)
    {
        LOG_INFO(("storage: " + std::to_string(m_queued) + " undelivered event(s) are sent again").c_str());
        for (auto& l : m_lanes)
            if (!l->q.empty())
                start(*l);
    }
    return true;
}

void notifier::append_record(char type, uint64_t id, std::string_view target, std::string_view json)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(type));
    w.u64(id);
    if (type == 'E')
    {
        w.bytes(target);
        w.bytes(json);
    }
    const std::string payload = w.take();
    bytes::writer h;
    h.u32(static_cast<uint32_t>(payload.size()));
    h.u32(journal_detail::crc32(payload));
    m_buf += h.take();
    m_buf += payload;
}

bool notifier::add(std::string_view target, std::string json)
{
    lane* l = find_lane(target);
    if (!l || m_stopped || m_queued >= m_queue_max)
    {
        ++m_c.dropped;
        return false;
    }
    const uint64_t id = m_next_id++;
    append_record('E', id, target, json);
    l->q.push_back({id, std::move(json)});
    ++m_queued;
    if (!l->busy)
        start(*l);
    return true;
}

void notifier::sync(std::function<void()> then)
{
    if (m_fd < 0 || (m_buf.empty() && !m_writing))
    {
        then();
        return;
    }
    m_buf_cbs.push_back(std::move(then));
    kick();
}

void notifier::kick()
{
    if (m_writing || m_rotating || m_fd < 0 || (m_buf.empty() && m_buf_cbs.empty()))
        return;
    m_writing = true;
    auto buf  = std::make_shared<std::string>(std::move(m_buf));
    auto cbs  = std::move(m_buf_cbs);
    m_buf.clear();
    m_buf_cbs.clear();
    auto alive = m_alive;
    // Only an event's record is waited on; a delivery record lost to a crash costs a second delivery, and the next
    // event's sync covers it anyway.
    const bool must_sync = !cbs.empty();
    auto sync_then = [this, alive, buf, cbs, must_sync](int64_t res)
    {
        if (!*alive)
            return;
        if (res >= 0 && !must_sync)
        {
            written(res, buf, cbs);
            return;
        }
        if (res >= 0 && !m_io.fsync(m_fd, true, [this, alive, buf, cbs](int64_t r2)
            {
                if (*alive)
                    written(r2, buf, cbs);
            }))
            res = -EIO;
        if (res < 0)
            written(res, buf, cbs);
    };
    if (buf->empty())
    {
        sync_then(0);
        return;
    }
    const uint64_t at = m_off;
    m_off += buf->size();
    if (!m_io.pwrite(m_fd, buf->data(), static_cast<uint32_t>(buf->size()), at, std::move(sync_then)))
        written(-EIO, buf, cbs);
}

void notifier::written(int64_t res, std::shared_ptr<std::string>, std::vector<std::function<void()>> cbs)
{
    m_writing = false;
    // A failed write leaves the events in memory, delivered as long as this process lives, and is said once.
    if (res < 0 && !m_write_failed)
    {
        m_write_failed = true;
        LOG_ERROR(("storage: writing the event outbox failed (" + std::string(std::strerror(static_cast<int>(-res))) +
                   "); events are delivered but would not survive a crash").c_str());
    }
    for (auto& cb : cbs)
        cb();
    kick();
    maybe_rotate();
}

void notifier::maybe_rotate()
{
    if (m_queued != 0 || m_writing || m_rotating || !m_buf.empty() || m_off < rotate_bytes || m_fd < 0 ||
        m_stopped)
        return;
    m_rotating = true;
    auto alive = m_alive;
    const std::string tmp = m_name + ".new";
    auto fail = [this](std::string_view why)
    {
        LOG_WARN(("storage: the event outbox could not be started again empty: " + std::string(why)).c_str());
        m_rotating = false;
        kick();
    };
    const bool q = m_io.openat(m_dir_fd, tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644,
        [this, alive, tmp, fail](int64_t fd)
        {
            if (!*alive)
                return;
            if (fd < 0)
            {
                fail(std::strerror(static_cast<int>(-fd)));
                return;
            }
            const bool q2 = m_io.renameat(m_dir_fd, tmp, m_dir_fd, m_name, [this, alive, fd, fail](int64_t r)
            {
                if (!*alive)
                    return;
                if (r < 0)
                {
                    m_loop.close_fd(static_cast<int>(fd));
                    fail(std::strerror(static_cast<int>(-r)));
                    return;
                }
                // The old file's name is gone, so its descriptor is let go of and everything after goes to the new one.
                m_loop.close_fd(m_fd);
                m_fd  = static_cast<int>(fd);
                m_off = 0;
                if (!m_io.fsync(m_dir_fd, false, [this, alive](int64_t)
                    {
                        if (!*alive)
                            return;
                        m_rotating = false;
                        kick();
                    }))
                {
                    m_rotating = false;
                    kick();
                }
            });
            if (!q2)
            {
                m_loop.close_fd(static_cast<int>(fd));
                fail("the ring is full");
            }
        });
    if (!q)
        fail("the ring is full");
}

// ─── Deliveries ─────────────────────────────────────────────────────────────

void notifier::arm_timer()
{
    if (m_timer_armed || m_stopped)
        return;
    m_timer_ts  = {0, tick_ns};
    m_timer_req = io_request{};
    m_timer_req.owner = m_owner;
    m_timer_req.type  = op_timeout;
    m_timer_armed = m_loop.submit_timeout(&m_timer_ts, &m_timer_req);
}

void notifier::on_timer()
{
    m_timer_armed = false;
    if (m_stopped)
        return;
    const auto now = std::chrono::steady_clock::now();
    bool waiting = false;
    for (auto& lp : m_lanes)
    {
        lane& l = *lp;
        if (l.busy && now >= l.deadline)
            finish(l, false);
        else if (!l.busy && !l.q.empty() && now >= l.next_try)
            start(l);
        waiting = waiting || l.busy || !l.q.empty();
    }
    if (waiting)
        arm_timer();
}

void notifier::start(lane& l)
{
    if (l.busy || l.q.empty() || m_stopped)
        return;
    const auto now = std::chrono::steady_clock::now();
    if (now < l.next_try)
    {
        arm_timer();
        return;
    }
    // A host with no address yet waits for the resolver, which starts the delivery when it answers.
    if (l.addrs.empty())
    {
        if (!resolve(l))
            back_off(l);
        return;
    }
    // A host is asked again now and then while it is used, without holding up this delivery.
    if (!l.literal && now - l.resolved_at > std::chrono::seconds(resolve_every_secs))
        if (!resolve(l)) {}
    l.busy          = true;
    l.handshaken    = false;
    l.request_given = false;
    l.wrote_request = false;
    l.response.clear();
    l.deadline = now + std::chrono::seconds(attempt_secs);
    arm_timer();
    if (l.target.tls && !l.tls)
    {
        finish(l, false);
        return;
    }
    const notify_endpoint& ep = l.addrs[l.cur % l.addrs.size()];
    l.fd = ::socket(ep.addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (l.fd < 0)
    {
        finish(l, false);
        return;
    }
    const uint64_t gen = l.gen;
    auto alive = m_alive;
    lane* lp = &l;
    if (!m_io.connect(l.fd, reinterpret_cast<const struct sockaddr*>(&ep.addr), ep.len,
                      [this, alive, lp, gen](int64_t res)
                      {
                          if (*alive && lp->gen == gen)
                              connected(*lp, res);
                      }))
        finish(l, false);
}

void notifier::connected(lane& l, int64_t res)
{
    if (res < 0)
    {
        // The host's next address is tried at once, and once every one has refused, its name is asked again.
        if (++l.cur < l.addrs.size())
        {
            ++l.gen;
            l.busy = false;
            m_loop.close_fd(l.fd);
            l.fd = -1;
            start(l);
            return;
        }
        l.cur = 0;
        if (!resolve(l)) {}
        finish(l, false);
        return;
    }
    if (l.target.tls)
    {
        l.ssl = l.tls->create_ssl_client(l.target.host);
        if (!l.ssl)
        {
            finish(l, false);
            return;
        }
    }
    advance(l);
}

void notifier::advance(lane& l)
{
    const pending& ev = l.q.front();
    std::string request;
    if (!l.request_given)
    {
        const bool default_port = l.target.port == (l.target.tls ? 443 : 80);
        const bool v6 = l.target.host.find(':') != std::string::npos;
        request = "POST " + l.target.path + " HTTP/1.1\r\nHost: " + (v6 ? "[" + l.target.host + "]" : l.target.host) +
                  (default_port ? "" : ":" + std::to_string(l.target.port)) +
                  "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(ev.json.size()) +
                  "\r\nConnection: close\r\nUser-Agent: socketley-storage\r\nX-Socketley-Event-Id: " +
                  std::to_string(ev.id) + "\r\n\r\n";
        request += ev.json;
    }
    if (!l.ssl)
    {
        if (!l.request_given)
        {
            l.request_given = true;
            send(l, std::move(request));
            return;
        }
        receive(l);
        return;
    }

    if (!l.handshaken)
    {
        const int h = tls_context::do_handshake(l.ssl);
        if (h < 0)
        {
            finish(l, false);
            return;
        }
        l.handshaken = h == 1;
    }
    if (l.handshaken && !l.request_given)
    {
        size_t off = 0;
        while (off < request.size())
        {
            const int n = tls_context::ssl_write(l.ssl, request.data() + off,
                                                 static_cast<int>(std::min<size_t>(request.size() - off, 1u << 20)));
            if (n <= 0)
            {
                finish(l, false);
                return;
            }
            off += static_cast<size_t>(n);
        }
        l.request_given = true;
    }
    std::string cipher;
    char buf[16384];
    for (;;)
    {
        const int n = tls_context::bio_read_out(l.ssl, buf, sizeof(buf));
        if (n <= 0)
            break;
        cipher.append(buf, static_cast<size_t>(n));
    }
    if (!cipher.empty())
    {
        send(l, std::move(cipher));
        return;
    }
    receive(l);
}

void notifier::send(lane& l, std::string bytes)
{
    auto buf = std::make_shared<std::string>(std::move(bytes));
    const uint64_t gen = l.gen;
    auto alive = m_alive;
    lane* lp = &l;
    if (!m_io.pwrite(l.fd, buf->data(), static_cast<uint32_t>(buf->size()), 0, [this, alive, lp, gen, buf](int64_t res)
        {
            if (!*alive || lp->gen != gen)
                return;
            if (res < 0)
            {
                finish(*lp, false);
                return;
            }
            lp->wrote_request = lp->request_given;
            advance(*lp);
        }))
        finish(l, false);
}

void notifier::receive(lane& l)
{
    // A buffer per read, held by its completion, so a read the end of an attempt left in the ring writes nowhere shared.
    std::shared_ptr<char[]> buf(new char[read_bytes]);
    const uint64_t gen = l.gen;
    auto alive = m_alive;
    lane* lp = &l;
    if (!m_io.pread(l.fd, buf.get(), read_bytes, 0, [this, alive, lp, gen, buf](int64_t res)
        {
            if (!*alive || lp->gen != gen)
                return;
            if (res <= 0)
            {
                // The webhook closed after answering, which is how a Connection: close answer ends.
                finish(*lp, response_status(lp->response) / 100 == 2);
                return;
            }
            got(*lp, buf.get(), static_cast<size_t>(res));
        }))
        finish(l, false);
}

void notifier::got(lane& l, const char* p, size_t n)
{
    if (!l.ssl)
        l.response.append(p, n);
    else
    {
        if (tls_context::bio_write_in(l.ssl, p, static_cast<int>(n)) < 0)
        {
            finish(l, false);
            return;
        }
        if (l.handshaken)
        {
            char buf[16384];
            for (;;)
            {
                const int r = tls_context::ssl_read(l.ssl, buf, sizeof(buf));
                if (r <= 0)
                    break;
                l.response.append(buf, static_cast<size_t>(r));
            }
        }
    }
    if (const int status = response_status(l.response); status != 0 || l.response.size() > response_cap)
    {
        finish(l, status / 100 == 2);
        return;
    }
    advance(l);
}

int notifier::response_status(std::string_view r)
{
    if (r.find("\r\n\r\n") == std::string_view::npos || !r.starts_with("HTTP/1.") || r.size() < 12 || r[8] != ' ')
        return 0;
    int status = 0;
    const auto res = std::from_chars(r.data() + 9, r.data() + 12, status);
    return res.ec == std::errc{} && res.ptr == r.data() + 12 ? status : 0;
}

void notifier::finish(lane& l, bool delivered)
{
    ++l.gen;
    l.busy = false;
    if (l.ssl)
    {
        tls_context::free_ssl(l.ssl);
        l.ssl = nullptr;
    }
    if (l.fd >= 0)
    {
        m_loop.close_fd(l.fd);
        l.fd = -1;
    }
    if (m_stopped)
        return;
    if (delivered)
    {
        ++m_c.sent;
        append_record('D', l.q.front().id, {}, {});
        l.q.pop_front();
        --m_queued;
        l.failures = 0;
        l.next_try = {};
        kick();
        start(l);
        return;
    }
    back_off(l);
}

void notifier::back_off(lane& l)
{
    ++m_c.failed;
    ++l.failures;
    const int64_t pause = std::min(backoff_cap_ms, backoff_first_ms << std::min<uint32_t>(l.failures - 1, 16));
    l.next_try = std::chrono::steady_clock::now() + std::chrono::milliseconds(pause);
    arm_timer();
}

void notifier::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    for (auto& l : m_lanes)
        if (l->busy)
            finish(*l, false);
    if (m_timer_armed)
        m_loop.submit_timeout_remove(&m_timer_req);
    // A resolve in progress is waited out here, which the system resolver's own timeout bounds.
    m_resolver.stop();
    if (const int fd = m_resolver.release_wake_fd(); fd >= 0)
        m_loop.close_fd(fd);
    // The delivery records not yet written are written here, blocking as a stop may, so a restart does not send them again.
    if (m_fd >= 0 && !m_buf.empty() && !m_rotating)
    {
        if (::pwrite(m_fd, m_buf.data(), m_buf.size(), static_cast<off_t>(m_off)) == static_cast<ssize_t>(m_buf.size()) &&
            ::fdatasync(m_fd) == 0)
            m_off += m_buf.size();
        m_buf.clear();
    }
    if (m_fd >= 0)
        m_loop.close_fd(m_fd);
    m_fd = -1;
    if (m_dir_fd >= 0)
        m_loop.close_fd(m_dir_fd);
    m_dir_fd = -1;
}

}   // namespace socketley::storage
