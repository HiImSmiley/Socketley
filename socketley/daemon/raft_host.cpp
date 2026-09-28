#include "raft_host.h"

#include "../shared/byte_codec.h"
#include "../shared/dial_address.h"
#include "../shared/event_loop.h"
#include "../shared/ipc_framing.h"
#include "../shared/logging.h"
#include "../shared/raft_codec.h"
#include "../shared/socket_tuning.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <netinet/tcp.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace raft = socketley::raft;
namespace wire = socketley::raft::wire;
namespace st   = socketley::raft::storage;

namespace {

void info(const std::string& s)  { LOG_INFO(("raft: " + s).c_str()); }
void warn(const std::string& s)  { LOG_WARN(("raft: " + s).c_str()); }
void debug(const std::string& s) { LOG_DEBUG(("raft: " + s).c_str()); }

std::string hex_id(raft::node_id id)
{
    char buf[20];
    std::snprintf(buf, sizeof buf, "%016" PRIx64, id);
    return buf;
}

const char* role_name(raft::role r)
{
    switch (r)
    {
    case raft::role::follower:      return "follower";
    case raft::role::pre_candidate: return "pre-candidate";
    case raft::role::candidate:     return "candidate";
    case raft::role::leader:        return "leader";
    }
    return "?";
}

uint64_t random_u64()
{
    uint64_t v = 0;
    while (v == 0)
        if (::getrandom(&v, sizeof v, 0) != static_cast<ssize_t>(sizeof v))
            v = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^ ::getpid();
    return v;
}

// A numeric host:port, because a peer's address arrives through the log and resolving a name would block the loop.
bool parse_numeric(const std::string& addr, sockaddr_storage& out, socklen_t& len, std::string* host_out = nullptr)
{
    std::string host;
    uint16_t port = 0;
    if (!socketley::dial_addr::refusal(addr, host, port, true).empty())
        return false;
    if (host.size() > 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    out = sockaddr_storage{};
    auto* v4 = reinterpret_cast<sockaddr_in*>(&out);
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&out);
    if (::inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1)
    {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(port);
        len = sizeof(sockaddr_in);
    }
    else if (::inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) == 1)
    {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
        len = sizeof(sockaddr_in6);
    }
    else
    {
        return false;
    }
    if (host_out)
        *host_out = host;
    return true;
}

bool wildcard(const std::string& addr)
{
    sockaddr_storage sa{};
    socklen_t len = 0;
    std::string host;
    return parse_numeric(addr, sa, len, &host) && (host == "0.0.0.0" || host == "::");
}

// Frames this far over a peer's unsent bytes are dropped, because Raft survives loss and a slow peer must not grow memory.
constexpr size_t outbound_cap = 8u * 1024u * 1024u;

void put_u64(std::string& o, uint64_t v)
{
    for (int b = 0; b < 8; ++b)
        o += static_cast<char>((v >> (8 * b)) & 0xFF);
}

bool get_u64(std::string_view in, size_t& off, uint64_t& v)
{
    if (in.size() - off < 8)
        return false;
    v = 0;
    for (int b = 0; b < 8; ++b)
        v |= static_cast<uint64_t>(static_cast<unsigned char>(in[off + b])) << (8 * b);
    off += 8;
    return true;
}

bool get_label(std::string_view in, size_t& off, std::string& s)
{
    if (in.size() - off < 1)
        return false;
    const size_t n = static_cast<unsigned char>(in[off++]);
    if (in.size() - off < n)
        return false;
    s.assign(in.substr(off, n));
    off += n;
    return true;
}

}   // namespace

// ─── configuration ───

static socketley::cluster::timing cluster_timing(const raft_host_config& c)
{
    socketley::cluster::timing t;
    t.election_ms   = static_cast<uint64_t>(c.election_ticks) * c.tick_ms;
    t.down_after_ms = c.down_after_ms ? c.down_after_ms : 4 * t.election_ms;
    return t;
}

std::string raft_timing_refusal(const raft_host_config& c)
{
    const std::string why = socketley::cluster::timing_refusal(cluster_timing(c));
    return why.empty() ? why : "--raft-down-after: " + why + "\n";
}

bool parse_raft_down_after(std::string_view text, uint64_t& ms)
{
    uint64_t unit = 1000;
    if (text.ends_with("ms"))
    {
        unit = 1;
        text.remove_suffix(2);
    }
    else if (text.ends_with('s'))
    {
        text.remove_suffix(1);
    }
    uint64_t n = 0;
    if (text.empty() || text.size() > 9)
        return false;
    for (char c : text)
    {
        if (c < '0' || c > '9')
            return false;
        n = n * 10 + static_cast<uint64_t>(c - '0');
    }
    if (n == 0 || n * unit > 86400000ull)
        return false;
    ms = n * unit;
    return true;
}

std::string raft_config_refusal(const raft_host_config& c)
{
    if (!c.enabled())
    {
        if (c.init || c.insecure || !c.join.empty() || !c.advertise.empty() || !c.name.empty()
            || !c.cert.empty() || !c.key.empty() || !c.ca.empty() || c.down_after_ms)
            return "--raft-* flags need --raft-listen <ip:port>, the address this daemon's Raft peers dial\n";
        return {};
    }

    sockaddr_storage sa{};
    socklen_t len = 0;
    if (!parse_numeric(c.listen, sa, len))
        return "--raft-listen " + c.listen + ": not a numeric ip:port (a peer address travels through the log "
               "and is dialled without a DNS lookup)\n";
    const std::string adv = c.advertise.empty() ? c.listen : c.advertise;
    if (!parse_numeric(adv, sa, len))
        return "--raft-advertise " + adv + ": not a numeric ip:port\n";
    if (wildcard(adv))
        return "--raft-listen " + c.listen + " is a wildcard, which no peer can dial: give --raft-advertise <ip:port>\n";
    if (c.init && !c.join.empty())
        return "--raft-init founds a new cluster and --raft-join joins an existing one: give one of them\n";
    if (!c.join.empty() && !parse_numeric(c.join, sa, len))
        return "--raft-join " + c.join + ": not a numeric ip:port\n";
    if (c.name.size() > wire::max_label || adv.size() > wire::max_label)
        return "--raft-name: at most 255 bytes\n";
    if (c.insecure && (!c.cert.empty() || !c.key.empty() || !c.ca.empty()))
        return "--raft-insecure turns mutual TLS off, and --raft-cert/--raft-key/--raft-ca configure it: give one "
               "or the other\n";
    if (!c.insecure && (c.cert.empty() || c.key.empty() || c.ca.empty()))
        return "Raft between daemons is mutual TLS: give --raft-cert, --raft-key and --raft-ca (the CA every "
               "member's certificate is signed by), or --raft-insecure to run it in cleartext on a network you trust\n";
    return {};
}

// ─── one TCP stream to or from a peer ───

struct raft_host::link : io_handler
{
    enum class phase : uint8_t { connecting, handshake, ready, dead };

    raft_host*     host = nullptr;
    bool           outbound = false;
    int            fd = -1;
    SSL*           ssl = nullptr;
    phase          state = phase::connecting;
    raft::node_id  peer = raft::no_node;
    bool           hello_seen = false;
    std::string    addr, name;
    sockaddr_storage sa{};
    socklen_t      salen = 0;
    uint32_t       token = 0;
    clock::time_point born = clock::now();

    io_request conn_req{}, read_req{}, write_req{};
    bool       read_pending = false, write_pending = false;
    char       rbuf[16384];
    std::string in;
    std::string queue;
    std::string wire_out;
    size_t      wire_off = 0;

    ~link() override { tls_context::free_ssl(ssl); }

    void begin()
    {
        if (host->m_tls)
        {
            ssl = outbound ? host->m_client_tls.create_ssl_client(name) : host->m_server_tls.create_ssl_server();
            if (!ssl)
                return fail("could not set up TLS");
            state = phase::handshake;
            if (tls_context::do_handshake(ssl) < 0)
                return fail("TLS handshake failed");
        }
        else
        {
            state = phase::ready;
        }
        start_read();
        flush();
    }

    void start_read()
    {
        if (read_pending || state == phase::dead)
            return;
        read_req = io_request{this, rbuf, fd, sizeof rbuf, op_read};
        if (!host->m_loop->submit_read(fd, rbuf, sizeof rbuf, &read_req))
            return fail("could not queue a read");
        read_pending = true;
    }

    void flush()
    {
        if (write_pending || state == phase::dead || state == phase::connecting)
            return;
        if (wire_off == wire_out.size())
        {
            wire_out.clear();
            wire_off = 0;
        }
        if (ssl)
        {
            while (state == phase::ready && !queue.empty())
            {
                const int n = tls_context::ssl_write(ssl, queue.data(), static_cast<int>(std::min<size_t>(queue.size(), 65536)));
                if (n < 0)
                    return fail("TLS write failed");
                if (n == 0)
                    break;
                queue.erase(0, static_cast<size_t>(n));
            }
            char buf[16384];
            for (;;)
            {
                const int k = tls_context::bio_read_out(ssl, buf, sizeof buf);
                if (k <= 0)
                    break;
                wire_out.append(buf, static_cast<size_t>(k));
            }
        }
        else if (state == phase::ready)
        {
            wire_out += queue;
            queue.clear();
        }
        if (wire_off == wire_out.size())
            return;
        const uint32_t len = static_cast<uint32_t>(std::min<size_t>(wire_out.size() - wire_off, 1u << 20));
        write_req = io_request{this, wire_out.data() + wire_off, fd, len, op_write};
        if (!host->m_loop->submit_write(fd, wire_out.data() + wire_off, len, &write_req))
            return fail("could not queue a write");
        write_pending = true;
    }

    void on_bytes(const char* data, size_t n)
    {
        if (ssl)
        {
            if (tls_context::bio_write_in(ssl, data, static_cast<int>(n)) < 0)
                return fail("TLS input overflow");
            if (state == phase::handshake)
            {
                const int r = tls_context::do_handshake(ssl);
                if (r < 0)
                    return fail("TLS handshake failed");
                if (r == 1)
                    state = phase::ready;
            }
            if (state == phase::ready)
            {
                char buf[16384];
                for (;;)
                {
                    const int k = tls_context::ssl_read(ssl, buf, sizeof buf);
                    if (k < 0)
                        return fail("TLS stream closed");
                    if (k == 0)
                        break;
                    if (!outbound)
                        in.append(buf, static_cast<size_t>(k));
                }
            }
            flush();
        }
        else if (!outbound)
        {
            in.append(data, n);
        }

        if (outbound || state != phase::ready)
            return;
        size_t off = 0;
        while (state != phase::dead)
        {
            std::string_view payload;
            size_t next = 0;
            if (off < in.size() && in[off] != ipc_frame::marker)
                return fail("not a frame");
            const ipc_frame::take t = ipc_frame::peek_frame(in, off, payload, next);
            if (t == ipc_frame::take::need_more)
                break;
            if (t == ipc_frame::take::fatal)
                return fail("a frame past the 16 MiB cap");
            if (!host->on_frame(*this, payload))
                return fail("refused a frame");
            off = next;
        }
        if (state != phase::dead)
            in.erase(0, off);
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req == &read_req)
            read_pending = false;
        else if (req == &write_req)
            write_pending = false;
        if (state == phase::dead)
            return;

        if (req == &conn_req)
        {
            if (cqe->res < 0)
                return fail(std::string("connect: ") + std::strerror(-cqe->res));
            begin();
        }
        else if (req == &read_req)
        {
            if (cqe->res <= 0)
                return fail(cqe->res == 0 ? "closed by the peer" : std::string("read: ") + std::strerror(-cqe->res));
            on_bytes(rbuf, static_cast<size_t>(cqe->res));
            start_read();
        }
        else if (req == &write_req)
        {
            if (cqe->res <= 0)
                return fail(std::string("write: ") + std::strerror(-cqe->res));
            wire_off += static_cast<size_t>(cqe->res);
            flush();
        }
    }

    void fail(const std::string& why)
    {
        if (state == phase::dead)
            return;
        state = phase::dead;
        debug((outbound ? "link to " : "link from ") + (peer ? hex_id(peer) : addr) + " closed: " + why);
        host->retire(this);
    }
};

// ─── lifecycle ───

raft_host::raft_host(raft_host_config cfg) : m_cfg(std::move(cfg))
{
    if (m_cfg.advertise.empty())
        m_cfg.advertise = m_cfg.listen;
    if (m_cfg.name.empty())
        m_cfg.name = m_cfg.advertise;
}

raft_host::~raft_host()
{
    if (m_listen_fd >= 0)
        ::close(m_listen_fd);
}

bool raft_host::load_identity(std::string& err)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(m_cfg.dir).parent_path(), ec);
    if (::mkdir(m_cfg.dir.c_str(), 0700) != 0 && errno != EEXIST)
    {
        err = "cannot create " + m_cfg.dir + ": " + std::strerror(errno);
        return false;
    }
    const std::string path = m_cfg.dir + "/node-id";
    if (FILE* f = std::fopen(path.c_str(), "r"))
    {
        unsigned long long v = 0;
        const bool ok = std::fscanf(f, "%16llx", &v) == 1 && v != 0;
        std::fclose(f);
        if (!ok)
        {
            err = path + " does not hold a node id";
            return false;
        }
        m_id = v;
        return true;
    }

    m_id = random_u64();
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const std::string text = hex_id(m_id) + "\n";
    const bool ok = fd >= 0 && ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size())
                 && ::fsync(fd) == 0;
    if (fd >= 0)
        ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0)
    {
        err = "cannot write " + path + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

bool raft_host::start(event_loop& loop, std::string& err)
{
    m_loop = &loop;

    if (!m_cfg.insecure)
    {
        if (!m_server_tls.init_server(m_cfg.cert, m_cfg.key, m_cfg.ca)
            || !m_client_tls.init_client(m_cfg.ca, m_cfg.cert, m_cfg.key))
        {
            err = "the certificates given to --raft-cert/--raft-key/--raft-ca could not be loaded\n";
            return false;
        }
        m_tls = true;
    }

    if (!load_identity(err))
        return false;

    st::recovery rec;
    if (!st::recover(m_cfg.dir, rec, err))
        return false;
    for (const std::string& n : rec.notes)
        warn("recovery " + n);

    if (rec.segment.empty())
    {
        raft::persisted fresh;
        if (!m_cfg.init && m_cfg.join.empty())
        {
            err = "no Raft state in " + m_cfg.dir + ": start with --raft-init to found a cluster, or --raft-join "
                  "<ip:port> to join one\n";
            return false;
        }
        // The founder's own record goes through the log like everyone's, since a joiner replays the log and never sees this snapshot.
        if (m_cfg.init)
            fresh.snap.voters = {m_id};
        fresh.snap.data = encode_snapshot({}, {});
        if (!st::initialize(m_cfg.dir, fresh, err) || !st::recover(m_cfg.dir, rec, err))
            return false;
        info(std::string(m_cfg.init ? "founded a new cluster" : "joining through " + m_cfg.join) + " as node "
             + hex_id(m_id));
    }
    else if (m_cfg.init || !m_cfg.join.empty())
    {
        info("state found in " + m_cfg.dir + ", so " + (m_cfg.init ? "--raft-init" : "--raft-join")
             + " is ignored: this node is " + hex_id(m_id));
    }

    raft::options o;
    o.id             = m_id;
    o.election_ticks = m_cfg.election_ticks;
    o.seed           = random_u64();
    const raft::index_t first = rec.state.snap.index;
    const size_t logged = rec.state.log.size();
    socketley::cluster::state restored;
    if (!decode_snapshot(rec.state.snap.data, m_applied_book, restored))
    {
        err = "the snapshot in " + m_cfg.dir + " does not hold a membership book and a cluster state";
        return false;
    }
    if (const std::string why = raft_timing_refusal(m_cfg); !why.empty())
    {
        err = why;
        return false;
    }
    m_brain = std::make_unique<socketley::cluster::brain>(m_id, m_cfg.name, cluster_timing(m_cfg));
    m_brain->restore(std::move(restored));
    m_node = std::make_unique<raft::node>(o, std::move(rec.state));
    m_applied = m_snap_index = first;
    refresh_book();

    if (!m_wal.open(loop, m_cfg.dir, rec, err))
        return false;
    if (!bind_listener(err))
        return false;

    m_owner_token = loop.register_owner(this);
    m_last_tick   = clock::now();
    m_soft        = raft::soft_state{m_node->current_role(), m_node->leader(), m_node->term()};
    arm_accept();
    arm_tick();
    arm_pump();

    info("node " + hex_id(m_id) + " (" + m_cfg.name + ") on " + m_cfg.listen + (m_tls ? " with mutual TLS" : " in cleartext")
         + ", term " + std::to_string(m_node->term()) + ", snapshot " + std::to_string(first) + " and "
         + std::to_string(logged) + " entries recovered");
    return true;
}

bool raft_host::bind_listener(std::string& err)
{
    sockaddr_storage sa{};
    socklen_t len = 0;
    parse_numeric(m_cfg.listen, sa, len);
    m_listen_fd = ::socket(sa.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int on = 1;
    if (m_listen_fd < 0 || ::setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) != 0
        || ::bind(m_listen_fd, reinterpret_cast<sockaddr*>(&sa), len) != 0 || ::listen(m_listen_fd, 64) != 0)
    {
        err = "cannot listen on " + m_cfg.listen + ": " + std::strerror(errno) + "\n";
        return false;
    }
    return true;
}

void raft_host::arm_accept()
{
    if (m_accept_armed || m_stopped)
        return;
    m_accept_len = sizeof m_accept_addr;
    m_accept_req = io_request{this, nullptr, m_listen_fd, 0, op_accept};
    m_accept_armed = m_loop->submit_accept(m_listen_fd, reinterpret_cast<sockaddr_in*>(&m_accept_addr),
                                           &m_accept_len, &m_accept_req);
}

void raft_host::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick_ts.tv_sec  = m_cfg.tick_ms / 1000;
    m_tick_ts.tv_nsec = static_cast<long long>(m_cfg.tick_ms % 1000) * 1000000;
    m_tick_req = io_request{this, nullptr, -1, 0, op_timeout};
    m_tick_armed = m_loop->submit_timeout(&m_tick_ts, &m_tick_req);
    if (!m_tick_armed)
        warn("the tick timer could not be armed; elections and heartbeats stop until the next completion");
}

void raft_host::arm_pump()
{
    if (m_pump_armed || m_stopped || !m_node || m_wal.busy() || !m_node->has_ready())
        return;
    // A no-op completion lands after everything already in the ring, so one ready gathers the whole turn: the group commit.
    m_pump_req = io_request{this, nullptr, -1, 0, op_nop};
    m_pump_armed = m_loop->submit_nop(&m_pump_req);
}

void raft_host::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (req == &m_accept_req)
        on_accept(cqe->res);
    else if (req == &m_tick_req)
        on_tick();
    else if (req == &m_pump_req)
        pump();
}

void raft_host::on_accept(int res)
{
    m_accept_armed = false;
    if (m_stopped)
    {
        if (res >= 0)
            ::close(res);
        return;
    }
    if (res >= 0)
    {
        int on = 1;
        if (::setsockopt(res, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on) < 0) {}
        socket_tuning::keepalive_dead_peer(res);
        auto l = std::make_unique<link>();
        l->host  = this;
        l->fd    = res;
        l->token = m_loop->register_owner(l.get());
        l->addr  = "inbound";
        link* raw = l.get();
        m_in.push_back(std::move(l));
        raw->begin();
    }
    else if (res != -ECANCELED)
    {
        warn(std::string("accept failed: ") + std::strerror(-res));
    }
    arm_accept();
}

void raft_host::on_tick()
{
    m_tick_armed = false;
    if (m_stopped)
        return;
    // Elapsed monotonic time decides how many ticks passed, so a loop that stalled cannot hide the ticks it missed.
    const auto now  = clock::now();
    const auto step = std::chrono::milliseconds(m_cfg.tick_ms);
    uint64_t n = static_cast<uint64_t>((now - m_last_tick) / step);
    const uint64_t cap = 4ull * m_cfg.election_ticks;
    if (n > cap)
    {
        n = cap;
        m_last_tick = now;
    }
    else
    {
        m_last_tick += n * step;
    }
    for (uint64_t i = 0; i < n; ++i)
        m_node->tick();
    m_ticks += n;
    maintain();
    drive_cluster();
    arm_pump();
    arm_tick();
    // Last, because the daemon's reconciliation may block on a worker starting and the next tick is already armed.
    if (m_on_tick && !m_stopped)
        m_on_tick();
}

uint64_t raft_host::now_ms() const
{
    // One past zero, so a lease that was never granted is never mistaken for one that expires at the origin.
    return 1 + static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - m_epoch).count());
}

socketley::cluster::view raft_host::make_view()
{
    if (m_node->current_role() != raft::role::leader)
        m_last_proposed = 0;
    return socketley::cluster::view_of(*m_node, m_applied, m_last_proposed);
}

void raft_host::drive_cluster()
{
    if (m_stopped)
        return;
    socketley::cluster::output out;
    m_brain->tick(now_ms(), make_view(), out);
    flush_cluster(out);
}

void raft_host::flush_cluster(socketley::cluster::output& out)
{
    for (const std::string& data : out.proposals)
    {
        const raft::proposal p = m_node->propose(data);
        if (p.status != raft::propose_status::ok)
            break;
        m_last_proposed = p.index;
    }
    namespace cl = socketley::cluster;
    for (const cl::frame& f : out.frames)
    {
        link* l = outbound(f.to);
        if (!l)
            continue;
        const wire::kind k = f.type == cl::frame::kind::lease_req ? wire::kind::lease_req : wire::kind::lease_grant;
        enqueue(l, wire::encode(k, wire::lease{f.nonce, f.index}));
    }
    if (!out.proposals.empty())
        arm_pump();
}

void raft_host::maintain()
{
    reap();
    const auto now = clock::now();
    auto stale = [&](const std::unique_ptr<link>& l)
    {
        return l && l->state != link::phase::ready && l->state != link::phase::dead && now - l->born > std::chrono::seconds(3);
    };
    std::vector<link*> timed_out;
    for (auto& [id, l] : m_out)
        if (stale(l))
            timed_out.push_back(l.get());
    for (auto& l : m_in)
        if (stale(l))
            timed_out.push_back(l.get());
    if (stale(m_join_link))
        timed_out.push_back(m_join_link.get());
    for (link* l : timed_out)
        l->fail("did not come up within 3 s");

    if (m_ticks % 10 == 0)
        try_join();
    if (m_node->current_role() == raft::role::leader)
    {
        ensure_own_record();
        promote_learners();
    }
}

// ─── the ready ───

void raft_host::pump()
{
    m_pump_armed = false;
    if (m_stopped || m_wal.busy() || !m_node->has_ready())
        return;

    m_pending = m_node->take_ready();
    if (m_pending.soft)
    {
        const raft::soft_state& s = *m_pending.soft;
        if (s.role != m_soft.role || s.leader != m_soft.leader)
            info("term " + std::to_string(s.term) + ": this node is " + role_name(s.role)
                 + (s.leader ? ", leader " + describe(s.leader) : ", no leader known"));
        m_soft = s;
    }
    if (!m_pending.append.empty() || m_pending.truncate_from || m_pending.snap)
        refresh_book();

    if (m_wal.persist(m_pending, *m_node, [this](bool ok) { after_persist(ok); }))
        return;
    if (m_wal.failed())
        return fail_stop(m_wal.error());
    after_persist(true);
}

void raft_host::after_persist(bool ok)
{
    if (!ok)
        return fail_stop(m_wal.error());
    if (m_stopped)
        return;
    for (const raft::message& m : m_pending.messages)
        send(m);
    apply(m_pending);
    m_pending = raft::ready{};

    if (m_applied >= m_snap_index + m_cfg.compact_every && m_node->compact(m_applied, encode_snapshot(m_applied_book, m_brain->current())))
        m_snap_index = m_applied;
    arm_pump();
}

void raft_host::apply(const raft::ready& r)
{
    if (r.restore)
    {
        book b;
        socketley::cluster::state c;
        if (decode_snapshot(r.restore->data, b, c))
        {
            m_applied_book = std::move(b);
            m_brain->restore(std::move(c));
        }
        else
        {
            warn("a snapshot at " + std::to_string(r.restore->index) + " holds no readable membership book and cluster state");
        }
        m_applied = r.restore->index;
        info("installed a snapshot at " + std::to_string(r.restore->index) + " from the leader");
    }
    if (r.snap)
        m_snap_index = r.snap->index;
    for (const raft::entry& e : r.committed)
    {
        m_applied = e.index;
        if (e.type == raft::entry_type::config)
        {
            const raft::membership m = raft::decode_config(e.data);
            std::string v, l;
            for (raft::node_id id : m.voters)
                v += " " + describe(id);
            for (raft::node_id id : m.learners)
                l += " " + describe(id);
            info("membership at " + std::to_string(e.index) + ": voters" + v + (l.empty() ? "" : "; learners" + l));
            continue;
        }
        if (e.type != raft::entry_type::normal)
            continue;
        if (socketley::cluster::is_command(e.data))
        {
            apply_command(e.data, e.index);
            continue;
        }
        raft::node_id id = raft::no_node;
        member mb;
        if (decode_record(e.data, id, mb))
            m_applied_book[id] = mb;
    }
    m_brain->note_applied(m_applied);
    if (r.restore || !r.committed.empty())
        refresh_book();
}

void raft_host::apply_command(const std::string& data, raft::index_t index)
{
    namespace cl = socketley::cluster;
    cl::command c;
    if (!cl::decode(data, c))
    {
        warn("entry " + std::to_string(index) + " is a cluster command this node cannot read; every node skips it alike");
        return;
    }
    if (!m_brain->apply(c))
        return;
    switch (c.op)
    {
    case cl::op::create:
        info("cluster runtime " + c.name + " declared: " + c.sp.type + ", " + std::to_string(c.sp.replicas) + " replicas");
        break;
    case cl::op::remove:
        info("cluster runtime " + c.name + " removed");
        break;
    case cl::op::scale:
        info("cluster runtime " + c.name + " scaled to " + std::to_string(c.sp.replicas) + " replicas");
        break;
    case cl::op::assign:
        info("cluster runtime " + c.name + " assigned to " + describe(c.node));
        break;
    case cl::op::unassign:
        info("cluster runtime " + c.name + " taken from " + describe(c.node));
        break;
    }
}

void raft_host::fail_stop(const std::string& why)
{
    if (!m_fatal.empty())
        return;
    m_fatal = why;
    LOG_ERROR(("raft: " + why + "; this node stops taking part in the cluster until the daemon restarts").c_str());
    m_stopped = true;
    std::vector<link*> all;
    for (auto& [id, l] : m_out)
        all.push_back(l.get());
    for (auto& l : m_in)
        all.push_back(l.get());
    if (m_join_link)
        all.push_back(m_join_link.get());
    for (link* l : all)
        l->fail("the node stopped");
}

// ─── transport ───

void raft_host::send(const raft::message& m)
{
    if (m.to == m_id)
        return;
    link* l = outbound(m.to);
    if (!l)
    {
        ++m_dropped;
        return;
    }
    enqueue(l, wire::encode(m));
}

raft_host::link* raft_host::outbound(raft::node_id id)
{
    auto it = m_out.find(id);
    if (it != m_out.end() && it->second->state != link::phase::dead)
        return it->second.get();
    const auto now = clock::now();
    auto after = m_dial_after.find(id);
    if (after != m_dial_after.end() && now < after->second)
        return nullptr;
    const member* mb = lookup(id);
    if (!mb)
        return nullptr;

    auto l = std::make_unique<link>();
    l->host     = this;
    l->outbound = true;
    l->peer     = id;
    l->addr     = mb->addr;
    l->name     = mb->name;
    if (!parse_numeric(mb->addr, l->sa, l->salen))
        return nullptr;
    l->fd = ::socket(l->sa.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (l->fd < 0)
        return nullptr;
    int on = 1;
    if (::setsockopt(l->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on) < 0) {}
    socket_tuning::keepalive_dead_peer(l->fd);
    l->token = m_loop->register_owner(l.get());
    l->queue = ipc_frame::encode(wire::encode(wire::hello{m_id, m_cfg.name, m_cfg.advertise}));
    l->conn_req = io_request{l.get(), nullptr, l->fd, 0, op_connect};
    link* raw = l.get();
    m_dial_after[id] = now + std::chrono::milliseconds(500);
    if (!m_loop->submit_connect(l->fd, reinterpret_cast<sockaddr*>(&l->sa), l->salen, &l->conn_req))
    {
        m_loop->deregister_owner(raw);
        ::close(l->fd);
        return nullptr;
    }
    m_out[id] = std::move(l);
    return raw;
}

void raft_host::enqueue(link* l, const std::string& payload)
{
    if (payload.size() > ipc_frame::max_payload || l->queue.size() + payload.size() + ipc_frame::header_size > outbound_cap)
    {
        ++m_dropped;
        return;
    }
    l->queue += ipc_frame::encode(payload);
    ++m_sent;
    l->flush();
}

bool raft_host::on_frame(link& l, std::string_view payload)
{
    wire::frame f;
    std::string why;
    if (!wire::decode(payload, f, &why))
    {
        warn("refused a frame from " + (l.peer ? describe(l.peer) : std::string("an unidentified peer")) + ": " + why);
        return false;
    }

    if (!l.hello_seen)
    {
        if (f.kind != wire::kind::hello || f.hi.id == m_id)
            return false;
        const member* known = lookup(f.hi.id);
        const bool listed = known && m_book.count(f.hi.id);
        if (listed && known->name != f.hi.name)
        {
            warn("node " + hex_id(f.hi.id) + " introduced itself as " + f.hi.name + " but membership names it "
                 + known->name);
            return false;
        }
        // The certificate must name whom membership records for this id, or whom a newcomer claims to be.
        if (m_tls && !tls_context::peer_name_matches(l.ssl, f.hi.name))
        {
            warn("refused node " + hex_id(f.hi.id) + ": its certificate does not name " + f.hi.name);
            return false;
        }
        l.peer       = f.hi.id;
        l.name       = f.hi.name;
        l.hello_seen = true;
        if (!listed)
            m_heard_book[f.hi.id] = member{f.hi.name, f.hi.addr, true};
        m_heard[f.hi.id] = clock::now();
        return true;
    }

    switch (f.kind)
    {
    case wire::kind::message:
        if (f.msg.from != l.peer || f.msg.to != m_id)
            return false;
        // A stranger's vote request could still move this node's term, so only members and recorded nodes are heard, or anyone before this node has a membership.
        if (!m_node->is_member(l.peer) && !m_book.count(l.peer) && !m_node->voters().empty())
            return true;
        m_heard[l.peer] = clock::now();
        ++m_received;
        m_node->step(f.msg);
        arm_pump();
        return true;

    case wire::kind::join:
        // A newcomer asks for itself; a member may pass on a newcomer's request to the leader.
        if (f.req.id != l.peer && !m_node->is_member(l.peer))
            return false;
        // A newcomer's name is the one its hello was checked against, never a second one.
        if (f.req.id == l.peer && f.req.name != l.name)
            return false;
        handle_join(std::string(payload), f.req.id, f.req.name, f.req.addr, f.req.voter);
        return true;

    case wire::kind::command:
        // Only a member may hand the leader a command, and a leader that has since moved drops it, since the sender hears nothing either way.
        if (!m_node->is_member(l.peer))
            return false;
        handle_command(f.cmd.data);
        return true;

    case wire::kind::lease_req:
    case wire::kind::lease_grant:
    {
        if (!m_node->is_member(l.peer))
            return false;
        socketley::cluster::output out;
        const socketley::cluster::view v = make_view();
        if (f.kind == wire::kind::lease_req)
            m_brain->on_lease_req(l.peer, f.lease.nonce, now_ms(), v, out);
        else
            m_brain->on_lease_grant(l.peer, f.lease.nonce, f.lease.index, now_ms(), v);
        flush_cluster(out);
        return true;
    }

    case wire::kind::hello:
        return false;
    }
    return false;
}

void raft_host::handle_command(const std::string& data)
{
    socketley::cluster::command c;
    if (m_node->current_role() != raft::role::leader || !socketley::cluster::decode(data, c))
        return;
    if (m_node->propose(data).status == raft::propose_status::ok)
        arm_pump();
}

bool raft_host::submit(const std::string& data, std::string& err)
{
    socketley::cluster::command c;
    if (m_stopped || !socketley::cluster::decode(data, c))
    {
        err = "the cluster command is malformed\n";
        return false;
    }
    if (m_node->current_role() == raft::role::leader)
    {
        switch (m_node->propose(data).status)
        {
        case raft::propose_status::ok:
            arm_pump();
            return true;
        case raft::propose_status::busy:
            err = "the leader has too many uncommitted entries; try again shortly\n";
            return false;
        default:
            err = "leadership is moving; try again shortly\n";
            return false;
        }
    }
    const raft::node_id leader = m_node->leader();
    if (leader == raft::no_node)
    {
        err = "no leader is known: the cluster has no quorum or an election is running\n";
        return false;
    }
    link* l = outbound(leader);
    if (!l)
    {
        err = "the leader " + describe(leader) + " cannot be reached from this node\n";
        return false;
    }
    enqueue(l, wire::encode(wire::command{data}));
    return true;
}

void raft_host::handle_join(const std::string& payload, raft::node_id id, const std::string& name,
                            const std::string& addr, bool voter)
{
    if (m_node->current_role() != raft::role::leader)
    {
        const raft::node_id leader = m_node->leader();
        if (leader != raft::no_node && leader != m_id)
            if (link* l = outbound(leader))
                enqueue(l, payload);
        return;
    }

    auto it = m_book.find(id);
    if (it == m_book.end() || it->second.name != name || it->second.addr != addr || it->second.voter != voter)
    {
        const raft::proposal p = m_node->propose(encode_record(id, member{name, addr, voter}));
        if (p.status == raft::propose_status::ok)
        {
            info("recording node " + hex_id(id) + " as " + name + " at " + addr);
            m_book[id] = member{name, addr, voter};
        }
    }
    if (!m_node->is_member(id))
    {
        const raft::proposal p = m_node->propose_add_learner(id);
        if (p.status == raft::propose_status::ok)
            info("adding " + describe(id) + " as a learner");
    }
    arm_pump();
}

void raft_host::try_join()
{
    if (m_cfg.join.empty() || m_stopped)
        return;
    if (m_node->is_member(m_id))
    {
        if (m_join_link)
        {
            info("joined the cluster as a " + std::string(m_node->is_voter(m_id) ? "voter" : "learner"));
            m_join_link->fail("joined");
        }
        return;
    }
    if (!m_join_link || m_join_link->state == link::phase::dead)
    {
        if (m_join_link)
            return;
        auto l = std::make_unique<link>();
        l->host     = this;
        l->outbound = true;
        l->addr     = m_cfg.join;
        std::string host;
        if (!parse_numeric(m_cfg.join, l->sa, l->salen, &host))
            return;
        // The target's id is not known yet, so its certificate is held to the address that was dialled.
        l->name = host;
        l->fd   = ::socket(l->sa.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (l->fd < 0)
            return;
        l->token = m_loop->register_owner(l.get());
        l->queue = ipc_frame::encode(wire::encode(wire::hello{m_id, m_cfg.name, m_cfg.advertise}));
        l->conn_req = io_request{l.get(), nullptr, l->fd, 0, op_connect};
        if (!m_loop->submit_connect(l->fd, reinterpret_cast<sockaddr*>(&l->sa), l->salen, &l->conn_req))
        {
            m_loop->deregister_owner(l.get());
            ::close(l->fd);
            return;
        }
        m_join_link = std::move(l);
    }
    enqueue(m_join_link.get(), wire::encode(wire::join{m_id, m_cfg.name, m_cfg.advertise, true}));
}

void raft_host::promote_learners()
{
    const raft::index_t commit = m_node->commit_index();
    for (raft::node_id l : m_node->learners())
    {
        const member* mb = lookup(l);
        if (!mb || !mb->voter || m_node->match_index(l) < commit)
            continue;
        if (m_node->propose_add(l).status == raft::propose_status::ok)
        {
            info("promoting " + describe(l) + " to voter, its log caught up at " + std::to_string(commit));
            arm_pump();
        }
        return;
    }
}

void raft_host::ensure_own_record()
{
    auto it = m_book.find(m_id);
    if (it != m_book.end() && it->second.name == m_cfg.name && it->second.addr == m_cfg.advertise)
        return;
    const member me{m_cfg.name, m_cfg.advertise, true};
    if (m_node->propose(encode_record(m_id, me)).status == raft::propose_status::ok)
    {
        m_book[m_id] = me;
        arm_pump();
    }
}

void raft_host::retire(link* l)
{
    std::unique_ptr<link> owned;
    for (auto it = m_out.begin(); it != m_out.end(); ++it)
        if (it->second.get() == l)
        {
            owned = std::move(it->second);
            m_out.erase(it);
            break;
        }
    if (!owned)
        for (auto it = m_in.begin(); it != m_in.end(); ++it)
            if (it->get() == l)
            {
                owned = std::move(*it);
                m_in.erase(it);
                break;
            }
    if (!owned && m_join_link.get() == l)
        owned = std::move(m_join_link);
    if (!owned)
        return;

    // Closing through the loop cancels what is still queued on the descriptor, and the storage waits in the graveyard for those completions.
    if (l->fd >= 0)
        m_loop->close_fd(l->fd);
    l->fd = -1;
    m_loop->deregister_owner(l);
    m_graveyard.push_back(grave{std::move(owned), l->token});
}

void raft_host::reap()
{
    std::erase_if(m_graveyard, [this](const grave& g) { return m_loop->token_inflight(g.token) == 0; });
}

// ─── membership book ───

const raft_host::member* raft_host::lookup(raft::node_id id) const
{
    auto it = m_book.find(id);
    if (it != m_book.end())
        return &it->second;
    auto h = m_heard_book.find(id);
    return h == m_heard_book.end() ? nullptr : &h->second;
}

void raft_host::refresh_book()
{
    m_book = m_applied_book;
    for (raft::index_t i = std::max(m_applied, m_node->first_index() - 1) + 1; i <= m_node->last_index(); ++i)
    {
        const raft::entry* e = m_node->entry_at(i);
        raft::node_id id = raft::no_node;
        member mb;
        if (e && e->type == raft::entry_type::normal && decode_record(e->data, id, mb))
            m_book[id] = mb;
    }
}

std::string raft_host::describe(raft::node_id id) const
{
    const member* mb = lookup(id);
    return hex_id(id) + (mb ? "(" + mb->name + ")" : "");
}

std::string raft_host::encode_record(raft::node_id id, const member& m)
{
    std::string out = "M";
    put_u64(out, id);
    out += static_cast<char>(m.voter ? 1 : 0);
    out += static_cast<char>(std::min<size_t>(m.name.size(), 255));
    out.append(m.name, 0, 255);
    out += static_cast<char>(std::min<size_t>(m.addr.size(), 255));
    out.append(m.addr, 0, 255);
    return out;
}

bool raft_host::decode_record(std::string_view data, raft::node_id& id, member& m)
{
    size_t off = 1;
    if (data.empty() || data[0] != 'M' || !get_u64(data, off, id) || off >= data.size())
        return false;
    m.voter = data[off++] != 0;
    return get_label(data, off, m.name) && get_label(data, off, m.addr) && off == data.size();
}

std::string raft_host::encode_book(const book& b)
{
    std::string out = "B";
    for (const auto& [id, m] : b)
        out += encode_record(id, m).substr(1);
    return out;
}

bool raft_host::decode_book(std::string_view data, book& b)
{
    b.clear();
    if (data.empty() || data[0] != 'B')
        return false;
    size_t off = 1;
    while (off < data.size())
    {
        raft::node_id id = 0;
        member m;
        if (!get_u64(data, off, id) || off >= data.size())
            return false;
        m.voter = data[off++] != 0;
        if (!get_label(data, off, m.name) || !get_label(data, off, m.addr))
            return false;
        b[id] = std::move(m);
    }
    return true;
}

std::string raft_host::node_name(raft::node_id id) const
{
    const member* mb = lookup(id);
    return mb ? mb->name : hex_id(id);
}

// A snapshot is the membership book and the cluster state, each length-prefixed; an older one is the bare book.
std::string raft_host::encode_snapshot(const book& b, const socketley::cluster::state& c)
{
    socketley::bytes::writer w;
    w.u8('N');
    w.bytes(encode_book(b));
    w.bytes(socketley::cluster::encode(c));
    return w.take();
}

bool raft_host::decode_snapshot(std::string_view data, book& b, socketley::cluster::state& c)
{
    c = socketley::cluster::state{};
    if (!data.empty() && data[0] == 'B')
        return decode_book(data, b);
    socketley::bytes::reader r(data);
    uint8_t tag = 0;
    std::string book_bytes, cluster_bytes;
    if (!r.u8(tag) || tag != 'N' || !r.bytes(book_bytes, ipc_frame::max_payload)
        || !r.bytes(cluster_bytes, ipc_frame::max_payload) || r.left() != 0)
        return false;
    return decode_book(book_bytes, b) && socketley::cluster::decode(cluster_bytes, c);
}

// ─── shutdown and status ───

void raft_host::hand_over(event_loop& loop)
{
    if (!m_node || m_stopped || m_node->current_role() != raft::role::leader)
        return;
    raft::node_id best = raft::no_node;
    raft::index_t best_match = 0;
    for (raft::node_id v : m_node->voters())
        if (v != m_id && m_node->match_index(v) >= best_match)
        {
            best = v;
            best_match = m_node->match_index(v);
        }
    if (best == raft::no_node || !m_node->transfer_leadership(best))
        return;
    info("handing leadership to " + describe(best) + " before shutting down");
    arm_pump();
    const auto deadline = clock::now() + std::chrono::milliseconds(2ull * m_cfg.election_ticks * m_cfg.tick_ms);
    // Until the successor is heard from, so the report below names it rather than guessing.
    while (clock::now() < deadline && !m_stopped
           && (m_node->current_role() == raft::role::leader || m_node->leader() == raft::no_node))
        loop.poll_completions(static_cast<int>(m_cfg.tick_ms));
    // The follower this node became has a vote durable or in flight, so the ready it produced is written before exit.
    for (int i = 0; i < 200 && (m_wal.busy() || m_node->has_ready()) && !m_stopped; ++i)
    {
        arm_pump();
        loop.poll_completions(10);
    }
    if (m_node->current_role() == raft::role::leader)
        info("leadership did not move; stopping as leader");
    else if (m_node->leader() != raft::no_node && m_node->leader() != m_id)
        info("leadership handed over to " + describe(m_node->leader()));
    else
        info("stepped down; no new leader heard from yet");
}

void raft_host::stop()
{
    if (!m_loop)
        return;
    const bool was_stopped = m_stopped;
    m_stopped = true;
    if (m_tick_armed)
        if (!m_loop->submit_timeout_remove(&m_tick_req)) {}
    if (m_listen_fd >= 0)
    {
        m_loop->close_fd(m_listen_fd);
        m_listen_fd = -1;
    }
    if (!was_stopped)
    {
        std::vector<link*> all;
        for (auto& [id, l] : m_out)
            all.push_back(l.get());
        for (auto& l : m_in)
            all.push_back(l.get());
        if (m_join_link)
            all.push_back(m_join_link.get());
        for (link* l : all)
            l->fail("the daemon is stopping");
    }
    for (int i = 0; i < 300; ++i)
    {
        reap();
        if (m_graveyard.empty() && !m_wal.busy() && m_loop->owner_inflight(this) == 0)
            break;
        m_loop->poll_completions(10);
    }
    m_wal.retire();
    m_loop->deregister_owner(this);
}

std::string raft_host::status(int& exit_code) const
{
    std::string out;
    auto line = [&out](const char* k, const std::string& v)
    {
        char key[16];
        std::snprintf(key, sizeof key, "%-11s", (std::string(k) + ":").c_str());
        out += key;
        out += v;
        out += '\n';
    };

    const raft::node& n = *m_node;
    line("node", describe(m_id));
    line("role", m_fatal.empty() ? role_name(n.current_role()) : "stopped");
    line("term", std::to_string(n.term()));
    line("leader", n.leader() ? describe(n.leader()) : "none known");
    line("commit", std::to_string(n.commit_index()));
    line("applied", std::to_string(m_applied));
    line("log", std::to_string(n.first_index()) + ".." + std::to_string(n.last_index()) + " (snapshot at "
                + std::to_string(n.current_snapshot().index) + ")");

    std::string v, l;
    for (raft::node_id id : n.voters())
        v += (v.empty() ? "" : " ") + describe(id);
    for (raft::node_id id : n.learners())
        l += (l.empty() ? "" : " ") + describe(id);
    line("voters", v.empty() ? "none" : v);
    line("learners", l.empty() ? "none" : l);

    const auto now = clock::now();
    const auto window = std::chrono::milliseconds(static_cast<uint64_t>(m_cfg.election_ticks) * m_cfg.tick_ms);
    size_t heard = 0;
    for (raft::node_id id : n.voters())
    {
        if (id == m_id)
        {
            ++heard;
            continue;
        }
        auto it = m_heard.find(id);
        if (it != m_heard.end() && now - it->second <= window)
            ++heard;
    }
    const size_t quorum = n.voters().size() / 2 + 1;
    const bool reachable = !n.voters().empty() && heard >= quorum;
    line("quorum", std::string(reachable ? "reachable" : "NOT reachable") + " (" + std::to_string(heard) + " of "
                   + std::to_string(n.voters().size()) + " voters heard within "
                   + std::to_string(window.count()) + " ms)");
    const uint64_t at = now_ms();
    line("cluster", std::to_string(m_brain->current().specs.size()) + " runtime(s) declared, this node "
                    + (m_brain->serving(at) ? "may serve its replicas (lease " + std::to_string(m_brain->lease_left_ms(at)) + " ms left)"
                                            : std::string("holds no lease and serves none")));
    line("transport", std::string(m_tls ? "mutual TLS" : "cleartext (--raft-insecure)") + ", " + std::to_string(m_sent)
                      + " frames sent, " + std::to_string(m_received) + " received, " + std::to_string(m_dropped)
                      + " dropped");
    line("wal", m_cfg.dir + ", " + std::to_string(m_wal.fsyncs()) + " fsyncs, "
                + std::to_string(m_wal.bytes_written()) + " bytes");
    if (!m_fatal.empty())
        line("error", m_fatal);

    const bool leader_known = n.leader() != raft::no_node;
    if (!m_fatal.empty() || !leader_known || !reachable)
    {
        out += "no leader with a reachable quorum; cluster writes are refused\n";
        exit_code = 2;
    }
    else
    {
        exit_code = 0;
    }
    return out;
}
