#include "mail_run.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <charconv>
#include <thread>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/statvfs.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "mail_delivery.h"
#include "mail_compose.h"
#include "mail_instance.h"
#include "mail_lua.h"
#include "mail_mailbox.h"
#include "mail_rspamd.h"
#include "mail_srs.h"
#include "mail_verify.h"
#include "../idp/idp_session.h"
#include "../storage/password_hash.h"
#include "../../shared/crypto/mac.h"
#include "../../shared/util/random_id.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/net/dns_feed.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/runtime/stats_text.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

// The buffer group the runtime's reads take their buffers from, one per runtime type on a loop.
constexpr uint16_t ring_group = 7;
constexpr uint32_t ring_bufs = 1024;
constexpr uint32_t ring_buf_bytes = 4096;
constexpr int64_t close_grace_ms = 5000;
// An owned write chunk grows to this and no further.
constexpr size_t chunk_max = 256u << 10;
// A writer waiting on a slow client goes on once this little is left to write.
constexpr size_t drained_at = 256u << 10;
constexpr int64_t handshake_ms = 30000;
// RFC 5321 4.5.3.2.7 has a server wait five minutes for the next command, RFC 3501 5.4 an IMAP one thirty.
constexpr int64_t idle_ms = 300000;
constexpr int64_t imap_idle_ms = 31 * 60000;
// A wrong password is answered after this, so guessing one costs a client a second a try.
constexpr auto auth_delay = std::chrono::seconds(1);

// Connections one client address may hold: an MTA needs few, an office behind one address reading mail many.
constexpr uint32_t smtp_per_ip = 50;
constexpr uint32_t other_per_ip = 200;
// Without --max-connections, a runtime holds at most this many, so a crowd meets a refusal before the fd limit.
constexpr size_t default_max_conns = 8192;
// Sign-ins that failed from one address in this window lock it out for as long.
constexpr uint32_t auth_failures_max = 10;
constexpr int64_t auth_window_ms = 600000;
// Unread input or unsent output a connection may hold past what its largest message needs.
constexpr size_t backlog_slack = 1u << 20;
constexpr size_t owed_max = 32u << 20;

// An address as text, a client of a dual-stack listener that came over IPv4 in its IPv4 form.
std::string peer_ip(const sockaddr_storage& a)
{
    char host[INET6_ADDRSTRLEN] = {};
    if (a.ss_family == AF_INET)
        ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in&>(a).sin_addr, host, sizeof host);
    else if (a.ss_family == AF_INET6)
    {
        const in6_addr& v6 = reinterpret_cast<const sockaddr_in6&>(a).sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&v6))
            ::inet_ntop(AF_INET, v6.s6_addr + 12, host, sizeof host);
        else
            ::inet_ntop(AF_INET6, &v6, host, sizeof host);
    }
    return host;
}

// This machine's own programs, which may relay and sign in without TLS; 127.0.0.1 or ::1 and not all of 127/8, so a
// test can be a stranger from 127.0.0.2.
bool loopback(const sockaddr_storage& a)
{
    const std::string ip = peer_ip(a);
    return ip == "127.0.0.1" || ip == "::1";
}

}   // namespace

mail_run::mail_run(mail_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_fio(loop, this), m_pool(1 + std::clamp(std::thread::hardware_concurrency() / 2, 1u, 8u)),
      // The checks wait on DNS, not on a core, so there are more of them than of cores.
      m_checks(16), m_spool(loop, m_fio, m_pool),
      m_alive(std::make_shared<bool>(true))
{
}

mail_run::~mail_run()
{
    *m_alive = false;
    m_pool.stop();
    m_checks.stop();
    m_delivery.reset();
    m_mailboxes.reset();
    for (auto& [id, c] : m_conns)
        if (c->ssl)
            tls_context::free_ssl(c->ssl);
    for (auto& c : m_closing)
        if (c->ssl)
            tls_context::free_ssl(c->ssl);
    m_loop.deregister_owner(this);
}

uint32_t mail_run::shard() const
{
    return m_owner.get_shard_index();
}

bool mail_run::script_takes() const
{
    return m_lua && m_lua->wants_rcpt();
}

void mail_run::stored(const std::string& user, uint64_t size)
{
    const uint32_t warn = m_owner.get_quota_warn();
    const uint64_t quota = m_mailboxes ? m_mailboxes->quota_of(user) : 0;
    if (!warn || !quota || !m_imap || m_domains.empty())
        return;
    const uint64_t used = m_imap->usage(user), mark = quota / 100 * warn;
    // Told once as it passes the mark, and again only after it fell below it.
    if (used < mark)
    {
        m_quota_warned.erase(user);
        return;
    }
    if (used - std::min(used, size) >= mark || !m_quota_warned.insert(user).second)
        return;
    compose c;
    c.from = "postmaster@" + m_domains.front();
    c.to = {user.find('@') == std::string::npos ? user + "@" + m_domains.front() : user};
    c.subject = "Your mailbox is " + std::to_string(used * 100 / quota) + "% full";
    const auto amount = [](uint64_t b) {
        return b >= (uint64_t{1} << 20) ? std::to_string(b >> 20) + " MiB" : std::to_string((b + 1023) >> 10) + " KiB";
    };
    c.text = "Your mailbox holds " + amount(used) + " of the " + amount(quota) +
             " it may.\nOnce it is full, mail for you is refused until you delete some.\n";
    c.headers = {"Auto-Submitted: auto-generated"};
    std::string from, body, why;
    std::vector<std::string> rcpts;
    if (m_delivery && m_delivery->compose_message(c, from, rcpts, body, why))
        queue_message(from, rcpts, std::move(body), false, "local", [](bool, std::string) {});
}

void mail_run::send_reports()
{
    if (!m_owner.get_reports() || m_domains.empty() || !m_delivery)
        return;
    auto list = std::make_shared<std::vector<report_mail>>(
        m_reports.due(wall::now_ms() / 1000, m_hostname, "postmaster@" + m_domains.front()));
    if (list->empty())
        return;
    // A TLS report's address is its domain's _smtp._tls record's, looked up off the loop (RFC 8460 3).
    m_checks.submit(m_checks.next_lane(), [list] {
        auto r = system_check_resolver();
        for (auto& m : *list)
        {
            if (!m.to.empty())
                continue;
            std::string domain;
            for (const auto& [k, v] : m.headers)
                if (k == "TLS-Report-Domain")
                    domain = v;
            std::vector<std::string> txts;
            bool nx = false;
            if (domain.empty() || !r->txt("_smtp._tls." + domain, txts, nx))
                continue;
            for (const auto& t : txts)
            {
                std::string l = t;
                socketley::ascii::lower_in_place(l);
                if (!l.starts_with("v=tlsrptv1"))
                    continue;
                const size_t at = l.find("rua=");
                if (at == std::string::npos)
                    continue;
                std::string_view rest = std::string_view(t).substr(at + 4);
                rest = rest.substr(0, rest.find(';'));
                while (!rest.empty())
                {
                    const size_t comma = rest.find(',');
                    std::string_view uri = rest.substr(0, comma);
                    rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
                    while (!uri.empty() && uri.front() == ' ')
                        uri.remove_prefix(1);
                    if (uri.size() > 7 && socketley::ascii::iequals(uri.substr(0, 7), "mailto:"))
                        m.to.emplace_back(uri.substr(7));
                }
            }
        }
    }, [this, list, alive = m_alive] {
        if (!*alive)
            return;
        for (const auto& m : *list)
        {
            if (m.to.empty())
                continue;
            compose c;
            c.from = "postmaster@" + m_domains.front();
            c.to = m.to;
            c.subject = m.subject;
            c.text = "A report of the mail this server handled, attached.\n";
            for (const auto& [k, v] : m.headers)
                c.headers.push_back(k + ": " + v);
            c.attachments.push_back({m.filename, m.content_type, m.data});
            std::string from, body, why;
            std::vector<std::string> rcpts;
            if (!m_delivery->compose_message(c, from, rcpts, body, why))
                continue;
            ++m_reports_sent;
            queue_message(from, rcpts, std::move(body), false, "local", [](bool, std::string) {});
        }
    });
}

std::string_view mail_run::without_detail(std::string_view local) const
{
    const std::string_view delims = m_owner.get_recipient_delimiter();
    if (delims.empty())
        return local;
    const size_t cut = local.find_first_of(delims);
    // A local part that begins with the delimiter has no user before it, and is left as it is.
    return cut == std::string_view::npos || cut == 0 ? local : local.substr(0, cut);
}

std::string mail_run::sts_policy() const
{
    // The one exchanger every domain names, kept a week by the senders that fetch it (RFC 8461 3.2).
    return "version: STSv1\r\nmode: " + std::string(m_owner.get_mta_sts()) + "\r\nmx: " + m_hostname +
           "\r\nmax_age: 604800\r\n";
}

std::string mail_run::sts_id() const
{
    const std::string h = socketley::crypto::hmac_sha256("socketley mta-sts", sts_policy());
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < 10 && i < h.size(); ++i)
    {
        out += hex[static_cast<uint8_t>(h[i]) >> 4];
        out += hex[static_cast<uint8_t>(h[i]) & 15];
    }
    return out;
}

void mail_run::sts_input(conn& c, std::string_view bytes)
{
    c.sts_in.append(bytes.substr(0, std::min<size_t>(bytes.size(), 8192)));
    const size_t end = c.sts_in.find("\r\n\r\n");
    if (end == std::string::npos)
    {
        if (c.sts_in.size() >= 8192)
            close_conn(c);
        return;
    }
    // GET /.well-known/mta-sts.txt for mta-sts.<a domain of this runtime>, and nothing else.
    const std::string_view head(c.sts_in.data(), end);
    const std::string_view first = head.substr(0, head.find("\r\n"));
    std::string host;
    for (const auto& [name, value] : split_headers(head.substr(first.size() + 2)))
        if (socketley::ascii::iequals(name, "Host"))
        {
            std::string_view v = value;
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
                v.remove_prefix(1);
            host = std::string(v.substr(0, v.find_first_of(": \t\r\n")));
            socketley::ascii::lower_in_place(host);
        }
    const bool asked = first.starts_with("GET /.well-known/mta-sts.txt ") && host.starts_with("mta-sts.") &&
                       is_local_domain(std::string_view(host).substr(8));
    const std::string body = asked ? sts_policy() : std::string("not found\r\n");
    c.in_input = true;
    out(c, std::string(asked ? "HTTP/1.1 200 OK" : "HTTP/1.1 404 Not Found") +
               "\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(body.size()) +
               "\r\nCache-Control: max-age=86400\r\nConnection: close\r\n\r\n" + body);
    c.in_input = false;
    flush(c);
    close_soon(c);
}

bool mail_run::is_local_domain(std::string_view d) const
{
    for (const auto& x : m_domains)
        if (x == d)
            return true;
    return false;
}

route_to mail_run::route(const address& a, bool from_null) const
{
    std::string domain = a.domain;
    // The postmaster with no domain is the first domain's.
    if (domain.empty())
    {
        if (m_domains.empty())
            return {};
        domain = m_domains.front();
    }
    if (!is_local_domain(domain))
        return {route_to::remote, a.text()};
    if (m_owner.get_no_reply() && no_reply_local(a.local))
        return from_null ? route_to{route_to::sink, {}} : route_to{};
    // A bounce to an address SRS made of a sender goes back to that sender, where the address is this runtime's and
    // young enough; one it did not make is no one's.
    if (const std::string head = a.local.substr(0, 5);
        socketley::ascii::iequals(head, "srs0=") || socketley::ascii::iequals(head, "srs1="))
    {
        const std::string back = srs::reverse(a.local + "@" + domain, domain, m_verp_key,
                                              wall::now_ms() / 86400000);
        return back.empty() ? route_to{} : route_to{route_to::remote, back};
    }
    // The address as given first, then the user it is a tag of (user+tag).
    const std::string base(without_detail(a.local));
    const auto* t = m_aliases.value().find(a.local, domain);
    if (!t && base.size() != a.local.size())
        t = m_aliases.value().find(base, domain);
    if (t)
    {
        const std::string& first = t->front();
        return first.find('@') == std::string::npos ? route_to{route_to::mailbox, first}
                                                     : route_to{route_to::remote, first};
    }
    // A user's own address, which the mailboxes say is one or is not.
    if (m_mailboxes && m_mailboxes->enabled() && !m_owner.get_idp().empty())
        return {route_to::mailbox, base};
    return {};
}

bool mail_run::suppressed(std::string_view addr) const
{
    std::string a(addr);
    socketley::ascii::lower_in_place(a);
    return m_suppressed.count(a) > 0;
}

bool mail_run::no_reply_local(std::string_view local)
{
    return socketley::ascii::iequals(local, "no-reply") ||
           (local.size() > 9 && socketley::ascii::iequals(local.substr(0, 9), "no-reply+"));
}

std::string mail_run::verp_token(std::string_view domain) const
{
    std::string d(domain);
    socketley::ascii::lower_in_place(d);
    const std::string mac = socketley::crypto::hmac_sha256(m_verp_key, d);
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < 8 && i < mac.size(); ++i)
    {
        out += hex[static_cast<uint8_t>(mac[i]) >> 4];
        out += hex[static_cast<uint8_t>(mac[i]) & 15];
    }
    return out;
}

namespace
{

// The suppressed list as its file holds it: an address and when it bounced, a line each.
std::unordered_map<std::string, int64_t> parse_suppressed(std::string_view text, int64_t now_s)
{
    std::unordered_map<std::string, int64_t> out;
    while (!text.empty())
    {
        const std::string_view line = socketley::take_item(text, '\n');
        if (line.empty())
            continue;
        const size_t tab = line.find('\t');
        int64_t at = now_s;
        if (tab != std::string_view::npos)
            std::from_chars(line.data() + tab + 1, line.data() + line.size(), at);
        out[std::string(line.substr(0, tab))] = at;
    }
    return out;
}

constexpr int64_t suppressed_for_s = 90 * 86400;

}   // namespace

void mail_run::load_suppressed()
{
    const std::string path = mail_suppressed_path(m_owner.get_name());
    const auto stamp = socketley::file_stamp::of(path);
    if (m_suppressed_stamp && *m_suppressed_stamp == stamp)
        return;
    m_suppressed_stamp = stamp;
    std::string text;
    if (!socketley::read_file(path, text, {.missing_ok = true}, nullptr))
        return;
    std::unordered_set<std::string> got;
    for (auto& [a, at] : parse_suppressed(text, wall::now_ms() / 1000))
        got.insert(a);
    m_suppressed = std::move(got);
}

void mail_run::edit_suppressed(std::vector<std::string> add, std::vector<std::string> remove)
{
    for (const auto& a : add)
        m_suppressed.insert(a);
    for (const auto& a : remove)
        m_suppressed.erase(a);
    // Read, merged and written under a lock of the file, so two shards' changes are both kept; never on the loop.
    auto result = std::make_shared<std::unordered_set<std::string>>();
    auto why = std::make_shared<std::string>();
    const std::string path = mail_suppressed_path(m_owner.get_name());
    m_pool.submit(0,
                  [path, add = std::move(add), remove = std::move(remove), result, why] {
                      const int lock = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
                      if (lock >= 0 && ::flock(lock, LOCK_EX) != 0) {}
                      std::string text;
                      const int64_t now_s = socketley::wall::now_ms() / 1000;
                      auto all = socketley::read_file(path, text, {.missing_ok = true}, nullptr)
                                     ? parse_suppressed(text, now_s)
                                     : std::unordered_map<std::string, int64_t>{};
                      std::erase_if(all, [now_s](const auto& kv) { return now_s - kv.second > suppressed_for_s; });
                      for (const auto& a : add)
                          all[a] = now_s;
                      for (const auto& a : remove)
                          all.erase(a);
                      std::string out;
                      for (const auto& [a, at] : all)
                      {
                          out += a + "\t" + std::to_string(at) + "\n";
                          result->insert(a);
                      }
                      if (!socketley::replace_file(path, out, socketley::durability::data, why.get()) && why->empty())
                          *why = "it could not be written";
                      if (lock >= 0)
                          ::close(lock);
                  },
                  [this, result, why, path, alive = m_alive] {
                      if (!*alive)
                          return;
                      if (!why->empty())
                      {
                          LOG_WARN(("mail " + std::string(m_owner.get_name()) +
                                    ": the suppressed addresses could not be kept: " + *why).c_str());
                          return;
                      }
                      m_suppressed = std::move(*result);
                      m_suppressed_stamp = socketley::file_stamp::of(path);
                  });
}

void mail_run::bounce_taken(std::string_view message, std::string_view to, bool trusted)
{
    ++m_bounces_taken;
    const size_t plus = to.find('+'), at = to.rfind('@');
    const std::string_view token = plus != std::string_view::npos && at != std::string_view::npos && plus < at
                                       ? to.substr(plus + 1, at - plus - 1)
                                       : std::string_view{};
    // A delivery status report names each recipient, then what was done with it (RFC 3464 2.3).
    std::vector<std::string> dead;
    bool unverified = false;
    std::string_view rest = message;
    std::string recipient;
    while (!rest.empty())
    {
        const size_t nl = rest.find('\n');
        std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view name = line.substr(0, colon);
        std::string_view value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ')
            value.remove_prefix(1);
        if (socketley::ascii::iequals(name, "Final-Recipient"))
        {
            const size_t semi = value.find(';');
            recipient = std::string(semi == std::string_view::npos ? value : value.substr(semi + 1));
            while (!recipient.empty() && recipient.front() == ' ')
                recipient.erase(0, 1);
            socketley::ascii::lower_in_place(recipient);
        }
        else if (socketley::ascii::iequals(name, "Action") && !recipient.empty())
        {
            const size_t ra = recipient.rfind('@');
            if (socketley::ascii::iequals(value.substr(0, 6), "failed") && ra != std::string::npos)
            {
                if (trusted || (!token.empty() && token == verp_token(std::string_view(recipient).substr(ra + 1))))
                {
                    if (!m_suppressed.count(recipient) &&
                        std::find(dead.begin(), dead.end(), recipient) == dead.end())
                        dead.push_back(recipient);
                }
                else
                    unverified = true;
            }
            recipient.clear();
        }
    }
    m_bounces_unverified += unverified;
    if (dead.empty())
        return;
    m_suppressions += dead.size();
    edit_suppressed(std::move(dead), {});
}

// ── Starting and stopping ───────────────────────────────────────────────────

bool mail_run::start(std::string& why)
{
    m_loop.register_owner(this);
    if (!m_pool.attach(m_fio))
        m_pool.stop();
    if (!m_checks.attach(m_fio))
        m_checks.stop();
    m_state_dir = mail_state_dir(m_owner.get_name(), m_owner.get_shard_index(), m_owner.get_shards());
    std::error_code ec;
    std::filesystem::create_directories(m_state_dir, ec);
    if (::chmod(m_state_dir.c_str(), 0700) != 0) {}
    if (!m_spool.open(m_state_dir + "/spool", false, why))
        return false;
    m_domains = m_owner.domains();
    m_arc_trusted.clear();
    for (std::string_view rest = m_owner.get_arc_trust(); !rest.empty();)
    {
        const size_t comma = rest.find(',');
        if (const std::string_view d = rest.substr(0, comma); !d.empty())
            m_arc_trusted.emplace_back(d);
        rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
    }
    m_hostname = m_owner.greeting_name();
    if (!m_owner.get_dnsbl().empty())
    {
        m_dnsbl = std::make_unique<dnsbl>(m_fio);
        m_dnsbl->set_zones(m_owner.get_dnsbl());
    }
    refresh_domains();
    load_suppressed();
    // The key of no-reply mail's tags, made by the first shard to start and read by the others.
    {
        const std::string path = mail_verp_key_path(m_owner.get_name());
        const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0)
        {
            const std::string key = socketley::random_hex(32);
            if (key.empty() || !socketley::write_all(fd, key.data(), key.size()) || ::fsync(fd) != 0) {}
            ::close(fd);
        }
        for (int tries = 0; tries < 50 && m_verp_key.size() < 64; ++tries)
        {
            if (!socketley::read_file(path, m_verp_key, {.missing_ok = true}, nullptr))
                m_verp_key.clear();
            if (m_verp_key.size() < 64)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (m_verp_key.size() < 64)
        {
            why = path + " holds no key for no-reply mail's tags";
            return false;
        }
    }
    if (m_owner.get_tls())
    {
        m_tls = std::make_unique<tls_context>();
        if (!m_tls->init_server(m_owner.get_cert_path(), m_owner.get_key_path(), m_owner.get_ca_path()))
        {
            why = "the certificate or key could not be loaded";
            return false;
        }
    }
    if (!m_owner.get_idp().empty())
    {
        m_idp = std::make_unique<socketley::idp::session_verifier>();
        m_idp->configure(m_owner.get_idp());
    }
    m_users.set_path(std::string(m_owner.get_users()));
    m_aliases.set_path(std::string(m_owner.get_aliases()));
    std::string file_why;
    if (!m_users.refresh([](user_table& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                         file_why) ||
        !m_aliases.refresh([](alias_table& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                           file_why))
    {
        why = file_why;
        return false;
    }
    m_lua = std::make_unique<mail_lua>(m_owner);
    m_mailboxes = std::make_unique<mailboxes>(*this);
    if (!m_mailboxes->configure(why))
        return false;
    if (const std::string path(m_owner.get_notify_targets()); !path.empty())
    {
        std::vector<socketley::notify_target> targets;
        if (!socketley::load_notify_targets(path, targets, why))
            return false;
        for (const auto& t : targets)
            m_notify_names.push_back(t.name);
        m_notify = std::make_unique<socketley::notifier>(m_loop, m_fio, this, "mail " + std::string(m_owner.get_name()));
        m_notify->set_targets(std::move(targets));
        m_notify->set_runtimes(m_owner.get_runtime_manager(), std::string(m_owner.get_name()));
        if (!m_notify->open(m_state_dir, ".notify", m_owner.get_shard_index(), [](std::string_view) { return true; },
                            why))
            return false;
        m_mailboxes->on_stored = [this](const mailboxes::stored_info& s) {
            std::string j = "{\"event\":\"mail.received\",\"id\":";
            socketley::json::quote_into(j, s.id);
            j += ",\"mailbox\":";
            socketley::json::quote_into(j, s.user);
            j += ",\"folder\":";
            socketley::json::quote_into(j, s.folder);
            j += ",\"key\":";
            socketley::json::quote_into(j, s.key);
            j += ",\"from\":";
            socketley::json::quote_into(j, s.from);
            j += ",\"subject\":";
            socketley::json::quote_into(j, s.subject);
            j += ",\"size\":" + std::to_string(s.size) + "}";
            for (const auto& n : m_notify_names)
                m_notify->add(n, j, "mail/" + s.user);
        };
    }
    m_ring = m_loop.setup_buf_ring(ring_group, ring_bufs, ring_buf_bytes);
    m_multishot = m_ring && m_loop.recv_multishot_enabled();
    if (!open_listener(m_smtp, m_owner.effective_port(), port_kind::smtp, why))
        return false;
    if (m_owner.get_submission_port() &&
        !open_listener(m_sub, m_owner.get_submission_port(), port_kind::submission, why))
        return false;
    if (m_owner.get_submissions_port() &&
        !open_listener(m_subs, m_owner.get_submissions_port(), port_kind::submissions, why))
        return false;
    // IMAP on every shard, each reading the others' changes from the users' journals.
    if (m_mailboxes && m_mailboxes->enabled())
    {
        m_imap = std::make_unique<imap_store>(*this);
        if (m_owner.get_imap_port() && !open_listener(m_imap_l, m_owner.get_imap_port(), port_kind::imap, why))
            return false;
        if (m_owner.get_imaps_port() && !open_listener(m_imaps_l, m_owner.get_imaps_port(), port_kind::imaps, why))
            return false;
    }
    // Sieve filters the mail a mailbox takes, so its scripts are every shard's, and ManageSieve listens on each.
    if (m_mailboxes && m_mailboxes->enabled())
    {
        m_sieve = std::make_unique<sieve_store>(mail_sieve_dir(m_owner.get_name()));
        if (m_owner.get_sieve_port() &&
            !open_listener(m_sieve_l, m_owner.get_sieve_port(), port_kind::sieve, why))
            return false;
    }
    else if (m_owner.get_sieve_port())
    {
        why = "--sieve keeps the filters of mailboxes, which need --idp and --storage";
        return false;
    }
    // POP3 reads the INBOX IMAP keeps, and LMTP hands mail to the mailboxes, on every shard.
    if (m_mailboxes && m_mailboxes->enabled() && m_imap)
    {
        if (m_owner.get_pop3_port() && !open_listener(m_pop3_l, m_owner.get_pop3_port(), port_kind::pop3, why))
            return false;
        if (m_owner.get_pop3s_port() && !open_listener(m_pop3s_l, m_owner.get_pop3s_port(), port_kind::pop3s, why))
            return false;
    }
    if (m_mailboxes && m_mailboxes->enabled() && m_owner.get_lmtp_port() &&
        !open_listener(m_lmtp_l, m_owner.get_lmtp_port(), port_kind::lmtp, why))
        return false;
    if (m_owner.get_mta_sts_port() && !open_listener(m_sts_l, m_owner.get_mta_sts_port(), port_kind::sts, why))
        return false;
    if (m_owner.get_greylist())
        m_greylist = std::make_unique<greylist>(
            (std::filesystem::path(mail_suppressed_path(m_owner.get_name())).parent_path() /
             (std::string(m_owner.get_name()) + ".greylist"))
                .string(),
            static_cast<int64_t>(m_owner.get_greylist()) * 1000);
    m_delivery = std::make_unique<delivery>(*this);
    if (!m_delivery->start(why))
        return false;
    for (listener* l : listeners())
        if (l->fd >= 0)
            arm_accept(*l);
    publish_records();
    arm_tick();
    LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": serving SMTP on " +
              std::to_string(m_owner.effective_port()) +
              (m_sub.fd >= 0 ? ", submission on " + std::to_string(m_owner.get_submission_port()) : std::string()) +
              (m_subs.fd >= 0 ? ", submission over TLS on " + std::to_string(m_owner.get_submissions_port())
                              : std::string()) +
              " as " + m_hostname + ", " + std::to_string(m_spool.entries().size()) + " message(s) queued")
                 .c_str());
    return true;
}

bool mail_run::open_listener(listener& l, uint16_t port, port_kind kind, std::string& why)
{
    l.kind = kind;
    // With no address to bind, one socket takes IPv6 and IPv4 alike, as an MX reachable over both must; an IPv6
    // address binds that alone, and an IPv4 one, or a kernel without IPv6, IPv4.
    const std::string_view bind = m_owner.get_bind_address();
    in6_addr v6{};
    const bool v6_bind = bind.find(':') != std::string_view::npos &&
                         ::inet_pton(AF_INET6, std::string(bind).c_str(), &v6) == 1;
    const bool dual = bind.empty();
    l.fd = dual || v6_bind ? ::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) : -1;
    const bool six = l.fd >= 0;
    if (!six)
        l.fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (l.fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1, zero = 0;
    ::setsockopt(l.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    // Every shard binds the ports, and the kernel spreads the connections over them.
    if (m_owner.get_shards() > 1)
        ::setsockopt(l.fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    sockaddr_storage st{};
    socklen_t len = 0;
    if (six)
    {
        ::setsockopt(l.fd, IPPROTO_IPV6, IPV6_V6ONLY, dual ? &zero : &one, sizeof one);
        auto& a = reinterpret_cast<sockaddr_in6&>(st);
        a.sin6_family = AF_INET6;
        a.sin6_addr = dual ? in6addr_any : v6;
        a.sin6_port = htons(port);
        len = sizeof a;
    }
    else
    {
        auto& a = reinterpret_cast<sockaddr_in&>(st);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = m_owner.bind_in_addr();
        a.sin_port = htons(port);
        len = sizeof a;
    }
    if (::bind(l.fd, reinterpret_cast<sockaddr*>(&st), len) < 0 || ::listen(l.fd, 4096) < 0)
    {
        why = "port " + std::to_string(port) + " could not be bound: " + std::strerror(errno);
        ::close(l.fd);
        l.fd = -1;
        return false;
    }
    return true;
}

void mail_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    for (listener* l : listeners())
        if (l->fd >= 0)
        {
            ::shutdown(l->fd, SHUT_RDWR);
            m_loop.close_fd(l->fd);
            l->fd = -1;
        }
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    if (m_delivery)
        m_delivery->stop();
    if (m_notify)
        m_notify->stop();
    if (m_imap)
        m_imap->flush_now();
    std::vector<conn*> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c.get());
    for (conn* c : all)
        close_conn(*c);
    m_pool.stop();
    m_checks.stop();
    // How many messages the spool still holds, for a remove that would otherwise delete mail it took.
    if (!m_spool.dir().empty())
    {
        const std::string n = std::to_string(m_spool.entries().size()) + "\n";
        const int fd = ::open((m_spool.dir() + "/queued").c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd >= 0)
        {
            if (!socketley::write_all(fd, n.data(), n.size())) {}
            ::close(fd);
        }
    }
    m_spool.close();
    *m_alive = false;
}

bool mail_run::drained() const
{
    return m_loop.owner_drained(this) && (!m_delivery || m_delivery->drained());
}

// ── Accepting ───────────────────────────────────────────────────────────────

void mail_run::arm_accept(listener& l)
{
    if (m_stopped || l.fd < 0 || l.pending)
        return;
    l.req = io_request{};
    l.req.owner = this;
    l.req.fd = l.fd;
    l.req.type = event_loop::supports_multishot_accept() ? op_multishot_accept : op_accept;
    l.pending = l.req.type == op_multishot_accept ? m_loop.submit_multishot_accept(l.fd, &l.req)
                                                  : m_loop.submit_accept(l.fd, nullptr, nullptr, &l.req);
}

void mail_run::accept_done(listener& l, struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
        l.pending = false;
    const int fd = cqe->res;
    if (fd >= 0)
    {
        sockaddr_storage peer{};
        socklen_t len = sizeof peer;
        if (::getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &len) < 0) {}
        const std::string ip = peer_ip(peer);
        const bool smtp_port = l.kind == port_kind::smtp || l.kind == port_kind::submission || l.kind == port_kind::lmtp;
        const bool imap_port = l.kind == port_kind::imap || l.kind == port_kind::imaps;
        const size_t limit = m_owner.get_max_connections() ? m_owner.get_max_connections() : default_max_conns;
        const uint32_t per_ip = l.kind == port_kind::smtp ? smtp_per_ip : other_per_ip;
        const bool full = limit && m_conns.size() >= limit;
        const bool crowded = !loopback(peer) && m_clients[ip].conns >= per_ip;
        // LMTP takes mail for the mailboxes with no check of it, so only a server on this machine may speak it.
        const bool stranger = l.kind == port_kind::lmtp && !loopback(peer);
        if (m_stopped || full || crowded || stranger)
        {
            // Refused with a word where the port speaks first in the clear, so a client knows it is a full server.
            const std::string why = stranger ? "LMTP is for this machine"
                                    : full   ? "too many connections"
                                             : "too many connections from " + ip;
            const std::string said = smtp_port ? "421 4.7.0 " + m_hostname + " " + why + ", try again later\r\n"
                                     : imap_port && l.kind == port_kind::imap ? "* BYE " + why + "\r\n"
                                     : l.kind == port_kind::sieve ? "BYE \"" + why + "\"\r\n"
                                     : l.kind == port_kind::pop3  ? "-ERR [SYS/TEMP] " + why + "\r\n"
                                                                  : std::string();
            if (!m_stopped && !said.empty() && ::send(fd, said.data(), said.size(), MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {}
            if (m_clients[ip].conns == 0 && m_clients[ip].failures == 0)
                m_clients.erase(ip);
            m_loop.close_fd(fd);
        }
        else
        {
            auto c = std::make_unique<conn>();
            c->run = this;
            c->id = m_next_id++;
            c->fd = fd;
            c->kind = l.kind;
            c->peer = peer;
            c->ip = ip;
            ++m_clients[ip].conns;
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->closing_ms = c->heard_ms = wall::now_ms_coarse();
            conn* raw = c.get();
            m_conns.emplace(raw->id, std::move(c));
            runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
            m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            // A port that speaks TLS from the first byte begins with the handshake, any other with the greeting.
            if (l.kind == port_kind::submissions || l.kind == port_kind::imaps || l.kind == port_kind::pop3s ||
                l.kind == port_kind::sts)
            {
                raw->ssl = m_tls ? m_tls->create_ssl_server() : nullptr;
                if (!raw->ssl)
                {
                    close_conn(*raw);
                    raw = nullptr;
                }
            }
            else
                begin_session(*raw);
            if (raw && !raw->dead)
                arm_read(*raw);
        }
    }
    // Out of descriptors, the next accept fails the same way at once: it waits a tenth of a second instead.
    if (fd == -EMFILE || fd == -ENFILE)
    {
        m_accept_paused_until_ms = wall::now_ms_coarse() + 100;
        return;
    }
    if (!l.pending && !m_stopped && fd != -ECANCELED)
        arm_accept(l);
}

smtp_config mail_run::session_config(const conn& c) const
{
    smtp_config cfg;
    cfg.hostname = m_hostname;
    cfg.max_size = m_owner.get_max_size();
    cfg.max_rcpt = m_owner.get_max_recipients();
    cfg.tls_offered = m_tls != nullptr && c.kind != port_kind::submissions;
    cfg.tls_active = c.ssl != nullptr && c.handshaken;
    const bool signs_in = !m_owner.get_users().empty() || m_idp != nullptr;
    cfg.auth_offered = signs_in;
    // A loopback peer is this machine, whose own programs need no TLS to sign in.
    cfg.auth_in_clear = loopback(c.peer);
    cfg.auth_required = c.kind != port_kind::smtp && c.kind != port_kind::lmtp;
    cfg.tls_required = c.kind == port_kind::submission && m_tls != nullptr && !loopback(c.peer);
    // LMTP is a server on this machine handing mail over: no TLS and no sign-in, as RFC 2033 has it.
    if (c.kind == port_kind::lmtp)
    {
        cfg.lmtp = true;
        cfg.tls_offered = false;
        cfg.auth_offered = false;
    }
    return cfg;
}

void mail_run::begin_session(conn& c)
{
    c.in_input = true;
    if (c.kind == port_kind::sieve)
    {
        managesieve_config cfg;
        cfg.hostname = m_hostname;
        cfg.tls_offered = m_tls != nullptr;
        cfg.tls_active = c.ssl != nullptr && c.handshaken;
        cfg.login_in_clear = loopback(c.peer);
        c.sieve = std::make_unique<managesieve_session>(cfg, c, *m_sieve);
        c.sieve->greet();
    }
    else if (c.kind == port_kind::pop3 || c.kind == port_kind::pop3s)
    {
        pop3_config cfg;
        cfg.hostname = m_hostname;
        cfg.tls_offered = m_tls != nullptr && c.kind == port_kind::pop3;
        cfg.tls_active = c.ssl != nullptr && c.handshaken;
        cfg.login_in_clear = loopback(c.peer);
        c.pop3 = std::make_unique<pop3_session>(cfg, c);
        c.pop3->greet();
    }
    else if (c.kind == port_kind::sts)
        c.sts = true;
    else if (c.kind == port_kind::imap || c.kind == port_kind::imaps)
    {
        imap_config cfg;
        cfg.hostname = m_hostname;
        cfg.tls_offered = m_tls != nullptr && c.kind == port_kind::imap;
        cfg.tls_active = c.ssl != nullptr && c.handshaken;
        cfg.login_in_clear = loopback(c.peer);
        cfg.max_append = m_owner.get_max_size();
        if (m_sieve && m_owner.get_sieve_port())
            cfg.imapsieve = "sieve://" + m_hostname + ":" + std::to_string(m_owner.get_sieve_port());
        c.imap = std::make_unique<imap_session>(cfg, c, *m_imap);
        c.imap->greet();
    }
    else
    {
        c.smtp = std::make_unique<smtp_session>(session_config(c), c);
        c.smtp->greet();
        // A stranger's address is asked of the blocklists while it greets, so MAIL seldom waits for them.
        if (c.kind == port_kind::smtp && m_dnsbl && m_dnsbl->enabled() && !loopback(c.peer))
        {
            c.blocklist = 1;
            m_dnsbl->check(c.ip, [this, id = c.id, alive = m_alive](std::string zone) {
                conn* x = *alive ? find(id) : nullptr;
                if (!x || x->dead)
                    return;
                x->blocklist = zone.empty() ? 2 : 3;
                x->listed_by = std::move(zone);
                if (auto go = std::move(x->after_blocklist))
                {
                    x->in_input = true;
                    go();
                    x->in_input = false;
                    flush(*x);
                }
            });
        }
    }
    c.in_input = false;
    flush(c);
}

// ── Reading ─────────────────────────────────────────────────────────────────

mail_run::conn* mail_run::conn_of(io_request* req)
{
    auto* raw = reinterpret_cast<conn*>(req->buffer);
    if (const auto it = m_conns.find(raw->id); it != m_conns.end() && it->second.get() == raw)
        return raw;
    for (const auto& c : m_closing)
        if (c.get() == raw)
            return raw;
    return nullptr;
}

mail_run::conn* mail_run::find(uint64_t id)
{
    const auto it = m_conns.find(id);
    return it == m_conns.end() ? nullptr : it->second.get();
}

void mail_run::arm_read(conn& c)
{
    if (c.dead || c.rd_pending || c.fd < 0)
        return;
    c.rd = io_request{};
    c.rd.owner = this;
    c.rd.buffer = reinterpret_cast<char*>(&c);
    c.rd.fd = c.fd;
    c.rearm = false;
    if (m_multishot)
    {
        c.rd.type = op_recv_multishot;
        c.rd.buf_group = static_cast<uint8_t>(ring_group);
        c.rd_pending = m_loop.submit_recv_multishot(c.fd, ring_group, &c.rd);
    }
    else
    {
        if (!c.rbuf)
            c.rbuf = std::make_unique<char[]>(ring_buf_bytes);
        c.rd.type = op_read;
        c.rd_pending = m_loop.submit_read(c.fd, c.rbuf.get(), ring_buf_bytes, &c.rd);
    }
    if (!c.rd_pending)
    {
        c.rearm = true;
        retry_io(c);
    }
}

void mail_run::retry_io(conn& c)
{
    m_retry_io.push_back(c.id);
}

void mail_run::read_done(conn& c, struct io_uring_cqe* cqe)
{
    const int res = cqe->res;
    if (c.rd.type == op_recv_multishot)
    {
        const bool more = cqe->flags & IORING_CQE_F_MORE;
        if (!more)
            c.rd_pending = false;
        if (res > 0)
        {
            m_loop.for_each_cqe_buf(ring_group, cqe, [&](const char* p, uint32_t n) {
                if (!c.dead)
                    bytes_in(c, p, n);
            });
        }
        else if (cqe->flags & IORING_CQE_F_BUFFER)
            m_loop.return_cqe_buf(cqe, &c.rd);
        if (c.dead)
            return;
        if (res == -ENOBUFS)
        {
            if (!more)
            {
                c.rearm = true;
                retry_io(c);
            }
            return;
        }
        if (res <= 0)
        {
            close_conn(c);
            return;
        }
        if (!more)
            arm_read(c);
        return;
    }
    c.rd_pending = false;
    if (c.dead)
        return;
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    bytes_in(c, c.rbuf.get(), static_cast<size_t>(res));
    if (!c.dead)
        arm_read(c);
}

void mail_run::bytes_in(conn& c, const char* p, size_t n)
{
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, n);
    c.heard_ms = wall::now_ms_coarse();
    if (c.ssl)
        tls_in(c, p, n);
    else
        plain_in(c, p, n);
}

void mail_run::tls_in(conn& c, const char* p, size_t n)
{
    if (tls_context::bio_write_in(c.ssl, p, static_cast<int>(n)) < 0)
    {
        close_conn(c);
        return;
    }
    if (!c.handshaken)
    {
        const int r = tls_context::do_handshake(c.ssl);
        queue_tls_out(c);
        flush(c);
        if (r < 0)
        {
            ++m_tls_failures;
            close_conn(c);
            return;
        }
        if (r == 0)
            return;
        c.handshaken = true;
        if (c.upgrading)
        {
            c.upgrading = false;
            ++m_starttls;
            c.in_input = true;
            if (c.imap)
                c.imap->tls_started();
            else if (c.sieve)
                c.sieve->tls_started();
            else if (c.pop3)
                c.pop3->tls_started();
            else
                c.smtp->tls_started();
            c.in_input = false;
            flush(c);
        }
        else
            begin_session(c);
        if (c.dead)
            return;
    }
    char buf[16384];
    while (!c.dead)
    {
        const int r = tls_context::ssl_read(c.ssl, buf, sizeof buf);
        if (r > 0)
        {
            plain_in(c, buf, static_cast<size_t>(r));
            continue;
        }
        if (r < 0)
            close_conn(c);
        break;
    }
    if (!c.dead && tls_context::has_pending_out(c.ssl))
    {
        queue_tls_out(c);
        flush(c);
    }
}

void mail_run::plain_in(conn& c, const char* p, size_t n)
{
    if (c.sts)
    {
        sts_input(c, std::string_view(p, n));
        return;
    }
    if (!c.smtp && !c.imap && !c.sieve && !c.pop3)
        return;
    // Under COMPRESS what came is opened first, a bounded amount at a time.
    if (c.zin)
    {
        c.zin->feed(reinterpret_cast<const uint8_t*>(p), n);
        for (;;)
        {
            c.zopened.clear();
            const auto r = c.zin->run(c.zopened, 1u << 20);
            if (r == socketley::inflater::result::bad || r == socketley::inflater::result::done)
            {
                close_conn(c);
                return;
            }
            if (!c.zopened.empty())
            {
                c.in_input = true;
                c.imap->input(c.zopened);
                c.in_input = false;
                if (c.dead)
                    return;
            }
            if (r == socketley::inflater::result::need_input)
                break;
        }
        flush(c);
        return;
    }
    c.in_input = true;
    if (c.imap)
        c.imap->input(std::string_view(p, n));
    else if (c.sieve)
        c.sieve->input(std::string_view(p, n));
    else if (c.pop3)
        c.pop3->input(std::string_view(p, n));
    else
        c.smtp->input(std::string_view(p, n));
    c.in_input = false;
    if (c.dead)
        return;
    // A client that sends past what a command and its largest message take while one waits, or that reads none of
    // what it is told, is not held in memory: it is told so and closed.
    const size_t cap = (c.sieve || c.pop3 ? 0 : m_owner.get_max_size()) + backlog_slack;
    const size_t held = c.imap ? c.imap->buffered() : c.sieve ? c.sieve->buffered() : c.pop3 ? c.pop3->buffered()
                                                                                         : c.smtp->buffered();
    if (held > cap || c.owed > owed_max + cap)
    {
        out(c, c.smtp ? "421 4.7.0 " + m_hostname + " too much input unanswered, closing\r\n"
               : c.imap ? std::string("* BYE Too much input unanswered\r\n")
               : c.pop3 ? std::string("-ERR too much input unanswered\r\n")
                        : std::string("BYE \"Too much input\"\r\n"));
        close_soon(c);
        return;
    }
    flush(c);
}

// ── Writing ─────────────────────────────────────────────────────────────────

void mail_run::out(conn& c, std::string_view bytes)
{
    if (c.dead)
        return;
    // Under COMPRESS, what a turn of the loop says goes out as one compressed block, at its flush.
    if (c.zout)
    {
        c.zplain.append(bytes);
        if (!c.reflush)
            retry_io(c);
        c.reflush = true;
        return;
    }
    send_raw(c, bytes);
    // Replies said while input is taken go in one write once all of it is, as pipelining wants them.
    if (!c.in_input)
        flush(c);
}

void mail_run::send_raw(conn& c, std::string_view bytes)
{
    if (c.ssl && c.handshaken && !c.upgrading)
    {
        // The record layer takes so much before what it made is taken out, which is done after each piece.
        size_t off = 0;
        while (off < bytes.size())
        {
            const int w = tls_context::ssl_write(c.ssl, bytes.data() + off,
                                                 static_cast<int>(std::min<size_t>(bytes.size() - off, 256u << 10)));
            queue_tls_out(c);
            if (w <= 0)
            {
                close_conn(c);
                return;
            }
            off += static_cast<size_t>(w);
        }
    }
    else
        queue_owned(c, bytes);
}

void mail_run::queue_owned(conn& c, std::string_view bytes)
{
    if (bytes.empty())
        return;
    c.owed += bytes.size();
    // A long reply goes in pieces, so the queue never moves a buffer it has grown to the whole of it.
    if (!c.queue.empty() && c.queue.back().owns() && c.queue.back().size() + bytes.size() <= chunk_max)
        c.queue.back().append(bytes);
    else
    {
        std::string b = std::move(c.spare);
        b.assign(bytes);
        c.queue.emplace_back(std::move(b));
    }
}

void mail_run::queue_shared(conn& c, const std::shared_ptr<const std::string>& bytes, size_t off, size_t len)
{
    if (len == 0)
        return;
    c.owed += len;
    c.queue.emplace_back(bytes, static_cast<uint32_t>(off), static_cast<uint32_t>(len));
}

void mail_run::queue_tls_out(conn& c)
{
    m_tls_out.clear();
    tls_context::take_out(c.ssl, m_tls_out);
    queue_owned(c, m_tls_out);
}

void mail_run::flush(conn& c)
{
    if (!c.dead && c.zout && !c.zplain.empty())
    {
        std::string z;
        c.zout->compress(c.zplain, z);
        c.zplain.clear();
        send_raw(c, z);
    }
    if (c.dead || c.wr_pending)
        return;
    if (c.sending_at >= c.sending.size())
    {
        c.sending.clear();
        c.sending_at = 0;
        c.sent = 0;
        if (c.queue.empty())
        {
            if (c.closing)
                m_close_soon.push_back(c.id);
            return;
        }
        c.sending.swap(c.queue);
    }
    c.wr = io_request{};
    c.wr.owner = this;
    c.wr.buffer = reinterpret_cast<char*>(&c);
    c.wr.fd = c.fd;
    const size_t left = c.sending.size() - c.sending_at;
    if (left == 1)
    {
        const std::string_view b = c.sending[c.sending_at].view().substr(c.sent);
        c.wr.type = op_write;
        c.wr_pending = m_loop.submit_write(c.fd, b.data(), static_cast<uint32_t>(std::min<size_t>(b.size(), UINT32_MAX)),
                                           &c.wr);
    }
    else
    {
        c.iov.clear();
        for (size_t i = c.sending_at; i < c.sending.size() && c.iov.size() < 128; ++i)
        {
            const std::string_view b = c.sending[i].view().substr(i == c.sending_at ? c.sent : 0);
            c.iov.push_back({const_cast<char*>(b.data()), b.size()});
        }
        c.wr.type = op_writev;
        c.wr_pending = m_loop.submit_writev(c.fd, c.iov.data(), static_cast<uint32_t>(c.iov.size()), &c.wr);
    }
    c.reflush = !c.wr_pending;
    if (c.reflush)
        retry_io(c);
}

void mail_run::write_done(conn& c, int res)
{
    c.wr_pending = false;
    if (c.dead)
        return;
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    auto done = static_cast<size_t>(res);
    c.owed -= std::min(c.owed, done);
    while (done && c.sending_at < c.sending.size())
    {
        const size_t rest = c.sending[c.sending_at].size() - c.sent;
        if (done < rest)
        {
            c.sent += done;
            break;
        }
        done -= rest;
        socketley::write_chunk& sent = c.sending[c.sending_at++];
        if (sent.owns())
        {
            std::string room = sent.take_owned();
            if (room.capacity() > c.spare.capacity())
            {
                room.clear();
                c.spare.swap(room);
            }
        }
        sent = socketley::write_chunk{};
        c.sent = 0;
    }
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(res));
    flush(c);
    if (c.drained && c.owed <= drained_at)
    {
        auto f = std::move(c.drained);
        c.drained = nullptr;
        f();
    }
}

void mail_run::close_soon(conn& c)
{
    if (c.dead)
        return;
    if (!c.closing)
    {
        c.closing = true;
        c.closing_ms = wall::now_ms_coarse();
    }
    m_close_soon.push_back(c.id);
}

void mail_run::close_conn(conn& c)
{
    if (c.dead)
        return;
    c.dead = true;
    if (const auto it = m_clients.find(c.ip); it != m_clients.end())
    {
        it->second.conns -= std::min<uint32_t>(it->second.conns, 1);
        if (it->second.conns == 0 && it->second.failures == 0 && it->second.tokens_ms == 0)
            m_clients.erase(it);
    }
    if (c.smtp)
        c.smtp->gone();
    if (c.imap)
        c.imap->gone();
    if (c.writer)
    {
        m_spool.abort(c.writer);
        c.writer = 0;
    }
    if (c.fd >= 0)
    {
        ::shutdown(c.fd, SHUT_RDWR);
        m_loop.close_fd(c.fd);
        c.fd = -1;
    }
    if (c.ssl)
    {
        tls_context::free_ssl(c.ssl);
        c.ssl = nullptr;
    }
    const auto it = m_conns.find(c.id);
    if (it != m_conns.end())
    {
        m_closing.push_back(std::move(it->second));
        m_conns.erase(it);
    }
    m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
}

void mail_run::settle()
{
    if (m_in_settle)
        return;
    m_in_settle = true;
    const int64_t now = wall::now_ms_coarse();
    for (int rounds = 0; rounds < 4 && !m_close_soon.empty(); ++rounds)
    {
        std::vector<uint64_t> ids;
        ids.swap(m_close_soon);
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        for (const uint64_t id : ids)
        {
            conn* c = find(id);
            if (!c || c->dead)
                continue;
            if (c->owed == 0)
                close_conn(*c);
            else if (now - c->closing_ms >= close_grace_ms)
            {
                // Its client read none of it in the grace: the connection is reset, not left draining for it.
                const linger now_reset{1, 0};
                if (c->fd >= 0 && ::setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &now_reset, sizeof now_reset) < 0) {}
                close_conn(*c);
            }
        }
    }
    std::erase_if(m_closing, [](const std::unique_ptr<conn>& c) { return !c->rd_pending && !c->wr_pending; });
    m_in_settle = false;
}

// ── The session's hooks ─────────────────────────────────────────────────────

void mail_run::conn::reply(std::string_view bytes)
{
    run->out(*this, bytes);
}

void mail_run::conn::start_tls()
{
    // The 220 goes in the clear, and everything after it is the handshake's.
    run->flush(*this);
    ssl = run->m_tls ? run->m_tls->create_ssl_server() : nullptr;
    if (!ssl)
    {
        run->close_conn(*this);
        return;
    }
    handshaken = false;
    upgrading = true;
    closing_ms = wall::now_ms_coarse();
}

void mail_run::conn::authenticate(std::string_view, std::string user, std::string secret,
                                  std::function<void(account, std::string)> done)
{
    mail_run& r = *run;
    // An address that failed too often lately is told to come back later, its password not looked at.
    const int64_t now = wall::now_ms_coarse();
    const bool guarded = !loopback(peer);
    if (guarded && r.m_clients[ip].locked_until_ms > now)
    {
        ++r.m_auth_locked;
        done(account::unreachable, {});
        return;
    }
    // A wrong answer waits a second before it is said, and counts against its address.
    auto finish = [&r, alive = r.m_alive, done, guarded, ip = ip](account a, std::string name) {
        if (!*alive)
            return;
        if (a != account::no)
        {
            r.m_auth_ok += a == account::yes;
            done(a, std::move(name));
            return;
        }
        ++r.m_auth_failed;
        if (guarded)
        {
            const int64_t t = wall::now_ms_coarse();
            mail_run::client& cl = r.m_clients[ip];
            if (t - cl.first_failure_ms > auth_window_ms)
            {
                cl.first_failure_ms = t;
                cl.failures = 0;
            }
            if (++cl.failures >= auth_failures_max && cl.locked_until_ms <= t)
            {
                cl.locked_until_ms = t + auth_window_ms;
                LOG_WARN(("mail " + std::string(r.m_owner.get_name()) + ": " + ip + " failed to sign in " +
                          std::to_string(cl.failures) + " times, and is refused for ten minutes")
                             .c_str());
            }
        }
        if (!r.m_fio.after(auth_delay, [alive, done](int64_t) {
                if (*alive)
                    done(account::no, {});
            }))
            done(account::no, {});
    };
    if (const std::string* hash = r.m_users.value().hash_of(user))
    {
        // scrypt costs tens of milliseconds, which the loop does not spend.
        auto matched = std::make_shared<bool>(false);
        r.m_pool.submit(r.cpu_lane(), [h = *hash, pw = std::move(secret), matched] {
                            *matched = socketley::storage::password_matches(h, pw);
                        },
                        [matched, user, finish] { finish(*matched ? account::yes : account::no, user); });
        return;
    }
    if (r.m_idp)
    {
        socketley::idp::session_verifier::who who;
        if (r.m_idp->check_bearer(secret, who) && (user == who.username || user == who.sub || user == who.email))
        {
            idp_user = true;
            user_email = who.email;
            finish(account::yes, who.username.empty() ? who.sub : who.username);
            return;
        }
        // A password, which only the idp runtime can check, on its own threads.
        const uint64_t me = id;
        r.m_mailboxes->verify(user, secret, [&r, me, finish](account a, std::string name, std::string email) {
            if (conn* c = r.find(me); c && a == account::yes)
            {
                c->idp_user = true;
                c->user_email = std::move(email);
            }
            finish(a, std::move(name));
        });
        return;
    }
    // A name no one has costs what a known one does, so the reply's time does not tell which names exist.
    if (!r.m_owner.get_users().empty())
    {
        static const std::string dummy = socketley::storage::password_hash("a password no account has");
        r.m_pool.submit(r.cpu_lane(), [pw = std::move(secret)] {
                            if (socketley::storage::password_matches(dummy, pw)) {}
                        },
                        [finish] { finish(account::no, {}); });
        return;
    }
    finish(account::no, {});
}

void mail_run::conn::mail_from(const address& from, std::function<void(rcpt_verdict)> done)
{
    // A stranger's address its blocklists list sends nothing, and MAIL waits for their answer if it has not come.
    if (blocklist == 1)
    {
        after_blocklist = [this, from, done] { mail_from(from, done); };
        return;
    }
    if (blocklist == 3 && smtp->user().empty())
    {
        ++run->m_blocklisted;
        done({554, "Service unavailable; " + ip + " is listed by " + listed_by});
        return;
    }
    // A signed-in user sends as their own address, as Postfix's reject_sender_login_mismatch has it.
    if (!smtp->user().empty() && !from.empty() && !owns(from))
    {
        done({553, "Sender address not owned by " + smtp->user()});
        return;
    }
    // A spool whose disk is nearly full takes no more mail, which its senders keep and try again (RFC 5321 4.5.3.1.10).
    if (run->m_disk_low)
    {
        done({452, "Insufficient system storage; try again later"});
        return;
    }
    // --rate-limit holds each sender to so many messages a second, its address or its account; the runtime is held to
    // --global-rate-limit's.
    if (!run->may_send(smtp->user().empty() ? ip : "user:" + smtp->user()))
    {
        ++run->m_rate_limited;
        done({450, "Too many messages; try again later"});
        return;
    }
    done({250, ""});
}

bool mail_run::conn::owns(const address& a) const
{
    const std::string user = smtp ? smtp->user() : std::string();
    if (user.empty())
        return false;
    return (run->is_local_domain(a.domain) && socketley::ascii::iequals(a.local, user)) ||
           (!user_email.empty() && socketley::ascii::iequals(a.text(), user_email)) ||
           socketley::ascii::iequals(a.text(), user);
}

bool mail_run::may_send(const std::string& who)
{
    const double rate = m_owner.get_rate_limit();
    if (rate > 0)
    {
        // A bucket of a second's allowance, at least one message, filled as time goes.
        const int64_t now = wall::now_ms_coarse();
        client& cl = m_clients[who];
        const double burst = std::max(1.0, rate);
        if (cl.tokens_ms == 0)
            cl.tokens = burst;
        else
            cl.tokens = std::min(burst, cl.tokens + rate * static_cast<double>(now - cl.tokens_ms) / 1000.0);
        cl.tokens_ms = now;
        if (cl.tokens < 1.0)
            return false;
        cl.tokens -= 1.0;
    }
    return m_owner.get_global_rate_limit() <= 0 || m_owner.take_global_token();
}

void mail_run::conn::rcpt_to(const address& to, std::function<void(rcpt_verdict)> answer)
{
    mail_run& r = *run;
    // The script has the last word on each recipient, told what would be answered without it.
    const std::string sender = smtp->sender().text(), who = smtp->user();
    std::function<void(rcpt_verdict)> done = [&r, answer, to, sender, who, ip = ip](rcpt_verdict v) {
        if (!r.m_lua || !r.m_lua->wants_rcpt())
        {
            answer(v);
            return;
        }
        r.m_lua->rcpt(to.text(), sender, ip, who, v.code / 100 == 2, [answer, v](account take) {
            if (take == account::unreachable)
                answer(rcpt_verdict{451, "The recipient cannot be decided now; try again later"});
            else if (take == account::yes)
                answer(v.code / 100 == 2 ? v : rcpt_verdict{250, "Taken by the script"});
            else
                answer(v.code / 100 == 2 ? rcpt_verdict{550, "Recipient refused"} : v);
        });
    };
    // A first triplet of a stranger's network, sender and recipient is told to come back, decided on the pool (RFC
    // 6647); a recipient refused anyway is refused as it is.
    if (r.m_greylist && kind == port_kind::smtp && smtp->user().empty() && !loopback(peer))
        done = [&r, then = std::move(done), net = greylist::network_of(ip), sender, rcpt = to.text()](rcpt_verdict v) {
            if (v.code / 100 != 2)
            {
                then(v);
                return;
            }
            auto wait = std::make_shared<int64_t>(0);
            r.m_pool.submit(0, [g = r.m_greylist.get(), net, sender, rcpt, wait] {
                *wait = g->check(net, sender, rcpt, wall::now_ms());
            }, [&r, then, v, wait, alive = r.m_alive] {
                if (!*alive)
                    return;
                if (*wait)
                {
                    ++r.m_greylisted;
                    then({451, "Greylisted, try again in " + std::to_string(*wait) + " seconds"});
                }
                else
                    then(v);
            });
        };
    const route_to where = r.route(to, smtp->sender().empty());
    // LMTP hands mail to this runtime's mailboxes, and to nothing else.
    if (kind == port_kind::lmtp && where.k != route_to::mailbox)
    {
        ++r.m_refused_rcpt;
        done({550, "LMTP takes mail for the mailboxes here"});
        return;
    }
    switch (where.k)
    {
        case route_to::mailbox:
        {
            if (!r.m_mailboxes || !r.m_mailboxes->enabled())
            {
                ++r.m_refused_rcpt;
                done({550, "No mailbox is kept here"});
                return;
            }
            r.m_mailboxes->find(where.target, [&r, done](account a, std::string, std::string) {
                if (a == account::unreachable)
                {
                    done({451, "The accounts cannot be checked now; try again later"});
                    return;
                }
                if (a == account::no)
                    ++r.m_refused_rcpt;
                done(a == account::yes ? rcpt_verdict{250, ""} : rcpt_verdict{550, "No such user here"});
            });
            return;
        }
        case route_to::sink:
            done({250, ""});
            return;
        case route_to::remote:
            // Mail for elsewhere is taken from a signed-in user, from this machine, or for an alias of a local
            // address; from anyone else it is relaying, which a mail server open to it is soon a spammer's.
            if (!smtp->user().empty() || loopback(peer) || r.is_local_domain(to.domain))
            {
                done({250, ""});
                return;
            }
            ++r.m_refused_relay;
            done({554, "Relay access denied"});
            return;
        case route_to::none:
            break;
    }
    ++r.m_refused_rcpt;
    if (r.m_owner.get_no_reply() && no_reply_local(to.local) && r.is_local_domain(to.domain))
        done({550, "This address takes no mail"});
    else
        done({550, "No such user here"});
}

bool mail_run::conn::data_begin()
{
    mail_run& r = *run;
    auto e = std::make_shared<spool_entry>();
    e->id = new_spool_id(r.shard());
    e->from = smtp->sender().text();
    const auto& dsn = smtp->recipients_dsn();
    for (size_t i = 0; i < smtp->recipients().size(); ++i)
    {
        e->rcpts.emplace_back(smtp->recipients()[i].text());
        if (i < dsn.size())
        {
            e->rcpts.back().notify = dsn[i].notify;
            e->rcpts.back().orcpt = dsn[i].orcpt;
        }
    }
    e->ret = smtp->ret();
    e->envid = smtp->envid();
    e->requiretls = smtp->requiretls();
    e->user = smtp->user();
    e->peer = ip;
    e->helo = smtp->helo();
    e->at_ms = wall::now_ms_coarse();
    const std::string head =
        r.received_line(*this, e->id, smtp->recipients().size() == 1 ? smtp->recipients().front().text() : "");
    entry = e;
    writer = r.m_spool.begin(std::move(e), head);
    head_seen.clear();
    holding = !smtp->user().empty();
    return writer != 0;
}

void mail_run::conn::data_bytes(std::string_view piece)
{
    if (!holding)
    {
        if (writer)
            run->m_spool.append(writer, piece);
        return;
    }
    // A signed-in user's header is held until its blank line or 64 KiB, then written with what it lacks.
    head_seen.append(piece);
    if (head_seen.find("\r\n\r\n") != std::string::npos || head_seen.starts_with("\r\n") ||
        head_seen.size() >= (64u << 10))
        release_head(false);
}

void mail_run::conn::release_head(bool at_end)
{
    holding = false;
    // A message submitted without a Date or a Message-ID is given one, as RFC 5322 3.6 asks and Postfix's cleanup does;
    // where the header did not end within what was held it is left as it came.
    std::string add;
    const bool whole = at_end || head_seen.find("\r\n\r\n") != std::string::npos || head_seen.starts_with("\r\n");
    if (whole)
    {
        bool date = false, id = false;
        for (const auto& [name, value] : split_headers(header_block(head_seen)))
        {
            date = date || socketley::ascii::iequals(name, "Date");
            id = id || socketley::ascii::iequals(name, "Message-ID");
        }
        if (!date)
            add += "Date: " + rfc5322_date(wall::now_ms()) + "\r\n";
        if (!id)
            add += "Message-ID: <" + socketley::random_hex(16) + "@" + run->hostname() + ">\r\n";
    }
    if (writer)
    {
        if (!add.empty())
            run->m_spool.append(writer, add);
        run->m_spool.append(writer, head_seen);
    }
    // What is kept is the header alone, for the From check at the end.
    head_seen.resize(header_block(head_seen).size());
}

void mail_run::conn::data_end(std::function<void(rcpt_verdict)> done)
{
    mail_run& r = *run;
    if (holding)
        release_head(true);
    const uint64_t w = writer;
    writer = 0;
    entry_ptr e = std::move(entry);
    // The header's From is the user's own too, or the runtime would sign another's name with its key.
    const std::string head = std::move(head_seen);
    head_seen.clear();
    if (!smtp->user().empty())
    {
        std::vector<address> authors;
        const std::string from = header_value(header_block(head), "From");
        if (!from.empty() && (!parse_mailbox_list(from, authors) ||
                              std::any_of(authors.begin(), authors.end(), [this](const address& a) { return !owns(a); })))
        {
            r.m_spool.abort(w);
            done({553, "The From header names an address not owned by " + smtp->user()});
            return;
        }
    }
    // Mail from elsewhere is checked before it is taken: from a user signed in, or this machine, it is not.
    const bool check = kind == port_kind::smtp && smtp->user().empty() && !loopback(peer);
    const std::string helo = smtp->helo();
    r.m_spool.finish(w, [&r, alive = r.m_alive, e, done, check, ip = ip, helo](bool ok) {
        if (!*alive)
            return;
        if (!ok)
        {
            ++r.m_spool_failed;
            done({451, "The message could not be written, try again later"});
            return;
        }
        if (!check)
        {
            done({250, "OK queued as " + e->id});
            r.accepted(e);
            return;
        }
        // Checks waiting past what the lanes work through are a flood: the sender is told to come back.
        if (r.m_checks_out >= 512)
        {
            r.m_spool.forget_written(e->id);
            done({451, "Too much mail is being checked now; try again later"});
            return;
        }
        ++r.m_checks_out;
        auto result = std::make_shared<inbound_result>();
        auto spam = std::make_shared<spam_verdict>();
        auto unread = std::make_shared<bool>(false);
        const std::string path = r.m_spool.file_of(*e);
        const uint64_t off = e->body_off, len = e->body_len;
        r.m_checks.submit(r.m_checks.next_lane(),
                          [e, result, spam, unread, ip, helo, path, off, len, trusted = r.m_arc_trusted,
                           rspamd = std::string(r.m_owner.get_rspamd())] {
                              std::string whole;
                              std::string_view msg;
                              if (e->body)
                                  msg = *e->body;
                              else
                              {
                                  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
                                  whole.resize(len);
                                  size_t got = 0;
                                  while (fd >= 0 && got < whole.size())
                                  {
                                      const ssize_t n = ::pread(fd, whole.data() + got, whole.size() - got,
                                                                static_cast<off_t>(off + got));
                                      if (n <= 0)
                                          break;
                                      got += static_cast<size_t>(n);
                                  }
                                  if (fd >= 0)
                                      ::close(fd);
                                  // A message that cannot be read back is not checked, and so not taken.
                                  if (got != whole.size())
                                  {
                                      *unread = true;
                                      return;
                                  }
                                  msg = whole;
                              }
                              auto resolver = system_check_resolver();
                              *result = check_inbound(msg, ip, helo, e->from, *resolver, wall::now_ms() / 1000,
                                                      trusted);
                              // Scored by Rspamd beside the checks, where it is named.
                              if (!rspamd.empty() && !result->reject())
                              {
                                  std::vector<std::string> rcpts;
                                  for (const auto& rc : e->rcpts)
                                      rcpts.push_back(rc.addr);
                                  *spam = rspamd_check(rspamd, msg, ip, helo, e->from, rcpts, {});
                              }
                          },
                          [&r, alive, e, done, result, unread, spam, ip] {
                              if (!*alive)
                                  return;
                              --r.m_checks_out;
                              if (*unread)
                              {
                                  r.m_spool.forget_written(e->id);
                                  done({451, "The message could not be checked; try again later"});
                                  return;
                              }
                              ++r.m_checked;
                              if (r.m_owner.get_reports() && !result->rua.empty())
                              {
                                  reports::dmarc_seen s;
                                  s.policy_domain = result->policy_domain;
                                  s.rua = result->rua;
                                  s.adkim = result->adkim;
                                  s.aspf = result->aspf;
                                  s.p = result->p;
                                  s.sp = result->sp;
                                  s.pct = result->pct;
                                  s.header_from = result->from_domain;
                                  s.source_ip = ip;
                                  s.disposition = result->reject() ? "reject" : result->quarantine() ? "quarantine" : "none";
                                  s.dkim_pass = result->dkim_aligned;
                                  s.spf_pass = result->spf_aligned;
                                  for (const auto& [res, d] : result->dkim)
                                      s.dkim.emplace_back(d, res);
                                  s.spf_domain = result->spf_domain;
                                  s.spf_result = result->spf;
                                  r.m_reports.dmarc(s);
                              }
                              if (result->reject())
                              {
                                  // DMARC says its domain's own mail never comes so: it is refused, not kept.
                                  ++r.m_dmarc_rejected;
                                  r.m_spool.forget_written(e->id);
                                  done({550, "Message refused: " + (result->why.empty()
                                                                         ? "DMARC policy of " + result->from_domain + " is reject"
                                                                         : result->why)});
                                  return;
                              }
                              // What Rspamd's rules decide: refused, told to come back, or kept in Junk.
                              std::string header = result->header();
                              bool junk = result->quarantine();
                              if (spam->scored)
                              {
                                  const std::string& a = spam->action;
                                  if (a == "reject")
                                  {
                                      ++r.m_spam_rejected;
                                      r.m_spool.forget_written(e->id);
                                      done({554, "Message refused as spam"});
                                      return;
                                  }
                                  if (a == "soft reject" || a == "greylist")
                                  {
                                      r.m_spool.forget_written(e->id);
                                      done({451, "Message deferred by the spam filter; try again later"});
                                      return;
                                  }
                                  const bool flagged = a == "add header" || a == "rewrite subject";
                                  junk = junk || flagged;
                                  r.m_spam_junked += flagged;
                                  char buf[96];
                                  std::snprintf(buf, sizeof buf, " (score=%.2f required=%.2f)", spam->score, spam->required);
                                  header += "; x-spam=" + std::string(flagged ? "yes" : "no") + buf;
                              }
                              if (junk)
                                  ++r.m_quarantined;
                              r.m_spool.note_auth(*e, header, junk ? "Junk" : "");
                              done({250, "OK queued as " + e->id});
                              r.accepted(e);
                          });
    });
}

void mail_run::conn::data_abort(bool too_big)
{
    holding = false;
    head_seen.clear();
    if (writer)
    {
        run->m_spool.abort(writer);
        writer = 0;
    }
    entry.reset();
    run->m_too_big += too_big;
}

void mail_run::conn::close()
{
    run->close_soon(*this);
}

void mail_run::conn::login(std::string user, std::string password, std::function<void(account, std::string)> done)
{
    authenticate("IMAP", std::move(user), std::move(password), std::move(done));
}

void mail_run::conn::offload(std::function<void()> job, std::function<void()> done)
{
    const uint64_t me = id;
    run->pool().submit(0, std::move(job), [r = run, me, done = std::move(done), alive = run->m_alive] {
        if (!*alive)
            return;
        if (conn* c = r->find(me); c && !c->dead)
        {
            c->in_input = true;
            done();
            c->in_input = false;
            r->flush(*c);
        }
    });
}

void mail_run::conn::maildrop(const std::string& user,
                              std::function<void(bool, uint32_t, std::vector<pop3_session::message>)> done)
{
    run->m_imap->open(user, "INBOX", [done](std::shared_ptr<imap_folder> f) {
        if (!f)
        {
            done(false, 0, {});
            return;
        }
        std::vector<pop3_session::message> drop;
        drop.reserve(f->msgs.size());
        for (const auto& m : f->msgs)
            drop.push_back({m.uid, m.size, m.key});
        done(true, f->uidvalidity, std::move(drop));
    }, true);
}

void mail_run::conn::read(const pop3_session::message& m, std::function<void(std::shared_ptr<const std::string>)> done)
{
    run->m_imap->body(m.key, m.size, std::move(done));
}

void mail_run::conn::remove(const std::string& user, std::vector<uint32_t> uids, std::function<void(bool)> done)
{
    imap_store* store = run->m_imap.get();
    store->open(user, "INBOX", [store, user, uids = std::move(uids), done](std::shared_ptr<imap_folder> f) {
        if (!f)
        {
            done(false);
            return;
        }
        store->expunge(user, f, uids, true, [want = uids.size(), done](std::vector<uint32_t> gone) {
            done(gone.size() == want);
        });
    });
}

void mail_run::conn::reply_shared(const std::shared_ptr<const std::string>& bytes, size_t off, size_t len)
{
    // TLS and COMPRESS make a copy anyway, and a slice is at most what 32 bits count.
    if (dead || zout || (ssl && handshaken && !upgrading) || len > UINT32_MAX || off > UINT32_MAX)
    {
        reply(std::string_view(*bytes).substr(off, len));
        return;
    }
    run->queue_shared(*this, bytes, off, len);
    if (!in_input)
        run->flush(*this);
}

void mail_run::conn::when_drained(std::function<void()> f)
{
    run->flush(*this);
    if (dead || owed <= drained_at)
    {
        if (!dead)
            f();
        return;
    }
    drained = std::move(f);
}

void mail_run::conn::later(std::function<void()> f)
{
    const uint64_t me = id;
    if (!run->m_fio.after(std::chrono::milliseconds(0), [r = run, me, f = std::move(f), alive = run->m_alive](int64_t) {
            if (!*alive)
                return;
            if (conn* c = r->find(me); c && !c->dead)
            {
                c->in_input = true;
                f();
                c->in_input = false;
                r->flush(*c);
            }
        }))
        f();
}

bool mail_run::conn::start_compress()
{
    zout = std::make_unique<socketley::deflater>();
    zin = std::make_unique<socketley::inflater>();
    return true;
}

void mail_run::conn::acknowledge()
{
    const int on = 1;
    if (fd >= 0 && ::setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &on, sizeof on) < 0) {}
}

std::string mail_run::received_line(const conn& c, const std::string& id, const std::string& rcpt) const
{
    const bool tls = c.ssl && c.handshaken;
    const bool auth = c.smtp && !c.smtp->user().empty();
    std::string with = c.smtp && c.smtp->esmtp() ? "ESMTP" : "SMTP";
    if (tls)
        with += "S";
    if (auth)
        with += "A";
    std::string out = "Received: from " + (c.smtp ? c.smtp->helo() : std::string()) + " (" + c.ip +
                      ")\r\n\tby " + m_hostname + " (socketley) with " + with + " id " + id;
    if (!rcpt.empty())
        out += "\r\n\tfor <" + rcpt + ">";
    out += "; " + rfc5322_date(wall::now_ms()) + "\r\n";
    return out;
}

void mail_run::accepted(const entry_ptr& e)
{
    ++m_received;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    if (m_lua)
        m_lua->message(*e);
    if (m_delivery)
        m_delivery->queued(e);
}

void mail_run::queue_message(const std::string& from, const std::vector<std::string>& rcpts, std::string body,
                             bool bounce, std::string user, std::function<void(bool, std::string)> done,
                             bool requiretls)
{
    auto e = std::make_shared<spool_entry>();
    e->requiretls = requiretls;
    e->id = new_spool_id(shard());
    e->from = from;
    for (const auto& a : rcpts)
        e->rcpts.emplace_back(a);
    e->user = std::move(user);
    e->peer = "local";
    e->helo = m_hostname;
    e->at_ms = wall::now_ms_coarse();
    e->bounce = bounce;
    const uint64_t w = m_spool.begin(e, {});
    m_spool.append(w, body);
    m_spool.finish(w, [this, alive = m_alive, e, done](bool ok) {
        if (!*alive)
            return;
        if (ok)
            accepted(e);
        if (done)
            done(ok, e->id);
    });
}

// ── The ring ────────────────────────────────────────────────────────────────

void mail_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (m_notify && m_notify->owns(req))
        m_notify->on_timer();
    else if (file_io::owns_type(req->type))
        m_fio.on_cqe(cqe);
    else if (req == &m_tick_req)
    {
        m_tick_armed = false;
        if (!m_stopped)
            tick();
    }
    else if (req == &m_smtp.req)
        accept_done(m_smtp, cqe);
    else if (req == &m_sub.req)
        accept_done(m_sub, cqe);
    else if (req == &m_subs.req)
        accept_done(m_subs, cqe);
    else if (req == &m_imap_l.req)
        accept_done(m_imap_l, cqe);
    else if (req == &m_imaps_l.req)
        accept_done(m_imaps_l, cqe);
    else if (req == &m_sieve_l.req)
        accept_done(m_sieve_l, cqe);
    else if (req == &m_pop3_l.req)
        accept_done(m_pop3_l, cqe);
    else if (req == &m_pop3s_l.req)
        accept_done(m_pop3s_l, cqe);
    else if (req == &m_lmtp_l.req)
        accept_done(m_lmtp_l, cqe);
    else if (req == &m_sts_l.req)
        accept_done(m_sts_l, cqe);
    else if (conn* c = conn_of(req))
    {
        if (req == &c->rd)
            read_done(*c, cqe);
        else if (req == &c->wr)
            write_done(*c, cqe->res);
    }
    else if (cqe->flags & IORING_CQE_F_BUFFER)
        m_loop.return_cqe_buf(cqe, req);
    settle();
}

void mail_run::on_loop_turn()
{
    if (m_stopped)
        return;
    if (wall::now_ms_coarse() >= m_accept_paused_until_ms)
        for (listener* l : listeners())
            if (l->fd >= 0 && !l->pending)
                arm_accept(*l);
    // Only the connections whose read or write the ring could not take, not every one each turn.
    if (!m_retry_io.empty())
    {
        std::vector<uint64_t> ids;
        ids.swap(m_retry_io);
        for (const uint64_t id : ids)
            if (conn* c = find(id); c && !c->dead)
            {
                if (c->rearm)
                    arm_read(*c);
                if (c->reflush)
                    flush(*c);
            }
    }
    if (m_delivery)
        m_delivery->on_loop_turn();
    settle();
}

void mail_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {1, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void mail_run::tick()
{
    const int64_t now = wall::now_ms_coarse();
    std::vector<conn*> late;
    for (auto& [id, c] : m_conns)
    {
        const bool shaking = c->ssl && !c->handshaken;
        const int64_t quiet = c->imap ? imap_idle_ms : idle_ms;
        if (!c->closing && ((shaking && now - c->closing_ms > handshake_ms) || now - c->heard_ms > quiet))
            late.push_back(c.get());
        // One closing with output its client does not read is closed once its grace is over.
        else if (c->closing && now - c->closing_ms >= close_grace_ms)
            m_close_soon.push_back(c->id);
        else if (c->imap && (c->imap->idling() || c->imap->notifying()))
        {
            c->in_input = true;
            c->imap->poll();
            c->in_input = false;
            flush(*c);
        }
    }
    for (conn* c : late)
    {
        if (c->imap && !(c->ssl && !c->handshaken))
        {
            out(*c, "* BYE " + m_hostname + " idle too long\r\n");
            close_soon(*c);
        }
        else if (c->smtp && !(c->ssl && !c->handshaken))
        {
            out(*c, "421 4.4.2 " + m_hostname + " idle too long, closing\r\n");
            close_soon(*c);
        }
        else if (c->sieve && !(c->ssl && !c->handshaken))
        {
            out(*c, "BYE \"idle too long\"\r\n");
            close_soon(*c);
        }
        else if (c->pop3 && !(c->ssl && !c->handshaken))
        {
            out(*c, "-ERR idle too long\r\n");
            close_soon(*c);
        }
        else
            close_conn(*c);
    }
    if (now >= m_next_files_ms)
    {
        m_next_files_ms = now + 1000;
        // An address with no connection, no lockout and no failure or message lately is forgotten.
        std::erase_if(m_clients, [now](const auto& kv) {
            const client& cl = kv.second;
            return cl.conns == 0 && cl.locked_until_ms <= now && now - cl.first_failure_ms > auth_window_ms &&
                   now - cl.tokens_ms > 60000;
        });
        refresh_files();
        refresh_domains();
        load_suppressed();
        // Below four messages of the largest size, or 256 MiB, of room on the spool's disk, MAIL is told 452.
        struct statvfs fs{};
        if (::statvfs(m_spool.dir().c_str(), &fs) == 0)
        {
            const uint64_t room = static_cast<uint64_t>(fs.f_bavail) * fs.f_frsize;
            m_disk_low = room < std::max<uint64_t>(256ull << 20, 4 * m_owner.get_max_size());
        }
    }
    if (now >= m_next_report_ms)
    {
        m_next_report_ms = now + 60000;
        send_reports();
    }
    m_spool.tick(now);
    if (m_delivery)
        m_delivery->tick(now);
    if (m_imap)
        m_imap->tick(now);
    tls_context::report_inbound_failures();
    settle();
    arm_tick();
}

void mail_run::refresh_files()
{
    std::string why;
    if (!m_users.refresh([](user_table& t, std::string_view text, std::string& w) { return t.parse(text, w); }, why))
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + why + "; the users read before are kept").c_str());
    why.clear();
    if (!m_aliases.refresh([](alias_table& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                           why))
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + why + "; the aliases read before are kept")
                     .c_str());
}

void mail_run::refresh_domains()
{
    if (m_owner.get_dns().empty() || !m_owner.get_mail_domains().empty())
        return;
    std::vector<std::string> now;
    for (auto& [rt, origin] : dns_feed::read_zones())
        if (rt == m_owner.get_dns())
        {
            std::string d = origin;
            if (!d.empty() && d.back() == '.')
                d.pop_back();
            socketley::ascii::lower_in_place(d);
            if (!d.empty())
                now.push_back(std::move(d));
        }
    if (now == m_domains)
        return;
    m_domains = std::move(now);
    m_owner.set_resolved_domains(m_domains);
    m_hostname = m_owner.greeting_name();
    std::string list;
    for (const auto& d : m_domains)
        list += (list.empty() ? "" : ", ") + d;
    LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": the zones of " + std::string(m_owner.get_dns()) +
              " are its domains: " + (list.empty() ? std::string("none") : list))
                 .c_str());
    publish_records();
}

std::string mail_run::records_text() const
{
    std::string out;
    const auto keys = m_delivery ? m_delivery->dkim_records() : std::vector<std::pair<std::string, std::string>>{};
    // Mail for elsewhere through a smarthost leaves from its addresses, which SPF cannot name here, so it only softfails.
    const std::string spf = m_owner.get_relay().empty() ? "v=spf1 mx -all" : "v=spf1 mx ~all";
    for (const auto& d : m_domains)
    {
        out += d + ". 300 IN MX 10 " + m_hostname + ".\n";
        out += d + ". 300 IN TXT \"" + spf + "\"\n";
        for (const auto& [sel, record] : keys)
            out += sel + "._domainkey." + d + ". 300 IN TXT \"" + record + "\"\n";
        const std::string_view rua = m_owner.get_dmarc_rua();
        out += "_dmarc." + d + ". 300 IN TXT \"v=DMARC1; p=quarantine; adkim=r; aspf=r" +
               (rua.empty() ? std::string() : "; rua=mailto:" + std::string(rua)) + "\"\n";
        // MTA-STS (RFC 8461) and where TLS reports go (RFC 8460), where it publishes them.
        if (!m_owner.get_mta_sts().empty())
            out += "_mta-sts." + d + ". 300 IN TXT \"v=STSv1; id=" + sts_id() + "\"\n";
        // The policy's host is this one where it serves the policy itself.
        if (!m_owner.get_mta_sts().empty() && m_owner.get_mta_sts_port())
            out += "mta-sts." + d + ". 300 IN CNAME " + m_hostname + ".\n";
        if (!m_owner.get_tls_rpt().empty())
            out += "_smtp._tls." + d + ". 300 IN TXT \"v=TLSRPTv1; rua=mailto:" + std::string(m_owner.get_tls_rpt()) +
                   "\"\n";
        // Where a mail client finds the ports it sends and reads on (RFC 6186, RFC 8314), and its filters' (RFC 5804).
        for (const auto& [service, port] : {std::pair{"_submissions", m_owner.get_submissions_port()},
                                            {"_submission", m_owner.get_submission_port()},
                                            {"_imaps", m_owner.get_imaps_port()},
                                            {"_imap", m_owner.get_imap_port()},
                                            {"_pop3s", m_owner.get_pop3s_port()},
                                            {"_pop3", m_owner.get_pop3_port()},
                                            {"_sieve", m_owner.get_sieve_port()}})
            if (port)
                out += std::string(service) + "._tcp." + d + ". 300 IN SRV 0 1 " + std::to_string(port) + " " +
                       m_hostname + ".\n";
    }
    // Its certificate's key pinned for senders that check DANE (RFC 7672): 3 1 1, its SubjectPublicKeyInfo's SHA-256.
    if (m_tls && !m_domains.empty())
    {
        std::string pem;
        if (socketley::read_file(std::string(m_owner.get_cert_path()), pem))
            if (BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())))
            {
                if (X509* x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
                {
                    unsigned char* der = nullptr;
                    const int n = i2d_PUBKEY(X509_get0_pubkey(x), &der);
                    if (n > 0)
                    {
                        unsigned char md[SHA256_DIGEST_LENGTH];
                        SHA256(der, static_cast<size_t>(n), md);
                        static constexpr char hex[] = "0123456789abcdef";
                        std::string h;
                        for (const unsigned char b : md)
                        {
                            h += hex[b >> 4];
                            h += hex[b & 15];
                        }
                        out += "_25._tcp." + m_hostname + ". 300 IN TLSA 3 1 1 " + h + "\n";
                        OPENSSL_free(der);
                    }
                    X509_free(x);
                }
                BIO_free(bio);
            }
    }
    return out;
}

void mail_run::publish_records()
{
    // One shard writes them, since every shard's are the same.
    if (m_owner.get_dns().empty() || m_owner.get_shard_index() != 0)
        return;
    const std::string text = records_text();
    if (text == m_published)
        return;
    if (dns_feed::write_records(m_owner.get_name(), text))
        m_published = text;
    else
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": its records could not be written for " +
                  std::string(m_owner.get_dns()))
                     .c_str());
}

// ── Requests ────────────────────────────────────────────────────────────────

void mail_run::expect_reply(uint64_t cookie, std::function<void(request_status, std::string_view)> cb)
{
    m_replies[cookie] = std::move(cb);
}

void mail_run::ask(const std::string& target, std::string payload,
                   std::function<void(request_status, std::string_view)> cb)
{
    auto* mgr = m_owner.get_runtime_manager();
    const uint64_t cookie = next_cookie();
    expect_reply(cookie, cb);
    if (!mgr || m_stopped || !mgr->requests().post(this, cookie, target, payload, request_class::background))
    {
        m_replies.erase(cookie);
        cb(request_status::no_target, {});
    }
}

void mail_run::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_replies.find(cookie);
    if (it == m_replies.end())
        return;
    auto cb = std::move(it->second);
    m_replies.erase(it);
    cb(st, reply);
}

std::string mail_run::queue_text(std::string_view filter) const
{
    std::string out;
    for (const auto& [id, e] : m_spool.entries())
    {
        if (!filter.empty() && id.find(filter) == std::string::npos && e->from.find(filter) == std::string::npos)
            continue;
        out += id + "\t" + std::to_string(e->body_len) + "\t" + (e->from.empty() ? "<>" : e->from) + "\t" +
               std::to_string(e->waiting()) + "/" + std::to_string(e->rcpts.size()) + " waiting\t" +
               std::to_string(e->attempts) + " tries\n";
    }
    return out;
}

std::string mail_run::show_text(const std::string& id) const
{
    const entry_ptr e = m_spool.find(id);
    if (!e)
        return "error: no message " + id + " is queued";
    std::string out = "id: " + e->id + "\nfrom: " + (e->from.empty() ? "<>" : e->from) + "\nsize: " +
                      std::to_string(e->body_len) + "\nreceived: " + rfc5322_date(e->at_ms) + "\npeer: " + e->peer +
                      "\n";
    if (!e->user.empty())
        out += "user: " + e->user + "\n";
    out += "tries: " + std::to_string(e->attempts) + "\n";
    if (e->next_ms)
        out += "next: " + rfc5322_date(e->next_ms) + "\n";
    for (const auto& r : e->rcpts)
        out += "rcpt: " + r.addr + "\t" +
               (r.state == rcpt_state::waiting ? "waiting" : r.state == rcpt_state::delivered ? "delivered" : "failed") +
               (r.why.empty() ? std::string() : "\t" + r.why) + "\n";
    return out;
}

void mail_run::command(uint64_t ticket, std::string_view payload)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    const auto answer = [mgr, ticket](std::string_view text) {
        mgr->requests().complete_deferred(ticket, request_status::ok, text);
    };
    socketley::bytes::reader r(payload);
    uint8_t v = 0;
    if (!r.marker(command_prefix) || !r.u8(v))
    {
        answer("error: no mail command");
        return;
    }
    if (static_cast<verb>(v) == verb::send)
    {
        send_command(ticket, r);
        return;
    }
    // A Sieve script of 64 KiB and its user and name, in base64, fit in a mebibyte.
    std::string arg;
    if (!r.bytes(arg, 1u << 20))
    {
        answer("error: the command is cut off past a mebibyte");
        return;
    }
    switch (static_cast<verb>(v))
    {
        case verb::send_file:
        {
            // Only a name this runtime's outbox gives, read and taken away off the loop.
            if (arg.size() != 36 || !arg.ends_with(".msg") ||
                !std::all_of(arg.begin(), arg.end() - 4, [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); }))
            {
                answer("error: no message file " + arg);
                return;
            }
            auto whole = std::make_shared<std::string>();
            auto read = std::make_shared<bool>(false);
            m_pool.submit(0,
                          [path = mail_outbox_dir(m_owner.get_name()) + "/" + arg, whole, read] {
                              *read = socketley::read_file(path, *whole);
                              ::unlink(path.c_str());
                          },
                          [this, ticket, whole, read, answer, alive = m_alive] {
                              if (!*alive)
                                  return;
                              socketley::bytes::reader fr(*whole);
                              uint8_t fv = 0;
                              if (!*read || !fr.marker(command_prefix) || !fr.u8(fv) || static_cast<verb>(fv) != verb::send)
                              {
                                  answer("error: the message file could not be read");
                                  return;
                              }
                              send_command(ticket, fr);
                          });
            return;
        }
        case verb::queue:
            answer(queue_text(arg));
            return;
        case verb::show:
            answer(show_text(arg));
            return;
        case verb::dns:
            answer(records_text());
            return;
        case verb::suppressed:
        {
            std::vector<std::string> all(m_suppressed.begin(), m_suppressed.end());
            std::sort(all.begin(), all.end());
            std::string out;
            for (const auto& a : all)
                out += a + "\n";
            answer(out);
            return;
        }
        case verb::sieve:
        {
            // A change of the scripts waits on the disk, so the loop does not.
            auto out = std::make_shared<std::string>();
            m_pool.submit(0, [this, arg, out] { *out = sieve_command(arg); },
                          [answer, out] { answer(*out); });
            return;
        }
        case verb::forgive:
        {
            std::string a = arg;
            socketley::ascii::lower_in_place(a);
            load_suppressed();
            if (!m_suppressed.count(a))
            {
                answer("error: " + arg + " is not suppressed");
                return;
            }
            edit_suppressed({}, {a});
            answer("ok");
            return;
        }
        case verb::flush:
            if (m_delivery)
                m_delivery->flush(arg);
            answer("ok");
            return;
        case verb::drop:
        {
            const entry_ptr e = m_spool.find(arg);
            if (!e)
            {
                answer("error: no message " + arg + " is queued");
                return;
            }
            if (m_delivery)
                m_delivery->forget(arg);
            m_spool.remove(arg);
            answer("ok");
            return;
        }
        default:
            answer("error: no such mail command");
            return;
    }
}

void mail_run::send_command(uint64_t ticket, socketley::bytes::reader& r)
{
    auto* mgr = m_owner.get_runtime_manager();
    const auto answer = [mgr, ticket](std::string_view text) {
        mgr->requests().complete_deferred(ticket, request_status::ok, text);
    };
    compose c;
    if (!decode_send(r, c, m_owner.get_max_size()))
    {
        answer("error: the message is cut off or larger than --max-size");
        return;
    }
    std::string body, from, why;
    std::vector<std::string> rcpts;
    if (!m_delivery->compose_message(c, from, rcpts, body, why))
    {
        answer("error: " + why);
        return;
    }
    queue_message(from, rcpts, std::move(body), false, "local", [answer](bool ok, std::string id) {
        answer(ok ? "queued " + id : "error: the message could not be written to the spool");
    });
}

std::string mail_run::sieve_command(const std::string& arg)
{
    if (!m_sieve)
        return "error: Sieve filters mailboxes, which need --idp and --storage";
    std::string all;
    if (!socketley::base64::decode(arg, all))
        return "error: the command did not arrive whole";
    std::string_view rest = all;
    const auto line = [&rest] {
        const size_t nl = rest.find('\n');
        const std::string_view l = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        return std::string(l);
    };
    const std::string asked = line(), what = line(), name = line();
    const std::string_view text = rest;
    // ".global" names the scripts any user's include :global reads, which no login can name.
    const std::string user = asked == ".global" ? sieve_store::global_user : asked;
    if (user != sieve_store::global_user && !sieve_store::name_ok(user))
        return "error: " + user + " is no user";
    if (user == sieve_store::global_user && (what == "activate" || what == "deactivate"))
        return "error: a global script is included, never active";
    std::string code, why;
    if (what == "list")
    {
        std::string out;
        for (const auto& [n, active] : m_sieve->list(user))
            out += n + (active ? "\tactive\n" : "\n");
        return out;
    }
    if (what == "get")
    {
        std::string t;
        return m_sieve->get(user, name, t) ? t : "error: " + user + " has no script " + name;
    }
    if (what == "put")
        return m_sieve->put(user, name, text, code, why) ? std::string() : "error: " + why;
    if (what == "check")
        return sieve::script::compile(text, why) ? std::string() : "error: " + why;
    if (what == "activate" || what == "deactivate")
        return m_sieve->activate(user, what == "activate" ? name : std::string(), code, why) ? std::string()
                                                                                              : "error: " + why;
    if (what == "delete")
        return m_sieve->remove(user, name, code, why) ? std::string() : "error: " + why;
    return "error: no sieve verb " + what;
}

std::string mail_run::stats() const
{
    std::string out;
    using socketley::stats_text::put;
    put(out, "mail_received", m_received);
    put(out, "mail_queued", m_spool.entries().size());
    put(out, "mail_queued_bytes", m_spool.bytes());
    put(out, "mail_refused_recipients", m_refused_rcpt);
    put(out, "mail_refused_relay", m_refused_relay);
    put(out, "mail_too_big", m_too_big);
    put(out, "mail_spool_failures", m_spool_failed + m_spool.write_failures());
    put(out, "mail_spool_commits", m_spool.commits());
    put(out, "mail_spool_committed", m_spool.committed());
    put(out, "mail_spool_segments", m_spool.segments());
    put(out, "mail_spool_moved", m_spool.moved());
    put(out, "mail_bounces_taken", m_bounces_taken);
    put(out, "mail_suppressed", m_suppressed.size());
    if (m_imap)
    {
        size_t imap = 0;
        for (const auto& [id, c] : m_conns)
            imap += c->imap != nullptr;
        put(out, "imap_connections", imap);
        put(out, "imap_reads", m_imap->gets());
        put(out, "imap_cache_hits", m_imap->cache_hits());
    }
    if (m_mailboxes && m_mailboxes->enabled())
    {
        put(out, "mail_stored", m_mailboxes->stored());
        put(out, "mail_store_failures", m_mailboxes->store_failures());
    }
    put(out, "mail_checked", m_checked);
    put(out, "mail_dmarc_rejected", m_dmarc_rejected);
    if (m_dnsbl)
    {
        put(out, "mail_dnsbl_asked", m_dnsbl->asked());
        put(out, "mail_dnsbl_listed", m_dnsbl->listed());
        put(out, "mail_blocklisted", m_blocklisted);
    }
    put(out, "mail_quarantined", m_quarantined);
    put(out, "mail_spam_rejected", m_spam_rejected);
    put(out, "mail_spam_junked", m_spam_junked);
    put(out, "mail_greylisted", m_greylisted);
    put(out, "mail_reports_sent", m_reports_sent);
    put(out, "auth_ok", m_auth_ok);
    put(out, "auth_failed", m_auth_failed);
    put(out, "auth_locked_out", m_auth_locked);
    put(out, "mail_rate_limited", m_rate_limited);
    put(out, "starttls", m_starttls);
    put(out, "tls_failures", m_tls_failures);
    if (m_delivery)
        m_delivery->stats(out);
    return out;
}

}   // namespace socketley::mail
