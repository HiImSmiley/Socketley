#include "mail_run.h"
#include "mail_text.h"
#include "mail_content.h"
#include "mail_setup.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <sys/stat.h>
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
#include "../../shared/persist/paths.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/net/address_key.h"
#include "../../shared/net/dns_feed.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/runtime/stats_text.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/hex.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/settings.h"
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
// An account failed at this often in the window, from this many addresses, is refused to all but those it signed in
// from within known_for_ms: a spray of guesses from many addresses, which no one address's count sees.
constexpr uint32_t account_failures_max = 20;
constexpr size_t account_addresses_min = 3;
constexpr int64_t known_for_ms = 30ll * 86400000;
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

// Whom a provider's feedback report (ARF, RFC 5965) says complained: its Original-Rcpt-To, or the To of the message it
// encloses; nothing for a message that is no such report.
std::vector<std::string> arf_complainants(std::string_view msg)
{
    std::vector<std::string> out;
    const std::string type = header_value(header_block(msg), "Content-Type");
    if (!contains_ci(type, "multipart/report") || !contains_ci(type, "feedback-report"))
        return out;
    const auto add = [&out](std::string_view v) {
        std::string a(v);
        if (const size_t lt = a.find('<'); lt != std::string::npos)
            a = a.substr(lt + 1, a.find('>', lt) == std::string::npos ? std::string::npos : a.find('>', lt) - lt - 1);
        while (!a.empty() && (a.back() == ' ' || a.back() == '\r'))
            a.pop_back();
        while (!a.empty() && a.front() == ' ')
            a.erase(0, 1);
        socketley::ascii::lower_in_place(a);
        if (a.find('@') != std::string::npos && a.find_first_of(" ,;") == std::string::npos && out.size() < 10 &&
            std::find(out.begin(), out.end(), a) == out.end())
            out.push_back(a);
    };
    const std::string_view body = msg.substr(std::min(msg.size(), header_block(msg).size()));
    for (size_t at = 0; (at = body.find("Original-Rcpt-To:", at)) != std::string_view::npos; at += 17)
    {
        const size_t end = body.find('\n', at);
        add(body.substr(at + 17, end == std::string_view::npos ? std::string_view::npos : end - at - 17));
    }
    if (!out.empty())
        return out;
    // The enclosed message's header, after the part that says it is one.
    for (const std::string_view kind : {std::string_view("message/rfc822"), std::string_view("text/rfc822-headers")})
        if (const size_t at = body.find(kind); at != std::string_view::npos)
        {
            const size_t start = body.find("\n\n", at) != std::string_view::npos ? body.find("\n\n", at) + 2
                                 : body.find("\r\n\r\n", at) != std::string_view::npos ? body.find("\r\n\r\n", at) + 4
                                                                                   : std::string_view::npos;
            if (start == std::string_view::npos)
                continue;
            const std::string to = header_value(header_block(body.substr(start)), "To");
            for (std::string_view rest = to; !rest.empty();)
            {
                const size_t comma = rest.find(',');
                add(rest.substr(0, comma));
                rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            }
            break;
        }
    return out;
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
    return socketley::hex_encode(h.data(), std::min<size_t>(h.size(), 10));
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
    // A request of its first line alone has no headers after it.
    const std::string_view rest = first.size() + 2 <= head.size() ? head.substr(first.size() + 2) : std::string_view();
    for (const auto& [name, value] : split_headers(rest))
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
    // The address an advertisement's mailto: unsubscribes at, its token in the Subject (RFC 2369).
    if (socketley::ascii::iequals(a.local, "unsubscribe"))
        return {route_to::unsubscribe, {}};
    // A user's own address, which the mailboxes say is one or is not.
    if (m_mailboxes && m_mailboxes->enabled() && !m_owner.get_idp().empty())
        return {route_to::mailbox, base};
    return {};
}

bool mail_run::suppressed(std::string_view addr) const
{
    std::string a(addr);
    socketley::ascii::lower_in_place(a);
    return m_suppressed.set.count(a) > 0;
}

std::string mail_run::unsubscribe_token(std::string_view addr) const
{
    std::string a(addr);
    socketley::ascii::lower_in_place(a);
    const std::string mac = socketley::crypto::hmac_sha256(m_verp_key, "unsubscribe\n" + a);
    return socketley::base64url::encode(a) + "." + socketley::hex_encode(mac.data(), std::min<size_t>(mac.size(), 12));
}

std::string mail_run::unsubscribe_address(std::string_view token) const
{
    const size_t dot = token.rfind('.');
    std::string a;
    if (dot == std::string_view::npos || !socketley::base64url::decode(token.substr(0, dot), a) || a.empty() ||
        a.size() > 320 || a.find_first_of(" \t\r\n<>") != std::string::npos)
        return {};
    // Compared whole and in constant time, so a guess learns nothing from how long the answer took.
    const std::string want = unsubscribe_token(a);
    return want.size() == token.size() && CRYPTO_memcmp(want.data(), token.data(), want.size()) == 0 ? a : std::string();
}

std::string mail_run::web_url() const
{
    if (!m_owner.get_web_port())
        return {};
    std::string_view names = m_owner.get_domains();
    std::string name;
    for (const char ch : socketley::take_item(names))
        if (ch != ' ' && ch != '\t')
            name += ch;
    if (name.empty())
        return {};
    if (name.find('.') == std::string::npos)
    {
        if (m_domains.empty())
            return {};
        name += "." + m_domains.front();
    }
    return "https://" + name;
}

bool mail_run::advertise(compose& c, std::string& why, bool& skipped)
{
    skipped = false;
    const size_t n = c.to.size() + c.cc.size() + c.bcc.size();
    if (n != 1)
    {
        why = "an advertisement goes to one recipient at a time, so each has a link to unsubscribe of their own";
        return false;
    }
    const std::string& one = !c.to.empty() ? c.to.front() : !c.cc.empty() ? c.cc.front() : c.bcc.front();
    address a;
    if (!parse_mailbox(one, a, nullptr) || a.domain.empty())
    {
        why = one + " is not an address";
        return false;
    }
    std::string addr = a.text();
    socketley::ascii::lower_in_place(addr);
    load_list(m_unsubscribed);
    if (m_unsubscribed.set.count(addr))
    {
        skipped = true;
        why = addr + " unsubscribed";
        return false;
    }
    const std::string token = unsubscribe_token(addr);
    const std::string base = web_url();
    const std::string https = base.empty() ? std::string() : base + "/unsubscribe?t=" + token;
    const std::string mailto = m_domains.empty() ? std::string() : "mailto:unsubscribe@" + m_domains.front() + "?subject=" + token;
    const std::string link = !https.empty() ? https : mailto;
    if (link.empty())
    {
        why = "an advertisement needs a way to unsubscribe: a domain, from --mail-domain or --dns, or --web with --domain";
        return false;
    }
    // Where the template says, or below what it says; the link is the same in the text and in the HTML.
    const auto put = [&link](std::string& body, bool html) {
        if (body.empty())
            return;
        const std::string mark = "{{unsubscribe}}";
        std::string shown = link;
        if (html)
            for (size_t at = 0; (at = shown.find('&', at)) != std::string::npos; at += 5)
                shown.replace(at, 1, "&amp;");
        if (body.find(mark) != std::string::npos)
        {
            for (size_t at = 0; (at = body.find(mark, at)) != std::string::npos; at += shown.size())
                body.replace(at, mark.size(), shown);
            return;
        }
        if (!html)
        {
            body += "\n\n--\nUnsubscribe: " + link + "\n";
            return;
        }
        const std::string footer = "<p style=\"margin:24px 0 0;font-size:12px;color:#888\"><a href=\"" + shown +
                                   "\" style=\"color:#888\">Unsubscribe</a></p>";
        std::string lower = body;
        socketley::ascii::lower_in_place(lower);
        const size_t end = lower.rfind("</body>");
        body.insert(end == std::string::npos ? body.size() : end, footer);
    };
    put(c.text, false);
    put(c.html, true);
    std::string header = "List-Unsubscribe: ";
    if (!https.empty())
        header += "<" + https + ">";
    if (!mailto.empty())
        header += std::string(https.empty() ? "" : ", ") + "<" + mailto + ">";
    c.headers.push_back(header);
    // One click at the provider unsubscribes, a POST to the https link (RFC 8058).
    if (!https.empty())
        c.headers.push_back("List-Unsubscribe-Post: List-Unsubscribe=One-Click");
    // Which list it is, its sender's address, as the providers that sort mailing lists apart read it (RFC 2919).
    const bool named = std::any_of(c.headers.begin(), c.headers.end(),
                                   [](const std::string& h) { return socketley::ascii::iequals(h.substr(0, 8), "List-Id:"); });
    std::string sender = c.from;
    if (const size_t lt = sender.rfind('<'); lt != std::string::npos)
        sender = sender.substr(lt + 1, sender.find('>', lt) - lt - 1);
    if (const size_t at = sender.rfind('@'); !named && at != std::string::npos && at > 0)
    {
        std::string id;
        for (const char ch : sender.substr(0, at) + "." + sender.substr(at + 1))
            if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '-')
                id += static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (!id.empty())
            c.headers.push_back("List-Id: <" + id + ">");
    }
    return true;
}

bool mail_run::unsubscribe(std::string_view token)
{
    const std::string a = unsubscribe_address(token);
    if (a.empty())
        return false;
    load_list(m_unsubscribed);
    if (!m_unsubscribed.set.count(a))
    {
        ++m_unsubscribes;
        LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": " + a + " unsubscribed").c_str());
        edit_list(m_unsubscribed, {a}, {});
    }
    return true;
}

bool mail_run::no_reply_local(std::string_view local)
{
    return socketley::ascii::iequals(local, "no-reply") ||
           (local.size() > 9 && socketley::ascii::iequals(local.substr(0, 9), "no-reply+"));
}

std::string mail_run::verp_token(std::string_view addr, int64_t day) const
{
    std::string a(addr);
    socketley::ascii::lower_in_place(a);
    const std::string d = std::to_string(day);
    const std::string mac = socketley::crypto::hmac_sha256(m_verp_key, "verp\n" + a + "\n" + d);
    return d + "-" + socketley::hex_encode(mac.data(), std::min<size_t>(mac.size(), 10));
}

namespace
{

// An address list as its file holds it: an address and when it went in, a line each.
std::unordered_map<std::string, int64_t> parse_list(std::string_view text, int64_t now_s)
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

void mail_run::load_list(address_list& l)
{
    const auto stamp = socketley::file_stamp::of(l.path);
    if (l.stamp && *l.stamp == stamp)
        return;
    l.stamp = stamp;
    std::string text;
    if (!socketley::read_file(l.path, text, {.missing_ok = true}, nullptr))
        return;
    std::unordered_set<std::string> got;
    for (auto& [a, at] : parse_list(text, wall::now_ms() / 1000))
        got.insert(a);
    l.set = std::move(got);
}

void mail_run::edit_list(address_list& l, std::vector<std::string> add, std::vector<std::string> remove)
{
    for (const auto& a : add)
        l.set.insert(a);
    for (const auto& a : remove)
        l.set.erase(a);
    // Read, merged and written under a lock of the file, so two shards' changes are both kept; never on the loop.
    auto result = std::make_shared<std::unordered_set<std::string>>();
    auto why = std::make_shared<std::string>();
    auto stamp = std::make_shared<socketley::file_stamp>();
    const std::string path = l.path;
    m_pool.submit(0,
                  [path, keep_s = l.keep_s, add = std::move(add), remove = std::move(remove), result, why, stamp] {
                      const int lock = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
                      if (lock >= 0 && ::flock(lock, LOCK_EX) != 0) {}
                      std::string text;
                      const int64_t now_s = socketley::wall::now_ms() / 1000;
                      auto all = socketley::read_file(path, text, {.missing_ok = true}, nullptr)
                                     ? parse_list(text, now_s)
                                     : std::unordered_map<std::string, int64_t>{};
                      if (keep_s)
                          std::erase_if(all, [now_s, keep_s](const auto& kv) { return now_s - kv.second > keep_s; });
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
                      // Taken under the lock, so a write of another shard after it is not taken as seen.
                      *stamp = socketley::file_stamp::of(path);
                      if (lock >= 0)
                          ::close(lock);
                  },
                  [this, &l, result, why, stamp, path, alive = m_alive] {
                      if (!*alive)
                          return;
                      if (!why->empty())
                      {
                          LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + path + " could not be kept: " + *why)
                                       .c_str());
                          return;
                      }
                      l.set = std::move(*result);
                      l.stamp = *stamp;
                  });
}

void mail_run::bounce_taken(std::string_view message, std::string_view to, bool trusted)
{
    ++m_bounces_taken;
    const size_t plus = to.find('+'), at = to.rfind('@');
    const std::string_view token = plus != std::string_view::npos && at != std::string_view::npos && plus < at
                                       ? to.substr(plus + 1, at - plus - 1)
                                       : std::string_view{};
    // The day the token was made on, -1 where it names none or one past verp_max_age_days.
    int64_t day = -1;
    if (const size_t dash = token.find('-'); dash != std::string_view::npos && dash > 0 && dash <= 9)
    {
        const int64_t today = wall::now_ms() / 86400000;
        const auto r = std::from_chars(token.data(), token.data() + dash, day);
        if (r.ec != std::errc() || r.ptr != token.data() + dash || day > today || today - day > verp_max_age_days)
            day = -1;
    }
    // A delivery status report names each recipient, then what was done with it (RFC 3464 2.3).
    std::vector<std::string> dead;
    // The one of `dead` its block's Status, read after its Action, may still take back.
    size_t dead_at_status = SIZE_MAX;
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
        // A Status of 4.x.x is a recipient deferred, whatever its Action says; one of 5.2.2 a mailbox full, which empties.
        if (socketley::ascii::iequals(name, "Status") && !dead.empty() && dead_at_status == dead.size() - 1 &&
            (value.starts_with("4.") || value.starts_with("5.2.2")))
        {
            dead.pop_back();
            dead_at_status = SIZE_MAX;
            continue;
        }
        if (socketley::ascii::iequals(name, "Final-Recipient"))
        {
            dead_at_status = SIZE_MAX;
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
                if (trusted || (day >= 0 && socketley::ascii::iequals(token, verp_token(recipient, day))))
                {
                    if (!m_suppressed.set.count(recipient) &&
                        std::find(dead.begin(), dead.end(), recipient) == dead.end())
                    {
                        dead.push_back(recipient);
                        dead_at_status = dead.size() - 1;
                    }
                }
            }
            recipient.clear();
        }
    }
    if (dead.empty())
        return;
    edit_list(m_suppressed, std::move(dead), {});
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
    // The addresses and accounts refused when it last ran, and the addresses each account signs in from.
    load_auth();
    m_spool.on_outcome = [this](const spool_entry& e, size_t i, rcpt_state s) {
        trace(e.id, e.from, e.rcpts[i].addr,
              s == rcpt_state::delivered ? "delivered" : s == rcpt_state::failed ? "bounced" : "deferred", e.rcpts[i].why);
    };
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
    m_suppressed.path = mail_suppressed_path(m_owner.get_name());
    m_suppressed.keep_s = suppressed_for_s;
    m_unsubscribed.path = mail_unsubscribed_path(m_owner.get_name());
    load_list(m_suppressed);
    load_list(m_unsubscribed);
    // The key of no-reply mail's tags, made by the first shard to start and read by the others.
    {
        const std::string path = mail_verp_key_path(m_owner.get_name());
        const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0)
        {
            const std::string key = socketley::random_hex(32);
            // A key not whole is taken away, so the next start makes one and not trips on an empty file.
            if (key.empty() || !socketley::write_all(fd, key.data(), key.size()) || ::fsync(fd) != 0)
                ::unlink(path.c_str());
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
    // A certificate the entrance has still to write is waited for, mail taken meanwhile by the listeners that need none.
    if (m_owner.get_tls() && certificate_to_come())
    {
        m_cert_wait = true;
        LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": waiting for its certificate, " +
                  std::string(m_owner.get_cert_path()) + "; what takes a password or speaks TLS opens when it is there")
                     .c_str());
    }
    else if (m_owner.get_tls())
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
        m_idp->configure(m_owner.get_idp(), m_owner.get_idp_audience());
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
    // The spam filter scores on the shard that takes mail: what it kept, what it was folding, and the journal after.
    if (m_owner.get_shard_index() == 0)
    {
        m_bayes = std::make_unique<bayes>();
        const std::string path = mail_bayes_path(m_owner.get_name());
        std::string bwhy, text;
        if (!m_bayes->load(path, bwhy))
        {
            LOG_ERROR(("mail " + std::string(m_owner.get_name()) + ": " + bwhy + "; its spam filter starts empty").c_str());
            m_bayes = std::make_unique<bayes>();
        }
        if (socketley::read_file(path + ".folding", text, {.missing_ok = true}, nullptr))
            m_bayes->apply(text);
        text.clear();
        if (socketley::read_file(path + ".journal", text, {.missing_ok = true}, nullptr))
            m_bayes_off = m_bayes->apply(text);
        m_bayes_folded_ms = wall::now_ms_coarse();
    }
    m_ring = m_loop.setup_buf_ring(ring_group, ring_bufs, ring_buf_bytes);
    m_multishot = m_ring && m_loop.recv_multishot_enabled();
    // Mail is taken on shard 0 alone, since each shard's spool syncs apart: on one disk four shards took half of what
    // one did.
    const bool takes_mail = m_owner.get_shard_index() == 0;
    if (takes_mail && !open_listener(m_smtp, m_owner.effective_port(), port_kind::smtp, why))
        return false;
    // IMAP on every shard, each reading the others' changes from the users' journals.
    if (m_mailboxes && m_mailboxes->enabled())
        m_imap = std::make_unique<imap_store>(*this);
    // Sieve filters the mail a mailbox takes, so its scripts are every shard's, and ManageSieve listens on each.
    if (m_mailboxes && m_mailboxes->enabled())
        m_sieve = std::make_unique<sieve_store>(mail_sieve_dir(m_owner.get_name()));
    // Calendars and contacts beside the mail, on the ports JMAP and the webmail answer on.
    if (m_mailboxes && m_mailboxes->enabled())
        m_dav = std::make_unique<dav_store>(*m_mailboxes, mail_dav_dir(m_owner.get_name()), m_alive);
    else if (m_owner.get_sieve_port())
    {
        why = "--sieve keeps the filters of mailboxes, which need --idp and --storage";
        return false;
    }
    // The webmail is the entrance's, which takes its TLS, and LMTP hands mail to the mailboxes, on every shard.
    if (m_imap && m_owner.get_web_port() && !open_listener(m_web_l, m_owner.get_web_port(), port_kind::web, why))
        return false;
    if (takes_mail && m_imap && m_owner.get_lmtp_port() &&
        !open_listener(m_lmtp_l, m_owner.get_lmtp_port(), port_kind::lmtp, why))
        return false;
    if (!m_cert_wait && !open_secured(why))
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
    LOG_INFO(("mail " + std::string(m_owner.get_name()) +
              (m_smtp.fd >= 0 ? ": serving SMTP on " + std::to_string(m_owner.effective_port())
                              : " shard " + std::to_string(m_owner.get_shard_index()) + ": serving the mailboxes, mail taken on shard 0") +
              (m_sub.fd >= 0 ? ", submission on " + std::to_string(m_owner.get_submission_port()) : std::string()) +
              (m_subs.fd >= 0 ? ", submission over TLS on " + std::to_string(m_owner.get_submissions_port())
                              : std::string()) +
              " as " + m_hostname + ", " + std::to_string(m_spool.entries().size()) + " message(s) queued")
                 .c_str());
    return true;
}

bool mail_run::certificate_to_come() const
{
    // Only one socketley writes, beside the entrance's ACME, is waited for; a path the operator gave is there or wrong.
    const std::string acme = (socketley_paths::resolve().state_dir / ".acme").string() + "/";
    struct stat st{};
    for (const std::string_view p : {m_owner.get_cert_path(), m_owner.get_key_path()})
        if (std::string(p).starts_with(acme) && ::stat(std::string(p).c_str(), &st) != 0 && errno == ENOENT)
            return true;
    return false;
}

bool mail_run::open_secured(std::string& why, std::vector<listener*>* opened)
{
    const bool takes_mail = m_owner.get_shard_index() == 0;
    const auto open = [&](bool wanted, listener& l, uint16_t port, port_kind kind) {
        if (!wanted || !port)
            return true;
        if (!open_listener(l, port, kind, why))
            return false;
        if (opened)
            opened->push_back(&l);
        return true;
    };
    // POP3 reads the INBOX IMAP keeps; all of them take a password, so they wait with the TLS ones for the certificate.
    return open(takes_mail, m_sub, m_owner.get_submission_port(), port_kind::submission) &&
           open(takes_mail, m_subs, m_owner.get_submissions_port(), port_kind::submissions) &&
           open(m_imap != nullptr, m_imap_l, m_owner.get_imap_port(), port_kind::imap) &&
           open(m_imap != nullptr, m_imaps_l, m_owner.get_imaps_port(), port_kind::imaps) &&
           open(m_sieve != nullptr, m_sieve_l, m_owner.get_sieve_port(), port_kind::sieve) &&
           open(m_imap != nullptr, m_pop3_l, m_owner.get_pop3_port(), port_kind::pop3) &&
           open(m_imap != nullptr, m_pop3s_l, m_owner.get_pop3s_port(), port_kind::pop3s) &&
           open(m_imap != nullptr, m_jmap_l, m_owner.get_jmap_port(), port_kind::jmap) &&
           open(true, m_sts_l, m_owner.get_mta_sts_port(), port_kind::sts);
}

bool mail_run::open_listener(listener& l, uint16_t port, port_kind kind, std::string& why)
{
    l.kind = kind;
    // With no address to bind, one socket takes IPv6 and IPv4 alike, as an MX reachable over both must; an IPv6
    // address binds that alone, and an IPv4 one, or a kernel without IPv6, IPv4.
    // The webmail port is the entrance's alone, which reaches it on 127.0.0.1 and takes its TLS.
    const bool local = kind == port_kind::web;
    const std::string_view bind = local ? std::string_view("127.0.0.1") : m_owner.get_bind_address();
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
        a.sin_addr.s_addr = local ? htonl(INADDR_LOOPBACK) : m_owner.bind_in_addr();
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
        const std::string net = socketley::address_key(ip);
        const bool smtp_port = l.kind == port_kind::smtp || l.kind == port_kind::submission || l.kind == port_kind::lmtp;
        const bool imap_port = l.kind == port_kind::imap || l.kind == port_kind::imaps;
        // The flag's limit is the runtime's, the default this process's own.
        const size_t asked = m_owner.get_max_connections();
        const uint32_t per_ip = l.kind == port_kind::smtp ? smtp_per_ip : other_per_ip;
        const bool full = asked ? m_owner.connections_full(m_conns.size(), asked)
                                : default_max_conns && m_conns.size() >= default_max_conns;
        const bool crowded = !loopback(peer) && m_clients[net].conns >= per_ip;
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
            if (m_clients[net].conns == 0 && m_clients[net].failures == 0)
                m_clients.erase(net);
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
            c->net = net;
            ++m_clients[net].conns;
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->closing_ms = c->heard_ms = wall::now_ms_coarse();
            conn* raw = c.get();
            m_conns.emplace(raw->id, std::move(c));
            runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
            m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            // A port that speaks TLS from the first byte begins with the handshake, any other with the greeting.
            // JMAP is HTTPS where the runtime has a certificate, HTTP for this machine's own clients where it has none.
            if (l.kind == port_kind::submissions || l.kind == port_kind::imaps || l.kind == port_kind::pop3s ||
                l.kind == port_kind::sts || (l.kind == port_kind::jmap && m_tls))
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
    cfg.bearer_offered = m_idp != nullptr;
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
        cfg.bearer_offered = m_idp != nullptr;
        c.pop3 = std::make_unique<pop3_session>(cfg, c);
        c.pop3->greet();
    }
    else if (c.kind == port_kind::sts)
        c.sts = true;
    else if (c.kind == port_kind::jmap || c.kind == port_kind::web)
    {
        jmap_config cfg;
        cfg.hostname = m_hostname;
        cfg.tls_active = c.ssl != nullptr && c.handshaken;
        cfg.web = c.kind == port_kind::web;
        // Behind the entrance every peer is 127.0.0.1, so a password goes only where it forwards HTTPS.
        cfg.login_in_clear = loopback(c.peer) && !cfg.web;
        cfg.trust_forwarded = cfg.web && loopback(c.peer);
        cfg.max_size = m_owner.get_max_size();
        c.jmap = std::make_unique<jmap_session>(cfg, c, *m_imap);
    }
    else if (c.kind == port_kind::imap || c.kind == port_kind::imaps)
    {
        imap_config cfg;
        cfg.hostname = m_hostname;
        cfg.tls_offered = m_tls != nullptr && c.kind == port_kind::imap;
        cfg.tls_active = c.ssl != nullptr && c.handshaken;
        cfg.login_in_clear = loopback(c.peer);
        cfg.bearer_offered = m_idp != nullptr;
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
    // Asked of the loop each time, because a kernel that refuses the flag turns it off after start.
    if (m_multishot && m_loop.recv_multishot_enabled())
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
    // A provided-buffer read is what the loop re-arms a refused multishot as, and it ends like one without F_MORE.
    if (c.rd.type == op_recv_multishot || c.rd.type == op_read_provided)
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
    if (!c.smtp && !c.imap && !c.sieve && !c.pop3 && !c.jmap)
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
    else if (c.jmap)
        c.jmap->input(std::string_view(p, n));
    else
        c.smtp->input(std::string_view(p, n));
    c.in_input = false;
    if (c.dead)
        return;
    // A client that sends past what a command and its largest message take while one waits, or that reads none of
    // what it is told, is not held in memory: it is told so and closed.
    const size_t cap = (c.sieve || c.pop3 ? 0 : c.jmap ? std::max<size_t>(m_owner.get_max_size(), jmap_session::max_request)
                                                       : m_owner.get_max_size()) + backlog_slack;
    const size_t held = c.imap ? c.imap->buffered() : c.sieve ? c.sieve->buffered() : c.pop3 ? c.pop3->buffered()
                        : c.jmap ? c.jmap->buffered() : c.smtp->buffered();
    if (held > cap || c.owed > owed_max + cap)
    {
        out(c, c.jmap ? std::string()
               : c.smtp ? "421 4.7.0 " + m_hostname + " too much input unanswered, closing\r\n"
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
    if (const auto it = m_clients.find(c.net); it != m_clients.end())
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

void mail_run::conn::authenticate(std::string_view protocol, std::string user, std::string secret,
                                  std::function<void(account, std::string)> done)
{
    mail_run& r = *run;
    // An address that failed too often lately is told to come back later, its password not looked at.
    const int64_t now = wall::now_ms_coarse();
    // Behind the entrance it is the client it forwards, which loopback never exempts.
    const std::string& seen = forwarded.empty() ? ip : forwarded;
    // Counted by its /64 for IPv6, so the addresses of one network are not each a fresh budget of guesses.
    const std::string from = socketley::address_key(seen);
    const bool guarded = !forwarded.empty() || !loopback(peer);
    std::string acct = user;
    socketley::ascii::lower_in_place(acct);
    if (guarded && (r.m_clients[from].locked_until_ms > now || r.account_refused(acct, from, now)))
    {
        ++r.m_auth_locked;
        done(account::unreachable, {});
        return;
    }
    // A wrong answer waits a second before it is said, and counts against its address and its account.
    auto finish = [&r, alive = r.m_alive, done, guarded, ip = from, seen, acct, proto = std::string(protocol)](
                      account a, std::string name) {
        if (!*alive)
            return;
        if (a != account::no)
        {
            r.m_auth_ok += a == account::yes;
            if (a == account::yes)
            {
                r.account_signed_in(acct, name, ip);
                LOG_INFO(("mail " + std::string(r.m_owner.get_name()) + ": " + name + " signed in over " + proto +
                          " from " + seen)
                             .c_str());
            }
            done(a, std::move(name));
            return;
        }
        ++r.m_auth_failed;
        if (guarded)
        {
            r.account_failed(acct, ip, wall::now_ms_coarse());
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
                r.m_auth_dirty = true;
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
        r.m_mailboxes->verify(user, secret, !guarded, [&r, me, finish](account a, std::string name, std::string email) {
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
    if (!run->may_send(smtp->user().empty() ? net : "user:" + smtp->user()))
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
        if (m_owner.get_global_rate_limit() > 0 && !m_owner.take_global_token())
        {
            // Refused by the shared bucket, the sender keeps its own token.
            cl.tokens += 1.0;
            return false;
        }
        return true;
    }
    return m_owner.get_global_rate_limit() <= 0 || m_owner.take_global_token();
}

void mail_run::conn::rcpt_to(const address& to, std::function<void(rcpt_verdict)> answer)
{
    mail_run& r = *run;
    // The script has the last word on each recipient, told what would be answered without it.
    const std::string sender = smtp->sender().text(), who = smtp->user();
    // A recipient refused for good is traced, so `mail trace` can say why mail never came.
    answer = [&r, inner = std::move(answer), sender, rcpt = to.text()](rcpt_verdict v) {
        if (v.code >= 500)
            r.trace("", sender, rcpt, "refused", std::to_string(v.code) + " " + v.text);
        inner(std::move(v));
    };
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
        case route_to::unsubscribe:
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
    head_cut = false;
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
    head_cut = !whole;
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
    // A message refused for good once it was whole -- by DMARC, the spam filter, a rule -- is traced for each recipient.
    if (entry)
    {
        std::vector<std::string> rcpts;
        for (const auto& rc : entry->rcpts)
            rcpts.push_back(rc.addr);
        done = [&r, inner = std::move(done), id = entry->id, from = entry->from, rcpts](rcpt_verdict v) {
            if (v.code >= 500)
                for (const auto& rc : rcpts)
                    r.trace(id, from, rc, "refused", std::to_string(v.code) + " " + v.text);
            inner(std::move(v));
        };
    }
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
        // A header whose end was not held may have its From past what was kept, and the signer would read that one.
        if (head_cut)
        {
            r.m_spool.abort(w);
            done({552, "The header runs past 64 KiB, too long for its From to be checked"});
            return;
        }
        if (!authors_owned(header_block(head), [this](const address& a) { return owns(a); }))
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
        auto tokens = std::make_shared<std::vector<uint32_t>>();
        auto complainants = std::make_shared<std::vector<std::string>>();
        // What inside it it is refused for: an attachment of a kind that runs, or what clamd found.
        auto refusal = std::make_shared<std::string>();
        auto unread = std::make_shared<bool>(false);
        const std::string path = r.m_spool.file_of(*e);
        const uint64_t off = e->body_off, len = e->body_len;
        r.m_checks.submit(r.m_checks.next_lane(),
                          [e, result, spam, tokens, complainants, refusal, unread, ip, helo, path, off, len,
                           trusted = r.m_arc_trusted, attachments = std::string(r.m_owner.get_refused_attachments()),
                           clamav = std::string(r.m_owner.get_clamav()),
                           rspamd = std::string(r.m_owner.get_rspamd()),
                           scored = r.m_bayes && r.m_bayes->trained()] {
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
                              // A provider's report that one of its users called our mail spam.
                              *complainants = arf_complainants(msg);
                              if (!result->reject())
                              {
                                  if (const std::string name = refused_attachment(msg, attachments); !name.empty())
                                      *refusal = "Message refused: attachments such as " + name + " are not taken";
                                  else if (!clamav.empty())
                                  {
                                      const virus_verdict v = clamav_scan(clamav, msg);
                                      if (!v.found.empty())
                                          *refusal = "Message refused: it carries " + v.found;
                                      else if (!v.scanned)
                                          LOG_WARN(("mail: clamd at " + clamav + " did not scan a message: " + v.why).c_str());
                                  }
                              }
                              // Its words, for the filter that learns, where Rspamd did not score it.
                              if (scored && !spam->scored && !result->reject())
                                  *tokens = spam_tokens(msg);
                          },
                          [&r, alive, e, done, result, unread, spam, tokens, complainants, refusal, ip] {
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
                              if (!refusal->empty())
                              {
                                  ++r.m_content_refused;
                                  r.m_spool.forget_written(e->id);
                                  done({554, *refusal});
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
                              // A complaint from a provider that is who it says, by its SPF or its DKIM: the
                              // complainant is sent no more advertisements, as one who unsubscribed is not.
                              if (!complainants->empty() && !result->reject() && (result->spf_aligned || result->dkim_aligned))
                                  r.complained(*complainants, result->from_domain);
                              // What the users taught the filter, where Rspamd said nothing.
                              if (!spam->scored && !tokens->empty() && r.m_bayes && r.m_bayes->trained())
                              {
                                  const double p = r.m_bayes->score(*tokens);
                                  char buf[48];
                                  std::snprintf(buf, sizeof buf, "; x-spam-bayes=%.2f", p);
                                  header += buf;
                                  if (p >= bayes::spam_at && !junk)
                                  {
                                      junk = true;
                                      ++r.m_bayes_junked;
                                  }
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

void mail_run::conn::bearer(std::string token, std::function<void(account, std::string)> done)
{
    socketley::idp::session_verifier::who who;
    if (!run->m_idp || !run->m_idp->check_bearer(token, who))
    {
        done(account::no, {});
        return;
    }
    idp_user = true;
    user_email = who.email;
    done(account::yes, who.username.empty() ? who.sub : who.username);
}

void mail_run::conn::cookie(std::string cookies, std::function<void(account, std::string)> done)
{
    socketley::idp::session_verifier::who who;
    if (!run->m_idp || !run->m_idp->check(cookies, who))
    {
        done(account::no, {});
        return;
    }
    idp_user = true;
    user_email = who.email;
    done(account::yes, who.username.empty() ? who.sub : who.username);
}

std::string mail_run::conn::idp_login(const std::string& back)
{
    return run->m_idp ? run->m_idp->login_url(back) : std::string();
}

std::string mail_run::conn::idp_logout(const std::string& back)
{
    return run->m_idp ? run->m_idp->logout_url(back) : std::string();
}

std::string mail_run::conn::address_of(const std::string& user)
{
    if (!user_email.empty())
        return user_email;
    return user.find('@') != std::string::npos || run->m_domains.empty() ? user : user + "@" + run->m_domains.front();
}

std::vector<std::string> mail_run::conn::addresses_of(const std::string& user)
{
    std::vector<std::string> out{address_of(user)};
    const auto add = [&out](std::string a) {
        socketley::ascii::lower_in_place(a);
        if (std::none_of(out.begin(), out.end(), [&](const std::string& x) { return socketley::ascii::iequals(x, a); }) &&
            out.size() < 32)
            out.push_back(std::move(a));
    };
    const std::string local = user.substr(0, user.find('@'));
    for (const auto& d : run->m_domains)
        add(local + "@" + d);
    for (const auto& [key, targets] : run->aliases().map)
        if (!key.starts_with("*@") && std::any_of(targets.begin(), targets.end(), [&](const std::string& t) {
                return socketley::ascii::iequals(t, out.front()) || socketley::ascii::iequals(t, user) ||
                       socketley::ascii::iequals(t, local);
            }))
            add(key);
    return out;
}

void mail_run::conn::submit(const std::string& user, const std::string& from, std::vector<std::string> rcpts,
                            std::string message, std::function<void(bool, std::string)> done, int64_t hold_until_ms)
{
    run->queue_message(from, rcpts, std::move(message), false, user, std::move(done), false, hold_until_ms);
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

// Taken as input is, so the head and the body go in one write.
void mail_run::conn::reply_with_body(std::string_view head, const std::shared_ptr<const std::string>& body)
{
    const bool was = in_input;
    in_input = true;
    reply(head);
    reply_shared(body, 0, body->size());
    in_input = was;
    if (!in_input && !dead)
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
    // Shared, so the fallback below still holds the callable the timer was given.
    const auto fn = std::make_shared<std::function<void()>>(std::move(f));
    if (!run->m_fio.after(std::chrono::milliseconds(0), [r = run, me, fn, alive = run->m_alive](int64_t) {
            if (!*alive)
                return;
            if (conn* c = r->find(me); c && !c->dead)
            {
                c->in_input = true;
                (*fn)();
                c->in_input = false;
                r->flush(*c);
            }
        }))
        (*fn)();
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

void mail_run::accepted(const entry_ptr& e, int64_t hold_until_ms)
{
    ++m_received;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    if (m_lua)
        m_lua->message(*e);
    if (!m_delivery)
        return;
    if (hold_until_ms)
        m_delivery->queued_at(e, hold_until_ms);
    else
        m_delivery->queued(e);
}

void mail_run::queue_message(const std::string& from, const std::vector<std::string>& rcpts, std::string body,
                             bool bounce, std::string user, std::function<void(bool, std::string)> done,
                             bool requiretls, int64_t hold_until_ms)
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
    m_spool.finish(w, [this, alive = m_alive, e, done, hold_until_ms](bool ok) {
        if (!*alive)
            return;
        // One held for later is taken now and first tried then, its time kept in the spool across a restart.
        if (ok && hold_until_ms > wall::now_ms_coarse())
        {
            m_spool.retry(*e, 0, hold_until_ms);
            accepted(e, hold_until_ms);
        }
        else if (ok)
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
    else if (req == &m_jmap_l.req)
        accept_done(m_jmap_l, cqe);
    else if (req == &m_web_l.req)
        accept_done(m_web_l, cqe);
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
    if (m_auth_dirty)
        save_auth();
    // Whether its address names it back and a blocklist names it at all: as it starts, and hourly after that.
    if (m_owner.get_shard_index() == 0 && (!m_self_checked_ms || now - m_self_checked_ms > 3600000))
    {
        m_self_checked_ms = now;
        check_own_listing();
        check_own_name();
    }
    // What the shards learned, into the table; folded into its file every ten minutes or past 8 MiB of journal.
    if (m_bayes)
    {
        bayes_read();
        // A test aid shortens the ten minutes.
        static const int64_t fold_ms = settings::number<int64_t>("SOCKETLEY_MAIL_BAYES_FOLD_MS").value_or(600000);
        if (m_bayes_off > (8u << 20) || (m_bayes_off && now - m_bayes_folded_ms > fold_ms))
            bayes_fold();
    }
    // The certificate written at last: TLS offered, and what waited for it opened.
    if (m_cert_wait && !certificate_to_come())
    {
        auto tls = std::make_unique<tls_context>();
        if (tls->init_server(m_owner.get_cert_path(), m_owner.get_key_path(), m_owner.get_ca_path()))
        {
            m_tls = std::move(tls);
            m_cert_wait = false;
            std::string why;
            std::vector<listener*> opened;
            if (!open_secured(why, &opened))
                LOG_ERROR(("mail " + std::string(m_owner.get_name()) + ": its certificate is there, but " + why).c_str());
            for (listener* l : opened)
                arm_accept(*l);
            publish_records();
            LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": its certificate is there; TLS is offered").c_str());
        }
    }
    std::vector<conn*> late;
    // Polling can close a connection, so it waits until the walk is over.
    std::vector<uint64_t> imap_poll, jmap_poll;
    for (auto& [id, c] : m_conns)
    {
        const bool shaking = c->ssl && !c->handshaken;
        // A test aid shortens every one of them alike.
        static const int64_t aid = settings::number<int64_t>("SOCKETLEY_MAIL_IDLE_MS").value_or(0);
        const int64_t quiet = aid ? aid : c->imap ? imap_idle_ms : idle_ms;
        const int64_t shake = aid ? std::min(aid, handshake_ms) : handshake_ms;
        if (!c->closing && ((shaking && now - c->closing_ms > shake) || now - c->heard_ms > quiet))
            late.push_back(c.get());
        // One closing with output its client does not read is closed once its grace is over.
        else if (c->closing && now - c->closing_ms >= close_grace_ms)
            m_close_soon.push_back(c->id);
        else if (c->imap && (c->imap->idling() || c->imap->notifying()))
            imap_poll.push_back(c->id);
        else if (c->jmap && c->jmap->streaming())
        {
            // An EventSource's client says nothing: it is kept while it reads what it is told.
            c->heard_ms = now;
            jmap_poll.push_back(c->id);
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
    for (const uint64_t id : imap_poll)
        if (conn* c = find(id); c && !c->dead && c->imap)
        {
            c->in_input = true;
            c->imap->poll();
            c->in_input = false;
            flush(*c);
        }
    for (const uint64_t id : jmap_poll)
        if (conn* c = find(id); c && !c->dead && c->jmap)
        {
            c->in_input = true;
            c->jmap->poll();
            c->in_input = false;
            flush(*c);
        }
    if (now >= m_next_files_ms)
    {
        m_next_files_ms = now + 1000;
        push_tick();
        // An address with no connection, no lockout and no failure or message lately is forgotten.
        std::erase_if(m_clients, [now](const auto& kv) {
            const client& cl = kv.second;
            return cl.conns == 0 && cl.locked_until_ms <= now && now - cl.first_failure_ms > auth_window_ms &&
                   now - cl.tokens_ms > 60000;
        });
        refresh_files();
        refresh_domains();
        load_list(m_suppressed);
        load_list(m_unsubscribed);
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
    // The name it greets with has an SPF of its own, which a receiver checking the HELO identity asks (RFC 7208 2.3).
    for (const auto& d : m_domains)
        if (m_hostname.size() > d.size() + 1 && m_hostname.ends_with("." + d))
        {
            out += m_hostname + ". 300 IN TXT \"v=spf1 a -all\"\n";
            break;
        }
    for (const auto& d : m_domains)
    {
        out += d + ". 300 IN MX 10 " + m_hostname + ".\n";
        out += d + ". 300 IN TXT \"" + spf + "\"\n";
        for (const auto& [sel, record] : keys)
            out += sel + "._domainkey." + d + ". 300 IN TXT \"" + record + "\"\n";
        const std::string_view rua = m_owner.get_dmarc_rua();
        out += "_dmarc." + d + ". 300 IN TXT \"v=DMARC1; p=" + std::string(m_owner.get_dmarc_policy()) + "; adkim=r; aspf=r" +
               (rua.empty() ? std::string() : "; rua=mailto:" + std::string(rua)) + "\"\n";
        // Its logo beside its messages, at the providers that show one for a domain DMARC enforces.
        if (const std::string_view bimi = m_owner.get_bimi(); !bimi.empty())
        {
            const size_t comma = bimi.find(',');
            out += "default._bimi." + d + ". 300 IN TXT \"v=BIMI1; l=" + std::string(bimi.substr(0, comma)) + "; a=" +
                   (comma == std::string_view::npos ? std::string() : std::string(bimi.substr(comma + 1))) + "\"\n";
        }
        // MTA-STS (RFC 8461) and where TLS reports go (RFC 8460), where it publishes them.
        if (!m_owner.get_mta_sts().empty())
            out += "_mta-sts." + d + ". 300 IN TXT \"v=STSv1; id=" + sts_id() + "\"\n";
        // The policy's host is this one where it serves the policy itself.
        if (!m_owner.get_mta_sts().empty() && m_owner.get_mta_sts_port())
            out += "mta-sts." + d + ". 300 IN CNAME " + m_hostname + ".\n";
        if (!m_owner.get_tls_rpt().empty())
            out += "_smtp._tls." + d + ". 300 IN TXT \"v=TLSRPTv1; rua=mailto:" + std::string(m_owner.get_tls_rpt()) +
                   "\"\n";
        // Where Outlook asks how a mailbox is reached, the entrance's name the webmail answers under.
        if (m_owner.get_web_port() && !m_owner.get_domains().empty())
            out += "_autodiscover._tcp." + d + ". 300 IN SRV 0 1 443 autodiscover." + d + ".\n";
        // And where a calendar or contacts client finds them, at the webmail's name (RFC 6764).
        if (const std::string url = web_url(); m_mailboxes && m_mailboxes->enabled() && !url.empty())
            for (const char* service : {"_caldavs", "_carddavs"})
                out += std::string(service) + "._tcp." + d + ". 300 IN SRV 0 1 443 " + url.substr(8) + ".\n" +
                       service + "._tcp." + d + ". 300 IN TXT \"path=/dav/\"\n";
        // Where a mail client finds the ports it sends and reads on (RFC 6186, RFC 8314), and its filters' (RFC 5804).
        for (const auto& [service, port] : {std::pair{"_submissions", m_owner.get_submissions_port()},
                                            {"_submission", m_owner.get_submission_port()},
                                            {"_imaps", m_owner.get_imaps_port()},
                                            {"_imap", m_owner.get_imap_port()},
                                            {"_pop3s", m_owner.get_pop3s_port()},
                                            {"_pop3", m_owner.get_pop3_port()},
                                            {"_jmap", m_owner.get_jmap_port()},
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
    // One shard writes them, since every shard's are the same, and only once start has the keys and the certificate
    // they are of, so a dns runtime never serves the zone without its DKIM keys.
    if (m_owner.get_dns().empty() || m_owner.get_shard_index() != 0 || !m_delivery)
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
        {
            if (arg != "--check")
            {
                answer(records_text());
                return;
            }
            // Asked of the resolvers this machine uses, off the loop, as a sender elsewhere would ask them.
            auto out = std::make_shared<std::string>();
            m_pool.submit(0, [records = records_text(), out] { *out = dns_check_text(records); },
                          [answer, out] { answer(*out); });
            return;
        }
        case verb::unsubscribed:
        {
            load_list(m_unsubscribed);
            std::vector<std::string> all(m_unsubscribed.set.begin(), m_unsubscribed.set.end());
            std::sort(all.begin(), all.end());
            std::string out;
            for (const auto& a : all)
                out += a + "\n";
            answer(out);
            return;
        }
        case verb::resubscribe:
        {
            std::string a = arg;
            socketley::ascii::lower_in_place(a);
            load_list(m_unsubscribed);
            if (!m_unsubscribed.set.count(a))
            {
                answer("error: " + arg + " has not unsubscribed");
                return;
            }
            edit_list(m_unsubscribed, {}, {a});
            answer("ok");
            return;
        }
        case verb::suppressed:
        {
            load_list(m_suppressed);
            std::vector<std::string> all(m_suppressed.set.begin(), m_suppressed.set.end());
            std::sort(all.begin(), all.end());
            std::string out;
            for (const auto& a : all)
                out += a + "\n";
            answer(out);
            return;
        }
        case verb::trace:
            answer(trace_text(arg));
            return;
        case verb::usage:
        {
            if (!m_imap)
            {
                answer("error: there are no mailboxes, which need --idp and --storage");
                return;
            }
            const auto size = [](uint64_t b) {
                char buf[32];
                if (b >= (1ull << 30))
                    std::snprintf(buf, sizeof buf, "%.1f GiB", static_cast<double>(b) / (1ull << 30));
                else if (b >= (1ull << 20))
                    std::snprintf(buf, sizeof buf, "%.1f MiB", static_cast<double>(b) / (1ull << 20));
                else
                    std::snprintf(buf, sizeof buf, "%.1f KiB", static_cast<double>(b) / 1024);
                return std::string(buf);
            };
            std::string out;
            for (std::string_view rest = arg; !rest.empty();)
            {
                const size_t comma = rest.find(',');
                const std::string user(rest.substr(0, comma));
                rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
                if (user.empty())
                    continue;
                const uint64_t used = m_imap->usage(user), quota = m_imap->quota(user);
                std::string line(user.size() + 160, '\0');
                std::snprintf(line.data(), line.size(), "%-24s %12s  of %s%s\n", user.c_str(), size(used).c_str(),
                              quota ? size(quota).c_str() : "no quota",
                              quota ? (" (" + std::to_string(used * 100 / quota) + "%)").c_str() : "");
                out += line.c_str();
            }
            answer(out);
            return;
        }
        case verb::export_box:
        case verb::import_box:
            answer(transfer_command(static_cast<verb>(v) == verb::export_box, arg));
            return;
        case verb::job:
            answer(transfer_job(arg));
            return;
        case verb::learn:
        {
            const std::string refused = learn_command(arg, answer);
            if (!refused.empty())
                answer(refused);
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
            load_list(m_suppressed);
            if (!m_suppressed.set.count(a))
            {
                answer("error: " + arg + " is not suppressed");
                return;
            }
            edit_list(m_suppressed, {}, {a});
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
    if (c.ad)
    {
        bool skipped = false;
        if (!advertise(c, why, skipped))
        {
            answer((skipped ? "skipped: " : "error: ") + why);
            return;
        }
    }
    std::vector<std::string> rcpts;
    if (!m_delivery)
    {
        answer("error: the mail runtime is not running");
        return;
    }
    if (!m_delivery->compose_message(c, from, rcpts, body, why))
    {
        answer("error: " + why);
        return;
    }
    queue_message(from, rcpts, std::move(body), false, "local", [answer](bool ok, std::string id) {
        answer(ok ? "queued " + id : "error: the message could not be written to the spool");
    });
}

void mail_run::trace(const std::string& id, const std::string& from, const std::string& rcpt, std::string_view what,
                     std::string_view why)
{
    if (m_traced.size() >= 20000)
        m_traced.pop_front();
    m_traced.push_back({wall::now_ms(), id, from, rcpt, std::string(what), std::string(why)});
    LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": " + (id.empty() ? std::string("-") : id) + " from <" + from +
              "> to <" + rcpt + ">: " + std::string(what) + (why.empty() ? "" : " (" + std::string(why) + ")"))
                 .c_str());
}

void mail_run::web_filters(const std::string& user, std::optional<std::string> script,
                           std::function<void(int, std::string)> done)
{
    if (!m_sieve)
    {
        done(404, "{\"error\":\"filters need --idp and --storage\"}");
        return;
    }
    auto status = std::make_shared<int>(200);
    auto out = std::make_shared<std::string>();
    m_pool.submit(0,
                  [this, user, script = std::move(script), status, out] {
                      const auto ask = [&](std::string_view verb, std::string_view text) {
                          return sieve_command(socketley::base64::encode(user + "\n" + std::string(verb) + "\nwebmail\n" +
                                                                         std::string(text)));
                      };
                      if (!script)
                      {
                          std::string active;
                          for (std::string_view rest = ask("list", ""); !rest.empty();)
                          {
                              const size_t nl = rest.find('\n');
                              const std::string_view line = rest.substr(0, nl);
                              rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
                              if (line.ends_with("\tactive"))
                                  active = std::string(line.substr(0, line.size() - 7));
                          }
                          std::string text = ask("get", "");
                          if (text.starts_with("error:"))
                              text.clear();
                          *out = "{\"script\":";
                          socketley::json::quote_into(*out, text);
                          *out += ",\"active\":";
                          socketley::json::quote_into(*out, active);
                          *out += "}";
                          return;
                      }
                      std::string why = ask("put", *script);
                      if (why.empty())
                          why = ask("activate", "");
                      if (!why.empty())
                      {
                          *status = 400;
                          *out = "{\"error\":";
                          socketley::json::quote_into(*out, why.substr(why.starts_with("error: ") ? 7 : 0));
                          *out += "}";
                          return;
                      }
                      *out = "{\"ok\":true}";
                  },
                  [alive = m_alive, status, out, done] {
                      if (*alive)
                          done(*status, *out);
                  });
}

std::string mail_run::client_setup(std::string_view kind, const std::string& email) const
{
    const size_t at = email.rfind('@');
    if (at == std::string::npos || at == 0 || !is_local_domain(email.substr(at + 1)))
        return {};
    client_settings s;
    s.hostname = m_hostname;
    s.email = email;
    s.domain = email.substr(at + 1);
    socketley::ascii::lower_in_place(s.domain);
    // What begins in the clear is offered only with TLS to start, as the runtime takes no password without it.
    const bool tls = m_tls != nullptr || m_cert_wait;
    s.imaps = m_owner.get_imaps_port();
    s.imap = tls ? m_owner.get_imap_port() : 0;
    s.pop3s = m_owner.get_pop3s_port();
    s.pop3 = tls ? m_owner.get_pop3_port() : 0;
    s.submissions = m_owner.get_submissions_port();
    s.submission = tls ? m_owner.get_submission_port() : 0;
    if (m_dav)
        if (const std::string url = web_url(); !url.empty())
            s.dav_host = url.substr(8);
    if (kind == "autoconfig")
        return thunderbird_autoconfig(s);
    if (kind == "autodiscover")
        return outlook_autodiscover(s);
    if (kind == "mobileconfig")
        return apple_mobileconfig(s);
    std::string out = "{\"host\":";
    socketley::json::quote_into(out, s.hostname);
    for (const auto& [name, port] : {std::pair<const char*, uint16_t>{"imaps", s.imaps}, {"imap", s.imap}, {"pop3s", s.pop3s},
                                     {"pop3", s.pop3}, {"submissions", s.submissions}, {"submission", s.submission}})
        out += ",\"" + std::string(name) + "\":" + std::to_string(port);
    if (!s.dav_host.empty())
        out += ",\"dav\":\"https://" + s.dav_host + "/dav/\"";
    return out + "}";
}

void mail_run::complained(const std::vector<std::string>& who, const std::string& reporter)
{
    m_complaints += who.size();
    for (const auto& a : who)
    {
        trace("", reporter, a, "complained", "a feedback report of " + reporter + "; no more advertisements");
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + a + " called its mail spam, as " + reporter +
                  " reports; it is sent no more advertisements")
                     .c_str());
    }
    load_list(m_unsubscribed);
    std::vector<std::string> fresh;
    for (const auto& a : who)
        if (!m_unsubscribed.set.count(a))
            fresh.push_back(a);
    if (!fresh.empty())
        edit_list(m_unsubscribed, std::move(fresh), {});
}

bool mail_run::account_refused(const std::string& acct, const std::string& ip, int64_t now) const
{
    const auto it = m_accounts.find(acct);
    if (it == m_accounts.end() || it->second.locked_until_ms <= now)
        return false;
    const auto known = it->second.known.find(ip);
    return known == it->second.known.end() || now - known->second > known_for_ms;
}

void mail_run::account_signed_in(const std::string& acct, const std::string& name, const std::string& ip)
{
    const int64_t now = wall::now_ms_coarse();
    for (std::string key : {acct, name})
    {
        socketley::ascii::lower_in_place(key);
        auto& a = m_accounts[key];
        // A device it signs in from again and again is written down once a day.
        auto& at = a.known[ip];
        m_auth_dirty = m_auth_dirty || now - at > 86400000;
        at = now;
        if (a.known.size() > 64)
            a.known.erase(std::min_element(a.known.begin(), a.known.end(),
                                           [](const auto& x, const auto& y) { return x.second < y.second; }));
    }
}

void mail_run::account_failed(const std::string& acct, const std::string& ip, int64_t now)
{
    if (m_accounts.size() > 100000 && !m_accounts.count(acct))
        return;
    auto& a = m_accounts[acct];
    if (now - a.first_failure_ms > auth_window_ms)
    {
        a.first_failure_ms = now;
        a.failures = 0;
        a.from.clear();
    }
    ++a.failures;
    if (a.from.size() < 64)
        a.from.insert(ip);
    if (a.failures >= account_failures_max && a.from.size() >= account_addresses_min && a.locked_until_ms <= now)
    {
        a.locked_until_ms = now + auth_window_ms;
        m_auth_dirty = true;
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + acct + " was failed at " + std::to_string(a.failures) +
                  " times from " + std::to_string(a.from.size()) +
                  " addresses, and is refused for ten minutes to all but those it signed in from")
                     .c_str());
    }
}

// Each address and account refused, and each account's known addresses, a line each, beside the shard's spool.
void mail_run::save_auth()
{
    m_auth_dirty = false;
    const int64_t now = wall::now_ms_coarse();
    std::string text;
    for (const auto& [ip, c] : m_clients)
        if (c.locked_until_ms > now)
            text += "ip " + ip + " " + std::to_string(c.locked_until_ms) + "\n";
    for (const auto& [name, a] : m_accounts)
    {
        // A name with a space or a control byte would not read back as one field.
        if (std::any_of(name.begin(), name.end(),
                        [](char ch) { return static_cast<unsigned char>(ch) <= ' ' || ch == 0x7f; }))
            continue;
        if (a.locked_until_ms > now)
            text += "locked " + name + " " + std::to_string(a.locked_until_ms) + "\n";
        for (const auto& [ip, ms] : a.known)
            if (now - ms <= known_for_ms)
                text += "known " + name + " " + ip + " " + std::to_string(ms) + "\n";
    }
    auto body = std::make_shared<std::string>(std::move(text));
    m_pool.submit(0, [body, path = m_state_dir + "/auth"] {
        const std::string tmp = path + ".tmp";
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        const bool ok = fd >= 0 && socketley::write_all(fd, body->data(), body->size());
        if (fd >= 0)
            ::close(fd);
        if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0)
            ::unlink(tmp.c_str());
    }, [] {});
}

void mail_run::load_auth()
{
    std::string text;
    if (!socketley::read_file(m_state_dir + "/auth", text, {.missing_ok = true}, nullptr))
        return;
    const int64_t now = wall::now_ms_coarse();
    for (std::string_view rest = text; !rest.empty();)
    {
        const size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        std::vector<std::string> w;
        for (std::string_view l = line; !l.empty();)
        {
            const size_t sp = l.find(' ');
            w.emplace_back(l.substr(0, sp));
            l = sp == std::string_view::npos ? std::string_view{} : l.substr(sp + 1);
        }
        const auto ms = [&](size_t i) { return i < w.size() ? std::strtoll(w[i].c_str(), nullptr, 10) : 0; };
        // An address an older runtime wrote whole is read as what it counts under now.
        if (w.size() == 3 && w[0] == "ip" && ms(2) > now)
            m_clients[socketley::address_key(w[1])].locked_until_ms = ms(2);
        else if (w.size() == 3 && w[0] == "locked" && ms(2) > now)
            m_accounts[w[1]].locked_until_ms = ms(2);
        else if (w.size() == 4 && w[0] == "known" && now - ms(3) <= known_for_ms)
            m_accounts[w[1]].known[socketley::address_key(w[2])] = ms(3);
    }
}

void mail_run::check_own_name()
{
    auto said = std::make_shared<std::string>();
    auto unsure = std::make_shared<bool>(false);
    m_pool.submit(0,
                  [host = m_hostname, said, unsure] {
                      bool nx = false;
                      auto r = system_check_resolver(5000);
                      std::vector<std::string> addrs;
                      if (!r->addrs4(host, addrs, nx) || addrs.empty())
                      {
                          if (nx)
                              *said = host + " has no address";
                          else
                              *unsure = true;
                          return;
                      }
                      for (const auto& ip : addrs)
                      {
                          std::vector<std::string> names;
                          if (!r->ptr(ip, names, nx))
                          {
                              if (nx)
                                  *said += (said->empty() ? "" : "; ") + ip + " has no PTR record";
                              else
                                  *unsure = true;
                              continue;
                          }
                          if (std::none_of(names.begin(), names.end(),
                                           [&](const std::string& n) { return socketley::ascii::iequals(n, host); }))
                              *said += (said->empty() ? "" : "; ") + ip + "'s PTR names " +
                                       (names.empty() ? std::string("nothing") : names.front()) + ", not " + host;
                      }
                  },
                  [this, alive = m_alive, said, unsure] {
                      // A lookup that timed out says nothing about a mismatch already found.
                      if (!*alive || (*unsure && said->empty()))
                          return;
                      if (*said != m_name_mismatch && !said->empty())
                          LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + *said +
                                    "; receivers refuse or file as spam mail from an address that does not name its "
                                    "sender, and the PTR is set where the address is rented")
                                       .c_str());
                      m_name_mismatch = *said;
                  });
}

void mail_run::check_own_listing()
{
    if (!m_dnsbl || !m_dnsbl->enabled())
        return;
    auto addrs = std::make_shared<std::vector<std::string>>();
    m_pool.submit(0,
                  [host = m_hostname, addrs] {
                      bool nx = false;
                      auto r = system_check_resolver(5000);
                      if (!r->addrs4(host, *addrs, nx))
                          addrs->clear();
                  },
                  [this, alive = m_alive, addrs] {
                      if (!*alive || addrs->empty() || !m_dnsbl)
                          return;
                      auto listed = std::make_shared<std::string>();
                      auto left = std::make_shared<size_t>(addrs->size());
                      for (const auto& ip : *addrs)
                          m_dnsbl->check(ip, [this, alive, ip, listed, left](std::string zone) {
                              if (!*alive)
                                  return;
                              if (!zone.empty())
                                  *listed += (listed->empty() ? "" : ", ") + zone + " (" + ip + ")";
                              if (--*left)
                                  return;
                              if (*listed != m_self_listed)
                                  LOG_WARN(("mail " + std::string(m_owner.get_name()) +
                                            (listed->empty() ? ": no blocklist names it any more"
                                                             : ": its address is on a blocklist: " + *listed))
                                               .c_str());
                              m_self_listed = *listed;
                          });
                  });
}

std::string mail_run::dns_check_text(const std::string& records)
{
    auto resolver = system_check_resolver(10000);
    std::string out;
    size_t ok = 0, asked = 0;
    for (std::string_view rest = records; !rest.empty();)
    {
        const size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        // <name>. <ttl> IN <type> <value>
        std::vector<std::string_view> w;
        std::string_view l = line;
        for (int i = 0; i < 4 && !l.empty(); ++i)
        {
            const size_t sp = l.find(' ');
            w.push_back(l.substr(0, sp));
            l = sp == std::string_view::npos ? std::string_view{} : l.substr(sp + 1);
        }
        if (w.size() < 4 || l.empty())
            continue;
        std::string name(w[0]), want(l);
        if (!name.empty() && name.back() == '.')
            name.pop_back();
        const std::string_view type = w[3];
        std::vector<std::string> have;
        bool nx = false, answered = false;
        if (type == "TXT")
        {
            if (want.size() >= 2 && want.front() == '"' && want.back() == '"')
                want = want.substr(1, want.size() - 2);
            answered = resolver->txt(name, have, nx);
        }
        else if (type == "MX")
        {
            want = want.substr(want.find(' ') == std::string::npos ? 0 : want.find(' ') + 1);
            if (!want.empty() && want.back() == '.')
                want.pop_back();
            answered = resolver->mx(name, have, nx);
        }
        else if (type == "A" || type == "AAAA")
            answered = resolver->addrs(name, have, nx);
        else
        {
            out += "unchecked  " + name + " " + std::string(type) + "\n";
            continue;
        }
        ++asked;
        const bool found = std::any_of(have.begin(), have.end(), [&](const std::string& h) {
            return type == "MX" ? socketley::ascii::iequals(h, want) : h == want;
        });
        if (found)
        {
            ++ok;
            out += "ok         " + name + " " + std::string(type) + "\n";
        }
        else if (!answered && !nx)
            out += "unasked    " + name + " " + std::string(type) + ": no resolver answered\n";
        else if (have.empty())
            out += "missing    " + name + " " + std::string(type) + ": want " + want + "\n";
        else
            out += "differs    " + name + " " + std::string(type) + ": is " + have.front() + ", want " + want + "\n";
    }
    return out + std::to_string(ok) + " of " + std::to_string(asked) + " records as they should be\n";
}

std::string mail_run::trace_text(const std::string& address) const
{
    std::string out;
    size_t shown = 0;
    // The newest last, at most 200 of them.
    for (auto it = m_traced.rbegin(); it != m_traced.rend() && shown < 200; ++it)
    {
        if (!address.empty() && !contains_ci(it->from, address) && !contains_ci(it->rcpt, address))
            continue;
        char when[32];
        const std::time_t t = static_cast<std::time_t>(it->ms / 1000);
        std::tm tm{};
        ::localtime_r(&t, &tm);
        std::strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", &tm);
        out.insert(0, std::string(when) + "  " + (it->id.empty() ? std::string("-") : it->id) + "  " +
                          (it->from.empty() ? "<>" : it->from) + " -> " + it->rcpt + "  " + it->what +
                          (it->why.empty() ? "" : ": " + it->why) + "\n");
        ++shown;
    }
    return out;
}

bool mail_run::learn(const std::string& user, const std::string& key, uint64_t size, bool spam)
{
    if (m_learn_queue.size() >= 100000)
        return false;
    m_learn_queue.push_back({user, key, size, spam});
    pump_learning();
    return true;
}

void mail_run::pump_learning()
{
    while (m_imap && m_learning < 8 && !m_learn_queue.empty())
    {
        learning l = std::move(m_learn_queue.front());
        m_learn_queue.pop_front();
        ++m_learning;
        m_imap->body(l.key, l.size, [this, alive = m_alive, spam = l.spam](std::shared_ptr<const std::string> bytes) {
            if (!*alive)
                return;
            if (!bytes)
            {
                --m_learning;
                pump_learning();
                return;
            }
            auto line = std::make_shared<std::string>();
            m_pool.submit(cpu_lane(),
                          [bytes, line, spam] { *line = bayes::line(message_identity(*bytes), spam, spam_tokens(*bytes)); },
                          [this, alive, line] {
                              if (!*alive)
                                  return;
                              --m_learning;
                              // One write a line, so the lines of shards writing at once are each whole.
                              const std::string path = mail_bayes_path(m_owner.get_name()) + ".journal";
                              const int fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
                              if (fd >= 0 && socketley::write_all(fd, line->data(), line->size()))
                                  ++m_bayes_learned;
                              if (fd >= 0)
                                  ::close(fd);
                              pump_learning();
                          });
        }, false);
    }
}

void mail_run::bayes_read()
{
    const std::string path = mail_bayes_path(m_owner.get_name()) + ".journal";
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
    {
        m_bayes_off = 0;
        return;
    }
    const auto size = static_cast<uint64_t>(st.st_size);
    if (size < m_bayes_off)
        m_bayes_off = 0;
    if (size == m_bayes_off)
        return;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    std::string text(std::min<uint64_t>(size - m_bayes_off, 16u << 20), '\0');
    const ssize_t n = ::pread(fd, text.data(), text.size(), static_cast<off_t>(m_bayes_off));
    ::close(fd);
    if (n > 0)
    {
        text.resize(static_cast<size_t>(n));
        m_bayes_off += m_bayes->apply(text);
    }
}

void mail_run::bayes_fold()
{
    // The journal moved aside, so a shard's next line starts a new one; what it held past what was read, taken.
    const std::string path = mail_bayes_path(m_owner.get_name());
    if (::rename((path + ".journal").c_str(), (path + ".folding").c_str()) != 0)
        return;
    std::string rest;
    if (socketley::read_file(path + ".folding", rest, {.missing_ok = true}, nullptr) && rest.size() > m_bayes_off)
        m_bayes->apply(std::string_view(rest).substr(m_bayes_off));
    m_bayes_off = 0;
    m_bayes_folded_ms = wall::now_ms_coarse();
    // Written off the loop from a copy, the folding file kept until the table it went into is on the disk.
    auto copy = std::make_shared<bayes>(*m_bayes);
    m_pool.submit(0, [copy, path, name = std::string(m_owner.get_name())] {
        std::string why;
        if (copy->save(path, why))
            ::unlink((path + ".folding").c_str());
        else
            LOG_ERROR(("mail " + name + ": " + why).c_str());
    }, [] {});
}

std::string mail_run::learn_command(const std::string& arg, std::function<void(std::string_view)> answer)
{
    if (!m_imap)
        return "error: the spam filter learns from mailboxes, which need --idp and --storage";
    std::string all;
    if (!socketley::base64::decode(arg, all))
        return "error: the command did not arrive whole";
    const size_t a = all.find('\n'), b = a == std::string::npos ? a : all.find('\n', a + 1);
    if (b == std::string::npos)
        return "usage: socketley mail [<mail>] learn <user>/<folder> --as spam|ham";
    const std::string user = all.substr(0, a), cls = all.substr(a + 1, b - a - 1), folder = all.substr(b + 1);
    if (cls != "spam" && cls != "ham")
        return "error: learn takes spam or ham, not " + cls;
    m_imap->open(user, folder, [this, alive = m_alive, answer, user, folder, spam = cls == "spam"](std::shared_ptr<imap_folder> f) {
        if (!*alive)
            return;
        if (!f)
        {
            answer("error: " + user + " has no folder " + folder);
            return;
        }
        size_t queued = 0;
        for (const auto& m : f->msgs)
            queued += learn(user, m.key, m.size, spam);
        answer("learning " + std::to_string(queued) + " message" + (queued == 1 ? "" : "s") + " of " +
               user + "'s " + folder + " as " + (spam ? "spam" : "not spam"));
    });
    return {};
}

std::string mail_run::transfer_command(bool out, const std::string& arg)
{
    if (!m_imap)
        return "error: there are no mailboxes, which need --idp and --storage";
    std::string all;
    if (!socketley::base64::decode(arg, all))
        return "error: the command did not arrive whole";
    const size_t nl = all.find('\n');
    const std::string user = all.substr(0, nl), path = nl == std::string::npos ? std::string() : all.substr(nl + 1);
    if (!sieve_store::name_ok(user) || user.empty())
        return "error: " + user + " is no user";
    if (path.empty() || path.front() != '/')
        return "error: the path is a full one";
    // A job the CLI stopped asking after is let go once ten more began.
    std::erase_if(m_transfers, [&](const auto& j) { return j.second->done && j.first + 10 < m_transfer_seq; });
    auto status = std::make_shared<transfer_status>();
    const uint64_t id = ++m_transfer_seq;
    m_transfers[id] = status;
    if (out)
        start_export(*m_imap, m_pool, m_alive, user, path, status);
    else
        start_import(*m_imap, m_pool, m_alive, user, path, status);
    return "job " + std::to_string(id);
}

std::string mail_run::transfer_job(const std::string& arg)
{
    const auto it = m_transfers.find(std::strtoull(arg.c_str(), nullptr, 10));
    if (it == m_transfers.end())
        return "error: no job " + arg + " is known, which a restart of the runtime forgets";
    const transfer_status& s = *it->second;
    if (!s.done)
        return "running " + std::to_string(s.count) + (s.total ? " of " + std::to_string(s.total) : std::string());
    std::string text = s.text;
    m_transfers.erase(it);
    return text;
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
    if (m_owner.get_shard_index() == 0)
        put(out, "mail_self_listed", m_self_listed.empty() ? 0 : 1);
    put(out, "mail_complaints", m_complaints);
    put(out, "mail_content_refused", m_content_refused);
    if (!m_self_listed.empty())
        put(out, "mail_self_listed_by", std::string_view(m_self_listed));
    if (!m_name_mismatch.empty())
        put(out, "mail_name_mismatch", std::string_view(m_name_mismatch));
    put(out, "mail_refused_recipients", m_refused_rcpt);
    put(out, "mail_refused_relay", m_refused_relay);
    put(out, "mail_too_big", m_too_big);
    put(out, "mail_spool_failures", m_spool_failed + m_spool.write_failures());
    put(out, "mail_spool_commits", m_spool.commits());
    put(out, "mail_spool_committed", m_spool.committed());
    put(out, "mail_spool_segments", m_spool.segments());
    put(out, "mail_spool_moved", m_spool.moved());
    put(out, "mail_bounces_taken", m_bounces_taken);
    put(out, "mail_suppressed", m_suppressed.set.size());
    put(out, "mail_unsubscribed", m_unsubscribed.set.size());
    put(out, "mail_unsubscribes", m_unsubscribes);
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
    put(out, "mail_jmap_pushes", m_pushes_sent);
    put(out, "mail_jmap_push_failures", m_pushes_failed);
    put(out, "auth_ok", m_auth_ok);
    put(out, "auth_failed", m_auth_failed);
    put(out, "auth_locked_out", m_auth_locked);
    put(out, "mail_rate_limited", m_rate_limited);
    put(out, "starttls", m_starttls);
    put(out, "tls_failures", m_tls_failures);
    if (m_bayes)
    {
        put(out, "mail_bayes_spam", m_bayes->spam_learned());
        put(out, "mail_bayes_ham", m_bayes->ham_learned());
        put(out, "mail_bayes_words", m_bayes->words());
        put(out, "mail_bayes_junked", m_bayes_junked);
    }
    put(out, "mail_bayes_learned", m_bayes_learned);
    if (m_delivery)
        m_delivery->stats(out);
    return out;
}

}   // namespace socketley::mail
