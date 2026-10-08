#include "dashboard.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <set>

#include "runtime_schema.h"
#include "ipc_client.h"
#include "../runtime/proxy/proxy_auth.h"
#include "../runtime/storage/json_doc.h"
#include "../shared/blocking_write.h"
#include "../shared/logging.h"
#include "../shared/log_ring.h"
#include "../shared/cert_keeper.h"
#include "../shared/dns_feed.h"
#include "../shared/runtime_instance.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_definitions.h"
#include "../runtime/dns/dns_instance.h"
#include "../runtime/dns/dns_zone.h"
#include "../runtime/dns/dns_wire.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/stat.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <shared_mutex>
#include <sstream>

namespace socketley::storage
{
std::string_view storage_ui_style();
std::string storage_ui_kit();
}

namespace dashboard
{

namespace
{

#include "dashboard_page.inc"

constexpr int64_t session_seconds = 12 * 3600;

std::string json_quote(std::string_view v)
{
    std::string o = "\"";
    for (unsigned char c : v)
    {
        if (c == '"' || c == '\\')
            o += '\\', o += static_cast<char>(c);
        else if (c < 0x20)
        {
            char b[8];
            std::snprintf(b, sizeof b, "\\u%04x", c);
            o += b;
        }
        else
            o += static_cast<char>(c);
    }
    return o + "\"";
}

std::string lower(std::string_view s)
{
    std::string o(s);
    std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return std::tolower(c); });
    return o;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

bool local(std::string_view ip)
{
    return ip.empty() || ip.starts_with("127.") || ip == "::1" || ip.starts_with("::ffff:127.");
}

// The page with the storage interface's look, which it shares rather than copies.
const std::string& page()
{
    static const std::string p = [] {
        std::string s(dashboard_page);
        const std::string mark = "/*STYLE*/";
        if (const size_t at = s.find(mark); at != std::string::npos)
            s.replace(at, mark.size(), socketley::storage::storage_ui_style());
        const std::string kit = "/*KIT*/";
        if (const size_t at = s.find(kit); at != std::string::npos)
            s.replace(at, kit.size(), socketley::storage::storage_ui_kit());
        return s;
    }();
    return p;
}

// The commands the page may send; anything else is the CLI's alone.
const std::set<std::string_view> verbs = {"create", "edit", "import", "start", "stop", "remove", "reload",
                                          "reload-lua", "show", "stats", "ls", "ps"};

}   // namespace

std::string_view request::header(std::string_view name) const
{
    const auto it = headers.find(std::string(name));
    return it == headers.end() ? std::string_view{} : std::string_view(it->second);
}

std::string request::client() const
{
    if (!local(peer))
        return peer;
    std::string_view xff = header("x-forwarded-for");
    if (const size_t comma = xff.rfind(','); comma != std::string_view::npos)
        xff.remove_prefix(comma + 1);
    xff = trim(xff);
    return xff.empty() ? (peer.empty() ? std::string("local") : peer) : std::string(xff);
}

bool read_request(int fd, request& r, size_t max_body)
{
    std::string in;
    size_t end;
    char buf[8192];
    while ((end = in.find("\r\n\r\n")) == std::string::npos)
    {
        if (in.size() > 16384)
            return false;
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n <= 0)
            return false;
        in.append(buf, static_cast<size_t>(n));
    }
    const std::string_view head(in.data(), end);
    const size_t line_end = head.find("\r\n");
    const std::string_view line = head.substr(0, line_end);
    const size_t sp1 = line.find(' '), sp2 = line.rfind(' ');
    if (sp1 == std::string_view::npos || sp2 == sp1)
        return false;
    r.method.assign(line.substr(0, sp1));
    std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    if (const size_t q = target.find('?'); q != std::string_view::npos)
    {
        r.query.assign(target.substr(q + 1));
        target = target.substr(0, q);
    }
    r.path.assign(target);
    for (size_t p = line_end == std::string_view::npos ? head.size() : line_end + 2; p < head.size();)
    {
        size_t nl = head.find("\r\n", p);
        if (nl == std::string_view::npos)
            nl = head.size();
        const std::string_view h = head.substr(p, nl - p);
        p = nl + 2;
        const size_t colon = h.find(':');
        if (colon == std::string_view::npos)
            continue;
        std::string name = lower(h.substr(0, colon));
        // A field sent twice is refused rather than one of them taken.
        if (r.headers.count(name))
            return false;
        r.headers.emplace(std::move(name), std::string(trim(h.substr(colon + 1))));
    }
    if (!r.header("transfer-encoding").empty())
        return false;
    const std::string_view cl = r.header("content-length");
    const size_t want = cl.empty() ? 0 : std::strtoull(std::string(cl).c_str(), nullptr, 10);
    if (want > max_body)
        return false;
    r.body = in.substr(end + 4);
    while (r.body.size() < want)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n <= 0)
            return false;
        r.body.append(buf, static_cast<size_t>(n));
    }
    r.body.resize(want);
    return true;
}

void send(int fd, int status, std::string_view type, std::string_view body, std::string_view extra_headers)
{
    const char* reason = status == 200 ? "OK" : status == 204 ? "No Content" : status == 400 ? "Bad Request"
                       : status == 401 ? "Unauthorized" : status == 403 ? "Forbidden" : status == 404 ? "Not Found"
                       : status == 405 ? "Method Not Allowed" : status == 413 ? "Payload Too Large"
                       : status == 429 ? "Too Many Requests" : status == 502 ? "Bad Gateway" : "Error";
    std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    if (!type.empty())
        out += "Content-Type: " + std::string(type) + "\r\n";
    out += "X-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
           "Cache-Control: no-store\r\nConnection: close\r\n";
    out += extra_headers;
    out += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    out += body;
    socketley::write_all(fd, out.data(), out.size());
}

server::server(std::string credentials, runtime_manager& manager)
    : m_credentials(std::move(credentials)), m_manager(manager)
{
    unsigned char k[32];
    if (RAND_bytes(k, sizeof k) == 1)
        m_key.assign(reinterpret_cast<char*>(k), sizeof k);
    if (configured())
    {
        m_auth = std::make_unique<proxy_auth>();
        m_auth->configure("basic:" + m_credentials, "dashboard");
    }
}

server::~server() = default;

std::string server::seal(std::string_view user, int64_t expires) const
{
    const std::string msg = std::string(user) + "." + std::to_string(expires);
    unsigned char mac[32];
    unsigned int n = 0;
    HMAC(EVP_sha256(), m_key.data(), static_cast<int>(m_key.size()), reinterpret_cast<const unsigned char*>(msg.data()),
         msg.size(), mac, &n);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out = msg + ".";
    for (unsigned i = 0; i < n; ++i)
        out += {hex[mac[i] >> 4], hex[mac[i] & 15]};
    return out;
}

std::string server::session_of(const request& r) const
{
    if (!configured() || m_key.size() != 32)
        return {};
    std::string_view cookies = r.header("cookie");
    std::string_view v;
    for (size_t p = 0; p < cookies.size();)
    {
        size_t semi = cookies.find(';', p);
        if (semi == std::string_view::npos)
            semi = cookies.size();
        const std::string_view c = trim(cookies.substr(p, semi - p));
        if (c.starts_with("skl_dash="))
            v = c.substr(9);
        p = semi + 1;
    }
    const size_t d2 = v.rfind('.'), d1 = d2 == std::string_view::npos ? d2 : v.rfind('.', d2 - 1);
    if (d1 == std::string_view::npos || d1 == 0)
        return {};
    const std::string user(v.substr(0, d1));
    const int64_t expires = std::strtoll(std::string(v.substr(d1 + 1, d2 - d1 - 1)).c_str(), nullptr, 10);
    if (expires < static_cast<int64_t>(std::time(nullptr)))
        return {};
    const std::string want = seal(user, expires);
    if (want.size() != v.size() || CRYPTO_memcmp(want.data(), v.data(), v.size()) != 0)
        return {};
    return user;
}

bool server::handle(int fd, const request& r)
{
    if (r.path == "/" || r.path == "/dashboard")
    {
        send(fd, 200, "text/html; charset=utf-8", page(),
             "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' "
             "'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'\r\n");
        return true;
    }
    if (r.path == "/api/session")
    {
        session(fd, r);
        return true;
    }
    if (r.path == "/api/schema")
    {
        if (!may_read(r))
            send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        else
            send(fd, 200, "application/json", runtime_schema::json());
        return true;
    }
    if (r.path == "/api/run")
    {
        run(fd, r);
        return true;
    }
    if (r.path == "/api/logs")
    {
        logs(fd, r);
        return true;
    }
    if (r.path == "/api/edge")
    {
        edge(fd, r);
        return true;
    }
    if (r.path == "/api/zone")
    {
        zone(fd, r);
        return true;
    }
    return false;
}

void server::session(int fd, const request& r)
{
    if (r.method == "GET")
    {
        const std::string who = session_of(r);
        send(fd, 200, "application/json",
             "{\"configured\":" + std::string(configured() ? "true" : "false") + ",\"user\":" +
                 (who.empty() ? std::string("null") : json_quote(who)) + "}");
        return;
    }
    const bool https = r.header("x-forwarded-proto") == "https";
    if (r.method == "DELETE")
    {
        send(fd, 204, {}, {}, std::string("Set-Cookie: skl_dash=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict") +
                                  (https ? "; Secure" : "") + "\r\n");
        return;
    }
    if (r.method != "POST")
    {
        send(fd, 405, "text/plain; charset=utf-8", "Signed in with POST, asked with GET, out with DELETE.\n");
        return;
    }
    if (!configured())
    {
        send(fd, 403, "text/plain; charset=utf-8",
             "Signing in needs daemon.dashboard_credentials in the daemon's configuration.\n");
        return;
    }
    int64_t retry = 0;
    const std::string_view authorization = r.header("authorization");
    const auto v = m_auth->check(authorization, r.client(), retry);
    if (v == proxy_auth::verdict::barred)
    {
        send(fd, 429, "text/plain; charset=utf-8", "Too many failed sign-ins from this address; try again later.\n",
             "Retry-After: " + std::to_string(retry) + "\r\n");
        return;
    }
    if (v != proxy_auth::verdict::pass)
    {
        send(fd, 401, "text/plain; charset=utf-8", "That access key and secret are no admin's.\n");
        return;
    }
    // The access key, which the check just took from the same field.
    std::string pair;
    {
        const std::string_view b64 = trim(authorization.substr(authorization.find(' ') + 1));
        std::string out(b64.size(), '\0');
        const int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                      reinterpret_cast<const unsigned char*>(b64.data()), static_cast<int>(b64.size()));
        if (n > 0)
            pair.assign(out.data(), static_cast<size_t>(n));
    }
    const std::string user = pair.substr(0, pair.find(':'));
    const int64_t expires = static_cast<int64_t>(std::time(nullptr)) + session_seconds;
    LOG_INFO(("dashboard: " + user + " signed in from " + r.client()).c_str());
    send(fd, 200, "application/json", "{\"user\":" + json_quote(user) + "}",
         "Set-Cookie: skl_dash=" + seal(user, expires) + "; Path=/; Max-Age=" + std::to_string(session_seconds) +
             "; HttpOnly; SameSite=Strict" + (https ? "; Secure" : "") + "\r\n");
}

std::string query_field(std::string_view q, std::string_view name)
{
    for (size_t p = 0; p < q.size();)
    {
        size_t amp = q.find('&', p);
        if (amp == std::string_view::npos)
            amp = q.size();
        const std::string_view kv = q.substr(p, amp - p);
        p = amp + 1;
        const size_t eq = kv.find('=');
        if (kv.substr(0, eq) != name)
            continue;
        std::string out;
        const std::string_view v = eq == std::string_view::npos ? std::string_view{} : kv.substr(eq + 1);
        for (size_t i = 0; i < v.size(); ++i)
        {
            if (v[i] == '%' && i + 2 < v.size())
            {
                out += static_cast<char>(std::strtol(std::string(v.substr(i + 1, 2)).c_str(), nullptr, 16));
                i += 2;
            }
            else
                out += v[i] == '+' ? ' ' : v[i];
        }
        return out;
    }
    return {};
}

void server::logs(int fd, const request& r)
{
    // The log says what runtimes do and with what, so only a session reads it when there are credentials.
    if (!may_read(r))
    {
        send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        return;
    }
    const uint64_t since = std::strtoull(query_field(r.query, "since").c_str(), nullptr, 10);
    size_t max = std::strtoul(query_field(r.query, "max").c_str(), nullptr, 10);
    if (max == 0 || max > 2000)
        max = 500;
    uint64_t next = 0;
    const auto lines = log_ring::since(since, max, query_field(r.query, "runtime"), query_field(r.query, "level"), next);
    std::string o = "{\"next\":" + std::to_string(next) + ",\"lines\":[";
    for (size_t i = 0; i < lines.size(); ++i)
    {
        const auto& e = lines[i];
        o += (i ? ",{" : "{") + std::string("\"seq\":") + std::to_string(e.seq) + ",\"at\":" + std::to_string(e.at_ms) +
             ",\"rt\":" + json_quote(e.runtime) + ",\"lv\":\"" + e.level + "\",\"text\":" + json_quote(e.text) + "}";
    }
    o += "]}";
    send(fd, 200, "application/json", o);
}

namespace
{

std::string read_text(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return f ? ss.str() : std::string{};
}

std::string last_line_of(const std::string& path)
{
    std::ifstream f(path);
    std::string line, last;
    while (std::getline(f, line))
        if (!line.empty())
            last = line;
    return last;
}

// What a certificate file says of itself, as JSON members after `{`; empty when it is no certificate.
std::string cert_json(const std::string& path)
{
    BIO* b = BIO_new_file(path.c_str(), "r");
    X509* x = b ? PEM_read_bio_X509(b, nullptr, nullptr, nullptr) : nullptr;
    if (b)
        BIO_free(b);
    ERR_clear_error();
    if (!x)
        return {};
    std::string names;
    if (auto* gens = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr)))
    {
        for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i)
            if (const GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i); g->type == GEN_DNS)
                names += (names.empty() ? "" : ",") +
                         json_quote(std::string_view(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)),
                                                     static_cast<size_t>(ASN1_STRING_length(g->d.dNSName))));
        GENERAL_NAMES_free(gens);
    }
    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, nullptr, X509_get0_notAfter(x));
    char issuer[256] = {};
    X509_NAME_get_text_by_NID(X509_get_issuer_name(x), NID_organizationName, issuer, sizeof issuer);
    if (!issuer[0])
        X509_NAME_get_text_by_NID(X509_get_issuer_name(x), NID_commonName, issuer, sizeof issuer);
    const bool self = X509_check_issued(x, x) == X509_V_OK;
    X509_free(x);
    const int64_t left = static_cast<int64_t>(days) * 86400 + secs;
    return "\"names\":[" + names + "],\"expires_in\":" + std::to_string(left) + ",\"issuer\":" + json_quote(issuer) +
           ",\"self_signed\":" + (self ? "true" : "false");
}

}   // namespace

void server::edge(int fd, const request& r)
{
    if (!may_read(r))
    {
        send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        return;
    }
    struct rt_info
    {
        std::string name, type, cert, address, proxy;
        bool tls{false}, entrance{false}, acme{false};
        std::vector<std::string> zones;
    };
    std::vector<rt_info> all;
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [name, rt] : m_manager.list())
        {
            rt_info i;
            i.name = name;
            i.type = type_to_string(rt->get_type());
            i.tls = rt->get_tls();
            i.cert.assign(rt->get_cert_path());
            if (!rt->get_acme_domains().empty())
            {
                i.acme = true;
                if (i.cert.empty())
                    i.cert = cert_keeper::acme_cert_path(rt->get_acme_domains().front());
            }
            const std::string bind(rt->get_bind_address());
            i.address = !rt->get_listen_path().empty() ? "unix:" + std::string(rt->get_listen_path())
                        : (bind.empty() || bind == "0.0.0.0" ? std::string("127.0.0.1") : bind) + ":" +
                              std::to_string(rt->effective_port());
            i.entrance = i.cert == cert_keeper::entrance_cert_path(name);
            if (rt->get_type() == runtime_dns)
            {
                const auto* d = static_cast<const dns_instance*>(rt.get());
                i.zones = d->zone_paths();
                i.proxy.assign(d->get_proxy());
            }
            all.push_back(std::move(i));
        }
    }
    std::map<std::string, std::string> by_address;
    for (const auto& i : all)
        by_address[i.address] = i.name;

    std::string o = "{\"entrances\":[";
    bool first = true;
    for (const auto& i : all)
    {
        const std::string table = read_text(dns_feed::routes_path(i.name));
        if (table.empty() && !i.entrance)
            continue;
        o += std::string(first ? "" : ",") + "{\"name\":" + json_quote(i.name) + ",\"zones\":[";
        first = false;
        std::string zones, routes;
        std::istringstream lines(table);
        for (std::string line; std::getline(lines, line);)
        {
            if (line.starts_with("zone "))
                zones += (zones.empty() ? "" : ",") + json_quote(line.substr(5));
            else if (line.starts_with("route "))
            {
                std::istringstream w(line.substr(6));
                std::string name, addr, to;
                w >> name;
                while (w >> addr)
                    to += (to.empty() ? "" : ",") + std::string("{\"address\":") + json_quote(addr) + ",\"runtime\":" +
                          json_quote(by_address.count(addr) ? by_address[addr] : std::string{}) + "}";
                routes += (routes.empty() ? "" : ",") + std::string("{\"name\":") + json_quote(name) + ",\"to\":[" + to + "]}";
            }
        }
        o += zones + "],\"routes\":[" + routes + "]}";
    }
    o += "],\"certs\":[";
    first = true;
    for (const auto& i : all)
    {
        if (i.cert.empty())
            continue;
        const std::string c = cert_json(i.cert);
        struct stat st{};
        const bool partial = ::stat((i.cert + ".partial").c_str(), &st) == 0;
        const std::string log = i.acme || i.entrance ? last_line_of(i.cert + ".log") : std::string{};
        o += std::string(first ? "" : ",") + "{\"runtime\":" + json_quote(i.name) + ",\"path\":" + json_quote(i.cert) +
             ",\"auto\":" + (i.acme || i.entrance ? "true" : "false") + ",\"partial\":" + (partial ? "true" : "false") +
             ",\"acme_log\":" + json_quote(log) + (c.empty() ? ",\"missing\":true" : "," + c) + "}";
        first = false;
    }
    o += "],\"zones\":[";
    first = true;
    for (const auto& i : all)
        for (const std::string& p : i.zones)
        {
            socketley::dns::zone z;
            std::string why;
            const bool ok = socketley::dns::load_zone(p, {}, z, why);
            o += std::string(first ? "" : ",") + "{\"runtime\":" + json_quote(i.name) + ",\"path\":" + json_quote(p) +
                 ",\"origin\":" + json_quote(ok ? socketley::dns::to_text(z.origin) : std::string{}) +
                 ",\"serial\":" + std::to_string(ok ? z.serial : 0) + ",\"error\":" + json_quote(ok ? std::string{} : why) +
                 ",\"proxy\":" + json_quote(i.proxy) + "}";
            first = false;
        }
    o += "]}";
    send(fd, 200, "application/json", o);
}

void server::zone(int fd, const request& r)
{
    if (r.method == "GET" ? !may_read(r) : session_of(r).empty())
    {
        send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        return;
    }
    std::string runtime, path, text;
    if (r.method == "GET")
    {
        runtime = query_field(r.query, "runtime");
        path = query_field(r.query, "path");
    }
    else if (r.method == "PUT")
    {
        if (r.header("x-socketley-dashboard") != "1")
        {
            send(fd, 403, "text/plain; charset=utf-8", "A change comes from the dashboard's own page.\n");
            return;
        }
        socketley::storage::jvalue doc;
        if (socketley::storage::json_reader(r.body).document(doc))
            for (const auto& [k, v] : doc.members)
            {
                if (v.k != socketley::storage::jvalue::kind::string)
                    continue;
                if (k == "runtime")
                    runtime = v.s;
                else if (k == "path")
                    path = v.s;
                else if (k == "text")
                    text = v.s;
            }
    }
    else
    {
        send(fd, 405, "text/plain; charset=utf-8", "A zone is read with GET and written with PUT.\n");
        return;
    }
    // Only a file a dns runtime serves, so the page writes nothing else on this machine.
    bool served = false;
    {
        std::shared_lock lock(m_manager.mutex);
        if (const auto* rt = m_manager.get(runtime); rt && rt->get_type() == runtime_dns)
            for (const std::string& p : static_cast<const dns_instance*>(rt)->zone_paths())
                served = served || p == path;
    }
    if (!served)
    {
        send(fd, 404, "text/plain; charset=utf-8", "No dns runtime " + runtime + " serves " + path + ".\n");
        return;
    }
    if (r.method == "GET")
    {
        send(fd, 200, "text/plain; charset=utf-8", read_text(path));
        return;
    }
    socketley::dns::zone z;
    std::string why;
    if (text.size() > (4u << 20) || !socketley::dns::parse_zone(text, {}, z, why))
    {
        send(fd, 400, "text/plain; charset=utf-8", why.empty() ? std::string("The zone is too large.\n") : why + "\n");
        return;
    }
    const std::string tmp = path + ".dashboard." + std::to_string(::getpid());
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f << text;
        f.close();
        std::error_code ec;
        if (!f || (std::filesystem::rename(tmp, path, ec), ec))
        {
            ::unlink(tmp.c_str());
            send(fd, 500, "text/plain; charset=utf-8", "The zone could not be written.\n");
            return;
        }
    }
    LOG_INFO(("dashboard: " + session_of(r) + " wrote the zone " + path + ", serial " + std::to_string(z.serial)).c_str());
    send(fd, 204, {}, {});
}

void server::run(int fd, const request& r)
{
    if (r.method != "POST")
    {
        send(fd, 405, "text/plain; charset=utf-8", "A command is sent with POST.\n");
        return;
    }
    if (!configured())
    {
        send(fd, 403, "text/plain; charset=utf-8",
             "Changing anything needs daemon.dashboard_credentials in the daemon's configuration.\n");
        return;
    }
    const std::string who = session_of(r);
    if (who.empty())
    {
        send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        return;
    }
    // Only the page sends it, since no other site's request can carry it.
    if (r.header("x-socketley-dashboard") != "1")
    {
        send(fd, 403, "text/plain; charset=utf-8", "A command comes from the dashboard's own page.\n");
        return;
    }
    socketley::storage::jvalue doc;
    const socketley::storage::jvalue* args = nullptr;
    if (socketley::storage::json_reader(r.body).document(doc))
        for (const auto& [k, v] : doc.members)
            if (k == "args" && v.k == socketley::storage::jvalue::kind::array)
                args = &v;
    if (!args || args->items.empty())
    {
        send(fd, 400, "text/plain; charset=utf-8", "The body is {\"args\": [the command's words]}.\n");
        return;
    }
    std::string command;
    for (size_t i = 0; i < args->items.size(); ++i)
    {
        const auto& a = args->items[i];
        if (a.k != socketley::storage::jvalue::kind::string || a.s.empty() ||
            a.s.find_first_of("\r\n\0", 0, 3) != std::string::npos)
        {
            send(fd, 400, "text/plain; charset=utf-8", "Each word is a string of one line.\n");
            return;
        }
        if (i == 0 && !verbs.count(a.s))
        {
            send(fd, 403, "text/plain; charset=utf-8", "The dashboard does not send " + a.s + ".\n");
            return;
        }
        // Words are split at spaces, but for an import's document, which is the rest of the line.
        const bool document = args->items[0].s == "import" && i == 2;
        if (!document && a.s.find_first_of(" \t") != std::string::npos)
        {
            send(fd, 400, "text/plain; charset=utf-8", "\"" + a.s + "\" holds a space, which no word may.\n");
            return;
        }
        command += (i ? " " : "") + a.s;
    }
    std::string out;
    const int rc = ipc_send(command, out);
    if (args->items[0].s != "show" && args->items[0].s != "stats" && args->items[0].s != "ls" &&
        args->items[0].s != "ps")
        LOG_INFO(("dashboard: " + who + " ran " + command.substr(0, 200) + " (" + std::to_string(rc) + ")").c_str());
    if (rc == ipc_unreachable || rc == ipc_no_answer)
    {
        send(fd, 502, "text/plain; charset=utf-8",
             rc == ipc_no_answer ? "The daemon is still at it; look again in a moment.\n"
                                 : "The daemon's control socket did not answer.\n");
        return;
    }
    send(fd, 200, "application/json", "{\"code\":" + std::to_string(rc) + ",\"out\":" + json_quote(out) + "}");
}

}   // namespace dashboard
