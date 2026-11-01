#include "jmap_session.h"
#include "dav.h"
#include "mail_setup.h"

#include <algorithm>
#include <charconv>

#include "mail_mime.h"
#include "mail_web.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

constexpr std::string_view core = "urn:ietf:params:jmap:core";
constexpr std::string_view mail_cap = "urn:ietf:params:jmap:mail";
constexpr std::string_view submission_cap = "urn:ietf:params:jmap:submission";
constexpr std::string_view vacation_cap = "urn:ietf:params:jmap:vacationresponse";
constexpr std::string_view quota_cap = "urn:ietf:params:jmap:quota";

std::string reason_of(int code)
{
    switch (code)
    {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 207: return "Multi-Status";
        case 301: return "Moved Permanently";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Content Too Large";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        default: return "Error";
    }
}

std::string percent_decoded(std::string_view s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '%' && i + 2 < s.size())
        {
            unsigned v = 0;
            const auto r = std::from_chars(s.data() + i + 1, s.data() + i + 3, v, 16);
            if (r.ec == std::errc() && r.ptr == s.data() + i + 3)
            {
                out += static_cast<char>(v);
                i += 2;
                continue;
            }
        }
        out += s[i] == '+' ? ' ' : s[i];
    }
    return out;
}

std::string query_param(std::string_view query, std::string_view name)
{
    for (std::string_view rest = query; !rest.empty();)
    {
        const size_t amp = rest.find('&');
        const std::string_view kv = rest.substr(0, amp);
        rest = amp == std::string_view::npos ? std::string_view{} : rest.substr(amp + 1);
        const size_t eq = kv.find('=');
        if (kv.substr(0, eq) == name)
            return eq == std::string_view::npos ? std::string() : percent_decoded(kv.substr(eq + 1));
    }
    return {};
}

uint64_t fnv(std::string_view s, uint64_t h = 1469598103934665603ull)
{
    for (const unsigned char c : s)
        h = (h ^ c) * 1099511628211ull;
    return h;
}

std::string hex64(uint64_t v)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i, v >>= 4)
        out[static_cast<size_t>(i)] = hex[v & 15];
    return out;
}

// A JSON pointer (RFC 6901) into `v`, with RFC 8620 3.7's * mapping over an array and flattening what it gives.
bool pointer(const json::jvalue& v, std::string_view path, json::jvalue& out)
{
    if (path.empty())
    {
        out = v;
        return true;
    }
    if (path.front() != '/')
        return false;
    path.remove_prefix(1);
    const size_t slash = path.find('/');
    std::string token(path.substr(0, slash));
    const std::string_view rest = slash == std::string_view::npos ? std::string_view{} : path.substr(slash);
    for (size_t at; (at = token.find("~1")) != std::string::npos;)
        token.replace(at, 2, "/");
    for (size_t at; (at = token.find("~0")) != std::string::npos;)
        token.replace(at, 2, "~");
    if (v.k == json::jvalue::kind::array && token == "*")
    {
        out = json::jvalue{};
        out.k = json::jvalue::kind::array;
        for (const auto& item : v.items)
        {
            json::jvalue got;
            if (!pointer(item, rest, got))
                return false;
            if (got.k == json::jvalue::kind::array)
                for (auto& g : got.items)
                    out.items.push_back(std::move(g));
            else
                out.items.push_back(std::move(got));
        }
        return true;
    }
    if (v.k == json::jvalue::kind::array)
    {
        size_t i = 0;
        const auto r = std::from_chars(token.data(), token.data() + token.size(), i);
        if (r.ec != std::errc() || r.ptr != token.data() + token.size() || i >= v.items.size())
            return false;
        return pointer(v.items[i], rest, out);
    }
    const json::jvalue* m = json::member(v, token);
    return m && pointer(*m, rest, out);
}

// Whether a browser may have sent `rq` from another site with no preflight, signed with credentials it keeps for here.
bool unasked_from_elsewhere(const jmap_session::request& rq)
{
    const std::string site = rq.header("sec-fetch-site");
    const bool elsewhere = !site.empty() && site != "same-origin" && site != "none";
    if (elsewhere && !socketley::ascii::iequals(rq.header("sec-fetch-mode"), "cors"))
        return true;
    if (rq.path != "/jmap/api")
        return false;
    std::string type = rq.header("content-type");
    type.erase(std::min(type.find(';'), type.size()));
    while (!type.empty() && (type.back() == ' ' || type.back() == '\t'))
        type.pop_back();
    socketley::ascii::lower_in_place(type);
    if (elsewhere)
        return type != "application/json";
    // The bodies a form sends, which no JMAP client does.
    return type == "text/plain" || type == "application/x-www-form-urlencoded" || type == "multipart/form-data";
}

}   // namespace

std::string jmap_session::request::header(std::string_view name) const
{
    for (const auto& [k, v] : headers)
        if (socketley::ascii::iequals(k, name))
            return v;
    return {};
}

jmap_session::jmap_session(const jmap_config& cfg, hooks& h, imap_store& store) : m_cfg(cfg), m_hooks(h), m_store(store)
{
}

jmap_session::~jmap_session()
{
    *m_alive = false;
}

std::string jmap_session::account_of(const std::string& user)
{
    return "a" + socketley::base64url::encode(user);
}

std::string jmap_session::email_state(imap_store& store, const std::string& user)
{
    uint64_t h = fnv("email");
    for (const auto& f : store.known(user))
    {
        h = fnv(f->id(), h);
        h = fnv(std::to_string(f->uidnext) + "." + std::to_string(f->highestmodseq) + "." + std::to_string(f->msgs.size()),
                h);
    }
    return "s" + hex64(h);
}

std::string jmap_session::mailbox_state(imap_store& store, const std::string& user)
{
    uint64_t h = fnv("mailbox");
    for (const auto& f : store.known(user))
    {
        h = fnv(f->id(), h);
        h = fnv(f->name + (f->subscribed ? "\x01" : "\x02"), h);
    }
    return "s" + hex64(h);
}

void jmap_session::input(std::string_view bytes)
{
    if (m_closed)
        return;
    // An EventSource takes nothing more from its client.
    if (m_stream)
        return;
    m_in.append(bytes);
    run();
}

void jmap_session::run()
{
    while (!m_busy && !m_closed && !m_stream)
    {
        const size_t end = m_in.find("\r\n\r\n");
        if (end == std::string::npos || end > max_head)
        {
            if (end != std::string::npos || m_in.size() > max_head)
            {
                fail(431, "urn:ietf:params:jmap:error:limit", "the request's head is too long");
                m_closed = true;
                m_hooks.close();
            }
            return;
        }
        request rq;
        std::string_view head(m_in.data(), end);
        const size_t eol = head.find("\r\n");
        const std::string_view line = head.substr(0, eol);
        head = eol == std::string_view::npos ? std::string_view{} : head.substr(eol + 2);
        const size_t sp1 = line.find(' '), sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
        if (sp2 == std::string_view::npos)
        {
            fail(400, "urn:ietf:params:jmap:error:notRequest", "not an HTTP request");
            m_closed = true;
            m_hooks.close();
            return;
        }
        rq.method = std::string(line.substr(0, sp1));
        rq.target = std::string(line.substr(sp1 + 1, sp2 - sp1 - 1));
        const std::string_view version = line.substr(sp2 + 1);
        const size_t q = rq.target.find('?');
        rq.path = rq.target.substr(0, q);
        rq.query = q == std::string::npos ? std::string() : rq.target.substr(q + 1);
        while (!head.empty())
        {
            const size_t nl = head.find("\r\n");
            const std::string_view h = head.substr(0, nl);
            head = nl == std::string_view::npos ? std::string_view{} : head.substr(nl + 2);
            const size_t colon = h.find(':');
            if (colon == std::string_view::npos)
                continue;
            std::string_view v = h.substr(colon + 1);
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
                v.remove_prefix(1);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
                v.remove_suffix(1);
            rq.headers.emplace_back(std::string(h.substr(0, colon)), std::string(v));
        }
        const std::string connection = rq.header("connection");
        rq.keep_alive = version == "HTTP/1.1" ? !socketley::ascii::iequals(connection, "close")
                                              : socketley::ascii::iequals(connection, "keep-alive");
        if (!rq.header("transfer-encoding").empty())
        {
            fail(501, "urn:ietf:params:jmap:error:notRequest", "a body is sent with Content-Length here");
            m_closed = true;
            m_hooks.close();
            return;
        }
        uint64_t length = 0;
        if (const std::string cl = rq.header("content-length"); !cl.empty())
        {
            const auto r = std::from_chars(cl.data(), cl.data() + cl.size(), length);
            if (r.ec != std::errc() || r.ptr != cl.data() + cl.size())
            {
                fail(400, "urn:ietf:params:jmap:error:notRequest", "Content-Length is no number");
                m_closed = true;
                m_hooks.close();
                return;
            }
        }
        // An upload as large as a message may be, any other request as large as the API takes.
        const uint64_t cap = rq.path.starts_with("/jmap/upload/") ? m_cfg.max_size : max_request;
        if (length > cap)
        {
            fail(413, "urn:ietf:params:jmap:error:limit", "the request is larger than this server takes");
            m_closed = true;
            m_hooks.close();
            return;
        }
        if (m_in.size() < end + 4 + length)
            return;
        rq.body = m_in.substr(end + 4, static_cast<size_t>(length));
        m_in.erase(0, end + 4 + static_cast<size_t>(length));
        m_busy = true;
        handle(std::move(rq));
    }
}

std::string jmap_session::head_of(int code, std::string_view type, size_t length, std::string_view extra) const
{
    std::string out = "HTTP/1.1 " + std::to_string(code) + " " + reason_of(code) + "\r\n";
    if (!type.empty())
        out += "Content-Type: " + std::string(type) + "\r\n";
    out += "Content-Length: " + std::to_string(length) + "\r\n";
    // A web client of another origin may call it with the user's credentials, never with the webmail's cookie.
    if (!m_from_page)
        out += "Access-Control-Allow-Origin: *\r\n";
    out += "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
    out.append(extra);
    out += "\r\n";
    return out;
}

void jmap_session::respond(int code, std::string_view type, std::string_view body, std::string_view extra)
{
    std::string out = head_of(code, type, body.size(), extra);
    out.append(body);
    m_hooks.reply(out);
}

void jmap_session::fail(int code, std::string_view type, std::string_view detail)
{
    std::string body = "{\"type\":";
    json::quote_into(body, type);
    body += ",\"status\":" + std::to_string(code) + ",\"detail\":";
    json::quote_into(body, detail);
    body += "}";
    // The webmail page is sent to the idp to sign in, not shown the browser's own prompt for a password.
    std::string extra;
    if (code == 401 && !m_from_page)
        extra = "WWW-Authenticate: Basic realm=\"jmap\", charset=\"UTF-8\"\r\n";
    else if (code == 401 && !m_login.empty())
        extra = "X-Socketley-Idp-Login: " + m_login + "\r\n";
    respond(code, "application/problem+json", body, extra);
}

void jmap_session::finished()
{
    m_busy = false;
    m_ids.clear();
    // A request that asked to close ends the connection with its answer.
    if (!m_keep)
    {
        m_closed = true;
        m_hooks.close();
        return;
    }
    run();
}

std::string jmap_session::base_url(const request& rq) const
{
    std::string host = rq.header("host");
    if (host.empty() || host.find_first_of(" /\\\"<>") != std::string::npos)
        host = m_cfg.hostname;
    return std::string(m_cfg.tls_active || m_https ? "https://" : "http://") + host;
}

void jmap_session::handle(request rq)
{
    // A request is answered, and the next taken, once it is done.
    m_keep = rq.keep_alive;
    const auto after = [this] { finished(); };
    m_https = m_from_page = false;
    m_login.clear();
    if (m_cfg.web)
    {
        // Behind the entrance: the scheme it was reached over and the client it forwards are the ones that count.
        m_https = socketley::ascii::iequals(rq.header("x-forwarded-proto"), "https");
        // Only the entrance names the client, or a peer would pick the address its failures count against.
        const std::string forwarded_for = m_cfg.trust_forwarded ? rq.header("x-forwarded-for") : std::string();
        std::string_view xff = forwarded_for;
        if (const size_t comma = xff.rfind(','); comma != std::string_view::npos)
            xff.remove_prefix(comma + 1);
        while (!xff.empty() && xff.front() == ' ')
            xff.remove_prefix(1);
        if (!xff.empty() && xff.size() <= 45 && xff.find_first_not_of("0123456789abcdefABCDEF:.") == std::string_view::npos)
            m_hooks.forward(std::string(xff));
        m_from_page = !rq.header("x-socketley-ui").empty() || !rq.header("cookie").empty();
        if ((rq.method == "GET" || rq.method == "HEAD") && rq.path == "/")
        {
            page(rq);
            return after();
        }
        if (rq.path == "/unsubscribe")
        {
            unsubscribe_page(rq);
            return after();
        }
        // A mail client asking how it reaches a mailbox: Thunderbird at autoconfig.<domain>, Outlook at autodiscover.
        std::string lower = rq.path;
        socketley::ascii::lower_in_place(lower);
        const auto told = [&](std::string_view kind, const std::string& email, std::string_view type) {
            const std::string doc = m_hooks.client_setup(kind, email);
            if (doc.empty())
                fail(404, "about:blank", "no mailbox of that domain is kept here");
            else
                respond(200, type, doc);
            return after();
        };
        if (lower == "/mail/config-v1.1.xml" || lower == "/.well-known/autoconfig/mail/config-v1.1.xml")
            return told("autoconfig", query_param(rq.query, "emailaddress"), "application/xml");
        if (lower == "/autodiscover/autodiscover.xml")
            return told("autodiscover", autodiscover_address(rq.body), "application/xml");
        if (lower.starts_with("/autodiscover/autodiscover.json"))
        {
            std::string host = rq.header("x-forwarded-host");
            if (host.empty())
                host = rq.header("host");
            respond(200, "application/json", outlook_autodiscover_json(host.substr(0, host.find(':'))));
            return after();
        }
    }
    // A calendar or contacts client looking for where they are kept (RFC 6764).
    if (rq.path == "/.well-known/caldav" || rq.path == "/.well-known/carddav")
    {
        respond(301, {}, {}, "Location: /dav/\r\n");
        return after();
    }
    if (rq.method == "OPTIONS" && dav_path(rq.path, "PROPFIND"))
    {
        respond(200, {}, {}, "DAV: " + std::string(dav_classes) + "\r\nAllow: " + std::string(dav_allow) + "\r\n");
        return after();
    }
    if (rq.method == "OPTIONS")
    {
        respond(204, {}, {}, "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                             "Access-Control-Allow-Headers: Authorization, Content-Type, Accept\r\n"
                             "Access-Control-Max-Age: 86400\r\n");
        return after();
    }
    // Basic, a bearer token and the cookie alike: what another site had the browser send unasked changes nothing.
    if (rq.method != "GET" && rq.method != "HEAD" && unasked_from_elsewhere(rq))
    {
        fail(403, "about:blank", "a change from another site goes by CORS, as application/json");
        return after();
    }
    const std::string auth = rq.header("authorization");
    const auto serve = [this, after](request r) {
        const std::string& p = r.path;
        if (p == "/~mail/session" && r.method == "GET" && m_cfg.web)
        {
            web_session(r);
            return after();
        }
        // The webmail's filter rules, read, or put by the page alone.
        if (p == "/~mail/filters" && m_cfg.web && (r.method == "GET" || (r.method == "PUT" && m_from_page)))
        {
            std::optional<std::string> script;
            if (r.method == "PUT")
                script = r.body;
            m_hooks.filters(m_user, std::move(script), [this, alive = m_alive, after](int status, std::string body) {
                if (!*alive)
                    return;
                respond(status, "application/json", body);
                after();
            });
            return;
        }
        // The signed-in user's profile for an iPhone, an iPad or a Mac.
        if (p == "/~mail/mobileconfig" && r.method == "GET" && m_cfg.web)
        {
            const std::string doc = m_hooks.client_setup("mobileconfig", m_hooks.address_of(m_user));
            if (doc.empty())
                fail(404, "about:blank", "no address of this runtime's domains is yours");
            else
                respond(200, "application/x-apple-aspen-config", doc,
                        "Content-Disposition: attachment; filename=\"mail.mobileconfig\"\r\n");
            return after();
        }
        if ((p == "/.well-known/jmap" || p == "/jmap/session") && r.method == "GET")
        {
            respond(200, "application/json", session_json(r));
            return after();
        }
        if (p == "/jmap/api")
        {
            if (r.method != "POST")
            {
                fail(405, "about:blank", "the API takes POST");
                return after();
            }
            return api(r);
        }
        if (p.starts_with("/jmap/upload/") && r.method == "POST")
        {
            const std::string a = percent_decoded(std::string_view(p).substr(13, p.find('/', 13) - 13));
            return upload(r, a);
        }
        if (p.starts_with("/jmap/download/") && r.method == "GET")
        {
            std::vector<std::string> parts;
            for (std::string_view rest = std::string_view(p).substr(15); !rest.empty();)
            {
                const size_t slash = rest.find('/');
                parts.push_back(percent_decoded(rest.substr(0, slash)));
                rest = slash == std::string_view::npos ? std::string_view{} : rest.substr(slash + 1);
            }
            if (parts.size() < 2)
            {
                fail(404, "about:blank", "no such blob");
                return after();
            }
            return download(parts[0], parts[1], query_param(r.query, "type"), parts.size() > 2 ? parts[2] : "blob");
        }
        if (p == "/jmap/eventsource" && r.method == "GET")
            return eventsource(r);
        if (dav_path(p, r.method))
        {
            dav_store* store = m_hooks.dav();
            if (!store)
            {
                fail(404, "about:blank", "calendars and contacts need --idp and --storage");
                return after();
            }
            dav_request d{r.method, p, [hs = r.headers](std::string_view n) {
                              for (const auto& [k, v] : hs)
                                  if (socketley::ascii::iequals(k, n))
                                      return v;
                              return std::string();
                          },
                          std::move(r.body)};
            return dav_serve(*store, m_alive, m_user, m_hooks.address_of(m_user), std::move(d),
                             [this, after, alive = m_alive](dav_reply out) {
                                 if (!*alive)
                                     return;
                                 respond(out.code, out.type, out.body, out.headers);
                                 after();
                             });
        }
        fail(404, "about:blank", "nothing is here");
        return after();
    };
    if (auth.empty())
    {
        const std::string cookies = m_cfg.web ? rq.header("cookie") : std::string();
        if (m_cfg.web)
            m_login = m_hooks.idp_login(base_url(rq) + "/");
        if (cookies.empty())
        {
            fail(401, "about:blank", "sign in with HTTP Basic or a bearer token");
            return after();
        }
        // A change signed in by the cookie alone carries the page's header, which another site cannot make a browser send.
        if (rq.method != "GET" && rq.method != "HEAD" && rq.header("x-socketley-ui").empty())
        {
            fail(403, "about:blank", "a change signed in by the webmail's cookie carries X-Socketley-UI");
            return after();
        }
        // The cookie is looked at on every request, so a session that ended or was signed out ends here at once.
        return m_hooks.cookie(cookies, [this, serve, after, rq, alive = m_alive](account a, std::string name) mutable {
            if (!*alive)
                return;
            if (a != account::yes || name.empty())
            {
                m_user.clear();
                m_auth_seen.clear();
                fail(401, "about:blank", "the session has ended: sign in again");
                return after();
            }
            m_user = std::move(name);
            m_auth_seen.clear();
            serve(std::move(rq));
        });
    }
    if (!m_user.empty() && auth == m_auth_seen)
        return serve(std::move(rq));
    const auto signed_in = [this, auth, serve, after, rq, alive = m_alive](account a, std::string name) mutable {
        if (!*alive)
            return;
        if (a != account::yes || name.empty())
        {
            m_user.clear();
            m_auth_seen.clear();
            if (a == account::unreachable)
                fail(503, "about:blank", "the accounts cannot be asked now");
            else
                fail(401, "about:blank", "the credentials are not right");
            return after();
        }
        m_user = std::move(name);
        m_auth_seen = auth;
        serve(std::move(rq));
    };
    if (auth.size() > 7 && socketley::ascii::iequals(std::string_view(auth).substr(0, 7), "Bearer "))
        return m_hooks.bearer(auth.substr(7), signed_in);
    std::string plain;
    if (auth.size() <= 6 || !socketley::ascii::iequals(std::string_view(auth).substr(0, 6), "Basic ") ||
        !socketley::base64::decode(std::string_view(auth).substr(6), plain) || plain.find(':') == std::string::npos)
    {
        fail(401, "about:blank", "sign in with HTTP Basic or a bearer token");
        return after();
    }
    // A password goes over TLS, the entrance's HTTPS, or in the clear from this machine alone.
    if (!m_cfg.tls_active && !m_https && !m_cfg.login_in_clear)
    {
        fail(403, "about:blank", "a password is taken over TLS only");
        return after();
    }
    const size_t colon = plain.find(':');
    m_hooks.login(plain.substr(0, colon), plain.substr(colon + 1), signed_in);
}

std::string jmap_session::session_json(const request& rq) const
{
    const std::string base = base_url(rq);
    const std::string acct = account_of(m_user);
    std::string a;
    json::quote_into(a, acct);
    std::string out = "{\"capabilities\":{";
    json::quote_into(out, core);
    out += ":{\"maxSizeUpload\":" + std::to_string(m_cfg.max_size) +
           ",\"maxConcurrentUpload\":4,\"maxSizeRequest\":" + std::to_string(max_request) +
           ",\"maxConcurrentRequests\":4,\"maxCallsInRequest\":64,\"maxObjectsInGet\":1000,\"maxObjectsInSet\":1000,"
           "\"collationAlgorithms\":[\"i;ascii-casemap\",\"i;octet\"]},";
    json::quote_into(out, mail_cap);
    out += ":{},";
    json::quote_into(out, submission_cap);
    out += ":{},";
    json::quote_into(out, vacation_cap);
    out += ":{},";
    json::quote_into(out, quota_cap);
    out += ":{}},\"accounts\":{" + a + ":{\"name\":";
    json::quote_into(out, m_user);
    out += ",\"isPersonal\":true,\"isReadOnly\":false,\"accountCapabilities\":{";
    json::quote_into(out, mail_cap);
    out += ":{\"maxMailboxesPerEmail\":1,\"maxMailboxDepth\":null,\"maxSizeMailboxName\":255,"
           "\"maxSizeAttachmentsPerEmail\":" +
           std::to_string(m_cfg.max_size) +
           ",\"emailQuerySortOptions\":[\"receivedAt\",\"size\",\"subject\",\"from\",\"to\",\"sentAt\"],"
           "\"mayCreateTopLevelMailbox\":true},";
    json::quote_into(out, submission_cap);
    out += ":{\"maxDelayedSend\":2592000,\"submissionExtensions\":{\"FUTURERELEASE\":[]}},";
    json::quote_into(out, vacation_cap);
    out += ":{},";
    json::quote_into(out, quota_cap);
    out += ":{}}}},\"primaryAccounts\":{";
    json::quote_into(out, mail_cap);
    out += ":" + a + ",";
    json::quote_into(out, submission_cap);
    out += ":" + a + ",";
    json::quote_into(out, vacation_cap);
    out += ":" + a + ",";
    json::quote_into(out, quota_cap);
    out += ":" + a + "},\"username\":";
    json::quote_into(out, m_user);
    out += ",\"apiUrl\":";
    json::quote_into(out, base + "/jmap/api");
    out += ",\"downloadUrl\":";
    json::quote_into(out, base + "/jmap/download/{accountId}/{blobId}/{name}?type={type}");
    out += ",\"uploadUrl\":";
    json::quote_into(out, base + "/jmap/upload/{accountId}/");
    out += ",\"eventSourceUrl\":";
    json::quote_into(out, base + "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}");
    out += ",\"state\":";
    json::quote_into(out, mailbox_state(m_store, m_user));
    out += "}";
    return out;
}

void jmap_session::api(const request& rq)
{
    m_threads_ready = false;
    auto cs = std::make_shared<call_state>();
    json::json_policy policy;
    policy.max_depth = 32;
    if (!json::json_reader(rq.body, policy).document(cs->req))
    {
        fail(400, "urn:ietf:params:jmap:error:notJSON", "the request is not JSON");
        return finished();
    }
    const json::jvalue* using_ = json::member(cs->req, "using");
    const json::jvalue* calls = json::member(cs->req, "methodCalls");
    if (!using_ || using_->k != json::jvalue::kind::array || !calls || calls->k != json::jvalue::kind::array)
    {
        fail(400, "urn:ietf:params:jmap:error:notRequest", "a request has using and methodCalls");
        return finished();
    }
    for (const auto& u : using_->items)
        if (u.k != json::jvalue::kind::string ||
            (u.s != core && u.s != mail_cap && u.s != submission_cap && u.s != vacation_cap && u.s != quota_cap))
        {
            fail(400, "urn:ietf:params:jmap:error:unknownCapability", "a capability this server does not have: " + u.s);
            return finished();
        }
    if (calls->items.size() > 64)
    {
        fail(400, "urn:ietf:params:jmap:error:limit", "more than 64 calls in one request");
        return finished();
    }
    if (const json::jvalue* ids = json::member(cs->req, "createdIds"); ids && ids->k == json::jvalue::kind::object)
    {
        cs->echo_created = true;
        for (const auto& [k, v] : ids->members)
            if (v.k == json::jvalue::kind::string)
                cs->created[k] = v.s;
    }
    // The index as it is now, every Email by its id, with what the bucket holds and no journal names taken up first.
    m_store.freshen(m_user, [this, cs, alive = m_alive] {
        if (!*alive)
            return;
        for (const auto& f : m_store.known(m_user))
            for (const auto& m : f->msgs)
                m_ids[imap_store::email_id(m.key)] = {f, m.uid};
        next_call(cs);
    });
}

void jmap_session::next_call(const std::shared_ptr<call_state>& cs)
{
    const json::jvalue& calls = *json::member(cs->req, "methodCalls");
    if (cs->at >= calls.items.size())
    {
        std::string body = "{\"methodResponses\":[" + cs->out + "],\"sessionState\":";
        json::quote_into(body, mailbox_state(m_store, m_user));
        if (cs->echo_created)
        {
            body += ",\"createdIds\":{";
            bool first = true;
            for (const auto& [k, v] : cs->created)
            {
                if (!first)
                    body += ",";
                first = false;
                json::quote_into(body, k);
                body += ":";
                json::quote_into(body, v);
            }
            body += "}";
        }
        body += "}";
        respond(200, "application/json", body);
        return finished();
    }
    const json::jvalue& c = calls.items[cs->at++];
    const auto said = [this, cs](const std::string& name, const std::string& args, const std::string& id) {
        if (!cs->out.empty())
            cs->out += ",";
        cs->out += "[";
        json::quote_into(cs->out, name);
        cs->out += "," + args + ",";
        json::quote_into(cs->out, id);
        cs->out += "]";
        call_state::said s{name, {}, id};
        json::json_policy policy;
        policy.max_depth = 32;
        if (!json::json_reader(args, policy).document(s.args))
            s.args = {};
        cs->answers.push_back(std::move(s));
    };
    if (c.k != json::jvalue::kind::array || c.items.size() != 3 || c.items[0].k != json::jvalue::kind::string ||
        c.items[1].k != json::jvalue::kind::object || c.items[2].k != json::jvalue::kind::string)
    {
        fail(400, "urn:ietf:params:jmap:error:notRequest", "a method call is [name, arguments, id]");
        return finished();
    }
    const std::string name = c.items[0].s, id = c.items[2].s;
    // Arguments that refer back to what a call before said (RFC 8620 3.7).
    json::jvalue args = c.items[1];
    for (auto& [k, v] : args.members)
    {
        if (k.empty() || k.front() != '#')
            continue;
        const std::string_view of = json::string_of(v, "resultOf"), what = json::string_of(v, "name"),
                               path = json::string_of(v, "path");
        const auto it = std::find_if(cs->answers.begin(), cs->answers.end(),
                                     [&](const call_state::said& s) { return s.id == of && s.name == what; });
        json::jvalue got;
        if (it == cs->answers.end() || !pointer(it->args, path, got))
        {
            said("error", "{\"type\":\"invalidResultReference\"}", id);
            return next_call(cs);
        }
        const std::string plain = k.substr(1);
        if (json::member(args, plain))
        {
            said("error", "{\"type\":\"invalidArguments\",\"description\":\"an argument and its reference both\"}", id);
            return next_call(cs);
        }
        k = plain;
        v = std::move(got);
    }
    // An id given as #<creation id> is what that creation made (RFC 8620 5.3).
    if (json::jvalue* ids = json::member(args, "ids"); ids && ids->k == json::jvalue::kind::array)
        for (auto& v : ids->items)
            if (v.k == json::jvalue::kind::string && v.s.size() > 1 && v.s.front() == '#')
                if (const auto it = cs->created.find(v.s.substr(1)); it != cs->created.end())
                    v.s = it->second;
    if (json::member(args, "accountId") && json::string_of(args, "accountId") != account_of(m_user) &&
        name != "Core/echo")
    {
        said("error", "{\"type\":\"accountNotFound\"}", id);
        return next_call(cs);
    }
    method(name, args, cs, [this, cs, id, said, alive = m_alive](answer a) {
        if (!*alive)
            return;
        for (const auto& [n, json_args] : a)
            said(n, json_args, id);
        next_call(cs);
    });
}

void jmap_session::method(const std::string& name, const json::jvalue& args, const std::shared_ptr<call_state>& cs,
                          std::function<void(answer)> done)
{
    if (name == "Core/echo")
        return done({{"Core/echo", json::written(args)}});
    if (name == "Mailbox/get")
        return mailbox_get(args, std::move(done));
    if (name == "Mailbox/query")
        return mailbox_query(args, std::move(done));
    if (name == "Mailbox/set")
        return mailbox_set(args, cs, std::move(done));
    if (name == "Email/get")
        return email_get(args, std::move(done));
    if (name == "Email/query")
        return email_query(args, std::move(done));
    if (name == "Email/set")
        return email_set(args, cs, std::move(done));
    if (name == "Email/import")
        return email_import(args, cs, std::move(done));
    if (name == "Thread/get")
        return thread_get(args, std::move(done));
    if (name == "Email/parse")
        return email_parse(args, std::move(done));
    if (name == "VacationResponse/get")
        return vacation_get(args, std::move(done));
    if (name == "VacationResponse/set")
        return vacation_set(args, std::move(done));
    if (name == "Quota/get" || name == "Quota/changes" || name == "Quota/query" || name == "Quota/queryChanges")
        return quota(name, args, std::move(done));
    if (name == "PushSubscription/get")
        return push_get(args, std::move(done));
    if (name == "PushSubscription/set")
        return push_set(args, cs, std::move(done));
    if (name == "Identity/get")
        return identity_get(args, std::move(done));
    if (name == "Identity/set")
        return identity_set(args, std::move(done));
    if (name == "EmailSubmission/set")
        return submission_set(args, cs, std::move(done));
    if (name == "Mailbox/changes" || name == "Email/changes" || name == "Thread/changes" ||
        name == "Identity/changes" || name == "EmailSubmission/changes")
        return changes(name.substr(0, name.find('/')), args, std::move(done));
    if (name == "SearchSnippet/get")
    {
        // No highlighting is made here: each Email's snippet is null, which a client shows as its preview.
        std::string list, missing;
        if (const json::jvalue* ids = json::member(args, "emailIds"); ids && ids->k == json::jvalue::kind::array)
            for (const auto& v : ids->items)
            {
                where w;
                std::string& to = v.k == json::jvalue::kind::string && locate(v.s, w) ? list : missing;
                if (!to.empty())
                    to += ",";
                to += &to == &list ? "{\"emailId\":" + json::quote(v.s) + ",\"subject\":null,\"preview\":null}"
                                               : json::quote(v.s);
            }
        return done({{"SearchSnippet/get", "{\"accountId\":" + json::quote(account_of(m_user)) + ",\"list\":[" + list +
                                               "],\"notFound\":[" + missing + "]}"}});
    }
    if (name == "Mailbox/queryChanges" || name == "Email/queryChanges" || name == "EmailSubmission/queryChanges")
        return done({{"error", "{\"type\":\"cannotCalculateChanges\"}"}});
    if (name == "EmailSubmission/get" || name == "EmailSubmission/query")
    {
        // What was submitted is in the spool and then gone; none is kept to be listed.
        std::string out = "{\"accountId\":";
        json::quote_into(out, account_of(m_user));
        out += name == "EmailSubmission/get" ? ",\"state\":\"s0\",\"list\":[],\"notFound\":" +
                                                   json::written(json::member(args, "ids") ? *json::member(args, "ids")
                                                                                           : json::jvalue{}) +
                                                   "}"
                                             : ",\"queryState\":\"s0\",\"canCalculateChanges\":false,\"position\":0,"
                                               "\"ids\":[],\"total\":0}";
        return done({{name, out}});
    }
    done({{"error", "{\"type\":\"unknownMethod\"}"}});
}

void jmap_session::changes(const std::string& type, const json::jvalue& args, std::function<void(answer)> done)
{
    // A state is a digest: the same one means nothing changed, another that what did must be read again.
    const std::string now = type == "Mailbox" ? mailbox_state(m_store, m_user)
                            : type == "Identity" || type == "EmailSubmission" ? std::string("s0")
                                                                              : email_state(m_store, m_user);
    const std::string since(json::string_of(args, "sinceState"));
    if (since != now)
        return done({{"error", "{\"type\":\"cannotCalculateChanges\"}"}});
    std::string out = "{\"accountId\":";
    json::quote_into(out, account_of(m_user));
    out += ",\"oldState\":";
    json::quote_into(out, now);
    out += ",\"newState\":";
    json::quote_into(out, now);
    out += ",\"hasMoreChanges\":false,\"created\":[],\"updated\":[],\"destroyed\":[]";
    if (type == "Mailbox")
        out += ",\"updatedProperties\":null";
    out += "}";
    done({{type + "/changes", out}});
}

void jmap_session::upload(const request& rq, const std::string& account)
{
    if (account != account_of(m_user))
    {
        fail(404, "urn:ietf:params:jmap:error:notFound", "no such account");
        return finished();
    }
    std::string type = rq.header("content-type");
    if (type.empty() || type.find_first_of("\r\n\"") != std::string::npos)
        type = "application/octet-stream";
    const size_t size = rq.body.size();
    m_store.put_upload(m_user, rq.body, [this, account, type, size, alive = m_alive](std::string id) {
        if (!*alive)
            return;
        if (id.empty())
        {
            fail(500, "about:blank", "the upload could not be kept");
            return finished();
        }
        std::string out = "{\"accountId\":";
        json::quote_into(out, account);
        out += ",\"blobId\":";
        json::quote_into(out, id);
        out += ",\"type\":";
        json::quote_into(out, type);
        out += ",\"size\":" + std::to_string(size) + "}";
        respond(201, "application/json", out);
        finished();
    });
}

void jmap_session::download(const std::string& account, const std::string& id, const std::string& type,
                            const std::string& name)
{
    if (account != account_of(m_user))
    {
        fail(404, "urn:ietf:params:jmap:error:notFound", "no such account");
        return finished();
    }
    for (const auto& f : m_store.known(m_user))
        for (const auto& m : f->msgs)
            m_ids[imap_store::email_id(m.key)] = {f, m.uid};
    // The type and name a client asked for, as long as they are ones a header may carry.
    const bool plain_type = !type.empty() && type.size() < 128 && type.find('/') != std::string::npos &&
                            type.find_first_of("\r\n;\" ") == std::string::npos;
    std::string file = name;
    std::erase_if(file, [](char c) { return c == '"' || c == '\\' || static_cast<unsigned char>(c) < 0x20; });
    blob(id, [this, type = plain_type ? type : std::string("application/octet-stream"), file,
              alive = m_alive](std::shared_ptr<const std::string> bytes) {
        if (!*alive)
            return;
        if (!bytes)
        {
            fail(404, "urn:ietf:params:jmap:error:notFound", "no such blob");
            return finished();
        }
        // The blob the store holds goes out as it is, where building an answer around it copied it twice.
        m_hooks.reply_with_body(
            head_of(200, type, bytes->size(), "Content-Disposition: attachment; filename=\"" + file + "\"\r\n"), bytes);
        finished();
    });
}

void jmap_session::page(const request& rq)
{
    // The page changes only with the binary, so a browser's copy is asked after and answered 304 while it holds.
    const web_page& w = webmail_page();
    const bool same = rq.header("if-none-match").find(w.etag) != std::string::npos;
    std::string out = same ? "HTTP/1.1 304 Not Modified\r\n" : "HTTP/1.1 200 OK\r\n";
    out += "ETag: " + w.etag + "\r\nCache-Control: no-cache\r\n";
    if (!same)
        out += "Content-Type: text/html; charset=utf-8\r\nContent-Length: " + std::to_string(w.html.size()) + "\r\n";
    out += "Content-Security-Policy: " + w.csp +
           "\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\r\n";
    if (!same && rq.method != "HEAD")
        out += w.html;
    m_hooks.reply(out);
}

void jmap_session::unsubscribe_page(const request& rq)
{
    // The token is the link's own, base64url and hex: one with any other character is no link this runtime made.
    const std::string token = query_param(rq.query, "t");
    const bool shaped = !token.empty() && token.size() < 600 &&
                        token.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.") ==
                            std::string::npos;
    std::string text, form;
    int code = 200;
    if (!shaped)
    {
        code = 404;
        text = "This link to unsubscribe is not one of this mail server's.";
    }
    else if (rq.method == "POST")
    {
        const bool done = m_hooks.unsubscribe(token);
        code = done ? 200 : 404;
        text = done ? "You are unsubscribed, and will get no more of these mails."
                    : "This link to unsubscribe is not one of this mail server's.";
    }
    else
    {
        // A GET only asks, as a mail scanner that opens every link would otherwise unsubscribe its reader.
        text = "Unsubscribe from these mails?";
        form = "<form method=\"post\" action=\"/unsubscribe?t=" + token +
               "\"><button type=\"submit\">Unsubscribe</button></form>";
    }
    const std::string body =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
        "content=\"width=device-width,initial-scale=1\"><title>Unsubscribe</title><style>body{margin:0;min-height:100vh;"
        "display:flex;align-items:center;justify-content:center;background:#07080c;color:#eef0f7;font:16px/1.5 system-ui,"
        "sans-serif}main{max-width:420px;padding:32px;text-align:center}button{margin-top:18px;font:inherit;font-weight:600;"
        "padding:10px 22px;border:0;border-radius:10px;background:linear-gradient(120deg,#c084fc,#f472b6);color:#fff;"
        "cursor:pointer}</style></head><body><main><p>" + text + "</p>" + form + "</main></body></html>";
    std::string out = "HTTP/1.1 " + std::to_string(code) + " " + reason_of(code) +
                      "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + std::to_string(body.size()) +
                      "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
                      "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                      "frame-ancestors 'none'\r\n\r\n";
    if (rq.method != "HEAD")
        out += body;
    m_hooks.reply(out);
}

void jmap_session::web_session(const request& rq)
{
    std::string out = "{\"user\":";
    json::quote_into(out, m_user);
    out += ",\"account\":";
    json::quote_into(out, account_of(m_user));
    out += ",\"address\":";
    json::quote_into(out, m_hooks.address_of(m_user));
    out += ",\"logout\":";
    json::quote_into(out, m_hooks.idp_logout(base_url(rq) + "/"));
    // The servers and ports a mail app is set up with.
    if (const std::string setup = m_hooks.client_setup("json", m_hooks.address_of(m_user)); !setup.empty())
        out += ",\"setup\":" + setup;
    out += "}";
    respond(200, "application/json", out);
}

void jmap_session::eventsource(const request& rq)
{
    // ping is seconds between pings, the least a client may ask 30 (RFC 8620 7.3).
    const std::string ping = query_param(rq.query, "ping");
    int64_t p = 0;
    std::from_chars(ping.data(), ping.data() + ping.size(), p);
    m_ping_s = p <= 0 ? 0 : std::clamp<int64_t>(p, 30, 86400);
    m_close_after_state = query_param(rq.query, "closeafter") == "state";
    m_stream = true;
    m_stream_state = email_state(m_store, m_user) + mailbox_state(m_store, m_user);
    m_last_sent_ms = wall::now_ms_coarse();
    m_hooks.reply(std::string("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n") +
                  (m_from_page ? "" : "Access-Control-Allow-Origin: *\r\n") + "\r\n");
    m_busy = false;
}

void jmap_session::poll()
{
    if (!m_stream || m_closed)
        return;
    const int64_t now = wall::now_ms_coarse();
    const std::string es = email_state(m_store, m_user), ms = mailbox_state(m_store, m_user);
    if (es + ms != m_stream_state)
    {
        m_stream_state = es + ms;
        std::string data = "{\"@type\":\"StateChange\",\"changed\":{";
        json::quote_into(data, account_of(m_user));
        data += ":{\"Email\":";
        json::quote_into(data, es);
        data += ",\"Thread\":";
        json::quote_into(data, es);
        data += ",\"Mailbox\":";
        json::quote_into(data, ms);
        data += "}}}";
        m_hooks.reply("event: state\ndata: " + data + "\n\n");
        m_last_sent_ms = now;
        if (m_close_after_state)
        {
            m_closed = true;
            m_hooks.close();
        }
        return;
    }
    if (m_ping_s && now - m_last_sent_ms >= m_ping_s * 1000)
    {
        m_hooks.reply("event: ping\ndata: {\"interval\":" + std::to_string(m_ping_s) + "}\n\n");
        m_last_sent_ms = now;
    }
}

bool jmap_session::locate(const std::string& id, where& out)
{
    const auto it = m_ids.find(id);
    if (it == m_ids.end() || !it->second.first->by_uid(it->second.second))
        return false;
    out.f = it->second.first;
    out.uid = it->second.second;
    return true;
}

std::shared_ptr<imap_folder> jmap_session::mailbox_by_id(const std::string& id)
{
    for (const auto& f : m_store.known(m_user))
        if (f->id() == id)
            return f;
    return nullptr;
}

void jmap_session::blob(const std::string& id, std::function<void(std::shared_ptr<const std::string>)> done)
{
    if (id.starts_with("U"))
        return m_store.get_upload(m_user, id, std::move(done));
    // An Email's id is its whole message's blob; <email>_<part> a part of it, its numbers joined by -.
    const size_t us = id.find('_');
    where w;
    if (!locate(id.substr(0, us), w))
        return done(nullptr);
    const imap_message* m = w.m();
    std::string section = us == std::string::npos ? std::string() : id.substr(us + 1);
    std::replace(section.begin(), section.end(), '-', '.');
    m_store.body(m->key, m->size, [section, done](std::shared_ptr<const std::string> bytes) {
        if (!bytes || section.empty())
            return done(bytes);
        const mime::part root = mime::parse(*bytes);
        auto out = std::make_shared<std::string>();
        if (mime::binary_of(*bytes, root, section, *out) <= 0)
            return done(nullptr);
        done(out);
    });
}

}   // namespace socketley::mail
