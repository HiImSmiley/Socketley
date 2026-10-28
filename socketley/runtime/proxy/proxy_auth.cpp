#include "proxy_auth.h"

#include <arpa/inet.h>
#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

#include <openssl/crypto.h>

#include "../../shared/util/logging.h"
#include "../storage/s3_sigv4_auth.h"
#include "../idp/idp_session.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/base64.h"
#include "../../shared/crypto/mac.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/net/peer_address.h"

namespace
{


std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

bool equal_secret(std::string_view a, std::string_view b)
{
    return !a.empty() && socketley::crypto::secure_equal(a, b);
}

// One holder of an IPv6 network has its whole /64, so that is what counts as one address.
std::string miss_key(std::string_view client)
{
    char text[INET6_ADDRSTRLEN]{};
    if (client.size() >= sizeof text)
        return std::string(client);
    std::memcpy(text, client.data(), client.size());
    in6_addr a{};
    if (::inet_pton(AF_INET6, text, &a) != 1)
        return std::string(client);
    // An IPv4 peer on a dual-stack socket is its own address, as it is on an IPv4 one, and not ::ffff:0:0/64.
    if (IN6_IS_ADDR_V4MAPPED(&a))
    {
        char v4[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &a.s6_addr[12], v4, sizeof v4))
            return v4;
    }
    // Led by a byte no address text has, so the raw bytes of a /64 can never equal an IPv4 peer's text.
    static constexpr unsigned char zero[8]{};
    const size_t n = std::memcmp(a.s6_addr, zero, 8) == 0 ? 16 : 8;
    return '\x06' + std::string(reinterpret_cast<const char*>(a.s6_addr), n);
}

}   // namespace

proxy_auth::proxy_auth() = default;
proxy_auth::~proxy_auth() = default;

std::string proxy_auth::spec_error(std::string_view spec)
{
    if (spec.starts_with("idp:"))
    {
        const std::string_view name = spec.substr(4);
        if (name.empty() || name.find_first_of("/ ") != std::string_view::npos)
            return "--auth: idp: takes the name of an idp runtime of this daemon, not '" + std::string(name) + "'";
        return {};
    }
    const bool bearer = spec.starts_with("bearer:"), basic = spec.starts_with("basic:");
    if (!bearer && !basic)
        return "--auth takes bearer:<file of tokens>, basic:<credentials file of a storage runtime> or "
               "idp:<idp runtime>, not '" +
               std::string(spec) + "'";
    const std::string file(spec.substr(bearer ? 7 : 6));
    if (file.empty() || file.front() != '/')
        return "--auth: the file is given by its absolute path, not '" + file + "'";
    return {};
}

void proxy_auth::configure(std::string_view spec, std::string_view runtime)
{
    // A spec that is none of the three, from saved state or an archive the flag never judged, is a bearer
    // --auth with no file, which refuses everybody where none would let everybody through.
    const bool unknown = !spec.empty() && !spec.starts_with("bearer:") && !spec.starts_with("basic:") &&
                         !spec.starts_with("idp:");
    m_kind = spec.starts_with("bearer:")  ? kind::bearer
           : spec.starts_with("basic:") ? kind::basic
           : spec.starts_with("idp:")   ? kind::idp
           : unknown                    ? kind::bearer
                                        : kind::none;
    m_file.assign(m_kind == kind::none || m_kind == kind::idp || unknown
                      ? std::string_view{}
                      : spec.substr(m_kind == kind::bearer ? 7 : 6));
    if (m_kind != kind::none && m_kind != kind::idp && m_file.empty())
        LOG_ERROR(("proxy " + std::string(runtime) + ": " + spec_error(spec) + "; every request is refused").c_str());
    m_sessions.reset();
    if (m_kind == kind::idp)
    {
        m_sessions = std::make_unique<socketley::idp::session_verifier>();
        m_sessions->configure(spec.substr(4));
    }
    m_runtime.assign(runtime);
    m_challenge = m_kind == kind::basic ? "WWW-Authenticate: Basic realm=\"" + m_runtime + "\", charset=\"UTF-8\"\r\n"
                                        : "WWW-Authenticate: Bearer realm=\"" + m_runtime + "\"\r\n";
    m_stamp.reset();
    m_loaded = false;
    m_tokens.clear();
    m_keys.reset();
    m_misses.clear();
}

void proxy_auth::reload(std::chrono::steady_clock::time_point now)
{
    // No file refuses everybody, which configure has already said.
    if (m_file.empty())
        return;
    if (m_stamp && now - m_checked < std::chrono::seconds(1))
        return;
    m_checked = now;
    const socketley::file_stamp stamp = socketley::file_stamp::of(m_file);
    if (stamp == m_stamp)
        return;
    m_stamp = stamp;
    m_loaded = false;
    m_tokens.clear();
    m_keys.reset();

    std::string text;
    if (!socketley::read_whole_file(m_file, text))
    {
        LOG_ERROR(("proxy " + m_runtime + ": --auth: " + m_file + " cannot be read; every request is refused").c_str());
        return;
    }
    if (m_kind == kind::bearer)
    {
        for (size_t p = 0; p < text.size();)
        {
            const size_t nl = std::min(text.find('\n', p), text.size());
            const std::string_view line = trim(std::string_view(text).substr(p, nl - p));
            if (!line.empty() && line.front() != '#')
                m_tokens.emplace_back(line);
            p = nl + 1;
        }
        m_loaded = !m_tokens.empty();
        if (!m_loaded)
            LOG_ERROR(("proxy " + m_runtime + ": --auth: " + m_file + " holds no token; every request is refused").c_str());
        return;
    }
    auto keys = std::make_unique<socketley::storage::credential_set>();
    std::string err;
    const std::string dir = m_file.substr(0, m_file.rfind('/'));
    if (!socketley::storage::parse_credentials(text, *keys, err, dir))
    {
        LOG_ERROR(("proxy " + m_runtime + ": --auth: " + m_file + ": " + err + "; every request is refused").c_str());
        return;
    }
    m_keys = std::move(keys);
    m_loaded = true;
}

std::string proxy_auth::user_of(std::string_view access_key) const
{
    if (!m_loaded || !m_keys)
        return {};
    const auto u = m_keys->user_of(access_key);
    return u ? u->id : std::string();
}

bool proxy_auth::admit(std::string_view authorization) const
{
    // An idp's sessions are cookies, which check_session answers.
    if (!m_loaded || m_kind == kind::idp)
        return false;
    std::string_view value;
    if (m_kind == kind::bearer)
    {
        if (!http_auth_credentials(authorization, "bearer", value))
            return false;
        // Every token is compared, so how long a refusal takes says nothing about which came close.
        bool ok = false;
        for (const std::string& t : m_tokens)
            ok = equal_secret(t, value) || ok;
        return ok;
    }
    std::string pair;
    if (!http_auth_credentials(authorization, "basic", value) || !socketley::base64::decode(value, pair))
        return false;
    const size_t colon = pair.find(':');
    if (colon == std::string::npos)
        return false;
    const std::string_view key = std::string_view(pair).substr(0, colon);
    const std::string_view secret = std::string_view(pair).substr(colon + 1);
    if (!equal_secret(m_keys->secret(key), secret))
        return false;
    // A key outside any [user] signs for the default owner, who is an admin.
    const auto user = m_keys->user_of(key);
    return !user || user->admin;
}

proxy_auth::verdict proxy_auth::check_session(std::string_view cookies, std::string& sub, std::string& username,
                                              std::string& email)
{
    socketley::idp::session_verifier::who w;
    if (!m_sessions || !m_sessions->check(cookies, w))
        return verdict::refuse;
    sub = std::move(w.sub);
    username = std::move(w.username);
    email = std::move(w.email);
    return verdict::pass;
}

std::string proxy_auth::login_url(std::string_view return_to)
{
    return m_sessions ? m_sessions->login_url(return_to) : std::string();
}

proxy_auth::verdict proxy_auth::check(std::string_view authorization, std::string_view client, int64_t& retry_after)
{
    if (m_kind == kind::none)
        return verdict::pass;
    const auto now = std::chrono::steady_clock::now();
    reload(now);
    const std::string key = miss_key(client);
    if (const int64_t left = m_misses.barred_for(key, now))
    {
        retry_after = left;
        return verdict::barred;
    }
    if (admit(authorization))
        return verdict::pass;
    // A request that offered nothing is a browser asking what to offer, not a guess.
    if (authorization.empty())
        return verdict::refuse;
    m_misses.missed(key, now);
    LOG_WARN(("proxy " + m_runtime + ": authorization refused from " + std::string(client)).c_str());
    return verdict::refuse;
}

proxy_auth::request_verdict proxy_auth::decide(std::string_view head, std::string_view peer, bool tls,
                                               std::string_view method, std::string_view path, std::string_view host)
{
    request_verdict v;
    int fields = 0;
    const std::string_view authorization = http_request_field(head, "authorization", fields);
    // Behind the entrance, a hop on this machine, the client is who it says it heard from last.
    std::string client(peer);
    if (socketley::is_loopback(client))
    {
        int xff_fields = 0;
        const std::string_view xff = http_last_forwarded_hop(http_request_field(head, "x-forwarded-for", xff_fields));
        if (xff_fields == 1 && !xff.empty())
            client.assign(xff);
    }
    if (client.empty())
        client = "local";
    if (!idp())
    {
        int64_t retry_after = 0;
        const verdict r = check(fields > 1 ? std::string_view("-") : authorization, client, retry_after);
        v.pass = r == verdict::pass;
        if (r == verdict::barred)
        {
            v.status = "429 Too Many Requests";
            v.body = "Too many failed authorizations from this address; try again later.\n";
            v.headers = "Retry-After: " + std::to_string(retry_after) + "\r\n";
        }
        else if (!v.pass)
        {
            v.status = "401 Unauthorized";
            v.body = "Unauthorized\n";
            v.headers = m_challenge;
        }
        return v;
    }

    // A sign-in an idp keeps: the cookie verified here, a browser without one sent to sign in and back, and anything
    // else told 401.
    std::string cookies;
    for (size_t pos = head.find("\r\n"); pos != std::string_view::npos && pos + 2 < head.size();)
    {
        const size_t nl = head.find("\r\n", pos + 2);
        const std::string_view line = head.substr(pos + 2, (nl == std::string_view::npos ? head.size() : nl) - pos - 2);
        pos = nl;
        if (header_name_equals(line, "cookie", 6))
        {
            if (!cookies.empty())
                cookies += "; ";
            cookies.append(http_trim_ows(line.substr(7)));
        }
    }
    if (check_session(cookies, v.sub, v.username, v.email) == verdict::pass)
    {
        v.pass = true;
        return v;
    }
    int accept_fields = 0, proto_fields = 0, host_fields = 0;
    const std::string_view accept = http_request_field(head, "accept", accept_fields);
    // The Host field whole, its port too, which the name a caller keeps for routing has lost.
    const std::string_view whole_host = http_trim_ows(http_request_field(head, "host", host_fields));
    const bool browser = (method == "GET" || method == "HEAD") && accept.find("text/html") != std::string_view::npos &&
                         host_fields == 1 && !host.empty();
    if (browser)
    {
        // The scheme the browser used: this hop's own, or what the entrance in front of it says it was.
        std::string_view scheme = tls ? "https" : "http";
        if (socketley::is_loopback(client) || socketley::is_loopback(peer))
            if (const std::string_view p = http_trim_ows(http_request_field(head, "x-forwarded-proto", proto_fields));
                proto_fields == 1 && (p == "https" || p == "http"))
                scheme = p;
        const bool host_ok = !whole_host.empty() && std::all_of(whole_host.begin(), whole_host.end(), [](char ch) {
            return std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '-' || ch == ':' || ch == '[' ||
                   ch == ']';
        });
        const std::string back = std::string(scheme) + "://" + std::string(host_ok ? whole_host : host) +
                                 std::string(path);
        if (const std::string to = login_url(back); !to.empty())
        {
            v.status = "302 Found";
            v.headers = "Location: " + to + "\r\nCache-Control: no-store\r\n";
            return v;
        }
    }
    v.status = "401 Unauthorized";
    v.body = "Sign in first.\n";
    v.headers = "WWW-Authenticate: Bearer realm=\"" + m_runtime + "\"\r\n";
    return v;
}
