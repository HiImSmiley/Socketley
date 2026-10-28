#include "idp_logic.h"

#include <algorithm>
#include <cctype>
#include <charconv>

#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "../../shared/crypto/jws.h"
#include "../../shared/json/json_doc.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/http/url.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/text_list.h"
#include "../../shared/crypto/mac.h"

namespace socketley::idp
{

namespace
{

bool unreserved(char c)
{
    return socketley::http::url_keeps(static_cast<unsigned char>(c), false);
}

std::vector<std::string_view> words(std::string_view line)
{
    std::vector<std::string_view> out;
    size_t i = 0;
    while (i < line.size())
    {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
            ++i;
        const size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t')
            ++i;
        if (i > start)
            out.push_back(line.substr(start, i - start));
    }
    return out;
}

}   // namespace

bool client::allows(std::string_view redirect) const
{
    for (const auto& r : redirects)
        if (r == redirect)
            return true;
    return false;
}

bool parse_clients(std::string_view text, std::vector<client>& out, std::string& why)
{
    out.clear();
    size_t line_no = 0;
    while (!text.empty())
    {
        ++line_no;
        std::string_view line = take_item(text, '\n');
        // A comment begins at a # that starts a word, so one inside an address is the address's.
        for (size_t h = line.find('#'); h != std::string_view::npos; h = line.find('#', h + 1))
            if (h == 0 || line[h - 1] == ' ' || line[h - 1] == '\t')
            {
                line = line.substr(0, h);
                break;
            }
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        const auto w = words(line);
        if (w.empty())
            continue;
        const std::string where = "line " + std::to_string(line_no) + ": ";
        if (w.size() < 3)
        {
            why = where + "a client is its id, its secret or -, and at least one redirect address, device or ssh";
            return false;
        }
        client c;
        c.id.assign(w[0]);
        for (const char ch : c.id)
            if (!unreserved(ch))
            {
                why = where + "the client id \"" + c.id + "\" may hold only letters, digits and -._~";
                return false;
            }
        if (w[1] != "-")
            c.secret.assign(w[1]);
        for (size_t i = 2; i < w.size(); ++i)
        {
            const std::string_view r = w[i];
            if (r == "device" || r == "ssh")
            {
                (r == "device" ? c.device : c.ssh) = true;
                continue;
            }
            // An http address only on this machine, where nobody can stand between the browser and the client.
            const std::string host = url_host(r);
            const bool local = r.starts_with("http://") && (host == "localhost" || host == "127.0.0.1" || host == "[::1]");
            if (host.empty() || (!r.starts_with("https://") && !local) || r.find('#') != std::string_view::npos)
            {
                why = where + "the redirect \"" + std::string(r) +
                      "\" is no https address (http only for localhost) without a fragment";
                return false;
            }
            c.redirects.emplace_back(r);
        }
        for (const auto& o : out)
            if (o.id == c.id)
            {
                why = where + "the client id \"" + c.id + "\" is named twice";
                return false;
            }
        out.push_back(std::move(c));
    }
    return true;
}

namespace
{

// Consonants alone, so no code spells a word, and none of the letters a person mixes up with a digit.
constexpr std::string_view user_code_letters = "BCDFGHJKLMNPQRSTVWXZ";

}   // namespace

std::string make_user_code()
{
    unsigned char raw[8];
    if (!socketley::random_bytes(raw, sizeof raw))
        return {};
    std::string out;
    for (size_t i = 0; i < sizeof raw; ++i)
    {
        if (i == 4)
            out += '-';
        // 256 is not a multiple of 20, and the bias of 16 in 256 is nothing a guess at a ten-minute code can use.
        out += user_code_letters[raw[i] % user_code_letters.size()];
    }
    return out;
}

std::string normal_user_code(std::string_view typed)
{
    std::string out;
    for (const char ch : typed)
    {
        if (ch == '-' || ch == ' ')
            continue;
        const char up = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        if (user_code_letters.find(up) == std::string_view::npos || out.size() == 8)
            return {};
        out += up;
    }
    return out.size() == 8 ? out : std::string();
}

uint32_t user_code_shard(std::string_view normal, uint32_t shards)
{
    uint32_t h = 2166136261u;
    for (const char ch : normal)
        h = (h ^ static_cast<unsigned char>(ch)) * 16777619u;
    return shards ? h % shards : 0;
}

params parse_form(std::string_view in)
{
    // A pair whose escape spells nothing is left out rather than read as something else.
    params out;
    socketley::http::for_each_pair(in, [&out](std::string_view name, std::string_view value) {
        std::string k, v;
        if (socketley::http::percent_decode(name, k, true) && socketley::http::percent_decode(value, v, true))
            out.emplace_back(std::move(k), std::move(v));
    });
    return out;
}

std::string_view param(const params& p, std::string_view name)
{
    for (const auto& [k, v] : p)
        if (k == name)
            return v;
    return {};
}

std::string url_encode(std::string_view in)
{
    return socketley::http::url_encode(in, false);
}

std::string html_escape(std::string_view in)
{
    std::string out;
    out.reserve(in.size());
    for (const char c : in)
        switch (c)
        {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default:   out += c;
        }
    return out;
}

bool pkce_matches(std::string_view verifier, std::string_view challenge)
{
    if (verifier.size() < 43 || verifier.size() > 128 || challenge.empty())
        return false;
    for (const char c : verifier)
        if (!unreserved(c))
            return false;
    return base64url::encode(socketley::jws::sha256(verifier)) == challenge;
}

bool has_scope(std::string_view scope, std::string_view want)
{
    for (const auto w : words(scope))
        if (w == want)
            return true;
    return false;
}

std::string url_host(std::string_view url)
{
    size_t at = 0;
    if (url.starts_with("https://"))
        at = 8;
    else if (url.starts_with("http://"))
        at = 7;
    else
        return {};
    const std::string_view rest = url.substr(at);
    const size_t end = rest.find_first_of("/?#");
    std::string_view authority = rest.substr(0, end);
    // Credentials in an address are a way to make it read as another host.
    if (authority.find('@') != std::string_view::npos || authority.empty())
        return {};
    // A browser reads a backslash as a slash and drops tabs, so a host is held to the letters a name or address has.
    for (const char c : authority)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_' && c != ':' && c != '[' &&
            c != ']')
            return {};
    std::string_view host = authority;
    if (host.front() == '[')
    {
        const size_t close = host.find(']');
        if (close == std::string_view::npos)
            return {};
        // Only a port may follow the literal, or "[::1]evil.example" would read as [::1].
        if (close + 1 < host.size() && host[close + 1] != ':')
            return {};
        host = host.substr(0, close + 1);
    }
    else if (const size_t colon = host.rfind(':'); colon != std::string_view::npos)
        host = host.substr(0, colon);
    std::string out;
    for (const char c : host)
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool return_allowed(std::string_view url, std::string_view issuer, std::string_view cookie_domain)
{
    // A browser drops tabs and line breaks from an address, so "/\t/evil.example" would leave as "//evil.example".
    for (const char c : url)
        if (static_cast<unsigned char>(c) <= 0x20 || c == 0x7f)
            return false;
    // A path on this provider itself.
    if (url.starts_with("/") && !url.starts_with("//") && url.find('\\') == std::string_view::npos)
        return true;
    if (!url.starts_with("https://") && !(issuer.starts_with("http://") && url.starts_with("http://")))
        return false;
    const std::string host = url_host(url);
    if (host.empty())
        return false;
    if (host == url_host(issuer))
        return true;
    if (cookie_domain.empty())
        return false;
    std::string domain;
    for (const char c : cookie_domain)
        domain += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (domain.starts_with("."))
        domain.erase(0, 1);
    return host == domain || (host.size() > domain.size() && host.ends_with(domain) &&
                              host[host.size() - domain.size() - 1] == '.');
}

std::string email_problem(std::string_view email)
{
    if (email.empty())
        return {};
    const size_t at = email.find('@');
    if (email.size() > 254 || at == std::string_view::npos || at == 0 || at > 64 || at + 1 == email.size())
        return "an e-mail address is a name, an @ and a domain, at most 254 characters";
    const std::string_view local = email.substr(0, at);
    for (const char c : local)
        if (!std::isalnum(static_cast<unsigned char>(c)) && std::string_view("!#$%&'*+-/=?^_`{|}~.").find(c) == std::string_view::npos)
            return "an e-mail address's name holds letters, digits and !#$%&'*+-/=?^_`{|}~. only";
    if (local.front() == '.' || local.back() == '.' || local.find("..") != std::string_view::npos)
        return "an e-mail address's name neither begins nor ends with a dot, nor has two together";
    for (std::string_view rest = email.substr(at + 1);;)
    {
        const size_t dot = rest.find('.');
        const std::string_view label = rest.substr(0, dot);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-' ||
            std::any_of(label.begin(), label.end(), [](char c) { return !std::isalnum(static_cast<unsigned char>(c)) && c != '-'; }))
            return "an e-mail address's domain is names of letters, digits and dashes between dots";
        if (dot == std::string_view::npos)
            return {};
        rest.remove_prefix(dot + 1);
    }
}

bool form_origin_allowed(std::string_view origin, std::string_view issuer, std::string_view cookie_domain)
{
    // "null", what a browser sends for a page that hides its origin, is no page of these.
    return origin.empty() ||
           ((origin.starts_with("https://") || origin.starts_with("http://")) && return_allowed(origin, issuer, cookie_domain));
}

std::string sign_token(EVP_PKEY* key, std::string_view kid, std::string_view typ, std::string_view body)
{
    std::string header;
    header.reserve(kid.size() + typ.size() + 40);
    header.append("{\"alg\":\"ES256\",\"kid\":").append(socketley::json::quote(kid)).append(",\"typ\":").append(socketley::json::quote(typ));
    header += '}';
    std::string payload;
    payload.reserve(body.size() + 2);
    payload.append("{").append(body).append("}");
    return socketley::jws::compact(key, header, payload);
}

namespace
{

// A token's claims when its header names `want_alg`, `kid` and `typ`, `holds` takes its signature over the part
// before it, it was issued by `issuer` and has not expired at `now`.
template <class Holds>
bool read_token(std::string_view want_alg, std::string_view kid, std::string_view typ, std::string_view issuer,
                std::string_view token, int64_t now, Holds&& holds, claims& out, std::string& why)
{
    using socketley::json::json_reader;
    using socketley::json::jvalue;
    out.clear();
    const size_t d1 = token.find('.');
    const size_t d2 = d1 == std::string_view::npos ? d1 : token.find('.', d1 + 1);
    if (d2 == std::string_view::npos || token.find('.', d2 + 1) != std::string_view::npos)
    {
        why = "not a signed token";
        return false;
    }
    std::string header, payload, sig;
    if (!base64url::decode(token.substr(0, d1), header) ||
        !base64url::decode(token.substr(d1 + 1, d2 - d1 - 1), payload) ||
        !base64url::decode(token.substr(d2 + 1), sig))
    {
        why = "not base64url";
        return false;
    }
    jvalue h;
    if (!json_reader(header).document(h))
    {
        why = "the header is not JSON";
        return false;
    }
    std::string alg, hkid, htyp;
    for (const auto& [k, v] : h.members)
    {
        if (v.k != jvalue::kind::string)
            continue;
        if (k == "alg") alg = v.s;
        else if (k == "kid") hkid = v.s;
        else if (k == "typ") htyp = v.s;
    }
    // The algorithm is this provider's and never the token's choice.
    if (alg != want_alg || hkid != kid || htyp != typ)
    {
        why = "not one of this provider's " + std::string(typ) + " tokens";
        return false;
    }
    if (!holds(token.substr(0, d2), sig))
    {
        why = "the signature does not hold";
        return false;
    }
    jvalue p;
    if (!json_reader(payload).document(p))
    {
        why = "the claims are not JSON";
        return false;
    }
    for (const auto& [k, v] : p.members)
        switch (v.k)
        {
            case jvalue::kind::string:
            case jvalue::kind::number:  out[k] = v.s; break;
            case jvalue::kind::boolean: out[k] = v.b ? "true" : "false"; break;
            default: break;
        }
    const auto iss = out.find("iss");
    if (iss == out.end() || iss->second != issuer)
    {
        why = "issued by someone else";
        return false;
    }
    int64_t exp = 0;
    const auto e = out.find("exp");
    if (e == out.end() || std::from_chars(e->second.data(), e->second.data() + e->second.size(), exp).ec != std::errc{})
    {
        why = "it has no expiry";
        return false;
    }
    if (exp <= now)
    {
        why = "it has expired";
        return false;
    }
    return true;
}

// The MAC this thread made last and its key, kept since making one looks HMAC and SHA-256 up by name every time.
struct mac_context
{
    std::string key;
    EVP_MAC_CTX* ctx{nullptr};
    ~mac_context()
    {
        EVP_MAC_CTX_free(ctx);
        OPENSSL_cleanse(key.data(), key.size());
    }
};
thread_local mac_context t_mac;

std::string hs256(std::string_view secret, std::string_view input)
{
    if (!t_mac.ctx)
    {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        t_mac.ctx = mac ? EVP_MAC_CTX_new(mac) : nullptr;
        EVP_MAC_free(mac);
        if (!t_mac.ctx)
            return {};
    }
    bool ready = false;
    if (t_mac.key == secret && !t_mac.key.empty())
        ready = EVP_MAC_init(t_mac.ctx, nullptr, 0, nullptr) == 1;
    else
    {
        char digest[] = "SHA256";
        const OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
                                     OSSL_PARAM_construct_end()};
        OPENSSL_cleanse(t_mac.key.data(), t_mac.key.size());
        t_mac.key.clear();
        ready = EVP_MAC_init(t_mac.ctx, reinterpret_cast<const unsigned char*>(secret.data()), secret.size(), params) == 1;
        if (ready)
            t_mac.key.assign(secret);
    }
    unsigned char md[32];
    size_t n = 0;
    if (!ready || EVP_MAC_update(t_mac.ctx, reinterpret_cast<const unsigned char*>(input.data()), input.size()) != 1 ||
        EVP_MAC_final(t_mac.ctx, md, &n, sizeof md) != 1 || n != sizeof md)
    {
        t_mac.key.clear();
        return {};
    }
    return std::string(reinterpret_cast<const char*>(md), n);
}

}   // namespace

bool verify_token(EVP_PKEY* key, std::string_view kid, std::string_view typ, std::string_view issuer,
                  std::string_view token, int64_t now, claims& out, std::string& why)
{
    return read_token("ES256", kid, typ, issuer, token, now,
                      [key](std::string_view input, std::string_view sig) {
                          return socketley::jws::es256_verify(key, input, sig);
                      },
                      out, why);
}

bool verified_tokens::verify(EVP_PKEY* key, std::string_view kid, std::string_view typ, std::string_view issuer,
                             std::string_view token, int64_t now, claims& out, std::string& why)
{
    std::string context = std::string(kid) + "\n" + std::string(typ) + "\n" + std::string(issuer);
    if (const auto it = m_seen.find(token); it != m_seen.end() && it->second.context == context)
    {
        if (it->second.expires > now)
        {
            out = it->second.c;
            return true;
        }
        m_seen.erase(it);
    }
    if (!verify_token(key, kid, typ, issuer, token, now, out, why))
        return false;
    if (m_seen.size() >= 4096)
    {
        std::erase_if(m_seen, [now](const auto& kv) { return kv.second.expires <= now; });
        if (m_seen.size() >= 4096)
            m_seen.clear();
    }
    int64_t exp = 0;
    const std::string& e = out.find("exp")->second;
    std::from_chars(e.data(), e.data() + e.size(), exp);
    m_seen.insert_or_assign(std::string(token), entry{std::move(context), out, exp});
    return true;
}

std::string token_secret(EVP_PKEY* key)
{
    BIGNUM* priv = nullptr;
    if (EVP_PKEY_get_bn_param(key, "priv", &priv) != 1)
        return {};
    std::string scalar(32, '\0');
    const bool ok = BN_bn2binpad(priv, reinterpret_cast<unsigned char*>(scalar.data()), 32) == 32;
    BN_clear_free(priv);
    const std::string secret = ok ? hs256(scalar, "socketley idp: tokens only this provider reads") : std::string();
    OPENSSL_cleanse(scalar.data(), scalar.size());
    return secret;
}

std::string sign_secret_token(std::string_view secret, std::string_view typ, std::string_view body)
{
    const std::string header = "{\"alg\":\"HS256\",\"kid\":\"self\",\"typ\":" + socketley::json::quote(typ) + "}";
    std::string payload;
    payload.reserve(body.size() + 2);
    payload.append("{").append(body).append("}");
    std::string out = base64url::encode(header);
    out += '.';
    out += base64url::encode(payload);
    const std::string mac = hs256(secret, out);
    out += '.';
    out += base64url::encode(mac);
    return out;
}

bool verify_secret_token(std::string_view secret, std::string_view typ, std::string_view issuer, std::string_view token,
                         int64_t now, claims& out, std::string& why)
{
    return read_token("HS256", "self", typ, issuer, token, now,
                      [secret](std::string_view input, std::string_view sig) {
                          const std::string want = hs256(secret, input);
                          return !want.empty() && crypto::secure_equal(sig, want);
                      },
                      out, why);
}

std::string address_key(std::string_view ip)
{
    const std::string text(ip);
    unsigned char a[16];
    if (text.find(':') == std::string::npos || ::inet_pton(AF_INET6, text.c_str(), a) != 1)
        return text;
    // An IPv4 address written as IPv6 is the IPv4 address.
    static constexpr unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    char buf[INET6_ADDRSTRLEN] = {};
    if (std::equal(mapped, mapped + 12, a))
        return ::inet_ntop(AF_INET, a + 12, buf, sizeof buf) ? std::string(buf) : text;
    std::fill(a + 8, a + 16, 0);
    return ::inet_ntop(AF_INET6, a, buf, sizeof buf) ? std::string(buf) + "/64" : text;
}

attempt_limits::entry& attempt_limits::fresh(const std::string& key, int64_t now)
{
    entry& e = m_keys[key];
    std::erase_if(e.at, [now](int64_t t) { return now - t > window_s; });
    return e;
}

bool attempt_limits::barred(const std::string& key, int64_t now, int limit)
{
    if (!m_keys.contains(key))
        return false;
    const entry& e = fresh(key, now);
    return static_cast<int64_t>(e.at.size()) + e.in_flight >= limit;
}

int64_t attempt_limits::wait(const std::string& key, int64_t now, int free)
{
    if (!m_keys.contains(key))
        return 0;
    const entry& e = fresh(key, now);
    const int64_t n = static_cast<int64_t>(e.at.size()) + e.in_flight;
    if (n < free)
        return 0;
    const int64_t delay = std::min<int64_t>(300, int64_t{30} << std::min<int64_t>(n - free, 4));
    // One still being checked is waited for as a failure would be, so a burst sent together gets one try.
    if (e.in_flight > 0 || e.at.empty())
        return delay;
    const int64_t last = *std::max_element(e.at.begin(), e.at.end());
    return std::max<int64_t>(0, last + delay - now);
}

void attempt_limits::end(const std::string& key)
{
    const auto it = m_keys.find(key);
    if (it != m_keys.end() && it->second.in_flight > 0)
        --it->second.in_flight;
}

void attempt_limits::failed(const std::string& key, int64_t at)
{
    m_keys[key].at.push_back(at);
}

void attempt_limits::age(int64_t now)
{
    // A loop rather than erase_if, whose predicate GCC 12's library hands each entry as const.
    for (auto it = m_keys.begin(); it != m_keys.end();)
    {
        std::erase_if(it->second.at, [now](int64_t t) { return now - t > window_s; });
        it = it->second.at.empty() && it->second.in_flight == 0 ? m_keys.erase(it) : std::next(it);
    }
}

int64_t issued_ms(const claims& c)
{
    const auto read = [&](std::string_view k) {
        int64_t v = 0;
        if (const auto it = c.find(k); it != c.end())
            std::from_chars(it->second.data(), it->second.data() + it->second.size(), v);
        return v;
    };
    const int64_t ms = read("iat_ms");
    return ms ? ms : read("iat") * 1000;
}

void append_standing(std::string& out, std::string_view id, const standing& s)
{
    out.append(id).append(" ").append(std::to_string(s.revoked_before)).append(" ");
    const size_t flags = out.size();
    if (s.admin)
        out += 'a';
    if (s.disabled)
        out += 'd';
    if (s.reset)
        out += 'r';
    if (out.size() == flags)
        out += '-';
    out += '\n';
}

bool parse_standing(std::string_view text, standing_table& out)
{
    if (!text.starts_with(standing_format))
        return false;
    text.remove_prefix(standing_format.size());
    standing_table read;
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        // A line cut short is a file being written, which a rename never shows, so the whole is refused.
        if (nl == std::string_view::npos)
            return false;
        const std::string_view line = text.substr(0, nl);
        text.remove_prefix(nl + 1);
        const size_t a = line.find(' ');
        const size_t b = a == std::string_view::npos ? a : line.find(' ', a + 1);
        if (b == std::string_view::npos || a == 0)
            return false;
        standing s;
        const auto [end, ec] = std::from_chars(line.data() + a + 1, line.data() + b, s.revoked_before);
        if (ec != std::errc{} || end != line.data() + b)
            return false;
        for (const char f : line.substr(b + 1))
        {
            if (f == 'a')
                s.admin = true;
            else if (f == 'd')
                s.disabled = true;
            else if (f == 'r')
                s.reset = true;
            else if (f != '-')
                return false;
        }
        read.insert_or_assign(std::string(line.substr(0, a)), s);
    }
    out = std::move(read);
    return true;
}

}   // namespace socketley::idp
