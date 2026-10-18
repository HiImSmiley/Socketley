#include "idp_logic.h"

#include <cctype>
#include <charconv>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "../../shared/crypto/jws.h"
#include "../../shared/json/json_doc.h"
#include "../../shared/json/json_escape.h"

namespace socketley::idp
{

namespace
{

bool unreserved(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.' || c == '_' || c == '~';
}

int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool form_decode(std::string_view in, std::string& out)
{
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        const char c = in[i];
        if (c == '+')
            out += ' ';
        else if (c == '%')
        {
            if (i + 2 >= in.size())
                return false;
            const int hi = hex_value(in[i + 1]), lo = hex_value(in[i + 2]);
            if (hi < 0 || lo < 0)
                return false;
            out += static_cast<char>(hi * 16 + lo);
            i += 2;
        }
        else
            out += c;
    }
    return true;
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
        const size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
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
            why = where + "a client is its id, its secret or -, and at least one redirect address";
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

params parse_form(std::string_view in)
{
    params out;
    while (!in.empty())
    {
        const size_t amp = in.find('&');
        const std::string_view pair = in.substr(0, amp);
        in = amp == std::string_view::npos ? std::string_view{} : in.substr(amp + 1);
        if (pair.empty())
            continue;
        const size_t eq = pair.find('=');
        std::string k, v;
        if (!form_decode(pair.substr(0, eq), k) ||
            !form_decode(eq == std::string_view::npos ? std::string_view{} : pair.substr(eq + 1), v))
            continue;
        out.emplace_back(std::move(k), std::move(v));
    }
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
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (const char c : in)
    {
        if (unreserved(c))
            out += c;
        else
        {
            out += '%';
            out += hex[static_cast<unsigned char>(c) >> 4];
            out += hex[static_cast<unsigned char>(c) & 15];
        }
    }
    return out;
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
    return socketley::jws::b64url(socketley::jws::sha256(verifier)) == challenge;
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
    std::string_view host = authority;
    if (host.front() == '[')
    {
        const size_t close = host.find(']');
        if (close == std::string_view::npos)
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
    if (!socketley::jws::b64url_decode(token.substr(0, d1), header) ||
        !socketley::jws::b64url_decode(token.substr(d1 + 1, d2 - d1 - 1), payload) ||
        !socketley::jws::b64url_decode(token.substr(d2 + 1), sig))
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
    std::string out = socketley::jws::b64url(header);
    out += '.';
    out += socketley::jws::b64url(payload);
    const std::string mac = hs256(secret, out);
    out += '.';
    out += socketley::jws::b64url(mac);
    return out;
}

bool verify_secret_token(std::string_view secret, std::string_view typ, std::string_view issuer, std::string_view token,
                         int64_t now, claims& out, std::string& why)
{
    return read_token("HS256", "self", typ, issuer, token, now,
                      [secret](std::string_view input, std::string_view sig) {
                          const std::string want = hs256(secret, input);
                          return !want.empty() && sig.size() == want.size() &&
                                 CRYPTO_memcmp(sig.data(), want.data(), want.size()) == 0;
                      },
                      out, why);
}

}   // namespace socketley::idp
