#include "mail_dkim.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <unordered_map>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "mail_compose.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"

namespace socketley::mail::dkim
{

namespace
{

bool wsp(char c)
{
    return c == ' ' || c == '\t';
}

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (wsp(s.front()) || s.front() == '\r' || s.front() == '\n'))
        s.remove_prefix(1);
    while (!s.empty() && (wsp(s.back()) || s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

std::string sha256_b64(std::string_view data)
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md);
    return socketley::base64::encode(std::string_view(reinterpret_cast<char*>(md), sizeof md));
}

// Every space, tab and line break taken out, as a tag's base64 is compared.
std::string no_space(std::string_view s)
{
    std::string out;
    for (const char c : s)
        if (!wsp(c) && c != '\r' && c != '\n')
            out += c;
    return out;
}

// The tags of a signature or a key record, `name=value; ...`.
std::vector<std::pair<std::string, std::string>> tags(std::string_view v)
{
    std::vector<std::pair<std::string, std::string>> out;
    while (!v.empty())
    {
        const size_t semi = v.find(';');
        const std::string_view one = trim(v.substr(0, semi));
        v = semi == std::string_view::npos ? std::string_view{} : v.substr(semi + 1);
        const size_t eq = one.find('=');
        if (eq == std::string_view::npos)
            continue;
        out.emplace_back(std::string(trim(one.substr(0, eq))), std::string(trim(one.substr(eq + 1))));
    }
    return out;
}

std::string simple_header(std::string_view name, std::string_view value)
{
    return std::string(name) + ":" + std::string(value);
}

}   // namespace

std::string without_b(std::string_view raw)
{
    std::string out(raw);
    size_t at = 0;
    while (at < out.size())
    {
        size_t t = at;
        while (t < out.size() && (wsp(out[t]) || out[t] == '\r' || out[t] == '\n'))
            ++t;
        const size_t semi = out.find(';', t);
        const size_t end = semi == std::string::npos ? out.size() : semi;
        size_t eq = out.find('=', t);
        if (eq != std::string::npos && eq < end)
        {
            std::string_view name = trim(std::string_view(out).substr(t, eq - t));
            if (name == "b")
            {
                out.erase(eq + 1, end - eq - 1);
                return out;
            }
        }
        at = end + 1;
    }
    return out;
}


key_ptr load_or_make(const std::string& path, std::string& why, bool ed25519)
{
    std::string pem;
    if (socketley::read_file(path, pem, {.missing_ok = true}, nullptr) && !pem.empty())
        return load_pem(path, pem, why);
    if (!make_key(path, why, ed25519))
        return nullptr;
    // What is at the path now, this one's key or the one another shard linked there first.
    if (!socketley::read_file(path, pem, {}, &why) || pem.empty())
        return nullptr;
    return load_pem(path, pem, why);
}

key_ptr load_pem(const std::string& path, const std::string& pem, std::string& why)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* k = bio ? PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr) : nullptr;
    if (bio)
        BIO_free(bio);
    if (!k)
    {
        why = path + " holds no private key";
        return nullptr;
    }
    return key_ptr(k, EVP_PKEY_free);
}

bool make_key(const std::string& path, std::string& why, bool ed25519)
{
    EVP_PKEY* k = ed25519 ? EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")
                          : EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(2048));
    if (!k)
    {
        why = "no DKIM key could be made";
        return false;
    }
    key_ptr key(k, EVP_PKEY_free);
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_PrivateKey(bio, k, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        if (bio)
            BIO_free(bio);
        why = "the DKIM key could not be written";
        return false;
    }
    char* data = nullptr;
    const long n = BIO_get_mem_data(bio, &data);
    // Linked into place, which fails where a shard starting beside this one put its key first; that one is kept.
    const std::string tmp = path + "." + std::to_string(::getpid()) + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const bool ok = fd >= 0 && socketley::write_all(fd, data, static_cast<size_t>(n)) && ::fsync(fd) == 0;
    if (fd >= 0)
        ::close(fd);
    BIO_free(bio);
    const bool linked = ok && (::link(tmp.c_str(), path.c_str()) == 0 || errno == EEXIST);
    ::unlink(tmp.c_str());
    if (!linked)
        why = path + " cannot be written";
    return linked;
}

std::string algorithm_of(EVP_PKEY* key)
{
    return EVP_PKEY_get_base_id(key) == EVP_PKEY_ED25519 ? "ed25519-sha256" : "rsa-sha256";
}

std::string public_record(EVP_PKEY* key)
{
    // An Ed25519 key is published as its 32 bytes, not as a SubjectPublicKeyInfo (RFC 8463 4).
    if (EVP_PKEY_get_base_id(key) == EVP_PKEY_ED25519)
    {
        unsigned char raw[32];
        size_t n = sizeof raw;
        if (EVP_PKEY_get_raw_public_key(key, raw, &n) != 1)
            return {};
        return "v=DKIM1; k=ed25519; p=" + socketley::base64::encode(std::string_view(reinterpret_cast<char*>(raw), n));
    }
    unsigned char* der = nullptr;
    const int n = i2d_PUBKEY(key, &der);
    if (n <= 0)
        return {};
    std::string out = "v=DKIM1; k=rsa; p=" +
                      socketley::base64::encode(std::string_view(reinterpret_cast<char*>(der), static_cast<size_t>(n)));
    OPENSSL_free(der);
    return out;
}

std::string relaxed_header(std::string_view name, std::string_view value)
{
    std::string out = lower(trim(name));
    out += ':';
    bool space = false;
    std::string v;
    for (size_t i = 0; i < value.size(); ++i)
    {
        const char c = value[i];
        if (c == '\r' || c == '\n')
            continue;
        if (wsp(c))
        {
            space = true;
            continue;
        }
        if (space && !v.empty())
            v += ' ';
        space = false;
        v += c;
    }
    out += v;
    return out;
}

std::string relaxed_body(std::string_view body)
{
    std::string out;
    out.reserve(body.size());
    size_t at = 0;
    size_t keep = 0;   // the size of what ends at the last line that was not empty
    while (at < body.size())
    {
        size_t nl = body.find("\r\n", at);
        const bool last = nl == std::string_view::npos;
        const std::string_view line = body.substr(at, last ? body.size() - at : nl - at);
        at = last ? body.size() : nl + 2;
        std::string l;
        bool space = false;
        for (const char c : line)
        {
            if (wsp(c))
            {
                space = true;
                continue;
            }
            if (space)
                l += ' ';
            space = false;
            l += c;
        }
        out += l;
        out += "\r\n";
        if (!l.empty())
            keep = out.size();
    }
    out.resize(keep);
    return out;
}

std::string simple_body(std::string_view body)
{
    std::string out(body);
    if (!out.empty() && !out.ends_with("\r\n"))
        out += "\r\n";
    while (out.size() >= 4 && out.ends_with("\r\n\r\n"))
        out.resize(out.size() - 2);
    if (out.empty())
        out = "\r\n";
    return out;
}

std::string sign_bytes(EVP_PKEY* key, std::string_view data)
{
    // Ed25519 signs the SHA-256 of what RSA would sign, with no digest of its own (RFC 8463 3).
    const bool ed = EVP_PKEY_get_base_id(key) == EVP_PKEY_ED25519;
    unsigned char md[SHA256_DIGEST_LENGTH];
    if (ed)
    {
        SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md);
        data = std::string_view(reinterpret_cast<char*>(md), sizeof md);
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t len = 0;
    std::string sig;
    if (ctx && EVP_DigestSignInit(ctx, nullptr, ed ? nullptr : EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestSign(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1)
    {
        sig.resize(len);
        if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(sig.data()), &len,
                           reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1)
            sig.resize(len);
        else
            sig.clear();
    }
    if (ctx)
        EVP_MD_CTX_free(ctx);
    return sig.empty() ? std::string() : socketley::base64::encode(sig);
}

std::string body_hash(std::string_view message)
{
    return sha256_b64(relaxed_body(message.substr(header_block(message).size())));
}

std::string sign(std::string_view message, std::string_view domain, std::string_view selector, EVP_PKEY* key,
                 int64_t now_s, std::string_view header, std::string_view first_tags, std::string_view body_hash_given)
{
    const std::string_view head = header_block(message);
    const std::string_view body = message.substr(head.size());
    const auto headers = split_headers(head);
    static constexpr std::string_view wanted[] = {"from",        "reply-to",   "subject",      "date",
                                                  "to",          "cc",         "message-id",   "in-reply-to",
                                                  "references",  "mime-version", "content-type", "content-transfer-encoding",
                                                  "list-unsubscribe"};
    std::string h;
    std::string data;
    for (const auto name : wanted)
    {
        // The last of a name, the one a reader is shown.
        for (auto it = headers.rbegin(); it != headers.rend(); ++it)
            if (socketley::ascii::iequals(trim(it->first), name))
            {
                h += (h.empty() ? "" : ":") + std::string(name);
                data += relaxed_header(it->first, it->second) + "\r\n";
                break;
            }
    }
    // From named once more than it is there, so a second From added on the way breaks the signature.
    h += ":from";
    const std::string bh = body_hash_given.empty() ? sha256_b64(relaxed_body(body)) : std::string(body_hash_given);
    // A DKIM-Signature says its version first, whatever tags come with it; ARC's signature has none.
    std::string value = " " + std::string(header == "DKIM-Signature" ? "v=1; " : "") + std::string(first_tags) + "a=" +
                        algorithm_of(key) + "; c=relaxed/relaxed; d=" + std::string(domain) + "; s=" +
                        std::string(selector) + ";\r\n\tt=" + std::to_string(now_s) + "; h=" + h + ";\r\n\tbh=" + bh +
                        ";\r\n\tb=";
    data += relaxed_header(header, value);
    const std::string b = sign_bytes(key, data);
    if (b.empty())
        return {};
    for (size_t at = 0; at < b.size(); at += 72)
        value += (at ? "\r\n\t " : "") + b.substr(at, 72);
    return std::string(header) + ":" + value + "\r\n";
}

bool ldh_name(std::string_view name)
{
    if (name.empty() || name.size() > 253)
        return false;
    for (size_t at = 0; at <= name.size();)
    {
        const size_t dot = std::min(name.find('.', at), name.size());
        const std::string_view label = name.substr(at, dot - at);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-')
            return false;
        for (const char c : label)
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
                return false;
        if (dot == name.size())
            break;
        at = dot + 1;
    }
    return true;
}

std::vector<signature> signatures(std::string_view message, std::string_view header)
{
    std::vector<signature> out;
    const auto headers = split_headers(header_block(message));
    for (size_t i = 0; i < headers.size(); ++i)
    {
        if (!socketley::ascii::iequals(trim(headers[i].first), header))
            continue;
        signature s;
        s.raw = std::string(headers[i].second);
        s.index = i;
        for (const auto& [k, v] : tags(s.raw))
        {
            if (k == "v") s.v = v;
            else if (k == "a") s.a = v;
            else if (k == "d") s.d = lower(v);
            else if (k == "s") s.s = v;
            else if (k == "c") s.c = v;
            else if (k == "h") s.h = no_space(v);
            else if (k == "bh") s.bh = no_space(v);
            else if (k == "b") s.b = no_space(v);
            else if (k == "i") s.i = v;
            else if (k == "l") s.l = v;
            else if (k == "t") s.t = v;
            else if (k == "x") s.x = v;
        }
        // A domain or selector that is no name would be a DNS name and a header of a sender's making.
        if (ldh_name(s.d) && ldh_name(s.s))
            out.push_back(std::move(s));
    }
    return out;
}

bool header_data(const std::vector<std::pair<std::string_view, std::string_view>>& headers, std::string_view h,
                 bool relaxed, size_t skip, std::string& data, bool& from_signed)
{
    // Each name's places from the bottom, so a name of h= costs one step however many headers there are.
    std::unordered_map<std::string, std::vector<size_t>> places;
    for (size_t i = 0; i < headers.size(); ++i)
        if (i != skip)
            places[lower(trim(headers[i].first))].push_back(i);
    size_t names = 0;
    while (!h.empty())
    {
        const size_t colon = h.find(':');
        const std::string name = lower(trim(h.substr(0, colon)));
        h = colon == std::string_view::npos ? std::string_view{} : h.substr(colon + 1);
        if (++names > 256)
            return false;
        from_signed = from_signed || name == "from";
        const auto it = places.find(name);
        if (it == places.end() || it->second.empty())
            continue;
        const size_t i = it->second.back();
        it->second.pop_back();
        data += (relaxed ? relaxed_header(headers[i].first, headers[i].second)
                         : simple_header(headers[i].first, headers[i].second)) +
                "\r\n";
    }
    return true;
}

result verify_bytes(std::string_view record, std::string_view algorithm, std::string_view data, std::string_view b64,
                    std::string* why)
{
    const auto fail = [&](result r, const char* w) {
        if (why)
            *why = w;
        return r;
    };
    const bool ed = algorithm == "ed25519-sha256";
    if (!ed && algorithm != "rsa-sha256")
        return fail(result::permerror, "an algorithm other than rsa-sha256 and ed25519-sha256");
    if (record.empty())
        return fail(result::permerror, "no key record for the selector");
    std::string p;
    std::string k = "rsa";
    for (const auto& [name, v] : tags(record))
        if (name == "p")
            p = no_space(v);
        else if (name == "k")
            k = lower(v);
    if (p.empty())
        return fail(result::fail, "the key is revoked");
    if (k != (ed ? "ed25519" : "rsa"))
        return fail(result::permerror, "a key not of the signature's algorithm");
    std::string der, sig;
    if (!socketley::base64::decode(p, der) || !socketley::base64::decode(b64, sig))
        return fail(result::permerror, "base64 that does not decode");
    EVP_PKEY* pub = nullptr;
    if (ed)
        pub = der.size() == 32 ? EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                              reinterpret_cast<const unsigned char*>(der.data()), 32)
                               : nullptr;
    else
    {
        const auto* q = reinterpret_cast<const unsigned char*>(der.data());
        pub = d2i_PUBKEY(nullptr, &q, static_cast<long>(der.size()));
    }
    if (!pub)
        return fail(result::permerror, "a public key that does not parse");
    // RSA under 1024 bits is too weak to say who signed (RFC 8301 3.2).
    if (!ed && (EVP_PKEY_get_base_id(pub) != EVP_PKEY_RSA || EVP_PKEY_get_bits(pub) < 1024))
    {
        EVP_PKEY_free(pub);
        return fail(result::permerror, "an RSA key shorter than 1024 bits");
    }
    unsigned char md[SHA256_DIGEST_LENGTH];
    if (ed)
    {
        SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md);
        data = std::string_view(reinterpret_cast<char*>(md), sizeof md);
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, ed ? nullptr : EVP_sha256(), nullptr, pub) == 1 &&
                    EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(sig.data()), sig.size(),
                                     reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
    if (ctx)
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pub);
    return ok ? result::pass : fail(result::fail, "the signature does not verify");
}

result verify(std::string_view message, const signature& sig, std::string_view record, int64_t now_s,
              std::string* why, bodies* cache)
{
    const auto fail = [&](result r, const char* w) {
        if (why)
            *why = w;
        return r;
    };
    if (sig.v != "1" || sig.h.empty() || sig.bh.empty() || sig.b.empty())
        return fail(result::permerror, "a tag the signature needs is missing");
    if (sig.a != "rsa-sha256" && sig.a != "ed25519-sha256")
        return fail(result::permerror, "an algorithm other than rsa-sha256 and ed25519-sha256");
    if (!sig.x.empty() && std::atoll(sig.x.c_str()) < now_s)
        return fail(result::fail, "the signature has expired");
    std::string hc = "simple", bc = "simple";
    if (!sig.c.empty())
    {
        const size_t slash = sig.c.find('/');
        hc = sig.c.substr(0, slash);
        if (slash != std::string::npos)
            bc = sig.c.substr(slash + 1);
    }
    if ((hc != "simple" && hc != "relaxed") || (bc != "simple" && bc != "relaxed"))
        return fail(result::permerror, "an unknown canonicalization");
    if (record.empty())
        return fail(result::permerror, "no key record for the selector");
    const std::string_view head = header_block(message);
    const std::string_view body = message.substr(head.size());
    bodies own;
    bodies& b = cache ? *cache : own;
    const bool relaxed_body_wanted = bc == "relaxed";
    if (relaxed_body_wanted && !b.have_relaxed)
    {
        b.relaxed = relaxed_body(body);
        b.have_relaxed = true;
    }
    if (!relaxed_body_wanted && !b.have_simple)
    {
        b.simple = simple_body(body);
        b.have_simple = true;
    }
    std::string_view canon = relaxed_body_wanted ? b.relaxed : b.simple;
    bool partial = false;
    if (!sig.l.empty())
    {
        const auto l = static_cast<size_t>(std::atoll(sig.l.c_str()));
        if (l > canon.size())
            return fail(result::permerror, "l= is longer than the body");
        partial = l < canon.size();
        canon = canon.substr(0, l);
    }
    if (sha256_b64(canon) != sig.bh)
        return fail(result::fail, "the body hash does not match");
    const auto headers = split_headers(head);
    std::string data;
    bool from_signed = false;
    if (!header_data(headers, sig.h, hc == "relaxed", sig.index, data, from_signed))
        return fail(result::permerror, "h= names more than 256 headers");
    if (!from_signed)
        return fail(result::permerror, "From is not signed");
    const auto& self = headers[sig.index];
    data += hc == "relaxed" ? relaxed_header(self.first, without_b(self.second))
                            : simple_header(self.first, without_b(self.second));
    const result r = verify_bytes(record, sig.a, data, sig.b, why);
    // What l= leaves out could be anyone's, so a signature of part of the body says nothing of the rest.
    if (r == result::pass && partial)
        return fail(result::neutral, "l= leaves part of the body unsigned");
    return r;
}

const char* result_name(result r)
{
    switch (r)
    {
        case result::pass: return "pass";
        case result::fail: return "fail";
        case result::neutral: return "neutral";
        case result::permerror: return "permerror";
        case result::temperror: return "temperror";
    }
    return "neutral";
}

}   // namespace socketley::mail::dkim
