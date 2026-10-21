#include "mail_dkim.h"

#include <cerrno>
#include <cstdio>
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

// The signature's own header with the value of b= emptied, as it is hashed.
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

}   // namespace

key_ptr load_or_make(const std::string& path, std::string& why)
{
    std::string pem;
    if (socketley::read_file(path, pem, {.missing_ok = true}, nullptr) && !pem.empty())
        return load_pem(path, pem, why);
    if (!make_key(path, why))
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

bool make_key(const std::string& path, std::string& why)
{
    EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(2048));
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

std::string public_record(EVP_PKEY* key)
{
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

std::string sign(std::string_view message, std::string_view domain, std::string_view selector, EVP_PKEY* key,
                 int64_t now_s)
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
    const std::string bh = sha256_b64(relaxed_body(body));
    std::string value = " v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + std::string(domain) + "; s=" +
                        std::string(selector) + ";\r\n\tt=" + std::to_string(now_s) + "; h=" + h + ";\r\n\tbh=" + bh +
                        ";\r\n\tb=";
    data += relaxed_header("DKIM-Signature", value);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t len = 0;
    std::string sig;
    if (ctx && EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestSignUpdate(ctx, data.data(), data.size()) == 1 && EVP_DigestSignFinal(ctx, nullptr, &len) == 1)
    {
        sig.resize(len);
        if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(sig.data()), &len) == 1)
            sig.resize(len);
        else
            sig.clear();
    }
    if (ctx)
        EVP_MD_CTX_free(ctx);
    if (sig.empty())
        return {};
    const std::string b = socketley::base64::encode(sig);
    for (size_t at = 0; at < b.size(); at += 72)
        value += (at ? "\r\n\t " : "") + b.substr(at, 72);
    return "DKIM-Signature:" + value + "\r\n";
}

std::vector<signature> signatures(std::string_view message)
{
    std::vector<signature> out;
    const auto headers = split_headers(header_block(message));
    for (size_t i = 0; i < headers.size(); ++i)
    {
        if (!socketley::ascii::iequals(trim(headers[i].first), "dkim-signature"))
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
        if (!s.d.empty() && !s.s.empty())
            out.push_back(std::move(s));
    }
    return out;
}

result verify(std::string_view message, const signature& sig, std::string_view record, int64_t now_s,
              std::string* why)
{
    const auto fail = [&](result r, const char* w) {
        if (why)
            *why = w;
        return r;
    };
    if (sig.v != "1" || sig.h.empty() || sig.bh.empty() || sig.b.empty())
        return fail(result::permerror, "a tag the signature needs is missing");
    if (sig.a != "rsa-sha256")
        return fail(result::permerror, "an algorithm other than rsa-sha256");
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
    std::string p;
    bool from_signed = false;
    for (const auto& [k, v] : tags(record))
        if (k == "p")
            p = no_space(v);
        else if (k == "k" && v != "rsa")
            return fail(result::permerror, "a key that is not RSA");
    if (record.empty())
        return fail(result::permerror, "no key record for the selector");
    if (p.empty())
        return fail(result::fail, "the key is revoked");
    const std::string_view head = header_block(message);
    std::string body(message.substr(head.size()));
    std::string canon = bc == "relaxed" ? relaxed_body(body) : simple_body(body);
    if (!sig.l.empty())
    {
        const auto l = static_cast<size_t>(std::atoll(sig.l.c_str()));
        if (l > canon.size())
            return fail(result::permerror, "l= is longer than the body");
        canon.resize(l);
    }
    if (sha256_b64(canon) != sig.bh)
        return fail(result::fail, "the body hash does not match");
    const auto headers = split_headers(head);
    std::vector<bool> used(headers.size(), false);
    std::string data;
    std::string_view list = sig.h;
    while (!list.empty())
    {
        const size_t colon = list.find(':');
        const std::string name = lower(trim(list.substr(0, colon)));
        list = colon == std::string_view::npos ? std::string_view{} : list.substr(colon + 1);
        from_signed = from_signed || name == "from";
        for (size_t i = headers.size(); i-- > 0;)
            if (!used[i] && i != sig.index && socketley::ascii::iequals(trim(headers[i].first), name))
            {
                used[i] = true;
                data += (hc == "relaxed" ? relaxed_header(headers[i].first, headers[i].second)
                                         : simple_header(headers[i].first, headers[i].second)) +
                        "\r\n";
                break;
            }
    }
    if (!from_signed)
        return fail(result::permerror, "From is not signed");
    const auto& own = headers[sig.index];
    data += hc == "relaxed" ? relaxed_header(own.first, without_b(own.second))
                            : simple_header(own.first, without_b(own.second));
    std::string der;
    std::string signature_bytes;
    if (!socketley::base64::decode(p, der) || !socketley::base64::decode(sig.b, signature_bytes))
        return fail(result::permerror, "base64 that does not decode");
    const auto* q = reinterpret_cast<const unsigned char*>(der.data());
    EVP_PKEY* pub = d2i_PUBKEY(nullptr, &q, static_cast<long>(der.size()));
    if (!pub)
        return fail(result::permerror, "a public key that does not parse");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pub) == 1 &&
                    EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(signature_bytes.data()),
                                     signature_bytes.size(), reinterpret_cast<const unsigned char*>(data.data()),
                                     data.size()) == 1;
    if (ctx)
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pub);
    return ok ? result::pass : fail(result::fail, "the signature does not verify");
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
