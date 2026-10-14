#include "jws.h"

#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace socketley::jws
{

std::string b64url(std::string_view in)
{
    static constexpr char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3)
    {
        const uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8) | uint8_t(in[i + 2]);
        out += tbl[v >> 18];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
        out += tbl[v & 63];
    }
    if (i + 1 == in.size())
    {
        const uint32_t v = uint8_t(in[i]) << 16;
        out += tbl[v >> 18];
        out += tbl[(v >> 12) & 63];
    }
    else if (i + 2 == in.size())
    {
        const uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8);
        out += tbl[v >> 18];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
    }
    return out;
}

bool b64url_decode(std::string_view in, std::string& out)
{
    // A single leftover character carries six bits, which is no whole byte, so no encoder ends that way.
    if (in.size() % 4 == 1)
        return false;
    auto val = [](char c) -> int
    {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    out.clear();
    out.reserve(in.size() * 3 / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (const char c : in)
    {
        const int v = val(c);
        if (v < 0)
            return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    // The bits below the last byte are zero in what an encoder writes, so other ones are a second spelling.
    return (acc & ((1u << bits) - 1)) == 0;
}

std::string sha256(std::string_view in)
{
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d);
    return std::string(reinterpret_cast<const char*>(d), sizeof d);
}

EVP_PKEY* load_or_make_key(const std::string& path, std::string_view what, std::string& err)
{
    if (BIO* b = BIO_new_file(path.c_str(), "r"))
    {
        EVP_PKEY* k = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
        BIO_free(b);
        if (k)
            return k;
        err = std::string(what) + " " + path + " does not load";
        return nullptr;
    }
    ERR_clear_error();
    EVP_PKEY* k = EVP_EC_gen("P-256");
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    // Written beside and linked into place whole, so a failure leaves no empty or cut key that would never load.
    const std::string tmp = path + ".new." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    FILE* f = fd >= 0 ? fdopen(fd, "w") : nullptr;
    bool ok = k && f && PEM_write_PrivateKey(f, k, nullptr, nullptr, 0, nullptr, nullptr) == 1 && fflush(f) == 0 &&
              ::fsync(fd) == 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    else if (fd >= 0)
        ::close(fd);
    ok = ok && ::link(tmp.c_str(), path.c_str()) == 0;
    if (fd >= 0)
        ::unlink(tmp.c_str());
    if (!ok)
    {
        // Another process linked its key first, which is the one both must use.
        if (BIO* b = BIO_new_file(path.c_str(), "r"))
        {
            EVP_PKEY* theirs = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
            BIO_free(b);
            if (theirs)
            {
                if (k)
                    EVP_PKEY_free(k);
                return theirs;
            }
        }
        err = std::string(what) + " " + path + " could not be written";
        if (k)
            EVP_PKEY_free(k);
        return nullptr;
    }
    return k;
}

std::string jwk_of(EVP_PKEY* k)
{
    BIGNUM *x = nullptr, *y = nullptr;
    EVP_PKEY_get_bn_param(k, "qx", &x);
    EVP_PKEY_get_bn_param(k, "qy", &y);
    std::string xs(32, '\0'), ys(32, '\0');
    if (x)
        BN_bn2binpad(x, reinterpret_cast<unsigned char*>(xs.data()), 32);
    if (y)
        BN_bn2binpad(y, reinterpret_cast<unsigned char*>(ys.data()), 32);
    BN_free(x);
    BN_free(y);
    return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + b64url(xs) + "\",\"y\":\"" + b64url(ys) + "\"}";
}

std::string thumbprint(EVP_PKEY* k)
{
    return b64url(sha256(jwk_of(k)));
}

std::string es256(EVP_PKEY* k, std::string_view input)
{
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    size_t n = 0;
    std::string der;
    if (EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, k) == 1 &&
        EVP_DigestSign(md, nullptr, &n, reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1)
    {
        der.resize(n);
        if (EVP_DigestSign(md, reinterpret_cast<unsigned char*>(der.data()), &n,
                           reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1)
            der.resize(n);
        else
            der.clear();
    }
    EVP_MD_CTX_free(md);
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    ECDSA_SIG* sig = der.empty() ? nullptr : d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    if (!sig)
        return {};
    std::string raw(64, '\0');
    BN_bn2binpad(ECDSA_SIG_get0_r(sig), reinterpret_cast<unsigned char*>(raw.data()), 32);
    BN_bn2binpad(ECDSA_SIG_get0_s(sig), reinterpret_cast<unsigned char*>(raw.data()) + 32, 32);
    ECDSA_SIG_free(sig);
    return raw;
}

bool es256_verify(EVP_PKEY* k, std::string_view input, std::string_view sig)
{
    if (!k || sig.size() != 64)
        return false;
    ECDSA_SIG* s = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(reinterpret_cast<const unsigned char*>(sig.data()), 32, nullptr);
    BIGNUM* t = BN_bin2bn(reinterpret_cast<const unsigned char*>(sig.data()) + 32, 32, nullptr);
    if (!s || !r || !t || ECDSA_SIG_set0(s, r, t) != 1)
    {
        BN_free(r);
        BN_free(t);
        ECDSA_SIG_free(s);
        return false;
    }
    unsigned char* der = nullptr;
    const int n = i2d_ECDSA_SIG(s, &der);
    ECDSA_SIG_free(s);
    if (n <= 0)
        return false;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    const bool ok = md && EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, k) == 1 &&
                    EVP_DigestVerify(md, der, static_cast<size_t>(n),
                                     reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1;
    EVP_MD_CTX_free(md);
    OPENSSL_free(der);
    ERR_clear_error();
    return ok;
}

std::string compact(EVP_PKEY* k, std::string_view header, std::string_view payload)
{
    std::string out = b64url(header);
    out += '.';
    out += b64url(payload);
    const std::string sig = es256(k, out);
    if (sig.empty())
        return {};
    out += '.';
    out += b64url(sig);
    return out;
}

}   // namespace socketley::jws
