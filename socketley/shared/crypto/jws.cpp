#include "jws.h"
#include "key_file.h"
#include "../util/base64.h"

#include <cstdint>
#include <cstring>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace socketley::jws
{



std::string sha256(std::string_view in)
{
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d);
    return std::string(reinterpret_cast<const char*>(d), sizeof d);
}

EVP_PKEY* load_or_make_key(const std::string& path, std::string_view what, std::string& err)
{
    return key_file::load_or_make(path, what, [] { return EVP_EC_gen("P-256"); }, err);
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
    return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + base64url::encode(xs) + "\",\"y\":\"" + base64url::encode(ys) + "\"}";
}

std::string thumbprint(EVP_PKEY* k)
{
    return base64url::encode(sha256(jwk_of(k)));
}

namespace
{

// The context of the key this thread signed with last, which holds a reference to it so no other key takes its
// address, kept since making one looks the digest and the signature up by name every time.
struct sign_context
{
    EVP_PKEY* key{nullptr};
    EVP_PKEY_CTX* ctx{nullptr};
    EVP_MD* sha256{nullptr};
    ~sign_context()
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_MD_free(sha256);
    }
};
// One for each way of choosing the nonce, which is a setting of the context.
thread_local sign_context t_sign[2];

// r and s of a DER ECDSA signature, each 32 bytes from the left, into `out`; false for anything else.
bool raw_of_der(const unsigned char* p, size_t n, char* out)
{
    // A P-256 signature is under 128 bytes, so every length is one byte.
    if (n < 8 || p[0] != 0x30 || p[1] != n - 2)
        return false;
    size_t at = 2;
    for (int i = 0; i < 2; ++i)
    {
        if (n - at < 2 || p[at] != 0x02)
            return false;
        size_t len = p[at + 1];
        at += 2;
        if (len == 0 || len > 33 || n - at < len)
            return false;
        const unsigned char* v = p + at;
        at += len;
        for (; len > 32; --len, ++v)
            if (*v != 0)
                return false;
        std::memset(out + 32 * i, 0, 32 - len);
        std::memcpy(out + 32 * i + 32 - len, v, len);
    }
    return at == n;
}

}   // namespace

std::string es256(EVP_PKEY* k, std::string_view input, nonce_kind how)
{
    if (!k)
        return {};
    sign_context& t = t_sign[how == nonce_kind::derived ? 1 : 0];
    if (!t.sha256)
        t.sha256 = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    if (!t.sha256)
        return {};
    if (t.key != k)
    {
        EVP_PKEY_CTX_free(t.ctx);
        t.key = nullptr;
        t.ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, k, nullptr);
        bool ready = t.ctx && EVP_PKEY_sign_init(t.ctx) == 1;
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
        // RFC 6979 takes its HMAC from the signature's digest, which the context is told.
        if (ready && how == nonce_kind::derived)
        {
            unsigned int type = 1;
            const OSSL_PARAM params[] = {OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &type),
                                         OSSL_PARAM_construct_end()};
            ready = EVP_PKEY_CTX_set_signature_md(t.ctx, t.sha256) == 1 && EVP_PKEY_CTX_set_params(t.ctx, params) == 1;
        }
#endif
        if (!ready)
        {
            EVP_PKEY_CTX_free(t.ctx);
            t.ctx = nullptr;
            ERR_clear_error();
            return {};
        }
        t.key = k;
    }
    unsigned char digest[32];
    unsigned int dn = 0;
    if (EVP_Digest(input.data(), input.size(), digest, &dn, t.sha256, nullptr) != 1 || dn != 32)
        return {};
    unsigned char der[80];
    size_t n = sizeof der;
    std::string raw(64, '\0');
    if (EVP_PKEY_sign(t.ctx, der, &n, digest, sizeof digest) != 1 || !raw_of_der(der, n, raw.data()))
    {
        ERR_clear_error();
        return {};
    }
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
    std::string out;
    out.reserve((header.size() + payload.size()) / 3 * 4 + 96);
    out += base64url::encode(header);
    out += '.';
    out += base64url::encode(payload);
    const std::string sig = es256(k, out);
    if (sig.empty())
        return {};
    out += '.';
    out += base64url::encode(sig);
    return out;
}

}   // namespace socketley::jws
