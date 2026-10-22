#include "web_push.h"

#include <cstdint>
#include <memory>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include "mac.h"

namespace socketley::crypto::web_push
{

namespace
{

using pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

// A P-256 key from its private scalar, or from its public point alone.
pkey key_of(std::string_view priv, std::string_view pub)
{
    pkey out(nullptr, EVP_PKEY_free);
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> bld(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> d(nullptr, BN_free);
    if (!bld || !OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0))
        return out;
    if (!pub.empty() && !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size()))
        return out;
    if (!priv.empty())
    {
        d.reset(BN_bin2bn(reinterpret_cast<const unsigned char*>(priv.data()), static_cast<int>(priv.size()), nullptr));
        if (!d || !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, d.get()))
            return out;
    }
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(OSSL_PARAM_BLD_to_param(bld.get()), OSSL_PARAM_free);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr),
                                                                    EVP_PKEY_CTX_free);
    EVP_PKEY* k = nullptr;
    if (params && ctx && EVP_PKEY_fromdata_init(ctx.get()) > 0 &&
        EVP_PKEY_fromdata(ctx.get(), &k, priv.empty() ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params.get()) > 0)
        out.reset(k);
    return out;
}

std::string public_of(EVP_PKEY* k)
{
    unsigned char buf[65];
    size_t n = 0;
    if (EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, sizeof buf, &n) != 1 || n != 65)
        return {};
    return std::string(reinterpret_cast<const char*>(buf), n);
}

// HKDF-Expand to at most one block of SHA-256 (RFC 5869 2.3), as every key here is.
std::string expand(std::string_view prk, std::string_view info, size_t n)
{
    std::string t = hmac_sha256(prk, std::string(info) + '\x01');
    return t.size() >= n ? t.substr(0, n) : std::string();
}

bool seal(const pkey& as_key, std::string_view payload, std::string_view ua_public, std::string_view auth,
          std::string_view salt, std::string& out)
{
    if (ua_public.size() != 65 || ua_public[0] != '\x04' || auth.size() != 16 || salt.size() != 16 || payload.size() > 3993)
        return false;
    const pkey ua = key_of({}, ua_public);
    const std::string as_public = public_of(as_key.get());
    if (!ua || as_public.empty())
        return false;
    // ecdh_secret = ECDH(as_private, ua_public).
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> dctx(EVP_PKEY_CTX_new(as_key.get(), nullptr),
                                                                     EVP_PKEY_CTX_free);
    unsigned char shared[32];
    size_t shared_len = sizeof shared;
    if (!dctx || EVP_PKEY_derive_init(dctx.get()) <= 0 || EVP_PKEY_derive_set_peer(dctx.get(), ua.get()) <= 0 ||
        EVP_PKEY_derive(dctx.get(), shared, &shared_len) <= 0 || shared_len != 32)
        return false;
    // IKM from the auth secret and both public keys, then the content key and nonce from the salt (RFC 8291 3.4).
    const std::string prk_key = hmac_sha256(auth, std::string_view(reinterpret_cast<const char*>(shared), 32));
    std::string key_info = "WebPush: info";
    key_info += '\0';
    key_info.append(ua_public).append(as_public);
    const std::string ikm = expand(prk_key, key_info, 32);
    const std::string prk = hmac_sha256(salt, ikm);
    const std::string cek = expand(prk, std::string("Content-Encoding: aes128gcm") + '\0', 16);
    const std::string nonce = expand(prk, std::string("Content-Encoding: nonce") + '\0', 12);
    if (prk_key.empty() || ikm.empty() || cek.size() != 16 || nonce.size() != 12)
        return false;
    // One record: the payload and the delimiter 0x02 that says it is the last (RFC 8188 2).
    std::string plain(payload);
    plain += '\x02';
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> c(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::string sealed(plain.size() + 16, '\0');
    int n = 0, tail = 0;
    if (!c || EVP_EncryptInit_ex(c.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(c.get(), nullptr, nullptr, reinterpret_cast<const unsigned char*>(cek.data()),
                           reinterpret_cast<const unsigned char*>(nonce.data())) != 1 ||
        EVP_EncryptUpdate(c.get(), reinterpret_cast<unsigned char*>(sealed.data()), &n,
                          reinterpret_cast<const unsigned char*>(plain.data()), static_cast<int>(plain.size())) != 1 ||
        EVP_EncryptFinal_ex(c.get(), reinterpret_cast<unsigned char*>(sealed.data()) + n, &tail) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, 16, sealed.data() + n + tail) != 1)
        return false;
    sealed.resize(static_cast<size_t>(n + tail) + 16);
    // salt, the record size 4096, the key id's length and the key id, the message's public key (RFC 8291 4).
    out.assign(salt);
    out += std::string("\x00\x00\x10\x00", 4);
    out += static_cast<char>(65);
    out += as_public;
    out += sealed;
    return true;
}

}   // namespace

bool encrypt_with(std::string_view payload, std::string_view ua_public, std::string_view auth,
                  std::string_view as_private, std::string_view as_public, std::string_view salt, std::string& out)
{
    const pkey as_key = key_of(as_private, as_public);
    return as_key && seal(as_key, payload, ua_public, auth, salt, out);
}

bool encrypt(std::string_view payload, std::string_view ua_public, std::string_view auth, std::string& out)
{
    pkey as_key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"), EVP_PKEY_free);
    unsigned char salt[16];
    if (!as_key || RAND_bytes(salt, sizeof salt) != 1)
        return false;
    return seal(as_key, payload, ua_public, auth, std::string_view(reinterpret_cast<const char*>(salt), 16), out);
}

}   // namespace socketley::crypto::web_push
