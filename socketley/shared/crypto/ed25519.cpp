#include "ed25519.h"
#include "key_file.h"

#include <openssl/err.h>
#include <openssl/evp.h>

namespace socketley::ed25519
{

namespace
{

const unsigned char* bytes(std::string_view s) { return reinterpret_cast<const unsigned char*>(s.data()); }

}   // namespace

EVP_PKEY* generate()
{
    return EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
}

EVP_PKEY* from_seed(std::string_view seed)
{
    if (seed.size() != 32)
        return nullptr;
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, bytes(seed), seed.size());
}

EVP_PKEY* load_or_make(const std::string& path, std::string_view what, std::string& err)
{
    EVP_PKEY* k = key_file::load_or_make(path, what, generate, err);
    if (k && EVP_PKEY_get_base_id(k) != EVP_PKEY_ED25519)
    {
        EVP_PKEY_free(k);
        err = std::string(what) + " " + path + " is not an Ed25519 key";
        return nullptr;
    }
    return k;
}

std::string public_raw(EVP_PKEY* k)
{
    std::string out(32, '\0');
    size_t n = out.size();
    if (!k || EVP_PKEY_get_base_id(k) != EVP_PKEY_ED25519 ||
        EVP_PKEY_get_raw_public_key(k, reinterpret_cast<unsigned char*>(out.data()), &n) != 1 || n != 32)
        return {};
    return out;
}

std::string sign(EVP_PKEY* k, std::string_view message)
{
    if (!k)
        return {};
    std::string sig(64, '\0');
    size_t n = sig.size();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    // Ed25519 hashes the message itself, so no digest is named.
    const bool ok = ctx && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, k) == 1 &&
                    EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(sig.data()), &n, bytes(message),
                                   message.size()) == 1 && n == 64;
    EVP_MD_CTX_free(ctx);
    if (!ok)
    {
        ERR_clear_error();
        return {};
    }
    return sig;
}

bool verify(std::string_view pub, std::string_view message, std::string_view sig)
{
    if (pub.size() != 32 || sig.size() != 64)
        return false;
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, bytes(pub), pub.size());
    EVP_MD_CTX* ctx = k ? EVP_MD_CTX_new() : nullptr;
    const bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, k) == 1 &&
                    EVP_DigestVerify(ctx, bytes(sig), sig.size(), bytes(message), message.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    if (!ok)
        ERR_clear_error();
    return ok;
}

}   // namespace socketley::ed25519
