#include "password_hash.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>
#include <cstdlib>

#include "checksum.h"

namespace socketley::storage
{

namespace
{

constexpr int salt_bytes = 16;
constexpr int hash_bytes = 32;
// 16 MiB a hash, which the memory bound must leave room for.
constexpr uint64_t max_mem = 64ull << 20;

bool derive(std::string_view password, std::string_view salt, int ln, int r, int p, std::string& out)
{
    out.assign(hash_bytes, '\0');
    return EVP_PBE_scrypt(password.data(), password.size(), reinterpret_cast<const unsigned char*>(salt.data()),
                          salt.size(), uint64_t(1) << ln, static_cast<uint64_t>(r), static_cast<uint64_t>(p), max_mem,
                          reinterpret_cast<unsigned char*>(out.data()), out.size()) == 1;
}

}   // namespace

std::string password_hash(std::string_view password)
{
    std::string salt(salt_bytes, '\0'), h;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt_bytes) != 1 || !derive(password, salt, 14, 8, 1, h))
        return {};
    return "$scrypt$ln=14,r=8,p=1$" + base64_encode(salt) + "$" + base64_encode(h);
}

bool password_matches(std::string_view hash, std::string_view password)
{
    // $scrypt$ln=<ln>,r=<r>,p=<p>$<salt>$<hash>
    static constexpr std::string_view head = "$scrypt$ln=";
    if (!hash.starts_with(head))
        return false;
    hash.remove_prefix(head.size());
    const size_t d1 = hash.find('$'), d2 = d1 == std::string_view::npos ? d1 : hash.find('$', d1 + 1);
    if (d2 == std::string_view::npos)
        return false;
    const std::string params(hash.substr(0, d1));
    int ln = 0, r = 0, p = 0;
    if (std::sscanf(params.c_str(), "%d,r=%d,p=%d", &ln, &r, &p) != 3 || ln < 10 || ln > 20 || r < 1 || r > 32 || p < 1 ||
        p > 16)
        return false;
    std::string salt, want, got;
    if (!base64_decode(hash.substr(d1 + 1, d2 - d1 - 1), salt) || !base64_decode(hash.substr(d2 + 1), want) ||
        want.size() != hash_bytes || !derive(password, salt, ln, r, p, got))
        return false;
    return CRYPTO_memcmp(got.data(), want.data(), want.size()) == 0;
}

std::string password_problem(std::string_view password, std::string_view user)
{
    if (password.size() < 8)
        return "A password is at least 8 characters long.";
    if (password.size() > 128)
        return "A password is at most 128 characters long.";
    if (password == user)
        return "A password is not the user's name.";
    return {};
}

}   // namespace socketley::storage
