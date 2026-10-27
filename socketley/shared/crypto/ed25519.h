#pragma once
// Ed25519 (RFC 8032) as OpenSSL does it: a key, its 32-byte public half, and signatures over a whole message.
#include <string>
#include <string_view>

typedef struct evp_pkey_st EVP_PKEY;

namespace socketley::ed25519
{

// A new key, null if none could be made; the caller frees it with EVP_PKEY_free.
EVP_PKEY* generate();

// The key whose 32-byte private seed is `seed`, null for any other length.
EVP_PKEY* from_seed(std::string_view seed);

// The Ed25519 key in `path`, made there (0600) when the file does not exist; null with `err` when it cannot be
// read or written, or when the file holds a key of another kind.
EVP_PKEY* load_or_make(const std::string& path, std::string_view what, std::string& err);

// The 32 bytes of the public half, empty for a key that is not Ed25519.
std::string public_raw(EVP_PKEY* k);

// The 64-byte signature over `message`, empty if signing failed.
std::string sign(EVP_PKEY* k, std::string_view message);

// Whether `sig` is the signature of the 32-byte public key `pub` over `message`.
bool verify(std::string_view pub, std::string_view message, std::string_view sig);

}   // namespace socketley::ed25519
