#pragma once
// The pieces of JSON Web Signature this tree signs with: ES256 over P-256, the key kept in a PEM file, and the
// encodings RFC 7515 and RFC 7638 fix, shared by the ACME client and the identity provider.
#include <string>
#include <string_view>

typedef struct evp_pkey_st EVP_PKEY;

namespace socketley::jws
{

// Base64url without padding, as every JWS part is written.
std::string b64url(std::string_view in);

// The bytes of an unpadded base64url string; false on a character or a length no encoder writes.
bool b64url_decode(std::string_view in, std::string& out);

// SHA-256 of `in`, the 32 raw bytes.
std::string sha256(std::string_view in);

// The P-256 private key in `path`, made and written there whole (0600) when the file does not exist; null with
// `err` saying so when it cannot be read or written.  `what` names the key in that sentence.
EVP_PKEY* load_or_make_key(const std::string& path, std::string_view what, std::string& err);

// The key's public half as a JWK in RFC 7638's member order, which is also its thumbprint's input.
std::string jwk_of(EVP_PKEY* k);

// The RFC 7638 thumbprint of that JWK, base64url, which the identity provider uses as the key's kid.
std::string thumbprint(EVP_PKEY* k);

// ES256 over `input` as JWS writes it: r and s, 32 bytes each, not DER; empty if signing failed.
std::string es256(EVP_PKEY* k, std::string_view input);

// Whether `sig`, 64 raw bytes, is the key's ES256 signature over `input`.
bool es256_verify(EVP_PKEY* k, std::string_view input, std::string_view sig);

// `header.payload.signature` for the JSON `header` and `payload` given, signed with `k`.
std::string compact(EVP_PKEY* k, std::string_view header, std::string_view payload);

}   // namespace socketley::jws
