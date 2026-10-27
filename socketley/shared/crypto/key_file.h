#pragma once
// A private key kept in a PEM file of its own, made at first use and linked into place whole, which the identity
// provider, the ACME client, DNSSEC and the SSH certificate authority each keep one or more of.
#include <string>
#include <string_view>

typedef struct evp_pkey_st EVP_PKEY;

namespace socketley::key_file
{

// The private key in `path`, or one `make` returns written there (0600) when the file does not exist; null with
// `err` saying so when it cannot be read, made or written.  `what` names the key in that sentence.
EVP_PKEY* load_or_make(const std::string& path, std::string_view what, EVP_PKEY* (*make)(), std::string& err);

}   // namespace socketley::key_file
