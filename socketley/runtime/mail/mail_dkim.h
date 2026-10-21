#pragma once
// DKIM (RFC 6376): the signature a mail runtime puts on the mail its domains send, rsa-sha256 with relaxed headers
// and body, and the check of the signatures on the mail it receives.  Pure functions of their bytes, so both run on a
// helper thread and a test runs them against dkimpy.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace socketley::mail::dkim
{

using key_ptr = std::shared_ptr<EVP_PKEY>;

// The key kept at `path`, made (RSA, 2048 bits) and written there first when there is none.
key_ptr load_or_make(const std::string& path, std::string& why);
// "v=DKIM1; k=rsa; p=<public key>", the TXT record <selector>._domainkey.<domain> carries.
std::string public_record(EVP_PKEY* key);

// The body and a header as the relaxed and the simple canonicalizations write them.
std::string relaxed_body(std::string_view body);
std::string simple_body(std::string_view body);
std::string relaxed_header(std::string_view name, std::string_view value);

// The DKIM-Signature header for `message`, its headers and body, ended by CRLF, to put ahead of it.
std::string sign(std::string_view message, std::string_view domain, std::string_view selector, EVP_PKEY* key,
                 int64_t now_s);

struct signature
{
    std::string v, a, d, s, c, h, bh, b, i, l, t, x;
    // The header's value as it stood, and its place among the message's headers.
    std::string raw;
    size_t index{0};
};
// The DKIM-Signature headers of a message, read; one that does not parse is left out.
std::vector<signature> signatures(std::string_view message);

enum class result : uint8_t { pass, fail, neutral, permerror, temperror };
// Whether `sig` is good for `message`, with `record` the TXT its selector names (empty when there was none).
result verify(std::string_view message, const signature& sig, std::string_view record, int64_t now_s,
              std::string* why = nullptr);
const char* result_name(result r);

}   // namespace socketley::mail::dkim
