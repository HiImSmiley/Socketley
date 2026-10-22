#pragma once
// DKIM (RFC 6376): the signature a mail runtime puts on the mail its domains send, rsa-sha256 or ed25519-sha256
// (RFC 8463) with relaxed headers and body, and the check of the signatures on the mail it receives.  Pure functions
// of their bytes, so both run on a helper thread and a test runs them against dkimpy; ARC's signatures are made and
// checked by the same parts.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace socketley::mail::dkim
{

using key_ptr = std::shared_ptr<EVP_PKEY>;

// The key kept at `path`, made (RSA of 2048 bits, or Ed25519) and written there first when there is none.
key_ptr load_or_make(const std::string& path, std::string& why, bool ed25519 = false);
key_ptr load_pem(const std::string& path, const std::string& pem, std::string& why);
// A new key linked in at `path`, or nothing where one is there already; false when neither could be.
bool make_key(const std::string& path, std::string& why, bool ed25519 = false);
// "v=DKIM1; k=rsa; p=<public key>" or "v=DKIM1; k=ed25519; p=<its 32 bytes>", the TXT record
// <selector>._domainkey.<domain> carries.
std::string public_record(EVP_PKEY* key);
// "rsa-sha256" or "ed25519-sha256", what a signature by `key` says it is.
std::string algorithm_of(EVP_PKEY* key);

// `data` signed by `key` as `algorithm_of` it, in base64; empty where it could not be.
std::string sign_bytes(EVP_PKEY* key, std::string_view data);
enum class result : uint8_t { pass, fail, neutral, permerror, temperror };
// Whether `b64` is `algorithm`'s signature of `data` by the key of the TXT `record`.
result verify_bytes(std::string_view record, std::string_view algorithm, std::string_view data, std::string_view b64,
                    std::string* why = nullptr);
// The headers `h` names, colon-separated, each the last not used yet from the bottom, canonicalized and ended by CRLF,
// the one at `skip` passed over; false where it names more than 256.
bool header_data(const std::vector<std::pair<std::string_view, std::string_view>>& headers, std::string_view h,
                 bool relaxed, size_t skip, std::string& data, bool& from_signed);
// A signature's own header with its b= emptied, as it is hashed.
std::string without_b(std::string_view raw);
// Whether `name` is a domain or a selector a signature may give: dot-separated letters, digits and hyphens.
bool ldh_name(std::string_view name);

// The body and a header as the relaxed and the simple canonicalizations write them.
std::string relaxed_body(std::string_view body);
std::string simple_body(std::string_view body);
std::string relaxed_header(std::string_view name, std::string_view value);

// The DKIM-Signature header for `message`, its headers and body, ended by CRLF, to put ahead of it; `header` and
// `first_tags` make ARC's ARC-Message-Signature of it instead ("i=1; ").
std::string sign(std::string_view message, std::string_view domain, std::string_view selector, EVP_PKEY* key,
                 int64_t now_s, std::string_view header = "DKIM-Signature", std::string_view first_tags = {},
                 std::string_view body_hash = {});
// The bh= of `message`: its relaxed body's SHA-256, which two signatures of one message share.
std::string body_hash(std::string_view message);

struct signature
{
    std::string v, a, d, s, c, h, bh, b, i, l, t, x;
    // The header's value as it stood, and its place among the message's headers.
    std::string raw;
    size_t index{0};
};
// The DKIM-Signature headers of a message, or those of `header`, read; one that does not parse, or names a domain or
// selector that is no name, is left out.
std::vector<signature> signatures(std::string_view message, std::string_view header = "DKIM-Signature");

// A message's body as each canonicalization wrote it, made once for every signature that asks.
struct bodies
{
    std::string relaxed, simple;
    bool have_relaxed{false}, have_simple{false};
};
// Whether `sig` is good for `message`, with `record` the TXT its selector names (empty when there was none); one whose
// l= leaves part of the body out is neutral, as that part could be anyone's.
result verify(std::string_view message, const signature& sig, std::string_view record, int64_t now_s,
              std::string* why = nullptr, bodies* cache = nullptr);
const char* result_name(result r);

}   // namespace socketley::mail::dkim
