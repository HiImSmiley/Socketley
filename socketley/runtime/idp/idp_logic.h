#pragma once
// What the identity provider decides without a socket: its clients, the forms and queries it reads, PKCE, the
// tokens it signs and verifies, and where it may send a browser back to.
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../../shared/util/transparent_string.h"

typedef struct evp_pkey_st EVP_PKEY;

namespace socketley::idp
{

// One relying party from --clients: an id, a secret (empty for a public client, which must use PKCE), and the
// addresses a browser may be sent back to, compared whole.
struct client
{
    std::string id;
    std::string secret;
    std::vector<std::string> redirects;

    bool is_public() const { return secret.empty(); }
    bool allows(std::string_view redirect) const;
};

// `id secret redirect [redirect...]` a line, `-` as the secret for a public client, `#` starting a comment; false
// with `why` naming the line for anything else, so a client is never half read.
bool parse_clients(std::string_view text, std::vector<client>& out, std::string& why);

using params = std::vector<std::pair<std::string, std::string>>;

// An application/x-www-form-urlencoded body or a query: `+` is a space, and a pair that does not decode is left out.
params parse_form(std::string_view in);

// The value of the first `name`, empty when there is none.
std::string_view param(const params& p, std::string_view name);

// Percent-encoded for a query value: everything but RFC 3986's unreserved characters.
std::string url_encode(std::string_view in);

// Text safe inside HTML, attribute values included.
std::string html_escape(std::string_view in);

// A JSON string literal, quotes included.
std::string json_string(std::string_view in);

// RFC 7636: a verifier of 43 to 128 unreserved characters whose SHA-256, base64url, is the S256 challenge.
bool pkce_matches(std::string_view verifier, std::string_view challenge);

// Whether `scope`, space-separated, holds `want`.
bool has_scope(std::string_view scope, std::string_view want);

// `https://host/...` or `http://host/...`: the host, lower case and without a port, empty for anything else.
std::string url_host(std::string_view url);

// Whether a browser may be sent to `url` after signing in: an address on the issuer's own host, or on
// `cookie_domain` or a name below it.
bool return_allowed(std::string_view url, std::string_view issuer, std::string_view cookie_domain);

// A signed token's claims, read back: strings, numbers as their text, and booleans as "true" or "false".
using claims = std::map<std::string, std::string, std::less<>>;

// A JWT signed with `key` under `kid`, `typ` naming what it is for, holding `body`, a JSON object's members
// without the braces.
std::string sign_token(EVP_PKEY* key, std::string_view kid, std::string_view typ, std::string_view body);

// The claims of `token` when it is ES256 under `kid` with typ `typ`, its signature holds against `key`, it was
// issued by `issuer` and has not expired at `now`; false with `why` otherwise.
bool verify_token(EVP_PKEY* key, std::string_view kid, std::string_view typ, std::string_view issuer,
                  std::string_view token, int64_t now, claims& out, std::string& why);

// verify_token with the tokens it took remembered until they expire, so one sent again costs a lookup rather than a
// signature check: a token's bytes decide its verification whole.
class verified_tokens
{
public:
    bool verify(EVP_PKEY* key, std::string_view kid, std::string_view typ, std::string_view issuer,
                std::string_view token, int64_t now, claims& out, std::string& why);
    void clear() { m_seen.clear(); }

private:
    struct entry
    {
        // The key's id, the typ and the issuer it was verified for, each a line.
        std::string context;
        claims c;
        int64_t expires{0};
    };
    std::unordered_map<std::string, entry, string_hash, string_equal> m_seen;
};

// The secret of the tokens only this provider reads back, made from `key`'s private half, so it lives and changes
// with the key; empty when that half cannot be read.
std::string token_secret(EVP_PKEY* key);

// A JWT signed HS256 with `secret`, for what this provider alone reads back, as a refresh token: an HMAC costs a
// microsecond where an ECDSA signature costs tens.
std::string sign_secret_token(std::string_view secret, std::string_view typ, std::string_view body);
bool verify_secret_token(std::string_view secret, std::string_view typ, std::string_view issuer, std::string_view token,
                         int64_t now, claims& out, std::string& why);

}   // namespace socketley::idp
