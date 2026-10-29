#pragma once
// What the identity provider decides without a socket: its clients, the forms and queries it reads, PKCE, the
// tokens it signs and verifies, and where it may send a browser back to.
#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../../shared/net/address_key.h"
#include "../../shared/util/transparent_string.h"

typedef struct evp_pkey_st EVP_PKEY;

namespace socketley::idp
{

// The cookie an idp runtime signs a browser in with, which every runtime that trusts it reads.
inline constexpr std::string_view session_cookie_name = "skl_idp";
// The cookie a browser keeps once an account has signed in on it, which only the provider reads.
inline constexpr std::string_view known_cookie_name = "skl_idp_known";

// The client `socketley login` signs in as, and so the one a tunnel edge takes when no --idp-audience is named.
inline constexpr std::string_view cli_client = "socketley";

// One relying party from --clients: an id, a secret (empty for a public client, which must use PKCE), and the
// addresses a browser may be sent back to, compared whole.
struct client
{
    std::string id;
    std::string secret;
    std::vector<std::string> redirects;
    // Whether it may sign a person in by the device grant (RFC 8628), which `device` in place of a redirect allows.
    bool device{false};
    // Whether its access tokens may ask for SSH certificates, which `ssh` in place of a redirect allows.
    bool ssh{false};

    bool is_public() const { return secret.empty(); }
    bool allows(std::string_view redirect) const;
};

// `id secret redirect [redirect...]` a line, `-` as the secret for a public client, `device` among the redirects
// for the device grant, `ssh` for SSH certificates, `#` starting a comment; false with `why` naming the line for anything else, so a client is
// never half read.
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

// A device grant's user code: eight letters a person reads and types without mistaking one for another,
// XXXX-XXXX; empty when there was no randomness.
std::string make_user_code();
// What a person typed as a user code, upper case without the dash and spaces; empty when it is not one.
std::string normal_user_code(std::string_view typed);
// The shard among `shards` that keeps the user code `normal`.
uint32_t user_code_shard(std::string_view normal, uint32_t shards);


// RFC 7636: a verifier of 43 to 128 unreserved characters whose SHA-256, base64url, is the S256 challenge.
bool pkce_matches(std::string_view verifier, std::string_view challenge);

// Whether `scope`, space-separated, holds `want`.
bool has_scope(std::string_view scope, std::string_view want);

// `https://host/...` or `http://host/...`: the host, lower case and without a port, empty for anything else.
std::string url_host(std::string_view url);

// Whether a browser may be sent to `url` after signing in: an address on the issuer's own host, or on
// `cookie_domain` or a name below it.
bool return_allowed(std::string_view url, std::string_view issuer, std::string_view cookie_domain);

// Whether a form a browser posted came from a page return_allowed() would send it to, `origin` being its Origin or
// else its Referer; true when it names none, as a client that is no browser sends neither.
bool form_origin_allowed(std::string_view origin, std::string_view issuer, std::string_view cookie_domain);

// Why `email` is no plain address, local@domain in ASCII without quotes, comments or control characters; empty when
// it is one, or empty.
std::string email_problem(std::string_view email);

// What failures from an address count under, as mail counts them too, and the IPv6 site around it.
using socketley::address_key;
using socketley::network_key;

// Failed attempts by what they were made at -- an address, an account -- within a window, and the attempts at each
// still being checked, so many sent at once are counted before any of them is answered.
class attempt_limits
{
public:
    static constexpr int64_t window_s = 15 * 60;

    // Whether `key` is refused outright: its failures in the window and its attempts in flight reach `limit`.
    bool barred(const std::string& key, int64_t now, int limit);
    // Seconds before `key` may try again: none while its failures and attempts in flight are below `free`, then 30
    // after the last failure, doubling with each one more, to 300 at most.
    int64_t wait(const std::string& key, int64_t now, int free);
    void begin(const std::string& key) { ++m_keys[key].in_flight; }
    void end(const std::string& key);
    void failed(const std::string& key, int64_t at);
    // Failures out of the window forgotten, and keys with nothing left.
    void age(int64_t now);
    bool empty() const { return m_keys.empty(); }

private:
    struct entry
    {
        std::vector<int64_t> at;
        uint32_t in_flight{0};
    };
    // The failures of `key` still in the window, its entry made when it has none.
    entry& fresh(const std::string& key, int64_t now);
    std::unordered_map<std::string, entry> m_keys;
};

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

// When a token of this provider was given, to the millisecond its own claim says, or its iat's second.
int64_t issued_ms(const claims& c);

// An account's standing as the provider publishes it beside its key, for a runtime that verifies its sessions alone:
// whether it is an admin, disabled or told to set its password again, and since when its sign-ins hold.
struct standing
{
    int64_t revoked_before{0};
    bool admin{false};
    bool disabled{false};
    bool reset{false};
    // The sessions signed out one at a time, by the sid each names, while they would still verify.
    std::vector<std::string> ended;

    // Whether a sign-in given at `issued` milliseconds still holds.
    bool admits(int64_t issued) const { return !disabled && !reset && issued >= revoked_before; }
    // Whether the session naming `sid` was signed out on its own.
    bool ended_session(std::string_view sid) const
    {
        return !sid.empty() && std::find(ended.begin(), ended.end(), sid) != ended.end();
    }
};
using standing_table = std::unordered_map<std::string, standing, string_hash, string_equal>;

// The file's first line, which names its format.
inline constexpr std::string_view standing_format = "socketley-idp-standing 1\n";

// One account's line, `<id> <revoked_before> <flags>` and then each ended sid, the flags `a` admin, `d` disabled and
// `r` reset, or `-`.
void append_standing(std::string& out, std::string_view id, const standing& s);
// The file whole, or false and `out` untouched when it is not one, so a reader keeps what it had.
bool parse_standing(std::string_view text, standing_table& out);

}   // namespace socketley::idp
