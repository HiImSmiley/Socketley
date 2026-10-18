#pragma once
// Identities from outside the credentials file that STS may give temporary credentials to: an OIDC provider's signed
// tokens (AssumeRoleWithWebIdentity) and an LDAP directory's simple bind (AssumeRoleWithLDAPIdentity), each mapped
// to a user of the credentials file whose rights the session takes, as a line-based provider file configures it.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/types.h>

namespace socketley::storage
{

// ---- the provider file ----

// The OIDC provider whose tokens are taken, none when `issuer` is empty.
struct federation_oidc
{
    // Compared with the token's iss byte for byte.
    std::string issuer;
    // The client ids a token's aud must name one of.
    std::vector<std::string> clients;
    // The JWK Set the tokens are signed with, read again whenever the file changes.
    std::string jwks_path;
    // The claim that names the users whose rights the session takes.
    std::string claim{"policy"};

    bool enabled() const { return !issuer.empty(); }
};

// Which socketley user an LDAP user binding as `ldap_user` signs as; `*` is any, and a `user` of `=` is the same name.
struct federation_ldap_map
{
    std::string ldap_user;
    std::string user;
};

// The LDAP directory a username and password are bound against, none when `host` is empty.
struct federation_ldap
{
    bool        tls{false};
    std::string host;
    uint16_t    port{0};
    // The CA an ldaps server's certificate is checked against, the system's when empty.
    std::string ca_file;
    // The DN bound as, with `%s` where the escaped username goes.
    std::string dn_template;
    std::vector<federation_ldap_map> users;
    // The whole exchange, connect to answer, ends after this long.
    int         timeout_ms{5000};

    bool enabled() const { return !host.empty(); }
};

// A RoleArn that AssumeRoleWithWebIdentity names and the user every verified token asking for it signs as.
struct federation_role
{
    std::string arn;
    std::string user;
};

struct federation_config
{
    federation_oidc oidc;
    federation_ldap ldap;
    std::vector<federation_role> roles;
};

// A provider file's lines (`oidc issuer|client|jwks|claim <v>`, `ldap url <url> [ca=<file>]`, `ldap dn <template>`,
// `ldap user <name|*> <user|=>`, `role <arn> <user>`), relative paths under `dir`; false with `why` naming the line.
bool parse_federation(std::string_view text, federation_config& out, std::string& why, std::string_view dir = {});
// The provider file at `path` read and parsed, its relative paths under its own directory.
bool load_federation(const std::string& path, federation_config& out, std::string& why);

// Whether `user` may name a user of the credentials file, by the rules its `[id]` sections follow.
bool federation_user_name(std::string_view user);

// ---- OIDC ----

// A clock up to a minute off either way still takes a token that is on time.
inline constexpr int64_t oidc_leeway_secs = 60;
// The longest token taken, past every IdP's in practice.
inline constexpr size_t  jwt_max_bytes = 16384;

// A JWS ECDSA signature, r and s of `coord` bytes each, as the DER SEQUENCE OpenSSL verifies.
bool jws_ecdsa_to_der(std::string_view raw, size_t coord, std::string& der);

struct evp_pkey_free
{
    void operator()(EVP_PKEY* k) const;
};

// One signing key of a JWK Set.
struct jwk
{
    std::string kid;
    // "RSA" or "EC".
    std::string kty;
    // An EC key's curve, "P-256" or "P-384".
    std::string crv;
    // The one alg the key signs with, empty when the key names none.
    std::string alg;
    std::unique_ptr<EVP_PKEY, evp_pkey_free> key;
};

struct jwks_keys
{
    std::vector<jwk> keys;
    // Keys of a type, use or size not verified with here, which a provider's set commonly carries beside its own.
    size_t skipped{0};
};

// A JWK Set's RSA (2048 bits and up) and EC P-256/P-384 signing keys; false for a set with none of them.
bool parse_jwks(std::string_view json, jwks_keys& out, std::string& why);

// The JWKS file of a provider, read again when its mtime, size or inode changed.
class jwks_file
{
public:
    explicit jwks_file(std::string path) : m_path(std::move(path)) {}

    // The keys last read whole, kept while the file is gone or unparsable; null with `why` when none ever were.
    const jwks_keys* current(std::string& why);

private:
    struct stamp
    {
        int64_t  mtime_ns{0};
        uint64_t size{0};
        uint64_t ino{0};
        bool operator==(const stamp&) const = default;
    };
    std::string m_path;
    jwks_keys   m_keys;
    bool        m_loaded{false};
    stamp       m_good;
    // The file as it was when it last failed to parse, so it is not read again until it changes.
    stamp       m_bad;
    bool        m_have_bad{false};
};

// What a verified token says.
struct oidc_identity
{
    std::string issuer;
    std::string subject;
    // The configured client id the token's aud named.
    std::string audience;
    // Unix seconds.
    int64_t     expires{0};
    // The names the configured claim gave, in the token's order without repeats.
    std::vector<std::string> policies;
    // On a false return only this is meaningful: the token was genuine and well-formed but its exp had passed.
    bool        expired{false};
};

// `token` verified at unix time `now` against `keys`, as `cfg` configures; false with `why` for a token not taken.
bool oidc_verify(const federation_oidc& cfg, const jwks_keys& keys, std::string_view token, int64_t now,
                 oidc_identity& out, std::string& why);

// A provider with its JWKS file, verifying on the loop: a stat per call and a read only when the file changed.
class oidc_verifier
{
public:
    explicit oidc_verifier(federation_oidc cfg) : m_cfg(std::move(cfg)), m_jwks(m_cfg.jwks_path) {}

    bool verify(std::string_view token, int64_t now, oidc_identity& out, std::string& why);
    const federation_oidc& config() const { return m_cfg; }

private:
    federation_oidc m_cfg;
    jwks_file       m_jwks;
};

// Whether the credentials file has a user of that id.
using federation_user_known = std::function<bool(std::string_view)>;

// The user a verified token's session signs as: the `role` line `role_arn` names, else the one user the claim names.
bool federation_web_user(const federation_config& cfg, const oidc_identity& id, std::string_view role_arn,
                         const federation_user_known& known, std::string& user, std::string& why);

// ---- LDAP ----

// The longest LDAP message read, far past any BindResponse.
inline constexpr size_t ldap_message_max = 65536;

// `value` escaped as one attribute value of a DN (RFC 4514 section 2.4).
std::string ldap_escape_dn_value(std::string_view value);
// The template's `%s` replaced by `username` escaped.
std::string ldap_bind_dn(std::string_view dn_template, std::string_view username);
// An LDAPv3 simple BindRequest, message `msg_id`, in BER.
std::string ldap_bind_request(int32_t msg_id, std::string_view dn, std::string_view password);
// The UnbindRequest of message `msg_id` that ends a session politely.
std::string ldap_unbind_request(int32_t msg_id);
// Whether `in` begins with a whole LDAP message: 1 with its size in `total`, 0 for one not yet whole, -1 for none.
int ldap_message_size(std::string_view in, size_t& total);

struct ldap_bind_result
{
    // The LDAPResult's resultCode: 0 success, 49 invalidCredentials.
    int         code{-1};
    // The server's diagnosticMessage, printable ASCII and at most 256 bytes.
    std::string diagnostic;

    bool bound() const { return code == 0; }
};

// The BindResponse to message `msg_id` that `msg` holds whole; false with `why` for anything else.
bool ldap_parse_bind_response(std::string_view msg, int32_t msg_id, ldap_bind_result& out, std::string& why);

// Blocking for up to cfg.timeout_ms beyond name resolution, so it runs on a helper thread and never on the loop:
// binds as `username` with `password`, true with the server's answer in `out`, false with `why` when none came.
bool ldap_simple_bind(const federation_ldap& cfg, std::string_view username, std::string_view password,
                      ldap_bind_result& out, std::string& why);

// The user an LDAP user that bound as `ldap_user` signs as: its own `ldap user` line, else the `*` one.
bool federation_ldap_user(const federation_config& cfg, std::string_view ldap_user,
                          const federation_user_known& known, std::string& user, std::string& why);

}   // namespace socketley::storage
