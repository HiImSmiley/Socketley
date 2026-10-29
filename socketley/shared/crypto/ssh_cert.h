#pragma once
// OpenSSH public keys and certificates (PROTOCOL.certkeys) as the SSH certificate authority writes and reads them:
// a certificate for any key type OpenSSH certifies, signed by an Ed25519 authority.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

typedef struct evp_pkey_st EVP_PKEY;

namespace socketley::ssh
{

// A public key as an authorized_keys line carries it: its type, its wire blob, and the comment after them.
struct public_key
{
    std::string type;
    std::string blob;
    std::string comment;
};

// `type base64 [comment]`, for a key type a certificate can be made for; false with `err` for anything else,
// including a certificate line.
bool parse_public_key(std::string_view line, public_key& out, std::string& err);

// `SHA256:` and the unpadded base64 of the blob's digest, as ssh-keygen -l prints it.
std::string fingerprint(std::string_view blob);

// The wire blob of the Ed25519 public key whose 32 bytes are `raw`.
std::string ed25519_blob(std::string_view raw);

// `type base64 comment` for a key or certificate blob, the comment left off when empty.
std::string line_of(std::string_view blob, std::string_view comment = {});

enum class cert_kind : uint32_t
{
    user = 1,
    host = 2,
};

struct cert_request
{
    std::string subject_blob;
    cert_kind kind{cert_kind::user};
    uint64_t serial{0};
    std::string key_id;
    std::vector<std::string> principals;
    uint64_t valid_after{0};
    uint64_t valid_before{0};
    // Name and value; a flag option has an empty value.
    std::vector<std::pair<std::string, std::string>> critical_options;
    // Names of flag extensions such as permit-pty.
    std::vector<std::string> extensions;
};

// The extensions a user certificate of this provider carries: a terminal, port forwarding and agent forwarding, and
// neither X11 forwarding nor ~/.ssh/rc, which ssh-keygen's default adds.
std::vector<std::string> default_user_extensions();

// The certificate blob for `req`, signed by the Ed25519 key `ca`; empty with `err` when the subject key is of a
// type that has no certificate form or the signature fails.
std::string sign_cert(const cert_request& req, EVP_PKEY* ca, std::string& err);

struct cert
{
    std::string type;
    std::string nonce;
    // The subject's public key blob, rebuilt from the certificate's key fields.
    std::string subject_blob;
    uint64_t serial{0};
    cert_kind kind{cert_kind::user};
    std::string key_id;
    std::vector<std::string> principals;
    uint64_t valid_after{0};
    uint64_t valid_before{0};
    std::vector<std::pair<std::string, std::string>> critical_options;
    std::vector<std::pair<std::string, std::string>> extensions;
    std::string signature_key;
    std::string signature;
    // Every byte the signature covers.
    std::string signed_part;
};

// The fields of a certificate blob; false with `err` for anything truncated, trailing, or of an unknown type.
bool parse_cert(std::string_view blob, cert& out, std::string& err);

// Whether the certificate's signature is its signature key's, for an Ed25519 signature key.
bool verify_cert(const cert& c);

// A key revocation list (PROTOCOL.krl) revoking the certificates of the authority `ca_blob` by their serials, for
// sshd's RevokedKeys; `version` grows with each one written, and no serials makes a list revoking nothing.
std::string krl_of(std::string_view ca_blob, std::vector<uint64_t> serials, uint64_t version);

}   // namespace socketley::ssh
