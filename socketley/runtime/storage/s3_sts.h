#pragma once
// Temporary credentials as STS gives them out: an access key, a secret and a session token that carries who they
// were given to, until when and under what policy, sealed with the secret of the key that asked so that any shard
// and any restart can check them with nothing kept.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::storage
{

// What a session token says.
struct session_grant
{
    // The long-term key the session was asked for with, whose secret seals the token.
    std::string parent_key;
    std::string access_key;
    // Unix seconds.
    int64_t     expires{0};
    // The session policy, empty for none.
    std::string policy;
};

// The most a session policy may hold, as STS bounds a packed one.
inline constexpr size_t sts_policy_max = 2048;

// A fresh temporary access key, ASIA and sixteen base32 characters.
std::string sts_new_access_key();
// The token for `g`, sealed with `parent_secret`.
std::string sts_token(const session_grant& g, std::string_view parent_secret);
// What `token` says, without checking its seal; false for one that is not a token.
bool sts_parse(std::string_view token, session_grant& out);
// Whether `token` was sealed with `parent_secret`.
bool sts_sealed_by(std::string_view token, std::string_view parent_secret);
// The secret that signs for the session `g`, which only the holder of `parent_secret` can derive.
std::string sts_secret(const session_grant& g, std::string_view parent_secret);

// The fields of an application/x-www-form-urlencoded body or a query; false for one that does not decode.
bool parse_form_fields(std::string_view text, std::vector<std::pair<std::string, std::string>>& out);

// STS's answer to GetSessionToken or AssumeRole, `action` naming which.
std::string sts_credentials_xml(std::string_view action, std::string_view access_key, std::string_view secret,
                                std::string_view token, int64_t expires, std::string_view role_arn,
                                std::string_view session_name, std::string_view request_id);
// STS's error document.
std::string sts_error_xml(std::string_view code, std::string_view message, std::string_view request_id);

}   // namespace socketley::storage
