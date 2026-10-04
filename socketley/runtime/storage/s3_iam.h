#pragma once
// The IAM a storage runtime answers itself: users with access keys, groups and roles, each with inline policies
// and attached managed ones, kept as one JSON document beside the buckets and read by every shard's
// authenticator next to the credentials file.  What the API does to that document is here, with no I/O.
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "s3_xml.h"

namespace socketley::storage
{

// The account every ARN names, empty since a runtime is one account and names none, as RGW writes them.
inline constexpr std::string_view iam_account = "";

struct iam_policies
{
    // Inline policies by name, as given.
    std::map<std::string, std::string> inline_docs;
    // Attached managed policies, by ARN.
    std::vector<std::string> attached;
};

struct iam_user
{
    std::string name;
    std::string id;
    std::string path{"/"};
    int64_t     created_ms{0};
    iam_policies policies;
    std::vector<std::string> groups;
    // A user of the credentials file, which the IAM API keeps policies for and nothing else.
    bool        external{false};
};

struct iam_key
{
    std::string access_key;
    std::string secret;
    std::string user;
    bool        active{true};
    int64_t     created_ms{0};
};

struct iam_group
{
    std::string name;
    std::string id;
    std::string path{"/"};
    int64_t     created_ms{0};
    iam_policies policies;
};

struct iam_role
{
    std::string name;
    std::string id;
    std::string path{"/"};
    int64_t     created_ms{0};
    std::string trust;
    std::string description;
    int64_t     max_session{3600};
    iam_policies policies;
};

struct iam_state
{
    std::map<std::string, iam_user>  users;
    std::map<std::string, iam_key>   keys;
    std::map<std::string, iam_group> groups;
    std::map<std::string, iam_role>  roles;
};

bool iam_parse(std::string_view json, iam_state& out, std::string& err);
std::string iam_json(const iam_state& s);

// The document of an AWS managed policy this runtime knows, null for any other ARN.
const char* iam_managed_policy(std::string_view arn);

// Every statement the user's own, attached and groups' policies hold, as one identity policy document; empty
// when it has none.
std::string iam_user_policy(const iam_state& s, const iam_user& u);
std::string iam_role_policy(const iam_role& r);

// Whether a role's trust policy lets the user `user_id` assume it.
bool iam_trusts(std::string_view trust, std::string_view user_id);

// The ARN of a role, and the name a role ARN or a bare name names.
std::string iam_role_arn(const iam_role& r);
std::string_view iam_role_name_of(std::string_view arn_or_name);

// Whether `action` is one of IAM's this runtime answers.
bool iam_action(std::string_view action);

// What an IAM request did: `xml` to answer with, or `err` with its status; `changed` when the state must be kept.
struct iam_result
{
    bool        ok{true};
    int         status{200};
    std::string code;
    std::string message;
    std::string xml;
    bool        changed{false};
};

using iam_fields = std::vector<std::pair<std::string, std::string>>;

// Runs `action` with `fields` on `s` at `now_ms`; `taken(id)` says whether a user id is already the credentials
// file's, so the API makes none of the same name.
iam_result iam_apply(iam_state& s, std::string_view action, const iam_fields& fields, int64_t now_ms,
                     std::string_view request_id, bool (*taken)(void*, std::string_view), void* taken_ctx);

std::string iam_error_xml(std::string_view code, std::string_view message, std::string_view request_id);

}   // namespace socketley::storage
