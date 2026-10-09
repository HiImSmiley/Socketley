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
    // A user of the credentials file, which the IAM API keeps policies and a login profile for and nothing else.
    bool        external{false};
    // Its login profile: the password's hash as password_hash.h makes it, empty for none, whether the next sign-in
    // must set another, and when it was set.
    std::string password;
    bool        password_reset{false};
    int64_t     password_ms{0};
    // The secret of the key "~<name>" a password's sessions are sealed under and git's runs sign with, drawn with the
    // profile and kept while it is, so a new password ends the sessions by their time and not by a new secret.
    std::string login_secret;
    // Its tags, those under "socketley:" read by the runtime itself (the iam_tag_ names below).
    std::map<std::string, std::string> tags;
};

// The tags of a user the runtime reads: the name it is shown by, its email, the bytes its buckets may hold, and
// whether it may not sign in at all.
inline constexpr std::string_view iam_tag_display_name = "socketley:display-name";
inline constexpr std::string_view iam_tag_email = "socketley:email";
inline constexpr std::string_view iam_tag_max_bytes = "socketley:max-bytes";
inline constexpr std::string_view iam_tag_disabled = "socketley:disabled";
// The group whose members are admins, as a credentials file's `admin = true` makes one.
inline constexpr std::string_view iam_admins_group = "admins";
// The inline policy that lets a user of the web interface make libraries of its own: an IAM user makes a bucket only
// where a policy allows it, as S3 judges, and owns what it makes.
inline constexpr std::string_view iam_libraries_policy = "socketley-libraries";
inline constexpr std::string_view iam_libraries_doc =
    R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:CreateBucket","Resource":"*"}]})";

// An invitation to make oneself a user: listed and withdrawn by `id`, the first 16 hex digits of the SHA-256 of the
// token it was given as, which is all of it that is kept besides `hash`, that whole SHA-256.
struct iam_invite
{
    std::string id;
    std::string hash;
    int64_t     created_ms{0};
    int64_t     expires_ms{0};
    std::string by;
    bool        admin{false};
    uint64_t    max_bytes{0};
    // Whether the user it makes may make libraries.
    bool        libraries{true};
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
    std::map<std::string, iam_invite> invites;
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

// The runtime's own actions on the document, which no S3 request reaches: the web interface's invitations,
// socketley:CreateInvitation, ListInvitations, DeleteInvitation and AcceptInvitation. iam_apply runs them as any.
bool iam_own_action(std::string_view action);

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

// The resources an IAM request acts on, each after "arn:aws:iam::<account>:" as user/<path><name>, group/... or
// role/..., and one empty string for an action on none, such as ListUsers.
std::vector<std::string> iam_resources(const iam_state& s, std::string_view action, const iam_fields& fields);

// Whether the request would let some identity call IAM: a policy put or attached whose Allow names an IAM action, or
// a user added to a group that has one.
bool iam_grants_iam(const iam_state& s, std::string_view action, const iam_fields& fields);

// Whether a request that names no UserName acts on its caller's user, as IAM reads it.
bool iam_defaults_to_caller(std::string_view action);

// Whether a user may call `action` on itself without a policy that allows it: reading itself, its keys and tags, and
// changing its password and keys, which IAM's console lets every user do.
bool iam_self_service(std::string_view action);

// The users a request acts on, by name: the one it names, or the user of the key it names.
std::vector<std::string> iam_users_of(const iam_state& s, std::string_view action, const iam_fields& fields);

std::string iam_error_xml(std::string_view code, std::string_view message, std::string_view request_id);

}   // namespace socketley::storage
