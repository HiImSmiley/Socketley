#pragma once
// A bucket policy: S3's JSON document, checked and compiled once when it is set
// or read back at start, into statements a request is judged against with no
// parsing of the document, the request's keys read only for a statement that
// names them, and no syscall unless a statement names aws:SourceIp.
//
// What it takes is the subset that can be honoured exactly on this runtime:
// Allow and Deny, a principal that is everyone or this runtime's access keys,
// the actions the runtime implements, resources in this bucket, and conditions
// on the keys a request here carries.  Anything else is refused as
// MalformedPolicy, never accepted to do less than it says.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "s3_auth.h"

namespace socketley::storage
{

inline constexpr size_t policy_max_bytes = 20 * 1024;

// The actions a request can be, by the IAM name a policy gives them.
enum class s3_action : uint8_t
{
    none,
    get_object,
    put_object,
    delete_object,
    get_object_tagging,
    put_object_tagging,
    delete_object_tagging,
    abort_multipart_upload,
    list_multipart_upload_parts,
    list_bucket,
    list_bucket_multipart_uploads,
    get_bucket_location,
    create_bucket,
    delete_bucket,
    get_bucket_cors,
    put_bucket_cors,
    get_lifecycle_configuration,
    put_lifecycle_configuration,
    get_bucket_policy,
    put_bucket_policy,
    delete_bucket_policy,
    get_bucket_policy_status,
    // A request that names a version is checked as the action S3 has for it.
    get_object_version,
    delete_object_version,
    get_object_version_tagging,
    put_object_version_tagging,
    delete_object_version_tagging,
    list_bucket_versions,
    get_bucket_versioning,
    put_bucket_versioning,
    get_encryption_configuration,
    put_encryption_configuration,
    get_object_attributes,
    get_object_version_attributes,
    get_bucket_acl,
    put_bucket_acl,
    get_object_acl,
    put_object_acl,
    get_object_version_acl,
    put_object_version_acl,
    get_bucket_tagging,
    put_bucket_tagging,
    get_bucket_object_lock_configuration,
    put_bucket_object_lock_configuration,
    get_object_retention,
    put_object_retention,
    get_object_legal_hold,
    put_object_legal_hold,
    // Asked of a request that would go past a GOVERNANCE retention, beside the action it is.
    bypass_governance_retention,
    get_bucket_notification,
    put_bucket_notification,
    get_replication_configuration,
    put_replication_configuration,
    // A write or a delete marker another runtime's replication makes, which is asked instead of the plain action.
    replicate_object,
    replicate_delete,
    replicate_tags,
    get_bucket_website,
    put_bucket_website,
    delete_bucket_website,
    get_bucket_public_access_block,
    put_bucket_public_access_block,
    get_bucket_logging,
    put_bucket_logging,
    // ListBuckets, whose resource is every bucket of the account.
    list_all_my_buckets,
    count,
};
static_assert(static_cast<int>(s3_action::count) <= 64);

// The action an operation, by the name storage_run::operation_name gives it, is checked as.
s3_action action_of_operation(std::string_view operation);

// Whether the action acts on an object, whose resource is bucket/key, rather than on the bucket.
bool action_on_object(s3_action a);

// The action `a` is when the request names a version with ?versionId=, `a` itself when S3 has no other for it.
s3_action version_action(s3_action a);

// A client's address as a condition compares it: an IPv4 address mapped into
// IPv6 is the IPv4 address, and a unix socket has none.
struct client_ip
{
    uint8_t family{0};   // 0 for none, 4 or 6
    uint8_t addr[16]{};
};

// The address of the peer of a connected socket.
client_ip client_ip_of(int fd);

// What a request says to a condition key, which only the runtime that parsed it can tell.
class policy_context
{
public:
    virtual ~policy_context() = default;
    // The values of `key`, lowercase, for this request; false when the request has none.
    virtual bool values(std::string_view key, std::vector<std::string>& out) const = 0;
};

// One request as a policy sees it.
struct policy_request
{
    s3_action        action{s3_action::none};
    // The bucket it acts on, which only an identity policy's resources are matched against.
    std::string_view bucket;
    // The object's key, for an action on an object.
    std::string_view key;
    // The request carried no credentials.
    bool             anonymous{false};
    // The access key it was signed with.
    std::string_view principal;
    // The id of the user the key belongs to, empty for the runtime's one owner of a file without users.
    std::string_view user;
    bool             tls{false};
    const client_ip* ip{nullptr};
    // The keys are named in the body, so only a statement over every key in the bucket can allow it.
    bool             every_key{false};
    // The request's x-amz-server-side-encryption, which a condition finds absent when it was not sent.
    bool             sse_sent{false};
    std::string_view sse;
    // A part or the completion of an upload, whose encryption its creation chose and was judged on, so a
    // statement conditioned on the encryption is not about it.
    bool             sse_inherited{false};
    // Every other condition key, null when nothing can be asked, which leaves each key absent.
    const policy_context* ctx{nullptr};
};

enum class policy_effect : uint8_t
{
    none,
    allow,
    deny,
};

class bucket_policy
{
public:
    // False with a MalformedPolicy `err` for a document this runtime cannot honour exactly.
    static bool compile(std::string_view json, std::string_view bucket, bucket_policy& out, s3_error& err);
    // A user's identity policy, which names no principal and whose resources may be in any bucket.
    static bool compile_identity(std::string_view json, bucket_policy& out, s3_error& err);
    // A stored document that no longer compiles, which denies every request it is asked about.
    static bucket_policy refusing(std::string_view json, std::string why);

    // Deny when a Deny statement matches, else allow when an Allow does, else none.
    policy_effect evaluate(const policy_request& r) const;

    // Whether some statement denies, which is all a signed request is checked for.
    bool has_deny() const { return m_has_deny; }
    // Whether some statement compares the client's address, so the caller has to know it.
    bool needs_ip() const { return m_needs_ip; }
    // Whether an Allow lets everyone in without narrowing them to some addresses, as GetBucketPolicyStatus answers.
    bool is_public() const { return m_public; }
    // The document as it was given.
    const std::string& text() const { return m_text; }
    // Why a refusing policy refuses, empty for one that compiled.
    const std::string& broken() const { return m_broken; }

    struct cidr
    {
        uint8_t family{0};
        uint8_t addr[16]{};
        uint8_t bits{0};
    };
    struct key_pattern
    {
        enum class kind : uint8_t { all, exact, prefix, wild };
        kind        k{kind::all};
        std::string text;
    };
    // A condition on any key the compiler knows, its values ORed, every condition of a statement ANDed.
    struct condition
    {
        enum class op : uint8_t
        {
            str_eq, str_ne, str_eq_ci, str_ne_ci, str_like, str_not_like,
            num_eq, num_ne, num_lt, num_le, num_gt, num_ge,
            date_eq, date_ne, date_lt, date_le, date_gt, date_ge,
            boolean, null, ip, not_ip,
        };
        enum class set : uint8_t { single, any_value, all_values };
        op          o{op::str_eq};
        set         quantifier{set::single};
        bool        if_exists{false};
        std::string key;
        std::vector<std::string> values;
        std::vector<double>      numbers;
        std::vector<cidr>        cidrs;
    };
    struct statement
    {
        bool     deny{false};
        bool     any_principal{false};
        // Every request signed by any of this runtime's keys.
        bool     any_signed{false};
        std::vector<std::string> keys;
        uint64_t actions{0};
        bool     bucket_resource{false};
        std::vector<key_pattern> objects;
        // An identity policy's resources, each an ARN without "arn:aws:s3:::" matched as IAM matches it.
        std::vector<std::string> arns;
        bool     has_ip_in{false};
        std::vector<cidr> ip_in;
        bool     has_ip_out{false};
        std::vector<cidr> ip_out;
        // The values aws:SecureTransport may have for the statement to apply, both when it names none.
        bool     tls_true{true};
        bool     tls_false{true};
        // s3:x-amz-server-side-encryption under StringEquals and StringNotEquals, and Null on it: -1 for no
        // Null, 1 for a statement about requests that do not send it, 0 for ones that do.
        bool     has_sse_eq{false};
        std::vector<std::string> sse_eq;
        bool     has_sse_ne{false};
        std::vector<std::string> sse_ne;
        int8_t   sse_null{-1};
        bool sse_conditioned() const { return has_sse_eq || has_sse_ne || sse_null >= 0; }
        std::vector<condition> conds;
    };

private:
    // Whether the request's encryption is what the statement's conditions on it ask for.
    static bool sse_matches(const statement& s, const policy_request& r);
    // Whether every condition on the other keys holds for the request.
    static bool conditions_hold(const statement& s, const policy_request& r);
    static bool compile_doc(std::string_view json, std::string_view bucket, bool identity, bucket_policy& out,
                            s3_error& err);

    bool m_identity{false};

    std::string m_text;
    std::string m_broken;
    std::vector<statement> m_statements;
    bool m_has_deny{false};
    bool m_needs_ip{false};
    bool m_public{false};
};

}   // namespace socketley::storage
