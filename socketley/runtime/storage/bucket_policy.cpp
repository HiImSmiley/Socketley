#include "bucket_policy.h"
#include "json_doc.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <utility>

namespace socketley::storage
{

namespace
{

// ─── Matching ───────────────────────────────────────────────────────────────

char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

// IAM's wildcard: '*' is any run of characters, '?' is one, and nothing else is special.
bool wild_match(std::string_view pat, std::string_view str, bool fold)
{
    constexpr size_t none = static_cast<size_t>(-1);
    size_t pi = 0, si = 0, star = none, star_si = 0;
    while (si < str.size())
    {
        if (pi < pat.size() && pat[pi] == '*')
        {
            star    = pi++;
            star_si = si;
            continue;
        }
        if (pi < pat.size() && (pat[pi] == '?' || (fold ? lower(pat[pi]) == lower(str[si]) : pat[pi] == str[si])))
        {
            ++pi;
            ++si;
            continue;
        }
        if (star == none)
            return false;
        pi = star + 1;
        si = ++star_si;
    }
    while (pi < pat.size() && pat[pi] == '*')
        ++pi;
    return pi == pat.size();
}

bool key_matches(const bucket_policy::key_pattern& p, std::string_view key)
{
    using k = bucket_policy::key_pattern::kind;
    switch (p.k)
    {
        case k::all:    return true;
        case k::exact:  return key == p.text;
        case k::prefix: return key.starts_with(p.text);
        case k::wild:   return wild_match(p.text, key, false);
    }
    return false;
}

bool cidr_matches(const bucket_policy::cidr& c, const client_ip& ip)
{
    if (ip.family != c.family)
        return false;
    const uint8_t full = c.bits / 8;
    if (std::memcmp(c.addr, ip.addr, full) != 0)
        return false;
    const uint8_t rest = c.bits % 8;
    if (rest == 0)
        return true;
    const uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rest));
    return (c.addr[full] & mask) == (ip.addr[full] & mask);
}

bool any_cidr(const std::vector<bucket_policy::cidr>& list, const client_ip* ip)
{
    if (!ip || ip->family == 0)
        return false;
    for (const auto& c : list)
        if (cidr_matches(c, *ip))
            return true;
    return false;
}

// Whether an identity policy's resource pattern names what `r` acts on: its bucket, or bucket/key for an object.
bool arn_covers(std::string_view pat, const policy_request& r, bool object, bool deny)
{
    if (!object)
        return wild_match(pat, r.bucket, false);
    std::string res;
    res.reserve(r.bucket.size() + 1 + r.key.size());
    res.append(r.bucket).push_back('/');
    if (!r.every_key)
        return wild_match(pat, res.append(r.key), false);
    // Keys named in the body: an Allow has to cover every key of the bucket, which a trailing '*' after it does.
    if (!deny)
        return pat.ends_with('*') && wild_match(pat, res, false);
    // A Deny over any key the body could name refuses them all.
    const std::string_view lit = pat.substr(0, pat.find_first_of("*?"));
    if (lit.size() == pat.size())
        return lit.starts_with(res);
    return lit.starts_with(res) || std::string_view(res).starts_with(lit);
}

// ─── The actions ────────────────────────────────────────────────────────────

enum class res_kind : uint8_t { object, bucket, service };

struct action_name
{
    std::string_view name;
    res_kind         kind;
    s3_action        action;
};

// Every S3 action a policy may name: those this runtime implements, and the
// rest of S3's, which are taken so a policy written for S3 is not refused and
// which match no request here.
constexpr action_name action_names[] = {
    {"GetObject", res_kind::object, s3_action::get_object},
    {"PutObject", res_kind::object, s3_action::put_object},
    {"DeleteObject", res_kind::object, s3_action::delete_object},
    {"GetObjectTagging", res_kind::object, s3_action::get_object_tagging},
    {"PutObjectTagging", res_kind::object, s3_action::put_object_tagging},
    {"DeleteObjectTagging", res_kind::object, s3_action::delete_object_tagging},
    {"AbortMultipartUpload", res_kind::object, s3_action::abort_multipart_upload},
    {"ListMultipartUploadParts", res_kind::object, s3_action::list_multipart_upload_parts},
    {"ListBucket", res_kind::bucket, s3_action::list_bucket},
    {"ListBucketMultipartUploads", res_kind::bucket, s3_action::list_bucket_multipart_uploads},
    {"GetBucketLocation", res_kind::bucket, s3_action::get_bucket_location},
    {"CreateBucket", res_kind::bucket, s3_action::create_bucket},
    {"DeleteBucket", res_kind::bucket, s3_action::delete_bucket},
    {"GetBucketCORS", res_kind::bucket, s3_action::get_bucket_cors},
    {"PutBucketCORS", res_kind::bucket, s3_action::put_bucket_cors},
    {"GetLifecycleConfiguration", res_kind::bucket, s3_action::get_lifecycle_configuration},
    {"PutLifecycleConfiguration", res_kind::bucket, s3_action::put_lifecycle_configuration},
    {"GetBucketPolicy", res_kind::bucket, s3_action::get_bucket_policy},
    {"PutBucketPolicy", res_kind::bucket, s3_action::put_bucket_policy},
    {"DeleteBucketPolicy", res_kind::bucket, s3_action::delete_bucket_policy},
    {"GetBucketPolicyStatus", res_kind::bucket, s3_action::get_bucket_policy_status},

    {"ListAllMyBuckets", res_kind::service, s3_action::none},
    {"GetObjectVersion", res_kind::object, s3_action::get_object_version},
    {"GetObjectAcl", res_kind::object, s3_action::get_object_acl},
    {"PutObjectAcl", res_kind::object, s3_action::put_object_acl},
    {"GetObjectVersionAcl", res_kind::object, s3_action::get_object_version_acl},
    {"PutObjectVersionAcl", res_kind::object, s3_action::put_object_version_acl},
    {"DeleteObjectVersion", res_kind::object, s3_action::delete_object_version},
    {"GetObjectVersionTagging", res_kind::object, s3_action::get_object_version_tagging},
    {"PutObjectVersionTagging", res_kind::object, s3_action::put_object_version_tagging},
    {"DeleteObjectVersionTagging", res_kind::object, s3_action::delete_object_version_tagging},
    {"GetObjectAttributes", res_kind::object, s3_action::get_object_attributes},
    {"GetObjectVersionAttributes", res_kind::object, s3_action::get_object_version_attributes},
    {"GetObjectRetention", res_kind::object, s3_action::get_object_retention},
    {"PutObjectRetention", res_kind::object, s3_action::put_object_retention},
    {"GetObjectLegalHold", res_kind::object, s3_action::get_object_legal_hold},
    {"PutObjectLegalHold", res_kind::object, s3_action::put_object_legal_hold},
    {"BypassGovernanceRetention", res_kind::object, s3_action::bypass_governance_retention},
    {"RestoreObject", res_kind::object, s3_action::none},
    {"GetObjectTorrent", res_kind::object, s3_action::none},
    {"GetObjectVersionTorrent", res_kind::object, s3_action::none},
    {"ReplicateObject", res_kind::object, s3_action::replicate_object},
    {"ReplicateDelete", res_kind::object, s3_action::replicate_delete},
    {"ReplicateTags", res_kind::object, s3_action::replicate_tags},
    {"ListBucketVersions", res_kind::bucket, s3_action::list_bucket_versions},
    {"GetBucketAcl", res_kind::bucket, s3_action::get_bucket_acl},
    {"PutBucketAcl", res_kind::bucket, s3_action::put_bucket_acl},
    {"GetBucketVersioning", res_kind::bucket, s3_action::get_bucket_versioning},
    {"PutBucketVersioning", res_kind::bucket, s3_action::put_bucket_versioning},
    {"GetBucketTagging", res_kind::bucket, s3_action::get_bucket_tagging},
    {"PutBucketTagging", res_kind::bucket, s3_action::put_bucket_tagging},
    {"GetBucketWebsite", res_kind::bucket, s3_action::get_bucket_website},
    {"PutBucketWebsite", res_kind::bucket, s3_action::put_bucket_website},
    {"DeleteBucketWebsite", res_kind::bucket, s3_action::delete_bucket_website},
    {"GetBucketNotification", res_kind::bucket, s3_action::get_bucket_notification},
    {"PutBucketNotification", res_kind::bucket, s3_action::put_bucket_notification},
    {"GetBucketLogging", res_kind::bucket, s3_action::get_bucket_logging},
    {"PutBucketLogging", res_kind::bucket, s3_action::put_bucket_logging},
    {"GetEncryptionConfiguration", res_kind::bucket, s3_action::get_encryption_configuration},
    {"PutEncryptionConfiguration", res_kind::bucket, s3_action::put_encryption_configuration},
    {"GetReplicationConfiguration", res_kind::bucket, s3_action::get_replication_configuration},
    {"PutReplicationConfiguration", res_kind::bucket, s3_action::put_replication_configuration},
    {"GetBucketObjectLockConfiguration", res_kind::bucket, s3_action::get_bucket_object_lock_configuration},
    {"PutBucketObjectLockConfiguration", res_kind::bucket, s3_action::put_bucket_object_lock_configuration},
    {"GetBucketPublicAccessBlock", res_kind::bucket, s3_action::get_bucket_public_access_block},
    {"PutBucketPublicAccessBlock", res_kind::bucket, s3_action::put_bucket_public_access_block},
    {"GetBucketOwnershipControls", res_kind::bucket, s3_action::none},
    {"PutBucketOwnershipControls", res_kind::bucket, s3_action::none},
    {"GetAccelerateConfiguration", res_kind::bucket, s3_action::none},
    {"PutAccelerateConfiguration", res_kind::bucket, s3_action::none},
    {"GetBucketRequestPayment", res_kind::bucket, s3_action::none},
    {"PutBucketRequestPayment", res_kind::bucket, s3_action::none},
    {"GetAnalyticsConfiguration", res_kind::bucket, s3_action::none},
    {"PutAnalyticsConfiguration", res_kind::bucket, s3_action::none},
    {"GetMetricsConfiguration", res_kind::bucket, s3_action::none},
    {"PutMetricsConfiguration", res_kind::bucket, s3_action::none},
    {"GetInventoryConfiguration", res_kind::bucket, s3_action::none},
    {"PutInventoryConfiguration", res_kind::bucket, s3_action::none},
    {"GetIntelligentTieringConfiguration", res_kind::bucket, s3_action::none},
    {"PutIntelligentTieringConfiguration", res_kind::bucket, s3_action::none},
};

uint64_t action_bit(s3_action a)
{
    return uint64_t{1} << static_cast<unsigned>(a);
}

// ─── Compiling ──────────────────────────────────────────────────────────────

constexpr std::string_view s3_arn = "arn:aws:s3:::";

struct compiler
{
    std::string_view bucket;
    s3_error&        err;
    bool             identity{false};

    bool fail(std::string message)
    {
        err = {"MalformedPolicy", std::move(message), 400};
        return false;
    }

    // A field that may be one string or a list of them, as Action, Resource and a condition's values may.
    bool strings(const jvalue& v, std::string_view field, std::vector<std::string>& out)
    {
        if (v.k == jvalue::kind::string)
        {
            out.push_back(v.s);
            return true;
        }
        if (v.k != jvalue::kind::array || v.items.empty())
            return fail(std::string(field) + " must be a string or a non-empty list of strings");
        for (const jvalue& i : v.items)
        {
            if (i.k != jvalue::kind::string)
                return fail(std::string(field) + " must be a string or a non-empty list of strings");
            out.push_back(i.s);
        }
        return true;
    }

    bool principal(const jvalue& v, bucket_policy::statement& s)
    {
        if (v.k == jvalue::kind::string)
        {
            if (v.s != "*")
                return fail("Invalid principal in policy: a principal is \"*\" or {\"AWS\": ...}");
            s.any_principal = true;
            return true;
        }
        if (v.k != jvalue::kind::object || v.members.empty())
            return fail("Invalid principal in policy");
        for (const auto& [name, val] : v.members)
        {
            if (name != "AWS")
                return fail("Invalid principal in policy: only AWS principals are supported, not " + name);
            std::vector<std::string> list;
            if (!strings(val, "Principal", list))
                return false;
            for (const std::string& p : list)
                if (!aws_principal(p, s))
                    return false;
        }
        return true;
    }

    // "*", an access key of this runtime, or an IAM ARN it maps onto one.
    bool aws_principal(std::string_view p, bucket_policy::statement& s)
    {
        if (p == "*")
        {
            s.any_principal = true;
            return true;
        }
        if (!p.starts_with("arn:"))
        {
            if (p.empty() || p.size() > 127 || p.find_first_of(" /:=,*?") != std::string_view::npos)
                return fail("Invalid principal in policy: " + std::string(p));
            s.keys.emplace_back(p);
            return true;
        }
        // arn:aws:iam::<account>:root is the account, which here is every key; :user/<name> is the key <name>.
        constexpr std::string_view iam = "arn:aws:iam::";
        if (!p.starts_with(iam))
            return fail("Invalid principal in policy: " + std::string(p));
        std::string_view rest = p.substr(iam.size());
        const size_t colon = rest.find(':');
        if (colon == std::string_view::npos)
            return fail("Invalid principal in policy: " + std::string(p));
        rest.remove_prefix(colon + 1);
        if (rest == "root")
        {
            s.any_signed = true;
            return true;
        }
        if (rest.starts_with("user/"))
        {
            std::string_view name = rest.substr(rest.rfind('/') + 1);
            if (name.empty() || name.size() > 127 || name.find_first_of(" :=,*?") != std::string_view::npos)
                return fail("Invalid principal in policy: " + std::string(p));
            s.keys.emplace_back(name);
            return true;
        }
        return fail("Invalid principal in policy: " + std::string(p) + " (a user or the account root only)");
    }

    bool actions(const jvalue& v, bucket_policy::statement& s, bool& on_object, bool& on_bucket)
    {
        std::vector<std::string> list;
        if (!strings(v, "Action", list))
            return false;
        for (const std::string& a : list)
        {
            std::string_view pat = a;
            if (pat != "*")
            {
                if (pat.size() < 3 || lower(pat[0]) != 's' || pat[1] != '3' || pat[2] != ':')
                    return fail("Policy has invalid action: " + a);
                pat.remove_prefix(3);
            }
            bool any = false;
            for (const action_name& n : action_names)
            {
                if (!wild_match(pat, n.name, true))
                    continue;
                any = true;
                if (n.action != s3_action::none)
                    s.actions |= action_bit(n.action);
                on_object = on_object || n.kind == res_kind::object;
                on_bucket = on_bucket || n.kind == res_kind::bucket;
            }
            if (!any)
                return fail("Policy has invalid action: " + a);
        }
        return true;
    }

    bool resources(const jvalue& v, bucket_policy::statement& s)
    {
        std::vector<std::string> list;
        if (!strings(v, "Resource", list))
            return false;
        for (const std::string& r : list)
        {
            std::string_view rv = r;
            if (identity && rv == "*")
            {
                s.arns.emplace_back("*");
                continue;
            }
            if (!rv.starts_with(s3_arn))
                return fail("Policy has invalid resource: " + r);
            rv.remove_prefix(s3_arn.size());
            if (rv.find("${") != std::string_view::npos)
                return fail("Policy has invalid resource: policy variables are not supported: " + r);
            if (identity)
            {
                if (rv.empty())
                    return fail("Policy has invalid resource: " + r);
                s.arns.emplace_back(rv);
                continue;
            }
            if (rv == bucket)
            {
                s.bucket_resource = true;
                continue;
            }
            if (!rv.starts_with(bucket) || rv.size() <= bucket.size() || rv[bucket.size()] != '/')
                return fail("Policy has invalid resource: " + r + " is not this bucket or an object in it");
            rv.remove_prefix(bucket.size() + 1);
            bucket_policy::key_pattern kp;
            kp.text = std::string(rv);
            const size_t wild = rv.find_first_of("*?");
            using k = bucket_policy::key_pattern::kind;
            if (rv == "*")
                kp.k = k::all;
            else if (wild == std::string_view::npos)
                kp.k = k::exact;
            else if (wild == rv.size() - 1 && rv.back() == '*')
            {
                kp.k = k::prefix;
                kp.text.pop_back();
            }
            else
                kp.k = k::wild;
            s.objects.push_back(std::move(kp));
        }
        return true;
    }

    bool parse_cidr(std::string_view text, bucket_policy::cidr& c)
    {
        std::string addr(text);
        int bits = -1;
        if (const size_t slash = addr.find('/'); slash != std::string::npos)
        {
            const std::string_view b = std::string_view(addr).substr(slash + 1);
            if (b.empty() || b.size() > 3)
                return false;
            bits = 0;
            for (char ch : b)
            {
                if (ch < '0' || ch > '9')
                    return false;
                bits = bits * 10 + (ch - '0');
            }
            addr.resize(slash);
        }
        if (::inet_pton(AF_INET, addr.c_str(), c.addr) == 1)
        {
            c.family = 4;
            if (bits > 32)
                return false;
            c.bits = static_cast<uint8_t>(bits < 0 ? 32 : bits);
            return true;
        }
        if (::inet_pton(AF_INET6, addr.c_str(), c.addr) == 1)
        {
            c.family = 6;
            if (bits > 128)
                return false;
            c.bits = static_cast<uint8_t>(bits < 0 ? 128 : bits);
            // An IPv4 address written as IPv6 is compared as IPv4, as the client's own address is.
            static constexpr uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
            if (std::memcmp(c.addr, mapped, 12) == 0 && c.bits >= 96)
            {
                std::memmove(c.addr, c.addr + 12, 4);
                std::memset(c.addr + 4, 0, 12);
                c.family = 4;
                c.bits   = static_cast<uint8_t>(c.bits - 96);
            }
            return true;
        }
        return false;
    }

    // The one key an operator takes here, compared without case as IAM compares condition keys.
    bool only_key(const jvalue& block, std::string_view op, std::string_view key, const jvalue*& val)
    {
        if (block.k != jvalue::kind::object || block.members.size() != 1)
            return fail("Condition " + std::string(op) + " must name exactly one key, " + std::string(key));
        const std::string& name = block.members[0].first;
        bool same = name.size() == key.size();
        for (size_t i = 0; same && i < key.size(); ++i)
            same = lower(name[i]) == lower(key[i]);
        if (!same)
            return fail("Condition key " + name + " is not supported with " + std::string(op) +
                        " (only " + std::string(key) + ")");
        val = &block.members[0].second;
        return true;
    }

    static constexpr std::string_view sse_key = "s3:x-amz-server-side-encryption";

    bool condition(const jvalue& v, bucket_policy::statement& s)
    {
        if (v.k != jvalue::kind::object)
            return fail("Condition must be an object");
        for (const auto& [op, block] : v.members)
        {
            const jvalue* val = nullptr;
            if (op == "IpAddress" || op == "NotIpAddress")
            {
                if (!only_key(block, op, "aws:SourceIp", val))
                    return false;
                std::vector<std::string> list;
                if (!strings(*val, "aws:SourceIp", list))
                    return false;
                std::vector<bucket_policy::cidr>& into = op == "IpAddress" ? s.ip_in : s.ip_out;
                for (const std::string& t : list)
                {
                    bucket_policy::cidr c;
                    if (!parse_cidr(t, c))
                        return fail("Invalid IP address or CIDR in aws:SourceIp: " + t);
                    into.push_back(c);
                }
                (op == "IpAddress" ? s.has_ip_in : s.has_ip_out) = true;
                continue;
            }
            if (op == "Bool")
            {
                if (!only_key(block, op, "aws:SecureTransport", val))
                    return false;
                std::vector<std::string> list;
                if (val->k == jvalue::kind::boolean)
                    list.push_back(val->b ? "true" : "false");
                else if (!strings(*val, "aws:SecureTransport", list))
                    return false;
                s.tls_true = s.tls_false = false;
                for (const std::string& t : list)
                {
                    if (t == "true")
                        s.tls_true = true;
                    else if (t == "false")
                        s.tls_false = true;
                    else
                        return fail("aws:SecureTransport takes \"true\" or \"false\", not " + t);
                }
                continue;
            }
            if (op == "StringEquals" || op == "StringNotEquals")
            {
                if (!only_key(block, op, sse_key, val))
                    return false;
                std::vector<std::string>& into = op == "StringEquals" ? s.sse_eq : s.sse_ne;
                if (!strings(*val, sse_key, into))
                    return false;
                (op == "StringEquals" ? s.has_sse_eq : s.has_sse_ne) = true;
                continue;
            }
            if (op == "Null")
            {
                if (!only_key(block, op, sse_key, val))
                    return false;
                std::vector<std::string> list;
                if (val->k == jvalue::kind::boolean)
                    list.push_back(val->b ? "true" : "false");
                else if (!strings(*val, sse_key, list))
                    return false;
                bool absent = false, present = false;
                for (const std::string& t : list)
                {
                    if (t == "true")
                        absent = true;
                    else if (t == "false")
                        present = true;
                    else
                        return fail("Null takes \"true\" or \"false\", not " + t);
                }
                // Both values are every request, which is no condition at all.
                s.sse_null = absent && present ? -1 : absent ? 1 : 0;
                continue;
            }
            return fail("Condition operator " + op +
                        " is not supported (only IpAddress and NotIpAddress on aws:SourceIp, Bool on "
                        "aws:SecureTransport, and StringEquals, StringNotEquals and Null on "
                        "s3:x-amz-server-side-encryption)");
        }
        return true;
    }

    bool statement(const jvalue& v, bucket_policy::statement& s, std::vector<std::string>& sids)
    {
        if (v.k != jvalue::kind::object)
            return fail("A statement must be an object");
        const jvalue* effect = nullptr;
        const jvalue* who    = nullptr;
        const jvalue* action = nullptr;
        const jvalue* res    = nullptr;
        const jvalue* cond   = nullptr;
        for (const auto& [name, val] : v.members)
        {
            if (name == "Sid")
            {
                if (val.k != jvalue::kind::string)
                    return fail("Sid must be a string");
                for (const std::string& seen : sids)
                    if (!val.s.empty() && seen == val.s)
                        return fail("Statement IDs (SID) must be unique: " + val.s);
                sids.push_back(val.s);
            }
            else if (name == "Effect")
                effect = &val;
            else if (name == "Principal")
                who = &val;
            else if (name == "Action")
                action = &val;
            else if (name == "Resource")
                res = &val;
            else if (name == "Condition")
                cond = &val;
            else if (name == "NotPrincipal" || name == "NotAction" || name == "NotResource")
                return fail(name + " is not supported");
            else
                return fail("Unknown field " + name);
        }
        if (!effect)
            return fail("Missing required field Effect");
        if (identity && who)
            return fail("Policy document should not specify a principal");
        if (!identity && !who)
            return fail("Missing required field Principal");
        if (!action)
            return fail("Missing required field Action");
        if (!res)
            return fail("Missing required field Resource");
        if (effect->k != jvalue::kind::string || (effect->s != "Allow" && effect->s != "Deny"))
            return fail("Invalid effect: Effect is Allow or Deny");
        s.deny = effect->s == "Deny";
        bool on_object = false, on_bucket = false;
        if ((who && !principal(*who, s)) || !actions(*action, s, on_object, on_bucket) || !resources(*res, s))
            return false;
        if (!identity && !(on_object && !s.objects.empty()) && !(on_bucket && s.bucket_resource))
            return fail("Action does not apply to any resource(s) in statement");
        return !cond || condition(*cond, s);
    }
};

}   // namespace

// ─── The interface ──────────────────────────────────────────────────────────

s3_action action_of_operation(std::string_view op)
{
    struct row { std::string_view op; s3_action a; };
    static constexpr row table[] = {
        {"GetObject", s3_action::get_object},
        {"HeadObject", s3_action::get_object},
        {"GetObjectAttributes", s3_action::get_object_attributes},
        {"GetBucketAcl", s3_action::get_bucket_acl},
        {"GetBucketTagging", s3_action::get_bucket_tagging},
        {"PutBucketTagging", s3_action::put_bucket_tagging},
        {"DeleteBucketTagging", s3_action::put_bucket_tagging},
        {"PutBucketAcl", s3_action::put_bucket_acl},
        {"GetObjectAcl", s3_action::get_object_acl},
        {"PutObjectAcl", s3_action::put_object_acl},
        {"PutObject", s3_action::put_object},
        {"CopyObject", s3_action::put_object},
        {"UploadPart", s3_action::put_object},
        {"UploadPartCopy", s3_action::put_object},
        {"CreateMultipartUpload", s3_action::put_object},
        {"CompleteMultipartUpload", s3_action::put_object},
        {"DeleteObject", s3_action::delete_object},
        {"DeleteObjects", s3_action::delete_object},
        {"AbortMultipartUpload", s3_action::abort_multipart_upload},
        {"ListParts", s3_action::list_multipart_upload_parts},
        {"GetObjectTagging", s3_action::get_object_tagging},
        {"PutObjectTagging", s3_action::put_object_tagging},
        {"DeleteObjectTagging", s3_action::delete_object_tagging},
        {"ListObjects", s3_action::list_bucket},
        {"ListObjectsV2", s3_action::list_bucket},
        {"HeadBucket", s3_action::list_bucket},
        {"ListMultipartUploads", s3_action::list_bucket_multipart_uploads},
        {"GetBucketLocation", s3_action::get_bucket_location},
        {"CreateBucket", s3_action::create_bucket},
        {"DeleteBucket", s3_action::delete_bucket},
        {"GetBucketCors", s3_action::get_bucket_cors},
        {"PutBucketCors", s3_action::put_bucket_cors},
        {"DeleteBucketCors", s3_action::put_bucket_cors},
        {"GetBucketLifecycleConfiguration", s3_action::get_lifecycle_configuration},
        {"PutBucketLifecycleConfiguration", s3_action::put_lifecycle_configuration},
        {"DeleteBucketLifecycle", s3_action::put_lifecycle_configuration},
        {"GetBucketPolicy", s3_action::get_bucket_policy},
        {"PutBucketPolicy", s3_action::put_bucket_policy},
        {"DeleteBucketPolicy", s3_action::delete_bucket_policy},
        {"GetBucketPolicyStatus", s3_action::get_bucket_policy_status},
        {"GetBucketVersioning", s3_action::get_bucket_versioning},
        {"PutBucketVersioning", s3_action::put_bucket_versioning},
        {"ListObjectVersions", s3_action::list_bucket_versions},
        {"GetBucketEncryption", s3_action::get_encryption_configuration},
        {"PutBucketEncryption", s3_action::put_encryption_configuration},
        {"DeleteBucketEncryption", s3_action::put_encryption_configuration},
        {"GetObjectLockConfiguration", s3_action::get_bucket_object_lock_configuration},
        {"PutObjectLockConfiguration", s3_action::put_bucket_object_lock_configuration},
        {"GetObjectRetention", s3_action::get_object_retention},
        {"PutObjectRetention", s3_action::put_object_retention},
        {"GetObjectLegalHold", s3_action::get_object_legal_hold},
        {"PutObjectLegalHold", s3_action::put_object_legal_hold},
        {"GetBucketNotificationConfiguration", s3_action::get_bucket_notification},
        {"PutBucketNotificationConfiguration", s3_action::put_bucket_notification},
        {"GetBucketWebsite", s3_action::get_bucket_website},
        {"PutBucketWebsite", s3_action::put_bucket_website},
        {"DeleteBucketWebsite", s3_action::delete_bucket_website},
        {"GetPublicAccessBlock", s3_action::get_bucket_public_access_block},
        {"GetBucketLogging", s3_action::get_bucket_logging},
        {"PutBucketLogging", s3_action::put_bucket_logging},
        {"PutPublicAccessBlock", s3_action::put_bucket_public_access_block},
        {"DeletePublicAccessBlock", s3_action::put_bucket_public_access_block},
        {"GetBucketReplication", s3_action::get_replication_configuration},
        {"PutBucketReplication", s3_action::put_replication_configuration},
        {"DeleteBucketReplication", s3_action::put_replication_configuration},
    };
    for (const row& r : table)
        if (r.op == op)
            return r.a;
    return s3_action::none;
}

bool action_on_object(s3_action a)
{
    switch (a)
    {
        case s3_action::get_object:
        case s3_action::put_object:
        case s3_action::delete_object:
        case s3_action::get_object_tagging:
        case s3_action::put_object_tagging:
        case s3_action::delete_object_tagging:
        case s3_action::abort_multipart_upload:
        case s3_action::list_multipart_upload_parts:
        case s3_action::get_object_version:
        case s3_action::delete_object_version:
        case s3_action::get_object_version_tagging:
        case s3_action::put_object_version_tagging:
        case s3_action::delete_object_version_tagging:
        case s3_action::get_object_attributes:
        case s3_action::get_object_version_attributes:
        case s3_action::get_object_acl:
        case s3_action::put_object_acl:
        case s3_action::get_object_version_acl:
        case s3_action::put_object_version_acl:
        case s3_action::get_object_retention:
        case s3_action::put_object_retention:
        case s3_action::get_object_legal_hold:
        case s3_action::put_object_legal_hold:
        case s3_action::bypass_governance_retention:
        case s3_action::replicate_object:
        case s3_action::replicate_delete:
        case s3_action::replicate_tags:
            return true;
        default:
            return false;
    }
}

s3_action version_action(s3_action a)
{
    switch (a)
    {
        case s3_action::get_object:            return s3_action::get_object_version;
        case s3_action::delete_object:         return s3_action::delete_object_version;
        case s3_action::get_object_tagging:    return s3_action::get_object_version_tagging;
        case s3_action::put_object_tagging:    return s3_action::put_object_version_tagging;
        case s3_action::delete_object_tagging: return s3_action::delete_object_version_tagging;
        case s3_action::get_object_attributes: return s3_action::get_object_version_attributes;
        case s3_action::get_object_acl:        return s3_action::get_object_version_acl;
        case s3_action::put_object_acl:        return s3_action::put_object_version_acl;
        default:                               return a;
    }
}

client_ip client_ip_of(int fd)
{
    client_ip ip;
    struct sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (fd < 0 || ::getpeername(fd, reinterpret_cast<struct sockaddr*>(&ss), &len) != 0)
        return ip;
    if (ss.ss_family == AF_INET)
    {
        ip.family = 4;
        std::memcpy(ip.addr, &reinterpret_cast<const struct sockaddr_in*>(&ss)->sin_addr, 4);
    }
    else if (ss.ss_family == AF_INET6)
    {
        const auto* a = reinterpret_cast<const struct sockaddr_in6*>(&ss);
        if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr))
        {
            ip.family = 4;
            std::memcpy(ip.addr, reinterpret_cast<const uint8_t*>(&a->sin6_addr) + 12, 4);
        }
        else
        {
            ip.family = 6;
            std::memcpy(ip.addr, &a->sin6_addr, 16);
        }
    }
    return ip;
}

bool bucket_policy::compile(std::string_view json, std::string_view bucket, bucket_policy& out, s3_error& err)
{
    return compile_doc(json, bucket, false, out, err);
}

bool bucket_policy::compile_identity(std::string_view json, bucket_policy& out, s3_error& err)
{
    return compile_doc(json, {}, true, out, err);
}

bool bucket_policy::compile_doc(std::string_view json, std::string_view bucket, bool identity, bucket_policy& out,
                                s3_error& err)
{
    compiler cc{bucket, err, identity};
    if (json.size() > policy_max_bytes)
        return cc.fail("Policy exceeds the maximum allowed document size of 20 KiB");
    jvalue doc;
    if (!json_reader(json).document(doc))
        return cc.fail("Policies must be valid JSON and the first byte must be '{'");

    const jvalue* statements = nullptr;
    for (const auto& [name, val] : doc.members)
    {
        if (name == "Version")
        {
            if (val.k != jvalue::kind::string || (val.s != "2012-10-17" && val.s != "2008-10-17"))
                return cc.fail("The policy Version is 2012-10-17 or 2008-10-17");
        }
        else if (name == "Id")
        {
            if (val.k != jvalue::kind::string)
                return cc.fail("Id must be a string");
        }
        else if (name == "Statement")
            statements = &val;
        else
            return cc.fail("Unknown field " + name);
    }
    if (!statements)
        return cc.fail("Missing required field Statement");

    bucket_policy p;
    std::vector<std::string> sids;
    auto take = [&](const jvalue& v)
    {
        statement s;
        if (!cc.statement(v, s, sids))
            return false;
        p.m_has_deny = p.m_has_deny || s.deny;
        p.m_needs_ip = p.m_needs_ip || s.has_ip_in || s.has_ip_out;
        bool open_cidr = !s.has_ip_in;
        for (const cidr& c : s.ip_in)
            open_cidr = open_cidr || c.bits == 0;
        p.m_public = p.m_public || (!s.deny && s.any_principal && s.actions != 0 && open_cidr);
        p.m_statements.push_back(std::move(s));
        return true;
    };
    if (statements->k == jvalue::kind::object)
    {
        if (!take(*statements))
            return false;
    }
    else if (statements->k == jvalue::kind::array && !statements->items.empty())
    {
        for (const jvalue& v : statements->items)
            if (!take(v))
                return false;
    }
    else
        return cc.fail("Statement must be a statement or a non-empty list of them");

    p.m_text     = std::string(json);
    p.m_identity = identity;
    out = std::move(p);
    return true;
}

bool bucket_policy::sse_matches(const statement& s, const policy_request& r)
{
    if (r.sse_inherited)
        return false;
    auto listed = [&](const std::vector<std::string>& values)
    { return r.sse_sent && std::find(values.begin(), values.end(), r.sse) != values.end(); };
    // A key the request does not carry equals nothing, and so differs from everything, as IAM judges it.
    if (s.has_sse_eq && !listed(s.sse_eq))
        return false;
    if (s.has_sse_ne && listed(s.sse_ne))
        return false;
    return s.sse_null < 0 || (s.sse_null == 1) == !r.sse_sent;
}

bucket_policy bucket_policy::refusing(std::string_view json, std::string why)
{
    bucket_policy p;
    p.m_text     = std::string(json);
    p.m_broken   = why.empty() ? std::string("it does not compile") : std::move(why);
    p.m_has_deny = true;
    return p;
}

policy_effect bucket_policy::evaluate(const policy_request& r) const
{
    if (!m_broken.empty())
        return policy_effect::deny;
    const uint64_t bit = action_bit(r.action);
    const bool object  = action_on_object(r.action);
    bool allowed = false;
    for (const statement& s : m_statements)
    {
        if (!(s.actions & bit))
            continue;
        if (!m_identity && !s.any_principal)
        {
            if (r.anonymous)
                continue;
            bool named = s.any_signed;
            for (size_t i = 0; !named && i < s.keys.size(); ++i)
                named = s.keys[i] == r.principal || (!r.user.empty() && s.keys[i] == r.user);
            if (!named)
                continue;
        }
        bool covered = false;
        if (m_identity)
        {
            for (size_t i = 0; !covered && i < s.arns.size(); ++i)
                covered = arn_covers(s.arns[i], r, object, s.deny);
        }
        else if (!object)
            covered = s.bucket_resource;
        else if (r.every_key)
        {
            // A Deny over any key refuses a request that may name it, and an Allow has to cover them all.
            for (size_t i = 0; !covered && i < s.objects.size(); ++i)
                covered = s.deny || s.objects[i].k == key_pattern::kind::all;
        }
        else
            for (size_t i = 0; !covered && i < s.objects.size(); ++i)
                covered = key_matches(s.objects[i], r.key);
        if (!covered)
            continue;
        if (!(r.tls ? s.tls_true : s.tls_false))
            continue;
        // A client with no address, on a unix socket, is in no range and so outside every one.
        if (s.has_ip_in && !any_cidr(s.ip_in, r.ip))
            continue;
        if (s.has_ip_out && any_cidr(s.ip_out, r.ip))
            continue;
        if (s.sse_conditioned() && !sse_matches(s, r))
            continue;
        if (s.deny)
            return policy_effect::deny;
        allowed = true;
    }
    return allowed ? policy_effect::allow : policy_effect::none;
}

}   // namespace socketley::storage
