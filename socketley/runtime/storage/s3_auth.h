#pragma once
// What the storage runtime asks of whoever decides whether a request may go
// on, and of whoever decodes a request body on its way in.
//
// The runtime calls authorize() once per request, after the head is parsed and
// before a byte of the body is read, with everything a signature covers.  An
// implementation that verifies a signature hands back a body_hook when the
// payload is signed or chunked, and the runtime feeds every byte of the body
// through it.
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::storage
{

struct user_identity;

// An S3 error as a client sees it: the code in the XML, the message, and the
// HTTP status it travels with.
struct s3_error
{
    std::string code;
    std::string message;
    int         status{0};
};

struct header_ref
{
    // Lowercase, so a lookup and a canonical request need no folding.
    std::string_view name;
    // With the optional whitespace at both ends removed and nothing else touched.
    std::string_view value;
};

// One request as the runtime parsed it.  Every view points into the
// connection's own buffers and is valid for the call and no longer.
struct request_view
{
    std::string_view method;
    // The path exactly as sent -- percent-encoded, without the query -- because
    // a signature is computed over these bytes and not over the decoded key.
    std::string_view raw_path;
    // The query exactly as sent, without the '?'.
    std::string_view raw_query;
    std::string_view host;
    // The x-amz-content-sha256 header, empty when the client sent none.
    std::string_view payload_hash;
    // In arrival order.
    const std::vector<header_ref>* headers{nullptr};
    // The target resolved and decoded, path-style: empty for the service.
    std::string_view bucket;
    std::string_view key;
    // Whether the connection is TLS, which decides what a presigned URL says.
    bool tls{false};
    // The bucket came from the host, virtual-hosted, which a Signature Version 2 resource names all the same.
    bool vhost{false};
    // The service the signature's scope must name: s3, or sts for a request for temporary credentials.
    std::string_view service{"s3"};
    // The body's sha256 in hex, for a body read before its request is judged that names no x-amz-content-sha256.
    std::string_view body_sha256_hex;

    std::string_view header(std::string_view lower_name) const
    {
        if (headers)
            for (const header_ref& h : *headers)
                if (h.name == lower_name)
                    return h.value;
        return {};
    }
};

// A stage a body passes through between the socket and the object: it turns the
// bytes as HTTP framed them into the bytes of the object, and may refuse.
class body_hook
{
public:
    virtual ~body_hook() = default;

    // `raw` is the next piece of the request body; the decoded payload is
    // appended to `out`.  False refuses the request with `err`.
    virtual bool feed(std::string_view raw, std::string& out, s3_error& err) = 0;

    // The body has ended.  False refuses the request -- a payload hash that
    // does not match, a chunk stream that stopped short -- and nothing is stored.
    virtual bool finish(std::string& out, s3_error& err) = 0;

    // Whether feeding this hook costs enough per byte (a SHA-256 of the whole
    // body) to be worth running on a helper thread, in order and one piece at a
    // time; a hook that only decodes framing is cheaper done in line.
    virtual bool heavy() const { return false; }

    // The length of the decoded payload when the framing announces it, as
    // aws-chunked does with x-amz-decoded-content-length.
    virtual std::optional<uint64_t> decoded_length() const { return std::nullopt; }

    // A header the body carried after its last chunk, such as
    // x-amz-checksum-crc32c, valid once finish() has returned true.
    virtual std::string trailer_value(std::string_view /*lowercase_name*/) const { return {}; }

    // Whether the payload is as long as the body less its framing, which a stage that stops at a delimiter is not.
    virtual bool length_from_body() const { return true; }
};

struct auth_verdict
{
    bool                        allowed{true};
    s3_error                    error;
    // Who the request was made by, for the log and for scripts.
    std::string                 principal;
    // The user the access key belongs to, null when the request carried no credentials.
    std::shared_ptr<const user_identity> user;
    // The request carried no credentials, which a bucket policy may still let in.
    bool                        anonymous{false};
    // The request was signed with temporary credentials, which may not ask for more.
    bool                        session{false};
    // Present when the body has to be decoded or verified on its way in.
    std::unique_ptr<body_hook>  hook;
};

// Temporary credentials as STS answers them.
struct session_credentials
{
    std::string access_key;
    std::string secret;
    std::string token;
    // Unix seconds.
    int64_t     expires{0};
};

// The fields a browser's form is signed with, which travel in the body and not in a header (SigV4 POST policy).
struct post_signature
{
    std::string_view algorithm;
    std::string_view credential;
    std::string_view amz_date;
    // The base64 policy exactly as the form carried it, which is what was signed.
    std::string_view policy;
    std::string_view signature;
    // The older form, AWSAccessKeyId and a base64 HMAC-SHA1 of the policy, which boto3's presigned POST still writes.
    std::string_view v2_access_key;
    std::string_view v2_signature;
};

// What a web interface's session cookie seals.
inline std::string ui_session_text(std::string_view access_key, int64_t expires_ms)
{
    return "socketley-ui\n" + std::string(access_key) + "\n" + std::to_string(expires_ms);
}

class authenticator
{
public:
    virtual ~authenticator() = default;
    virtual auth_verdict authorize(const request_view& req) = 0;
    // A signed form's verdict; an authenticator that holds no credentials can verify none.
    virtual auth_verdict authorize_post(const post_signature& /*sig*/)
    {
        auth_verdict v;
        v.allowed = false;
        v.error   = {"InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.", 403};
        return v;
    }
    // A WebDAV client's or a browser's HTTP Basic credentials, the access key as the user name and its secret as the
    // password; an authenticator that holds no keys lets everyone in as with no credentials.
    virtual auth_verdict authorize_basic(std::string_view /*access_key*/, std::string_view /*secret*/)
    {
        auth_verdict v;
        v.anonymous = true;
        return v;
    }
    // The web interface's sign-in cookie for `access_key`, sealed with that key's own secret: `mac_hex` must be the
    // HMAC-SHA256 under the secret of ui_session_text(access_key, expires_ms). The caller judges the expiry. A key that
    // is gone or whose secret changed no longer verifies, so its sessions end with it; an authenticator that holds no
    // keys lets everyone in as with no credentials.
    virtual auth_verdict authorize_ui_session(std::string_view /*access_key*/, int64_t /*expires_ms*/,
                                              std::string_view /*mac_hex*/)
    {
        auth_verdict v;
        v.anonymous = true;
        return v;
    }
    // The display name of user `id` as an Owner element gives it, the id itself for one no longer known.
    virtual std::string display_name(std::string_view id) const { return std::string(id); }
    // The quota on the bytes of the buckets user `id` owns, 0 for none or for a user no longer known.
    virtual uint64_t max_bytes_of(std::string_view /*id*/) const { return 0; }
    // Temporary credentials signing for the user of long-term key `access_key` until `expires`, bounded by `policy`
    // when it is not empty; false for a key that is not one, which an authenticator without keys has none of.
    virtual bool issue_session(std::string_view /*access_key*/, int64_t /*expires*/, std::string_view /*policy*/,
                               std::string_view /*role*/, session_credentials& /*out*/)
    {
        return false;
    }
    // The same for user `user_id`, signed under one of its long-term keys, for an identity an outside provider vouched
    // for; false for a user with no key here.
    virtual bool issue_session_as(std::string_view /*user_id*/, int64_t /*expires*/, std::string_view /*policy*/,
                                  std::string_view /*role*/, session_credentials& /*out*/)
    {
        return false;
    }
    // Whether user `id` is one the credentials or the IAM API declared.
    virtual bool has_user(std::string_view /*id*/) const { return false; }
    // The id of the user whose email is `email`, empty for none.
    virtual std::string user_of_email(std::string_view /*email*/) const { return {}; }
    // Whether the IAM role `role` lets user `user_id` assume it: -1 for no such role, 0 for a refusal, 1 with
    // `max_session` set to the longest session it gives.
    virtual int role_check(std::string_view /*role*/, std::string_view /*user_id*/, int64_t& /*max_session*/)
    {
        return -1;
    }
    // The file the IAM API keeps its users, groups and roles in, empty for an authenticator without one.
    virtual std::string iam_file() const { return {}; }
    // Reads the credentials and the IAM file again now, as after the IAM API changed the latter.
    virtual void refresh() {}
    // Whether the credentials file declares user `id`, which the IAM API then makes none of.
    virtual bool file_user(std::string_view /*id*/) const { return false; }
};

// `--anonymous`: every request is allowed and nobody is named.  A body that is
// aws-chunked without signatures is decoded, and one whose chunks are signed is
// left for the runtime to refuse, since nobody is there to verify them.
class anonymous_authenticator final : public authenticator
{
public:
    auth_verdict authorize(const request_view& req) override;
};

}   // namespace socketley::storage
