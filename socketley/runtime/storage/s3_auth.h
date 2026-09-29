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

    // The length of the decoded payload when the framing announces it, as
    // aws-chunked does with x-amz-decoded-content-length.
    virtual std::optional<uint64_t> decoded_length() const { return std::nullopt; }
};

struct auth_verdict
{
    bool                        allowed{true};
    s3_error                    error;
    // Who the request was made by, for the log and for scripts.
    std::string                 principal;
    // Present when the body has to be decoded or verified on its way in.
    std::unique_ptr<body_hook>  hook;
};

class authenticator
{
public:
    virtual ~authenticator() = default;
    virtual auth_verdict authorize(const request_view& req) = 0;
};

// `--anonymous`: every request is allowed and nobody is named.
class anonymous_authenticator final : public authenticator
{
public:
    auth_verdict authorize(const request_view&) override { return {}; }
};

}   // namespace socketley::storage
