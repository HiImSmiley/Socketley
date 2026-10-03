#pragma once
// AWS Signature Version 4 verification for an S3-speaking server: pure code, no I/O, no allocation per body byte.
//
// USAGE, one request.
//   The caller fills a request_view (method, raw path, raw query, header fields) and calls verify() with its options,
//   a secret_lookup and the current unix time.
//   The path and the query are the bytes on the wire, still percent-encoded, without the '?'.
//   Header names may be in any case, repeated headers are repeated fields, and values are as received.
//   Both the Authorization-header form and the presigned-query form are accepted, and the form is chosen by what the
//   request carries.
//
// THE RESULT.
//   verify_result::status is one of ok, missing_auth, malformed, unknown_access_key, signature_mismatch,
//   request_time_too_skewed and expired.
//   For every status the result also carries the S3 error code, the http status and a short message for the XML body.
//   ok means the request line, the query and the signed headers are authentic; it says nothing about the body yet.
//
// THE BODY, chosen by verify_result::payload.
//   payload_kind::hex: feed every body byte to a payload_hasher and, at the end, call matches() with
//   verify_result::payload_sha256; on a mismatch answer payload_mismatch().
//   payload_kind::unsigned_payload: nothing to check.
//   The three streaming kinds (aws-chunked): construct a chunk_stream from verify_result::stream and feed it the raw
//   body bytes as they arrive, in pieces of any size.
//   feed() returns at most one span of decoded bytes per call, pointing into the bytes just fed, and how many it used.
//   Decoded bytes are provisional until the chunk that holds them has been verified, so a caller writing to a temporary
//   file must not commit it before status() is done.
//   A bad chunk signature, a malformed frame or a decoded length that disagrees with x-amz-decoded-content-length ends
//   the stream, and error() then says which S3 error to answer.
//   A body that ends before done is incomplete_body().
//   After done, trailer_value() gives a trailing checksum header such as x-amz-checksum-crc32c.
//
// CLOCK AND REGION.
//   A request more than skew_seconds (15 minutes) away from `now` is request_time_too_skewed.
//   A presigned request is expired after X-Amz-Expires seconds (1 to 604800), and one dated more than skew_seconds in
//   the future is request_time_too_skewed.
//   The region is whatever the credential scope says unless verify_options::region pins one.
//
// CANONICAL FORM, as S3 does it.
//   The path is encoded once and never normalised, so dot segments and repeated slashes stay.
//   The path is tried as decoded-and-re-encoded first and as sent second, because clients differ on what they sign.
//   Query parameters are decoded, re-encoded, and sorted by encoded name then value, with a missing value taken as empty.
//   A header value has its outer whitespace trimmed and its inner runs folded to one space, and repeated headers are
//   joined with a comma.
//   The signed headers must include host, the date header the request uses, and x-amz-content-sha256 when present.
//   The payload hash is the x-amz-content-sha256 header, else request_view::body_sha256_hex, else an error (header form);
//   a presigned request uses UNSIGNED-PAYLOAD unless the query gives X-Amz-Content-Sha256.
//
// THREADING.
//   Nothing here holds state between calls but a per-thread cache of derived signing keys, and every object is used from one thread at a time.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

struct evp_md_ctx_st;

namespace socketley::s3
{

struct header_field
{
    std::string_view name;
    std::string_view value;
};

struct request_view
{
    std::string_view method;
    std::string_view raw_path;
    std::string_view raw_query;
    std::span<const header_field> headers;
    // Hex sha256 of the body, used only when the request has no x-amz-content-sha256 header.
    std::string_view body_sha256_hex;
};

enum class sigv4_status : uint8_t
{
    ok,
    missing_auth,
    malformed,
    unknown_access_key,
    signature_mismatch,
    request_time_too_skewed,
    expired,
};

// The S3 error a status maps to when nothing more specific applies.
const char* default_code(sigv4_status s);

struct error_info
{
    sigv4_status status = sigv4_status::ok;
    int http_status     = 200;
    // Static strings, so the view outlives everything.
    const char* code    = "";
    const char* message = "";
};

enum class auth_form : uint8_t { none, header, query };

enum class payload_kind : uint8_t
{
    hex,
    unsigned_payload,
    streaming_signed,
    streaming_unsigned_trailer,
    streaming_signed_trailer,
};

// Everything a chunk_stream needs, copied out of the verified request so the request can go away.
struct stream_context
{
    payload_kind kind = payload_kind::streaming_unsigned_trailer;
    uint8_t  signing_key[32] = {};
    char     amz_date[16] = {};
    char     scope[112] = {};
    uint8_t  scope_len = 0;
    // The signature of the request, then of each chunk in turn, as lowercase hex.
    char     prev_signature[64] = {};
    // x-amz-decoded-content-length, or UINT64_MAX when the request did not say.
    uint64_t decoded_length = UINT64_MAX;

    // For a body the runtime decodes without checking signatures, as when the request itself was anonymous.
    static stream_context unsigned_trailer(uint64_t decoded_length = UINT64_MAX);
};

struct verify_result : error_info
{
    auth_form    form    = auth_form::none;
    payload_kind payload = payload_kind::unsigned_payload;
    // The access key the request named, copied so the result does not depend on the request's bytes.
    std::string_view access_key() const { return {access_key_buf, access_key_len}; }
    char    access_key_buf[128] = {};
    uint8_t access_key_len = 0;
    // The declared body hash when payload is hex.
    uint8_t payload_sha256[32] = {};
    stream_context stream;

    bool ok() const { return status == sigv4_status::ok; }
};

// Secret for an access key, or an empty view for an unknown key; the view only has to outlive the call, and the callable is a lambda or function object, not a bare function.
// It holds a pointer to the callable and not a copy, so a secret_lookup built from a temporary and kept past that statement dangles: name the callable and keep it alive.
class secret_lookup
{
public:
    template <class F>
        requires(!std::is_same_v<std::remove_cvref_t<F>, secret_lookup>)
    secret_lookup(const F& f)
        : ctx_(&f), fn_([](const void* c, std::string_view key) -> std::string_view { return (*static_cast<const F*>(c))(key); })
    {
    }

    std::string_view operator()(std::string_view access_key) const { return fn_(ctx_, access_key); }

private:
    const void* ctx_;
    std::string_view (*fn_)(const void*, std::string_view);
};

struct verify_options
{
    // Empty accepts any region; otherwise the credential scope must name exactly this one.
    std::string_view region;
    std::string_view service = "s3";
    int64_t skew_seconds     = 15 * 60;
    int64_t max_expires_seconds = 7 * 24 * 60 * 60;
};

verify_result verify(const request_view& req, const verify_options& opts, const secret_lookup& secrets, int64_t now_unix);

// What a client signs one request with, in the terms verify() checks it in.
struct sign_input
{
    std::string_view method;
    // The path and the query as they go on the wire, already encoded, the query without its '?'.
    std::string_view raw_path;
    std::string_view raw_query;
    // Every header the signature covers, host and x-amz-date among them, each name once and in lower case.
    std::span<const header_field> headers;
    // What x-amz-content-sha256 says: a hex digest, or UNSIGNED-PAYLOAD.
    std::string_view payload_hash;
    std::string_view access_key;
    std::string_view secret;
    std::string_view region;
    std::string_view service = "s3";
    // YYYYMMDDTHHMMSSZ, the request's x-amz-date.
    std::string_view amz_date;
};

// The Authorization header's value that signs `in`.
std::string sign(const sign_input& in);

// Incremental sha256 for a declared payload hash; one allocation at construction, none per byte.
class payload_hasher
{
public:
    payload_hasher();
    ~payload_hasher();
    payload_hasher(const payload_hasher&)            = delete;
    payload_hasher& operator=(const payload_hasher&) = delete;

    void update(std::string_view data);
    void reset();
    // Finishes the hash, so update() needs a reset() first.
    void finish(uint8_t out[32]);
    bool matches(const uint8_t expected[32]);

private:
    evp_md_ctx_st* ctx_;
};

// What to answer when the body's hash is not the one the request signed.
error_info payload_mismatch();
// What to answer when the body ended before its framing said it would.
error_info incomplete_body();

enum class stream_status : uint8_t { need_more, done, bad_signature, malformed, length_mismatch };

struct feed_result
{
    stream_status status = stream_status::need_more;
    // How many of the fed bytes were used; bytes after a done status belong to whatever follows the body.
    size_t consumed = 0;
    // Decoded body bytes, pointing into the fed buffer and empty when there are none.
    std::string_view data;
};

// The aws-chunked decoder and verifier: signed chunks, and the trailing-checksum variants of both.
class chunk_stream
{
public:
    // A chunk larger than max_chunk_bytes is malformed; nothing is buffered either way.
    explicit chunk_stream(const stream_context& ctx, uint64_t max_chunk_bytes = uint64_t{1} << 30);
    ~chunk_stream();
    chunk_stream(const chunk_stream&)            = delete;
    chunk_stream& operator=(const chunk_stream&) = delete;

    feed_result feed(std::string_view in);

    stream_status status() const { return status_; }
    // The S3 error for a failed stream; status ok when the stream has not failed.
    error_info error() const;
    // Decoded bytes returned so far.
    uint64_t decoded_bytes() const { return decoded_; }
    // A trailing header such as x-amz-checksum-crc32c, valid once done, or empty when the trailer had none.
    std::string_view trailer_value(std::string_view name) const;

private:
    enum class state : uint8_t { header, data, data_cr, data_lf, trailer, finished };

    bool on_header();
    bool on_chunk_end();
    bool on_trailer();
    bool sign_matches(bool final_chunk, const uint8_t claimed[32]);
    stream_status fail(stream_status s);
    bool bad(stream_status s);

    stream_context ctx_;
    uint64_t max_chunk_;
    state    state_  = state::header;
    stream_status status_ = stream_status::need_more;
    uint64_t chunk_remaining_ = 0;
    uint64_t decoded_ = 0;
    uint8_t  claimed_[32] = {};
    char     hdr_[128];
    uint8_t  hdr_len_ = 0;
    char     trailer_[1024];
    uint16_t trailer_len_ = 0;
    evp_md_ctx_st* hash_;
};

} // namespace socketley::s3
