// Fuzz target: AWS Signature V4 and V2 verification (socketley/shared/s3_sigv4.h) and the aws-chunked decoder.
//
// Reachable by anything that can send an HTTP request to a storage runtime: every request is verified before any
// other work, and the chunk decoder reads the body of any request that says it is aws-chunked.
//
// The first input byte picks the mode:
//   even  the rest is a request: lines "method", "path", "query", "payload hash", then "name:value" header lines, all
//         separated by LF; bit 1 of the first byte pins the region
//   odd   the rest is one byte for the stream kind, one byte for the piece size, and the bytes of an aws-chunked body
//
// Properties checked, beyond "did it crash":
//   * a request that verifies names the key the lookup knows, verifies again identically, still verifies with every
//     header name in upper case, and stops verifying with another secret, with the clock two days behind and with it eight days ahead;
//   * a request that does not verify says why with an S3 code, an http status of 400 or 403, and no access key;
//   * a body fed in pieces of any size gives the same status, the same decoded bytes and the same consumed count as
//     the same body fed whole, decoded spans point inside what was fed, and a failed or finished stream stays so;
//   * a stream that is done has read no more bytes than it was given, and its trailer lookup does not run off the buffer.
//
// WHAT THIS TARGET DOES NOT COVER: that a signature is right, which only the unit test's vectors say, since the
// fuzzer cannot forge one; the seeds carry valid ones, so mutations reach the verifying branches from just off them.

#include "fuzz_common.h"
#include "shared/s3_sigv4.h"

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace s3 = socketley::s3;

namespace {

constexpr int64_t now_unix = 1790683200; // 2026-09-29T12:00:00Z

const auto lookup_real = [](std::string_view key) { return key == "AKIDFUZZ" ? std::string_view("fuzz-secret-key") : std::string_view(); };

const auto lookup_other = [](std::string_view key) { return key == "AKIDFUZZ" ? std::string_view("another-secret") : std::string_view(); };

void one_request(uint8_t flags, std::string_view text)
{
    std::vector<std::string_view> lines;
    for (size_t b = 0; b <= text.size();)
    {
        size_t e = text.find('\n', b);
        lines.push_back(text.substr(b, e == std::string_view::npos ? e : e - b));
        if (e == std::string_view::npos)
            break;
        b = e + 1;
    }
    while (lines.size() < 4)
        lines.push_back({});

    std::vector<s3::header_field> fields;
    std::vector<std::string> upper_names;
    for (size_t i = 4; i < lines.size(); i++)
    {
        size_t colon = lines[i].find(':');
        if (colon == std::string_view::npos)
            continue;
        fields.push_back({lines[i].substr(0, colon), lines[i].substr(colon + 1)});
    }
    upper_names.reserve(fields.size());
    std::vector<s3::header_field> upper = fields;
    for (size_t i = 0; i < fields.size(); i++)
    {
        std::string n(fields[i].name);
        for (char& c : n)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        upper_names.push_back(std::move(n));
        upper[i].name = upper_names.back();
    }

    s3::request_view rv{lines[0], lines[1], lines[2], fields, lines[3]};
    s3::verify_options opts;
    if (flags & 2)
        opts.region = "us-east-1";

    s3::verify_result r = s3::verify(rv, opts, lookup_real, now_unix);
    s3::verify_result again = s3::verify(rv, opts, lookup_real, now_unix);
    FUZZ_CHECK(r.status == again.status && r.access_key() == again.access_key(), "verify is not deterministic");
    FUZZ_CHECK(r.code != nullptr && r.message != nullptr, "a result without a code or message");
    FUZZ_CHECK(r.ok() == (r.status == s3::sigv4_status::ok), "ok() disagrees with status");

    if (r.ok())
    {
        FUZZ_CHECK(r.http_status == 200 && r.code[0] == '\0', "an ok result with an error code");
        FUZZ_CHECK(r.access_key() == "AKIDFUZZ", "verified as a key the lookup does not know");

        s3::request_view up{rv.method, rv.raw_path, rv.raw_query, upper, rv.body_sha256_hex};
        FUZZ_CHECK(s3::verify(up, opts, lookup_real, now_unix).ok(), "header names in upper case stopped verifying");
        FUZZ_CHECK(!s3::verify(rv, opts, lookup_other, now_unix).ok(), "verified under two different secrets");
        // A Signature Version 2 URL names when it expires and not when it was made, so an earlier clock still takes it.
        const bool v2_url = r.form == s3::auth_form::query && rv.raw_query.find("AWSAccessKeyId=") != std::string_view::npos;
        FUZZ_CHECK(v2_url || !s3::verify(rv, opts, lookup_real, now_unix - 2 * 86400).ok(),
                   "verified with the clock two days behind");
        FUZZ_CHECK(!s3::verify(rv, opts, lookup_real, now_unix + 8 * 86400).ok(), "verified with the clock eight days ahead");
    }
    else
    {
        FUZZ_CHECK(r.http_status == 400 || r.http_status == 403, "a failed result with an unexpected http status");
        FUZZ_CHECK(r.code[0] != '\0', "a failed result without an S3 code");
        FUZZ_CHECK(r.access_key().empty() || r.status != s3::sigv4_status::missing_auth, "a missing-auth result naming a key");
    }
}

s3::stream_context fixed_context(uint8_t kind)
{
    s3::stream_context c;
    static constexpr s3::payload_kind kinds[] = {s3::payload_kind::streaming_signed, s3::payload_kind::streaming_signed_trailer,
                                                 s3::payload_kind::streaming_unsigned_trailer};
    c.kind = kinds[kind % 3];
    for (size_t i = 0; i < sizeof(c.signing_key); i++)
        c.signing_key[i] = static_cast<uint8_t>(0x11 + i);
    std::string_view date  = "20260929T120000Z";
    std::string_view scope = "20260929/us-east-1/s3/aws4_request";
    for (size_t i = 0; i < date.size(); i++)
        c.amz_date[i] = date[i];
    for (size_t i = 0; i < scope.size(); i++)
        c.scope[i] = scope[i];
    c.scope_len = static_cast<uint8_t>(scope.size());
    for (char& ch : c.prev_signature)
        ch = '0';
    return c;
}

struct outcome
{
    s3::stream_status status = s3::stream_status::need_more;
    std::string decoded;
    size_t consumed = 0;
    std::string trailer;
};

outcome run_stream(const s3::stream_context& ctx, std::string_view wire, size_t step)
{
    outcome o;
    s3::chunk_stream s(ctx, 1 << 20);
    size_t pos = 0;
    while (pos < wire.size())
    {
        std::string_view piece = wire.substr(pos, step);
        size_t off = 0;
        while (off < piece.size())
        {
            std::string_view rest = piece.substr(off);
            s3::feed_result r = s.feed(rest);
            FUZZ_CHECK(r.consumed <= rest.size(), "feed consumed more than it was given");
            if (!r.data.empty())
                FUZZ_CHECK(r.data.data() >= rest.data() && r.data.data() + r.data.size() <= rest.data() + rest.size(), "a decoded span outside the fed bytes");
            o.decoded.append(r.data);
            off += r.consumed;
            o.status = r.status;
            if (r.status != s3::stream_status::need_more)
            {
                o.consumed = pos + off;
                FUZZ_CHECK(s.status() == r.status, "status() disagrees with the last feed");
                s3::feed_result again = s.feed("x");
                FUZZ_CHECK(again.status == r.status && again.consumed == 0 && again.data.empty(), "a finished or failed stream took more bytes");
                if (r.status == s3::stream_status::done)
                    o.trailer = std::string(s.trailer_value("x-amz-checksum-crc32"));
                else
                    FUZZ_CHECK(s.error().status != s3::sigv4_status::ok && s.error().code[0] != '\0', "a failed stream without an error");
                FUZZ_CHECK(s.decoded_bytes() == o.decoded.size(), "decoded_bytes() disagrees with the spans handed out");
                return o;
            }
            if (r.consumed == 0)
                break;
        }
        pos += piece.size();
    }
    o.consumed = wire.size();
    FUZZ_CHECK(s.decoded_bytes() == o.decoded.size(), "decoded_bytes() disagrees with the spans handed out");
    return o;
}

void one_stream(std::string_view in)
{
    if (in.size() < 2)
        return;
    s3::stream_context ctx = fixed_context(static_cast<uint8_t>(in[0]));
    size_t step = 1 + static_cast<uint8_t>(in[1]) % 16;
    std::string_view wire = in.substr(2);

    outcome whole = run_stream(ctx, wire, wire.size() ? wire.size() : 1);
    outcome piecewise = run_stream(ctx, wire, step);
    outcome bytewise = run_stream(ctx, wire, 1);
    for (const outcome* o : {&piecewise, &bytewise})
    {
        FUZZ_CHECK(o->status == whole.status, "the status depends on how the body was cut");
        FUZZ_CHECK(o->decoded == whole.decoded, "the decoded bytes depend on how the body was cut");
        FUZZ_CHECK(o->consumed == whole.consumed, "the consumed count depends on how the body was cut");
        FUZZ_CHECK(o->trailer == whole.trailer, "the trailer depends on how the body was cut");
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size == 0)
        return 0;
    data = fuzz::never_null(data);
    std::string_view rest(reinterpret_cast<const char*>(data) + 1, size - 1);
    if (data[0] & 1)
        one_stream(rest);
    else
        one_request(data[0], rest);
    return 0;
}
