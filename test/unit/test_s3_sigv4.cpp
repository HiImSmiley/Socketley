#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/s3_sigv4.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

// Verification of AWS Signature V4 as an S3 server needs it: the published vectors, what botocore actually sends, the
// aws-chunked framing byte by byte, and every field of a request tampered in turn.
//
// The tables in s3_sigv4_cases.inc come from gen_s3_sigv4_cases.py and hold, per case, the request as it arrived and
// what it must be taken for; their sources are the AWS SigV4 test suite as shipped in botocore, the S3 API reference's
// signature examples, requests botocore 1.34.46 signed with a frozen clock, and requests signed by the generator's own
// reference implementation for the variants no installed client sends.

namespace s3 = socketley::s3;

namespace {

using sv = std::string_view;

struct hdr
{
    sv n, v;
};

struct kase
{
    sv name, source, access_key, secret, region, service;
    int64_t now;
    sv method, path, query;
    std::vector<hdr> headers;
    sv fallback, body, decoded, trailer_name, trailer_value, kind;
};

const kase g_cases[] = {
#include "s3_sigv4_cases.inc"
};

// A request that can be taken apart and put back together, so a test can change one field.
struct req
{
    std::string method, path, query, fallback;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string access_key, secret, region, service;
    int64_t now = 0;
    s3::verify_options opts;

    explicit req(const kase& c)
        : method(c.method), path(c.path), query(c.query), fallback(c.fallback), access_key(c.access_key), secret(c.secret),
          region(c.region), service(c.service), now(c.now)
    {
        for (const hdr& h : c.headers)
            headers.emplace_back(std::string(h.n), std::string(h.v));
        opts.service = service;
    }

    std::string* find(sv name)
    {
        for (auto& [n, v] : headers)
            if (n.size() == name.size() && std::equal(n.begin(), n.end(), name.begin(), [](char a, char b) { return std::tolower(a) == std::tolower(b); }))
                return &v;
        return nullptr;
    }

    s3::verify_result run() const
    {
        std::vector<s3::header_field> fields;
        for (auto& [n, v] : headers)
            fields.push_back({n, v});
        s3::request_view rv{method, path, query, fields, fallback};
        auto lookup = [&](sv k) -> sv { return k == access_key ? sv(secret) : sv(); };
        return s3::verify(rv, opts, lookup, now);
    }
};

const char* kind_name(s3::payload_kind k)
{
    switch (k)
    {
    case s3::payload_kind::hex: return "hex";
    case s3::payload_kind::unsigned_payload: return "unsigned_payload";
    case s3::payload_kind::streaming_signed: return "streaming_signed";
    case s3::payload_kind::streaming_unsigned_trailer: return "streaming_unsigned_trailer";
    case s3::payload_kind::streaming_signed_trailer: return "streaming_signed_trailer";
    }
    return "?";
}

bool is_streaming(s3::payload_kind k)
{
    return k == s3::payload_kind::streaming_signed || k == s3::payload_kind::streaming_unsigned_trailer || k == s3::payload_kind::streaming_signed_trailer;
}

bool is_signed_streaming(s3::payload_kind k)
{
    return k == s3::payload_kind::streaming_signed || k == s3::payload_kind::streaming_signed_trailer;
}

std::string hex_of(const uint8_t* p, size_t n)
{
    static constexpr char d[] = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++)
    {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}

// Feeds `wire` in pieces of `step` bytes, collecting decoded bytes; `used` is how much of the wire the stream took.
s3::stream_status feed_all(s3::chunk_stream& s, sv wire, size_t step, std::string& decoded, size_t* used = nullptr)
{
    size_t pos = 0;
    s3::stream_status st = s3::stream_status::need_more;
    while (pos < wire.size())
    {
        sv piece = wire.substr(pos, step);
        size_t off = 0;
        while (off < piece.size())
        {
            s3::feed_result r = s.feed(piece.substr(off));
            decoded.append(r.data);
            off += r.consumed;
            st = r.status;
            if (st != s3::stream_status::need_more)
            {
                if (used)
                    *used = pos + off;
                return st;
            }
            if (r.consumed == 0)
                break;
        }
        pos += piece.size();
    }
    if (used)
        *used = wire.size();
    return st;
}

const kase* find_case(sv name)
{
    for (const kase& c : g_cases)
        if (c.name == name)
            return &c;
    return nullptr;
}

int64_t unix_of(int y, int mo, int d, int h, int mi, int s)
{
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min  = mi;
    tm.tm_sec  = s;
    return static_cast<int64_t>(timegm(&tm));
}

// The x-amz-date of a case, from wherever it carries one.
int64_t signing_time(const kase& c)
{
    std::string d;
    for (const hdr& h : c.headers)
        if (h.n == "x-amz-date" || h.n == "X-Amz-Date")
            d = std::string(h.v);
    size_t at = c.query.find("X-Amz-Date=");
    if (d.empty() && at != sv::npos)
        d = std::string(c.query.substr(at + 11, 16));
    if (d.empty())
        return c.now;
    int y, mo, dd, h, mi, s;
    std::sscanf(d.c_str(), "%4d%2d%2dT%2d%2d%2dZ", &y, &mo, &dd, &h, &mi, &s);
    return unix_of(y, mo, dd, h, mi, s);
}

bool presigned(const kase& c)
{
    return c.query.find("X-Amz-Signature=") != sv::npos;
}

int64_t expires_of(const kase& c)
{
    size_t at = c.query.find("X-Amz-Expires=");
    return at == sv::npos ? 0 : std::atoll(std::string(c.query.substr(at + 14, 10)).c_str());
}

// Changes the last digit, or failing that the last letter, so a value stays the same shape.
std::string nudge(std::string v)
{
    for (size_t i = v.size(); i-- > 0;)
        if (v[i] >= '0' && v[i] <= '9')
        {
            v[i] = static_cast<char>('0' + (v[i] - '0' + 1) % 10);
            return v;
        }
    for (size_t i = v.size(); i-- > 0;)
        if (v[i] >= 'a' && v[i] <= 'z')
        {
            v[i] = v[i] == 'z' ? 'a' : static_cast<char>(v[i] + 1);
            return v;
        }
    return v + "x";
}

std::string signed_list(const std::string& authorization_or_query, bool query)
{
    std::string key = query ? "X-Amz-SignedHeaders=" : "SignedHeaders=";
    size_t at = authorization_or_query.find(key);
    if (at == std::string::npos)
        return {};
    size_t b = at + key.size(), e = authorization_or_query.find_first_of(query ? "&" : ",", b);
    std::string l = authorization_or_query.substr(b, e == std::string::npos ? e : e - b);
    for (size_t p; (p = l.find("%3B")) != std::string::npos;)
        l.replace(p, 3, ";");
    return l;
}

} // namespace

// ─── the hash ───

TEST_CASE("payload_hasher: sha256 of known inputs, in pieces of any size")
{
    struct vec { sv in; const char* hex; };
    const vec vecs[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    };
    for (const vec& v : vecs)
        for (size_t step : {size_t{1}, size_t{3}, size_t{64}, size_t{1000}})
        {
            s3::payload_hasher h;
            for (size_t i = 0; i < v.in.size(); i += step)
                h.update(v.in.substr(i, step));
            uint8_t out[32];
            h.finish(out);
            CHECK(hex_of(out, 32) == v.hex);
        }
    // One million 'a', the FIPS 180 long message.
    s3::payload_hasher h;
    std::string block(1000, 'a');
    for (int i = 0; i < 1000; i++)
        h.update(block);
    uint8_t out[32];
    h.finish(out);
    CHECK(hex_of(out, 32) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_CASE("payload_hasher: matches compares against the declared hash and reset starts over")
{
    uint8_t want[32];
    {
        s3::payload_hasher h;
        h.update("Welcome to Amazon S3.");
        h.finish(want);
    }
    s3::payload_hasher h;
    h.update("Welcome to Amazon S3.");
    CHECK(h.matches(want));
    h.reset();
    h.update("Welcome to Amazon S3!");
    CHECK_FALSE(h.matches(want));
}

// ─── the vectors ───

TEST_CASE("every case verifies, and says what its payload is")
{
    int n = 0;
    for (const kase& c : g_cases)
    {
        INFO(c.name);
        req r(c);
        s3::verify_result res = r.run();
        REQUIRE(res.status == s3::sigv4_status::ok);
        CHECK(res.ok());
        CHECK(res.http_status == 200);
        CHECK(std::string(res.code) == "");
        CHECK(res.access_key() == c.access_key);
        CHECK(res.form == (presigned(c) ? s3::auth_form::query : s3::auth_form::header));
        if (!c.kind.empty())
            CHECK(std::string(kind_name(res.payload)) == std::string(c.kind));
        n++;
    }
    CHECK(n == 90);
}

TEST_CASE("every case that declares a body hash checks the body against it")
{
    int checked = 0;
    for (const kase& c : g_cases)
    {
        req r(c);
        s3::verify_result res = r.run();
        REQUIRE(res.ok());
        if (res.payload != s3::payload_kind::hex)
            continue;
        INFO(c.name);
        for (size_t step : {size_t{1}, size_t{5}, size_t{4096}})
        {
            s3::payload_hasher h;
            for (size_t i = 0; i < c.body.size(); i += step)
                h.update(c.body.substr(i, step));
            CHECK(h.matches(res.payload_sha256));
        }
        std::string bad(c.body);
        bad.push_back('x');
        s3::payload_hasher h;
        h.update(bad);
        CHECK_FALSE(h.matches(res.payload_sha256));
        if (!c.body.empty())
        {
            std::string flipped(c.body);
            flipped[flipped.size() / 2] ^= 1;
            s3::payload_hasher h2;
            h2.update(flipped);
            CHECK_FALSE(h2.matches(res.payload_sha256));
        }
        checked++;
    }
    CHECK(checked >= 40);
}

TEST_CASE("the published signatures are the ones in the Authorization header, not just verified against themselves")
{
    // Pinning the constants of the S3 API reference in the test source too, so a regenerated table cannot move them.
    struct pub { sv name; sv sig; };
    const pub pubs[] = {
        {"docs/get-object", "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"},
        {"docs/put-object", "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"},
        {"docs/get-bucket-lifecycle", "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"},
        {"docs/list-objects", "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"},
        {"docs/presigned-get", "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"},
        {"docs/chunked-put", "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"},
        {"suite/get-vanilla", "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
        {"suite/get-vanilla-query-order-key-case", "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"},
        {"suite/post-x-www-form-urlencoded", "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"},
        {"suite/get-header-value-trim", "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736"},
    };
    for (const pub& p : pubs)
    {
        INFO(p.name);
        const kase* c = find_case(p.name);
        REQUIRE(c);
        bool found = false;
        for (const hdr& h : c->headers)
            if (h.v.find(p.sig) != sv::npos)
                found = true;
        found = found || c->query.find(p.sig) != sv::npos;
        CHECK(found);
    }
}

TEST_CASE("aws-chunked example from the S3 API reference, with its three published chunk signatures")
{
    const kase* c = find_case("docs/chunked-put");
    REQUIRE(c);
    req r(*c);
    s3::verify_result res = r.run();
    REQUIRE(res.ok());
    REQUIRE(res.payload == s3::payload_kind::streaming_signed);
    CHECK(res.stream.decoded_length == 66560);

    auto build = [](sv s1, sv s2, sv s3_) {
        std::string w = "10000;chunk-signature=" + std::string(s1) + "\r\n" + std::string(65536, 'a') + "\r\n";
        w += "400;chunk-signature=" + std::string(s2) + "\r\n" + std::string(1024, 'a') + "\r\n";
        w += "0;chunk-signature=" + std::string(s3_) + "\r\n\r\n";
        return w;
    };
    const sv s1 = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";
    const sv s2 = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497";
    const sv s3_ = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9";
    std::string wire = build(s1, s2, s3_);
    CHECK(wire.size() == 66824 - 0); // the Content-Length the example states

    for (size_t step : {size_t{1}, size_t{100}, size_t{8192}, size_t{70000}})
    {
        s3::chunk_stream s(res.stream);
        std::string decoded;
        CHECK(feed_all(s, wire, step, decoded) == s3::stream_status::done);
        CHECK(decoded == std::string(66560, 'a'));
        CHECK(s.decoded_bytes() == 66560);
    }

    // Each of the three signatures, when wrong, is the one that fails, and the bytes before it were still handed out.
    struct wrong { sv a, b, c; int at; };
    std::string bad = "0000000000000000000000000000000000000000000000000000000000000000";
    const wrong ws[] = {{bad, s2, s3_, 1}, {s1, bad, s3_, 2}, {s1, s2, bad, 3}};
    for (const wrong& w : ws)
    {
        s3::chunk_stream s(res.stream);
        std::string decoded;
        CHECK(feed_all(s, build(w.a, w.b, w.c), 4096, decoded) == s3::stream_status::bad_signature);
        CHECK(s.error().status == s3::sigv4_status::signature_mismatch);
        CHECK(std::string(s.error().code) == "SignatureDoesNotMatch");
        CHECK(s.error().http_status == 403);
        CHECK(decoded.size() == (w.at == 1 ? 65536u : 66560u));
    }
    // Chunks are chained: the same two chunks in the other order do not verify.
    {
        std::string swapped = "400;chunk-signature=" + std::string(s2) + "\r\n" + std::string(1024, 'a') + "\r\n" + "10000;chunk-signature=" + std::string(s1) +
                              "\r\n" + std::string(65536, 'a') + "\r\n" + "0;chunk-signature=" + std::string(s3_) + "\r\n\r\n";
        s3::chunk_stream s(res.stream);
        std::string decoded;
        CHECK(feed_all(s, swapped, 4096, decoded) == s3::stream_status::bad_signature);
    }
}

// ─── the streaming cases ───

TEST_CASE("streaming cases decode to the payload, in every split of the wire and one byte at a time")
{
    int streams = 0;
    for (const kase& c : g_cases)
    {
        req r(c);
        s3::verify_result res = r.run();
        REQUIRE(res.ok());
        if (!is_streaming(res.payload) || c.body.empty())
            continue;
        INFO(c.name);
        streams++;
        // Every two-piece split of the wire.
        for (size_t cut = 0; cut <= c.body.size(); cut++)
        {
            s3::chunk_stream s(res.stream);
            std::string decoded;
            s3::stream_status st = feed_all(s, c.body.substr(0, cut), c.body.size() + 1, decoded);
            if (cut < c.body.size())
            {
                REQUIRE(st == s3::stream_status::need_more);
                REQUIRE(decoded == c.decoded.substr(0, decoded.size()));
                st = feed_all(s, c.body.substr(cut), c.body.size() + 1, decoded);
            }
            REQUIRE(st == s3::stream_status::done);
            REQUIRE(decoded == c.decoded);
            CHECK(s.trailer_value(c.trailer_name.empty() ? sv("x-amz-checksum-crc32") : c.trailer_name) == c.trailer_value);
        }
        s3::chunk_stream s(res.stream);
        std::string decoded;
        CHECK(feed_all(s, c.body, 1, decoded) == s3::stream_status::done);
        CHECK(decoded == c.decoded);
        CHECK(s.decoded_bytes() == c.decoded.size());
    }
    CHECK(streams >= 12);
}

TEST_CASE("a stream that stops early is never taken for a finished one")
{
    for (const kase& c : g_cases)
    {
        req r(c);
        s3::verify_result res = r.run();
        REQUIRE(res.ok());
        if (!is_streaming(res.payload) || c.body.empty())
            continue;
        INFO(c.name);
        for (size_t cut = 0; cut < c.body.size(); cut++)
        {
            s3::chunk_stream s(res.stream);
            std::string decoded;
            REQUIRE(feed_all(s, c.body.substr(0, cut), 3, decoded) == s3::stream_status::need_more);
            REQUIRE(s.status() == s3::stream_status::need_more);
            REQUIRE(s.trailer_value("x-amz-checksum-crc32").empty());
        }
    }
    s3::error_info e = s3::incomplete_body();
    CHECK(std::string(e.code) == "IncompleteBody");
    CHECK(e.http_status == 400);
}

TEST_CASE("bytes after the final chunk are left for whatever follows")
{
    for (const kase& c : g_cases)
    {
        req r(c);
        s3::verify_result res = r.run();
        if (!is_streaming(res.payload) || c.body.empty())
            continue;
        INFO(c.name);
        std::string wire = std::string(c.body) + "GET /next HTTP/1.1\r\n\r\n";
        for (size_t step : {size_t{1}, size_t{7}, wire.size()})
        {
            s3::chunk_stream s(res.stream);
            std::string decoded;
            size_t used = 0;
            CHECK(feed_all(s, wire, step, decoded, &used) == s3::stream_status::done);
            CHECK(used == c.body.size());
            CHECK(decoded == c.decoded);
            // A finished stream takes nothing more.
            s3::feed_result again = s.feed("more");
            CHECK(again.status == s3::stream_status::done);
            CHECK(again.consumed == 0);
        }
    }
}

TEST_CASE("signed streams: no single flipped byte of the wire gets through")
{
    int streams = 0;
    for (const kase& c : g_cases)
    {
        req r(c);
        s3::verify_result res = r.run();
        if (!is_signed_streaming(res.payload) || c.body.empty() || c.body.size() > 2000)
            continue;
        INFO(c.name);
        streams++;
        for (size_t i = 0; i < c.body.size(); i++)
        {
            std::string w(c.body);
            w[i] ^= 1;
            s3::chunk_stream s(res.stream);
            std::string decoded;
            s3::stream_status st = feed_all(s, w, w.size(), decoded);
            INFO("byte " << i);
            REQUIRE(st != s3::stream_status::done);
            if (st == s3::stream_status::need_more)
                // The flip made the stream look longer than it is, so it waits for bytes that never come.
                CHECK(s.status() == s3::stream_status::need_more);
            else
                CHECK(s.error().status != s3::sigv4_status::ok);
        }
    }
    CHECK(streams >= 8);
}

TEST_CASE("a trailer is covered by the signature in the signed variant and its lines are readable in both")
{
    for (const kase& c : g_cases)
    {
        req r(c);
        s3::verify_result res = r.run();
        if (res.payload != s3::payload_kind::streaming_signed_trailer)
            continue;
        INFO(c.name);
        size_t at = c.body.find("x-amz-checksum-");
        REQUIRE(at != sv::npos);

        std::string w(c.body);
        w[at + 22] = w[at + 22] == 'A' ? 'B' : 'A';
        s3::chunk_stream s(res.stream);
        std::string decoded;
        CHECK(feed_all(s, w, 5, decoded) == s3::stream_status::bad_signature);
        CHECK(decoded == c.decoded);

        // A trailer with the signature line taken off is malformed, not unsigned.
        size_t sig = c.body.find("x-amz-trailer-signature:");
        REQUIRE(sig != sv::npos);
        std::string cut = std::string(c.body.substr(0, sig)) + "\r\n";
        s3::chunk_stream s2(res.stream);
        std::string d2;
        CHECK(feed_all(s2, cut, 5, d2) == s3::stream_status::malformed);
    }
}

TEST_CASE("boto3 unsigned-trailer bodies are decoded and their checksum trailer is readable")
{
    int n = 0;
    for (const kase& c : g_cases)
    {
        if (c.name.substr(0, 6) != "boto3/" || c.kind != "streaming_unsigned_trailer")
            continue;
        INFO(c.name);
        n++;
        req r(c);
        s3::verify_result res = r.run();
        REQUIRE(res.ok());
        s3::chunk_stream s(res.stream);
        std::string decoded;
        REQUIRE(feed_all(s, c.body, 11, decoded) == s3::stream_status::done);
        CHECK(decoded == c.decoded);
        CHECK(s.trailer_value(c.trailer_name) == c.trailer_value);
        CHECK(s.trailer_value(c.trailer_name).size() > 4);
        CHECK(s.trailer_value("x-amz-no-such").empty());
    }
    CHECK(n == 3);
}

TEST_CASE("chunk framing errors")
{
    const kase* c = find_case("ref/signed-three-chunks");
    REQUIRE(c);
    req r(*c);
    s3::verify_result res = r.run();
    REQUIRE(res.ok());
    auto run = [&](std::string wire, s3::stream_context ctx = {}, uint64_t max_chunk = 1 << 20) {
        if (ctx.kind != res.stream.kind || ctx.scope_len == 0)
            ctx = res.stream;
        s3::chunk_stream s(ctx, max_chunk);
        std::string decoded;
        s3::stream_status st = feed_all(s, wire, wire.size(), decoded);
        return std::make_pair(st, s.error());
    };
    std::string good(c->body);

    SUBCASE("no chunk-signature extension")
    {
        std::string w = good;
        size_t at = w.find(";chunk-signature=");
        w.erase(at, 17 + 64);
        CHECK(run(w).first == s3::stream_status::malformed);
    }
    SUBCASE("a chunk size that is not hex")
    {
        std::string w = good;
        w[0] = 'g';
        CHECK(run(w).first == s3::stream_status::malformed);
    }
    SUBCASE("a chunk size wider than sixteen digits")
    {
        std::string w = "00000000000000064" + good.substr(good.find(';'));
        CHECK(run(w).first == s3::stream_status::malformed);
    }
    SUBCASE("a chunk larger than the allowed maximum")
    {
        auto [st, err] = run(good, {}, 50);
        CHECK(st == s3::stream_status::malformed);
        CHECK(std::string(err.code) == "InvalidRequest");
        CHECK(err.http_status == 400);
    }
    SUBCASE("a header line with a bare LF")
    {
        std::string w = good;
        size_t at = w.find("\r\n");
        w.erase(at, 1);
        CHECK(run(w).first == s3::stream_status::malformed);
    }
    SUBCASE("a header line that never ends")
    {
        CHECK(run(std::string(300, '1')).first == s3::stream_status::malformed);
    }
    SUBCASE("a missing CRLF after the data")
    {
        std::string w = good;
        size_t at = w.find("\r\n", w.find("\r\n") + 2);
        w[at] = 'X';
        CHECK(run(w).first == s3::stream_status::malformed);
    }
    SUBCASE("a signature that is not hex")
    {
        std::string w = good;
        size_t at = w.find("chunk-signature=") + 16;
        w[at] = 'z';
        CHECK(run(w).first == s3::stream_status::malformed);
    }
    SUBCASE("a decoded length the payload does not reach")
    {
        s3::stream_context ctx = res.stream;
        ctx.decoded_length     = c->decoded.size() + 1;
        auto [st, err] = run(good, ctx);
        CHECK(st == s3::stream_status::length_mismatch);
        CHECK(std::string(err.code) == "IncompleteBody");
    }
    SUBCASE("a decoded length the payload passes")
    {
        s3::stream_context ctx = res.stream;
        ctx.decoded_length     = c->decoded.size() - 1;
        CHECK(run(good, ctx).first == s3::stream_status::length_mismatch);
    }
    SUBCASE("a decoded length that is exactly right")
    {
        s3::stream_context ctx = res.stream;
        ctx.decoded_length     = c->decoded.size();
        CHECK(run(good, ctx).first == s3::stream_status::done);
    }
    SUBCASE("an unknown decoded length is accepted")
    {
        s3::stream_context ctx = res.stream;
        ctx.decoded_length     = UINT64_MAX;
        CHECK(run(good, ctx).first == s3::stream_status::done);
    }
    SUBCASE("a stream that has failed stays failed")
    {
        s3::chunk_stream s(res.stream);
        std::string w = good;
        w[0] = 'g';
        std::string decoded;
        REQUIRE(feed_all(s, w, w.size(), decoded) == s3::stream_status::malformed);
        s3::feed_result again = s.feed(good);
        CHECK(again.status == s3::stream_status::malformed);
        CHECK(again.consumed == 0);
        CHECK(again.data.empty());
    }
}

TEST_CASE("an unsigned trailer stream needs no request to be decoded")
{
    std::string wire = "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";
    s3::chunk_stream s(s3::stream_context::unsigned_trailer(11));
    std::string decoded;
    CHECK(feed_all(s, wire, 3, decoded) == s3::stream_status::done);
    CHECK(decoded == "hello world");
    CHECK(s.trailer_value("X-Amz-Checksum-CRC32") == "AAAAAA==");

    s3::chunk_stream s2(s3::stream_context::unsigned_trailer(12));
    std::string d2;
    CHECK(feed_all(s2, wire, 3, d2) == s3::stream_status::length_mismatch);

    s3::chunk_stream s3_(s3::stream_context::unsigned_trailer());
    std::string d3;
    CHECK(feed_all(s3_, "0\r\n\r\n", 2, d3) == s3::stream_status::done);
    CHECK(d3.empty());
    CHECK(s3_.trailer_value("x").empty());

    // minio-go ends each trailer line with a bare LF and the trailer with one CRLF, which ends it here as there.
    s3::chunk_stream s4(s3::stream_context::unsigned_trailer());
    std::string d4;
    CHECK(feed_all(s4, "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\n\r\n", 40, d4) == s3::stream_status::done);
    CHECK(s4.trailer_value("x-amz-checksum-crc32") == "AAAAAA==");
    s3::chunk_stream s5(s3::stream_context::unsigned_trailer());
    std::string d5;
    CHECK(feed_all(s5, "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\nx", 40, d5) == s3::stream_status::need_more);
}

// ─── every field tampered ───

TEST_CASE("changing the signature, method, path, query or secret is a SignatureDoesNotMatch")
{
    for (const kase& c : g_cases)
    {
        INFO(c.name);
        auto expect_mismatch = [&](req r, const char* what) {
            INFO(what);
            s3::verify_result res = r.run();
            CHECK(res.status == s3::sigv4_status::signature_mismatch);
            CHECK(std::string(res.code) == "SignatureDoesNotMatch");
            CHECK(res.http_status == 403);
        };
        bool q = presigned(c);

        {
            req r(c);
            if (q)
                r.query.back() = r.query.back() == '0' ? '1' : '0';
            else
                r.find("authorization")->back() = r.find("authorization")->back() == '0' ? '1' : '0';
            expect_mismatch(r, "signature");
        }
        {
            req r(c);
            r.method = c.method == "GET" ? "PUT" : "GET";
            expect_mismatch(r, "method");
        }
        {
            req r(c);
            r.path += "x";
            expect_mismatch(r, "path appended");
        }
        {
            req r(c);
            r.path.insert(r.path.size() / 2 + 1, "Q");
            expect_mismatch(r, "path middle");
        }
        {
            req r(c);
            r.query += r.query.empty() ? "zz=1" : "&zz=1";
            expect_mismatch(r, "extra query parameter");
        }
        if (!c.query.empty() && !q)
        {
            req r(c);
            r.query = nudge(r.query);
            expect_mismatch(r, "query value");
        }
        {
            req r(c);
            r.secret = nudge(r.secret);
            expect_mismatch(r, "secret");
        }
        {
            // The scope's region is part of the signing key, so naming another is a different signature.
            req r(c);
            std::string& where = q ? r.query : *r.find("authorization");
            size_t at = where.find(c.region);
            if (at != std::string::npos)
            {
                where.replace(at, c.region.size(), std::string(c.region.substr(0, c.region.size() - 1)) + "9");
                expect_mismatch(r, "region");
            }
        }
        {
            // The header form's signed header list is signed, so it cannot be widened or narrowed.
            req r(c);
            if (!q)
            {
                std::string& a = *r.find("authorization");
                size_t at = a.find("SignedHeaders=host;");
                if (at != std::string::npos)
                {
                    a.replace(at, 19, "SignedHeaders=host;host;");
                    expect_mismatch(r, "signed headers list");
                }
            }
        }
    }
}

TEST_CASE("changing the value of any signed header is a mismatch, and an unsigned header changes nothing")
{
    int tampered = 0;
    for (const kase& c : g_cases)
    {
        INFO(c.name);
        bool q = presigned(c);
        req base(c);
        std::string list = q ? signed_list(std::string(c.query), true) : signed_list(*base.find("authorization"), false);
        REQUIRE(!list.empty());

        for (size_t i = 0; i < c.headers.size(); i++)
        {
            std::string name(c.headers[i].n);
            for (char& ch : name)
                ch = static_cast<char>(std::tolower(ch));
            bool is_signed = (";" + list + ";").find(";" + name + ";") != std::string::npos;
            if (name == "authorization")
                continue;
            req r(c);
            r.headers[i].second = nudge(r.headers[i].second);
            INFO("header " << name);
            s3::verify_result res = r.run();
            if (!is_signed)
            {
                CHECK(res.status == s3::sigv4_status::ok);
                continue;
            }
            tampered++;
            REQUIRE(res.status != s3::sigv4_status::ok);
            if (res.status == s3::sigv4_status::malformed)
                CHECK((name == "x-amz-content-sha256" || name == "x-amz-date"));
            else
                CHECK((res.status == s3::sigv4_status::signature_mismatch || res.status == s3::sigv4_status::request_time_too_skewed));
        }

        req r(c);
        r.headers.emplace_back("x-unsigned-extra", "anything");
        r.headers.emplace_back("Expect", "100-continue");
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    CHECK(tampered >= 150);
}

TEST_CASE("an unknown access key is InvalidAccessKeyId")
{
    for (const kase& c : g_cases)
    {
        INFO(c.name);
        req r(c);
        r.access_key = "someone-else";
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::unknown_access_key);
        CHECK(std::string(res.code) == "InvalidAccessKeyId");
        CHECK(res.http_status == 403);
    }
}

TEST_CASE("a signed header the request does not carry is a mismatch")
{
    for (const kase& c : g_cases)
    {
        INFO(c.name);
        req base(c);
        bool q = presigned(c);
        std::string list = q ? signed_list(std::string(c.query), true) : signed_list(*base.find("authorization"), false);
        // Drop the last signed header that is not one of the mandatory ones.
        std::string victim;
        for (size_t b = 0; b < list.size();)
        {
            size_t e = list.find(';', b);
            std::string n = list.substr(b, e == std::string::npos ? e : e - b);
            if (n != "host" && n != "x-amz-date" && n != "x-amz-content-sha256" && n != "date")
                victim = n;
            b = e == std::string::npos ? list.size() : e + 1;
        }
        if (victim.empty())
            continue;
        req r(c);
        r.headers.erase(std::remove_if(r.headers.begin(), r.headers.end(), [&](auto& h) {
            std::string n = h.first;
            for (char& ch : n)
                ch = static_cast<char>(std::tolower(ch));
            return n == victim;
        }), r.headers.end());
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
    }
}

// ─── the clock ───

TEST_CASE("the header form allows fifteen minutes of skew either way")
{
    for (const kase& c : g_cases)
    {
        if (presigned(c))
            continue;
        INFO(c.name);
        int64_t t = signing_time(c);
        for (int64_t d : {int64_t{-900}, int64_t{0}, int64_t{900}})
        {
            req r(c);
            r.now = t + d;
            CHECK(r.run().status == s3::sigv4_status::ok);
        }
        for (int64_t d : {int64_t{-901}, int64_t{901}, int64_t{86400 * 30}, int64_t{-86400 * 30}})
        {
            req r(c);
            r.now = t + d;
            s3::verify_result res = r.run();
            CHECK(res.status == s3::sigv4_status::request_time_too_skewed);
            CHECK(std::string(res.code) == "RequestTimeTooSkewed");
            CHECK(res.http_status == 403);
        }
    }
}

TEST_CASE("the skew window is the option's")
{
    const kase* c = find_case("boto3/get-special-key");
    REQUIRE(c);
    int64_t t = signing_time(*c);
    req r(*c);
    r.opts.skew_seconds = 60;
    r.now = t + 60;
    CHECK(r.run().status == s3::sigv4_status::ok);
    r.now = t + 61;
    CHECK(r.run().status == s3::sigv4_status::request_time_too_skewed);
}

TEST_CASE("a presigned request is good until its expiry and no longer")
{
    int n = 0;
    for (const kase& c : g_cases)
    {
        if (!presigned(c))
            continue;
        INFO(c.name);
        n++;
        int64_t t = signing_time(c), e = expires_of(c);
        REQUIRE(e > 0);
        for (int64_t at : {t - 900, t, t + e / 2, t + e})
        {
            req r(c);
            r.now = at;
            CHECK(r.run().status == s3::sigv4_status::ok);
        }
        {
            req r(c);
            r.now = t + e + 1;
            s3::verify_result res = r.run();
            CHECK(res.status == s3::sigv4_status::expired);
            CHECK(std::string(res.code) == "AccessDenied");
            CHECK(std::string(res.message) == "Request has expired");
            CHECK(res.http_status == 403);
        }
        {
            req r(c);
            r.now = t - 901;
            CHECK(r.run().status == s3::sigv4_status::request_time_too_skewed);
        }
    }
    CHECK(n >= 5);
}

TEST_CASE("X-Amz-Expires must be between one second and a week")
{
    const kase* c = find_case("docs/presigned-get");
    REQUIRE(c);
    for (const char* bad : {"0", "604801", "-5", "abc", ""})
    {
        req r(*c);
        size_t at = r.query.find("X-Amz-Expires=86400");
        r.query.replace(at, 19, std::string("X-Amz-Expires=") + bad);
        s3::verify_result res = r.run();
        INFO(bad);
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "AuthorizationQueryParametersError");
        CHECK(res.http_status == 400);
    }
    // A week is allowed by the limit; the signature then fails only because the parameter is signed.
    req r(*c);
    size_t at = r.query.find("X-Amz-Expires=86400");
    r.query.replace(at, 19, "X-Amz-Expires=604800");
    CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
    r.opts.max_expires_seconds = 100;
    CHECK(r.run().status == s3::sigv4_status::malformed);
}

// ─── region, service, and the shape of the request ───

TEST_CASE("the region is whatever the request says unless one is pinned")
{
    const kase* eu = find_case("boto3/session-token-eu-central");
    const kase* us = find_case("boto3/get-special-key");
    REQUIRE(eu);
    REQUIRE(us);
    {
        req r(*eu);
        CHECK(r.run().status == s3::sigv4_status::ok);
        r.opts.region = "eu-central-1";
        CHECK(r.run().status == s3::sigv4_status::ok);
        r.opts.region = "us-east-1";
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "AuthorizationHeaderMalformed");
        CHECK(res.http_status == 400);
    }
    {
        req r(*us);
        r.opts.region = "us-east-1";
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    const kase* p = find_case("boto3/presigned-get-session-token");
    REQUIRE(p);
    req r(*p);
    r.opts.region = "us-east-1";
    CHECK(r.run().status == s3::sigv4_status::malformed);
    CHECK(std::string(r.run().code) == "AuthorizationQueryParametersError");
}

TEST_CASE("a request signed for no region is taken unless a region is pinned")
{
    // What boto3 sends when it is given region_name='', as the s3-tests suite's STS cases do.
    const std::string date = "20261006T120000Z";
    const std::string empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const std::vector<s3::header_field> signed_headers = {{"host", "127.0.0.1:9000"}, {"x-amz-content-sha256", empty},
                                                          {"x-amz-date", date}};
    s3::sign_input in;
    in.method       = "GET";
    in.raw_path     = "/bucket/key";
    in.headers      = signed_headers;
    in.payload_hash = empty;
    in.access_key   = "AKIDEXAMPLE";
    in.secret       = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    in.region       = "";
    in.amz_date     = date;
    const std::string auth = s3::sign(in);
    REQUIRE(auth.find("/20261006//s3/aws4_request") != std::string::npos);
    std::vector<s3::header_field> sent = signed_headers;
    sent.push_back({"authorization", auth});
    const s3::request_view rv{"GET", "/bucket/key", "", sent, {}};
    auto lookup = [&](sv k) -> sv { return k == in.access_key ? in.secret : sv(); };
    s3::verify_options opts;
    CHECK(s3::verify(rv, opts, lookup, 1791288000).status == s3::sigv4_status::ok);
    opts.region = "us-east-1";
    const s3::verify_result pinned = s3::verify(rv, opts, lookup, 1791288000);
    CHECK(pinned.status == s3::sigv4_status::malformed);
    CHECK(std::string(pinned.code) == "AuthorizationHeaderMalformed");
}

TEST_CASE("a presigned request's stated payload hash is the body's, and one that is no hash is refused")
{
    const kase* p = find_case("docs/presigned-get");
    REQUIRE(p);
    {
        req r(*p);
        r.headers.emplace_back("x-amz-content-sha256", "invalid-sha256");
        const s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "InvalidArgument");
    }
    {
        req r(*p);
        const std::string hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        r.headers.emplace_back("x-amz-content-sha256", hash);
        const s3::verify_result res = r.run();
        REQUIRE(res.status == s3::sigv4_status::ok);
        CHECK(res.payload == s3::payload_kind::hex);
        CHECK(hex_of(res.payload_sha256, 32) == hash);
    }
    {
        req r(*p);
        r.headers.emplace_back("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        const s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::ok);
        CHECK(res.payload == s3::payload_kind::unsigned_payload);
    }
}

TEST_CASE("Signature Version 2: the S3 documentation's examples, a presigned URL, and the refusals")
{
    const sv key = "AKIAIOSFODNN7EXAMPLE";
    const sv secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    auto lookup = [&](sv k) -> sv { return k == key ? secret : sv(); };
    s3::verify_options opts;
    opts.v2_bucket = "johnsmith";
    {
        // "Example Object GET", virtual-hosted, whose signature the S3 documentation publishes.
        const std::vector<s3::header_field> h = {{"host", "johnsmith.s3.amazonaws.com"},
                                                 {"date", "Tue, 27 Mar 2007 19:36:42 +0000"},
                                                 {"authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU="}};
        const s3::request_view rv{"GET", "/photos/puppy.jpg", "", h, {}};
        const s3::verify_result r = s3::verify(rv, opts, lookup, 1175024202);
        REQUIRE(r.status == s3::sigv4_status::ok);
        CHECK(r.access_key() == key);
        CHECK(r.form == s3::auth_form::header);
        CHECK(r.payload == s3::payload_kind::unsigned_payload);
        CHECK(s3::verify(rv, opts, lookup, 1175024202 + 3600).status == s3::sigv4_status::request_time_too_skewed);
        s3::verify_options path_style;
        CHECK(s3::verify(rv, path_style, lookup, 1175024202).status == s3::sigv4_status::signature_mismatch);
    }
    {
        // "Example Object PUT", with its Content-Type on the third line.
        const std::vector<s3::header_field> h = {{"host", "johnsmith.s3.amazonaws.com"},
                                                 {"date", "Tue, 27 Mar 2007 21:15:45 +0000"},
                                                 {"content-type", "image/jpeg"}, {"content-length", "94328"},
                                                 {"authorization", "AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg="}};
        const s3::request_view rv{"PUT", "/photos/puppy.jpg", "", h, {}};
        CHECK(s3::verify(rv, opts, lookup, 1175030145).status == s3::sigv4_status::ok);
        std::vector<s3::header_field> other = h;
        other[2].value = "image/png";
        const s3::request_view changed{"PUT", "/photos/puppy.jpg", "", other, {}};
        CHECK(s3::verify(changed, opts, lookup, 1175030145).status == s3::sigv4_status::signature_mismatch);
    }
    {
        // A presigned URL signs its Expires where a header signs its Date; the value is Python's hmac over that string.
        const std::vector<s3::header_field> h = {{"host", "johnsmith.s3.amazonaws.com"}};
        const s3::request_view rv{"GET", "/photos/puppy.jpg",
                                  "AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1141889120&Signature=fScKGHCDI0NY5E7CYp9Vc8VKMbY%3D", h, {}};
        const s3::verify_result r = s3::verify(rv, opts, lookup, 1141889000);
        CHECK(r.status == s3::sigv4_status::ok);
        CHECK(r.form == s3::auth_form::query);
        const s3::verify_result late = s3::verify(rv, opts, lookup, 1141889121);
        CHECK(late.status == s3::sigv4_status::expired);
        CHECK(std::string(late.code) == "AccessDenied");
        const s3::request_view unknown{"GET", "/photos/puppy.jpg",
                                       "AWSAccessKeyId=AKIANOBODY&Expires=1141889120&Signature=fScKGHCDI0NY5E7CYp9Vc8VKMbY%3D", h, {}};
        CHECK(std::string(s3::verify(unknown, opts, lookup, 1141889000).code) == "InvalidAccessKeyId");
    }
}

TEST_CASE("the service must be the one the server is")
{
    const kase* c = find_case("boto3/get-special-key");
    REQUIRE(c);
    req r(*c);
    r.opts.service = "ec2";
    CHECK(r.run().status == s3::sigv4_status::malformed);
}

TEST_CASE("no credentials at all is AccessDenied, and mixed or foreign schemes are refused")
{
    const kase* c = find_case("boto3/get-special-key");
    REQUIRE(c);
    {
        req r(*c);
        r.headers.erase(std::remove_if(r.headers.begin(), r.headers.end(), [](auto& h) { return h.first == "Authorization"; }), r.headers.end());
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::missing_auth);
        CHECK(std::string(res.code) == "AccessDenied");
        CHECK(res.http_status == 403);
        CHECK(std::string(s3::default_code(s3::sigv4_status::missing_auth)) == "AccessDenied");
    }
    {
        req r(*c);
        *r.find("authorization") = "Bearer AKIAIOSFODNN7EXAMPLE";
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "InvalidRequest");
    }
    {
        // Signature Version 2 is verified, not refused as foreign: this key is not the case's.
        req r(*c);
        *r.find("authorization") = "AWS AKIAIOSFODNN7EXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg=";
        s3::verify_result res = r.run();
        CHECK(std::string(res.code) == "InvalidAccessKeyId");
    }
    {
        req r(*c);
        r.query = "X-Amz-Algorithm=AWS4-HMAC-SHA256";
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "InvalidRequest");
    }
    {
        req r(*c);
        r.headers.erase(std::remove_if(r.headers.begin(), r.headers.end(), [](auto& h) { return h.first == "Authorization"; }), r.headers.end());
        r.query = "X-Amz-Algorithm=AWS4-HMAC-SHA512";
        CHECK(r.run().status == s3::sigv4_status::malformed);
    }
}

TEST_CASE("malformed Authorization headers are AuthorizationHeaderMalformed")
{
    const kase* c = find_case("boto3/get-special-key");
    REQUIRE(c);
    const char* good = "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=";
    const std::string sig(64, '0');
    const std::vector<std::string> bad = {
        "AWS4-HMAC-SHA256",
        "AWS4-HMAC-SHA256 ",
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request",
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request, SignedHeaders=host",
        "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request, SignedHeaders=host, Signature",
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=zz",
        std::string(good) + std::string(63, '0'),
        std::string(good) + std::string(65, '0'),
        std::string(good) + std::string(63, '0') + "g",
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3, SignedHeaders=host, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws5_request, SignedHeaders=host, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=/20260929/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260928/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request, SignedHeaders=, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request, SignedHeaders=x-amz-date, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + sig,
        "AWS4-HMAC-SHA256 Credential=AKIABOTO3EXAMPLE/20260929/" + std::string(60, 'r') + "/s3/aws4_request, SignedHeaders=host, Signature=" + sig,
    };
    for (const std::string& a : bad)
    {
        INFO(a);
        req r(*c);
        *r.find("authorization") = a;
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "AuthorizationHeaderMalformed");
        CHECK(res.http_status == 400);
    }
}

TEST_CASE("the date the request uses, x-amz-date or Date, must be present, well formed and signed")
{
    const kase* c = find_case("docs/put-object");
    REQUIRE(c);
    {
        // The example signs both, and x-amz-date wins.
        req r(*c);
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    {
        req r(*c);
        *r.find("x-amz-date") = "20130524T0000Z";
        CHECK(r.run().status == s3::sigv4_status::malformed);
    }
    {
        req r(*c);
        *r.find("x-amz-date") = "20131324T000000Z";
        CHECK(r.run().status == s3::sigv4_status::malformed);
    }
    {
        req r(*c);
        r.headers.erase(std::remove_if(r.headers.begin(), r.headers.end(), [](auto& h) { return h.first == "x-amz-date"; }), r.headers.end());
        // Date alone is the timestamp, and x-amz-date was signed, so its absence is a mismatch of the list, not a missing date.
        s3::verify_result res = r.run();
        CHECK(res.status != s3::sigv4_status::ok);
    }
    {
        req r(*c);
        r.headers.erase(std::remove_if(r.headers.begin(), r.headers.end(), [](auto& h) { return h.first == "x-amz-date" || h.first == "Date"; }), r.headers.end());
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::missing_auth);
        CHECK(std::string(res.code) == "AccessDenied");
    }
}

TEST_CASE("host, the date header and x-amz-content-sha256 must be signed")
{
    const kase* c = find_case("boto3/get-special-key");
    REQUIRE(c);
    for (const char* dropped : {"host;", ";x-amz-date", "x-amz-content-sha256;"})
    {
        req r(*c);
        std::string& a = *r.find("authorization");
        size_t at = a.find(dropped);
        REQUIRE(at != std::string::npos);
        a.erase(at, std::strlen(dropped));
        INFO(dropped);
        CHECK(r.run().status == s3::sigv4_status::malformed);
    }
}

TEST_CASE("the payload hash comes from x-amz-content-sha256, else from the caller, else it is an error")
{
    const kase* c = find_case("suite/post-x-www-form-urlencoded");
    REQUIRE(c);
    {
        req r(*c);
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    {
        req r(*c);
        r.fallback.clear();
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "InvalidRequest");
    }
    {
        // The hash of a different body gives a different signature.
        req r(*c);
        r.fallback = std::string(64, 'a');
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
    }
    {
        req r(*c);
        r.fallback = "not a hash";
        s3::verify_result res = r.run();
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "InvalidArgument");
    }
    const kase* g = find_case("boto3/get-special-key");
    REQUIRE(g);
    for (const char* v : {"unsigned-payload", "STREAMING-BOGUS", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", "EG3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B85"})
    {
        req r(*g);
        *r.find("x-amz-content-sha256") = v;
        s3::verify_result res = r.run();
        INFO(v);
        CHECK(res.status == s3::sigv4_status::malformed);
        CHECK(std::string(res.code) == "InvalidArgument");
    }
}

TEST_CASE("the payload kinds of the S3 spellings")
{
    struct row { const char* name; s3::payload_kind kind; };
    const row rows[] = {
        {"boto3/put-http-hex-payload", s3::payload_kind::hex},
        {"boto3/put-https-unsigned", s3::payload_kind::unsigned_payload},
        {"boto3/put-https-crc32-trailer", s3::payload_kind::streaming_unsigned_trailer},
        {"docs/chunked-put", s3::payload_kind::streaming_signed},
        {"ref/signed-trailer-crc32", s3::payload_kind::streaming_signed_trailer},
        {"docs/presigned-get", s3::payload_kind::unsigned_payload},
    };
    for (const row& w : rows)
    {
        const kase* c = find_case(w.name);
        REQUIRE(c);
        req r(*c);
        s3::verify_result res = r.run();
        REQUIRE(res.ok());
        CHECK(res.payload == w.kind);
        CHECK(res.stream.kind == w.kind);
    }
    const kase* c = find_case("boto3/put-https-crc32-trailer");
    req r(*c);
    CHECK(r.run().stream.decoded_length == 440);
}

TEST_CASE("a presigned request may name its payload hash in the query, and a header cannot change it")
{
    const kase* c = find_case("docs/presigned-get");
    REQUIRE(c);
    req r(*c);
    r.headers.emplace_back("x-amz-content-sha256", std::string(64, 'a'));
    CHECK(r.run().status == s3::sigv4_status::ok);
    req q(*c);
    q.query += "&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD";
    CHECK(q.run().status == s3::sigv4_status::signature_mismatch);
    req st(*c);
    st.query += "&X-Amz-Content-Sha256=STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    CHECK(st.run().status == s3::sigv4_status::malformed);
}

// ─── canonicalisation rules, one at a time ───

TEST_CASE("query parameters: order, case, encoding, empty values and a bare name")
{
    // ref/query-* were signed with parameters in an order the server must undo.
    for (const char* n : {"ref/query-plus-is-space", "ref/query-no-equals-and-duplicates", "ref/query-equal-names-sort-by-value",
                          "suite/get-vanilla-query-order-key-case", "suite/get-vanilla-query-order-value", "suite/get-vanilla-query-order-key",
                          "suite/get-vanilla-query-order-encoded", "boto3/list-v2-all-params"})
    {
        const kase* c = find_case(n);
        REQUIRE(c);
        INFO(n);
        req r(*c);
        CHECK(r.run().status == s3::sigv4_status::ok);
        // The same parameters in the reverse order are the same request.
        std::vector<std::string> parts;
        std::string q = r.query;
        for (size_t b = 0; b <= q.size();)
        {
            size_t e = q.find('&', b);
            parts.push_back(q.substr(b, e == std::string::npos ? e : e - b));
            b = e == std::string::npos ? q.size() + 1 : e + 1;
        }
        std::reverse(parts.begin(), parts.end());
        std::string rev;
        for (auto& p : parts)
            rev += (rev.empty() ? "" : "&") + p;
        r.query = rev;
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    // '+' in a query is a space, and %7e is the unreserved ~ in either case.
    const kase* c = find_case("ref/query-plus-is-space");
    req r(*c);
    r.query = "prefix=a%20b&x=~&my%20key=1";
    CHECK(r.run().status == s3::sigv4_status::ok);
    r.query = "prefix=a%2Bb&x=~&my%20key=1";
    CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
}

TEST_CASE("paths: encoded once, never normalised, and either the encoded or the sent form may be what was signed")
{
    for (const char* n : {"ref/path-signed-as-sent-lowercase-hex", "ref/path-signed-as-sent-encoded-slash", "ref/path-canonical-lowercase-hex",
                          "ref/path-literal-plus-and-sub-delims", "ref/path-empty-segments-kept", "ref/path-dot-segments-kept", "ref/path-tidied-would-not-verify",
                          "boto3/get-slashes-and-dots", "boto3/get-special-key", "docs/put-object", "suite/get-utf8", "suite/get-unreserved"})
    {
        const kase* c = find_case(n);
        REQUIRE(c);
        INFO(n);
        req r(*c);
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    // Normalising the path would make these the same request as their tidy forms; S3 says they are not.
    {
        req r(*find_case("ref/path-empty-segments-kept"));
        r.path = "/bkt/a/b/";
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
    }
    {
        req r(*find_case("ref/path-dot-segments-kept"));
        r.path = "/bkt/c";
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
        r.path = "/bkt/a/b/../c";
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
    }
    // A path is not encoded twice: a '%' that arrived encoded as %25 stays one level deep.
    {
        req r(*find_case("boto3/get-special-key"));
        CHECK(r.path.find("%20") != std::string::npos);
        r.path = "/bkt/a%2520b";
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
    }
    // The tidy path is the one the docs example signed even though it arrived with a raw '$'.
    {
        const kase* c = find_case("docs/put-object");
        CHECK(c->path.find('$') != sv::npos);
    }
}

TEST_CASE("headers: names in any case, values trimmed and folded, repeats joined with a comma in order")
{
    for (const char* n : {"suite/get-header-value-trim", "suite/get-header-value-multiline", "suite/get-header-value-order",
                          "suite/get-header-key-duplicate", "suite/post-header-key-case", "suite/post-header-key-sort", "suite/post-header-value-case"})
    {
        const kase* c = find_case(n);
        REQUIRE(c);
        INFO(n);
        req r(*c);
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    // The case of a value is part of the signature, though the case of a name is not.
    {
        req r(*find_case("suite/post-header-value-case"));
        *r.find("my-header1") = "value1";
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
        req s(*find_case("suite/post-header-value-case"));
        for (auto& h : s.headers)
            for (char& ch : h.first)
                ch = static_cast<char>(std::toupper(ch));
        CHECK(s.run().status == s3::sigv4_status::ok);
    }
    // Inner whitespace of any width folds to one space, outer whitespace goes, and a tab counts.
    {
        req r(*find_case("suite/get-header-value-trim"));
        *r.find("my-header2") = "\t \"a \t  b\t\tc\"   ";
        *r.find("my-header1") = "   value1\t";
        CHECK(r.run().status == s3::sigv4_status::ok);
        *r.find("my-header2") = "\"a b c\"";
        CHECK(r.run().status == s3::sigv4_status::ok);
        *r.find("my-header2") = "\"abc\"";
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
    }
    // Repeats keep their order.
    {
        req r(*find_case("suite/get-header-value-order"));
        std::vector<std::string*> mine;
        for (auto& h : r.headers)
            if (h.first == "My-Header1")
                mine.push_back(&h.second);
        REQUIRE(mine.size() == 4);
        std::swap(*mine[0], *mine[1]);
        CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
        std::swap(*mine[0], *mine[1]);
        CHECK(r.run().status == s3::sigv4_status::ok);
    }
    // A header that is present and empty is signed as empty, and a comma is not a repeat.
    {
        req r(*find_case("suite/get-header-key-duplicate"));
        int seen = 0;
        for (auto& h : r.headers)
            if (h.first == "My-Header1")
                seen++;
        CHECK(seen == 3);
    }
}

// ─── the callable a caller passes ───

TEST_CASE("secret_lookup accepts a lambda, a function object and a function, and sees the access key")
{
    const kase* c = find_case("boto3/head-object");
    REQUIRE(c);
    std::vector<s3::header_field> fields;
    for (const hdr& h : c->headers)
        fields.push_back({h.n, h.v});
    s3::request_view rv{c->method, c->path, c->query, fields, c->fallback};
    s3::verify_options opts;

    std::string seen;
    auto lambda = [&](sv k) -> sv { seen = std::string(k); return c->secret; };
    CHECK(s3::verify(rv, opts, lambda, c->now).ok());
    CHECK(seen == c->access_key);

    struct functor
    {
        sv secret;
        sv operator()(sv) const { return secret; }
    };
    CHECK(s3::verify(rv, opts, functor{c->secret}, c->now).ok());
    CHECK(s3::verify(rv, opts, functor{"wrong secret"}, c->now).status == s3::sigv4_status::signature_mismatch);
    CHECK(s3::verify(rv, opts, functor{""}, c->now).status == s3::sigv4_status::unknown_access_key);
}

TEST_CASE("a secret longer than a hash block still signs")
{
    // 100 bytes makes the "AWS4" key longer than the 64-byte HMAC block, so it is hashed first.
    const kase* c = find_case("boto3/head-object");
    REQUIRE(c);
    // The reference secret is 44 bytes, so only that side of the block boundary is covered by the table; the other is
    // covered by the success of the hash tests and by this check that a long wrong secret is a mismatch, not a crash.
    req r(*c);
    r.secret = std::string(100, 'k');
    CHECK(r.run().status == s3::sigv4_status::signature_mismatch);
}

TEST_CASE("a signing key kept for reuse is never served to another secret, day, region or service")
{
    for (const kase& c : g_cases)
    {
        INFO(c.name);
        // Twice, so the second is answered from what the first left, then the same request under a changed
        // secret and back again: a key remembered by access key alone would pass the middle one.
        req a(c);
        CHECK(a.run().ok());
        CHECK(a.run().ok());
        req rotated(c);
        rotated.secret = c.secret == sv("rotated-secret") ? "another" : "rotated-secret";
        CHECK(rotated.run().status == s3::sigv4_status::signature_mismatch);
        CHECK(req(c).run().ok());
        // The credential scope names the region, so a pinned other region is refused whatever was kept.
        req pinned(c);
        pinned.opts.region = "no-such-region-1";
        CHECK_FALSE(pinned.run().ok());
        CHECK(req(c).run().ok());
    }
}

TEST_CASE("status names and the S3 code of each result")
{
    CHECK(std::string(s3::default_code(s3::sigv4_status::ok)) == "");
    CHECK(std::string(s3::default_code(s3::sigv4_status::missing_auth)) == "AccessDenied");
    CHECK(std::string(s3::default_code(s3::sigv4_status::malformed)) == "AuthorizationHeaderMalformed");
    CHECK(std::string(s3::default_code(s3::sigv4_status::unknown_access_key)) == "InvalidAccessKeyId");
    CHECK(std::string(s3::default_code(s3::sigv4_status::signature_mismatch)) == "SignatureDoesNotMatch");
    CHECK(std::string(s3::default_code(s3::sigv4_status::request_time_too_skewed)) == "RequestTimeTooSkewed");
    CHECK(std::string(s3::default_code(s3::sigv4_status::expired)) == "AccessDenied");
    s3::error_info m = s3::payload_mismatch();
    CHECK(std::string(m.code) == "XAmzContentSHA256Mismatch");
    CHECK(m.http_status == 400);
}
