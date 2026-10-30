// The remote-write codec: Snappy blocks built by hand from the format description, each kind of element and each
// refusal; WriteRequests built byte by byte, unknown fields, negative timestamps and malformed ones; and a request
// written by the encoder, compressed, opened and read back as what went in.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <bit>
#include <cmath>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "runtime/metrics/metrics_remote.h"

namespace r = socketley::metrics::remote;
using namespace std::string_literals;

namespace
{

std::string open_block(const std::string& block, size_t cap = 1u << 20)
{
    std::string out(cap, '\0');
    const long n = r::snappy_decompress(reinterpret_cast<const uint8_t*>(block.data()), block.size(),
                                        reinterpret_cast<uint8_t*>(out.data()), out.size());
    if (n < 0)
        return "<refused>";
    out.resize(static_cast<size_t>(n));
    return out;
}

std::string roundtrip(const std::string& in)
{
    std::string c, back;
    r::snappy_compress(in, c);
    REQUIRE(c.size() <= r::snappy_bound(in.size()));
    REQUIRE(r::snappy_decompress(c, back, in.size()));
    return back;
}

struct got
{
    std::vector<std::vector<std::pair<std::string, std::string>>> labels;
    std::vector<std::vector<std::pair<uint64_t, int64_t>>> samples;
    std::vector<uint32_t> histograms, exemplars;
    std::vector<std::tuple<uint32_t, std::string, std::string, std::string>> meta;
};

struct keeping_sink : r::write_sink
{
    got g;
    void on_series(const r::series& s) override
    {
        auto& ls = g.labels.emplace_back();
        for (const auto& l : s.labels)
            ls.emplace_back(std::string(l.name), std::string(l.value));
        auto& ss = g.samples.emplace_back();
        for (const auto& x : s.samples)
            ss.emplace_back(std::bit_cast<uint64_t>(x.value), x.timestamp_ms);
        g.histograms.push_back(s.histograms);
        g.exemplars.push_back(s.exemplars);
    }
    void on_metadata(const r::metadata& m) override
    {
        g.meta.emplace_back(m.type, std::string(m.family), std::string(m.help), std::string(m.unit));
    }
};

std::string field(uint8_t tag, const std::string& body)
{
    std::string out(1, static_cast<char>(tag));
    size_t n = body.size();
    while (n >= 0x80)
    {
        out += static_cast<char>(n | 0x80);
        n >>= 7;
    }
    out += static_cast<char>(n);
    return out + body;
}

std::string double_le(double v)
{
    const uint64_t bits = std::bit_cast<uint64_t>(v);
    std::string out(8, '\0');
    for (int i = 0; i < 8; ++i)
        out[static_cast<size_t>(i)] = static_cast<char>(bits >> (8 * i));
    return out;
}

// timeseries { labels {__name__ up} labels {job x} samples {1.0 @ 1000} }, written out by hand.
const std::string one_series =
    "\x0a\x28"
    "\x0a\x0e" "\x0a\x08" "__name__" "\x12\x02" "up"
    "\x0a\x08" "\x0a\x03" "job" "\x12\x01" "x"
    "\x12\x0c" "\x09" "\x00\x00\x00\x00\x00\x00\xf0\x3f" "\x10\xe8\x07"s;

}   // namespace

// ── Snappy ──────────────────────────────────────────────────────────────────

TEST_CASE("snappy: the empty block and a literal")
{
    CHECK(open_block("\x00"s) == "");
    CHECK(open_block("\x01\x00" "a"s) == "a");
    CHECK(open_block("\x05\x10" "hello"s) == "hello");
}

TEST_CASE("snappy: a literal's length in one to four extra bytes")
{
    const std::string body(300, 'q');
    // 300 - 1 = 299 needs two bytes, tag 61 << 2.
    CHECK(open_block("\xac\x02" "\xf4\x2b\x01"s + body) == body);
    const std::string sixty(60, 'z');
    CHECK(open_block("\x3c" "\xf0\x3b"s + sixty) == sixty);
    const std::string seventy(70, 'y');
    CHECK(open_block("\x46" "\xfc\x45\x00\x00\x00"s + seventy) == seventy);
}

TEST_CASE("snappy: copies with 1-, 2- and 4-byte offsets, overlapping ones too")
{
    // abcd, then 8 bytes from 4 back: tag 01 | (8-4)<<2.
    CHECK(open_block("\x0c\x0c" "abcd" "\x11\x04"s) == "abcdabcdabcd");
    // A run: one byte, then 9 copied from 1 back.
    CHECK(open_block("\x0a\x00" "a" "\x15\x01"s) == "aaaaaaaaaa");
    // 2-byte offset 4, length 20: tag 10 | (20-1)<<2.
    CHECK(open_block("\x18\x0c" "wxyz" "\x4e\x04\x00"s) == "wxyzwxyzwxyzwxyzwxyzwxyz");
    // 4-byte offset 2, length 6: tag 11 | (6-1)<<2.
    CHECK(open_block("\x08\x04" "mn" "\x17\x02\x00\x00\x00"s) == "mnmnmnmn");
    // An 11-bit offset, its top three bits in the tag: 300 back.
    std::string far(300, 'f');
    far[0] = 'S';
    std::string block = "\xb4\x02"s;
    block += "\xf4\x2b\x01"s + far;
    block += static_cast<char>(1 | (4 << 2) | ((300 >> 8) << 5));
    block += static_cast<char>(300 & 0xff);
    CHECK(open_block(block) == far + far.substr(0, 8));
}

TEST_CASE("snappy: what is refused")
{
    CHECK(open_block("") == "<refused>");
    CHECK(open_block("\x80"s) == "<refused>");
    CHECK(open_block("\xff\xff\xff\xff\x1f"s) == "<refused>");
    CHECK(open_block("\x80\x80\x80\x80\x80\x01"s) == "<refused>");
    // Says 3 and holds 2, says 1 and holds 2.
    CHECK(open_block("\x03\x04" "ab"s) == "<refused>");
    CHECK(open_block("\x01\x04" "ab"s) == "<refused>");
    // A literal running past the end.
    CHECK(open_block("\x05\x10" "hel"s) == "<refused>");
    // Offset 0, an offset before the start, and a copy past the length said.
    CHECK(open_block("\x05\x00" "a" "\x01\x00"s) == "<refused>");
    CHECK(open_block("\x05\x00" "a" "\x01\x02"s) == "<refused>");
    CHECK(open_block("\x04\x00" "a" "\x05\x01"s) == "<refused>");
    // An element cut short.
    CHECK(open_block("\x05\x00" "a" "\x02\x01"s) == "<refused>");
    CHECK(open_block("\x05\x00" "a" "\x03\x01\x00"s) == "<refused>");
    // A block that says more than the room it is given.
    CHECK(open_block("\x05\x10" "hello"s, 4) == "<refused>");
    std::string out;
    CHECK_FALSE(r::snappy_decompress("\x05\x10" "hello"s, out, 4));
    CHECK(r::snappy_decompress("\x05\x10" "hello"s, out, 5));
    CHECK(out == "hello");
}

TEST_CASE("snappy: what is written opens to what went in")
{
    CHECK(roundtrip("") == "");
    CHECK(roundtrip("a") == "a");
    const std::string text = "the quick brown fox jumps over the lazy dog, the quick brown fox jumps again";
    CHECK(roundtrip(text) == text);
    std::string runs(200000, 'x');
    for (size_t i = 0; i < runs.size(); i += 777)
        runs[i] = static_cast<char>('a' + i % 26);
    std::string c;
    r::snappy_compress(runs, c);
    CHECK(c.size() < runs.size() / 10);
    CHECK(roundtrip(runs) == runs);
    std::mt19937_64 rng(7);
    std::string noise(150000, '\0');
    for (char& ch : noise)
        ch = static_cast<char>(rng());
    CHECK(roundtrip(noise) == noise);
    // A series name repeated the way a WriteRequest repeats it, which is what remote_write compresses.
    std::string req;
    for (int i = 0; i < 2000; ++i)
        req += "\x0a\x08__name__\x12\x10socketley_up_one" + std::to_string(i);
    r::snappy_compress(req, c);
    CHECK(c.size() < req.size() / 3);
    CHECK(roundtrip(req) == req);
}

// ── WriteRequest ────────────────────────────────────────────────────────────

TEST_CASE("a WriteRequest written by hand is read into its labels and samples")
{
    keeping_sink k;
    r::write_decoder d;
    const r::decode_result res = d.decode(one_series, k);
    REQUIRE(res.ok);
    CHECK(res.error == nullptr);
    CHECK(res.series == 1);
    CHECK(res.samples == 1);
    REQUIRE(k.g.labels.size() == 1);
    CHECK(k.g.labels[0] == std::vector<std::pair<std::string, std::string>>{{"__name__", "up"}, {"job", "x"}});
    CHECK(k.g.samples[0] == std::vector<std::pair<uint64_t, int64_t>>{{std::bit_cast<uint64_t>(1.0), 1000}});
}

TEST_CASE("the views are of the body, not copies")
{
    struct view_sink : r::write_sink
    {
        std::string_view body;
        bool inside{true};
        void on_series(const r::series& s) override
        {
            for (const auto& l : s.labels)
                inside = inside && l.name.data() >= body.data() && l.value.data() + l.value.size() <= body.data() + body.size();
        }
    } v;
    v.body = one_series;
    r::write_decoder d;
    REQUIRE(d.decode(one_series, v).ok);
    CHECK(v.inside);
}

TEST_CASE("unknown fields are skipped, fields in any order, the last of a repeated scalar kept")
{
    // A sample whose timestamp comes first, then the value twice, then an unknown fixed32 and varint.
    const std::string smp = "\x10\x05"s + "\x09" + double_le(2.0) + "\x09" + double_le(3.5) + "\x7d\x01\x02\x03\x04"s +
                            "\x78\x2a"s;
    const std::string lbl = "\x12\x01" "v" "\x0a\x01" "n" "\x1a\x03" "zzz"s;
    // An exemplar, a native histogram, an unknown varint field 9 and a sample before a label.
    const std::string ts = field(0x12, smp) + field(0x0a, lbl) + field(0x1a, "\x0a\x00"s) + field(0x22, "") +
                           field(0x22, "\x08\x01"s) + "\x48\x01"s;
    // The reserved field 2 of the request, and an unknown 64-bit field 7.
    const std::string req = "\x12\x02" "xx"s + field(0x0a, ts) + "\x39"s + double_le(9.0);
    keeping_sink k;
    r::write_decoder d;
    const r::decode_result res = d.decode(req, k);
    REQUIRE(res.ok);
    CHECK(res.histograms == 2);
    REQUIRE(k.g.labels.size() == 1);
    CHECK(k.g.labels[0] == std::vector<std::pair<std::string, std::string>>{{"n", "v"}});
    CHECK(k.g.samples[0] == std::vector<std::pair<uint64_t, int64_t>>{{std::bit_cast<uint64_t>(3.5), 5}});
    CHECK(k.g.histograms[0] == 2);
    CHECK(k.g.exemplars[0] == 1);
}

TEST_CASE("a negative timestamp is ten bytes of varint, and fields at their default may be absent")
{
    const std::string smp = "\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"s;
    const std::string req = field(0x0a, field(0x0a, "\x0a\x01q"s) + field(0x12, smp) + field(0x12, ""));
    keeping_sink k;
    r::write_decoder d;
    REQUIRE(d.decode(req, k).ok);
    CHECK(k.g.samples[0] == std::vector<std::pair<uint64_t, int64_t>>{{0, -1}, {0, 0}});
    CHECK(k.g.labels[0] == std::vector<std::pair<std::string, std::string>>{{"q", ""}});
}

TEST_CASE("metadata is read")
{
    const std::string md = "\x08\x01"s + field(0x12, "http_requests_total") + field(0x22, "Requests.") +
                           field(0x2a, "requests");
    keeping_sink k;
    r::write_decoder d;
    const r::decode_result res = d.decode(field(0x1a, md) + one_series, k);
    REQUIRE(res.ok);
    CHECK(res.metadata == 1);
    REQUIRE(k.g.meta.size() == 1);
    CHECK(k.g.meta[0] == std::make_tuple(1u, "http_requests_total"s, "Requests."s, "requests"s));
    CHECK(k.g.labels.size() == 1);
}

TEST_CASE("a malformed request is refused whole, its good series handed on to nobody")
{
    const auto refused = [](const std::string& req) {
        keeping_sink k;
        r::write_decoder d;
        const r::decode_result res = d.decode(req, k);
        return !res.ok && res.error != nullptr && k.g.labels.empty() && k.g.meta.empty();
    };
    // A length past the end, after one good series.
    CHECK(refused(one_series + "\x0a\x05\x0a\x03"s));
    // A tag cut short, a field number 0, a group start and a group end.
    CHECK(refused(one_series + "\x80"s));
    CHECK(refused(one_series + "\x00\x00"s));
    CHECK(refused(one_series + "\x0b"s));
    CHECK(refused(one_series + "\x0c"s));
    // A varint of eleven bytes, and a tenth byte above the 64th bit.
    CHECK(refused(field(0x0a, field(0x12, "\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"s))));
    CHECK(refused(field(0x0a, field(0x12, "\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02"s))));
    // Known fields under the wrong wire type: timeseries as a varint, a label as a varint, a value as a varint.
    CHECK(refused("\x08\x01"s));
    CHECK(refused(field(0x0a, "\x08\x01"s)));
    CHECK(refused(field(0x0a, field(0x0a, "\x08\x01"s))));
    CHECK(refused(field(0x0a, field(0x12, "\x08\x01"s))));
    // A double cut short.
    CHECK(refused(field(0x0a, field(0x12, "\x09\x00\x00\x00"s))));
    // A fixed32 cut short.
    CHECK(refused(field(0x0a, "\x7d\x01\x02"s)));
    // And an empty request is a good one with nothing in it.
    keeping_sink k;
    r::write_decoder d;
    const r::decode_result res = d.decode("", k);
    CHECK(res.ok);
    CHECK(res.series == 0);
}

TEST_CASE("encoded, compressed, opened and decoded, a request reads back as what went in")
{
    r::write_encoder e;
    const r::label a[] = {{"__name__", "socketley_proxy_request_duration_seconds_bucket"}, {"le", "+Inf"},
                          {"name", "px"}};
    const r::sample as[] = {{12.0, 1761800000000}, {13.0, 1761800010000}, {0.0, 0}, {-0.0, -5},
                            {std::nan(""), 1}, {INFINITY, 2}};
    const std::string long_value(300, 'j');
    const r::label b[] = {{"__name__", "up"}, {"job", long_value}};
    const r::sample bs[] = {{1.0, 7}};
    e.add(a, as);
    e.add_metadata({static_cast<uint32_t>(r::metadata_type::histogram), "socketley_proxy_request_duration_seconds",
                    "HTTP requests.", "seconds"});
    e.add(b, bs);
    e.add({}, {});
    std::string body;
    e.compressed(body);

    keeping_sink k;
    r::write_decoder d;
    const r::decode_result res = d.decode_snappy(body, k);
    REQUIRE(res.ok);
    CHECK(res.series == 3);
    CHECK(res.samples == 7);
    REQUIRE(k.g.labels.size() == 3);
    CHECK(k.g.labels[0][0] == std::pair<std::string, std::string>{"__name__",
                                                                    "socketley_proxy_request_duration_seconds_bucket"});
    CHECK(k.g.labels[0][2] == std::pair<std::string, std::string>{"name", "px"});
    CHECK(k.g.labels[1][1].second == std::string(300, 'j'));
    CHECK(k.g.labels[2].empty());
    REQUIRE(k.g.samples[0].size() == 6);
    for (size_t i = 0; i < 6; ++i)
    {
        CAPTURE(i);
        CHECK(k.g.samples[0][i].first == std::bit_cast<uint64_t>(as[i].value));
        CHECK(k.g.samples[0][i].second == as[i].timestamp_ms);
    }
    REQUIRE(k.g.meta.size() == 1);
    CHECK(std::get<0>(k.g.meta[0]) == 3u);
    CHECK(std::get<3>(k.g.meta[0]) == "seconds");

    // The protobuf alone decodes the same, and a body opened past the limit is refused.
    keeping_sink k2;
    CHECK(d.decode(e.proto(), k2).ok);
    CHECK(k2.g.samples == k.g.samples);
    keeping_sink k3;
    CHECK_FALSE(d.decode_snappy(body, k3, e.proto().size() - 1).ok);
    CHECK(k3.g.labels.empty());
}

TEST_CASE("the encoder writes the bytes the hand-built request holds")
{
    r::write_encoder e;
    const r::label l[] = {{"__name__", "up"}, {"job", "x"}};
    const r::sample s[] = {{1.0, 1000}};
    e.add(l, s);
    CHECK(e.proto() == one_series);
}
