// Fuzz target: the metrics runtime's remote-write codec (socketley/runtime/metrics/metrics_remote): a Snappy block
// and a WriteRequest, as a POST body brings them.
//
// The first byte chooses: 0 the rest is a WriteRequest's protobuf, 1 it is a Snappy-compressed body, 2 it is bytes
// to compress, 3 it describes one series by its sizes (a count of labels, then two bytes of a name's length and two
// of a value's for each), which is written as a request and read back, so a few bytes reach the bounds a series is
// stored under (64 labels, names of 256 bytes, 64 KiB in all) that a spelled-out request would need megabytes for.
//
// Properties checked, beyond "did it crash":
//   * a block that opens says the length it opened to, and compressed again opens to the same bytes;
//   * any bytes compressed fit snappy_bound and open to themselves;
//   * a request refused hands on nothing, and one taken hands on views that lie inside the bytes it was read from;
//   * the series and samples a request hands on, written again by the encoder, read back the same, bit for bit;
//   * every series handed on is stored or refused by series_fits exactly as a scraped line's bounds say.
//
// Not reached here: who may write at all (a key or an admin's bearer token, never a cookie) is decided in
// metrics_run's handler, before the body is read; test_metrics_remote_write_guarded.sh holds that.
#include "fuzz_common.h"
#include "runtime/metrics/metrics_remote.h"
#include "runtime/metrics/metrics_text.h"

#include <algorithm>
#include <bit>
#include <cstdio>
#include <string>
#include <vector>

namespace r = socketley::metrics::remote;

namespace {

struct copy
{
    std::vector<std::pair<std::string, std::string>> labels;
    std::vector<std::pair<uint64_t, int64_t>> samples;
};

// The bounds metrics_run stores a written series under, a scraped line's.
constexpr r::series_bounds stored{socketley::metrics::text_limits{}.max_labels, socketley::metrics::text_limits{}.max_name,
                                  socketley::metrics::text_limits{}.max_line};

// series_fits, said again from the numbers the manual gives, so that a bound loosened in either place is seen.
bool fits_by_the_book(const r::series& s)
{
    if (s.labels.size() > 64)
        return false;
    size_t bytes = 0;
    for (const auto& l : s.labels)
    {
        if (l.name.size() > 256)
            return false;
        bytes += l.name.size() + l.value.size();
    }
    return bytes <= 64 * 1024;
}

bool inside(std::string_view part, std::string_view whole)
{
    return part.empty() || (part.data() >= whole.data() && part.data() + part.size() <= whole.data() + whole.size());
}

struct checking_sink : r::write_sink
{
    std::string_view body;
    std::vector<copy> got;
    size_t metadata{0};
    size_t fitting[2]{0, 0};

    void on_series(const r::series& s) override
    {
        FUZZ_CHECK(r::series_fits(s, stored) == fits_by_the_book(s),
                   "a series stored past a scraped line's bounds, or one refused within them");
        ++fitting[r::series_fits(s, stored)];
        copy c;
        for (const auto& l : s.labels)
        {
            FUZZ_CHECK(inside(l.name, body) && inside(l.value, body), "a label view outside the request");
            c.labels.emplace_back(std::string(l.name), std::string(l.value));
        }
        for (const auto& x : s.samples)
            c.samples.emplace_back(std::bit_cast<uint64_t>(x.value), x.timestamp_ms);
        got.push_back(std::move(c));
    }
    void on_metadata(const r::metadata& m) override
    {
        FUZZ_CHECK(inside(m.family, body) && inside(m.help, body) && inside(m.unit, body),
                   "a metadata view outside the request");
        ++metadata;
    }
};

void request(std::string_view proto, std::string_view body_seen)
{
    checking_sink k;
    k.body = body_seen;
    r::write_decoder d;
    const r::decode_result res = d.decode(proto, k);
    if (!res.ok)
    {
        FUZZ_CHECK(res.error != nullptr, "a refusal without a reason");
        FUZZ_CHECK(k.got.empty() && k.metadata == 0, "a refused request handed series on");
        return;
    }
    FUZZ_CHECK(res.series == k.got.size() && res.metadata == k.metadata, "the counts are not what was handed on");

    r::write_encoder e;
    std::vector<r::label> ls;
    std::vector<r::sample> ss;
    for (const copy& c : k.got)
    {
        ls.clear();
        ss.clear();
        for (const auto& [n, v] : c.labels)
            ls.push_back({n, v});
        for (const auto& [bits, ts] : c.samples)
            ss.push_back({std::bit_cast<double>(bits), ts});
        e.add(ls, ss);
    }
    std::string wire;
    e.compressed(wire);
    checking_sink again;
    std::string opened;
    FUZZ_CHECK(r::snappy_decompress(wire, opened, 1u << 30), "an encoded request does not open");
    again.body = opened;
    r::write_decoder d2;
    const r::decode_result res2 = d2.decode(opened, again);
    FUZZ_CHECK(res2.ok, "an encoded request is refused");
    FUZZ_CHECK(again.got.size() == k.got.size(), "an encoded request reads back with other series");
    for (size_t i = 0; i < k.got.size(); ++i)
        FUZZ_CHECK(again.got[i].labels == k.got[i].labels && again.got[i].samples == k.got[i].samples,
                   "an encoded series reads back differently");
}

void block(std::string_view in)
{
    std::string out;
    if (!r::snappy_decompress(in, out, 1u << 22))
        return;
    size_t said = 0;
    FUZZ_CHECK(r::snappy_length(reinterpret_cast<const uint8_t*>(in.data()), in.size(), said) && said == out.size(),
               "a block opened to another length than it says");
    std::string c, back;
    r::snappy_compress(out, c);
    FUZZ_CHECK(c.size() <= r::snappy_bound(out.size()), "compressed past the bound");
    FUZZ_CHECK(r::snappy_decompress(c, back, out.size()) && back == out, "an opened block compressed again differs");
    request(out, out);
}

void bytes(std::string_view in)
{
    std::string c, back;
    r::snappy_compress(in, c);
    FUZZ_CHECK(c.size() <= r::snappy_bound(in.size()), "compressed past the bound");
    FUZZ_CHECK(r::snappy_decompress(c, back, in.size()) && back == in, "compressed bytes do not open to themselves");
}

void sized(std::string_view in)
{
    if (in.empty())
        return;
    const size_t n = static_cast<uint8_t>(in[0]);
    in.remove_prefix(1);
    std::vector<std::string> names, values;
    size_t total = 0;
    for (size_t i = 0; i < n && total < (1u << 20); ++i)
    {
        // A name of its index first, so no two are the same, which the decoder refuses before any bound.
        size_t nl = i % 7, vl = 1;
        if (in.size() >= 4)
        {
            const auto u = [&](size_t i) { return static_cast<size_t>(static_cast<uint8_t>(in[i])); };
            nl = (u(0) | u(1) << 8) % 1024;
            vl = u(2) | u(3) << 8;
            in.remove_prefix(4);
        }
        char head[8];
        std::snprintf(head, sizeof head, "l%03zu", i);
        names.push_back(head + std::string(nl, 'n'));
        values.push_back(std::string(vl, 'v'));
        total += names.back().size() + vl;
    }
    std::vector<r::label> ls;
    for (size_t i = 0; i < names.size(); ++i)
        ls.push_back({names[i], values[i]});
    const r::sample one{1.5, 1700000000000};
    r::write_encoder e;
    e.add(ls, std::span<const r::sample>(&one, 1));
    checking_sink k;
    k.body = e.proto();
    r::write_decoder d;
    const r::decode_result res = d.decode(e.proto(), k);
    FUZZ_CHECK(res.ok && k.got.size() == 1, "a series written by the encoder reads back");
    FUZZ_CHECK(k.got[0].labels.size() == names.size(), "with every label it was given");
    // At the edge the bounds name, one byte either side decides.
    size_t bytes = 0, longest = 0;
    for (size_t i = 0; i < names.size(); ++i)
    {
        bytes += names[i].size() + values[i].size();
        longest = std::max(longest, names[i].size());
    }
    const bool want = names.size() <= 64 && longest <= 256 && bytes <= 64 * 1024;
    FUZZ_CHECK(k.fitting[1] == (want ? 1u : 0u) && k.fitting[0] == (want ? 0u : 1u),
               "a series stored or refused against its sizes");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = fuzz::never_null(data);
    fuzz::set_current(data, size);
    if (size == 0)
        return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data + 1), size - 1);
    switch (data[0] % 4)
    {
        case 0: request(rest, rest); break;
        case 1: block(rest); break;
        case 2: bytes(rest); break;
        default: sized(rest); break;
    }
    return 0;
}
