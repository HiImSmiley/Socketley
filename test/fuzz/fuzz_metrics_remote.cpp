// Fuzz target: the metrics runtime's remote-write codec (socketley/runtime/metrics/metrics_remote): a Snappy block
// and a WriteRequest, as a POST body brings them.
//
// The first byte chooses: 0 the rest is a WriteRequest's protobuf, 1 it is a Snappy-compressed body, 2 it is bytes
// to compress.
//
// Properties checked, beyond "did it crash":
//   * a block that opens says the length it opened to, and compressed again opens to the same bytes;
//   * any bytes compressed fit snappy_bound and open to themselves;
//   * a request refused hands on nothing, and one taken hands on views that lie inside the bytes it was read from;
//   * the series and samples a request hands on, written again by the encoder, read back the same, bit for bit.
#include "fuzz_common.h"
#include "runtime/metrics/metrics_remote.h"

#include <bit>
#include <string>
#include <vector>

namespace r = socketley::metrics::remote;

namespace {

struct copy
{
    std::vector<std::pair<std::string, std::string>> labels;
    std::vector<std::pair<uint64_t, int64_t>> samples;
};

bool inside(std::string_view part, std::string_view whole)
{
    return part.empty() || (part.data() >= whole.data() && part.data() + part.size() <= whole.data() + whole.size());
}

struct checking_sink : r::write_sink
{
    std::string_view body;
    std::vector<copy> got;
    size_t metadata{0};

    void on_series(const r::series& s) override
    {
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

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = fuzz::never_null(data);
    fuzz::set_current(data, size);
    if (size == 0)
        return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data + 1), size - 1);
    switch (data[0] % 3)
    {
        case 0: request(rest, rest); break;
        case 1: block(rest); break;
        default: bytes(rest); break;
    }
    return 0;
}
