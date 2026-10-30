// Fuzz target: the metrics runtime's readers of bytes the disk hands back (socketley/runtime/metrics/): a raw chunk, a
// tier chunk, a block file and a head log.
//
// The first byte chooses: 0 a raw chunk, 1 a tier chunk, 2 samples written into a fixed head slot, 3 a block file with
// its crc32cs made to match so the reader behind them is reached, 4 a head log.
//
// Properties checked, beyond "did it crash":
//   * a chunk that decodes encodes back to one that decodes to the same samples, bit for bit;
//   * samples written into a slot until it is full never overflow it and decode back bit for bit;
//   * a block that opens hands out chunks that decode or fail cleanly, and the labels of every series are sorted;
//   * a head log read again up to where its whole records end reads the same, with nothing torn.
#include "fuzz_common.h"
#include "runtime/metrics/metrics_block.h"
#include "runtime/metrics/metrics_chunk.h"
#include "shared/util/byte_codec.h"
#include "shared/util/crc.h"

#include <bit>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace mt = socketley::metrics;

namespace {

bool same(const std::vector<mt::sample>& a, const std::vector<mt::sample>& b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i].t != b[i].t || std::bit_cast<uint64_t>(a[i].v) != std::bit_cast<uint64_t>(b[i].v))
            return false;
    return true;
}

void raw_chunk(const uint8_t* p, size_t n)
{
    std::vector<mt::sample> out;
    if (!mt::decode_chunk(std::span<const uint8_t>(p, n), out))
        return;
    std::vector<uint8_t> enc;
    mt::encode_chunk(out, enc);
    std::vector<mt::sample> again;
    FUZZ_CHECK(mt::decode_chunk(enc, again), "a re-encoded chunk does not decode");
    FUZZ_CHECK(same(out, again), "a re-encoded chunk decodes to other samples");
}

void tier_chunk(const uint8_t* p, size_t n)
{
    std::vector<mt::tier_point> out;
    if (!mt::decode_tier_chunk(std::span<const uint8_t>(p, n), out))
        return;
    std::vector<uint8_t> enc;
    mt::encode_tier_chunk(out, enc);
    std::vector<mt::tier_point> again;
    FUZZ_CHECK(mt::decode_tier_chunk(enc, again), "a re-encoded tier chunk does not decode");
    FUZZ_CHECK(again.size() == out.size(), "a re-encoded tier chunk lost points");
    for (size_t i = 0; i < out.size(); ++i)
        FUZZ_CHECK(again[i].t == out[i].t && std::bit_cast<uint64_t>(again[i].rise) == std::bit_cast<uint64_t>(out[i].rise) &&
                       std::bit_cast<uint64_t>(again[i].min) == std::bit_cast<uint64_t>(out[i].min),
                   "a re-encoded tier chunk decodes to other points");
}

void slot(const uint8_t* p, size_t n)
{
    // A guard band past the slot's end, so a write beyond it is seen even without the sanitizer.
    uint8_t buf[200 + 16] = {};
    mt::chunk_appender a;
    std::vector<mt::sample> in;
    for (size_t i = 0; i + 16 <= n; i += 16)
    {
        const mt::sample x{static_cast<int64_t>(socketley::bytes::load64(p + i)),
                           std::bit_cast<double>(socketley::bytes::load64(p + i + 8))};
        if (!a.append(buf, 200, x.t, x.v))
            break;
        in.push_back(x);
    }
    for (size_t i = 200; i < sizeof buf; ++i)
        FUZZ_CHECK(buf[i] == 0, "the appender wrote past its slot");
    std::vector<mt::sample> out;
    FUZZ_CHECK(mt::decode_chunk(std::span<const uint8_t>(buf, in.empty() ? 0 : a.bytes()), out), "a slot does not decode");
    FUZZ_CHECK(same(in, out), "a slot decodes to other samples");
}

std::string& scratch_path()
{
    static std::string path = [] {
        char t[] = "/tmp/fuzz_metrics.XXXXXX";
        const int fd = ::mkstemp(t);
        if (fd < 0)
            abort();
        ::close(fd);
        return std::string(t);
    }();
    return path;
}

struct cleanup
{
    ~cleanup() { ::unlink(scratch_path().c_str()); }
} cleanup_at_exit;

void block_file(const uint8_t* p, size_t n)
{
    constexpr size_t footer = 120;
    std::string f(reinterpret_cast<const char*>(p), n);
    if (f.size() >= footer)
    {
        auto* d = reinterpret_cast<uint8_t*>(f.data());
        uint8_t* ft = d + f.size() - footer;
        std::memcpy(ft, "SKLMBLK1", 8);
        socketley::bytes::store32(ft + 8, mt::block_version);
        const uint64_t body = f.size() - footer;
        for (int i = 0; i < 4; ++i)
        {
            uint8_t* s = ft + 36 + 20 * i;
            const uint64_t off = socketley::bytes::load64(s) % (body + 1);
            const uint64_t len = socketley::bytes::load64(s + 8) % (body - off + 1);
            socketley::bytes::store64(s, off);
            socketley::bytes::store64(s + 8, len);
            socketley::bytes::store32(s + 16, socketley::crc::crc32c(d + off, len));
        }
        socketley::bytes::store32(ft + footer - 4, socketley::crc::crc32c(ft, footer - 4));
    }
    std::string why;
    {
        const int fd = ::open(scratch_path().c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0)
            abort();
        if (::write(fd, f.data(), f.size()) != static_cast<ssize_t>(f.size()))
            abort();
        ::close(fd);
    }
    auto b = mt::block::open(scratch_path(), why);
    if (!b)
        return;
    mt::label_set ls;
    std::vector<mt::sample> xs;
    std::vector<mt::tier_point> pts;
    for (uint32_t i = 0; i < b->count(); ++i)
    {
        b->labels(i, ls);
        for (size_t k = 1; k < ls.size(); ++k)
            FUZZ_CHECK(ls[k - 1].name < ls[k].name, "a block opened with labels out of order");
        int64_t lo = 0, hi = 0;
        b->range(i, lo, hi);
        FUZZ_CHECK(lo <= hi, "a block opened with a series ending before it starts");
        b->each_chunk(i, [&](const mt::block::chunk& c) {
            xs.clear();
            pts.clear();
            if (b->step() == 0)
                mt::decode_chunk(c.bytes, xs);
            else
                mt::decode_tier_chunk(c.bytes, pts);
            return true;
        });
    }
    std::vector<std::pair<mt::label, uint32_t>> ps;
    b->postings(ps);
}

struct counting final : mt::log_visitor
{
    size_t n_series{0}, n_chunks{0}, n_samples{0};
    void series(uint32_t, mt::label_set&) override { ++n_series; }
    void chunk(uint32_t, int64_t mint, int64_t maxt, std::span<const uint8_t>) override
    {
        FUZZ_CHECK(mint <= maxt, "a chunk record ending before it starts");
        ++n_chunks;
    }
    void sample(uint32_t, int64_t, double) override { ++n_samples; }
};

void head_log(const uint8_t* p, size_t n)
{
    counting a, b;
    int64_t w1 = 0, w2 = 0;
    std::string why1, why2;
    const size_t good = mt::read_head_log(std::span<const uint8_t>(p, n), w1, a, why1);
    FUZZ_CHECK(good <= n, "a head log read past its end");
    if (good == 0)
        return;
    const size_t again = mt::read_head_log(std::span<const uint8_t>(p, good), w2, b, why2);
    FUZZ_CHECK(again == good && why2.empty() && w1 == w2, "a head log cut at its last whole record reads differently");
    FUZZ_CHECK(a.n_series == b.n_series && a.n_chunks == b.n_chunks && a.n_samples == b.n_samples,
               "a head log cut at its last whole record hands out other records");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = fuzz::never_null(data);
    fuzz::set_current(data, size);
    if (size == 0)
        return 0;
    const uint8_t* p = data + 1;
    const size_t n = size - 1;
    switch (data[0] % 5)
    {
        case 0: raw_chunk(p, n); break;
        case 1: tier_chunk(p, n); break;
        case 2: slot(p, n); break;
        case 3: block_file(p, n); break;
        default: head_log(p, n); break;
    }
    return 0;
}
