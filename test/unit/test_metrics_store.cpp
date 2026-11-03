// The metrics runtime's storage without a socket: the Gorilla codec at its edges, the index and its matchers, the head
// and its limits, blocks cut, reopened, damaged, merged and expired, the head log replayed after a stop and a crash, and
// the tiers checked against a brute force over random data.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <chrono>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <unistd.h>

#include "runtime/metrics/metrics_block.h"
#include "runtime/metrics/metrics_chunk.h"
#include "runtime/metrics/metrics_index.h"
#include "runtime/metrics/metrics_query.h"
#include "runtime/metrics/metrics_store.h"

using namespace socketley::metrics;
namespace fs = std::filesystem;

namespace
{

// 2026-01-01T00:00:00Z, a day boundary.
constexpr int64_t T0 = 1767225600000;

struct tmpdir
{
    std::string path;
    tmpdir()
    {
        char t[] = "/tmp/test_metrics.XXXXXX";
        REQUIRE(::mkdtemp(t) != nullptr);
        path = t;
    }
    ~tmpdir() { fs::remove_all(path); }
    std::string sub(const std::string& n) const { return path + "/" + n; }
};

label_set L(std::initializer_list<std::pair<const char*, const char*>> kv)
{
    label_set ls;
    for (const auto& [k, v] : kv)
        ls.push_back(label{k, v});
    std::sort(ls.begin(), ls.end(), [](const label& a, const label& b) { return a.name < b.name; });
    return ls;
}

uint64_t bits(double v) { return std::bit_cast<uint64_t>(v); }

// Ticks until no background work is in flight and none is started.
void settle(store& s, int64_t now)
{
    s.tick(now);
    while (s.busy())
    {
        std::this_thread::sleep_for(std::chrono::microseconds(200));
        s.tick(now);
    }
}

std::vector<sample> all_samples(store& s, uint32_t id)
{
    std::vector<sample> out;
    s.samples(id, INT64_MIN, INT64_MAX, out);
    return out;
}

std::vector<std::string> files_in(const std::string& dir)
{
    std::vector<std::string> out;
    for (const auto& e : fs::directory_iterator(dir))
        out.push_back(e.path().filename().string());
    std::sort(out.begin(), out.end());
    return out;
}

size_t count_prefix(const std::vector<std::string>& names, const std::string& prefix)
{
    return static_cast<size_t>(std::count_if(names.begin(), names.end(), [&](const std::string& n) {
        return n.starts_with(prefix) && n.ends_with(".blk");
    }));
}

store_config small_config()
{
    store_config c;
    c.keep_raw = 30 * day_ms;
    return c;
}

// ── a brute force of what a tier's steps hold ──

struct ref_point
{
    double min{0}, max{0}, sum{0}, count{0}, last{0}, first{0}, inc{0};
};

// The first multiple of `step` at or after `t`, which ends the left-open step (e - step, e] holding `t`.
int64_t ceil_to(int64_t t, int64_t step) { return t % step == 0 ? t : (t / step + 1) * step; }

std::map<int64_t, ref_point> brute(const std::vector<sample>& xs, int64_t step)
{
    std::map<int64_t, ref_point> m;
    const sample* prev = nullptr;
    for (const sample& x : xs)
    {
        if (std::isnan(x.v))
            continue;
        const int64_t e = ceil_to(x.t, step);
        auto [it, made] = m.try_emplace(e);
        ref_point& p = it->second;
        if (made)
            p = ref_point{x.v, x.v, x.v, 1, x.v, x.v, 0};
        else
        {
            p.min = std::min(p.min, x.v);
            p.max = std::max(p.max, x.v);
            p.sum += x.v;
            p.count += 1;
            p.last = x.v;
        }
        if (prev && ceil_to(prev->t, step) == e)
            p.inc += counter_rise(prev->v, x.v);
        prev = &x;
    }
    for (auto& [e, p] : m)
        if (const auto it = m.find(e - step); it != m.end())
            p.inc += counter_rise(it->second.last, p.first);
    return m;
}

bool near(double a, double b)
{
    if (a == b)
        return true;
    return std::fabs(a - b) <= 1e-9 * std::max(std::fabs(a), std::fabs(b));
}

void check_tier(store& s, uint32_t id, const std::vector<sample>& xs, int64_t step, int64_t mint, int64_t maxt)
{
    const auto ref = brute(xs, step);
    std::vector<agg_point> got;
    s.aggregates(id, step, mint, maxt, got);
    size_t want = 0;
    for (const auto& [e, p] : ref)
        if (e > mint && e <= maxt)
            ++want;
    REQUIRE(got.size() == want);
    for (const agg_point& a : got)
    {
        const auto it = ref.find(a.t);
        REQUIRE(it != ref.end());
        const ref_point& r = it->second;
        INFO("step " << step << " t " << a.t);
        CHECK(near(a.min, r.min));
        CHECK(near(a.max, r.max));
        CHECK(near(a.sum, r.sum));
        CHECK(a.count == r.count);
        CHECK(near(a.last, r.last));
        CHECK(near(a.inc, r.inc));
    }
}

// A field of /proc/self/status in kB: VmRSS, RssAnon or RssFile.
long status_kb(const char* field)
{
    std::ifstream f("/proc/self/status");
    std::string line;
    const std::string key = std::string(field) + ":";
    while (std::getline(f, line))
        if (line.starts_with(key))
            return std::stol(line.substr(key.size()));
    return 0;
}

#ifdef NDEBUG
constexpr int64_t day_rounds = 8640, month_days = 30;
#else
// The sanitizer's build walks the same paths, shorter.
constexpr int64_t day_rounds = 1440, month_days = 5;
#endif
using clk = std::chrono::steady_clock;

}   // namespace

// ── the codec ─────────────────────────────────────────────────────────────

TEST_CASE("chunk: the edge values round-trip bit for bit")
{
    const double nan_payload = std::bit_cast<double>(0x7ff8dead0000beefull);
    const std::vector<double> vs = {0.0,        -0.0,         1.0,       std::nan(""), nan_payload, stale_nan(),
                                    INFINITY,   -INFINITY,    DBL_MAX,   -DBL_MAX,     DBL_MIN,     4.9e-324,
                                    -4.9e-324,  1e300,        42.0,      42.0,         42.0,        -1.5};
    std::vector<sample> in;
    int64_t t = 1000;
    for (double v : vs)
        in.push_back(sample{t += 10'000, v});
    std::vector<uint8_t> enc;
    encode_chunk(in, enc);
    std::vector<sample> out;
    REQUIRE(decode_chunk(enc, out));
    REQUIRE(out.size() == in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        CHECK(out[i].t == in[i].t);
        CHECK(bits(out[i].v) == bits(in[i].v));
    }
    CHECK(is_stale(out[5].v));
    CHECK_FALSE(is_stale(out[3].v));
    CHECK(std::signbit(out[1].v));
}

TEST_CASE("chunk: equal, falling, huge and negative timestamps round-trip")
{
    const std::vector<int64_t> ts = {0,          0,          5,         -7,         INT64_MAX, INT64_MIN, 1,
                                     1LL << 62,  -(1LL << 62), 123456789, 123456789, 123456790, -1};
    std::vector<sample> in;
    for (size_t i = 0; i < ts.size(); ++i)
        in.push_back(sample{ts[i], double(i)});
    std::vector<uint8_t> enc;
    encode_chunk(in, enc);
    std::vector<sample> out;
    REQUIRE(decode_chunk(enc, out));
    REQUIRE(out.size() == in.size());
    for (size_t i = 0; i < in.size(); ++i)
        CHECK(out[i].t == in[i].t);
}

TEST_CASE("chunk: a counter reset and every delta-of-delta bucket")
{
    std::vector<sample> in;
    int64_t t = T0, d = 0;
    double v = 0;
    const int64_t deltas[] = {10'000, 10'000, 10'001, 10'000 + 8000, 10'000 - 60'000, 600'000, 10'000'000, 1, 1, 0};
    for (int64_t dd : deltas)
    {
        d = dd;
        in.push_back(sample{t += d, v += 1000});
    }
    in.push_back(sample{t += 10'000, 3});   // the reset
    in.push_back(sample{t += 10'000, 5});
    std::vector<uint8_t> enc;
    encode_chunk(in, enc);
    std::vector<sample> out;
    REQUIRE(decode_chunk(enc, out));
    REQUIRE(out.size() == in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        CHECK(out[i].t == in[i].t);
        CHECK(out[i].v == in[i].v);
    }
}

TEST_CASE("chunk: a fixed slot closes before it overflows, and every prefix of a chunk decodes or fails cleanly")
{
    uint8_t buf[200] = {};
    chunk_appender a;
    std::mt19937_64 rng(7);
    std::vector<sample> in;
    int64_t t = T0;
    for (;;)
    {
        const sample x{t += int64_t(rng() % 100000), std::bit_cast<double>(rng())};
        if (!a.append(buf, sizeof buf, x.t, x.v))
            break;
        in.push_back(x);
    }
    CHECK(in.size() >= 8);
    CHECK(a.bytes() <= sizeof buf);
    std::vector<sample> out;
    REQUIRE(decode_chunk(std::span<const uint8_t>(buf, a.bytes()), out));
    REQUIRE(out.size() == in.size());
    for (size_t i = 0; i < in.size(); ++i)
        CHECK((out[i].t == in[i].t && bits(out[i].v) == bits(in[i].v)));
    // Cut anywhere short of the end, the decoder stops with a failure and never reads past the bytes it was given.
    size_t failures = 0;
    for (size_t n = 0; n < a.bytes(); ++n)
    {
        std::vector<uint8_t> cut(buf, buf + n);
        out.clear();
        failures += !decode_chunk(cut, out);
        CHECK(out.size() <= in.size());
    }
    CHECK(failures >= a.bytes() - 2);
}

TEST_CASE("chunk: tier points round-trip")
{
    std::mt19937_64 rng(11);
    std::vector<tier_point> in;
    for (int i = 0; i < 500; ++i)
        in.push_back(tier_point{T0 + i * 300'000, double(rng() % 100), double(rng() % 1000), double(rng()),
                                30, std::bit_cast<double>(rng()), -0.0, double(i)});
    std::vector<uint8_t> enc;
    encode_tier_chunk(in, enc);
    std::vector<tier_point> out;
    REQUIRE(decode_tier_chunk(enc, out));
    REQUIRE(out.size() == in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        CHECK(out[i].t == in[i].t);
        CHECK(bits(out[i].last) == bits(in[i].last));
        CHECK(bits(out[i].first) == bits(in[i].first));
        CHECK(out[i].sum == in[i].sum);
        CHECK(out[i].rise == in[i].rise);
    }
    enc.resize(enc.size() / 2);
    out.clear();
    CHECK_FALSE(decode_tier_chunk(enc, out));
}

TEST_CASE("chunk: bytes per sample for counters, gauges and constants")
{
    std::mt19937_64 rng(3);
    const auto measure = [&](const char* what, auto gen, bool jitter) {
        size_t bytes = 0, n = 0;
        double v = 0;
        int64_t t = T0;
        for (int c = 0; c < 500; ++c)
        {
            std::vector<sample> in;
            for (int i = 0; i < chunk_samples; ++i)
            {
                t += 10'000 + (jitter ? int64_t(rng() % 21) - 10 : 0);
                v = gen(v);
                in.push_back(sample{t, v});
            }
            std::vector<uint8_t> enc;
            encode_chunk(in, enc);
            bytes += enc.size();
            n += in.size();
        }
        std::printf("  bytes/sample  %-34s %s %.2f\n", what, jitter ? "jitter +-10ms" : "exact 10s    ",
                    double(bytes) / double(n));
    };
    std::printf("[perf] chunk payload, %d samples per chunk:\n", chunk_samples);
    for (bool j : {false, true})
    {
        measure("counter, +0..1000 per 10s", [&](double v) { return v + double(rng() % 1000); }, j);
        measure("counter, bytes at ~1 MB/s", [&](double v) { return v + double(1'000'000 * 10 + rng() % 100000); }, j);
        measure("gauge, small int random walk", [&](double v) { return std::max(0.0, v + double(int(rng() % 5) - 2)); }, j);
        measure("gauge, float ratio", [&](double) { return double(rng() % 10000) / 10000.0; }, j);
        measure("constant", [&](double) { return 1.0; }, j);
    }
}

// ── the index ─────────────────────────────────────────────────────────────

TEST_CASE("index: matchers follow Prometheus, an empty value matching a missing label")
{
    series_index ix;
    const uint32_t a = ix.add(L({{"__name__", "up"}, {"job", "api"}, {"env", "prod"}}));
    const uint32_t b = ix.add(L({{"__name__", "up"}, {"job", "web"}, {"env", "dev"}}));
    const uint32_t c = ix.add(L({{"__name__", "up"}, {"job", "web2"}}));
    const uint32_t d = ix.add(L({{"__name__", "down"}, {"job", "foo"}, {"env", "prod"}}));
    CHECK(ix.find(L({{"__name__", "up"}, {"job", "web"}, {"env", "dev"}})) == b);
    CHECK(ix.find(L({{"__name__", "up"}, {"job", "web"}})) == no_series);

    const auto q = [&](std::vector<matcher> ms) {
        std::vector<uint32_t> out;
        ix.match(ms, out);
        return out;
    };
    using V = std::vector<uint32_t>;
    CHECK(q({{"__name__", match_op::eq, "up"}}) == V{a, b, c});
    CHECK(q({{"__name__", match_op::eq, "up"}, {"env", match_op::eq, ""}}) == V{c});
    CHECK(q({{"__name__", match_op::eq, "up"}, {"env", match_op::ne, ""}}) == V{a, b});
    CHECK(q({{"env", match_op::ne, "prod"}}) == V{b, c});
    CHECK(q({{"nolabel", match_op::eq, ""}}) == V{a, b, c, d});
    CHECK(q({{"nolabel", match_op::eq, "x"}}).empty());
    CHECK(q({{"nolabel", match_op::ne, "x"}}) == V{a, b, c, d});
    CHECK(q({{"job", match_op::eq, "nothere"}}).empty());

    // Fully anchored, the literal and alternation fast paths, .* and .+, and the rest through metrics_regex.
    CHECK(q({{"job", match_op::re, "web"}}) == V{b});
    CHECK(q({{"job", match_op::re, "we"}}).empty());
    CHECK(q({{"job", match_op::re, "web.*"}}) == V{b, c});
    CHECK(q({{"job", match_op::re, "api|foo"}}) == V{a, d});
    CHECK(q({{"job", match_op::re, "(api|foo)"}}) == V{a, d});
    CHECK(q({{"job", match_op::nre, "api|foo"}}) == V{b, c});
    CHECK(q({{"env", match_op::re, ".*"}}) == V{a, b, c, d});
    CHECK(q({{"env", match_op::re, ".+"}}) == V{a, b, d});
    CHECK(q({{"env", match_op::nre, ".+"}}) == V{c});
    CHECK(q({{"env", match_op::nre, ".*"}}).empty());
    CHECK(q({{"env", match_op::re, "prod|"}}) == V{a, c, d});
    CHECK(q({{"env", match_op::nre, "prod|"}}) == V{b});
    CHECK(q({{"job", match_op::re, "web\\d"}}) == V{c});
    CHECK(q({{"job", match_op::re, "(?i)WEB"}}) == V{b});
    CHECK(q({{"job", match_op::re, "w[a-e]b[0-9]?"}}) == V{b, c});
    CHECK(q({{"job", match_op::re, "a.*?i"}}) == V{a});
    CHECK(q({{"env", match_op::re, "d.*|"}}) == V{b, c});
    CHECK(q({{"__name__", match_op::eq, "up"}, {"job", match_op::re, "web.*"}, {"env", match_op::ne, "dev"}}) == V{c});

    // RE2 syntax that POSIX ERE lacks, matched by the query engine's own regex.
    CHECK(q({{"job", match_op::re, "\\bweb\\b"}}) == V{b});
    CHECK(q({{"job", match_op::re, "(?P<x>web)\\d"}}) == V{c});
    CHECK(q({{"job", match_op::re, "(?:a|w)\\w+"}}) == V{a, b, c});
    CHECK(q({{"job", match_op::re, "[[:alpha:]]+"}}) == V{a, b, d});
    // An invalid regex matches nothing and its negation everything.
    CHECK(q({{"job", match_op::re, "("}}).empty());
    CHECK(q({{"job", match_op::nre, "("}}) == V{a, b, c, d});

    std::vector<std::string> names, values;
    ix.label_names(names);
    CHECK(names == std::vector<std::string>{"__name__", "env", "job"});
    ix.label_values("job", values);
    CHECK(values == std::vector<std::string>{"api", "foo", "web", "web2"});
    CHECK(ix.labels(b) == L({{"__name__", "up"}, {"job", "web"}, {"env", "dev"}}));
}

TEST_CASE("index: postings survive many series and table growth")
{
    series_index ix;
    for (int i = 0; i < 5000; ++i)
        ix.add(L({{"__name__", "m"}, {"i", std::to_string(i).c_str()}, {"mod", std::to_string(i % 7).c_str()}}));
    std::vector<uint32_t> out;
    ix.match(std::vector<matcher>{{"mod", match_op::eq, "3"}}, out);
    CHECK(out.size() == 714);
    for (uint32_t id : out)
        CHECK(id % 7 == 3);
    ix.match(std::vector<matcher>{{"i", match_op::re, "1.*"}, {"mod", match_op::ne, "0"}}, out);
    size_t want = 0;
    for (int i = 0; i < 5000; ++i)
        want += std::to_string(i)[0] == '1' && i % 7 != 0;
    CHECK(out.size() == want);
    CHECK(ix.find(L({{"__name__", "m"}, {"i", "4999"}, {"mod", "1"}})) == 4999);
}

TEST_CASE("index: the label sets a query reads are counted in bytes() once, as each is made")
{
    // bytes() is asked on every tick, and walked every cached set until it counted them as they were made.
    series_index ix;
    const int n = 1000;
    for (int i = 0; i < n; ++i)
        ix.add(L({{"__name__", "m"}, {"path", ("/a/path/longer/than/sixteen/" + std::to_string(i)).c_str()}}));
    const size_t before = ix.bytes();
    for (int i = 0; i < n; ++i)
        REQUIRE(ix.labels(static_cast<uint32_t>(i)).size() == 2);
    const size_t after = ix.bytes();
    CHECK(after - before >= size_t(n) * (sizeof(label_set) + 2 * sizeof(label) + 16));
    for (int i = 0; i < n; ++i)
        ix.labels(static_cast<uint32_t>(i));
    CHECK(ix.bytes() == after);
}

// ── the head ──────────────────────────────────────────────────────────────

TEST_CASE("store: max_series refuses new series and counts them, and labels are normalized")
{
    tmpdir d;
    store s;
    store_config c = small_config();
    c.max_series = 3;
    std::string why;
    REQUIRE(s.open(d.path, c, why));
    const uint32_t a = s.get_or_create(L({{"__name__", "x"}, {"i", "1"}}));
    s.get_or_create(L({{"__name__", "x"}, {"i", "2"}}));
    s.get_or_create(L({{"__name__", "x"}, {"i", "3"}}));
    CHECK(s.get_or_create(L({{"__name__", "x"}, {"i", "4"}})) == no_series);
    CHECK(s.get_or_create(L({{"__name__", "x"}, {"i", "5"}})) == no_series);
    CHECK(s.stats().refused_series == 2);
    // A known series is never refused, unsorted and with an empty label it is the same series.
    CHECK(s.get_or_create(label_set{{"i", "1"}, {"__name__", "x"}, {"empty", ""}}) == a);
    CHECK(s.get_or_create(label_set{{"i", "1"}, {"i", "2"}}) == no_series);
    CHECK(s.stats().series == 3);
}

TEST_CASE("store: an out-of-order or repeated sample is refused and counted")
{
    tmpdir d;
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    const uint32_t id = s.get_or_create(L({{"__name__", "x"}}));
    CHECK(s.append(id, T0 + 1000, 1));
    CHECK_FALSE(s.append(id, T0 + 1000, 2));
    CHECK_FALSE(s.append(id, T0 + 999, 3));
    CHECK(s.append(id, T0 + 1001, 4));
    CHECK_FALSE(s.append(99, T0 + 2000, 5));
    CHECK_FALSE(s.append(id, max_abs_time + 1, 5));
    const auto st = s.stats();
    CHECK(st.samples_appended == 2);
    CHECK(st.refused_out_of_order == 2);
    CHECK(st.refused_too_old == 1);
    const auto xs = all_samples(s, id);
    REQUIRE(xs.size() == 2);
    CHECK(xs[1].v == 4);
    CHECK(s.mark_stale(id, T0 + 2000));
    CHECK(is_stale(all_samples(s, id).back().v));
}

TEST_CASE("store: a sample stamped years ahead expires nothing and refuses nobody's present")
{
    tmpdir d;
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    const uint32_t id = s.get_or_create(L({{"__name__", "now"}}));
    for (int64_t k = 1; k <= 4 * 360; ++k)
        REQUIRE(s.append(id, T0 + k * 10'000, 1));
    settle(s, T0 + 4 * hour_ms);
    const uint64_t blocks = s.stats().blocks;
    REQUIRE(blocks == 2);
    const uint32_t skewed = s.get_or_create(L({{"__name__", "skewed"}}));
    REQUIRE(s.append(skewed, T0 + 10 * 365 * day_ms, 1));
    settle(s, T0 + 4 * hour_ms + 10'000);
    CHECK(s.stats().blocks == blocks);
    CHECK(s.append(id, T0 + 4 * hour_ms + 10'000, 2));
    CHECK(s.tier_for(T0, 5 * minute_ms) == 5 * minute_ms);
}

// ── blocks ────────────────────────────────────────────────────────────────

TEST_CASE("store: a window is cut into a block, read across head and block, and read back after a restart")
{
    tmpdir d;
    std::vector<sample> want[3];
    {
        store s;
        std::string why;
        REQUIRE(s.open(d.path, small_config(), why));
        uint32_t ids[3];
        for (int i = 0; i < 3; ++i)
            ids[i] = s.get_or_create(L({{"__name__", "m"}, {"i", std::to_string(i).c_str()}}));
        s.set_meta("m", metric_type::counter, "a test metric");
        // Four hours, the first window (T0, T0 + 2h] cut once samples reach an hour past its end.
        for (int64_t k = 0; k < 4 * 360; ++k)
            for (int i = 0; i < 3; ++i)
            {
                const sample x{T0 + k * 10'000 + i + 1, double(k * (i + 1))};
                REQUIRE(s.append(ids[i], x.t, x.v));
                want[i].push_back(x);
            }
        settle(s, T0 + 4 * hour_ms);
        const auto st = s.stats();
        CHECK(st.blocks == 2);
        CHECK(st.bytes_on_disk > 0);
        // A series that never appended before is refused a time in a window already cut.
        const uint32_t late = s.get_or_create(L({{"__name__", "late"}}));
        CHECK_FALSE(s.append(late, T0 + hour_ms, 1));
        CHECK(s.stats().refused_too_old == 1);
        CHECK(s.append(late, T0 + 3 * hour_ms, 1));
        for (int i = 0; i < 3; ++i)
        {
            const auto got = all_samples(s, ids[i]);
            REQUIRE(got.size() == want[i].size());
            for (size_t k = 0; k < got.size(); ++k)
                REQUIRE((got[k].t == want[i][k].t && got[k].v == want[i][k].v));
            std::vector<sample> part;
            const int64_t lo = T0 + block_ms - 30'000, hi = T0 + block_ms + 30'000;
            s.samples(ids[i], lo, hi, part);
            const auto want_n = std::count_if(want[i].begin(), want[i].end(), [&](const sample& x) { return x.t >= lo && x.t <= hi; });
            CHECK(part.size() == size_t(want_n));
            CHECK(part.size() >= 6);
        }
        const auto names = files_in(d.sub("blocks"));
        CHECK(count_prefix(names, "raw_") == 1);
        CHECK(count_prefix(names, "s300000_") == 1);
        s.stop();
    }
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    CHECK(s.type_of("m") == metric_type::counter);
    CHECK(s.help_of("m") == "a test metric");
    for (int i = 0; i < 3; ++i)
    {
        const uint32_t id = s.find(L({{"__name__", "m"}, {"i", std::to_string(i).c_str()}}));
        REQUIRE(id != no_series);
        const auto got = all_samples(s, id);
        REQUIRE(got.size() == want[i].size());
        for (size_t k = 0; k < got.size(); ++k)
            REQUIRE((got[k].t == want[i][k].t && got[k].v == want[i][k].v));
    }
    // The block's own index lists its symbols' postings.
    auto b = block::open(d.sub("blocks/" + block_name(0, T0, T0 + block_ms)), why);
    REQUIRE(b);
    CHECK(b->count() == 3);
    std::vector<std::pair<label, uint32_t>> ps;
    b->postings(ps);
    REQUIRE(ps.size() == 4);
    CHECK(ps[0].first == label{"__name__", "m"});
    CHECK(ps[0].second == 3);
}

TEST_CASE("store: a clean stop keeps the open head chunks, so a restart loses nothing")
{
    tmpdir d;
    std::vector<sample> want;
    {
        store s;
        std::string why;
        REQUIRE(s.open(d.path, small_config(), why));
        const uint32_t id = s.get_or_create(L({{"__name__", "g"}}));
        for (int k = 0; k < 250; ++k)
        {
            want.push_back(sample{T0 + k * 15'000, std::sin(k)});
            REQUIRE(s.append(id, want.back().t, want.back().v));
        }
        s.mark_stale(id, T0 + 250 * 15'000);
        want.push_back(sample{T0 + 250 * 15'000, stale_nan()});
        s.tick(T0 + 251 * 15'000);
        s.stop();
    }
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    const uint32_t id = s.find(L({{"__name__", "g"}}));
    REQUIRE(id != no_series);
    const auto got = all_samples(s, id);
    REQUIRE(got.size() == want.size());
    for (size_t k = 0; k < got.size(); ++k)
        CHECK((got[k].t == want[k].t && bits(got[k].v) == bits(want[k].v)));
    // Appending goes on behind what was restored.
    CHECK_FALSE(s.append(id, want.back().t, 1));
    CHECK(s.append(id, want.back().t + 1, 1));
}

TEST_CASE("store: a crash loses only the open chunks, or nothing with durable on")
{
    for (bool durable : {false, true})
    {
        CAPTURE(durable);
        tmpdir d;
        store_config c = small_config();
        c.durable = durable;
        std::vector<sample> want;
        size_t closed = 0;
        store s;
        std::string why;
        REQUIRE(s.open(d.sub("live"), c, why));
        const uint32_t id = s.get_or_create(L({{"__name__", "c"}}));
        for (int k = 0; k < 300; ++k)
        {
            want.push_back(sample{T0 + k * 10'000, double(k * 7)});
            REQUIRE(s.append(id, want.back().t, want.back().v));
        }
        s.tick(T0 + 300 * 10'000);
        closed = s.stats().head_chunks;
        CHECK(closed >= 1);
        // The directory as a killed process leaves it: the files, whatever was written to them.
        fs::copy(d.sub("live"), d.sub("crashed"), fs::copy_options::recursive);
        store r;
        REQUIRE(r.open(d.sub("crashed"), c, why));
        const uint32_t rid = r.find(L({{"__name__", "c"}}));
        REQUIRE(rid != no_series);
        const auto got = all_samples(r, rid);
        if (durable)
            CHECK(got.size() == want.size());
        else
        {
            CHECK(got.size() < want.size());
            CHECK(got.size() >= closed * 40);
        }
        for (size_t k = 0; k < got.size(); ++k)
            CHECK((got[k].t == want[k].t && got[k].v == want[k].v));
    }
}

TEST_CASE("store: a torn head log tail is cut and the records before it kept")
{
    tmpdir d;
    store_config c = small_config();
    c.durable = true;
    store s;
    std::string why;
    REQUIRE(s.open(d.sub("live"), c, why));
    const uint32_t id = s.get_or_create(L({{"__name__", "c"}}));
    for (int k = 0; k < 100; ++k)
    {
        REQUIRE(s.append(id, T0 + (k + 1) * 10'000, k));
        if (k % 10 == 9)
            s.tick(T0 + k * 10'000);
    }
    CHECK(s.stats().head_chunks == 0);
    // A crash's image, its last record of ten samples torn in half and followed by garbage.
    fs::copy(d.sub("live"), d.sub("crashed"), fs::copy_options::recursive);
    const std::string log = d.sub("crashed/head/" + head_log_name(T0));
    const auto size = fs::file_size(log);
    fs::resize_file(log, size - 60);
    {
        std::ofstream f(log, std::ios::app | std::ios::binary);
        f << "garbage";
    }
    store r;
    REQUIRE(r.open(d.sub("crashed"), c, why));
    const uint32_t rid = r.find(L({{"__name__", "c"}}));
    REQUIRE(rid != no_series);
    const auto got = all_samples(r, rid);
    CHECK(got.size() == 90);
    for (size_t k = 0; k < got.size(); ++k)
        CHECK(got[k].v == double(k));
    CHECK(fs::file_size(log) < size - 60);
    // The cut log takes appends behind its last whole record and reads back whole once more.
    REQUIRE(r.append(rid, T0 + 200 * 10'000, 200));
    r.stop();
    store again;
    REQUIRE(again.open(d.sub("crashed"), c, why));
    CHECK(all_samples(again, again.find(L({{"__name__", "c"}}))).size() == 91);
}

TEST_CASE("store: a damaged block is refused with its reason and the store opens without it")
{
    tmpdir d;
    {
        store s;
        std::string why;
        REQUIRE(s.open(d.path, small_config(), why));
        const uint32_t id = s.get_or_create(L({{"__name__", "m"}}));
        for (int64_t k = 1; k <= 6 * 360; ++k)
            REQUIRE(s.append(id, T0 + k * 10'000, double(k)));
        settle(s, T0 + 6 * hour_ms);
        CHECK(s.stats().blocks == 4);
        s.stop();
    }
    const std::string victim = d.sub("blocks/" + block_name(0, T0, T0 + block_ms));
    {
        std::fstream f(victim, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(40);
        char c = 0;
        f.read(&c, 1);
        f.seekp(40);
        c = static_cast<char>(c ^ 0x10);
        f.write(&c, 1);
    }
    std::string why;
    CHECK_FALSE(block::open(victim, why));
    CHECK(why.find("crc32c") != std::string::npos);
    store s;
    REQUIRE(s.open(d.path, small_config(), why));
    const auto st = s.stats();
    CHECK(st.blocks_refused == 1);
    CHECK(st.blocks == 3);
    CHECK(fs::exists(victim + ".damaged"));
    const uint32_t id = s.find(L({{"__name__", "m"}}));
    REQUIRE(id != no_series);
    const auto got = all_samples(s, id);
    CHECK(got.size() == 6 * 360 - 720);
    CHECK(got.front().t == T0 + block_ms + 10'000);
}

// ── compaction, tiers, retention ──────────────────────────────────────────

namespace
{

// Random counters with resets and gaps, and gauges with NaN and stale markers unless `nan` is off, over `hours`, ticked
// as it goes: unaligned a few hundred ms off the 10 s grid, aligned on it as the runtime's tick stamps, so a sample lies
// on every edge of a step and of a window.
struct workload
{
    std::vector<uint32_t> ids;
    std::vector<std::vector<sample>> xs;
    int64_t end{0};

    workload(store& s, int series, int64_t hours, uint64_t seed, int64_t tick_every = hour_ms, bool aligned = false,
             bool nan = true)
    {
        std::mt19937_64 rng(seed);
        xs.resize(series);
        std::vector<double> v(series, 0);
        for (int i = 0; i < series; ++i)
            ids.push_back(s.get_or_create(L({{"__name__", i % 2 ? "g" : "c"}, {"i", std::to_string(i).c_str()}})));
        int64_t next_tick = T0 + tick_every;
        for (int64_t k = 0; k < hours * 360; ++k)
        {
            const int64_t base = T0 + k * 10'000;
            for (int i = 0; i < series; ++i)
            {
                const uint64_t r = rng();
                if (r % 100 == 0 || (k / 180 + i) % 37 == 0)
                    continue;   // a missed sample, and a half-hour gap now and then
                double x;
                if (i % 2 == 0)
                {
                    v[i] += double(rng() % 500);
                    if (rng() % 400 == 0)
                        v[i] = double(rng() % 10);
                    x = v[i];
                }
                else
                {
                    x = double(int64_t(rng() % 2001) - 1000) / 8.0;
                    if (rng() % 300 == 0 && nan)
                        x = std::nan("");
                    if (rng() % 300 == 0 && nan)
                        x = stale_nan();
                }
                const int64_t jitter = int64_t(rng() % 401) - 200 + 300;
                const sample smp{aligned ? base + 10'000 : base + jitter, x};
                REQUIRE(s.append(ids[i], smp.t, smp.v));
                xs[i].push_back(smp);
            }
            if (base >= next_tick)
            {
                s.tick(base);
                next_tick += tick_every;
            }
        }
        end = T0 + hours * hour_ms;
    }
};

}   // namespace

TEST_CASE("store: a day of 2h blocks is merged into a day block, and the 1h tier built from the 5m day")
{
    tmpdir d;
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    workload w(s, 4, 30, 5);
    settle(s, w.end);
    const auto names = files_in(d.sub("blocks"));
    CHECK(fs::exists(d.sub("blocks/" + block_name(0, T0, T0 + day_ms))));
    CHECK(fs::exists(d.sub("blocks/" + block_name(5 * minute_ms, T0, T0 + day_ms))));
    CHECK(fs::exists(d.sub("blocks/" + block_name(hour_ms, T0, T0 + day_ms))));
    // The merged day's children are gone; the second day's windows stay 2h blocks until it ends.
    CHECK_FALSE(fs::exists(d.sub("blocks/" + block_name(0, T0, T0 + block_ms))));
    CHECK(fs::exists(d.sub("blocks/" + block_name(0, T0 + day_ms, T0 + day_ms + block_ms))));
    CHECK(count_prefix(names, "raw_") == 1 + 2);
    CHECK(count_prefix(names, "s3600000_") == 1);
    for (size_t i = 0; i < w.ids.size(); ++i)
    {
        const auto got = all_samples(s, w.ids[i]);
        REQUIRE(got.size() == w.xs[i].size());
        for (size_t k = 0; k < got.size(); ++k)
            REQUIRE((got[k].t == w.xs[i][k].t && bits(got[k].v) == bits(w.xs[i][k].v)));
    }
    s.stop();
    store r;
    REQUIRE(r.open(d.path, small_config(), why));
    for (size_t i = 0; i < w.ids.size(); ++i)
        CHECK(all_samples(r, r.find(s.labels(w.ids[i]))).size() == w.xs[i].size());
}

TEST_CASE("store: what a crash between writing a block and deleting what it replaces leaves is cleared at open")
{
    tmpdir d;
    const std::string child = d.sub("blocks/" + block_name(0, T0, T0 + block_ms));
    const std::string log = d.sub("head/" + head_log_name(T0 + day_ms));
    std::vector<std::vector<sample>> want;
    std::vector<label_set> names;
    uint64_t blocks = 0;
    {
        store s;
        std::string why;
        REQUIRE(s.open(d.path, small_config(), why));
        uint32_t ids[3];
        for (int i = 0; i < 3; ++i)
            ids[i] = s.get_or_create(L({{"__name__", "m"}, {"i", std::to_string(i).c_str()}}));
        int64_t k = 0;
        const auto until = [&](int64_t hours) {
            for (; k < hours * 360; ++k)
                for (uint32_t id : ids)
                    REQUIRE(s.append(id, T0 + k * 10'000, double(k)));
        };
        // A 2h child, kept from before the day it belongs to was merged.
        until(4);
        settle(s, T0 + 4 * hour_ms);
        REQUIRE(fs::exists(child));
        fs::copy_file(child, d.sub("child.copy"));
        until(25);
        settle(s, T0 + 25 * hour_ms);
        REQUIRE_FALSE(fs::exists(child));
        // The head log of a window, kept from before that window was cut.
        REQUIRE(fs::exists(log));
        fs::copy_file(log, d.sub("log.copy"));
        until(27);
        settle(s, T0 + 27 * hour_ms);
        REQUIRE_FALSE(fs::exists(log));
        blocks = s.stats().blocks;
        for (uint32_t id : ids)
        {
            want.push_back(all_samples(s, id));
            names.push_back(s.labels(id));
        }
        s.stop();
    }
    fs::copy_file(d.sub("child.copy"), child);
    fs::copy_file(d.sub("log.copy"), log);
    store r;
    std::string why;
    REQUIRE(r.open(d.path, small_config(), why));
    CHECK_FALSE(fs::exists(child));
    CHECK_FALSE(fs::exists(log));
    CHECK(r.stats().blocks == blocks);
    CHECK(r.stats().refused_too_old == 0);
    for (size_t i = 0; i < names.size(); ++i)
    {
        const auto got = all_samples(r, r.find(names[i]));
        REQUIRE(got.size() == want[i].size());
        for (size_t k = 0; k < got.size(); ++k)
            REQUIRE(got[k].t == want[i][k].t);
    }
}

TEST_CASE("store: the tiers' min, max, sum, count, last and inc match a brute force across head, blocks and tiers")
{
    for (const bool aligned : {false, true})
    {
    CAPTURE(aligned);
    tmpdir d;
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    workload w(s, 6, 53, 21, hour_ms, aligned);
    settle(s, w.end);
    // Two whole days merged, the 1h tier built for both, the third day in 2h blocks and the head.
    bool second_day = false;
    for (const std::string& n : files_in(d.sub("blocks")))
    {
        int64_t step = 0, lo = 0, hi = 0;
        if (parse_block_name(n, step, lo, hi) && step == hour_ms && lo <= T0 + day_ms && hi >= T0 + 2 * day_ms)
            second_day = true;
    }
    CHECK(second_day);
    CHECK(s.stats().head_chunks > 0);
    for (size_t i = 0; i < w.ids.size(); ++i)
    {
        CAPTURE(i);
        check_tier(s, w.ids[i], w.xs[i], 5 * minute_ms, T0 - day_ms, w.end + hour_ms);
        check_tier(s, w.ids[i], w.xs[i], hour_ms, T0 - day_ms, w.end + hour_ms);
        // A range that starts and ends inside blocks and inside the head.
        check_tier(s, w.ids[i], w.xs[i], 5 * minute_ms, T0 + 47 * hour_ms + 5 * minute_ms, w.end - 15 * minute_ms);
        check_tier(s, w.ids[i], w.xs[i], hour_ms, T0 + 13 * hour_ms, T0 + 50 * hour_ms);
    }
    std::vector<agg_point> none;
    s.aggregates(w.ids[0], 7 * minute_ms, T0, w.end, none);
    CHECK(none.empty());
    if (aligned)
    {
        // The sample on an edge ends the step it closes, so an hour's point holds its 360 samples.
        std::vector<agg_point> one;
        s.aggregates(w.ids[0], hour_ms, T0 + 9 * hour_ms, T0 + 10 * hour_ms, one);
        REQUIRE(one.size() == 1);
        const auto& xs = w.xs[0];
        const auto in = std::count_if(xs.begin(), xs.end(), [](const sample& x) {
            return x.t > T0 + 9 * hour_ms && x.t <= T0 + 10 * hour_ms;
        });
        CHECK(one[0].count == double(in));
        const auto on_edge = std::find_if(xs.begin(), xs.end(), [](const sample& x) { return x.t == T0 + 10 * hour_ms; });
        if (on_edge != xs.end())
            CHECK(one[0].last == on_edge->v);
    }
    }
}

namespace
{

query_result range_query(query_engine& e, std::string_view q, int64_t start, int64_t end, int64_t step)
{
    query_result r;
    query_error err;
    REQUIRE_MESSAGE(e.eval_range(q, start, end, step, r, err), std::string(q) << ": " << err.message);
    return r;
}

void check_same(const query_result& a, const query_result& b, std::string_view q)
{
    REQUIRE_MESSAGE(a.series.size() == b.series.size(), q);
    for (size_t i = 0; i < a.series.size(); ++i)
    {
        CHECK(a.series[i].labels == b.series[i].labels);
        REQUIRE_MESSAGE(a.series[i].points.size() == b.series[i].points.size(), q << " series " << i);
        for (size_t k = 0; k < a.series[i].points.size(); ++k)
        {
            CHECK(a.series[i].points[k].t == b.series[i].points[k].t);
            CHECK_MESSAGE(near(a.series[i].points[k].v, b.series[i].points[k].v),
                          q << " at " << a.series[i].points[k].t << ": " << a.series[i].points[k].v << " against "
                            << b.series[i].points[k].v);
        }
    }
}

}   // namespace

TEST_CASE("store and query: the tiers answer as raw does, with a sample on every edge or on none")
{
    for (const bool aligned : {false, true})
    {
        CAPTURE(aligned);
        tmpdir d;
        store s;
        std::string why;
        REQUIRE(s.open(d.path, small_config(), why));
        workload w(s, 4, 75, 7, hour_ms, aligned, false);
        settle(s, w.end);
        query_engine with(s), without(s);
        without.limits().use_tiers = false;
        // Hours over merged days, 2h blocks and the head, and five minutes over the last day and a half.
        const struct { int64_t from, step; const char* range; } spans[] = {
            {T0 + hour_ms, hour_ms, "1h"}, {w.end - 36 * hour_ms, 5 * minute_ms, "5m"}};
        for (const auto& sp : spans)
        {
            for (const char* f : {"avg_over_time", "min_over_time", "max_over_time", "sum_over_time",
                                  "count_over_time", "last_over_time"})
            {
                const std::string q = std::string(f) + "({__name__=~\"c|g\"}[" + sp.range + "])";
                const auto a = range_query(with, q, sp.from, w.end, sp.step);
                CHECK_MESSAGE(with.last_stats().tier_selectors == 1, q);
                CHECK(with.last_stats().raw_samples == 0);
                check_same(a, range_query(without, q, sp.from, w.end, sp.step), q);
            }
            const auto a = range_query(with, "g", sp.from, w.end, sp.step);
            CHECK(with.last_stats().tier_selectors == 1);
            check_same(a, range_query(without, "g", sp.from, w.end, sp.step), "g");

            // increase over a tier is the sum of each step's, a rise counted where its two samples lie in one step
            // or in two steps side by side.
            const std::string q = std::string("increase(c[") + sp.range + "])";
            const auto inc = range_query(with, q, sp.from, w.end, sp.step);
            CHECK(with.last_stats().tier_selectors == 1);
            REQUIRE(inc.series.size() == 2);
            for (size_t i = 0; i < inc.series.size(); ++i)
            {
                const auto& xs = w.xs[2 * i];
                CHECK(label_value(inc.series[i].labels, "i") == label_value(s.labels(w.ids[2 * i]), "i"));
                for (const auto& p : inc.series[i].points)
                {
                    double want = 0;
                    for (size_t k = 1; k < xs.size(); ++k)
                    {
                        const int64_t ea = ceil_to(xs[k - 1].t, sp.step), eb = ceil_to(xs[k].t, sp.step);
                        if (xs[k].t > p.t - sp.step && xs[k].t <= p.t && (ea == eb || ea == eb - sp.step))
                            want += counter_rise(xs[k - 1].v, xs[k].v);
                    }
                    CHECK_MESSAGE(near(p.v, want), q << " at " << p.t);
                }
            }
        }
    }
}

TEST_CASE("store: retention deletes whole blocks past their window, the coarser tiers outliving raw")
{
    tmpdir d;
    store_config c;
    c.keep_raw = 2 * day_ms;
    c.tiers = {{5 * minute_ms, 4 * day_ms}, {hour_ms, 30 * day_ms}};
    store s;
    std::string why;
    REQUIRE(s.open(d.path, c, why));
    workload w(s, 2, 6 * 24, 9, 6 * hour_ms);
    settle(s, w.end);
    const auto names = files_in(d.sub("blocks"));
    for (const std::string& n : names)
    {
        int64_t step = 0, lo = 0, hi = 0;
        REQUIRE(parse_block_name(n, step, lo, hi));
        const int64_t keep = step == 0 ? c.keep_raw : step == 5 * minute_ms ? c.tiers[0].keep : c.tiers[1].keep;
        CHECK(hi >= w.end - keep);
    }
    CHECK_FALSE(fs::exists(d.sub("blocks/" + block_name(0, T0, T0 + day_ms))));
    CHECK_FALSE(fs::exists(d.sub("blocks/" + block_name(5 * minute_ms, T0, T0 + day_ms))));
    CHECK(fs::exists(d.sub("blocks/" + block_name(hour_ms, T0, T0 + day_ms))));
    std::vector<sample> raw;
    s.samples(w.ids[0], T0, T0 + day_ms, raw);
    CHECK(raw.empty());
    std::vector<agg_point> hours;
    s.aggregates(w.ids[0], hour_ms, T0, T0 + day_ms, hours);
    CHECK(hours.size() >= 20);
    // The series lives on in the tier, so a selector over its first day still finds it.
    std::vector<uint32_t> sel;
    s.select(std::vector<matcher>{{"i", match_op::eq, "0"}}, T0, T0 + day_ms, sel);
    CHECK(sel == std::vector<uint32_t>{w.ids[0]});
}

TEST_CASE("store: tier_for picks the coarsest tier no coarser than asked that reaches back far enough")
{
    tmpdir d;
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    const int64_t now = T0 + 10 * 365 * day_ms;
    s.tick(now);
    CHECK(s.tier_for(now - day_ms, 30'000) == 0);
    CHECK(s.tier_for(now - day_ms, 5 * minute_ms) == 5 * minute_ms);
    CHECK(s.tier_for(now - day_ms, 30 * minute_ms) == 5 * minute_ms);
    CHECK(s.tier_for(now - day_ms, 2 * hour_ms) == hour_ms);
    CHECK(s.tier_for(now - 300 * day_ms, 10 * minute_ms) == 5 * minute_ms);
    CHECK(s.tier_for(now - 400 * day_ms, 10 * minute_ms) == 0);
    CHECK(s.tier_for(now - 400 * day_ms, hour_ms) == hour_ms);
    CHECK(s.tier_for(now - 6 * 365 * day_ms, day_ms) == 0);
}

TEST_CASE("store: select and samples span blocks, the head's windows and the open chunk without duplicates")
{
    tmpdir d;
    store s;
    std::string why;
    REQUIRE(s.open(d.path, small_config(), why));
    // An old series that stops, and one that only starts in the head.
    const uint32_t old_id = s.get_or_create(L({{"__name__", "old"}}));
    REQUIRE(s.append(old_id, T0 - 3 * hour_ms, 1));
    workload w(s, 4, 27, 33);
    settle(s, w.end);
    const uint32_t new_id = s.get_or_create(L({{"__name__", "new"}}));
    REQUIRE(s.append(new_id, w.end + 1000, 2));

    std::vector<uint32_t> sel;
    s.select(std::vector<matcher>{{"__name__", match_op::re, "c|g"}}, T0, w.end, sel);
    CHECK(sel == w.ids);
    s.select(std::vector<matcher>{{"__name__", match_op::re, ".+"}}, w.end - hour_ms, w.end + 2000, sel);
    CHECK(std::find(sel.begin(), sel.end(), old_id) == sel.end());
    CHECK(std::find(sel.begin(), sel.end(), new_id) != sel.end());
    s.select(std::vector<matcher>{{"__name__", match_op::eq, "old"}}, T0 - 4 * hour_ms, T0, sel);
    CHECK(sel == std::vector<uint32_t>{old_id});
    s.select(std::vector<matcher>{{"__name__", match_op::eq, "new"}}, T0, w.end, sel);
    CHECK(sel.empty());

    for (size_t i = 0; i < w.ids.size(); ++i)
    {
        const auto got = all_samples(s, w.ids[i]);
        REQUIRE(got.size() == w.xs[i].size());
        for (size_t k = 1; k < got.size(); ++k)
            REQUIRE(got[k].t > got[k - 1].t);
        // Ranges cut across a block edge, a window edge in the head and into the open chunk.
        for (const auto& [lo, hi] : std::vector<std::pair<int64_t, int64_t>>{
                 {T0 + 23 * hour_ms, T0 + 25 * hour_ms}, {w.end - 3 * hour_ms, w.end}, {w.end - 7 * minute_ms, w.end}})
        {
            std::vector<sample> part;
            s.samples(w.ids[i], lo, hi, part);
            size_t want = 0;
            for (const sample& x : w.xs[i])
                want += x.t >= lo && x.t <= hi;
            CHECK(part.size() == want);
        }
    }
    std::vector<std::string> values;
    s.label_values("__name__", values);
    CHECK(values == std::vector<std::string>{"c", "g", "new", "old"});
}

// ── how much it costs ─────────────────────────────────────────────────────

TEST_CASE("perf: append to 100k series, once and then ten rounds")
{
    {
        tmpdir d;
        store s;
        store_config c = small_config();
        std::string why;
        REQUIRE(s.open(d.path, c, why));
        std::vector<uint32_t> ids;
        for (int i = 0; i < 100'000; ++i)
            ids.push_back(s.get_or_create(L({{"__name__", "bench"}, {"i", std::to_string(i).c_str()}})));
        auto t0 = clk::now();
        // Inside one window, (T0, T0 + 2h], so no chunk closes at its edge.
        for (uint32_t id : ids)
            s.append(id, T0 + 10'000, 1.0);
        const double first = std::chrono::duration<double, std::nano>(clk::now() - t0).count() / 1e5;
        t0 = clk::now();
        for (int r = 1; r <= 10; ++r)
            for (uint32_t id : ids)
                s.append(id, T0 + (r + 1) * 10'000, double(r * (id % 100)));
        const double rounds = std::chrono::duration<double, std::nano>(clk::now() - t0).count() / 1e6;
        std::printf("[perf] append: 100k series x 1 sample %.1f ns each, then 10 rounds %.1f ns each\n", first, rounds);
        CHECK(s.stats().samples_appended == 1'100'000);
    }
}

TEST_CASE("perf: RAM for 2000 series after a day of 10s samples")
{
    {
        tmpdir d;
        store s;
        std::string why;
        REQUIRE(s.open(d.path, small_config(), why));
        const long anon0 = status_kb("RssAnon"), file0 = status_kb("RssFile");
        std::vector<uint32_t> ids;
        for (int i = 0; i < 2000; ++i)
            ids.push_back(s.get_or_create(L({{"__name__", i % 3 == 0 ? "socketley_bytes_total" : "socketley_conns"},
                                             {"runtime", ("rt" + std::to_string(i / 20)).c_str()},
                                             {"stat", std::to_string(i % 20).c_str()}})));
        std::mt19937_64 rng(1);
        std::vector<double> v(ids.size(), 0);
        const auto t0 = clk::now();
        for (int64_t k = 0; k < day_rounds; ++k)
        {
            const int64_t t = T0 + k * 10'000;
            for (size_t i = 0; i < ids.size(); ++i)
            {
                if (i % 3 == 0)
                    v[i] += double(rng() % 100000);
                else if (i % 3 == 1)
                    v[i] = double(rng() % 50);
                s.append(ids[i], t, v[i]);
            }
            // The background work keeps up in real time, where two hours are far longer than a cut.
            if (k % 360 == 0)
                settle(s, t);
        }
        settle(s, T0 + day_rounds * 10'000);
        const double secs = std::chrono::duration<double>(clk::now() - t0).count();
        const auto st = s.stats();
        std::printf("[perf] 2000 series x %lld rounds of 10s: %.2f s, store RAM %.2f MB, RSS grew %.2f MB anon "
                    "%.2f MB file, %.2f MB on disk (%.2f B/sample), %llu blocks\n",
                    static_cast<long long>(day_rounds), secs, double(st.bytes_in_ram) / 1048576.0,
                    double(status_kb("RssAnon") - anon0) / 1024.0, double(status_kb("RssFile") - file0) / 1024.0,
                    double(st.bytes_on_disk) / 1048576.0,
                    double(st.bytes_on_disk) / double(st.samples_appended), static_cast<unsigned long long>(st.blocks));
        CHECK(st.bytes_in_ram < 20u * 1048576u);
    }
}

TEST_CASE("perf: 30 days of one series through the 5m tier")
{
    {
        tmpdir d;
        store s;
        std::string why;
        REQUIRE(s.open(d.path, small_config(), why));
        const uint32_t id = s.get_or_create(L({{"__name__", "one"}}));
        double v = 0;
        std::mt19937_64 rng(2);
        const int64_t n = month_days * 8640;
        for (int64_t k = 0; k < n; ++k)
        {
            v += double(rng() % 1000);
            s.append(id, T0 + k * 10'000, v);
            if (k % 360 == 0)
                settle(s, T0 + k * 10'000);
        }
        const int64_t end = T0 + n * 10'000;
        settle(s, end);
        std::vector<agg_point> pts;
        auto t0 = clk::now();
        s.aggregates(id, 5 * minute_ms, end - month_days * day_ms, end, pts);
        const double ms = std::chrono::duration<double, std::milli>(clk::now() - t0).count();
        std::vector<sample> raw;
        t0 = clk::now();
        s.samples(id, end - month_days * day_ms, end, raw);
        const double raw_ms = std::chrono::duration<double, std::milli>(clk::now() - t0).count();
        std::printf("[perf] %lld days of one series: 5m tier %zu points in %.3f ms, raw %zu samples in %.3f ms, "
                    "%llu blocks\n",
                    static_cast<long long>(month_days), pts.size(), ms, raw.size(), raw_ms,
                    static_cast<unsigned long long>(s.stats().blocks));
        CHECK(pts.size() == size_t(month_days * 288));
        CHECK(ms < 50);

        // What a 30-day Grafana panel at a one-hour step costs, through the tiers and raw.
        query_engine with(s), without(s);
        without.limits().use_tiers = false;
        for (const char* q : {"one", "avg_over_time(one[1h])", "rate(one[5m])", "rate(one[1h])"})
        {
            double best[2] = {1e30, 1e30};
            uint64_t read[2] = {0, 0};
            for (int arm = 0; arm < 2; ++arm)
                for (int i = 0; i < 5; ++i)
                {
                    query_engine& e = arm == 0 ? with : without;
                    const auto t1 = clk::now();
                    const auto r = range_query(e, q, end - month_days * day_ms, end, hour_ms);
                    best[arm] = std::min(best[arm], std::chrono::duration<double, std::milli>(clk::now() - t1).count());
                    read[arm] = arm == 0 ? e.last_stats().tier_points : e.last_stats().raw_samples;
                    REQUIRE(r.series.size() == 1);
                }
            std::printf("[perf] %lld days at step 1h, %s: tiers %.3f ms (%llu points), raw %.3f ms (%llu samples)\n",
                        static_cast<long long>(month_days), q, best[0], static_cast<unsigned long long>(read[0]),
                        best[1], static_cast<unsigned long long>(read[1]));
        }
    }
}

TEST_CASE("a staleness marker set after a reopen ends what was there before it")
{
    tmpdir d;
    std::string why;
    store_config c;
    const label_set ls = L({{"__name__", "gone"}, {"job", "socketley"}});
    const int64_t t0 = T0 + 3600000;
    {
        store s;
        REQUIRE_MESSAGE(s.open(d.sub("s"), c, why), why);
        const uint32_t id = s.get_or_create(ls);
        CHECK(s.append(id, t0, 1));
        CHECK(s.append(id, t0 + 10000, 1));
        s.tick(t0 + 10000);
        s.stop();
    }
    store s;
    REQUIRE_MESSAGE(s.open(d.sub("s"), c, why), why);
    s.tick(t0 + 10500);
    const uint32_t id = s.find(ls);
    REQUIRE(id != no_series);
    CHECK(s.mark_stale(id, t0 + 10500));
    query_engine q(s);
    query_result r;
    query_error e;
    REQUIRE(q.eval_instant("gone", t0 + 12000, r, e));
    CHECK(r.series.empty());
    std::vector<sample> raw;
    s.samples(id, t0, t0 + 20000, raw);
    REQUIRE(raw.size() == 3);
    CHECK(is_stale(raw[2].v));
    s.stop();
}
