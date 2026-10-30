// The latency histogram the runtimes fill and the catalog's reading of it: the bucket of a duration at every bound
// and a nanosecond either side, the stats line and back, two shards' lines added, and the exposition text it becomes.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <charconv>
#include <cstdlib>
#include <string>
#include <vector>

#include "shared/runtime/latency_histogram.h"
#include "shared/runtime/metric_catalog.h"
#include "shared/runtime/metric_text.h"

using socketley::latency_histogram;
namespace mc = socketley::metric_catalog;

namespace
{

constexpr uint64_t us = 1000;

double le_value(std::string_view s)
{
    double v = 0;
    std::from_chars(s.data(), s.data() + s.size(), v);
    return v;
}

}   // namespace

TEST_CASE("a duration's bucket is the first whose bound it does not pass")
{
    CHECK(latency_histogram::index_of_ns(0) == 0);
    CHECK(latency_histogram::index_of_ns(1) == 0);
    CHECK(latency_histogram::index_of_ns(64 * us) == 0);
    CHECK(latency_histogram::index_of_ns(64 * us + 1) == 1);
    CHECK(latency_histogram::index_of_ns(128 * us) == 1);
    CHECK(latency_histogram::index_of_ns(128 * us + 1) == 2);
    for (int i = 0; i < latency_histogram::finite; ++i)
    {
        const uint64_t bound = latency_histogram::bound_us(i) * us;
        CAPTURE(i);
        CHECK(latency_histogram::index_of_ns(bound) == i);
        CHECK(latency_histogram::index_of_ns(bound - 1) == i);
        CHECK(latency_histogram::index_of_ns(bound + 1) == i + 1);
        if (i > 0)
            CHECK(latency_histogram::index_of_ns(latency_histogram::bound_us(i - 1) * us + 1) == i);
    }
    // Past the last finite bound, and past any duration a clock could measure, it is +Inf.
    CHECK(latency_histogram::index_of_ns(latency_histogram::bound_us(latency_histogram::finite - 1) * us + 1) ==
          latency_histogram::finite);
    CHECK(latency_histogram::index_of_ns(3600ull * 1000000000ull) == latency_histogram::finite);
    CHECK(latency_histogram::index_of_ns(UINT64_MAX - 1000) == latency_histogram::finite);
}

TEST_CASE("le names each bucket's bound in seconds, ascending, and ends in +Inf")
{
    for (int i = 0; i < latency_histogram::finite; ++i)
    {
        CAPTURE(i);
        CHECK(le_value(latency_histogram::le[static_cast<size_t>(i)]) * 1e6 ==
              doctest::Approx(static_cast<double>(latency_histogram::bound_us(i))));
    }
    CHECK(latency_histogram::le[latency_histogram::finite] == "+Inf");
    CHECK(latency_histogram::le[0] == "0.000064");
    CHECK(latency_histogram::le[latency_histogram::finite - 1] == "16.777216");
}

TEST_CASE("an end before its start counts as no time")
{
    latency_histogram h;
    h.observe(500, 100);
    h.observe(100, 100 + 200 * us);
    CHECK(h.count() == 2);
    CHECK(h.bucket(0) == 1);
    CHECK(h.bucket(2) == 1);
    CHECK(h.sum_ns() == 200 * us);
}

TEST_CASE("the stats line reads back as the histogram it was written from")
{
    latency_histogram h;
    h.observe_ns(10 * us);
    h.observe_ns(70 * us);
    h.observe_ns(3ull * 1000000000ull);
    h.observe_ns(100ull * 1000000000ull);
    std::string line;
    h.put(line, "request_latency");
    REQUIRE(line.starts_with("request_latency:"));
    REQUIRE(line.ends_with("\n"));
    latency_histogram back;
    REQUIRE(latency_histogram::parse(std::string_view(line).substr(16, line.size() - 17), back));
    CHECK(back.count() == 4);
    CHECK(back.sum_ns() == h.sum_ns());
    for (int i = 0; i < latency_histogram::buckets; ++i)
        CHECK(back.bucket(i) == h.bucket(i));

    latency_histogram junk;
    CHECK_FALSE(latency_histogram::parse("", junk));
    CHECK_FALSE(latency_histogram::parse("1 2 3", junk));
    CHECK_FALSE(latency_histogram::parse(std::string(line.substr(16, line.size() - 17)) + " 9", junk));
    CHECK_FALSE(latency_histogram::parse(std::string(line.substr(16, line.size() - 17)) + " ", junk));
    CHECK_FALSE(latency_histogram::parse("x 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", junk));
    CHECK(latency_histogram::parse("0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", junk));
}

TEST_CASE("the catalog turns two shards' lines into one cumulative histogram")
{
    latency_histogram a, b;
    a.observe_ns(10 * us);
    a.observe_ns(100 * us);
    b.observe_ns(100 * us);
    b.observe_ns(5ull * 1000000000ull);
    b.observe_ns(60ull * 1000000000ull);
    std::string text = "[shard 0]\nbackend_responses:2\n";
    a.put(text, "request_latency");
    text += "[shard 1]\nbackend_responses:3\n";
    b.put(text, "request_latency");

    mc::figures f;
    f.parse(runtime_proxy, text);
    std::string out;
    {
        socketley::metric_text::writer w(out);
        const mc::source src{"px", &f};
        mc::emit(*mc::entry_for(runtime_proxy), std::span<const mc::source>(&src, 1), w);
    }
    CHECK(out.find("# TYPE socketley_proxy_request_duration_seconds histogram\n") != std::string::npos);
    CHECK(out.find("socketley_proxy_request_duration_seconds_bucket{name=\"px\",le=\"0.000064\"} 1\n") !=
          std::string::npos);
    CHECK(out.find("socketley_proxy_request_duration_seconds_bucket{name=\"px\",le=\"0.000128\"} 3\n") !=
          std::string::npos);
    CHECK(out.find("socketley_proxy_request_duration_seconds_bucket{name=\"px\",le=\"8.388608\"} 4\n") !=
          std::string::npos);
    CHECK(out.find("socketley_proxy_request_duration_seconds_bucket{name=\"px\",le=\"16.777216\"} 4\n") !=
          std::string::npos);
    CHECK(out.find("socketley_proxy_request_duration_seconds_bucket{name=\"px\",le=\"+Inf\"} 5\n") !=
          std::string::npos);
    CHECK(out.find("socketley_proxy_request_duration_seconds_count{name=\"px\"} 5\n") != std::string::npos);
    CHECK(out.find("socketley_proxy_request_duration_seconds_sum{name=\"px\"} 65.00021\n") != std::string::npos);
    // The histogram is written once, and the line is no catch-all figure.
    CHECK(out.find("# TYPE socketley_proxy_request_duration_seconds histogram") ==
          out.rfind("# TYPE socketley_proxy_request_duration_seconds histogram"));
    CHECK(out.find("stat=\"request_latency\"") == std::string::npos);
    // A family's bucket lines come in ascending le, all twenty of them.
    size_t at = 0, buckets = 0;
    double last = -1;
    while ((at = out.find("_seconds_bucket{name=\"px\",le=\"", at)) != std::string::npos)
    {
        at += 30;
        const std::string_view le = std::string_view(out).substr(at, out.find('"', at) - at);
        const double v = le == "+Inf" ? 1e300 : le_value(le);
        CHECK(v > last);
        last = v;
        ++buckets;
    }
    CHECK(buckets == latency_histogram::buckets);
}

TEST_CASE("a histogram line that is not one is left out, and the runtime's other figures stay")
{
    mc::figures f;
    f.parse(runtime_proxy, "backend_responses:7\nrequest_latency:12 1 2\n");
    std::string out;
    {
        socketley::metric_text::writer w(out);
        const mc::source src{"px", &f};
        mc::emit(*mc::entry_for(runtime_proxy), std::span<const mc::source>(&src, 1), w);
    }
    CHECK(out.find("request_duration_seconds") == std::string::npos);
    CHECK(out.find("socketley_proxy_backend_responses_total{name=\"px\"} 7\n") != std::string::npos);
}
