// The metrics runtime's reader of the Prometheus text format 0.0.4: what a node_exporter-style target writes, each
// sample's views, the family types, escapes, CRLF, the limits, and the lines it refuses without ending the scrape.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <cmath>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

#include "runtime/metrics/metrics_text.h"

using namespace socketley::metrics;

// Every allocation this binary makes, so a test can say a parse made none.
static size_t g_allocations = 0;
void* operator new(size_t n)
{
    ++g_allocations;
    if (void* p = std::malloc(n ? n : 1))
        return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }

namespace
{

struct got
{
    std::string name, series;
    std::vector<std::pair<std::string, std::string>> labels;
    double value;
    bool has_ts;
    int64_t ts;
    metric_type type;
};

struct sink : text_sink
{
    std::vector<got> samples;
    std::vector<std::pair<std::string, metric_type>> types;
    std::vector<std::pair<std::string, std::string>> helps;
    const char* body_begin{nullptr};
    const char* body_end{nullptr};
    bool views_inside{true};

    void on_sample(const text_sample& s) override
    {
        got g{std::string(s.name), std::string(s.series), {}, s.value, s.has_timestamp, s.timestamp_ms, s.type};
        for (const auto& l : s.labels)
            g.labels.emplace_back(std::string(l.name), std::string(l.value));
        // The name and the raw series bytes are views into the body itself, never a copy.
        if (body_begin && (s.series.data() < body_begin || s.series.data() + s.series.size() > body_end ||
                           s.name.data() != s.series.data()))
            views_inside = false;
        samples.push_back(std::move(g));
    }
    void on_type(std::string_view f, metric_type t) override { types.emplace_back(std::string(f), t); }
    void on_help(std::string_view f, std::string_view h) override { helps.emplace_back(std::string(f), std::string(h)); }
};

const char* node_exporter = R"(# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 2.6542e-05
go_gc_duration_seconds{quantile="0.25"} 3.4211e-05
go_gc_duration_seconds{quantile="1"} 0.000338416
go_gc_duration_seconds_sum 0.012734917
go_gc_duration_seconds_count 287
# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 394851.43
node_cpu_seconds_total{cpu="0",mode="iowait"} 92.78
node_cpu_seconds_total{cpu="0",mode="user"} 4823.9
# HELP node_filesystem_avail_bytes Filesystem space available to non-root users in bytes.
# TYPE node_filesystem_avail_bytes gauge
node_filesystem_avail_bytes{device="/dev/nvme0n1p2",fstype="ext4",mountpoint="/"} 1.73264674816e+11
# HELP node_http_request_duration_seconds A histogram of request latencies.
# TYPE node_http_request_duration_seconds histogram
node_http_request_duration_seconds_bucket{handler="/metrics",le="0.005"} 1342
node_http_request_duration_seconds_bucket{handler="/metrics",le="0.01"} 1350
node_http_request_duration_seconds_bucket{handler="/metrics",le="+Inf"} 1351
node_http_request_duration_seconds_sum{handler="/metrics"} 4.21
node_http_request_duration_seconds_count{handler="/metrics"} 1351
# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 0.52
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="arp"} 1
untyped_thing 7 1700000000123
)";

}   // namespace

TEST_CASE("a node_exporter-style page reads into samples with their family's type")
{
    text_parser p;
    sink s;
    text_stats st;
    const std::string body = node_exporter;
    s.body_begin = body.data();
    s.body_end = body.data() + body.size();
    p.parse(body, s, st);
    CHECK(st.refused == 0);
    CHECK(st.samples == 17);
    REQUIRE(s.samples.size() == 17);
    CHECK(s.views_inside);

    CHECK(s.samples[0].name == "go_gc_duration_seconds");
    CHECK(s.samples[0].series == "go_gc_duration_seconds{quantile=\"0\"}");
    CHECK(s.samples[0].labels == std::vector<std::pair<std::string, std::string>>{{"quantile", "0"}});
    CHECK(s.samples[0].value == 2.6542e-05);
    CHECK(s.samples[0].type == metric_type::summary);
    CHECK(s.samples[3].type == metric_type::summary);
    CHECK(s.samples[4].name == "go_gc_duration_seconds_count");
    CHECK(s.samples[4].type == metric_type::summary);
    CHECK(s.samples[4].series == "go_gc_duration_seconds_count");
    CHECK(s.samples[4].labels.empty());
    CHECK(s.samples[5].type == metric_type::counter);
    CHECK(s.samples[5].labels.size() == 2);
    CHECK(s.samples[8].value == 1.73264674816e+11);
    CHECK(s.samples[8].type == metric_type::gauge);
    for (int i = 9; i <= 13; ++i)
        CHECK_MESSAGE(s.samples[static_cast<size_t>(i)].type == metric_type::histogram, i);
    CHECK(s.samples[11].labels[1] == std::pair<std::string, std::string>{"le", "+Inf"});
    CHECK(s.samples[14].name == "node_load1");
    CHECK(s.samples[14].type == metric_type::gauge);
    CHECK(!s.samples[14].has_ts);
    CHECK(s.samples[16].type == metric_type::untyped);
    CHECK(s.samples[16].has_ts);
    CHECK(s.samples[16].ts == 1700000000123);

    REQUIRE(s.types.size() == 6);
    CHECK(s.types[3] == std::pair<std::string, metric_type>{"node_http_request_duration_seconds", metric_type::histogram});
    REQUIRE(s.helps.size() == 6);
    CHECK(s.helps[1].second == "Seconds the CPUs spent in each mode.");
    CHECK(s.helps[5].second == "node_exporter: Whether a collector succeeded.");
}

TEST_CASE("values are Go floats: NaN, +Inf, -Inf, exponents; a timestamp is whole milliseconds")
{
    text_parser p;
    sink s;
    text_stats st;
    p.parse("a NaN\nb +Inf\nc -Inf\nd Inf\ne -1.5E3\nf .5\ng 1.\nh 1e-400\ni 0 -5\nj -0\n", s, st);
    REQUIRE(st.refused == 0);
    REQUIRE(s.samples.size() == 10);
    CHECK(std::isnan(s.samples[0].value));
    CHECK(s.samples[1].value == INFINITY);
    CHECK(s.samples[2].value == -INFINITY);
    CHECK(s.samples[3].value == INFINITY);
    CHECK(s.samples[4].value == -1500);
    CHECK(s.samples[5].value == 0.5);
    CHECK(s.samples[6].value == 1);
    CHECK(s.samples[7].value == 0);
    CHECK(s.samples[8].ts == -5);
    CHECK(std::signbit(s.samples[9].value));

    // Forms Go's ParseFloat or the text format refuses: hex, underscores, a sign on NaN, a bare point, an overflow.
    sink bad;
    text_stats bst;
    p.parse("a 0x10\nb 1_000\nc -NaN\nd .\ne 1e400\nf nan(1)\ng 1 2.5\nh 1 2 3\n", bad, bst);
    CHECK(bst.refused == 8);
    CHECK(bad.samples.empty());
}

TEST_CASE("label values unescape \\\\, \\\" and \\n into scratch, other escapes stay as written")
{
    text_parser p;
    sink s;
    text_stats st;
    p.parse("m{a=\"x\\\\y\",b=\"q\\\"t\",c=\"l1\\nl2\",d=\"\\t\",e=\"plain\"} 1\n", s, st);
    REQUIRE(st.refused == 0);
    REQUIRE(s.samples.size() == 1);
    const auto& l = s.samples[0].labels;
    REQUIRE(l.size() == 5);
    CHECK(l[0].second == "x\\y");
    CHECK(l[1].second == "q\"t");
    CHECK(l[2].second == "l1\nl2");
    CHECK(l[3].second == "\\t");
    CHECK(l[4].second == "plain");
    // The raw series keeps the escapes, as the target wrote them.
    CHECK(s.samples[0].series == "m{a=\"x\\\\y\",b=\"q\\\"t\",c=\"l1\\nl2\",d=\"\\t\",e=\"plain\"}");

    // A HELP text unescapes \\ and \n.
    sink h;
    p.parse("# HELP m a\\nb\\\\c\n", h, st);
    REQUIRE(h.helps.size() == 1);
    CHECK(h.helps[0].second == "a\nb\\c");
}

TEST_CASE("CRLF, blank lines, other comments, spaces and a trailing comma are tolerated")
{
    text_parser p;
    sink s;
    text_stats st;
    p.parse("# just a comment\r\n\r\n   \n#HELP not_help x\nm { a = \"1\" , b=\"2\", } 3 \r\n\tn\t4\r\nlast 5", s, st);
    CHECK(st.refused == 0);
    REQUIRE(s.samples.size() == 3);
    CHECK(s.samples[0].labels.size() == 2);
    CHECK(s.samples[0].value == 3);
    CHECK(s.samples[1].name == "n");
    CHECK(s.samples[1].value == 4);
    CHECK(s.samples[2].value == 5);
    CHECK(s.helps.empty());
    CHECK(st.lines == 7);
    sink e;
    text_stats est;
    p.parse("m{} 1\n", e, est);
    REQUIRE(e.samples.size() == 1);
    CHECK(e.samples[0].labels.empty());
}

TEST_CASE("a malformed line is skipped and counted while the lines around it are read")
{
    text_parser p;
    sink s;
    text_stats st;
    const char* body = "ok 1\n"
                       "9bad 1\n"
                       "m{a=\"1\" 2\n"
                       "m{a=1} 2\n"
                       "m{a=\"1\",a=\"2\"} 2\n"
                       "m{__name__=\"x\"} 2\n"
                       "m{1a=\"x\"} 2\n"
                       "m{a=\"unterminated} 2\n"
                       "nospace{a=\"b\"}\n"
                       "novalue\n"
                       "m{a=\"1\"} 2 notanumber\n"
                       "# TYPE x bogus\n"
                       "# TYPE x counter extra\n"
                       "m{a=\"1\"}{b=\"2\"} 1\n"
                       "fine{a=\"1\"} 2\n";
    p.parse(body, s, st);
    CHECK(st.refused == 13);
    REQUIRE(s.samples.size() == 2);
    CHECK(s.samples[0].name == "ok");
    CHECK(s.samples[1].name == "fine");
    CHECK(st.samples == 2);
}

TEST_CASE("the limits refuse a long line, too many labels and a long name")
{
    text_limits lim;
    lim.max_line = 64;
    lim.max_labels = 3;
    lim.max_name = 16;
    text_parser p(lim);
    sink s;
    text_stats st;
    std::string body = "m{a=\"1\",b=\"2\",c=\"3\"} 1\n";
    body += "m{a=\"1\",b=\"2\",c=\"3\",d=\"4\"} 1\n";
    body += "a_very_long_metric_name_here 1\n";
    body += "m{a_very_long_label_name=\"1\"} 1\n";
    body += "m{a=\"" + std::string(80, 'x') + "\"} 1\n";
    body += "short 1\n";
    p.parse(body, s, st);
    CHECK(st.refused == 4);
    REQUIRE(s.samples.size() == 2);
    CHECK(s.samples[1].name == "short");
}

TEST_CASE("the type applies to its own family only, and a TYPE line names the next family")
{
    text_parser p;
    sink s;
    text_stats st;
    p.parse("# TYPE h histogram\nh_bucket{le=\"1\"} 1\nh_sum 1\nh_count 1\nh_other 1\nhx_sum 1\n"
            "# TYPE s summary\ns_bucket 1\ns_sum 1\n# TYPE c counter\nc 1\nc_total 1\n",
            s, st);
    REQUIRE(s.samples.size() == 9);
    CHECK(s.samples[0].type == metric_type::histogram);
    CHECK(s.samples[1].type == metric_type::histogram);
    CHECK(s.samples[2].type == metric_type::histogram);
    CHECK(s.samples[3].type == metric_type::untyped);
    CHECK(s.samples[4].type == metric_type::untyped);
    CHECK(s.samples[5].type == metric_type::untyped);
    CHECK(s.samples[6].type == metric_type::summary);
    CHECK(s.samples[7].type == metric_type::counter);
    CHECK(s.samples[8].type == metric_type::untyped);
}

TEST_CASE("the parser allocates nothing per line once its scratch has grown")
{
    text_parser p;
    sink s;
    text_stats st;
    std::string body;
    for (int i = 0; i < 1000; ++i)
        body += "m{a=\"x\\\\" + std::to_string(i) + "\",b=\"y\"} " + std::to_string(i) + "\n";
    p.parse(body, s, st);
    struct counting : text_sink
    {
        size_t n{0};
        double sum{0};
        void on_sample(const text_sample& s) override
        {
            ++n;
            sum += s.value;
        }
    } c;
    const size_t before = g_allocations;
    p.parse(body, c, st);
    CHECK(g_allocations == before);
    CHECK(c.n == 1000);
    CHECK(c.sum == 999.0 * 1000 / 2);
}
