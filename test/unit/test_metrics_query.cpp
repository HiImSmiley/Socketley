// The metrics runtime's PromQL against a vector-backed store: every function and operator with values derived by hand
// from Prometheus's documented semantics, the errors it gives, the JSON it renders, and the tier planner checked
// against brute force over the raw samples.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "runtime/metrics/metrics_query.h"
#include "runtime/metrics/metrics_regex.h"
#include "metrics_fake_source.h"

using namespace socketley::metrics;
using socketley::metrics::testing::fake_source;

namespace
{

constexpr int64_t sec = 1000;

std::string str(const label_set& ls)
{
    std::string out = "{";
    for (size_t i = 0; i < ls.size(); ++i)
        out += (i ? "," : "") + ls[i].name + "=\"" + ls[i].value + "\"";
    return out + "}";
}

std::vector<sample> pts(std::initializer_list<std::pair<double, double>> l)
{
    std::vector<sample> out;
    for (auto [t, v] : l)
        out.push_back({static_cast<int64_t>(t * sec), v});
    return out;
}

struct db
{
    fake_source src;
    query_engine eng{src};

    std::map<std::string, double> at(std::string_view q, double t)
    {
        query_result r;
        query_error e;
        const bool ok = eng.eval_instant(q, static_cast<int64_t>(t * sec), r, e);
        REQUIRE_MESSAGE(ok, std::string(q) << ": " << e.message);
        std::map<std::string, double> out;
        if (r.kind == result_kind::scalar)
            out[""] = r.scalar;
        for (const auto& s : r.series)
        {
            CHECK_MESSAGE(out.count(str(s.labels)) == 0, "duplicate " << str(s.labels));
            out[str(s.labels)] = s.points.at(0).v;
        }
        return out;
    }
    double one(std::string_view q, double t)
    {
        auto m = at(q, t);
        REQUIRE_MESSAGE(m.size() == 1, std::string(q) << " gave " << m.size() << " results");
        return m.begin()->second;
    }
    std::string fails(std::string_view q, double t = 100, std::string* type = nullptr)
    {
        query_result r;
        query_error e;
        CHECK_MESSAGE(!eng.eval_instant(q, static_cast<int64_t>(t * sec), r, e), q);
        if (type)
            *type = e.type;
        return e.message;
    }
    query_result range(std::string_view q, double start, double end, double step)
    {
        query_result r;
        query_error e;
        const bool ok = eng.eval_range(q, static_cast<int64_t>(start * sec), static_cast<int64_t>(end * sec),
                                       static_cast<int64_t>(step * sec), r, e);
        REQUIRE_MESSAGE(ok, std::string(q) << ": " << e.message);
        return r;
    }
};

bool contains(const std::string& s, std::string_view part) { return s.find(part) != std::string::npos; }

}   // namespace

TEST_CASE("an instant selector looks back five minutes, left-open, and a staleness marker ends its series")
{
    db d;
    d.src.add({{"__name__", "x"}, {"a", "1"}}, pts({{10, 1}, {20, 2}}));
    d.src.add({{"__name__", "y"}}, pts({{10, 1}, {20, stale_nan()}, {40, 3}}));
    CHECK(d.one("x", 20) == 2);
    CHECK(d.one("x", 25) == 2);
    CHECK(d.one("x", 15) == 1);
    CHECK(d.at("x", 5).empty());
    CHECK(d.one("x", 319) == 2);
    // (20, 320] no longer holds the sample at 20.
    CHECK(d.at("x", 320).empty());
    CHECK(d.one("y", 15) == 1);
    CHECK(d.at("y", 25).empty());
    CHECK(d.one("y", 40) == 3);
    CHECK(d.at("x", 20).begin()->first == "{__name__=\"x\",a=\"1\"}");
    CHECK(d.one("x offset 10s", 30) == 2);
    CHECK(d.one("x offset 15s", 30) == 1);
    CHECK(d.one("x offset -10s", 10) == 2);
    CHECK(d.one("timestamp(x)", 25) == 20);
    CHECK(d.one("timestamp(y)", 45) == 40);
    CHECK(d.one("timestamp(x + 1)", 25) == 25);
}

TEST_CASE("selectors match =, !=, =~ and !~ anchored, an absent label as the empty string")
{
    db d;
    d.src.add({{"__name__", "up"}, {"job", "api"}, {"env", "prod"}}, pts({{0, 1}}));
    d.src.add({{"__name__", "up"}, {"job", "api-canary"}}, pts({{0, 2}}));
    d.src.add({{"__name__", "up"}, {"job", "db"}, {"env", "dev"}}, pts({{0, 3}}));
    d.src.add({{"__name__", "down"}, {"job", "db"}}, pts({{0, 4}}));
    CHECK(d.at("up", 1).size() == 3);
    CHECK(d.one("up{job=\"db\"}", 1) == 3);
    CHECK(d.at("up{job!=\"db\"}", 1).size() == 2);
    CHECK(d.at("up{job=~\"api\"}", 1).size() == 1);
    CHECK(d.at("up{job=~\"api.*\"}", 1).size() == 2);
    CHECK(d.at("up{job!~\"api.*\"}", 1).size() == 1);
    CHECK(d.one("up{env=\"\"}", 1) == 2);
    CHECK(d.at("up{env!=\"\"}", 1).size() == 2);
    CHECK(d.at("up{job=~\"API|db\"}", 1).size() == 1);
    CHECK(d.at("up{job=~\"(?i)API\"}", 1).size() == 1);
    CHECK(d.at("{__name__=~\"up|down\",job=\"db\"}", 1).size() == 2);
    CHECK(d.at("{job=\"db\"}", 1).size() == 2);
    CHECK(d.one("{\"down\"}", 1) == 4);
    CHECK(d.at("up{job=~\"a.i\",}", 1).size() == 1);
}

TEST_CASE("rate, increase and delta extrapolate as Prometheus's extrapolatedRate")
{
    db d;
    // One per second from zero, at 0, 15, 30, 45 and 60: the window (0, 60] holds four of them.
    d.src.add({{"__name__", "a"}}, pts({{0, 0}, {15, 15}, {30, 30}, {45, 45}, {60, 60}}));
    CHECK(d.one("rate(a[1m])", 60) == doctest::Approx(1.0));
    CHECK(d.one("increase(a[1m])", 60) == doctest::Approx(60.0));
    // Both edges near enough: (10, 70] runs to 5 s before the first sample and 10 s after the last.
    CHECK(d.one("increase(a[1m])", 70) == doctest::Approx(60.0));

    // A series that starts inside the window is stretched back only half an interval: 30 * 37.5 / 30.
    d.src.add({{"__name__", "b"}}, pts({{30, 100}, {45, 115}, {60, 130}}));
    CHECK(d.one("increase(b[1m])", 60) == doctest::Approx(37.5));
    CHECK(d.one("rate(b[1m])", 60) == doctest::Approx(37.5 / 60));

    // A counter that would cross zero is stretched back only to where it would: 1 s here, so 30 * 31 / 30.
    d.src.add({{"__name__", "c"}}, pts({{30, 1}, {45, 16}, {60, 31}}));
    CHECK(d.one("increase(c[1m])", 60) == doctest::Approx(31.0));

    // A reset adds the value before it: 10, 20, 5, 15 is an increase of 25 over 45 s, stretched to 60.
    d.src.add({{"__name__", "r"}}, pts({{15, 10}, {30, 20}, {45, 5}, {60, 15}}));
    CHECK(d.one("increase(r[1m])", 60) == doctest::Approx(25.0 * 60 / 45));
    CHECK(d.one("rate(r[1m])", 60) == doctest::Approx(25.0 / 45));
    CHECK(d.one("delta(r[1m])", 60) == doctest::Approx(5.0 * 60 / 45));
    CHECK(d.one("resets(r[1m])", 60) == 1);
    CHECK(d.one("irate(r[1m])", 45) == doctest::Approx(5.0 / 15));
    CHECK(d.one("idelta(r[1m])", 45) == -15);
    CHECK(d.one("irate(r[1m])", 60) == doctest::Approx(10.0 / 15));

    // One sample is no rate.
    CHECK(d.at("rate(a[10s])", 60).empty());
    CHECK(d.one("count_over_time(a[10s])", 60) == 1);
    // The name goes with the change.
    CHECK(d.at("rate(a[1m])", 60).begin()->first == "{}");
}

TEST_CASE("the over_time functions, quantile_over_time and the regressions")
{
    db d;
    d.src.add({{"__name__", "g"}, {"k", "v"}}, pts({{10, 1}, {20, 2}, {30, 3}, {40, 4}}));
    CHECK(d.one("avg_over_time(g[1m])", 40) == 2.5);
    CHECK(d.one("min_over_time(g[1m])", 40) == 1);
    CHECK(d.one("max_over_time(g[1m])", 40) == 4);
    CHECK(d.one("sum_over_time(g[1m])", 40) == 10);
    CHECK(d.one("count_over_time(g[1m])", 40) == 4);
    CHECK(d.one("last_over_time(g[1m])", 40) == 4);
    CHECK(d.one("present_over_time(g[1m])", 40) == 1);
    CHECK(d.one("stdvar_over_time(g[1m])", 40) == doctest::Approx(1.25));
    CHECK(d.one("stddev_over_time(g[1m])", 40) == doctest::Approx(std::sqrt(1.25)));
    CHECK(d.one("quantile_over_time(0.5, g[1m])", 40) == doctest::Approx(2.5));
    CHECK(d.one("quantile_over_time(0.9, g[1m])", 40) == doctest::Approx(3.7));
    CHECK(std::isinf(d.one("quantile_over_time(2, g[1m])", 40)));
    CHECK(d.one("deriv(g[1m])", 40) == doctest::Approx(0.1));
    // The line through (10,1)..(40,4), 20 s past the evaluation time: 4 + 0.1 * 20.
    CHECK(d.one("predict_linear(g[1m], 20)", 40) == doctest::Approx(6.0));
    CHECK(d.one("changes(g[1m])", 40) == 3);
    CHECK(d.one("count_over_time(g[25s])", 40) == 3);
    CHECK(d.one("sum_over_time(g[30s] offset 10s)", 50) == 9);
    CHECK(d.at("last_over_time(g[1m])", 40).begin()->first == "{__name__=\"g\",k=\"v\"}");
    CHECK(d.at("avg_over_time(g[1m])", 40).begin()->first == "{k=\"v\"}");
    CHECK(d.at("absent_over_time(g[1m])", 40).empty());
    CHECK(d.at("absent_over_time(nope{job=\"a\",x=~\"y\"}[1m])", 40) == std::map<std::string, double>{{"{job=\"a\"}", 1}});

    d.src.add({{"__name__", "flat"}}, pts({{10, 5}, {20, 5}, {30, 5}}));
    CHECK(d.one("deriv(flat[1m])", 30) == 0);
    CHECK(d.one("changes(flat[1m])", 30) == 0);
    d.src.add({{"__name__", "ch"}}, pts({{10, 1}, {20, 2}, {30, 2}, {40, 1}, {50, 3}, {60, 3}}));
    CHECK(d.one("changes(ch[1m])", 60) == 3);
    CHECK(d.one("resets(ch[1m])", 60) == 1);
    // A staleness marker is no sample of a range.
    d.src.add({{"__name__", "st"}}, pts({{10, 1}, {20, stale_nan()}, {30, 3}}));
    CHECK(d.one("count_over_time(st[1m])", 30) == 2);
}

TEST_CASE("aggregations with by and without on either side, topk and bottomk ties as Prometheus's heap keeps them")
{
    db d;
    d.src.add({{"__name__", "http"}, {"code", "200"}, {"inst", "a"}}, pts({{0, 1}}));
    d.src.add({{"__name__", "http"}, {"code", "200"}, {"inst", "b"}}, pts({{0, 2}}));
    d.src.add({{"__name__", "http"}, {"code", "500"}, {"inst", "a"}}, pts({{0, 3}}));
    d.src.add({{"__name__", "http"}, {"code", "500"}, {"inst", "b"}}, pts({{0, 6}}));
    using m = std::map<std::string, double>;
    CHECK(d.at("sum(http)", 1) == m{{"{}", 12}});
    CHECK(d.at("sum by (code) (http)", 1) == m{{"{code=\"200\"}", 3}, {"{code=\"500\"}", 9}});
    CHECK(d.at("sum(http) by (code)", 1) == m{{"{code=\"200\"}", 3}, {"{code=\"500\"}", 9}});
    CHECK(d.at("SUM without (inst) (http)", 1) == m{{"{code=\"200\"}", 3}, {"{code=\"500\"}", 9}});
    CHECK(d.at("avg by (inst) (http)", 1) == m{{"{inst=\"a\"}", 2}, {"{inst=\"b\"}", 4}});
    CHECK(d.one("min(http)", 1) == 1);
    CHECK(d.one("max(http)", 1) == 6);
    CHECK(d.one("count(http)", 1) == 4);
    CHECK(d.one("stdvar(http)", 1) == doctest::Approx(3.5));
    CHECK(d.one("stddev(http)", 1) == doctest::Approx(std::sqrt(3.5)));
    CHECK(d.one("quantile(0.5, http)", 1) == doctest::Approx(2.5));
    CHECK(d.at("group by (code) (http)", 1) == m{{"{code=\"200\"}", 1}, {"{code=\"500\"}", 1}});
    CHECK(d.at("sum by (__name__) (http)", 1) == m{{"{__name__=\"http\"}", 12}});
    CHECK(d.at("topk(2, http)", 1) ==
          m{{"{__name__=\"http\",code=\"500\",inst=\"a\"}", 3}, {"{__name__=\"http\",code=\"500\",inst=\"b\"}", 6}});
    CHECK(d.at("bottomk(1, http)", 1) == m{{"{__name__=\"http\",code=\"200\",inst=\"a\"}", 1}});
    CHECK(d.at("topk by (code) (1, http)", 1) ==
          m{{"{__name__=\"http\",code=\"200\",inst=\"b\"}", 2}, {"{__name__=\"http\",code=\"500\",inst=\"b\"}", 6}});
    CHECK(d.at("topk(0, http)", 1).empty());
    CHECK(d.at("count_values(\"v\", http)", 1) ==
          m{{"{v=\"1\"}", 1}, {"{v=\"2\"}", 1}, {"{v=\"3\"}", 1}, {"{v=\"6\"}", 1}});
    CHECK(d.at("count_values by (code) (\"v\", http > 1)", 1).size() == 3);
    // The value label replaces a label of that name before grouping, so equal values merge into one count.
    CHECK(d.at("count_values(\"inst\", http == 1 or http == 3)", 1) == m{{"{inst=\"1\"}", 1}, {"{inst=\"3\"}", 1}});
    CHECK(d.at("count_values by (inst) (\"inst\", http > 0 < 4)", 1) ==
          m{{"{inst=\"1\"}", 1}, {"{inst=\"2\"}", 1}, {"{inst=\"3\"}", 1}});
    CHECK(d.at("count_values without (inst) (\"code\", http * 0)", 1) == m{{"{code=\"0\"}", 4}});
    // The value is Go's 'f' at every magnitude, as count_values writes it.
    CHECK(d.at("count_values(\"v\", vector(1e-7))", 1) == m{{"{v=\"0.0000001\"}", 1}});
    CHECK(d.at("count_values(\"v\", vector(2^70))", 1) == m{{"{v=\"1180591620717411300000\"}", 1}});

    // Ties: a=1, b=1, c=2; the heap holds a and b, and c replaces its root a, so b and c remain.
    db t;
    t.src.add({{"__name__", "x"}, {"n", "a"}}, pts({{0, 1}}));
    t.src.add({{"__name__", "x"}, {"n", "b"}}, pts({{0, 1}}));
    t.src.add({{"__name__", "x"}, {"n", "c"}}, pts({{0, 2}}));
    CHECK(t.at("topk(2, x)", 1) == m{{"{__name__=\"x\",n=\"b\"}", 1}, {"{__name__=\"x\",n=\"c\"}", 2}});
    CHECK(t.at("topk(1, x == 1)", 1) == m{{"{__name__=\"x\",n=\"a\"}", 1}});
    db u;
    u.src.add({{"__name__", "x"}, {"n", "a"}}, pts({{0, 2}}));
    u.src.add({{"__name__", "x"}, {"n", "b"}}, pts({{0, 2}}));
    u.src.add({{"__name__", "x"}, {"n", "c"}}, pts({{0, 1}}));
    CHECK(u.at("bottomk(2, x)", 1) == m{{"{__name__=\"x\",n=\"b\"}", 2}, {"{__name__=\"x\",n=\"c\"}", 1}});

    // An instant topk lists the largest first.
    query_result r;
    query_error e;
    REQUIRE(d.eng.eval_instant("topk(3, http)", sec, r, e));
    REQUIRE(r.series.size() == 3);
    CHECK(r.series[0].points[0].v == 6);
    CHECK(r.series[2].points[0].v == 2);
}

TEST_CASE("sums are Kahan-compensated and a mean that would overflow turns incremental, as in Prometheus 3")
{
    db d;
    d.src.add({{"__name__", "k"}, {"n", "a"}}, pts({{0, 1e100}, {10, 1e308}}));
    d.src.add({{"__name__", "k"}, {"n", "b"}}, pts({{0, 1}, {10, 1e308}}));
    d.src.add({{"__name__", "k"}, {"n", "c"}}, pts({{0, -1e100}, {10, 1e308}}));
    // A plain sum of 1e100, 1 and -1e100 is 0; the compensation keeps the 1.
    CHECK(d.one("sum(k)", 1) == 1);
    CHECK(d.one("avg(k)", 1) == doctest::Approx(1.0 / 3));
    // Three times 1e308 overflows a sum, but not the mean the incremental form keeps.
    CHECK(d.one("avg(k)", 10) == 1e308);
    CHECK(std::isinf(d.one("sum(k)", 10)));
    CHECK(d.one("avg_over_time(k{n=\"a\"}[20s])", 10) == doctest::Approx(5e307));
    d.src.add({{"__name__", "s"}}, pts({{1, 1e100}, {2, 1}, {3, -1e100}}));
    CHECK(d.one("sum_over_time(s[10s])", 3) == 1);
    CHECK(d.one("stddev(vector(7))", 1) == 0);
}

TEST_CASE("arithmetic, comparisons and bool between scalars and vectors")
{
    db d;
    d.src.add({{"__name__", "http"}, {"code", "200"}}, pts({{0, 1}}));
    d.src.add({{"__name__", "http"}, {"code", "500"}}, pts({{0, 3}}));
    using m = std::map<std::string, double>;
    CHECK(d.one("1 + 2 * 3", 1) == 7);
    CHECK(d.one("2 ^ 3 ^ 2", 1) == 512);
    CHECK(d.one("-2 ^ 2", 1) == -4);
    CHECK(d.one("10 % 3", 1) == 1);
    CHECK(d.one("-7 % 3", 1) == -1);
    CHECK(d.one("5 == bool 5", 1) == 1);
    CHECK(d.one("5 < bool 4", 1) == 0);
    CHECK(d.one("1 atan2 1", 1) == doctest::Approx(std::atan2(1, 1)));
    CHECK(d.one("0x10 + 010 + 1e1", 1) == 34);
    CHECK(std::isinf(d.one("Inf", 1)));
    CHECK(std::isnan(d.one("NaN", 1)));
    CHECK(d.one("-Inf", 1) < 0);
    CHECK(d.one("(1 + 2) * 3", 1) == 9);
    CHECK(d.at("http + 1", 1) == m{{"{code=\"200\"}", 2}, {"{code=\"500\"}", 4}});
    CHECK(d.at("2 * http", 1) == m{{"{code=\"200\"}", 2}, {"{code=\"500\"}", 6}});
    CHECK(d.at("http > 2", 1) == m{{"{__name__=\"http\",code=\"500\"}", 3}});
    CHECK(d.at("2 < http", 1) == m{{"{__name__=\"http\",code=\"500\"}", 3}});
    CHECK(d.at("http > bool 2", 1) == m{{"{code=\"200\"}", 0}, {"{code=\"500\"}", 1}});
    CHECK(d.at("-http", 1) == m{{"{code=\"200\"}", -1}, {"{code=\"500\"}", -3}});
    CHECK(d.at("http == http", 1).size() == 2);
    CHECK(d.at("http != http", 1).empty());
    CHECK(d.at("http / http", 1) == m{{"{code=\"200\"}", 1}, {"{code=\"500\"}", 1}});
    CHECK(d.at("http - 1 > 0", 1) == m{{"{code=\"500\"}", 2}});
}

TEST_CASE("vector matching: on, ignoring, group_left and group_right copy labels, and the matching errors")
{
    db d;
    d.src.add({{"__name__", "a"}, {"x", "1"}, {"y", "p"}}, pts({{0, 10}}));
    d.src.add({{"__name__", "a"}, {"x", "2"}, {"y", "p"}}, pts({{0, 20}}));
    d.src.add({{"__name__", "b"}, {"x", "1"}, {"y", "q"}}, pts({{0, 2}}));
    d.src.add({{"__name__", "b"}, {"x", "2"}, {"y", "q"}}, pts({{0, 4}}));
    using m = std::map<std::string, double>;
    CHECK(d.at("a / on(x) b", 1) == m{{"{x=\"1\"}", 5}, {"{x=\"2\"}", 5}});
    CHECK(d.at("a / ignoring(y) b", 1) == m{{"{x=\"1\"}", 5}, {"{x=\"2\"}", 5}});
    CHECK(d.at("a / b", 1).empty());
    CHECK(d.at("a > on(x) b", 1) == m{{"{x=\"1\"}", 10}, {"{x=\"2\"}", 20}});

    d.src.add({{"__name__", "req"}, {"inst", "a"}, {"path", "/x"}}, pts({{0, 10}}));
    d.src.add({{"__name__", "req"}, {"inst", "a"}, {"path", "/y"}}, pts({{0, 20}}));
    d.src.add({{"__name__", "info"}, {"inst", "a"}, {"version", "v1"}}, pts({{0, 1}}));
    CHECK(d.at("req * on(inst) group_left(version) info", 1) ==
          m{{"{inst=\"a\",path=\"/x\",version=\"v1\"}", 10}, {"{inst=\"a\",path=\"/y\",version=\"v1\"}", 20}});
    CHECK(d.at("info * on(inst) group_right(version) req", 1) ==
          m{{"{inst=\"a\",path=\"/x\",version=\"v1\"}", 10}, {"{inst=\"a\",path=\"/y\",version=\"v1\"}", 20}});
    CHECK(d.at("req > on(inst) group_left info", 1) ==
          m{{"{__name__=\"req\",inst=\"a\",path=\"/x\"}", 10}, {"{__name__=\"req\",inst=\"a\",path=\"/y\"}", 20}});
    // A comparison to the right of group_right keeps the one side's value under the many side's labels.
    CHECK(d.at("info < on(inst) group_right req", 1) ==
          m{{"{__name__=\"req\",inst=\"a\",path=\"/x\"}", 1}, {"{__name__=\"req\",inst=\"a\",path=\"/y\"}", 1}});

    std::string type;
    CHECK(contains(d.fails("req * on(inst) info", 1, &type), "multiple matches for labels: many-to-one matching must "
                                                             "be explicit (group_left/group_right)"));
    CHECK(type == "execution");
    CHECK(contains(d.fails("info + on(inst) group_left req", 1),
                   "found duplicate series for the match group {inst=\"a\"} on the right hand-side of the operation"));
    CHECK(contains(d.fails("info + on(inst) group_left req", 1), "many-to-many matching not allowed"));
}

TEST_CASE("and, or and unless match on all labels but the name unless on or ignoring say otherwise")
{
    db d;
    d.src.add({{"__name__", "a"}, {"x", "1"}}, pts({{0, 1}}));
    d.src.add({{"__name__", "a"}, {"x", "2"}}, pts({{0, 2}}));
    d.src.add({{"__name__", "b"}, {"x", "1"}}, pts({{0, 3}}));
    using m = std::map<std::string, double>;
    CHECK(d.at("a and b", 1) == m{{"{__name__=\"a\",x=\"1\"}", 1}});
    CHECK(d.at("a unless b", 1) == m{{"{__name__=\"a\",x=\"2\"}", 2}});
    CHECK(d.at("b or a", 1) == m{{"{__name__=\"b\",x=\"1\"}", 3}, {"{__name__=\"a\",x=\"2\"}", 2}});
    CHECK(d.at("a and on() b", 1).size() == 2);
    CHECK(d.at("a unless ignoring(x) b", 1).empty());
    CHECK(d.at("a or vector(5)", 1).size() == 3);
}

TEST_CASE("histogram_quantile interpolates in classic le buckets, forced monotonic")
{
    db d;
    for (auto [le, n] : std::vector<std::pair<std::string, double>>{{"0.1", 10}, {"0.5", 30}, {"1", 40}, {"+Inf", 50}})
        d.src.add({{"__name__", "lat_bucket"}, {"job", "a"}, {"le", le}}, pts({{0, n}}));
    CHECK(d.at("histogram_quantile(0.5, lat_bucket)", 1).begin()->first == "{job=\"a\"}");
    CHECK(d.one("histogram_quantile(0.5, lat_bucket)", 1) == doctest::Approx(0.4));
    CHECK(d.one("histogram_quantile(0.95, lat_bucket)", 1) == 1);
    CHECK(d.one("histogram_quantile(0.05, lat_bucket)", 1) == doctest::Approx(0.025));
    CHECK(d.one("histogram_quantile(0.5, sum by (le) (lat_bucket))", 1) == doctest::Approx(0.4));
    CHECK(std::isinf(d.one("histogram_quantile(1.5, lat_bucket)", 1)));
    CHECK(std::isnan(d.one("histogram_quantile(0.5, lat_bucket{le!=\"+Inf\"})", 1)));

    db f;
    for (auto [le, n] : std::vector<std::pair<std::string, double>>{{"1", 10}, {"2", 8}, {"+Inf", 12}})
        f.src.add({{"__name__", "h_bucket"}, {"le", le}}, pts({{0, n}}));
    CHECK(f.one("histogram_quantile(0.5, h_bucket)", 1) == doctest::Approx(0.6));
}

TEST_CASE("label_replace expands as Go's Regexp.Expand and label_join joins")
{
    db d;
    d.src.add({{"__name__", "up"}, {"job", "api"}, {"instance", "host:9090"}}, pts({{0, 1}}));
    auto labels = [&](std::string_view q) { return d.at(q, 1).begin()->first; };
    CHECK(labels("label_replace(up, \"host\", \"$1\", \"instance\", \"(.*):.*\")") ==
          "{__name__=\"up\",host=\"host\",instance=\"host:9090\",job=\"api\"}");
    CHECK(labels("label_replace(up, \"host\", \"$1x\", \"instance\", \"(.*):.*\")") ==
          "{__name__=\"up\",instance=\"host:9090\",job=\"api\"}");
    CHECK(labels("label_replace(up, \"host\", \"${1}x-$2\", \"instance\", \"(.*):(.*)\")") ==
          "{__name__=\"up\",host=\"hostx-9090\",instance=\"host:9090\",job=\"api\"}");
    CHECK(labels("label_replace(up, \"port\", \"$p\", \"instance\", \".*:(?P<p>[0-9]+)\")") ==
          "{__name__=\"up\",instance=\"host:9090\",job=\"api\",port=\"9090\"}");
    CHECK(labels("label_replace(up, \"host\", \"$1\", \"instance\", \"nomatch(.*)\")") ==
          "{__name__=\"up\",instance=\"host:9090\",job=\"api\"}");
    CHECK(labels("label_replace(up, \"job\", \"\", \"job\", \".*\")") == "{__name__=\"up\",instance=\"host:9090\"}");
    CHECK(labels("label_replace(up, \"foo\", \"bar$$\", \"none\", \"\")") ==
          "{__name__=\"up\",foo=\"bar$\",instance=\"host:9090\",job=\"api\"}");
    CHECK(labels("label_join(up, \"x\", \"-\", \"job\", \"instance\")") ==
          "{__name__=\"up\",instance=\"host:9090\",job=\"api\",x=\"api-host:9090\"}");
    CHECK(contains(d.fails("label_replace(up, \"1x\", \"\", \"job\", \".*\")", 1), "invalid destination label name"));
    CHECK(contains(d.fails("label_replace(up, \"x\", \"\", \"job\", \"(\")", 1), "invalid regular expression"));

    // Two series that become one labelset are Prometheus's error.
    d.src.add({{"__name__", "up"}, {"job", "db"}, {"instance", "host:9090"}}, pts({{0, 1}}));
    CHECK(contains(d.fails("label_replace(up, \"job\", \"\", \"job\", \".*\")", 1),
                   "vector cannot contain metrics with the same labelset"));
}

TEST_CASE("absent, scalar, vector, time and the date functions")
{
    db d;
    d.src.add({{"__name__", "up"}, {"job", "a"}}, pts({{0, 1}}));
    d.src.add({{"__name__", "up"}, {"job", "b"}}, pts({{0, 2}}));
    using m = std::map<std::string, double>;
    CHECK(d.at("absent(up)", 1).empty());
    CHECK(d.at("absent(nope{job=\"a\",env=~\"x\"})", 1) == m{{"{job=\"a\"}", 1}});
    CHECK(d.at("absent(nope{job=\"a\",job=\"b\"})", 1) == m{{"{}", 1}});
    CHECK(d.at("absent(sum(nope))", 1) == m{{"{}", 1}});
    CHECK(d.one("time()", 100) == 100);
    CHECK(d.one("scalar(vector(3))", 1) == 3);
    CHECK(std::isnan(d.one("scalar(up)", 1)));
    CHECK(d.one("scalar(up{job=\"b\"})", 1) == 2);
    CHECK(d.at("vector(time())", 7) == m{{"{}", 7}});
    CHECK(d.one("pi()", 1) == doctest::Approx(3.14159265358979));

    // 2024-02-29T13:45:00Z, a Thursday, day 60 of a leap year.
    const char* t = "vector(1709214300)";
    auto f = [&](const char* fn) { return d.one(std::string(fn) + "(" + t + ")", 1); };
    CHECK(f("year") == 2024);
    CHECK(f("month") == 2);
    CHECK(f("day_of_month") == 29);
    CHECK(f("day_of_week") == 4);
    CHECK(f("day_of_year") == 60);
    CHECK(f("days_in_month") == 29);
    CHECK(f("hour") == 13);
    CHECK(f("minute") == 45);
    CHECK(d.one("day_of_week()", 0) == 4);
    CHECK(d.one("days_in_month(vector(1700000000))", 1) == 30);
    CHECK(d.one("year(vector(-1))", 1) == 1969);
}

TEST_CASE("the mathematical functions, clamps and rounding drop the name")
{
    db d;
    d.src.add({{"__name__", "g"}}, pts({{0, -2.5}}));
    CHECK(d.one("abs(g)", 1) == 2.5);
    CHECK(d.one("ceil(g)", 1) == -2);
    CHECK(d.one("floor(g)", 1) == -3);
    CHECK(d.one("round(g)", 1) == -2);
    CHECK(d.one("round(g, 2)", 1) == -2);
    CHECK(d.one("round(vector(1.26), 0.1)", 1) == doctest::Approx(1.3));
    CHECK(d.one("sgn(g)", 1) == -1);
    CHECK(d.one("clamp(g, -1, 1)", 1) == -1);
    CHECK(d.one("clamp_min(g, 0)", 1) == 0);
    CHECK(d.one("clamp_max(g, -3)", 1) == -3);
    CHECK(d.at("clamp(g, 1, -1)", 1).empty());
    CHECK(std::isnan(d.one("clamp_min(vector(NaN), 0)", 1)));
    CHECK(d.one("exp(vector(0))", 1) == 1);
    CHECK(d.one("ln(vector(1))", 1) == 0);
    CHECK(d.one("log2(vector(8))", 1) == 3);
    CHECK(d.one("log10(vector(1000))", 1) == doctest::Approx(3));
    CHECK(d.one("sqrt(vector(16))", 1) == 4);
    CHECK(d.one("deg(vector(pi()))", 1) == doctest::Approx(180));
    CHECK(d.at("abs(g)", 1).begin()->first == "{}");
}

TEST_CASE("sort and sort_desc order an instant vector, NaN last")
{
    db d;
    d.src.add({{"__name__", "s"}, {"n", "a"}}, pts({{0, 3}}));
    d.src.add({{"__name__", "s"}, {"n", "b"}}, pts({{0, 1}}));
    d.src.add({{"__name__", "s"}, {"n", "c"}}, pts({{0, NAN}}));
    d.src.add({{"__name__", "s"}, {"n", "d"}}, pts({{0, 2}}));
    query_result r;
    query_error e;
    auto order = [&](std::string_view q) {
        REQUIRE(d.eng.eval_instant(q, sec, r, e));
        std::string o;
        for (const auto& s : r.series)
            o += label_value(s.labels, "n");
        return o;
    };
    CHECK(order("sort(s)") == "bdac");
    CHECK(order("sort_desc(s)") == "adbc");
}

TEST_CASE("a range query evaluates at start + k*step into a matrix sorted by labels")
{
    db d;
    std::vector<sample> s;
    for (int i = 0; i <= 40; ++i)
        s.push_back({i * 15 * sec, static_cast<double>(i * 15)});
    d.src.add({{"__name__", "c"}, {"j", "b"}}, s);
    d.src.add({{"__name__", "c"}, {"j", "a"}}, pts({{0, 1}, {300, 1}}));
    query_result r = d.range("rate(c[1m])", 60, 600, 60);
    REQUIRE(r.kind == result_kind::matrix);
    // a holds at most one sample in any window, so it has no rate at any step and no series in the matrix.
    REQUIRE(r.series.size() == 1);
    CHECK(label_value(r.series[0].labels, "j") == "b");
    CHECK(d.range("c", 60, 600, 60).series.size() == 2);
    const auto& b = r.series[0].points;
    REQUIRE(b.size() == 10);
    for (size_t k = 0; k < b.size(); ++k)
    {
        CHECK(b[k].t == (60 + static_cast<int64_t>(k) * 60) * sec);
        CHECK(b[k].v == doctest::Approx(1.0));
    }
    query_result sc = d.range("time()", 0, 30, 10);
    REQUIRE(sc.series.size() == 1);
    CHECK(sc.series[0].points.size() == 4);
    CHECK(sc.series[0].points[3].v == 30);

    // A series that comes and goes is one series in the matrix, its points where it had a value.
    db g;
    g.src.add({{"__name__", "x"}}, pts({{0, 1}, {1000, 2}}));
    query_result gap = g.range("x", 0, 1000, 100);
    REQUIRE(gap.series.size() == 1);
    CHECK(gap.series[0].points.size() == 4);

    query_error e;
    CHECK(!d.eng.eval_range("c[5m]", 0, 100 * sec, 10 * sec, r, e));
    CHECK(e.message == "invalid expression type \"range vector\" for range query, must be Scalar or instant Vector");
    CHECK(e.type == "bad_data");
    CHECK(!d.eng.eval_range("c", 0, 100 * sec, 0, r, e));
    CHECK(contains(e.message, "zero or negative query resolution step"));
    CHECK(!d.eng.eval_range("c", 0, 20000 * sec, sec, r, e));
    CHECK(contains(e.message, "exceeded maximum resolution of 11,000 points per timeseries"));
    CHECK(!d.eng.eval_range("c", 100 * sec, 0, sec, r, e));
    CHECK(contains(e.message, "end timestamp must not be before start time"));
}

TEST_CASE("an instant query answers a range selector with its raw samples and a string as a string")
{
    db d;
    d.src.add({{"__name__", "x"}}, pts({{10, 1}, {20, stale_nan()}, {30, 3}}));
    query_result r;
    query_error e;
    REQUIRE(d.eng.eval_instant("x[1m]", 30 * sec, r, e));
    CHECK(r.kind == result_kind::matrix);
    REQUIRE(r.series.size() == 1);
    CHECK(r.series[0].points.size() == 2);
    REQUIRE(d.eng.eval_instant("\"hello\\n\"", 30 * sec, r, e));
    CHECK(r.kind == result_kind::string);
    CHECK(r.str == "hello\n");
    REQUIRE(d.eng.eval_instant("`raw\\n`", 30 * sec, r, e));
    CHECK(r.str == "raw\\n");
}

TEST_CASE("metric names collide where Prometheus drops them")
{
    db d;
    d.src.add({{"__name__", "a"}, {"x", "1"}}, pts({{0, 1}, {30, 2}}));
    d.src.add({{"__name__", "b"}, {"x", "1"}}, pts({{0, 1}, {30, 2}}));
    std::string type;
    CHECK(d.fails("rate({__name__=~\"a|b\"}[1m])", 30, &type) == "vector cannot contain metrics with the same labelset");
    CHECK(type == "execution");
    CHECK(contains(d.fails("{__name__=~\"a|b\"} + 1", 30), "same labelset"));
    CHECK(d.at("last_over_time({__name__=~\"a|b\"}[1m])", 30).size() == 2);
    CHECK(d.at("{__name__=~\"a|b\"} > 1", 30).size() == 2);
}

TEST_CASE("parse errors carry a position and Prometheus's message")
{
    db d;
    query_error e;
    auto err = [&](std::string_view q) {
        CHECK_MESSAGE(!d.eng.check(q, e), q);
        CHECK(e.type == "bad_data");
        return e.message;
    };
    CHECK(err("sum(") == "1:5: parse error: unexpected end of input");
    CHECK(err("  # nothing") == "1:1: parse error: no expression found in input");
    CHECK(err("rate(x)") == "1:6: parse error: expected type range vector in call to function \"rate\", got instant "
                            "vector");
    CHECK(err("sum(x[5m])") == "1:5: parse error: expected type instant vector in aggregation expression, got range "
                               "vector");
    CHECK(err("{}") == "1:1: parse error: vector selector must contain at least one non-empty matcher");
    CHECK(err("{a=~\".*\"}") == "1:1: parse error: vector selector must contain at least one non-empty matcher");
    CHECK(err("x[1h:5m]") == "1:2: parse error: subqueries are not supported");
    CHECK(err("rate(x[5m])[1h:]") == "1:12: parse error: subqueries are not supported");
    CHECK(err("1 > 2") == "1:3: parse error: comparisons between scalars must use BOOL modifier");
    CHECK(err("nope(x)") == "1:1: parse error: unknown function with name \"nope\"");
    CHECK(contains(err("x @ 100"), "@ modifier is not supported"));
    CHECK(contains(err("x{a=~\"(\"}"), "1:6: parse error: error parsing regexp: missing closing )"));
    CHECK(contains(err("foo{__name__=\"bar\"}"), "metric name must not be set twice"));
    CHECK(contains(err("topk(x)"), "wrong number of arguments for aggregate expression provided, expected 2, got 1"));
    CHECK(contains(err("x[30m1h]"), "bad number or duration syntax"));
    CHECK(contains(err("x and 1"), "set operator \"and\" not allowed in binary scalar expression"));
    CHECK(contains(err("1 + on(a) x"), "vector matching only allowed between instant vectors"));
    CHECK(contains(err("x + bool y"), "bool modifier can only be used on comparison operators"));
    CHECK(contains(err("round()"), "expected at least 1 argument(s) in call to \"round\", got 0"));
    CHECK(contains(err("abs(x, y)"), "expected 1 argument(s) in call to \"abs\", got 2"));
    CHECK(contains(err("x offset 5m[1m]"), "no offset modifiers allowed before range"));
    CHECK(contains(err("x offset 1m offset 2m"), "offset may not be set multiple times"));
    CHECK(contains(err("x[0s]"), "duration must be greater than 0"));
    CHECK(contains(err("x[293y]"), "duration out of range"));
    CHECK(d.eng.check("x[292y] offset 292y", e));
    CHECK(d.eng.check("x[300]", e));
    CHECK(contains(err("\"unterminated"), "unterminated quoted string"));
    CHECK(err("sum(x)\n  + ") == "2:5: parse error: unexpected end of input");
    CHECK(contains(err("(x)[5m]"), "ranges only allowed for vector selectors"));
    CHECK(contains(err("x == bool on(a) group_left(a) y"), "must not occur in ON and GROUP clause at once"));
    CHECK(contains(err("count_values(1, x)"), "expected type string in aggregation parameter, got scalar"));
    CHECK(d.eng.check("rate(x[1h30m]) + x offset -5m # a comment", e));
    CHECK(d.eng.check("sum by (job) (rate(x{job=~\"a|b\",env!=\"\"}[5ms])) / ignoring(a) group_left sum(y)", e));
    CHECK(d.eng.check("x{\"label.with.dots\"=\"v\"}", e));
    d.eng.limits().max_query_length = 10;
    CHECK(contains(err("sum(rate(x[5m]))"), "exceeds the limit"));
    int64_t ms = 0;
    CHECK((parse_duration("1h30m", ms) && ms == 5400000));
    CHECK((parse_duration("1y", ms) && ms == 365LL * 86400000));
    CHECK((parse_duration("250ms", ms) && ms == 250));
    CHECK(!parse_duration("1.5h", ms));
    CHECK(!parse_duration("5m1h", ms));
}

TEST_CASE("the samples budget and the deadline end a query with Prometheus's errors")
{
    db d;
    std::vector<sample> s;
    for (int i = 0; i < 1000; ++i)
        s.push_back({i * sec, static_cast<double>(i)});
    d.src.add({{"__name__", "x"}}, s);
    d.eng.limits().max_samples = 100;
    std::string type;
    CHECK(d.fails("sum_over_time(x[1000s])", 999, &type) ==
          "query processing would load too many samples into memory in query execution");
    CHECK(type == "execution");
    d.eng.limits().max_samples = 50'000'000;
    CHECK(d.one("sum_over_time(x[1000s])", 999) == 999.0 * 1000 / 2);
    d.eng.limits().timeout_ms = 0;
    CHECK(d.fails("x", 999, &type) == "query timed out in expression evaluation");
    CHECK(type == "timeout");
}

TEST_CASE("the JSON data part is Prometheus's, floats and timestamps formatted as Go writes them")
{
    std::string out;
    auto v = [&](double x) {
        out.clear();
        format_value(x, out);
        return out;
    };
    CHECK(v(1) == "1");
    CHECK(v(0.1) == "0.1");
    CHECK(v(-0.0) == "-0");
    CHECK(v(1e-7) == "1e-07");
    CHECK(v(0.000001) == "0.000001");
    CHECK(v(1e21) == "1e+21");
    CHECK(v(1.2345678901234568e20) == "123456789012345680000");
    CHECK(v(NAN) == "NaN");
    CHECK(v(INFINITY) == "+Inf");
    CHECK(v(-INFINITY) == "-Inf");
    CHECK(v(1.0 / 3) == "0.3333333333333333");
    CHECK(v(-123.456) == "-123.456");
    CHECK(v(1e20) == "100000000000000000000");
    CHECK(v(12345.678e-10) == "0.0000012345678");
    CHECK(v(-2.5e-7) == "-2.5e-07");
    CHECK(v(5e-324) == "5e-324");
    CHECK(v(1.7976931348623157e308) == "1.7976931348623157e+308");
    auto ts = [&](int64_t t) {
        out.clear();
        format_timestamp(t, out);
        return out;
    };
    CHECK(ts(1435781451781) == "1435781451.781");
    CHECK(ts(1435781451780) == "1435781451.780");
    CHECK(ts(1005) == "1.005");
    CHECK(ts(1000) == "1");
    CHECK(ts(-1500) == "-1.500");

    db d;
    d.src.add({{"__name__", "up"}, {"job", "a\"b"}}, pts({{0, 1}, {10, 2}}));
    query_result r;
    query_error e;
    REQUIRE(d.eng.eval_instant("up", 10500, r, e));
    out.clear();
    render_json(r, out);
    CHECK(out == R"({"resultType":"vector","result":[{"metric":{"__name__":"up","job":"a\"b"},"value":[10.500,"2"]}]})");
    REQUIRE(d.eng.eval_range("up", 0, 10 * sec, 5 * sec, r, e));
    out.clear();
    render_json(r, out);
    CHECK(out == R"({"resultType":"matrix","result":[{"metric":{"__name__":"up","job":"a\"b"},"values":[[0,"1"],[5,"1"],[10,"2"]]}]})");
    REQUIRE(d.eng.eval_instant("1 / 0", 2000, r, e));
    out.clear();
    render_json(r, out);
    CHECK(out == R"({"resultType":"scalar","result":[2,"+Inf"]})");
    REQUIRE(d.eng.eval_instant("\"s\"", 2000, r, e));
    out.clear();
    render_json(r, out);
    CHECK(out == R"({"resultType":"string","result":[2,"s"]})");
    REQUIRE(d.eng.eval_instant("\"a\\xffb\"", 2000, r, e));
    out.clear();
    render_json(r, out);
    CHECK(out == "{\"resultType\":\"string\",\"result\":[2,\"a\xEF\xBF\xBD" "b\"]}");
    REQUIRE(d.eng.eval_instant("nope", 2000, r, e));
    out.clear();
    render_json(r, out);
    CHECK(out == R"({"resultType":"vector","result":[]})");
}

TEST_CASE("the regex engine reads RE2 syntax and matches whole strings")
{
    regex r;
    std::string why;
    auto m = [&](std::string_view p, std::string_view s) {
        REQUIRE_MESSAGE(r.compile(p, why), p << ": " << why);
        return r.matches(s);
    };
    CHECK(m("abc", "abc"));
    CHECK(!m("abc", "abcd"));
    CHECK(m("a.c", "a\nc"));
    CHECK(m("a|b|c", "b"));
    CHECK(m("(a|b)*c", "ababc"));
    CHECK(!m("(a|b)*c", "abab"));
    CHECK(m("[a-c]+[^0-9]", "abcx"));
    CHECK(!m("[a-c]+[^0-9]", "abc1"));
    CHECK(m("\\d{3}-\\d{2,}", "123-4567"));
    CHECK(!m("\\d{3}-\\d{2,}", "123-4"));
    CHECK(m("x{2,3}", "xxx"));
    CHECK(!m("x{2,3}", "xxxx"));
    CHECK(m("(?i)HeLLo", "hello"));
    CHECK(m("[[:alpha:]]+", "abcXYZ"));
    CHECK(m("\\w+\\s\\W", "ab_9 !"));
    CHECK(m("a{,2}", "a{,2}"));
    CHECK(m("é.", "éü"));
    CHECK(m(".", "ü"));
    CHECK(!m("..", "ü"));
    CHECK(m("foo.*", "foobar"));
    CHECK(m(".*bar", "foobar"));
    CHECK(m(".*ob.*", "foobar"));
    CHECK(m("", ""));
    CHECK(m("(?:a|)b", "b"));
    CHECK(m("\\.\\*\\Q.+\\E", ".*.+"));
    CHECK(m("^abc$", "abc"));
    CHECK(m("a\\bb|a b", "a b"));
    CHECK(!r.compile("(", why));
    CHECK(contains(why, "missing closing )"));
    CHECK(!r.compile("a**", why));
    CHECK(!r.compile("*a", why));
    CHECK(!r.compile("[z-a]", why));
    CHECK(!r.compile("x{1001}", why));
    CHECK(!r.compile("\\8", why));
    CHECK(!r.compile("(?P<n>a)(?P<n>b)", why));
    std::vector<int> g;
    REQUIRE(r.compile("(a+)(b+)?(c)", why));
    REQUIRE(r.matches("aac", g));
    CHECK(g == std::vector<int>{0, 3, 0, 2, -1, -1, 2, 3});
    REQUIRE(r.compile("(a*)(a*)", why));
    REQUIRE(r.matches("aaa", g));
    CHECK(g == std::vector<int>{0, 3, 0, 3, 3, 3});
    REQUIRE(r.compile("(a*?)(a*)", why));
    REQUIRE(r.matches("aaa", g));
    CHECK(g == std::vector<int>{0, 3, 0, 0, 0, 3});
    // Linear time: thirty nested optionals against thirty letters would take 2^30 steps backtracking.
    std::string p, s(30, 'a');
    for (int i = 0; i < 30; ++i)
        p += "a?";
    p += s;
    REQUIRE(r.compile(p, why));
    CHECK(r.matches(s));
    CHECK(r.matches_empty() == false);
    REQUIRE(r.compile(".*", why));
    CHECK(r.matches_empty());
}

namespace
{

// Increments over [from, to), from the last sample before it, a reset counted as the counter starting from zero.
double brute_increase(const std::vector<sample>& s, int64_t from, int64_t to, bool& any)
{
    bool have = false;
    double prev = 0, inc = 0;
    any = false;
    for (const auto& x : s)
    {
        if (x.t >= to)
            break;
        if (x.t >= from)
        {
            any = true;
            if (have)
                inc += x.v >= prev ? x.v - prev : x.v;
        }
        prev = x.v;
        have = true;
    }
    return inc;
}

struct tiered
{
    fake_source src;
    query_engine with{src};
    query_engine without{src};
    std::vector<uint32_t> counters, gauges;

    tiered()
    {
        without.limits().use_tiers = false;
        src.tiers = {300 * sec, 3600 * sec};
        for (int i = 0; i < 3; ++i)
        {
            std::vector<sample> c, g;
            double v = 0;
            // Every 15 s, 3 s past the minute's quarter, so no sample lies on a step's edge.
            for (int j = 0; j < 2 * 5760; ++j)
            {
                v += j % 7 + i;
                if (j % 1000 == 999)
                    v = j % 5;
                c.push_back({3 * sec + j * 15 * sec, v});
                g.push_back({3 * sec + j * 15 * sec, static_cast<double>((j * 37 + i * 11) % 101) - 50});
            }
            counters.push_back(src.add({{"__name__", "c"}, {"i", std::to_string(i)}}, c));
            gauges.push_back(src.add({{"__name__", "g"}, {"i", std::to_string(i)}}, g));
        }
    }

    query_result run(query_engine& e, std::string_view q, int64_t start, int64_t end, int64_t step)
    {
        query_result r;
        query_error err;
        REQUIRE_MESSAGE(e.eval_range(q, start, end, step, r, err), std::string(q) << ": " << err.message);
        return r;
    }
};

}   // namespace

TEST_CASE("the planner reads a tier where window and step are whole steps of it, and it equals brute force")
{
    tiered t;
    const int64_t h = 3600 * sec;
    for (const char* f : {"avg_over_time", "min_over_time", "max_over_time", "sum_over_time", "count_over_time",
                          "last_over_time"})
    {
        const std::string q = std::string(f) + "(g[1h])";
        const auto a = t.run(t.with, q, 12 * h, 36 * h, h);
        CHECK_MESSAGE(t.with.last_stats().tier_selectors == 1, q);
        CHECK(t.with.last_stats().raw_samples == 0);
        const auto b = t.run(t.without, q, 12 * h, 36 * h, h);
        CHECK(t.without.last_stats().tier_selectors == 0);
        REQUIRE(a.series.size() == 3);
        REQUIRE(b.series.size() == 3);
        for (size_t i = 0; i < 3; ++i)
        {
            CHECK(a.series[i].labels == b.series[i].labels);
            REQUIRE(a.series[i].points.size() == 25);
            for (size_t k = 0; k < 25; ++k)
                CHECK_MESSAGE(a.series[i].points[k].v == b.series[i].points[k].v, q << " step " << k);
        }
    }

    // An instant selector at hour steps is the tier's last, the same sample the lookback finds.
    {
        const auto a = t.run(t.with, "g", 12 * h, 36 * h, h);
        CHECK(t.with.last_stats().tier_selectors == 1);
        const auto b = t.run(t.without, "g", 12 * h, 36 * h, h);
        REQUIRE(a.series.size() == b.series.size());
        for (size_t i = 0; i < a.series.size(); ++i)
        {
            REQUIRE(a.series[i].points.size() == b.series[i].points.size());
            for (size_t k = 0; k < a.series[i].points.size(); ++k)
                CHECK(a.series[i].points[k].v == b.series[i].points[k].v);
        }
    }

    // rate and increase from `inc` are the increments of [T - 1h, T) over the window, resets folded in.
    auto check_rate = [&](std::string_view q, int64_t step, int64_t range, bool increase, int64_t stretched) {
        const auto a = t.run(t.with, q, 12 * h, 36 * h, step);
        CHECK_MESSAGE(t.with.last_stats().tier_selectors == 1, q);
        REQUIRE(a.series.size() == 3);
        for (size_t i = 0; i < 3; ++i)
        {
            const auto& raw = t.src.series[t.counters[i]].samples;
            for (const auto& p : a.series[i].points)
            {
                bool any = false;
                const double inc = brute_increase(raw, p.t - range, p.t, any);
                const double want = increase ? inc * static_cast<double>(stretched) / static_cast<double>(range)
                                             : inc / (static_cast<double>(range) / 1000);
                CHECK_MESSAGE(p.v == doctest::Approx(want).epsilon(1e-12), q << " at " << p.t);
            }
            CHECK(a.series[i].points.size() == static_cast<size_t>(24 * h / step + 1));
        }
    };
    check_rate("rate(c[1h])", h, h, false, h);
    check_rate("increase(c[1h])", h, h, true, h);
    // A half-hour step reads the five-minute tier, the coarsest no coarser than it.
    check_rate("rate(c[1h])", h / 2, h, false, h);
    // Grafana's $__rate_interval, one scrape past the step, reads the whole hour.
    check_rate("rate(c[1h15s])", h, h, false, h);
    check_rate("increase(c[1h15s])", h, h, true, h + 15 * sec);

    // What a tier cannot answer exactly is read raw.
    t.run(t.with, "sum_over_time(g[1h15s])", 12 * h, 36 * h, h);
    CHECK(t.with.last_stats().tier_selectors == 0);
    t.run(t.with, "rate(c[1h])", 12 * h + sec, 36 * h + sec, h);
    CHECK(t.with.last_stats().tier_selectors == 0);
    t.run(t.with, "irate(c[1h])", 12 * h, 36 * h, h);
    CHECK(t.with.last_stats().tier_selectors == 0);
    t.run(t.with, "rate(c[1h])", 12 * h, 36 * h, 90 * 60 * sec);
    CHECK(t.with.last_stats().tier_selectors == 1);
    t.run(t.with, "rate(c[7m])", 12 * h, 36 * h, h);
    CHECK(t.with.last_stats().tier_selectors == 0);
    t.src.tiers_from = 20 * h;
    t.run(t.with, "rate(c[1h])", 12 * h, 36 * h, h);
    CHECK(t.with.last_stats().tier_selectors == 0);
    t.src.tiers_from = std::numeric_limits<int64_t>::min();

    // With offset the evaluation times minus the offset must lie on the tier's grid.
    t.run(t.with, "rate(c[1h] offset 1h)", 12 * h, 36 * h, h);
    CHECK(t.with.last_stats().tier_selectors == 1);
    t.run(t.with, "rate(c[1h] offset 1m)", 12 * h, 36 * h, h);
    CHECK(t.with.last_stats().tier_selectors == 0);
}

namespace
{

// Counters of slope id+1 per second sampled every ten seconds, generated on demand, with tiers computed in closed form.
class synthetic_source : public series_source
{
public:
    synthetic_source(uint32_t n, int64_t from, int64_t to) : m_from(from), m_to(to)
    {
        for (uint32_t i = 0; i < n; ++i)
            m_labels.push_back({{"__name__", "x"}, {"i", std::to_string(i)}});
    }
    void select(std::span<const matcher>, int64_t, int64_t, std::vector<uint32_t>& out) override
    {
        for (uint32_t i = 0; i < m_labels.size(); ++i)
            out.push_back(i);
    }
    const label_set& labels(uint32_t id) const override { return m_labels[id]; }
    void samples(uint32_t id, int64_t mint, int64_t maxt, std::vector<sample>& out) override
    {
        int64_t t = std::max(mint, m_from);
        t += (every - t % every) % every;
        for (; t <= std::min(maxt, m_to); t += every)
            out.push_back({t, static_cast<double>(id + 1) * static_cast<double>(t) / 1000});
    }
    int64_t tier_for(int64_t, int64_t resolution) const override
    {
        return resolution >= 3600000 ? 3600000 : resolution >= 300000 ? 300000 : 0;
    }
    void aggregates(uint32_t id, int64_t step, int64_t mint, int64_t maxt, std::vector<agg_point>& out) override
    {
        const double slope = id + 1;
        for (int64_t t = (mint / step + 1) * step; t <= std::min(maxt, m_to); t += step)
        {
            const double first = slope * static_cast<double>(t - step) / 1000;
            const double last = slope * static_cast<double>(t - every) / 1000;
            const double n = static_cast<double>(step / every);
            out.push_back({t, first, last, (first + last) / 2 * n, n, last, slope * static_cast<double>(step) / 1000});
        }
    }
    void label_names(std::vector<std::string>&) const override {}
    void label_values(std::string_view, std::vector<std::string>&) const override {}
    metric_type type_of(std::string_view) const override { return metric_type::counter; }
    std::string_view help_of(std::string_view) const override { return {}; }

    static constexpr int64_t every = 10000;

private:
    int64_t m_from, m_to;
    std::vector<label_set> m_labels;
};

}   // namespace

TEST_CASE("perf: a 30-day rate(x[5m]) at step 1h over 100 series, raw against the tier")
{
    const int64_t day = 86400 * sec, end = 1'700'000'000LL * sec / 3600000 * 3600000, start = end - 30 * day;
    synthetic_source src(100, start - day, end);
    query_engine raw(src), tier(src);
    raw.limits().use_tiers = false;
    auto timed = [](query_engine& e, std::string_view q, int64_t s, int64_t en, int64_t step, query_result& r) {
        query_error err;
        double best = 1e30;
        for (int i = 0; i < 3; ++i)
        {
            const auto t0 = std::chrono::steady_clock::now();
            REQUIRE_MESSAGE(e.eval_range(q, s, en, step, r, err), err.message);
            best = std::min(best, std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count());
        }
        return best;
    };
    query_result a, b;
    const double t_raw = timed(raw, "rate(x[5m])", start, end, 3600 * sec, a);
    const auto raw_stats = raw.last_stats();
    const double t_tier = timed(tier, "rate(x[5m])", start, end, 3600 * sec, b);
    const auto tier_stats = tier.last_stats();
    CHECK(tier_stats.tier_selectors == 1);
    REQUIRE(a.series.size() == 100);
    REQUIRE(b.series.size() == 100);
    for (size_t i = 0; i < 100; ++i)
    {
        REQUIRE(a.series[i].points.size() == 721);
        REQUIRE(b.series[i].points.size() == 721);
        CHECK(a.series[i].points[360].v == doctest::Approx(b.series[i].points[360].v));
    }
    query_result c, dd;
    const double t_raw_dense = timed(raw, "avg_over_time(x[1h])", start, end, 3600 * sec, c);
    const auto dense_stats = raw.last_stats();
    const double t_tier_dense = timed(tier, "avg_over_time(x[1h])", start, end, 3600 * sec, dd);
    std::printf("perf: rate(x[5m]) 30d step 1h 100 series: raw %.2f ms (%llu samples), tier %.2f ms (%llu points)\n",
                t_raw, static_cast<unsigned long long>(raw_stats.raw_samples), t_tier,
                static_cast<unsigned long long>(tier_stats.tier_points));
    std::printf("perf: avg_over_time(x[1h]) 30d step 1h 100 series: raw %.2f ms (%llu samples), tier %.2f ms\n",
                t_raw_dense, static_cast<unsigned long long>(dense_stats.raw_samples), t_tier_dense);
}
