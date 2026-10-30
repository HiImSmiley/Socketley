// Fuzz target: the metrics runtime's PromQL parser and evaluator (socketley/runtime/metrics/metrics_query) over a
// small vector-backed store with tiers.
//
// The first byte chooses: bit 0 a range query rather than an instant one, bits 1-2 its step, bit 3 the tiers off,
// bit 4 a tight samples budget.  The rest is the query.
//
// Properties checked, beyond "did it crash":
//   * a failure names a Prometheus errorType and a message, a parse error a position inside the query;
//   * check() and eval agree on whether the query parses;
//   * a result's labels are sorted, unique and non-empty, no two series share a labelset, and no point is a hole;
//   * a range query's points lie on start + k*step, ascending;
//   * the JSON rendered is a document a strict reader takes;
//   * evaluating again gives the same JSON, so no buffer reused across queries leaks into the next.
#include "fuzz_common.h"
#include "runtime/metrics/metrics_query.h"
#include "metrics_fake_source.h"
#include "shared/json/json_doc.h"

#include <bit>
#include <cmath>
#include <string>

namespace m = socketley::metrics;

namespace {

m::testing::fake_source& store()
{
    static m::testing::fake_source s = [] {
        m::testing::fake_source f;
        f.tiers = {300'000, 3'600'000};
        const int64_t step = 15'000;
        for (int i = 0; i < 3; ++i)
        {
            std::vector<m::sample> c, g, b1, b2, binf;
            double v = 0;
            for (int j = 0; j < 600; ++j)
            {
                const int64_t t = 3'000 + j * step;
                v += (j * 7 + i) % 5;
                if (j == 300 + i)
                    v = 1;
                c.push_back({t, v});
                double gv = std::sin(j * 0.1 + i) * 100;
                if (j == 50)
                    gv = NAN;
                if (j == 51)
                    gv = INFINITY;
                if (j == 400 + i)
                    gv = m::stale_nan();
                g.push_back({t, gv});
                b1.push_back({t, static_cast<double>(j)});
                b2.push_back({t, static_cast<double>(j * 2)});
                binf.push_back({t, static_cast<double>(j * 3)});
            }
            const std::string inst = "host" + std::to_string(i);
            const std::string job = i == 2 ? "db" : "api";
            f.add({{"__name__", "requests_total"}, {"instance", inst}, {"job", job}}, c);
            f.add({{"__name__", "temp"}, {"instance", inst}, {"job", job}}, g);
            f.add({{"__name__", "lat_bucket"}, {"instance", inst}, {"le", "0.1"}}, b1);
            f.add({{"__name__", "lat_bucket"}, {"instance", inst}, {"le", "1"}}, b2);
            f.add({{"__name__", "lat_bucket"}, {"instance", inst}, {"le", "+Inf"}}, binf);
        }
        f.add({{"__name__", "info"}, {"instance", "host0"}, {"version", "1.2"}}, {{0, 1}, {9'000'000, 1}});
        f.add({{"__name__", "up"}, {"instance", "host1"}}, {{3'000, 1}, {3'600'000, 0}, {3'700'000, m::stale_nan()}});
        return f;
    }();
    return s;
}

void check_result(const m::query_result& r, bool range, int64_t start, int64_t end, int64_t step)
{
    for (size_t i = 0; i < r.series.size(); ++i)
    {
        const auto& s = r.series[i];
        for (size_t k = 0; k < s.labels.size(); ++k)
        {
            FUZZ_CHECK(!s.labels[k].value.empty(), "a label with an empty value");
            FUZZ_CHECK(k == 0 || s.labels[k - 1].name < s.labels[k].name, "labels unsorted or a name twice");
        }
        for (size_t j = 0; j < i; ++j)
            FUZZ_CHECK(!(r.series[j].labels == s.labels), "two series share a labelset");
        for (size_t k = 0; k < s.points.size(); ++k)
        {
            const auto& p = s.points[k];
            FUZZ_CHECK(std::bit_cast<uint64_t>(p.v) != 0x7ff0000000000001ull, "a hole reached the result");
            if (range)
            {
                FUZZ_CHECK(p.t >= start && p.t <= end && (p.t - start) % step == 0, "a point off the step grid");
                FUZZ_CHECK(k == 0 || s.points[k - 1].t < p.t, "points out of order");
            }
        }
        if (range || r.kind == m::result_kind::vector)
            FUZZ_CHECK(!s.points.empty(), "a series without points");
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = fuzz::never_null(data);
    fuzz::set_current(data, size);
    if (size < 1)
        return 0;
    const uint8_t mode = data[0];
    std::string_view q(reinterpret_cast<const char*>(data + 1), size - 1);
    // Bit 5 spells the query from fragments, one per byte, so mutations reach the evaluator and not only the lexer.
    static constexpr std::string_view words[] = {
        "requests_total", "temp", "lat_bucket", "up", "info", "(", ")", "[5m]", "[1h]", "[15s]", "{job=\"api\"}",
        "{instance=~\"host.*\"}", "rate(", "irate(", "increase(", "delta(", "deriv(", "avg_over_time(",
        "max_over_time(", "last_over_time(", "quantile_over_time(0.5,", "predict_linear(", "sum", "avg", "max",
        "count", "topk(2,", "bottomk(1,", "quantile(0.9,", "count_values(\"v\",", "stddev", "group", " by (job) ",
        " without (instance) ", " + ", " - ", " * ", " / ", " % ", " ^ ", " > ", " < bool ", " == ", " and ", " or ",
        " unless ", " on(instance) ", " ignoring(job) ", " group_left(version) ", " group_right ", ",", "1", "0.5",
        "-", "NaN", "Inf", " offset 5m", " offset -1h", "histogram_quantile(0.9,", "label_replace(", "\"dst\",",
        "\"$1\",", "\"instance\",", "\"host(.*)\")", "label_join(", "absent(", "absent_over_time(", "scalar(",
        "vector(", "time()", "timestamp(", "sort_desc(", "clamp(", "abs(", "round(", "hour(", "changes(", "resets(",
    };
    std::string spelled;
    if (mode & 32)
    {
        for (size_t i = 1; i < size; ++i)
            spelled += words[data[i] % std::size(words)];
        q = spelled;
    }

    m::query_limits lim;
    lim.use_tiers = !(mode & 8);
    lim.max_samples = (mode & 16) ? 500 : 2'000'000;
    lim.timeout_ms = 5'000;
    lim.max_query_length = 4096;
    m::query_engine eng(store(), lim);

    static constexpr int64_t steps[] = {15'000, 60'000, 300'000, 3'600'000};
    const bool range = mode & 1;
    const int64_t step = steps[(mode >> 1) & 3];
    const int64_t start = 0, end = 2 * 3'600'000, t = 3'600'000;

    m::query_error perr;
    const bool parses = eng.check(q, perr);
    if (!parses)
    {
        FUZZ_CHECK(perr.type == "bad_data", "a parse error that is not bad_data");
        FUZZ_CHECK(perr.position <= static_cast<int64_t>(q.size()), "a parse error past the query");
    }

    m::query_result r;
    m::query_error err;
    const bool ok = range ? eng.eval_range(q, start, end, step, r, err) : eng.eval_instant(q, t, r, err);
    if (!parses)
        FUZZ_CHECK(!ok && err.type == "bad_data", "eval took a query check refused");
    if (!ok)
    {
        FUZZ_CHECK(err.type == "bad_data" || err.type == "execution" || err.type == "timeout", "an unknown errorType");
        FUZZ_CHECK(!err.message.empty(), "an error without a message");
        return 0;
    }
    if (range)
        FUZZ_CHECK(r.kind == m::result_kind::matrix, "a range query that is no matrix");
    check_result(r, range, start, end, step);

    std::string json;
    m::render_json(r, json);
    socketley::json::jvalue doc;
    FUZZ_CHECK(socketley::json::json_reader(json).document(doc), "rendered JSON a strict reader refuses");

    m::query_result r2;
    m::query_error err2;
    const bool ok2 = range ? eng.eval_range(q, start, end, step, r2, err2) : eng.eval_instant(q, t, r2, err2);
    if (ok2)
    {
        std::string json2;
        m::render_json(r2, json2);
        FUZZ_CHECK(json == json2, "the same query answered twice differently");
    }
    else
        FUZZ_CHECK(err2.type == "timeout", "the same query failed the second time only");
    return 0;
}
