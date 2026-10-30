#pragma once
// PromQL over a series_source with Prometheus 3's semantics, a planner that reads a coarser tier where a window and a
// step allow it, and the `data` part of the Prometheus HTTP API's answer.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "metrics_types.h"

namespace socketley::metrics
{

struct query_limits
{
    // Samples and result points held at once, as Prometheus's --query.max-samples.
    uint64_t max_samples{50'000'000};
    int64_t  timeout_ms{120'000};
    size_t   max_query_length{64 * 1024};
    int64_t  lookback_ms{300'000};
    // Prometheus's cap on (end - start) / step.
    int64_t  max_points_per_series{11'000};
    // Off reads raw samples only, which the tests use as the reference for the tiers: a tier answers as raw does but
    // that it holds no NaN, so a NaN sample and a staleness marker take no part in what it answers.
    bool     use_tiers{true};
};

struct query_error
{
    // The Prometheus API's errorType: bad_data, execution or timeout.
    std::string type;
    std::string message;
    // The byte offset in the query a parse error is at, or -1.
    int64_t position{-1};
};

enum class result_kind : uint8_t { scalar, string, vector, matrix };

struct result_series
{
    label_set labels;
    // One point for an instant query's vector, every step's for a matrix.
    std::vector<sample> points;
};

struct query_result
{
    result_kind kind{result_kind::vector};
    // A scalar's or a string's evaluation time and its value.
    int64_t     t{0};
    double      scalar{0};
    std::string str;
    std::vector<result_series> series;
};

// How a query was served, for the tests and a slow-query log.
struct query_stats
{
    uint64_t raw_samples{0};
    uint64_t tier_points{0};
    uint32_t tier_selectors{0};
    uint32_t raw_selectors{0};
};

struct expr_node;

// A query parsed once, for a caller that evaluates it again and again, as a rule does.
class prepared_query
{
public:
    prepared_query();
    ~prepared_query();
    prepared_query(prepared_query&&) noexcept;
    prepared_query& operator=(prepared_query&&) noexcept;

    bool empty() const { return !m_expr; }
    // Whether it answers an instant vector or a scalar, which is all a range query and a rule take.
    bool is_instant_value() const;

private:
    friend class query_engine;
    std::unique_ptr<expr_node> m_expr;
};

class query_engine
{
public:
    explicit query_engine(series_source& source, query_limits limits = {});
    ~query_engine();
    query_engine(const query_engine&) = delete;
    query_engine& operator=(const query_engine&) = delete;

    // The query at `t_ms`: a vector, a scalar, a string, or for a range selector at the top a matrix.
    bool eval_instant(std::string_view query, int64_t t_ms, query_result& out, query_error& err);
    // The query at start + k*step up to end, every one in milliseconds: always a matrix.
    bool eval_range(std::string_view query, int64_t start_ms, int64_t end_ms, int64_t step_ms, query_result& out,
                    query_error& err);

    // Whether a query parses, with Prometheus's error where it does not.
    bool check(std::string_view query, query_error& err) const;

    // The query parsed into `out`, false with Prometheus's error where it does not parse.
    bool prepare(std::string_view query, prepared_query& out, query_error& err) const;
    // A prepared query at `t_ms`, as eval_instant() of its text answers.
    bool eval_instant(const prepared_query& query, int64_t t_ms, query_result& out, query_error& err);

    const query_stats& last_stats() const { return m_stats; }
    query_limits& limits() { return m_limits; }

private:
    struct scratch;
    series_source& m_source;
    query_limits m_limits;
    query_stats m_stats;
    std::unique_ptr<scratch> m_scratch;
};

// The `data` member of a Prometheus API answer, `{"resultType":...,"result":...}`, appended to `out`.
void render_json(const query_result& r, std::string& out);

// A sample value as Prometheus writes it: +Inf, -Inf, NaN, else Go's shortest 'f' form, or 'e' outside [1e-6, 1e21).
void format_value(double v, std::string& out);
// Milliseconds as Prometheus writes a timestamp: seconds with the milliseconds after a point when there are any.
void format_timestamp(int64_t t_ms, std::string& out);

// A Prometheus duration such as 1h30m or 500ms, false when it is not one.
bool parse_duration(std::string_view s, int64_t& ms);

}   // namespace socketley::metrics
