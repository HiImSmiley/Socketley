#pragma once
// The evaluator of a parsed query: every node's value at every step at once, a series' samples read once per query.
#include <bit>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "metrics_promql.h"

namespace socketley::metrics
{

// The value of a series at a step where it has none: a signalling NaN no arithmetic and no sample produces.
inline constexpr uint64_t hole_bits = 0x7ff0000000000001ull;
inline double hole() { return std::bit_cast<double>(hole_bits); }
inline bool   is_hole(double v) { return std::bit_cast<uint64_t>(v) == hole_bits; }

struct vseries
{
    label_set labels;
    std::vector<double> v;
};

struct value
{
    value_type type{value_type::none};
    std::vector<double> s;
    std::string str;
    std::vector<vseries> vec;
    // An instant query's order from sort() or sort_desc(): 1 ascending, -1 descending.
    int sort{0};
};

struct eval_fail
{
    const char* type;
    std::string msg;
};

// The buffers a query reuses for every series and every step.
struct eval_scratch
{
    std::vector<sample> samples;
    std::vector<agg_point> points;
    std::vector<double> row;
    std::vector<double> qbuf;
};

int  compare_labels(const label_set& a, const label_set& b);
// Go's strconv.FormatFloat with the shortest digits, 'e' when `exponent` and 'f' otherwise.
void format_go_float(double v, bool exponent, std::string& out);
void drop_name(label_set& ls);
void set_label(label_set& ls, std::string_view name, std::string_view value);

class evaluator
{
public:
    evaluator(series_source& src, const query_limits& lim, query_stats& stats, eval_scratch& sc, int64_t start,
              int64_t end, int64_t step);

    value  eval(const expr_node& e);
    // A range selector at the top of an instant query, answered as its raw samples.
    void   top_matrix(const expr_node& e, std::vector<result_series>& out);
    size_t steps() const { return m_n; }

private:
    void     charge(uint64_t n);
    void     release(uint64_t n);
    uint64_t held(const value& v) const { return v.vec.size() * m_n; }
    void     tick(uint64_t work);
    void     select(const expr_node& sel, int64_t mint, int64_t maxt, std::vector<uint32_t>& ids);
    void     emit_row(value& out, const label_set& labels, bool drop);
    void     dedupe(std::vector<vseries>& vec);
    void     drop_empty(std::vector<vseries>& vec);
    value    scalar_value(double v) const;

    int64_t plan_instant(int64_t t0);
    int64_t plan_range(fn f, int64_t range, int64_t t0, int64_t& range_eff);

    value vector_selector(const expr_node& e, bool timestamps);
    value range_call(const expr_node& e);
    double raw_window(fn f, std::span<const sample> w, int64_t t, int64_t te, int64_t range, double arg);
    double tier_window(fn f, std::span<const agg_point> w, int64_t range, int64_t range_eff);
    label_set absent_labels(const expr_node& e);

    value call(const expr_node& e);
    value aggregate(const expr_node& e);
    value binary(const expr_node& e);
    value set_op(const expr_node& e, value& l, value& r);
    value vector_op(const expr_node& e, value& l, value& r);
    static std::string signature(const label_set& ls, bool on, const std::vector<std::string>& names);
    value label_replace(const expr_node& e);
    value label_join(const expr_node& e);
    value histogram_quantile(const expr_node& e);

    series_source&      m_src;
    const query_limits& m_lim;
    query_stats&        m_stats;
    eval_scratch&       m_sc;
    int64_t m_start, m_end, m_step;
    size_t  m_n{1};
    uint64_t m_live{0};
    uint64_t m_work{0};
    uint64_t m_next_check{0};
    std::chrono::steady_clock::time_point m_deadline;
};

}   // namespace socketley::metrics
