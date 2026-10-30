#pragma once
// A PromQL query as the parser leaves it and the evaluator walks it.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "metrics_query.h"
#include "metrics_types.h"

namespace socketley::metrics
{

enum class value_type : uint8_t { none, scalar, vector, matrix, string };

enum class bin_op : uint8_t { add, sub, mul, div, mod, pow, atan2, eq, ne, gt, lt, ge, le, land, lor, lunless };

enum class agg_op : uint8_t { sum, avg, min, max, count, stddev, stdvar, topk, bottomk, quantile, count_values, group };

enum class card : uint8_t { one_to_one, many_to_one, one_to_many, many_to_many };

enum class fn : uint8_t
{
    abs, ceil, floor, exp, ln, log2, log10, sqrt, sgn,
    acos, acosh, asin, asinh, atan, atanh, cos, cosh, sin, sinh, tan, tanh, deg, rad, pi,
    round, clamp, clamp_min, clamp_max, time, timestamp, vector, scalar, absent, absent_over_time,
    label_replace, label_join, sort, sort_desc, histogram_quantile,
    day_of_month, day_of_week, day_of_year, days_in_month, hour, minute, month, year,
    rate, irate, increase, delta, idelta, deriv, predict_linear, resets, changes,
    avg_over_time, min_over_time, max_over_time, sum_over_time, count_over_time, last_over_time,
    quantile_over_time, stddev_over_time, stdvar_over_time, present_over_time,
};

struct func_info
{
    std::string_view name;
    fn id;
    value_type args[5];
    uint8_t nargs;
    // 0 a fixed count, 1 the last argument optional, -1 the last repeated any number of times.
    int8_t variadic;
    value_type ret;
};

const func_info* find_function(std::string_view name);
std::string_view type_name(value_type t);

struct expr_node
{
    enum class kind : uint8_t { number, string, vector_sel, matrix_sel, call, aggregate, binary, unary, paren };

    kind       k{kind::number};
    value_type type{value_type::none};
    uint32_t   pos{0};

    double      num{0};
    std::string str;

    // A selector's matchers, its name's among them, and a matrix selector's range.
    std::vector<matcher> matchers;
    int64_t offset_ms{0};
    int64_t range_ms{0};

    const func_info* func{nullptr};
    // A call's arguments; an aggregation's parameter, when it has one, then its expression; an operator's operands.
    std::vector<std::unique_ptr<expr_node>> args;

    agg_op agg{agg_op::sum};
    std::vector<std::string> grouping;
    bool without{false};

    bin_op op{bin_op::add};
    bool   return_bool{false};
    card   cardinality{card::one_to_one};
    bool   on{false};
    std::vector<std::string> match_labels;
    std::vector<std::string> include;
};

bool parse_promql(std::string_view query, size_t max_length, std::unique_ptr<expr_node>& out, query_error& err);

}   // namespace socketley::metrics
