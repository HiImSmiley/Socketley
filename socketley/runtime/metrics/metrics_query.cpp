#include "metrics_query.h"

#include "metrics_promql_eval.h"
#include "shared/json/json_escape.h"
#include "shared/util/utf8.h"

#include <algorithm>
#include <charconv>
#include <cmath>

namespace socketley::metrics
{

struct query_engine::scratch : eval_scratch
{
};

namespace
{

const expr_node& unparen(const expr_node& e)
{
    const expr_node* n = &e;
    while (n->k == expr_node::kind::paren)
        n = n->args[0].get();
    return *n;
}

// Query times past ±31,000 years are refused, so no window arithmetic on them can overflow.
constexpr int64_t max_time_ms = 1'000'000'000'000'000LL;

std::string thousands(int64_t v)
{
    std::string s = std::to_string(v);
    for (int i = static_cast<int>(s.size()) - 3; i > 0; i -= 3)
        s.insert(static_cast<size_t>(i), ",");
    return s;
}

void sort_by_labels(std::vector<result_series>& v)
{
    std::sort(v.begin(), v.end(),
              [](const result_series& a, const result_series& b) { return compare_labels(a.labels, b.labels) < 0; });
}

}   // namespace

query_engine::query_engine(series_source& source, query_limits limits)
    : m_source(source), m_limits(limits), m_scratch(std::make_unique<scratch>())
{
}

query_engine::~query_engine() = default;

bool query_engine::check(std::string_view query, query_error& err) const
{
    std::unique_ptr<expr_node> e;
    return parse_promql(query, m_limits.max_query_length, e, err);
}

prepared_query::prepared_query() = default;
prepared_query::~prepared_query() = default;
prepared_query::prepared_query(prepared_query&&) noexcept = default;
prepared_query& prepared_query::operator=(prepared_query&&) noexcept = default;

bool prepared_query::is_instant_value() const
{
    return m_expr && (m_expr->type == value_type::vector || m_expr->type == value_type::scalar);
}

bool query_engine::prepare(std::string_view query, prepared_query& out, query_error& err) const
{
    out.m_expr.reset();
    return parse_promql(query, m_limits.max_query_length, out.m_expr, err);
}

bool query_engine::eval_instant(std::string_view query, int64_t t_ms, query_result& out, query_error& err)
{
    out = {};
    m_stats = {};
    prepared_query q;
    if (!prepare(query, q, err))
        return false;
    return eval_instant(q, t_ms, out, err);
}

bool query_engine::eval_instant(const prepared_query& query, int64_t t_ms, query_result& out, query_error& err)
{
    out = {};
    m_stats = {};
    if (!query.m_expr)
    {
        err.type = "bad_data";
        err.message = "no query";
        return false;
    }
    const std::unique_ptr<expr_node>& e = query.m_expr;
    if (t_ms > max_time_ms || t_ms < -max_time_ms)
    {
        err.type = "bad_data";
        err.message = "invalid time: out of range";
        return false;
    }
    try
    {
        evaluator ev(m_source, m_limits, m_stats, *m_scratch, t_ms, t_ms, 0);
        const expr_node& top = unparen(*e);
        out.t = t_ms;
        if (top.type == value_type::matrix)
        {
            out.kind = result_kind::matrix;
            ev.top_matrix(top, out.series);
            sort_by_labels(out.series);
            return true;
        }
        value v = ev.eval(*e);
        switch (v.type)
        {
            case value_type::scalar:
                out.kind = result_kind::scalar;
                out.scalar = v.s[0];
                return true;
            case value_type::string:
                out.kind = result_kind::string;
                out.str = std::move(v.str);
                return true;
            default: break;
        }
        out.kind = result_kind::vector;
        for (auto& s : v.vec)
            if (!is_hole(s.v[0]))
                out.series.push_back({std::move(s.labels), {{t_ms, s.v[0]}}});
        if (v.sort)
        {
            // sort() and sort_desc() put NaN last either way, as Prometheus's heaps do.
            const bool asc = v.sort > 0;
            std::stable_sort(out.series.begin(), out.series.end(),
                             [asc](const result_series& a, const result_series& b) {
                                 const double x = a.points[0].v, y = b.points[0].v;
                                 if (std::isnan(x) || std::isnan(y))
                                     return !std::isnan(x) && std::isnan(y);
                                 return asc ? x < y : x > y;
                             });
        }
        return true;
    }
    catch (const eval_fail& f)
    {
        out = {};
        err.type = f.type;
        err.message = f.msg;
        return false;
    }
}

bool query_engine::eval_range(std::string_view query, int64_t start_ms, int64_t end_ms, int64_t step_ms,
                              query_result& out, query_error& err)
{
    out = {};
    m_stats = {};
    err = {};
    err.type = "bad_data";
    if (step_ms <= 0)
    {
        err.message = "zero or negative query resolution step widths are not accepted. Try a positive integer";
        return false;
    }
    if (start_ms > max_time_ms || start_ms < -max_time_ms || end_ms > max_time_ms || end_ms < -max_time_ms)
    {
        err.message = "invalid time: out of range";
        return false;
    }
    if (end_ms < start_ms)
    {
        err.message = "end timestamp must not be before start time";
        return false;
    }
    if ((end_ms - start_ms) / step_ms > m_limits.max_points_per_series)
    {
        err.message = "exceeded maximum resolution of " + thousands(m_limits.max_points_per_series) +
                      " points per timeseries. Try decreasing the query resolution (?step=XX)";
        return false;
    }
    std::unique_ptr<expr_node> e;
    if (!parse_promql(query, m_limits.max_query_length, e, err))
        return false;
    if (e->type != value_type::scalar && e->type != value_type::vector)
    {
        err.type = "bad_data";
        err.message = "invalid expression type \"" + std::string(type_name(e->type)) +
                      "\" for range query, must be Scalar or instant Vector";
        return false;
    }
    try
    {
        evaluator ev(m_source, m_limits, m_stats, *m_scratch, start_ms, end_ms, step_ms);
        value v = ev.eval(*e);
        out.kind = result_kind::matrix;
        const size_t n = ev.steps();
        if (v.type == value_type::scalar)
        {
            result_series rs;
            for (size_t k = 0; k < n; ++k)
                rs.points.push_back({start_ms + static_cast<int64_t>(k) * step_ms, v.s[k]});
            out.series.push_back(std::move(rs));
            return true;
        }
        for (auto& s : v.vec)
        {
            result_series rs;
            for (size_t k = 0; k < n; ++k)
                if (!is_hole(s.v[k]))
                    rs.points.push_back({start_ms + static_cast<int64_t>(k) * step_ms, s.v[k]});
            if (rs.points.empty())
                continue;
            rs.labels = std::move(s.labels);
            out.series.push_back(std::move(rs));
        }
        sort_by_labels(out.series);
        return true;
    }
    catch (const eval_fail& f)
    {
        out = {};
        err.type = f.type;
        err.message = f.msg;
        return false;
    }
}

void format_value(double v, std::string& out)
{
    if (std::isnan(v))
    {
        out += "NaN";
        return;
    }
    if (std::isinf(v))
    {
        out += v > 0 ? "+Inf" : "-Inf";
        return;
    }
    const double a = std::fabs(v);
    format_go_float(v, a != 0 && (a < 1e-6 || a >= 1e21), out);
}

void format_go_float(double v, bool exponent, std::string& out)
{
    char buf[64];
    const auto r = std::to_chars(buf, buf + sizeof buf, v, std::chars_format::scientific);
    if (exponent)
    {
        out.append(buf, r.ptr);
        return;
    }
    // Go's 'f' with the shortest digits writes those digits and zeros after them, where to_chars writes the exact value.
    const std::string_view sci(buf, static_cast<size_t>(r.ptr - buf));
    const size_t e = sci.find('e');
    std::string_view mant = sci.substr(0, e);
    int exp10 = 0;
    std::from_chars(sci.data() + e + 1 + (sci[e + 1] == '+'), sci.data() + sci.size(), exp10);
    if (mant.front() == '-')
    {
        out += '-';
        mant.remove_prefix(1);
    }
    char digits[32];
    size_t n = 0;
    for (char c : mant)
        if (c != '.')
            digits[n++] = c;
    if (exp10 < 0)
    {
        out += "0.";
        out.append(static_cast<size_t>(-exp10 - 1), '0');
        out.append(digits, n);
        return;
    }
    const auto whole = static_cast<size_t>(exp10) + 1;
    if (n <= whole)
    {
        out.append(digits, n);
        out.append(whole - n, '0');
        return;
    }
    out.append(digits, whole);
    out += '.';
    out.append(digits + whole, n - whole);
}

void format_timestamp(int64_t t, std::string& out)
{
    uint64_t u = static_cast<uint64_t>(t);
    if (t < 0)
    {
        out += '-';
        u = 0 - u;
    }
    out += std::to_string(u / 1000);
    if (const uint64_t frac = u % 1000)
    {
        out += '.';
        if (frac < 100)
            out += '0';
        if (frac < 10)
            out += '0';
        out += std::to_string(frac);
    }
}

namespace
{

void point_json(const sample& p, std::string& out)
{
    out += '[';
    format_timestamp(p.t, out);
    out += ",\"";
    format_value(p.v, out);
    out += "\"]";
}

// A JSON string of `s`, each byte that starts no valid UTF-8 sequence written as U+FFFD, as Go's encoder does.
void quote_utf8(std::string& out, std::string_view s)
{
    if (utf8::valid(s))
    {
        json::quote_into(out, s);
        return;
    }
    std::string clean;
    for (size_t i = 0; i < s.size();)
    {
        size_t n = 1;
        const auto b = static_cast<unsigned char>(s[i]);
        if (b >= 0x80)
        {
            n = (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 0;
            if (!n || i + n > s.size() || !utf8::valid(s.substr(i, n)))
            {
                clean += "\xEF\xBF\xBD";
                ++i;
                continue;
            }
        }
        clean.append(s.substr(i, n));
        i += n;
    }
    json::quote_into(out, clean);
}

void metric_json(const label_set& ls, std::string& out)
{
    out += "{\"metric\":{";
    for (size_t i = 0; i < ls.size(); ++i)
    {
        if (i)
            out += ',';
        quote_utf8(out, ls[i].name);
        out += ':';
        quote_utf8(out, ls[i].value);
    }
    out += '}';
}

}   // namespace

void render_json(const query_result& r, std::string& out)
{
    static constexpr std::string_view kinds[] = {"scalar", "string", "vector", "matrix"};
    out += "{\"resultType\":\"";
    out += kinds[static_cast<int>(r.kind)];
    out += "\",\"result\":";
    switch (r.kind)
    {
        case result_kind::scalar: point_json({r.t, r.scalar}, out); break;
        case result_kind::string:
            out += '[';
            format_timestamp(r.t, out);
            out += ',';
            quote_utf8(out, r.str);
            out += ']';
            break;
        case result_kind::vector:
        case result_kind::matrix:
            out += '[';
            for (size_t i = 0; i < r.series.size(); ++i)
            {
                const auto& s = r.series[i];
                if (i)
                    out += ',';
                metric_json(s.labels, out);
                if (r.kind == result_kind::vector)
                {
                    out += ",\"value\":";
                    point_json(s.points.empty() ? sample{r.t, 0} : s.points[0], out);
                }
                else
                {
                    out += ",\"values\":[";
                    for (size_t k = 0; k < s.points.size(); ++k)
                    {
                        if (k)
                            out += ',';
                        point_json(s.points[k], out);
                    }
                    out += ']';
                }
                out += '}';
            }
            out += ']';
            break;
    }
    out += '}';
}

}   // namespace socketley::metrics
