#include "metrics_promql_eval.h"

#include "metrics_regex.h"
#include "metrics_text.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>
#include <numbers>
#include <unordered_map>

namespace socketley::metrics
{

namespace
{

using V = value_type;
constexpr double nan_v = std::numeric_limits<double>::quiet_NaN();
constexpr double inf_v = std::numeric_limits<double>::infinity();

double canon(double v) { return std::isnan(v) ? nan_v : v; }

// Go's math.Max and math.Min, which put +Inf and -Inf before NaN where fmax and fmin drop the NaN.
double go_max(double x, double y)
{
    if (std::isinf(x) && x > 0) return x;
    if (std::isinf(y) && y > 0) return y;
    if (std::isnan(x) || std::isnan(y)) return nan_v;
    if (x == 0 && x == y) return std::signbit(x) ? y : x;
    return x > y ? x : y;
}

double go_min(double x, double y)
{
    if (std::isinf(x) && x < 0) return x;
    if (std::isinf(y) && y < 0) return y;
    if (std::isnan(x) || std::isnan(y)) return nan_v;
    if (x == 0 && x == y) return std::signbit(x) ? x : y;
    return x < y ? x : y;
}

// Go's math.Log2 and math.Log10, which are exact on powers of two and go through Log2 for base ten.
double go_log2(double x)
{
    int e = 0;
    const double frac = std::frexp(x, &e);
    if (frac == 0.5)
        return static_cast<double>(e - 1);
    return std::log(frac) * (1 / std::numbers::ln2) + static_cast<double>(e);
}

double go_log10(double x) { return go_log2(x) * (std::numbers::ln2 / std::numbers::ln10); }

// Prometheus's kahanSumInc, with Neumaier's improvement.
inline void kahan_inc(double inc, double& sum, double& c)
{
    const double t = sum + inc;
    if (std::isinf(t))
        c = 0;
    else if (std::fabs(sum) >= std::fabs(inc))
        c += (sum - t) + inc;
    else
        c += (inc - t) + sum;
    sum = t;
}

std::string go_quote(std::string_view s)
{
    std::string out = "\"";
    for (const char c : s)
    {
        if (c == '"' || c == '\\')
        {
            out += '\\';
            out += c;
        }
        else if (c == '\n')
            out += "\\n";
        else if (static_cast<unsigned char>(c) < 0x20)
        {
            static constexpr char hex[] = "0123456789abcdef";
            out += "\\x";
            out += hex[static_cast<unsigned char>(c) >> 4];
            out += hex[c & 15];
        }
        else
            out += c;
    }
    return out + "\"";
}

std::string labels_string(const label_set& ls)
{
    std::string out = "{";
    for (size_t i = 0; i < ls.size(); ++i)
    {
        if (i)
            out += ", ";
        out += ls[i].name + "=" + go_quote(ls[i].value);
    }
    return out + "}";
}

void key_into(std::string& key, const label& l)
{
    key += l.name;
    key += '\xff';
    key += l.value;
    key += '\xff';
}

bool listed(const std::vector<std::string>& names, std::string_view n)
{
    return std::find(names.begin(), names.end(), n) != names.end();
}

bool is_comparison(bin_op o) { return o >= bin_op::eq && o <= bin_op::le; }
bool is_arithmetic(bin_op o) { return o <= bin_op::atan2; }

// Prometheus's vectorElemBinop for floats: the value, and whether a comparison keeps it.
inline double elem_op(bin_op op, double l, double r, bool& keep)
{
    keep = true;
    switch (op)
    {
        case bin_op::add: return l + r;
        case bin_op::sub: return l - r;
        case bin_op::mul: return l * r;
        case bin_op::div: return l / r;
        case bin_op::pow: return std::pow(l, r);
        case bin_op::mod: return std::fmod(l, r);
        case bin_op::atan2: return std::atan2(l, r);
        case bin_op::eq: keep = l == r; return l;
        case bin_op::ne: keep = l != r; return l;
        case bin_op::gt: keep = l > r; return l;
        case bin_op::lt: keep = l < r; return l;
        case bin_op::ge: keep = l >= r; return l;
        case bin_op::le: keep = l <= r; return l;
        default: return l;
    }
}

int64_t floor_mod(int64_t a, int64_t b)
{
    const int64_t m = a % b;
    return m < 0 ? m + b : m;
}

int64_t floor_div(int64_t a, int64_t b)
{
    return (a - floor_mod(a, b)) / b;
}

struct civil
{
    int64_t year;
    int month, day, hour, minute, wday, yday;
};

bool leap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

// The UTC calendar of a unix second, after Howard Hinnant's days_from_civil inverse.
civil civil_of(int64_t secs)
{
    const int64_t days = floor_div(secs, 86400);
    const int64_t sod = secs - days * 86400;
    const int64_t z = days + 719468;
    const int64_t era = floor_div(z, 146097);
    const int64_t doe = z - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    civil c{};
    c.day = static_cast<int>(doy - (153 * mp + 2) / 5 + 1);
    c.month = static_cast<int>(mp < 10 ? mp + 3 : mp - 9);
    c.year = yoe + era * 400 + (c.month <= 2 ? 1 : 0);
    c.hour = static_cast<int>(sod / 3600);
    c.minute = static_cast<int>(sod / 60 % 60);
    c.wday = static_cast<int>(floor_mod(days + 4, 7));
    static constexpr int before[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    c.yday = before[c.month - 1] + c.day + (c.month > 2 && leap(c.year) ? 1 : 0);
    return c;
}

double date_part(fn f, double v)
{
    if (!std::isfinite(v) || std::fabs(v) > 9e15)
        return nan_v;
    const civil c = civil_of(static_cast<int64_t>(v));
    static constexpr int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    switch (f)
    {
        case fn::day_of_month: return c.day;
        case fn::day_of_week: return c.wday;
        case fn::day_of_year: return c.yday;
        case fn::days_in_month: return month_days[c.month - 1] + (c.month == 2 && leap(c.year) ? 1 : 0);
        case fn::hour: return c.hour;
        case fn::minute: return c.minute;
        case fn::month: return c.month;
        default: return static_cast<double>(c.year);
    }
}

using unary_fn = double (*)(double);

unary_fn math_of(fn f)
{
    switch (f)
    {
        case fn::abs: return [](double v) { return std::fabs(v); };
        case fn::ceil: return [](double v) { return std::ceil(v); };
        case fn::floor: return [](double v) { return std::floor(v); };
        case fn::exp: return [](double v) { return std::exp(v); };
        case fn::ln: return [](double v) { return std::log(v); };
        case fn::log2: return go_log2;
        case fn::log10: return go_log10;
        case fn::sqrt: return [](double v) { return std::sqrt(v); };
        case fn::sgn: return [](double v) { return v < 0 ? -1.0 : v > 0 ? 1.0 : v; };
        case fn::acos: return [](double v) { return std::acos(v); };
        case fn::acosh: return [](double v) { return std::acosh(v); };
        case fn::asin: return [](double v) { return std::asin(v); };
        case fn::asinh: return [](double v) { return std::asinh(v); };
        case fn::atan: return [](double v) { return std::atan(v); };
        case fn::atanh: return [](double v) { return std::atanh(v); };
        case fn::cos: return [](double v) { return std::cos(v); };
        case fn::cosh: return [](double v) { return std::cosh(v); };
        case fn::sin: return [](double v) { return std::sin(v); };
        case fn::sinh: return [](double v) { return std::sinh(v); };
        case fn::tan: return [](double v) { return std::tan(v); };
        case fn::tanh: return [](double v) { return std::tanh(v); };
        case fn::deg: return [](double v) { return v * 180 / std::numbers::pi; };
        case fn::rad: return [](double v) { return v * std::numbers::pi / 180; };
        default: return nullptr;
    }
}

bool is_range_fn(fn f)
{
    switch (f)
    {
        case fn::rate: case fn::irate: case fn::increase: case fn::delta: case fn::idelta: case fn::deriv:
        case fn::predict_linear: case fn::resets: case fn::changes: case fn::avg_over_time: case fn::min_over_time:
        case fn::max_over_time: case fn::sum_over_time: case fn::count_over_time: case fn::last_over_time:
        case fn::quantile_over_time: case fn::stddev_over_time: case fn::stdvar_over_time:
        case fn::present_over_time: case fn::absent_over_time:
            return true;
        default: return false;
    }
}

const expr_node& unparen(const expr_node& e)
{
    const expr_node* n = &e;
    while (n->k == expr_node::kind::paren)
        n = n->args[0].get();
    return *n;
}

// Prometheus's quantile over values it sorts, NaN first, the rank interpolated between two neighbours.
double quantile_of(double q, std::vector<double>& vs)
{
    if (vs.empty() || std::isnan(q))
        return nan_v;
    if (q < 0)
        return -inf_v;
    if (q > 1)
        return inf_v;
    std::sort(vs.begin(), vs.end(), [](double a, double b) { return std::isnan(a) ? !std::isnan(b) : a < b; });
    const double n = static_cast<double>(vs.size());
    const double rank = q * (n - 1);
    const double lower = std::max(0.0, std::floor(rank));
    const double upper = std::min(n - 1, lower + 1);
    const double weight = rank - std::floor(rank);
    return vs[static_cast<size_t>(lower)] * (1 - weight) + vs[static_cast<size_t>(upper)] * weight;
}

// Prometheus's linearRegression with Kahan sums, x in seconds from `intercept_t`.
void linear_regression(std::span<const sample> w, int64_t intercept_t, double& slope, double& intercept)
{
    double n = 0, sx = 0, cx = 0, sy = 0, cy = 0, sxy = 0, cxy = 0, sx2 = 0, cx2 = 0;
    const double init_y = w[0].v;
    bool const_y = true;
    for (size_t i = 0; i < w.size(); ++i)
    {
        if (const_y && i > 0 && w[i].v != init_y)
            const_y = false;
        n += 1;
        const double x = static_cast<double>(w[i].t - intercept_t) / 1e3;
        kahan_inc(x, sx, cx);
        kahan_inc(w[i].v, sy, cy);
        kahan_inc(x * w[i].v, sxy, cxy);
        kahan_inc(x * x, sx2, cx2);
    }
    if (const_y)
    {
        if (std::isinf(init_y))
        {
            slope = intercept = nan_v;
            return;
        }
        slope = 0;
        intercept = init_y;
        return;
    }
    sx += cx;
    sy += cy;
    sxy += cxy;
    sx2 += cx2;
    const double cov = sxy - sx * sy / n;
    const double var = sx2 - sx * sx / n;
    slope = cov / var;
    intercept = sy / n - slope * sx / n;
}

// Prometheus's extrapolatedRate: the change across the window, stretched to its edges where the samples reach them.
double extrapolated(std::span<const sample> w, int64_t range_start, int64_t range_end, int64_t range_ms,
                    bool counter, bool rate)
{
    if (w.size() < 2)
        return hole();
    const int64_t first_t = w.front().t, last_t = w.back().t;
    double result = w.back().v - w.front().v;
    if (counter)
    {
        double last = 0;
        for (const auto& s : w)
        {
            if (s.v < last)
                result += last;
            last = s.v;
        }
    }
    double to_start = static_cast<double>(first_t - range_start) / 1000;
    double to_end = static_cast<double>(range_end - last_t) / 1000;
    const double sampled = static_cast<double>(last_t - first_t) / 1000;
    const double avg_gap = sampled / static_cast<double>(w.size() - 1);
    const double threshold = avg_gap * 1.1;
    double interval = sampled;
    if (to_start >= threshold)
        to_start = avg_gap / 2;
    if (counter && result > 0 && w.front().v >= 0)
    {
        // A counter cannot have been below zero, so the stretch back stops where the line through it reaches zero.
        const double to_zero = sampled * (w.front().v / result);
        if (to_zero < to_start)
            to_start = to_zero;
    }
    interval += to_start;
    if (to_end >= threshold)
        to_end = avg_gap / 2;
    interval += to_end;
    double factor = interval / sampled;
    if (rate)
        factor /= static_cast<double>(range_ms) / 1000;
    return result * factor;
}

double instant_value(std::span<const sample> w, bool rate)
{
    if (w.size() < 2)
        return hole();
    const sample& last = w[w.size() - 1];
    const sample& prev = w[w.size() - 2];
    double v = rate && last.v < prev.v ? last.v : last.v - prev.v;
    const int64_t gap = last.t - prev.t;
    if (gap == 0)
        return hole();
    if (rate)
        v /= static_cast<double>(gap) / 1000;
    return v;
}

// Prometheus's average of a run with Kahan sums, falling back to an incremental mean once the sum would overflow.
struct mean_acc
{
    double sum{0}, c{0}, mean{0}, count{0};
    bool incremental{false};

    void add(double f)
    {
        count += 1;
        if (!incremental)
        {
            double ns = sum, nc = c;
            kahan_inc(f, ns, nc);
            if (count == 1 || !std::isinf(ns))
            {
                sum = ns;
                c = nc;
                return;
            }
            incremental = true;
            mean = sum / (count - 1);
            c /= count - 1;
        }
        if (std::isinf(mean))
        {
            if (std::isinf(f) && (mean > 0) == (f > 0))
                return;
            if (!std::isinf(f) && !std::isnan(f))
                return;
        }
        const double corrected = mean + c;
        kahan_inc(f / count - corrected / count, mean, c);
    }
    double result() const { return incremental ? mean + c : (sum + c) / count; }
};

struct bucket
{
    double le, count;
};

// Prometheus's bucketQuantile over classic `le` buckets, which it sorts, merges and forces monotonic.
double bucket_quantile(double q, std::vector<bucket>& b)
{
    if (std::isnan(q))
        return nan_v;
    if (q < 0)
        return -inf_v;
    if (q > 1)
        return inf_v;
    std::sort(b.begin(), b.end(), [](const bucket& x, const bucket& y) { return x.le < y.le; });
    if (b.empty() || !(std::isinf(b.back().le) && b.back().le > 0))
        return nan_v;
    size_t o = 0;
    for (size_t i = 1; i < b.size(); ++i)
    {
        if (b[i].le == b[o].le)
            b[o].count += b[i].count;
        else
            b[++o] = b[i];
    }
    b.resize(o + 1);
    const double min_normal = std::numeric_limits<double>::min();
    auto almost_equal = [&](double x, double y) {
        if (std::isnan(x) && std::isnan(y))
            return true;
        if (x == y)
            return true;
        const double abs_sum = std::fabs(x) + std::fabs(y);
        const double diff = std::fabs(x - y);
        if (x == 0 || y == 0 || abs_sum < min_normal)
            return diff < 1e-12 * min_normal;
        return diff / std::min(abs_sum, std::numeric_limits<double>::max()) < 1e-12;
    };
    double prev = b[0].count;
    for (size_t i = 1; i < b.size(); ++i)
    {
        const double cur = b[i].count;
        if (cur == prev)
            continue;
        if (almost_equal(prev, cur) || cur < prev)
        {
            b[i].count = prev;
            continue;
        }
        prev = cur;
    }
    if (b.size() < 2)
        return nan_v;
    const double observations = b.back().count;
    if (observations == 0)
        return nan_v;
    double rank = q * observations;
    size_t i = 0;
    {
        size_t lo = 0, hi = b.size() - 1;
        while (lo < hi)
        {
            const size_t mid = (lo + hi) / 2;
            if (b[mid].count >= rank)
                hi = mid;
            else
                lo = mid + 1;
        }
        i = lo;
    }
    if (i == b.size() - 1)
        return b[b.size() - 2].le;
    if (i == 0 && b[0].le <= 0)
        return b[0].le;
    double start = 0, count = b[i].count;
    const double end = b[i].le;
    if (i > 0)
    {
        start = b[i - 1].le;
        count -= b[i - 1].count;
        rank -= b[i - 1].count;
    }
    return start + (end - start) * (rank / count);
}

// Go's container/heap over series indexes by one step's values, as Prometheus's topk and bottomk keep their k.
struct k_heap
{
    std::vector<uint32_t>* h;
    const std::vector<double>* vals;
    bool top;

    bool less(size_t i, size_t j) const
    {
        const double a = (*vals)[(*h)[i]], b = (*vals)[(*h)[j]];
        if (std::isnan(a))
            return true;
        return top ? a < b : a > b;
    }
    void up(size_t j)
    {
        while (j > 0)
        {
            const size_t i = (j - 1) / 2;
            if (!less(j, i))
                break;
            std::swap((*h)[i], (*h)[j]);
            j = i;
        }
    }
    bool down(size_t i0, size_t n)
    {
        size_t i = i0;
        while (true)
        {
            const size_t j1 = 2 * i + 1;
            if (j1 >= n)
                break;
            size_t j = j1;
            if (const size_t j2 = j1 + 1; j2 < n && less(j2, j1))
                j = j2;
            if (!less(j, i))
                break;
            std::swap((*h)[i], (*h)[j]);
            i = j;
        }
        return i > i0;
    }
    void push(uint32_t x)
    {
        h->push_back(x);
        up(h->size() - 1);
    }
    void fix0()
    {
        if (!down(0, h->size()))
            up(0);
    }
};

}   // namespace

int compare_labels(const label_set& a, const label_set& b)
{
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i)
    {
        if (const int c = a[i].name.compare(b[i].name))
            return c;
        if (const int c = a[i].value.compare(b[i].value))
            return c;
    }
    return a.size() < b.size() ? -1 : a.size() > b.size() ? 1 : 0;
}

void drop_name(label_set& ls)
{
    std::erase_if(ls, [](const label& l) { return l.name == name_label; });
}

void set_label(label_set& ls, std::string_view name, std::string_view value)
{
    auto it = std::lower_bound(ls.begin(), ls.end(), name, [](const label& l, std::string_view n) { return l.name < n; });
    const bool found = it != ls.end() && it->name == name;
    if (value.empty())
    {
        if (found)
            ls.erase(it);
        return;
    }
    if (found)
        it->value.assign(value);
    else
        ls.insert(it, label{std::string(name), std::string(value)});
}

evaluator::evaluator(series_source& src, const query_limits& lim, query_stats& stats, eval_scratch& sc, int64_t start,
                     int64_t end, int64_t step)
    : m_src(src), m_lim(lim), m_stats(stats), m_sc(sc), m_start(start), m_end(end), m_step(step)
{
    m_n = step > 0 ? static_cast<size_t>((end - start) / step) + 1 : 1;
    m_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(lim.timeout_ms);
}

void evaluator::charge(uint64_t n)
{
    m_live += n;
    if (m_live > m_lim.max_samples)
        throw eval_fail{"execution", "query processing would load too many samples into memory in query execution"};
}

void evaluator::release(uint64_t n) { m_live -= std::min(n, m_live); }

void evaluator::tick(uint64_t work)
{
    m_work += work;
    if (m_work < m_next_check)
        return;
    m_next_check = m_work + (1u << 16);
    if (std::chrono::steady_clock::now() >= m_deadline)
        throw eval_fail{"timeout", "query timed out in expression evaluation"};
}

void evaluator::select(const expr_node& sel, int64_t mint, int64_t maxt, std::vector<uint32_t>& ids)
{
    ids.clear();
    m_src.select(sel.matchers, mint, maxt, ids);
    std::sort(ids.begin(), ids.end(),
              [&](uint32_t a, uint32_t b) { return compare_labels(m_src.labels(a), m_src.labels(b)) < 0; });
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    tick(ids.size());
}

void evaluator::emit_row(value& out, const label_set& labels, bool drop)
{
    const auto& row = m_sc.row;
    bool any = false;
    for (double v : row)
        if (!is_hole(v))
        {
            any = true;
            break;
        }
    if (!any)
        return;
    charge(m_n);
    out.vec.push_back({labels, row});
    if (drop)
        drop_name(out.vec.back().labels);
}

value evaluator::scalar_value(double v) const
{
    value out;
    out.type = V::scalar;
    out.s.assign(m_n, v);
    return out;
}

// A tier's point is read only where a step needs it once more of them lie between two steps than a stored chunk holds,
// since a read decodes a whole chunk.
bool evaluator::tier_per_step(int64_t s) const { return m_step > 0 && m_step / s > 1024; }

// An instant selector reads the tier S no longer than the lookback whose points end on every evaluation time, its `last`
// the sample the lookback finds but for a staleness marker, which no tier holds.
int64_t evaluator::plan_instant(int64_t t0)
{
    if (!m_lim.use_tiers || m_step <= 0)
        return 0;
    // A coarser tier that does not divide the step gives way to the next finer one.
    for (int64_t s = m_src.tier_for(t0, std::min(m_step, m_lim.lookback_ms)); s > 0; s = m_src.tier_for(t0, s - 1))
        if (!(m_step % s) && !floor_mod(t0, s))
            return s;
    return 0;
}

// A range function reads tier S when S divides the step and every evaluation time, and the window holds whole steps.
int64_t evaluator::plan_range(fn f, int64_t range, int64_t t0, int64_t& range_eff)
{
    range_eff = range;
    if (!m_lim.use_tiers)
        return 0;
    switch (f)
    {
        case fn::rate: case fn::increase: case fn::avg_over_time: case fn::min_over_time: case fn::max_over_time:
        case fn::sum_over_time: case fn::count_over_time: case fn::last_over_time: case fn::present_over_time:
        case fn::absent_over_time:
            break;
        default: return 0;
    }
    const bool instant = m_step <= 0;
    const int64_t mint = t0 - range;
    for (int64_t s = m_src.tier_for(mint, instant ? range : std::min(range, m_step)); s > 0;
         s = m_src.tier_for(mint, s - 1))
    {
        if ((!instant && m_step % s) || floor_mod(t0, s))
            continue;
        const int64_t rem = range % s;
        if (range - rem < s)
            continue;
        // A window a quarter step past whole steps, as Grafana's $__rate_interval adds one scrape, reads the whole steps.
        if (rem && (f == fn::sum_over_time || f == fn::count_over_time || rem * 4 > s))
            continue;
        range_eff = range - rem;
        return s;
    }
    return 0;
}

value evaluator::vector_selector(const expr_node& e, bool timestamps)
{
    value out;
    out.type = V::vector;
    const int64_t t0 = m_start - e.offset_ms, t1 = m_end - e.offset_ms;
    const int64_t step = m_step > 0 ? m_step : 0;
    const int64_t s = timestamps ? 0 : plan_instant(t0);
    std::vector<uint32_t> ids;
    auto& row = m_sc.row;
    row.resize(m_n);
    if (s)
    {
        ++m_stats.tier_selectors;
        select(e, t0 - s, t1, ids);
        auto& pts = m_sc.points;
        const bool per_step = tier_per_step(s);
        for (uint32_t id : ids)
        {
            std::fill(row.begin(), row.end(), hole());
            uint64_t work = 0;
            // A tier holds no NaN, the staleness marker among them, so its `last` is always a value.
            auto take = [&](size_t k, const agg_point& p) { row[k] = canon(p.last); };
            if (per_step)
                for (size_t k = 0; k < m_n; ++k)
                {
                    const int64_t t = t0 + static_cast<int64_t>(k) * step;
                    pts.clear();
                    m_src.aggregates(id, s, t - s, t, pts);
                    work += pts.size();
                    if (!pts.empty() && pts.back().t == t)
                        take(k, pts.back());
                }
            else
            {
                pts.clear();
                m_src.aggregates(id, s, t0 - s, t1, pts);
                work = pts.size();
                charge(pts.size());
                size_t j = 0;
                for (size_t k = 0; k < m_n; ++k)
                {
                    const int64_t t = t0 + static_cast<int64_t>(k) * step;
                    while (j < pts.size() && pts[j].t < t)
                        ++j;
                    if (j < pts.size() && pts[j].t == t)
                        take(k, pts[j]);
                }
                release(pts.size());
            }
            m_stats.tier_points += work;
            tick(work + m_n);
            emit_row(out, m_src.labels(id), false);
        }
        return out;
    }
    ++m_stats.raw_selectors;
    const int64_t lb = m_lim.lookback_ms;
    select(e, t0 - lb + 1, t1, ids);
    auto& smp = m_sc.samples;
    // Lookbacks shorter than the step leave gaps, so each is read alone and no sample between them is decoded.
    const bool per_step = m_step > lb;
    for (uint32_t id : ids)
    {
        std::fill(row.begin(), row.end(), hole());
        uint64_t work = 0;
        auto take = [&](size_t k, const sample& x) {
            // The last sample in (t - lookback, t], unless it is the marker that ended its series.
            if (!is_stale(x.v))
                row[k] = timestamps ? static_cast<double>(x.t) / 1000 : canon(x.v);
        };
        if (per_step)
            for (size_t k = 0; k < m_n; ++k)
            {
                const int64_t t = t0 + static_cast<int64_t>(k) * step;
                smp.clear();
                m_src.samples(id, t - lb + 1, t, smp);
                work += smp.size();
                if (!smp.empty())
                    take(k, smp.back());
            }
        else
        {
            smp.clear();
            m_src.samples(id, t0 - lb + 1, t1, smp);
            work = smp.size();
            charge(smp.size());
            size_t j = 0;
            for (size_t k = 0; k < m_n; ++k)
            {
                const int64_t t = t0 + static_cast<int64_t>(k) * step;
                while (j < smp.size() && smp[j].t <= t)
                    ++j;
                if (j > 0 && smp[j - 1].t > t - lb)
                    take(k, smp[j - 1]);
            }
            release(smp.size());
        }
        m_stats.raw_samples += work;
        tick(work + m_n);
        emit_row(out, m_src.labels(id), timestamps);
    }
    return out;
}

double evaluator::raw_window(fn f, std::span<const sample> w, int64_t t, int64_t te, int64_t range, double arg)
{
    switch (f)
    {
        case fn::rate: return extrapolated(w, te - range, te, range, true, true);
        case fn::increase: return extrapolated(w, te - range, te, range, true, false);
        case fn::delta: return extrapolated(w, te - range, te, range, false, false);
        case fn::irate: return instant_value(w, true);
        case fn::idelta: return instant_value(w, false);
        case fn::deriv:
        {
            if (w.size() < 2)
                return hole();
            double slope = 0, icpt = 0;
            linear_regression(w, w[0].t, slope, icpt);
            return slope;
        }
        case fn::predict_linear:
        {
            if (w.size() < 2)
                return hole();
            double slope = 0, icpt = 0;
            linear_regression(w, t, slope, icpt);
            return slope * arg + icpt;
        }
        case fn::resets:
        {
            double n = 0;
            for (size_t i = 1; i < w.size(); ++i)
                if (w[i].v < w[i - 1].v)
                    n += 1;
            return n;
        }
        case fn::changes:
        {
            double n = 0;
            for (size_t i = 1; i < w.size(); ++i)
                if (w[i].v != w[i - 1].v && !(std::isnan(w[i].v) && std::isnan(w[i - 1].v)))
                    n += 1;
            return n;
        }
        case fn::avg_over_time:
        {
            mean_acc m;
            for (const auto& s : w)
                m.add(s.v);
            return m.result();
        }
        case fn::sum_over_time:
        {
            double sum = 0, c = 0;
            for (const auto& s : w)
                kahan_inc(s.v, sum, c);
            return std::isinf(sum) ? sum : sum + c;
        }
        case fn::min_over_time:
        {
            double m = w[0].v;
            for (const auto& s : w)
                if (s.v < m || std::isnan(m))
                    m = s.v;
            return m;
        }
        case fn::max_over_time:
        {
            double m = w[0].v;
            for (const auto& s : w)
                if (s.v > m || std::isnan(m))
                    m = s.v;
            return m;
        }
        case fn::count_over_time: return static_cast<double>(w.size());
        case fn::last_over_time: return canon(w.back().v);
        case fn::present_over_time: case fn::absent_over_time: return 1;
        case fn::quantile_over_time:
        {
            auto& q = m_sc.qbuf;
            q.clear();
            for (const auto& s : w)
                q.push_back(s.v);
            return quantile_of(arg, q);
        }
        case fn::stddev_over_time: case fn::stdvar_over_time:
        {
            double count = 0, mean = 0, cmean = 0, aux = 0, caux = 0;
            for (const auto& s : w)
            {
                count += 1;
                const double delta = s.v - (mean + cmean);
                kahan_inc(delta / count, mean, cmean);
                kahan_inc(delta * (s.v - (mean + cmean)), aux, caux);
            }
            const double var = (aux + caux) / count;
            return f == fn::stddev_over_time ? std::sqrt(var) : var;
        }
        default: return hole();
    }
}

double evaluator::tier_window(fn f, std::span<const agg_point> w, int64_t range, int64_t range_eff)
{
    double count = 0;
    for (const auto& p : w)
        count += p.count;
    if (count <= 0)
        return hole();
    switch (f)
    {
        case fn::rate: case fn::increase:
        {
            double sum = 0, c = 0;
            for (const auto& p : w)
                kahan_inc(p.inc, sum, c);
            sum += c;
            return f == fn::rate ? sum / (static_cast<double>(range_eff) / 1000)
                                 : sum * static_cast<double>(range) / static_cast<double>(range_eff);
        }
        case fn::sum_over_time: case fn::avg_over_time:
        {
            double sum = 0, c = 0;
            for (const auto& p : w)
                kahan_inc(p.sum, sum, c);
            sum = std::isinf(sum) ? sum : sum + c;
            return f == fn::sum_over_time ? sum : sum / count;
        }
        case fn::count_over_time: return count;
        case fn::min_over_time: case fn::max_over_time:
        {
            double m = f == fn::min_over_time ? w[0].min : w[0].max;
            for (const auto& p : w)
                m = f == fn::min_over_time ? std::min(m, p.min) : std::max(m, p.max);
            return m;
        }
        case fn::last_over_time: return canon(w.back().last);
        default: return 1;
    }
}

label_set evaluator::absent_labels(const expr_node& e)
{
    const expr_node* sel = &e;
    if (sel->k != expr_node::kind::vector_sel && sel->k != expr_node::kind::matrix_sel)
        return {};
    label_set out;
    std::vector<std::string> seen;
    for (const auto& m : sel->matchers)
    {
        if (m.name == name_label)
            continue;
        if (m.op == match_op::eq && !listed(seen, m.name))
        {
            set_label(out, m.name, m.value);
            seen.push_back(m.name);
        }
        else
            set_label(out, m.name, {});
    }
    return out;
}

value evaluator::range_call(const expr_node& e)
{
    const fn f = e.func->id;
    const size_t mi = f == fn::quantile_over_time ? 1 : 0;
    const expr_node& ms = unparen(*e.args[mi]);
    value arg;
    if (f == fn::quantile_over_time)
        arg = eval(*e.args[0]);
    else if (f == fn::predict_linear)
        arg = eval(*e.args[1]);
    const int64_t range = ms.range_ms, t0 = m_start - ms.offset_ms, t1 = m_end - ms.offset_ms;
    const int64_t step = m_step > 0 ? m_step : 0;
    int64_t range_eff = range;
    const int64_t s = plan_range(f, range, t0, range_eff);
    std::vector<uint32_t> ids;
    select(ms, t0 - range + 1, t1, ids);
    auto& row = m_sc.row;
    row.resize(m_n);
    value out;
    out.type = V::vector;
    std::vector<uint8_t> any;
    if (f == fn::absent_over_time)
        any.assign(m_n, 0);
    const bool drop = f != fn::last_over_time;
    // Windows shorter than the step leave gaps, so each is read alone and no sample between them is decoded.
    const bool per_step = m_step > range;
    if (s)
        ++m_stats.tier_selectors;
    else
        ++m_stats.raw_selectors;
    for (uint32_t id : ids)
    {
        std::fill(row.begin(), row.end(), hole());
        if (s)
        {
            auto& pts = m_sc.points;
            uint64_t work = 0;
            if (tier_per_step(s))
                for (size_t k = 0; k < m_n; ++k)
                {
                    const int64_t te = t0 + static_cast<int64_t>(k) * step;
                    pts.clear();
                    m_src.aggregates(id, s, te - range_eff, te, pts);
                    work += pts.size();
                    if (!pts.empty())
                        row[k] = tier_window(f, pts, range, range_eff);
                }
            else
            {
                pts.clear();
                m_src.aggregates(id, s, t0 - range_eff, t1, pts);
                work = pts.size();
                charge(pts.size());
                size_t lo = 0, hi = 0;
                for (size_t k = 0; k < m_n; ++k)
                {
                    const int64_t te = t0 + static_cast<int64_t>(k) * step;
                    while (hi < pts.size() && pts[hi].t <= te)
                        ++hi;
                    while (lo < hi && pts[lo].t <= te - range_eff)
                        ++lo;
                    if (lo < hi)
                        row[k] = tier_window(f, std::span<const agg_point>(pts).subspan(lo, hi - lo), range,
                                             range_eff);
                }
                release(pts.size());
            }
            m_stats.tier_points += work;
            tick(work + m_n);
        }
        else
        {
            auto& smp = m_sc.samples;
            // A range keeps no staleness marker, which only ends what an instant selector sees.
            auto no_stale = [](const sample& x) { return is_stale(x.v); };
            uint64_t work = 0;
            if (per_step)
                for (size_t k = 0; k < m_n; ++k)
                {
                    const int64_t te = t0 + static_cast<int64_t>(k) * step;
                    smp.clear();
                    m_src.samples(id, te - range + 1, te, smp);
                    m_stats.raw_samples += smp.size();
                    std::erase_if(smp, no_stale);
                    work += smp.size();
                    if (!smp.empty())
                        row[k] = raw_window(f, smp, m_start + static_cast<int64_t>(k) * step, te, range,
                                            arg.s.empty() ? 0 : arg.s[k]);
                }
            else
            {
                smp.clear();
                m_src.samples(id, t0 - range + 1, t1, smp);
                m_stats.raw_samples += smp.size();
                std::erase_if(smp, no_stale);
                charge(smp.size());
                size_t lo = 0, hi = 0;
                work = smp.size();
                for (size_t k = 0; k < m_n; ++k)
                {
                    const int64_t te = t0 + static_cast<int64_t>(k) * step;
                    while (hi < smp.size() && smp[hi].t <= te)
                        ++hi;
                    while (lo < hi && smp[lo].t <= te - range)
                        ++lo;
                    if (lo == hi)
                        continue;
                    row[k] = raw_window(f, std::span<const sample>(smp).subspan(lo, hi - lo),
                                        m_start + static_cast<int64_t>(k) * step, te, range,
                                        arg.s.empty() ? 0 : arg.s[k]);
                    work += hi - lo;
                }
                release(smp.size());
            }
            tick(work + m_n);
        }
        if (f == fn::absent_over_time)
        {
            for (size_t k = 0; k < m_n; ++k)
                any[k] = any[k] || !is_hole(row[k]);
            continue;
        }
        emit_row(out, m_src.labels(id), drop);
    }
    if (f == fn::absent_over_time)
    {
        for (size_t k = 0; k < m_n; ++k)
            row[k] = any[k] ? hole() : 1.0;
        emit_row(out, absent_labels(ms), false);
        return out;
    }
    if (drop)
        dedupe(out.vec);
    release(held(arg));
    return out;
}

void evaluator::dedupe(std::vector<vseries>& vec)
{
    if (vec.size() < 2)
        return;
    std::vector<uint32_t> idx(vec.size());
    for (uint32_t i = 0; i < idx.size(); ++i)
        idx[i] = i;
    std::stable_sort(idx.begin(), idx.end(),
                     [&](uint32_t a, uint32_t b) { return compare_labels(vec[a].labels, vec[b].labels) < 0; });
    bool same = false;
    for (size_t i = 1; i < idx.size() && !same; ++i)
        same = compare_labels(vec[idx[i - 1]].labels, vec[idx[i]].labels) == 0;
    if (!same)
        return;
    std::vector<uint8_t> gone(vec.size(), 0);
    for (size_t i = 0; i < idx.size();)
    {
        size_t j = i + 1;
        auto& keep = vec[idx[i]];
        while (j < idx.size() && compare_labels(keep.labels, vec[idx[j]].labels) == 0)
        {
            auto& other = vec[idx[j]];
            for (size_t k = 0; k < m_n; ++k)
            {
                if (is_hole(other.v[k]))
                    continue;
                if (!is_hole(keep.v[k]))
                    throw eval_fail{"execution", "vector cannot contain metrics with the same labelset"};
                keep.v[k] = other.v[k];
            }
            gone[idx[j]] = 1;
            ++j;
        }
        i = j;
    }
    size_t o = 0;
    for (size_t i = 0; i < vec.size(); ++i)
        if (!gone[i])
        {
            if (o != i)
                vec[o] = std::move(vec[i]);
            ++o;
        }
    release((vec.size() - o) * m_n);
    vec.resize(o);
}

void evaluator::drop_empty(std::vector<vseries>& vec)
{
    const size_t before = vec.size();
    std::erase_if(vec, [](const vseries& s) {
        return std::all_of(s.v.begin(), s.v.end(), [](double v) { return is_hole(v); });
    });
    release((before - vec.size()) * m_n);
}

value evaluator::eval(const expr_node& e)
{
    tick(1);
    switch (e.k)
    {
        case expr_node::kind::number: return scalar_value(e.num);
        case expr_node::kind::string:
        {
            value out;
            out.type = V::string;
            out.str = e.str;
            return out;
        }
        case expr_node::kind::paren: return eval(*e.args[0]);
        case expr_node::kind::vector_sel: return vector_selector(e, false);
        case expr_node::kind::matrix_sel:
            throw eval_fail{"execution", "a range vector is only an argument to a function"};
        case expr_node::kind::unary:
        {
            value v = eval(*e.args[0]);
            for (double& x : v.s)
                x = -x;
            for (auto& s : v.vec)
            {
                drop_name(s.labels);
                for (double& x : s.v)
                    if (!is_hole(x))
                        x = -x;
            }
            dedupe(v.vec);
            v.sort = 0;
            return v;
        }
        case expr_node::kind::call: return call(e);
        case expr_node::kind::aggregate: return aggregate(e);
        case expr_node::kind::binary: return binary(e);
    }
    return {};
}

value evaluator::binary(const expr_node& e)
{
    value l = eval(*e.args[0]);
    value r = eval(*e.args[1]);
    const bin_op op = e.op;
    if (l.type == V::scalar && r.type == V::scalar)
    {
        for (size_t k = 0; k < m_n; ++k)
        {
            bool keep = true;
            const double v = elem_op(op, l.s[k], r.s[k], keep);
            l.s[k] = is_comparison(op) ? (keep ? 1.0 : 0.0) : v;
        }
        release(held(r));
        return l;
    }
    if (l.type == V::scalar || r.type == V::scalar)
    {
        const bool swap = l.type == V::scalar;
        value& vec = swap ? r : l;
        const value& sc = swap ? l : r;
        const bool drop = is_arithmetic(op) || e.return_bool;
        for (auto& s : vec.vec)
        {
            if (drop)
                drop_name(s.labels);
            for (size_t k = 0; k < m_n; ++k)
            {
                if (is_hole(s.v[k]))
                    continue;
                double lf = s.v[k], rf = sc.s[k];
                if (swap)
                    std::swap(lf, rf);
                bool keep = true;
                double v = elem_op(op, lf, rf, keep);
                // A comparison keeps the vector's value even where the scalar stands on its left.
                if (is_comparison(op) && swap)
                    v = rf;
                if (e.return_bool)
                {
                    v = keep ? 1.0 : 0.0;
                    keep = true;
                }
                s.v[k] = keep ? v : hole();
            }
        }
        release(held(sc));
        drop_empty(vec.vec);
        if (drop)
            dedupe(vec.vec);
        vec.sort = 0;
        return std::move(vec);
    }
    const uint64_t inputs = held(l) + held(r);
    value out = op >= bin_op::land ? set_op(e, l, r) : vector_op(e, l, r);
    release(inputs);
    return out;
}

std::string evaluator::signature(const label_set& ls, bool on, const std::vector<std::string>& names)
{
    std::string key;
    for (const auto& l : ls)
    {
        const bool in = listed(names, l.name);
        if (on ? in : (!in && l.name != name_label))
            key_into(key, l);
    }
    return key;
}

value evaluator::set_op(const expr_node& e, value& l, value& r)
{
    std::unordered_map<std::string, uint32_t> sigs;
    auto sig_of = [&](const label_set& ls) {
        return sigs.try_emplace(signature(ls, e.on, e.match_labels), static_cast<uint32_t>(sigs.size()))
            .first->second;
    };
    std::vector<uint32_t> ls(l.vec.size()), rs(r.vec.size());
    for (size_t i = 0; i < l.vec.size(); ++i)
        ls[i] = sig_of(l.vec[i].labels);
    for (size_t j = 0; j < r.vec.size(); ++j)
        rs[j] = sig_of(r.vec[j].labels);
    std::vector<int64_t> mark(sigs.size(), -1);
    value out;
    out.type = V::vector;
    if (e.op == bin_op::lor)
    {
        for (size_t k = 0; k < m_n; ++k)
        {
            for (size_t i = 0; i < l.vec.size(); ++i)
                if (!is_hole(l.vec[i].v[k]))
                    mark[ls[i]] = static_cast<int64_t>(k);
            for (size_t j = 0; j < r.vec.size(); ++j)
                if (mark[rs[j]] == static_cast<int64_t>(k))
                    r.vec[j].v[k] = hole();
        }
        out.vec = std::move(l.vec);
        for (auto& s : r.vec)
            out.vec.push_back(std::move(s));
        charge(held(out));
        drop_empty(out.vec);
        dedupe(out.vec);
        return out;
    }
    for (size_t k = 0; k < m_n; ++k)
    {
        for (size_t j = 0; j < r.vec.size(); ++j)
            if (!is_hole(r.vec[j].v[k]))
                mark[rs[j]] = static_cast<int64_t>(k);
        for (size_t i = 0; i < l.vec.size(); ++i)
        {
            const bool matched = mark[ls[i]] == static_cast<int64_t>(k);
            if (matched != (e.op == bin_op::land))
                l.vec[i].v[k] = hole();
        }
    }
    out.vec = std::move(l.vec);
    charge(held(out));
    drop_empty(out.vec);
    return out;
}

value evaluator::vector_op(const expr_node& e, value& l, value& r)
{
    const bool swap = e.cardinality == card::one_to_many;
    // The many side, and the one side each of its series is matched against; for one-to-one simply left and right.
    std::vector<vseries>& many = swap ? r.vec : l.vec;
    std::vector<vseries>& one = swap ? l.vec : r.vec;
    std::unordered_map<std::string, uint32_t> sigs;
    auto sig_of = [&](const label_set& ls) {
        return sigs.try_emplace(signature(ls, e.on, e.match_labels), static_cast<uint32_t>(sigs.size()))
            .first->second;
    };
    std::vector<uint32_t> ms(many.size()), os(one.size());
    for (size_t i = 0; i < many.size(); ++i)
        ms[i] = sig_of(many[i].labels);
    for (size_t j = 0; j < one.size(); ++j)
        os[j] = sig_of(one[j].labels);
    const size_t nsig = sigs.size();
    std::vector<int64_t> one_at(nsig, -1), matched_at(nsig, -1);
    std::vector<uint32_t> pick(nsig, 0);

    value out;
    out.type = V::vector;
    std::unordered_map<uint64_t, uint32_t> pairs;
    std::unordered_map<std::string, uint32_t> by_labels;
    std::vector<int64_t> written_at;
    std::vector<uint32_t> written_sig;
    std::string key;
    auto out_of = [&](uint32_t i, uint32_t j) {
        const uint64_t pk = (static_cast<uint64_t>(i) << 32) | j;
        if (auto it = pairs.find(pk); it != pairs.end())
            return it->second;
        label_set ls = many[i].labels;
        if (is_arithmetic(e.op) || e.return_bool)
            drop_name(ls);
        if (e.cardinality == card::one_to_one)
        {
            if (e.on)
                std::erase_if(ls, [&](const label& x) { return !listed(e.match_labels, x.name); });
            else
                std::erase_if(ls, [&](const label& x) { return listed(e.match_labels, x.name); });
        }
        for (const auto& name : e.include)
            set_label(ls, name, label_value(one[j].labels, name));
        key.clear();
        for (const auto& x : ls)
            key_into(key, x);
        auto [it, fresh] = by_labels.try_emplace(key, static_cast<uint32_t>(out.vec.size()));
        if (fresh)
        {
            charge(m_n);
            out.vec.push_back({std::move(ls), std::vector<double>(m_n, hole())});
            written_at.push_back(-1);
            written_sig.push_back(0);
        }
        pairs.emplace(pk, it->second);
        return it->second;
    };

    for (size_t k = 0; k < m_n; ++k)
    {
        const auto step = static_cast<int64_t>(k);
        for (size_t j = 0; j < one.size(); ++j)
        {
            if (is_hole(one[j].v[k]))
                continue;
            const uint32_t s = os[j];
            if (one_at[s] == step)
            {
                label_set match;
                for (const auto& x : one[j].labels)
                {
                    const bool in = listed(e.match_labels, x.name);
                    if (e.on ? in : (!in && x.name != name_label))
                        match.push_back(x);
                }
                throw eval_fail{"execution",
                                "found duplicate series for the match group " + labels_string(match) + " on the " +
                                    (swap ? "left" : "right") + " hand-side of the operation: [" +
                                    labels_string(one[j].labels) + ", " + labels_string(one[pick[s]].labels) +
                                    "];many-to-many matching not allowed: matching labels must be unique on one side"};
            }
            one_at[s] = step;
            pick[s] = static_cast<uint32_t>(j);
        }
        for (size_t i = 0; i < many.size(); ++i)
        {
            if (is_hole(many[i].v[k]))
                continue;
            const uint32_t s = ms[i];
            if (one_at[s] != step)
                continue;
            const uint32_t j = pick[s];
            double fl = many[i].v[k], fr = one[j].v[k];
            if (swap)
                std::swap(fl, fr);
            bool keep = true;
            double v = elem_op(e.op, fl, fr, keep);
            if (e.return_bool)
                v = keep ? 1.0 : 0.0;
            else if (!keep)
                continue;
            if (e.cardinality == card::one_to_one)
            {
                if (matched_at[s] == step)
                    throw eval_fail{"execution", "multiple matches for labels: many-to-one matching must be explicit "
                                                 "(group_left/group_right)"};
                matched_at[s] = step;
            }
            const uint32_t o = out_of(static_cast<uint32_t>(i), j);
            if (written_at[o] == step)
                throw eval_fail{"execution", written_sig[o] == s && e.cardinality != card::one_to_one
                                                 ? "multiple matches for labels: grouping labels must ensure unique "
                                                   "matches"
                                                 : "vector cannot contain metrics with the same labelset"};
            written_at[o] = step;
            written_sig[o] = s;
            out.vec[o].v[k] = v;
        }
        tick(many.size() + one.size());
    }
    return out;
}

value evaluator::aggregate(const expr_node& e)
{
    value param;
    if (e.args.size() == 2)
        param = eval(*e.args[0]);
    value in = eval(*e.args.back());
    const agg_op op = e.agg;
    value out;
    out.type = V::vector;

    // count_values sets its label before it groups, so the input's own value of that label never counts.
    const std::string& value_label = param.str;
    if (op == agg_op::count_values)
    {
        bool valid = !value_label.empty() && !(value_label[0] >= '0' && value_label[0] <= '9');
        for (char c : value_label)
            valid = valid && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (c >= '0' && c <= '9'));
        if (!valid)
            throw eval_fail{"execution", "invalid label name \"" + value_label + "\""};
    }

    // Every series' group, from the labels `by` keeps or `without` leaves, the name always among the latter.
    std::unordered_map<std::string, uint32_t> groups;
    std::vector<uint32_t> gid(in.vec.size());
    std::vector<label_set> glabels;
    std::string key;
    for (size_t i = 0; i < in.vec.size(); ++i)
    {
        label_set ls;
        key.clear();
        for (const auto& l : in.vec[i].labels)
        {
            const bool in_list = listed(e.grouping, l.name);
            if (op == agg_op::count_values && l.name == value_label)
                continue;
            if (e.without ? (!in_list && l.name != name_label) : in_list)
            {
                ls.push_back(l);
                key_into(key, l);
            }
        }
        auto [it, fresh] = groups.try_emplace(key, static_cast<uint32_t>(glabels.size()));
        if (fresh)
            glabels.push_back(std::move(ls));
        gid[i] = it->second;
    }
    const size_t ng = glabels.size();

    if (op == agg_op::topk || op == agg_op::bottomk)
    {
        std::vector<std::vector<uint32_t>> heaps(ng);
        std::vector<int64_t> seen(ng, -1);
        std::vector<uint32_t> touched;
        std::vector<int64_t> out_of(in.vec.size(), -1);
        std::vector<double> vals(in.vec.size());
        for (size_t k = 0; k < m_n; ++k)
        {
            const double p = param.s[k];
            if (std::isnan(p) || p < 1)
                continue;
            if (p > 9.2e18)
                throw eval_fail{"execution", "Scalar value " + std::to_string(p) + " overflows int64"};
            const auto kk = std::min<uint64_t>(static_cast<uint64_t>(p), in.vec.size());
            touched.clear();
            for (size_t i = 0; i < in.vec.size(); ++i)
            {
                const double x = in.vec[i].v[k];
                if (is_hole(x))
                    continue;
                vals[i] = x;
                const uint32_t g = gid[i];
                k_heap h{&heaps[g], &vals, op == agg_op::topk};
                if (seen[g] != static_cast<int64_t>(k))
                {
                    seen[g] = static_cast<int64_t>(k);
                    heaps[g].assign(1, static_cast<uint32_t>(i));
                    touched.push_back(g);
                    continue;
                }
                const double head = vals[heaps[g][0]];
                if (heaps[g].size() < kk)
                    h.push(static_cast<uint32_t>(i));
                else if ((op == agg_op::topk ? head < x : head > x) || (std::isnan(head) && !std::isnan(x)))
                {
                    heaps[g][0] = static_cast<uint32_t>(i);
                    if (kk > 1)
                        h.fix0();
                }
            }
            for (uint32_t g : touched)
            {
                auto& hp = heaps[g];
                // The output of an instant query lists the best first, as Prometheus sorts the heap.
                std::stable_sort(hp.begin(), hp.end(), [&](uint32_t a, uint32_t b) {
                    const double x = vals[a], y = vals[b];
                    if (std::isnan(y))
                        return !std::isnan(x);
                    if (std::isnan(x))
                        return false;
                    return op == agg_op::topk ? x > y : x < y;
                });
                for (uint32_t i : hp)
                {
                    if (out_of[i] < 0)
                    {
                        charge(m_n);
                        out_of[i] = static_cast<int64_t>(out.vec.size());
                        out.vec.push_back({in.vec[i].labels, std::vector<double>(m_n, hole())});
                    }
                    out.vec[static_cast<size_t>(out_of[i])].v[k] = vals[i];
                }
            }
            tick(in.vec.size());
        }
        release(held(in) + held(param));
        return out;
    }

    if (op == agg_op::count_values)
    {
        const std::string& lname = value_label;
        std::unordered_map<std::string, uint32_t> outs;
        std::string text;
        for (size_t k = 0; k < m_n; ++k)
        {
            for (size_t i = 0; i < in.vec.size(); ++i)
            {
                const double x = in.vec[i].v[k];
                if (is_hole(x))
                    continue;
                text.clear();
                if (std::isnan(x))
                    text = "NaN";
                else if (std::isinf(x))
                    text = x > 0 ? "+Inf" : "-Inf";
                else
                    format_go_float(x, false, text);
                key = std::to_string(gid[i]);
                key += '\xff';
                key += text;
                auto [it, fresh] = outs.try_emplace(key, static_cast<uint32_t>(out.vec.size()));
                if (fresh)
                {
                    charge(m_n);
                    label_set ls = glabels[gid[i]];
                    set_label(ls, lname, text);
                    out.vec.push_back({std::move(ls), std::vector<double>(m_n, hole())});
                }
                double& slot = out.vec[it->second].v[k];
                slot = is_hole(slot) ? 1.0 : slot + 1;
            }
            tick(in.vec.size());
        }
        release(held(in));
        return out;
    }

    charge(ng * m_n);
    out.vec.reserve(ng);
    for (auto& ls : glabels)
        out.vec.push_back({std::move(ls), std::vector<double>(m_n, hole())});
    struct state
    {
        double value, mean, c, count;
        bool incremental;
    };
    std::vector<state> st(ng);
    std::vector<int64_t> seen(ng, -1);
    std::vector<uint32_t> touched;
    std::vector<std::vector<double>> qv(op == agg_op::quantile ? ng : 0);
    for (size_t k = 0; k < m_n; ++k)
    {
        const auto step = static_cast<int64_t>(k);
        touched.clear();
        for (size_t i = 0; i < in.vec.size(); ++i)
        {
            const double f = in.vec[i].v[k];
            if (is_hole(f))
                continue;
            const uint32_t g = gid[i];
            state& a = st[g];
            if (seen[g] != step)
            {
                seen[g] = step;
                touched.push_back(g);
                a = {f, f, 0, 1, false};
                if (op == agg_op::stddev || op == agg_op::stdvar)
                    a.value = 0;
                else if (op == agg_op::group)
                    a.value = 1;
                else if (op == agg_op::quantile)
                    qv[g].assign(1, f);
                continue;
            }
            switch (op)
            {
                case agg_op::sum: kahan_inc(f, a.value, a.c); break;
                case agg_op::avg:
                {
                    a.count += 1;
                    if (!a.incremental)
                    {
                        double nv = a.value, nc = a.c;
                        kahan_inc(f, nv, nc);
                        if (!std::isinf(nv))
                        {
                            a.value = nv;
                            a.c = nc;
                            break;
                        }
                        a.incremental = true;
                        a.mean = a.value / (a.count - 1);
                        a.c /= a.count - 1;
                    }
                    if (std::isinf(a.mean))
                    {
                        if (std::isinf(f) && (a.mean > 0) == (f > 0))
                            break;
                        if (!std::isinf(f) && !std::isnan(f))
                            break;
                    }
                    const double cur = a.mean + a.c;
                    kahan_inc(f / a.count - cur / a.count, a.mean, a.c);
                    break;
                }
                case agg_op::max:
                    if (a.value < f || std::isnan(a.value))
                        a.value = f;
                    break;
                case agg_op::min:
                    if (a.value > f || std::isnan(a.value))
                        a.value = f;
                    break;
                case agg_op::count: a.count += 1; break;
                case agg_op::stddev: case agg_op::stdvar:
                {
                    a.count += 1;
                    const double delta = f - a.mean;
                    a.mean += delta / a.count;
                    a.value += delta * (f - a.mean);
                    break;
                }
                case agg_op::quantile: qv[g].push_back(f); break;
                default: break;
            }
        }
        for (uint32_t g : touched)
        {
            const state& a = st[g];
            double v = a.value;
            switch (op)
            {
                case agg_op::sum: v = a.value + a.c; break;
                case agg_op::avg: v = a.incremental ? a.mean + a.c : (a.value + a.c) / a.count; break;
                case agg_op::count: v = a.count; break;
                case agg_op::stdvar: v = a.value / a.count; break;
                case agg_op::stddev: v = std::sqrt(a.value / a.count); break;
                case agg_op::quantile: v = quantile_of(param.s[k], qv[g]); break;
                default: break;
            }
            out.vec[g].v[k] = v;
        }
        tick(in.vec.size());
    }
    release(held(in) + held(param));
    return out;
}

value evaluator::call(const expr_node& e)
{
    const fn f = e.func->id;
    if (is_range_fn(f))
        return range_call(e);
    switch (f)
    {
        case fn::pi: return scalar_value(std::numbers::pi);
        case fn::time:
        {
            value out = scalar_value(0);
            for (size_t k = 0; k < m_n; ++k)
                out.s[k] = static_cast<double>(m_start + static_cast<int64_t>(k) * std::max<int64_t>(m_step, 0)) /
                           1000;
            return out;
        }
        case fn::vector:
        {
            value s = eval(*e.args[0]);
            value out;
            out.type = V::vector;
            charge(m_n);
            out.vec.push_back({{}, std::move(s.s)});
            return out;
        }
        case fn::scalar:
        {
            value in = eval(*e.args[0]);
            value out = scalar_value(nan_v);
            for (size_t k = 0; k < m_n; ++k)
            {
                size_t count = 0;
                double last = 0;
                for (const auto& s : in.vec)
                    if (!is_hole(s.v[k]))
                    {
                        ++count;
                        last = s.v[k];
                    }
                if (count == 1)
                    out.s[k] = last;
            }
            release(held(in));
            return out;
        }
        case fn::absent:
        {
            value in = eval(*e.args[0]);
            auto& row = m_sc.row;
            row.assign(m_n, 1.0);
            for (const auto& s : in.vec)
                for (size_t k = 0; k < m_n; ++k)
                    if (!is_hole(s.v[k]))
                        row[k] = hole();
            release(held(in));
            value out;
            out.type = V::vector;
            emit_row(out, absent_labels(*e.args[0]), false);
            return out;
        }
        case fn::timestamp:
        {
            const expr_node& a = unparen(*e.args[0]);
            if (a.k == expr_node::kind::vector_sel)
                return vector_selector(a, true);
            value v = eval(a);
            for (auto& s : v.vec)
            {
                drop_name(s.labels);
                for (size_t k = 0; k < m_n; ++k)
                    if (!is_hole(s.v[k]))
                        s.v[k] = static_cast<double>(m_start + static_cast<int64_t>(k) * std::max<int64_t>(m_step, 0)) /
                                 1000;
            }
            dedupe(v.vec);
            v.sort = 0;
            return v;
        }
        case fn::sort: case fn::sort_desc:
        {
            value v = eval(*e.args[0]);
            v.sort = f == fn::sort ? 1 : -1;
            return v;
        }
        case fn::label_replace: return label_replace(e);
        case fn::label_join: return label_join(e);
        case fn::histogram_quantile: return histogram_quantile(e);
        case fn::day_of_month: case fn::day_of_week: case fn::day_of_year: case fn::days_in_month: case fn::hour:
        case fn::minute: case fn::month: case fn::year:
        {
            value v;
            if (e.args.empty())
            {
                v.type = V::vector;
                value t = scalar_value(0);
                for (size_t k = 0; k < m_n; ++k)
                    t.s[k] = static_cast<double>(m_start + static_cast<int64_t>(k) * std::max<int64_t>(m_step, 0)) /
                             1000;
                charge(m_n);
                v.vec.push_back({{}, std::move(t.s)});
            }
            else
                v = eval(*e.args[0]);
            for (auto& s : v.vec)
            {
                drop_name(s.labels);
                for (double& x : s.v)
                    if (!is_hole(x))
                        x = date_part(f, x);
            }
            dedupe(v.vec);
            v.sort = 0;
            return v;
        }
        default: break;
    }

    // The functions left map each value of their vector, scalars at the same step as their parameters.
    value v = eval(*e.args[0]);
    value a1, a2;
    if (e.args.size() > 1)
        a1 = eval(*e.args[1]);
    if (e.args.size() > 2)
        a2 = eval(*e.args[2]);
    const unary_fn m = math_of(f);
    for (auto& s : v.vec)
    {
        drop_name(s.labels);
        for (size_t k = 0; k < m_n; ++k)
        {
            double& x = s.v[k];
            if (is_hole(x))
                continue;
            if (m)
            {
                x = m(x);
                continue;
            }
            switch (f)
            {
                case fn::round:
                {
                    const double inv = 1.0 / (a1.s.empty() ? 1.0 : a1.s[k]);
                    x = std::floor(x * inv + 0.5) / inv;
                    break;
                }
                case fn::clamp:
                    x = a2.s[k] < a1.s[k] ? hole() : go_max(a1.s[k], go_min(a2.s[k], x));
                    break;
                case fn::clamp_min: x = go_max(a1.s[k], x); break;
                case fn::clamp_max: x = go_min(a1.s[k], x); break;
                default: break;
            }
        }
    }
    release(held(a1) + held(a2));
    drop_empty(v.vec);
    dedupe(v.vec);
    v.sort = 0;
    return v;
}

value evaluator::label_replace(const expr_node& e)
{
    value v = eval(*e.args[0]);
    const std::string& dst = e.args[1]->str;
    const std::string& repl = e.args[2]->str;
    const std::string& src = e.args[3]->str;
    const std::string& pattern = e.args[4]->str;
    regex re;
    std::string why;
    if (!re.compile(pattern, why))
        throw eval_fail{"execution", "invalid regular expression in label_replace(): " + pattern};
    bool valid = !dst.empty() && !(dst[0] >= '0' && dst[0] <= '9');
    for (char c : dst)
        valid = valid && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (c >= '0' && c <= '9'));
    if (!valid)
        throw eval_fail{"execution", "invalid destination label name in label_replace(): " + dst};
    std::vector<int> groups;
    std::string res;
    for (auto& s : v.vec)
    {
        const std::string_view sv = label_value(s.labels, src);
        if (!re.matches(sv, groups))
            continue;
        // Go's Regexp.Expand: $n, ${n}, $name and ${name}, the longest run of word characters taken as the name.
        res.clear();
        for (size_t i = 0; i < repl.size();)
        {
            if (repl[i] != '$')
            {
                res += repl[i++];
                continue;
            }
            ++i;
            if (i < repl.size() && repl[i] == '$')
            {
                res += '$';
                ++i;
                continue;
            }
            const bool brace = i < repl.size() && repl[i] == '{';
            size_t j = brace ? i + 1 : i;
            const size_t name_from = j;
            while (j < repl.size() && ((repl[j] >= 'a' && repl[j] <= 'z') || (repl[j] >= 'A' && repl[j] <= 'Z') ||
                                       (repl[j] >= '0' && repl[j] <= '9') || repl[j] == '_'))
                ++j;
            const std::string_view name(repl.data() + name_from, j - name_from);
            if (name.empty() || (brace && (j >= repl.size() || repl[j] != '}')))
            {
                res += '$';
                continue;
            }
            i = brace ? j + 1 : j;
            int num = 0;
            for (char c : name)
            {
                if (c < '0' || c > '9' || num >= 100000000)
                {
                    num = -1;
                    break;
                }
                num = num * 10 + (c - '0');
            }
            if (name.size() > 1 && name[0] == '0')
                num = -1;
            const int g = num >= 0 ? num : re.group_named(name);
            if (g >= 0 && g < re.group_count() && groups[2 * static_cast<size_t>(g)] >= 0)
                res.append(sv.substr(static_cast<size_t>(groups[2 * static_cast<size_t>(g)]),
                                     static_cast<size_t>(groups[2 * static_cast<size_t>(g) + 1] -
                                                         groups[2 * static_cast<size_t>(g)])));
        }
        set_label(s.labels, dst, res);
    }
    dedupe(v.vec);
    v.sort = 0;
    return v;
}

value evaluator::label_join(const expr_node& e)
{
    value v = eval(*e.args[0]);
    const std::string& dst = e.args[1]->str;
    const std::string& sep = e.args[2]->str;
    auto valid = [](const std::string& n) {
        bool ok = !n.empty() && !(n[0] >= '0' && n[0] <= '9');
        for (char c : n)
            ok = ok && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (c >= '0' && c <= '9'));
        return ok;
    };
    if (!valid(dst))
        throw eval_fail{"execution", "invalid destination label name in label_join(): " + dst};
    for (size_t i = 3; i < e.args.size(); ++i)
        if (!valid(e.args[i]->str))
            throw eval_fail{"execution", "invalid source label name in label_join(): " + e.args[i]->str};
    std::string res;
    for (auto& s : v.vec)
    {
        res.clear();
        for (size_t i = 3; i < e.args.size(); ++i)
        {
            if (i > 3)
                res += sep;
            res += label_value(s.labels, e.args[i]->str);
        }
        set_label(s.labels, dst, res);
    }
    dedupe(v.vec);
    v.sort = 0;
    return v;
}

value evaluator::histogram_quantile(const expr_node& e)
{
    value q = eval(*e.args[0]);
    value in = eval(*e.args[1]);
    std::unordered_map<std::string, uint32_t> groups;
    std::vector<int64_t> gid(in.vec.size(), -1);
    std::vector<double> les(in.vec.size(), 0);
    std::vector<label_set> glabels;
    std::string key;
    for (size_t i = 0; i < in.vec.size(); ++i)
    {
        const auto& ls = in.vec[i].labels;
        const std::string_view le = label_value(ls, "le");
        double bound = 0;
        if (le.empty() || !parse_go_float(le, bound))
            continue;
        les[i] = bound;
        label_set g;
        key.clear();
        for (const auto& l : ls)
            if (l.name != "le" && l.name != name_label)
            {
                g.push_back(l);
                key_into(key, l);
            }
        auto [it, fresh] = groups.try_emplace(key, static_cast<uint32_t>(glabels.size()));
        if (fresh)
            glabels.push_back(std::move(g));
        gid[i] = it->second;
    }
    value out;
    out.type = V::vector;
    charge(glabels.size() * m_n);
    for (auto& g : glabels)
        out.vec.push_back({std::move(g), std::vector<double>(m_n, hole())});
    std::vector<std::vector<bucket>> buckets(out.vec.size());
    std::vector<int64_t> seen(out.vec.size(), -1);
    std::vector<uint32_t> touched;
    for (size_t k = 0; k < m_n; ++k)
    {
        touched.clear();
        for (size_t i = 0; i < in.vec.size(); ++i)
        {
            if (gid[i] < 0 || is_hole(in.vec[i].v[k]))
                continue;
            const auto g = static_cast<uint32_t>(gid[i]);
            if (seen[g] != static_cast<int64_t>(k))
            {
                seen[g] = static_cast<int64_t>(k);
                buckets[g].clear();
                touched.push_back(g);
            }
            buckets[g].push_back({les[i], in.vec[i].v[k]});
        }
        for (uint32_t g : touched)
            out.vec[g].v[k] = bucket_quantile(q.s[k], buckets[g]);
        tick(in.vec.size());
    }
    release(held(in) + held(q));
    drop_empty(out.vec);
    return out;
}

void evaluator::top_matrix(const expr_node& e, std::vector<result_series>& out)
{
    const int64_t te = m_start - e.offset_ms, range = e.range_ms;
    std::vector<uint32_t> ids;
    select(e, te - range + 1, te, ids);
    ++m_stats.raw_selectors;
    auto& smp = m_sc.samples;
    for (uint32_t id : ids)
    {
        smp.clear();
        m_src.samples(id, te - range + 1, te, smp);
        m_stats.raw_samples += smp.size();
        std::erase_if(smp, [](const sample& x) { return is_stale(x.v); });
        if (smp.empty())
            continue;
        charge(smp.size());
        result_series rs;
        rs.labels = m_src.labels(id);
        rs.points = smp;
        for (auto& p : rs.points)
            p.v = canon(p.v);
        out.push_back(std::move(rs));
        tick(smp.size());
    }
}

}   // namespace socketley::metrics
