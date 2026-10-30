#include "metrics_rules.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <map>

#include "../../shared/json/json_escape.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/util/logging.h"
#include "metrics_index.h"
#include "metrics_promql.h"
#include "metrics_promql_eval.h"

namespace socketley::metrics
{

namespace
{

constexpr int64_t default_every_ms = 10'000;
// A pending alert's progress is restored only from state written this recently, as Prometheus's outage tolerance.
constexpr int64_t outage_tolerance_ms = 3'600'000;
// A restored alert is held this many evaluations without its condition, so a store still filling does not resolve it.
constexpr int64_t restore_grace_evals = 3;
constexpr std::string_view state_magic = "socketley-rules-state 1";

bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
bool is_digit(char c) { return c >= '0' && c <= '9'; }

bool is_label_name(std::string_view s)
{
    if (s.empty() || !is_alpha(s[0]))
        return false;
    return std::all_of(s.begin(), s.end(), [](char c) { return is_alpha(c) || is_digit(c); });
}

bool is_metric_name(std::string_view s)
{
    if (s.empty() || !(is_alpha(s[0]) || s[0] == ':'))
        return false;
    return std::all_of(s.begin(), s.end(), [](char c) { return is_alpha(c) || is_digit(c) || c == ':'; });
}

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r'; }

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (is_space(s.front()) || s.front() == '\n'))
        s.remove_prefix(1);
    while (!s.empty() && (is_space(s.back()) || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

int64_t floor_to(int64_t t, int64_t step)
{
    const int64_t q = t / step;
    return (t % step != 0 && t < 0 ? q - 1 : q) * step;
}

std::string duration_text(int64_t ms)
{
    if (ms % 3'600'000 == 0 && ms > 0)
        return std::to_string(ms / 3'600'000) + "h";
    if (ms % 60'000 == 0 && ms > 0)
        return std::to_string(ms / 60'000) + "m";
    if (ms % 1000 == 0)
        return std::to_string(ms / 1000) + "s";
    return std::to_string(ms) + "ms";
}

// ── values as Go's fmt writes them ──

// %v of a float64: the shortest digits, in 'e' form below 1e-4 and from 1e21.
void go_v(double v, std::string& out)
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
    if (v == 0)
    {
        out += std::signbit(v) ? "-0" : "0";
        return;
    }
    char buf[64];
    const auto r = std::to_chars(buf, buf + sizeof buf, v, std::chars_format::scientific);
    const std::string_view sci(buf, static_cast<size_t>(r.ptr - buf));
    int exp10 = 0;
    const size_t e = sci.find('e');
    std::from_chars(sci.data() + e + 1 + (sci[e + 1] == '+'), sci.data() + sci.size(), exp10);
    format_go_float(v, exp10 < -4 || exp10 >= 21, out);
}

// C's %.4g as Go writes it, which spells the non-finite values its own way.
void g4(double v, std::string_view suffix, std::string& out)
{
    if (std::isnan(v))
        out += "NaN";
    else if (std::isinf(v))
        out += v > 0 ? "+Inf" : "-Inf";
    else
    {
        char buf[64];
        std::snprintf(buf, sizeof buf, "%.4g", v);
        out += buf;
    }
    out += suffix;
}

void humanize(double v, std::string& out)
{
    if (v == 0 || !std::isfinite(v))
        return g4(v, "", out);
    static constexpr const char* big[] = {"k", "M", "G", "T", "P", "E", "Z", "Y"};
    static constexpr const char* small[] = {"m", "u", "n", "p", "f", "a", "z", "y"};
    const char* prefix = "";
    if (std::fabs(v) >= 1)
    {
        for (const char* p : big)
        {
            if (std::fabs(v) < 1000)
                break;
            prefix = p;
            v /= 1000;
        }
    }
    else
        for (const char* p : small)
        {
            if (std::fabs(v) >= 1)
                break;
            prefix = p;
            v *= 1000;
        }
    g4(v, prefix, out);
}

void humanize1024(double v, std::string& out)
{
    if (std::fabs(v) <= 1 || !std::isfinite(v))
        return g4(v, "", out);
    static constexpr const char* big[] = {"ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"};
    const char* prefix = "";
    for (const char* p : big)
    {
        if (std::fabs(v) < 1024)
            break;
        prefix = p;
        v /= 1024;
    }
    g4(v, prefix, out);
}

void humanize_duration(double v, std::string& out)
{
    if (!std::isfinite(v))
        return g4(v, "", out);
    if (v == 0)
    {
        out += "0s";
        return;
    }
    if (std::fabs(v) >= 1)
    {
        const char* sign = v < 0 ? "-" : "";
        const double a = std::fabs(v);
        const auto d = static_cast<int64_t>(a);
        const int64_t s = d % 60, m = d / 60 % 60, h = d / 3600 % 24, days = d / 86400;
        char buf[96];
        if (days != 0)
            std::snprintf(buf, sizeof buf, "%s%lldd %lldh %lldm %llds", sign, static_cast<long long>(days),
                          static_cast<long long>(h), static_cast<long long>(m), static_cast<long long>(s));
        else if (h != 0)
            std::snprintf(buf, sizeof buf, "%s%lldh %lldm %llds", sign, static_cast<long long>(h),
                          static_cast<long long>(m), static_cast<long long>(s));
        else if (m != 0)
            std::snprintf(buf, sizeof buf, "%s%lldm %llds", sign, static_cast<long long>(m), static_cast<long long>(s));
        else
        {
            out += sign;
            return g4(a, "s", out);
        }
        out += buf;
        return;
    }
    const char* prefix = "";
    for (const char* p : {"m", "u", "n", "p", "f", "a", "z", "y"})
    {
        if (std::fabs(v) >= 1)
            break;
        prefix = p;
        v *= 1000;
    }
    g4(v, std::string(prefix) + "s", out);
}

// printf's one verb applied to a number or a string, the verb found and checked when the template was read.
void printf_one(const std::string& fmt, double num, std::string_view str, bool is_num, std::string& out)
{
    size_t at = std::string::npos;
    for (size_t i = 0; i < fmt.size(); ++i)
        if (fmt[i] == '%')
        {
            if (i + 1 < fmt.size() && fmt[i + 1] == '%')
            {
                ++i;
                continue;
            }
            at = i;
            break;
        }
    size_t verb = at + 1;
    while (verb < fmt.size() && std::string_view("-+ #0123456789.").find(fmt[verb]) != std::string_view::npos)
        ++verb;
    const char v = fmt[verb];
    std::string spec = fmt.substr(0, verb);
    const std::string tail = fmt.substr(verb + 1);
    char buf[512];
    if (v == 's' || v == 'v' || !is_num)
    {
        std::string text;
        if (is_num)
            go_v(num, text);
        else
            text.assign(str);
        spec += 's';
        spec += tail;
        std::snprintf(buf, sizeof buf, spec.c_str(), text.c_str());
    }
    else if (v == 'd')
    {
        spec += "lld";
        spec += tail;
        std::snprintf(buf, sizeof buf, spec.c_str(), std::isfinite(num) ? static_cast<long long>(num) : 0LL);
    }
    else
    {
        spec += v;
        spec += tail;
        std::snprintf(buf, sizeof buf, spec.c_str(), num);
    }
    out += buf;
}

// ── template reading ──

bool template_fail(std::string& why, std::string_view what)
{
    why = std::string(what);
    return false;
}

// The words of an action: quoted strings unquoted, `|` a word of its own.
bool action_words(std::string_view body, std::vector<std::pair<std::string, bool>>& out, std::string& why)
{
    out.clear();
    size_t i = 0;
    while (i < body.size())
    {
        if (is_space(body[i]) || body[i] == '\n')
        {
            ++i;
            continue;
        }
        if (body[i] == '|')
        {
            out.push_back({"|", false});
            ++i;
            continue;
        }
        if (body[i] == '"')
        {
            std::string s;
            ++i;
            for (;; ++i)
            {
                if (i >= body.size())
                    return template_fail(why, "an unterminated string in {{ }}");
                if (body[i] == '"')
                    break;
                if (body[i] == '\\' && i + 1 < body.size())
                {
                    const char e = body[++i];
                    s += e == 'n' ? '\n' : e == 't' ? '\t' : e;
                    continue;
                }
                s += body[i];
            }
            ++i;
            out.push_back({std::move(s), true});
            continue;
        }
        const size_t from = i;
        while (i < body.size() && !is_space(body[i]) && body[i] != '\n' && body[i] != '|' && body[i] != '"')
            ++i;
        out.push_back({std::string(body.substr(from, i - from)), false});
    }
    return true;
}

bool printf_format_ok(const std::string& f, std::string& why)
{
    int verbs = 0;
    for (size_t i = 0; i < f.size(); ++i)
    {
        if (f[i] != '%')
            continue;
        if (i + 1 < f.size() && f[i + 1] == '%')
        {
            ++i;
            continue;
        }
        size_t j = i + 1;
        while (j < f.size() && std::string_view("-+ #0").find(f[j]) != std::string_view::npos)
            ++j;
        size_t digits = 0;
        while (j < f.size() && is_digit(f[j]) && digits < 3)
            ++j, ++digits;
        if (j < f.size() && f[j] == '.')
        {
            ++j;
            digits = 0;
            while (j < f.size() && is_digit(f[j]) && digits < 2)
                ++j, ++digits;
        }
        if (j >= f.size() || std::string_view("fFeEgGdsv").find(f[j]) == std::string_view::npos)
            return template_fail(why, "printf takes one of the verbs %f %e %g %d %s %v");
        ++verbs;
        i = j;
    }
    if (verbs != 1)
        return template_fail(why, "printf takes a format with exactly one verb");
    return true;
}

bool parse_arg(const std::string& w, template_part& p, std::string& why)
{
    if (w == "$value" || w == ".Value")
    {
        p.k = template_part::kind::value;
        return true;
    }
    for (std::string_view pre : {"$labels.", ".Labels."})
        if (w.starts_with(pre) && is_label_name(std::string_view(w).substr(pre.size())))
        {
            p.k = template_part::kind::label;
            p.s = w.substr(pre.size());
            return true;
        }
    return template_fail(why, "{{ }} reads $value or $labels.<name>, not " + w);
}

bool parse_filter(const std::string& w, template_part& p)
{
    using F = template_part::filter;
    static constexpr std::pair<std::string_view, F> names[] = {
        {"humanize", F::humanize}, {"humanize1024", F::humanize1024}, {"humanizePercentage", F::percentage},
        {"humanizeDuration", F::duration}};
    for (const auto& [n, f] : names)
        if (w == n)
        {
            p.f = f;
            return true;
        }
    return false;
}

bool parse_action(std::string_view body, template_part& p, std::string& why)
{
    std::vector<std::pair<std::string, bool>> w;
    if (!action_words(body, w, why))
        return false;
    if (w.empty())
        return template_fail(why, "an empty {{ }}");
    const auto pipe = std::find_if(w.begin(), w.end(), [](const auto& x) { return !x.second && x.first == "|"; });
    std::string fmt;
    if (pipe != w.end())
    {
        // ARG | FN, or ARG | printf "FORMAT".
        if (pipe - w.begin() != 1 || w[0].second || !parse_arg(w[0].first, p, why))
            return why.empty() ? template_fail(why, "{{ x | f }} takes one value before the |") : false;
        const auto fn = pipe + 1;
        if (fn == w.end() || fn->second)
            return template_fail(why, "a function name after the |");
        if (fn->first == "printf")
        {
            if (w.end() - fn != 2 || !(fn + 1)->second)
                return template_fail(why, "printf takes its format as a quoted string");
            p.f = template_part::filter::printf;
            p.s = (fn + 1)->first;
            return printf_format_ok(p.s, why);
        }
        if (w.end() - fn != 1 || !parse_filter(fn->first, p))
            return template_fail(why, "unknown template function " + fn->first);
        return true;
    }
    if (w.size() == 1)
        return !w[0].second ? parse_arg(w[0].first, p, why) : template_fail(why, "{{ }} holds a value, not a string");
    // FN ARG, or printf "FORMAT" ARG.
    if (w[0].first == "printf" && !w[0].second)
    {
        if (w.size() != 3 || !w[1].second || w[2].second)
            return template_fail(why, "printf takes a quoted format and one value");
        p.f = template_part::filter::printf;
        if (!printf_format_ok(w[1].first, why))
            return false;
        const std::string f = w[1].first;
        if (!parse_arg(w[2].first, p, why))
            return false;
        p.s = f;
        return true;
    }
    if (w.size() != 2 || w[0].second || w[1].second || !parse_filter(w[0].first, p))
        return template_fail(why, "unknown template action {{ " + std::string(trim(body)) + " }}");
    return parse_arg(w[1].first, p, why);
}

// ── the file ──

struct logical_line
{
    std::string text;
    // Where each physical line starts in `text`, and its number.
    std::vector<std::pair<size_t, uint32_t>> starts;

    uint32_t line_at(size_t off) const
    {
        uint32_t ln = starts.front().second;
        for (const auto& [at, n] : starts)
            if (at <= off)
                ln = n;
        return ln;
    }
};

struct head_word
{
    std::string text;
    size_t off{0};
    // For `key=value`: where the `=` is, npos for a word without one.
    size_t eq{std::string::npos};
};

bool line_fail(std::string& why, uint32_t line, std::string_view what)
{
    why = "line " + std::to_string(line) + ": " + std::string(what);
    return false;
}

// The words of a rule's head up to its ` : `, and where the expression starts, npos when there is no ` : `.
bool head_words(const logical_line& l, std::vector<head_word>& out, size_t& expr_at, std::string& why)
{
    out.clear();
    expr_at = std::string::npos;
    const std::string& t = l.text;
    size_t i = 0;
    while (i < t.size())
    {
        if (is_space(t[i]) || t[i] == '\n')
        {
            ++i;
            continue;
        }
        if (t[i] == ':' && (i + 1 == t.size() || is_space(t[i + 1]) || t[i + 1] == '\n'))
        {
            expr_at = i + 1;
            return true;
        }
        head_word w;
        w.off = i;
        while (i < t.size() && !is_space(t[i]) && t[i] != '\n')
        {
            if (t[i] == '=' && w.eq == std::string::npos)
                w.eq = w.text.size();
            if (t[i] == '"' && w.eq != std::string::npos)
            {
                ++i;
                for (;; ++i)
                {
                    if (i >= t.size())
                        return line_fail(why, l.line_at(w.off), "a quoted value that does not end");
                    if (t[i] == '"')
                        break;
                    if (t[i] == '\\' && i + 1 < t.size())
                    {
                        const char e = t[++i];
                        w.text += e == 'n' ? '\n' : e == 't' ? '\t' : e;
                        continue;
                    }
                    w.text += t[i];
                }
                ++i;
                continue;
            }
            w.text += t[i++];
        }
        out.push_back(std::move(w));
    }
    return true;
}

bool parse_dur(std::string_view s, int64_t& ms)
{
    if (s == "0")
    {
        ms = 0;
        return true;
    }
    return parse_duration(s, ms);
}

bool rule_line(const logical_line& l, std::string_view source, rule_file& f, std::string& why)
{
    std::vector<head_word> w;
    size_t expr_at = 0;
    if (!head_words(l, w, expr_at, why))
        return false;
    const uint32_t ln = l.starts.front().second;
    if (w.empty())
        return line_fail(why, ln, "a ' : ' with no rule before it");
    const std::string& first = w[0].text;
    if (first.starts_with("every="))
    {
        if (w.size() != 1 || expr_at != std::string::npos)
            return line_fail(why, ln, "every= stands on a line of its own");
        if (f.every_ms != 0)
            return line_fail(why, ln, "every= is set twice");
        int64_t ms = 0;
        if (!parse_dur(std::string_view(first).substr(6), ms) || ms < 1000)
            return line_fail(why, ln, "every= takes a duration of a second or more, such as 30s");
        f.every_ms = ms;
        return true;
    }
    if (first == "off")
    {
        if (w.size() != 2 || expr_at != std::string::npos)
            return line_fail(why, ln, "off takes the name of one built-in rule");
        f.off.emplace_back(w[1].text, ln);
        return true;
    }
    rule_def r;
    r.source = std::string(source);
    r.line = ln;
    if (first == "alert")
        r.k = rule_def::kind::alert;
    else if (first == "record")
        r.k = rule_def::kind::record;
    else
        return line_fail(why, ln, "a line is alert, record, off or every=, not " + first);
    const bool alert = r.k == rule_def::kind::alert;
    size_t next = 1;
    if (w.size() < 2 || w[1].eq != std::string::npos)
        return line_fail(why, ln, alert ? "alert takes a name and a severity" : "record takes the name of a metric");
    r.name = w[1].text;
    if (alert ? !is_label_name(r.name) : !is_metric_name(r.name))
        return line_fail(why, ln, (alert ? "an alert's name is letters, digits and _, not " : "a metric's name is letters, digits, _ and :, not ") + r.name);
    next = 2;
    if (alert)
    {
        if (w.size() < 3 || w[2].eq != std::string::npos || !is_label_name(w[2].text))
            return line_fail(why, ln, "alert " + r.name + " takes a severity after its name, such as warning");
        r.severity = w[2].text;
        next = 3;
    }
    std::vector<std::string> seen;
    for (size_t i = next; i < w.size(); ++i)
    {
        const head_word& hw = w[i];
        const uint32_t at = l.line_at(hw.off);
        if (hw.eq == std::string::npos)
            return line_fail(why, at, "expected key=value or ' : ', not " + hw.text);
        const std::string key = hw.text.substr(0, hw.eq), val = hw.text.substr(hw.eq + 1);
        if (std::find(seen.begin(), seen.end(), key) != seen.end())
            return line_fail(why, at, key + "= is given twice");
        seen.push_back(key);
        int64_t* dur = key == "every" ? &r.every_ms : key == "for" ? &r.for_ms : key == "keep" ? &r.keep_ms : nullptr;
        if (dur)
        {
            if (!alert && dur != &r.every_ms)
                return line_fail(why, at, "a recording rule takes no " + key + "=");
            if (!parse_dur(val, *dur) || (dur == &r.every_ms && *dur < 1000))
                return line_fail(why, at, key + "= takes a duration such as 30s, not " + val);
            continue;
        }
        if (key == "inhibits")
        {
            if (!alert)
                return line_fail(why, at, "a recording rule inhibits nothing");
            size_t s = 0;
            while (s <= val.size())
            {
                const size_t e = std::min(val.find(',', s), val.size());
                const std::string name = val.substr(s, e - s);
                if (!is_label_name(name))
                    return line_fail(why, at, "inhibits= takes alert names separated by commas, not " + val);
                r.inhibits.push_back(name);
                s = e + 1;
            }
            continue;
        }
        rule_template t;
        std::string twhy;
        if (!parse_template(val, t, twhy))
            return line_fail(why, at, key + "=: " + twhy);
        if (key == "summary" || key == "description" || key == "runbook_url")
        {
            if (!alert)
                return line_fail(why, at, "a recording rule has no " + key + "=");
            r.annotations.emplace_back(key, std::move(t));
            continue;
        }
        if (!is_label_name(key) || key.starts_with("__"))
            return line_fail(why, at, key + " is no label's name");
        if (alert && (key == "alertname" || key == "severity"))
            return line_fail(why, at, key + "= is the alert's own; its name and severity come first on the line");
        // Empty takes the label off what the rule writes, as Prometheus does: a reason the annotations still read is
        // then no part of the alert's identity.
        if (!alert && !t.plain)
            return line_fail(why, at, "a recording rule's labels are written as they are, without {{ }}");
        r.labels.emplace_back(key, std::move(t));
    }
    std::sort(r.labels.begin(), r.labels.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    if (expr_at == std::string::npos)
        return line_fail(why, ln, r.name + " has no ' : ' before its expression");
    const std::string_view rest(l.text.data() + expr_at, l.text.size() - expr_at);
    const std::string_view expr = trim(rest);
    if (expr.empty())
        return line_fail(why, ln, r.name + " has no expression after its ' : '");
    const size_t expr_off = static_cast<size_t>(expr.data() - l.text.data());
    std::unique_ptr<expr_node> e;
    query_error err;
    if (!parse_promql(expr, query_limits{}.max_query_length, e, err))
    {
        std::string msg = err.message;
        // The parser's own line:column is the expression's; the file's line is said instead.
        if (const size_t c = msg.find(": "); c != std::string::npos && c < 12 && is_digit(msg[0]))
            msg.erase(0, c + 2);
        const size_t pos = err.position >= 0 ? expr_off + static_cast<size_t>(err.position) : expr_off;
        return line_fail(why, l.line_at(pos), r.name + ": " + msg);
    }
    if (e->type != value_type::vector && e->type != value_type::scalar)
        return line_fail(why, ln, r.name + ": the expression is a " + std::string(type_name(e->type)) +
                                      ", where a rule takes an instant vector or a scalar");
    r.expr = std::string(expr);
    for (const rule_def& o : f.rules)
        if (o.name == r.name)
            return line_fail(why, ln, r.name + " is defined twice, first on line " + std::to_string(o.line));
    f.rules.push_back(std::move(r));
    return true;
}

// ── the engine's own helpers ──

struct labels_less
{
    bool operator()(const label_set& a, const label_set& b) const { return compare_labels(a, b) < 0; }
};

void without_name(const label_set& in, label_set& out)
{
    out.clear();
    for (const label& l : in)
        if (l.name != name_label)
            out.push_back(l);
}

// Whether every label name `a` and `b` both have holds the same value in each.
bool share_labels(const label_set& a, const label_set& b)
{
    size_t i = 0, j = 0;
    while (i < a.size() && j < b.size())
    {
        if (a[i].name < b[j].name)
            ++i;
        else if (b[j].name < a[i].name)
            ++j;
        else
        {
            if (a[i].value != b[j].value)
                return false;
            ++i, ++j;
        }
    }
    return true;
}

// Milliseconds as RFC 3339 in UTC, the fraction only when there is one, as Go's time marshals.
void rfc3339(int64_t ms, std::string& out)
{
    if (ms == 0)
    {
        out += "0001-01-01T00:00:00Z";
        return;
    }
    const int64_t secs = floor_to(ms, 1000) / 1000;
    const int64_t frac = ms - secs * 1000;
    int64_t days = floor_to(secs, 86400) / 86400;
    const int64_t sod = secs - days * 86400;
    // Howard Hinnant's civil_from_days.
    days += 719468;
    const int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const int64_t doe = days - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = yoe + era * 400;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t d = doy - (153 * mp + 2) / 5 + 1;
    const int64_t m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
    char buf[96];
    std::snprintf(buf, sizeof buf, "%04lld-%02lld-%02lldT%02lld:%02lld:%02lld", static_cast<long long>(y),
                  static_cast<long long>(m), static_cast<long long>(d), static_cast<long long>(sod / 3600),
                  static_cast<long long>(sod / 60 % 60), static_cast<long long>(sod % 60));
    out += buf;
    if (frac)
    {
        std::snprintf(buf, sizeof buf, ".%03lld", static_cast<long long>(frac));
        std::string_view f(buf);
        while (f.back() == '0')
            f.remove_suffix(1);
        out += f;
    }
    out += 'Z';
}

void json_labels(const label_set& ls, std::string& out)
{
    out += '{';
    bool first = true;
    for (const label& l : ls)
    {
        if (!first)
            out += ',';
        first = false;
        json::quote_into(out, l.name);
        out += ':';
        json::quote_into(out, l.value);
    }
    out += '}';
}

void json_pairs(const std::vector<std::pair<std::string, std::string>>& ps, std::string& out)
{
    out += '{';
    for (size_t i = 0; i < ps.size(); ++i)
    {
        if (i)
            out += ',';
        json::quote_into(out, ps[i].first);
        out += ':';
        json::quote_into(out, ps[i].second);
    }
    out += '}';
}

void json_seconds(double s, std::string& out)
{
    char buf[48];
    std::snprintf(buf, sizeof buf, "%.9g", s);
    out += buf;
}

void escape_state(std::string_view s, std::string& out)
{
    for (char c : s)
    {
        if (c == '\\')
            out += "\\\\";
        else if (c == '\t')
            out += "\\t";
        else if (c == '\n')
            out += "\\n";
        else
            out += c;
    }
}

std::string unescape_state(std::string_view s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] != '\\' || i + 1 == s.size())
        {
            out += s[i];
            continue;
        }
        const char e = s[++i];
        out += e == 't' ? '\t' : e == 'n' ? '\n' : e;
    }
    return out;
}

}   // namespace

// ── templates ─────────────────────────────────────────────────────────────

bool parse_template(std::string_view text, rule_template& out, std::string& why)
{
    out = {};
    out.raw.assign(text);
    size_t i = 0;
    std::string lit;
    while (i < text.size())
    {
        const size_t open = text.find("{{", i);
        if (open == std::string_view::npos)
        {
            lit.append(text.substr(i));
            break;
        }
        lit.append(text.substr(i, open - i));
        size_t body_from = open + 2;
        if (body_from < text.size() && text[body_from] == '-' && body_from + 1 < text.size() && is_space(text[body_from + 1]))
        {
            while (!lit.empty() && (is_space(lit.back()) || lit.back() == '\n'))
                lit.pop_back();
            ++body_from;
        }
        // The action ends at the first }} outside a quoted string.
        size_t close = std::string_view::npos;
        bool quoted = false;
        for (size_t j = body_from; j + 1 < text.size(); ++j)
        {
            if (quoted)
            {
                if (text[j] == '\\')
                    ++j;
                else if (text[j] == '"')
                    quoted = false;
                continue;
            }
            if (text[j] == '"')
                quoted = true;
            else if (text[j] == '}' && text[j + 1] == '}')
            {
                close = j;
                break;
            }
        }
        if (close == std::string_view::npos)
            return template_fail(why, "a {{ that is not closed");
        size_t body_to = close;
        bool trim_after = false;
        if (body_to > body_from && text[body_to - 1] == '-' && body_to - 1 > body_from && is_space(text[body_to - 2]))
        {
            --body_to;
            trim_after = true;
        }
        template_part p;
        if (!parse_action(text.substr(body_from, body_to - body_from), p, why))
            return false;
        if (!lit.empty())
            out.parts.push_back({template_part::kind::text, template_part::filter::none, std::move(lit)});
        lit.clear();
        out.parts.push_back(std::move(p));
        out.plain = false;
        i = close + 2;
        if (trim_after)
            while (i < text.size() && (is_space(text[i]) || text[i] == '\n'))
                ++i;
    }
    if (!lit.empty())
        out.parts.push_back({template_part::kind::text, template_part::filter::none, std::move(lit)});
    return true;
}

void expand_template(const rule_template& t, const label_set& labels, double value, std::string& out)
{
    using F = template_part::filter;
    for (const template_part& p : t.parts)
    {
        if (p.k == template_part::kind::text)
        {
            out += p.s;
            continue;
        }
        const bool is_num = p.k == template_part::kind::value;
        std::string_view str;
        double num = value;
        if (!is_num)
        {
            str = label_value(labels, p.s);
            if (p.f != F::none && p.f != F::printf)
            {
                // A label read as a number, as Prometheus's humanize functions convert a string.
                const std::string s(str);
                char* end = nullptr;
                num = std::strtod(s.c_str(), &end);
                if (s.empty() || end != s.c_str() + s.size())
                {
                    out += str;
                    continue;
                }
            }
        }
        switch (p.f)
        {
            case F::none:
                if (is_num)
                    go_v(num, out);
                else
                    out += str;
                break;
            case F::humanize: humanize(num, out); break;
            case F::humanize1024: humanize1024(num, out); break;
            case F::percentage: g4(num * 100, "%", out); break;
            case F::duration: humanize_duration(num, out); break;
            case F::printf: printf_one(p.s, num, str, is_num, out); break;
        }
    }
}

// ── the file ──────────────────────────────────────────────────────────────

bool parse_rules(std::string_view text, std::string_view source, rule_file& out, std::string& why)
{
    rule_file f;
    std::vector<logical_line> lines;
    uint32_t ln = 0;
    size_t pos = 0;
    while (pos <= text.size())
    {
        size_t end = text.find('\n', pos);
        if (end == std::string_view::npos)
            end = text.size();
        std::string_view phys = text.substr(pos, end - pos);
        pos = end + 1;
        ++ln;
        if (!phys.empty() && phys.back() == '\r')
            phys.remove_suffix(1);
        const std::string_view t = trim(phys);
        if (t.empty() || t.front() == '#')
        {
            if (end == text.size())
                break;
            continue;
        }
        if (is_space(phys.front()))
        {
            if (lines.empty())
                return line_fail(why, ln, "a line that carries on a rule, with no rule above it");
            logical_line& l = lines.back();
            l.text += '\n';
            l.starts.emplace_back(l.text.size(), ln);
            l.text.append(t);
        }
        else
        {
            lines.emplace_back();
            lines.back().starts.emplace_back(0, ln);
            lines.back().text.assign(t);
        }
        if (end == text.size())
            break;
    }
    for (const logical_line& l : lines)
        if (!rule_line(l, source, f, why))
            return false;
    out = std::move(f);
    return true;
}

std::string_view builtin_rules()
{
    return R"(# socketley's own alerts over the series the daemon's /metrics writes, `name` the runtime: one reading is 10s, a
# condition held for N readings is for=N*10s, and keep=20s clears an alert at its third reading without it. A label
# set empty is left out of the alert, so a reason that changes words is still the same alert.
every=10s

alert RuntimeFailed critical keep=20s inhibits=SyncFailing reason=""
    summary="{{ $labels.name }} failed"
    description="{{ $labels.reason }}"
    : socketley_runtime_failure == 1

alert SyncFailing warning for=30s keep=20s
    summary="{{ $labels.name }} cannot carry everything it owes"
    description="{{ $value }} failures since the last thing it carried"
    : socketley_sync_failing > 0

alert RuntimeRestarting warning keep=20s
    summary="{{ $labels.name }} was started again {{ $value | printf \"%.0f\" }} times in the last hour"
    : increase(socketley_runtime_restarts_total[1h]) >= 3

alert CertificateEnded critical keep=20s inhibits=CertificateExpiringSoon,CertificateExpiring
    summary="The certificate of {{ $labels.name }} has ended"
    description="{{ $labels.path }}"
    : socketley_cert_expiry_seconds < 0
alert CertificateExpiringSoon critical keep=20s inhibits=CertificateExpiring
    summary="The certificate of {{ $labels.name }} ends in {{ $value | printf \"%.1f\" }} days"
    description="{{ $labels.path }}"
    : socketley_cert_expiry_seconds / 86400 < 3
alert CertificateExpiring warning keep=20s
    summary="The certificate of {{ $labels.name }} ends in {{ $value | printf \"%.0f\" }} days"
    description="{{ $labels.path }}"
    : socketley_cert_expiry_seconds / 86400 < 14

alert DiskSpaceCritical critical for=30s keep=20s inhibits=DiskSpaceLow
    summary="The disk of {{ $labels.path }} has {{ $value | humanizePercentage }} free"
    : socketley_disk_free_ratio < 0.05
alert DiskSpaceLow warning for=30s keep=20s
    summary="The disk of {{ $labels.path }} has {{ $value | humanizePercentage }} free"
    : socketley_disk_free_ratio < 0.10

alert HostMemoryCritical critical for=30s keep=20s inhibits=HostMemoryLow
    summary="The host has {{ $value | humanizePercentage }} of its memory available"
    : socketley_host_memory_available_ratio < 0.05
alert HostMemoryLow warning for=30s keep=20s
    summary="The host has {{ $value | humanizePercentage }} of its memory available"
    : socketley_host_memory_available_ratio < 0.10

alert QuotaFull critical for=30s keep=20s inhibits=QuotaNearlyFull
    summary="{{ $labels.name }} holds {{ $value | humanizePercentage }} of its limit"
    : socketley_runtime_quota_ratio >= 0.98
alert QuotaNearlyFull warning for=30s keep=20s
    summary="{{ $labels.name }} holds {{ $value | humanizePercentage }} of its limit"
    : socketley_runtime_quota_ratio >= 0.90

alert MailQueueVeryLong critical for=50s keep=20s inhibits=MailQueueLong
    summary="{{ $labels.name }} has {{ $value }} messages waiting"
    description="socketley mail {{ $labels.name }} queue says why"
    : socketley_mail_queued >= 1000
alert MailQueueLong warning for=50s keep=20s
    summary="{{ $labels.name }} has {{ $value }} messages waiting"
    description="socketley mail {{ $labels.name }} queue says why"
    : socketley_mail_queued >= 100

alert MailBlocklisted critical keep=20s
    summary="A blocklist names the address {{ $labels.name }} sends from"
    description="socketley mail {{ $labels.name }} says which"
    : socketley_mail_blocklisted == 1

alert GitPullFailed warning keep=20s error=""
    summary="Git: pulling {{ $labels.repo }} into {{ $labels.name }} failed"
    description="{{ $labels.error }}"
    : socketley_git_mirror_failed == 1

alert TargetDown warning for=2m keep=20s
    summary="{{ $labels.job }} at {{ $labels.instance }} does not answer its scrape"
    : up == 0

alert TunnelAgentGone warning for=2m keep=20s
    summary="{{ $labels.name }} misses {{ $value }} of the agents that joined it"
    description="socketley tunnel {{ $labels.name }} agents says which"
    : socketley_tunnel_agents_joined - socketley_tunnel_agents_connected > 0

alert TunnelDatagramsDropped warning for=2m keep=20s
    summary="{{ $labels.name }} drops {{ $value | humanizePercentage }} of the datagrams it is given"
    : rate(socketley_tunnel_datagrams_dropped_total[5m])
        / (rate(socketley_tunnel_datagrams_total[5m]) + rate(socketley_tunnel_datagrams_dropped_total[5m])) > 0.01

alert IdpSignInsBarred warning keep=20s
    summary="{{ $labels.name }} barred {{ $value | printf \"%.0f\" }} sign-ins in ten minutes"
    description="Too many failures from one address or for one user"
    : increase(socketley_idp_sign_ins_barred_total[10m]) > 20
)";
}

bool merge_rules(const rule_file& builtin, const rule_file* user, std::vector<rule_def>& out, std::string& why)
{
    const int64_t every = user && user->every_ms ? user->every_ms : builtin.every_ms ? builtin.every_ms : default_every_ms;
    std::vector<rule_def> list = builtin.rules;
    std::vector<bool> off(list.size(), false);
    const auto find = [&](std::string_view n) {
        return static_cast<size_t>(std::find_if(list.begin(), list.end(), [&](const rule_def& r) { return r.name == n; }) -
                                   list.begin());
    };
    if (user)
    {
        for (const auto& [name, line] : user->off)
        {
            const size_t i = find(name);
            if (i >= builtin.rules.size())
                return line_fail(why, line, "off " + name + ": no built-in rule is named so");
            for (const rule_def& r : user->rules)
                if (r.name == name)
                    return line_fail(why, line, name + " is both defined, on line " + std::to_string(r.line) + ", and off");
            off[i] = true;
        }
        for (const rule_def& r : user->rules)
        {
            const size_t i = find(r.name);
            if (i < builtin.rules.size())
                list[i] = r;
            else
            {
                list.push_back(r);
                off.push_back(false);
            }
        }
    }
    out.clear();
    for (size_t i = 0; i < list.size(); ++i)
        if (!off[i])
            out.push_back(std::move(list[i]));
    for (rule_def& r : out)
    {
        if (r.every_ms == 0)
            r.every_ms = every;
        const bool from_file = r.source != "builtin";
        std::vector<std::string> kept;
        for (const std::string& n : r.inhibits)
        {
            const auto t = std::find_if(out.begin(), out.end(), [&](const rule_def& o) { return o.name == n; });
            const bool ok = t != out.end() && t->k == rule_def::kind::alert && t->name != r.name;
            if (ok)
                kept.push_back(n);
            else if (from_file)
                return line_fail(why, r.line, r.name + " inhibits " + n + ", which is no other alerting rule");
        }
        r.inhibits = std::move(kept);
    }
    return true;
}

std::string_view state_name(alert_state s)
{
    switch (s)
    {
        case alert_state::pending: return "pending";
        case alert_state::firing: return "firing";
        default: return "inactive";
    }
}

// ── events ────────────────────────────────────────────────────────────────

std::string alert_event::id() const
{
    std::string out(rule);
    for (const label& l : labels)
        if (l.name != "alertname" && l.name != "severity")
        {
            out += ':';
            out += l.value;
        }
    return out;
}

std::string_view alert_event::annotation(std::string_view name) const
{
    for (const auto& [k, v] : annotations)
        if (k == name)
            return v;
    return {};
}

std::string notification_text(const alert_event& e, std::string_view host)
{
    const bool raised = e.to == alert_state::firing;
    std::string text = !raised ? "\xe2\x9c\x85 " : e.severity == "critical" ? "\xf0\x9f\x94\xb4 " : "\xe2\x9a\xa0\xef\xb8\x8f ";
    if (!host.empty())
        text.append(host).append(": ");
    const std::string_view summary = e.annotation("summary");
    if (!summary.empty())
        text += summary;
    else
        text += e.id();
    const std::string_view detail = e.annotation("description");
    if (!raised)
        text += " -- resolved";
    else if (!detail.empty())
        text.append("\n").append(detail);
    if (text.size() > 1800)
    {
        // Cut on a character's first byte, so the body stays UTF-8 a strict hook takes.
        size_t at = 1800;
        while (at > 0 && (static_cast<unsigned char>(text[at]) & 0xC0) == 0x80)
            --at;
        text.resize(at);
    }
    return text;
}

// ── the engine ────────────────────────────────────────────────────────────

namespace
{

struct instance
{
    label_set series;
    std::vector<std::pair<std::string, std::string>> annotations;
    double value{0};
    alert_state state{alert_state::pending};
    // The state at the start of this evaluation, which an event goes from.
    alert_state was{alert_state::inactive};
    int64_t active_at{0}, fired_at{0}, resolved_at{0}, keep_since{0};
    bool told{false}, inhibited{false}, restored{false}, seen{false}, dead{false}, changed{false};
    // The ALERTS series of the state last written and the ALERTS_FOR_STATE series.
    uint32_t alerts_h{no_series}, for_h{no_series};
    alert_state alerts_state{alert_state::inactive};
};

struct rule_state
{
    rule_def def;
    prepared_query q;
    std::map<label_set, instance, labels_less> alerts;
    std::map<label_set, uint32_t, labels_less> recorded;
    int64_t next_due{INT64_MIN};
    int64_t last_t{INT64_MIN};
    int64_t last_eval_ms{0};
    double eval_seconds{0};
    std::string last_error;
    bool evaluated{false};
};

void render_alert(const label_set& ls, const instance& a, std::string& out)
{
    out += "{\"labels\":";
    json_labels(ls, out);
    out += ",\"annotations\":";
    json_pairs(a.annotations, out);
    out += ",\"state\":";
    json::quote_into(out, state_name(a.state));
    out += ",\"activeAt\":\"";
    rfc3339(a.active_at, out);
    out += '"';
    if (a.keep_since)
    {
        out += ",\"keepFiringSince\":\"";
        rfc3339(a.keep_since, out);
        out += '"';
    }
    // Prometheus writes an alert's value as Go's 'e' with the shortest digits.
    out += ",\"value\":\"";
    if (std::isnan(a.value))
        out += "NaN";
    else if (std::isinf(a.value))
        out += a.value > 0 ? "+Inf" : "-Inf";
    else
        format_go_float(a.value, true, out);
    out += "\"}";
}

}   // namespace

struct rule_engine::impl
{
    series_source& src;
    rule_hooks hooks;
    query_engine eng;
    std::vector<std::unique_ptr<rule_state>> rules;
    // Alerts of rules a load took away, resolved at the next evaluation, and series of theirs to end.
    std::vector<std::pair<std::unique_ptr<rule_state>, bool>> retired;
    std::string state_path;
    rule_stats st;

    // An evaluation round's changes, told once inhibition is known.
    struct change
    {
        rule_state* r;
        instance* a;
        const label_set* labels;
    };
    std::vector<change> changes;
    bool dirty{false};

    // Per evaluation, reused.
    query_result res;
    label_set tmp_ls;
    std::string tmp_s;

    impl(series_source& s, rule_hooks h) : src(s), hooks(std::move(h)), eng(s, rule_limits()) {}

    static query_limits rule_limits()
    {
        query_limits l;
        // A rule runs on the loop, so a heavy one is ended long before a dashboard's query would be.
        l.timeout_ms = 5'000;
        l.max_samples = 5'000'000;
        return l;
    }

    uint32_t handle(const label_set& ls)
    {
        return hooks.series ? hooks.series(ls) : no_series;
    }

    void write(uint32_t h, int64_t t, double v)
    {
        if (h == no_series || !hooks.append)
            return;
        hooks.append(h, t, v);
        ++st.samples_written;
    }

    uint32_t alerts_series(const label_set& labels, alert_state s)
    {
        tmp_ls = labels;
        set_label(tmp_ls, name_label, "ALERTS");
        set_label(tmp_ls, "alertstate", state_name(s));
        return handle(tmp_ls);
    }

    uint32_t for_state_series(const label_set& labels)
    {
        tmp_ls = labels;
        set_label(tmp_ls, name_label, "ALERTS_FOR_STATE");
        return handle(tmp_ls);
    }

    // The series an alert wrote ended at `t`.
    void end_series(instance& a, int64_t t)
    {
        write(a.alerts_h, t, stale_nan());
        write(a.for_h, t, stale_nan());
        a.alerts_h = a.for_h = no_series;
        a.alerts_state = alert_state::inactive;
    }

    void note(rule_state& r, instance& a, const label_set& labels)
    {
        a.changed = true;
        changes.push_back({&r, &a, &labels});
    }

    // The query's answer at `t` as (labels, value) pairs, a scalar as one without labels; false with the error.
    bool answer(rule_state& r, int64_t t)
    {
        query_error err;
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = eng.eval_instant(r.q, t, res, err);
        r.eval_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        r.last_eval_ms = t;
        r.evaluated = true;
        ++st.evaluations;
        if (!ok)
        {
            r.last_error = err.message;
            ++st.failures;
            return false;
        }
        if (res.kind == result_kind::scalar)
        {
            res.series.clear();
            res.series.push_back({{}, {{t, res.scalar}}});
        }
        r.last_error.clear();
        return true;
    }

    void eval_record(rule_state& r, int64_t t)
    {
        if (!answer(r, t))
            return;
        std::vector<std::pair<label_set, double>> got;
        got.reserve(res.series.size());
        for (result_series& x : res.series)
        {
            label_set ls = std::move(x.labels);
            set_label(ls, name_label, r.def.name);
            for (const auto& [n, tmpl] : r.def.labels)
                set_label(ls, n, tmpl.raw);
            got.emplace_back(std::move(ls), x.points.empty() ? 0 : x.points[0].v);
        }
        std::sort(got.begin(), got.end(), [](const auto& a, const auto& b) { return compare_labels(a.first, b.first) < 0; });
        for (size_t i = 1; i < got.size(); ++i)
            if (got[i].first == got[i - 1].first)
            {
                r.last_error = "vector contains metrics with the same labelset after applying rule labels";
                ++st.failures;
                return;
            }
        std::map<label_set, uint32_t, labels_less> now;
        for (auto& [ls, v] : got)
        {
            const auto old = r.recorded.find(ls);
            const uint32_t h = old != r.recorded.end() ? old->second : handle(ls);
            write(h, t, v);
            now.emplace_hint(now.end(), std::move(ls), h);
        }
        for (const auto& [ls, h] : r.recorded)
            if (!now.count(ls))
                write(h, t, stale_nan());
        r.recorded = std::move(now);
    }

    void eval_alert(rule_state& r, int64_t t)
    {
        if (!answer(r, t))
            return;
        struct element
        {
            label_set labels, series;
            std::vector<std::pair<std::string, std::string>> annotations;
            double value;
        };
        std::vector<element> els;
        els.reserve(res.series.size());
        for (result_series& s : res.series)
        {
            element e;
            e.value = s.points.empty() ? 0 : s.points[0].v;
            without_name(s.labels, e.series);
            e.labels = e.series;
            for (const auto& [n, tmpl] : r.def.labels)
            {
                tmp_s.clear();
                expand_template(tmpl, s.labels, e.value, tmp_s);
                set_label(e.labels, n, tmp_s);
            }
            set_label(e.labels, "severity", r.def.severity);
            set_label(e.labels, "alertname", r.def.name);
            for (const auto& [n, tmpl] : r.def.annotations)
            {
                tmp_s.clear();
                expand_template(tmpl, s.labels, e.value, tmp_s);
                e.annotations.emplace_back(n, tmp_s);
            }
            els.push_back(std::move(e));
        }
        std::sort(els.begin(), els.end(), [](const element& a, const element& b) { return compare_labels(a.labels, b.labels) < 0; });
        for (size_t i = 1; i < els.size(); ++i)
            if (els[i].labels == els[i - 1].labels)
            {
                r.last_error = "vector contains metrics with the same labelset after applying alert labels";
                ++st.failures;
                return;
            }
        for (auto& [ls, a] : r.alerts)
            a.was = a.state;
        for (element& e : els)
        {
            auto it = r.alerts.find(e.labels);
            if (it == r.alerts.end())
            {
                it = r.alerts.emplace(std::move(e.labels), instance{}).first;
                instance& a = it->second;
                a.state = alert_state::pending;
                a.was = alert_state::inactive;
                a.active_at = t;
            }
            instance& a = it->second;
            a.series = std::move(e.series);
            a.annotations = std::move(e.annotations);
            a.value = e.value;
            a.seen = true;
            a.restored = false;
            a.keep_since = 0;
        }
        for (auto& [ls, a] : r.alerts)
        {
            if (!a.seen)
            {
                int64_t keep = r.def.keep_ms;
                if (a.restored)
                    keep = std::max(keep, restore_grace_evals * r.def.every_ms);
                bool keep_firing = false;
                if (a.state == alert_state::firing && keep > 0)
                {
                    if (a.keep_since == 0)
                    {
                        a.keep_since = t;
                        dirty = true;
                    }
                    keep_firing = t - a.keep_since < keep;
                }
                if (!keep_firing)
                {
                    if (a.state == alert_state::firing)
                        a.resolved_at = t;
                    a.state = alert_state::inactive;
                    a.dead = true;
                    end_series(a, t);
                    note(r, a, ls);
                    continue;
                }
            }
            a.seen = false;
            if (a.state == alert_state::pending && t - a.active_at >= r.def.for_ms)
            {
                a.state = alert_state::firing;
                a.fired_at = t;
            }
            if (a.state != a.was)
                note(r, a, ls);
            if (a.alerts_state != a.state)
            {
                write(a.alerts_h, t, stale_nan());
                a.alerts_h = alerts_series(ls, a.state);
                a.alerts_state = a.state;
            }
            if (a.for_h == no_series)
                a.for_h = for_state_series(ls);
            write(a.alerts_h, t, 1);
            write(a.for_h, t, static_cast<double>(a.active_at) / 1000);
        }
    }

    // Each alert's inhibition from the firing alerts of the rules that inhibit it, then every change told.
    void settle()
    {
        for (auto& r : rules)
            for (auto& [ls, a] : r->alerts)
                a.inhibited = false;
        for (auto& src_rule : rules)
        {
            if (src_rule->def.inhibits.empty())
                continue;
            for (const std::string& target : src_rule->def.inhibits)
                for (auto& r : rules)
                {
                    if (r->def.name != target)
                        continue;
                    for (auto& [ls, a] : r->alerts)
                        for (const auto& [sls, s] : src_rule->alerts)
                            if (s.state == alert_state::firing && !s.dead && share_labels(s.series, a.series))
                            {
                                a.inhibited = true;
                                break;
                            }
                }
        }
        for (const change& c : changes)
            tell(*c.r, *c.a, *c.labels, c.a->was, c.a->state);
        // An alert that fired while inhibited is told of once nothing inhibits it.
        for (auto& r : rules)
            for (auto& [ls, a] : r->alerts)
                if (!a.changed && !a.dead && a.state == alert_state::firing && !a.inhibited && !a.told)
                    tell(*r, a, ls, alert_state::firing, alert_state::firing);
        changes.clear();
        for (auto& r : rules)
            for (auto it = r->alerts.begin(); it != r->alerts.end();)
            {
                it->second.changed = false;
                if (it->second.dead)
                    it = r->alerts.erase(it);
                else
                    ++it;
            }
    }

    void tell(rule_state& r, instance& a, const label_set& labels, alert_state from, alert_state to)
    {
        bool notify = false;
        if (to == alert_state::firing && !a.inhibited && !a.told)
        {
            notify = a.told = true;
        }
        else if (to == alert_state::inactive && a.told)
        {
            notify = true;
            a.told = false;
        }
        dirty = true;
        if (notify)
            ++st.notifications;
        if (!hooks.on_change)
            return;
        alert_event e{r.def.name, r.def.severity, labels, a.annotations};
        e.value = a.value;
        e.from = from;
        e.to = to;
        e.active_at = a.active_at;
        e.fired_at = a.fired_at;
        e.resolved_at = a.resolved_at;
        e.inhibited = a.inhibited;
        e.notify = notify;
        hooks.on_change(e);
    }

    // Alerts and series of rules a load took away, ended at `t`.
    void retire(int64_t t)
    {
        for (auto& [r, alerting] : retired)
        {
            for (auto& [ls, a] : r->alerts)
            {
                a.was = a.state;
                if (a.state == alert_state::firing)
                    a.resolved_at = t;
                a.state = alert_state::inactive;
                end_series(a, t);
                tell(*r, a, ls, a.was, alert_state::inactive);
            }
            for (const auto& [ls, h] : r->recorded)
                write(h, t, stale_nan());
        }
        retired.clear();
    }

    void save(int64_t now)
    {
        dirty = false;
        if (state_path.empty())
            return;
        std::string out(state_magic);
        out += ' ';
        out += std::to_string(now);
        out += '\n';
        for (const auto& r : rules)
            for (const auto& [ls, a] : r->alerts)
            {
                if (a.dead)
                    continue;
                escape_state(r->def.name, out);
                out += '\t';
                out += a.state == alert_state::firing ? '2' : '1';
                for (int64_t v : {a.active_at, a.fired_at, a.keep_since})
                {
                    out += '\t';
                    out += std::to_string(v);
                }
                out += '\t';
                out += a.told ? '1' : '0';
                out += '\t';
                format_go_float(a.value, true, out);
                for (const label& l : ls)
                {
                    out += '\t';
                    out += l.name;
                    out += '=';
                    escape_state(l.value, out);
                }
                out += '\n';
            }
        std::string why;
        if (!replace_file(state_path, out, durability::none, &why))
            LOG_WARN(("metrics: the rules' state is not kept: " + why).c_str());
    }

    void restore(int64_t now)
    {
        std::string data;
        if (!read_file(state_path, data, read_options{.missing_ok = true, .max_bytes = 64u << 20}) || data.empty())
            return;
        size_t pos = data.find('\n');
        const std::string_view head = std::string_view(data).substr(0, pos);
        if (pos == std::string::npos || !head.starts_with(state_magic))
        {
            LOG_WARN(("metrics: " + state_path + " is not the rules' state, which starts empty").c_str());
            return;
        }
        int64_t saved = 0;
        std::from_chars(head.data() + state_magic.size() + 1, head.data() + head.size(), saved);
        const bool fresh = now - saved <= outage_tolerance_ms;
        ++pos;
        while (pos < data.size())
        {
            size_t end = data.find('\n', pos);
            if (end == std::string::npos)
                end = data.size();
            const std::string_view line(data.data() + pos, end - pos);
            pos = end + 1;
            std::vector<std::string_view> f;
            size_t s = 0;
            while (s <= line.size())
            {
                const size_t e = std::min(line.find('\t', s), line.size());
                f.push_back(line.substr(s, e - s));
                s = e + 1;
            }
            if (f.size() < 7)
                continue;
            const std::string name = unescape_state(f[0]);
            const auto r = std::find_if(rules.begin(), rules.end(), [&](const auto& x) {
                return x->def.name == name && x->def.k == rule_def::kind::alert;
            });
            if (r == rules.end())
                continue;
            instance a;
            a.state = f[1] == "2" ? alert_state::firing : alert_state::pending;
            int64_t* fields[] = {&a.active_at, &a.fired_at, &a.keep_since};
            for (int k = 0; k < 3; ++k)
                std::from_chars(f[2 + static_cast<size_t>(k)].data(), f[2 + static_cast<size_t>(k)].data() + f[2 + static_cast<size_t>(k)].size(), *fields[k]);
            a.told = f[5] == "1";
            a.value = std::strtod(std::string(f[6]).c_str(), nullptr);
            a.restored = true;
            if (a.state == alert_state::pending && !fresh)
                continue;
            label_set ls;
            for (size_t k = 7; k < f.size(); ++k)
            {
                const size_t eq = f[k].find('=');
                if (eq == std::string_view::npos)
                    continue;
                ls.push_back({std::string(f[k].substr(0, eq)), unescape_state(f[k].substr(eq + 1))});
            }
            std::sort(ls.begin(), ls.end(), [](const label& x, const label& y) { return x.name < y.name; });
            // What the expression gave: the alert's labels less those its rule adds.
            for (const label& l : ls)
                if (l.name != "alertname" && l.name != "severity" &&
                    std::none_of((*r)->def.labels.begin(), (*r)->def.labels.end(), [&](const auto& x) { return x.first == l.name; }))
                    a.series.push_back(l);
            (*r)->alerts.emplace(std::move(ls), std::move(a));
        }
    }
};

rule_engine::rule_engine(series_source& source, rule_hooks hooks) : m(std::make_unique<impl>(source, std::move(hooks))) {}

rule_engine::~rule_engine() = default;

bool rule_engine::load(std::string_view user_text, std::string_view source, std::string& why)
{
    static const rule_file builtin = [] {
        rule_file f;
        std::string w;
        if (!parse_rules(builtin_rules(), "builtin", f, w))
            LOG_ERROR(("metrics: the built-in rules do not read: " + w).c_str());
        return f;
    }();
    rule_file user;
    const bool has_user = !source.empty() || !user_text.empty();
    if (has_user && !parse_rules(user_text, source, user, why))
        return false;
    std::vector<rule_def> defs;
    if (!merge_rules(builtin, has_user ? &user : nullptr, defs, why))
        return false;
    std::vector<std::unique_ptr<rule_state>> next;
    for (rule_def& d : defs)
    {
        auto r = std::make_unique<rule_state>();
        query_error err;
        if (!m->eng.prepare(d.expr, r->q, err))
        {
            why = (d.source == "builtin" ? "builtin line " : "line ") + std::to_string(d.line) + ": " + d.name + ": " +
                  err.message;
            return false;
        }
        r->def = std::move(d);
        next.push_back(std::move(r));
    }
    // A rule that keeps its name and kind keeps its alerts, its series and when it is due.
    for (auto& old : m->rules)
    {
        const auto it = std::find_if(next.begin(), next.end(), [&](const auto& n) {
            return n->def.name == old->def.name && n->def.k == old->def.k;
        });
        if (it == next.end())
        {
            const bool alerting = old->def.k == rule_def::kind::alert;
            m->retired.emplace_back(std::move(old), alerting);
            continue;
        }
        rule_state& n = **it;
        n.alerts = std::move(old->alerts);
        n.recorded = std::move(old->recorded);
        n.last_t = old->last_t;
        n.last_eval_ms = old->last_eval_ms;
        n.eval_seconds = old->eval_seconds;
        n.last_error = old->last_error;
        n.evaluated = old->evaluated;
    }
    m->rules = std::move(next);
    return true;
}

void rule_engine::persist_at(std::string path, int64_t now)
{
    m->state_path = std::move(path);
    m->restore(now);
}

void rule_engine::flush(int64_t now) { m->save(now); }

int64_t rule_engine::eval(int64_t now)
{
    impl& s = *m;
    if (!s.retired.empty())
        s.retire(now);
    int64_t next = INT64_MAX;
    for (auto& rp : s.rules)
    {
        rule_state& r = *rp;
        const int64_t every = r.def.every_ms;
        if (r.next_due <= now)
        {
            const int64_t t = floor_to(now, every);
            if (t > r.last_t)
            {
                r.last_t = t;
                if (r.def.k == rule_def::kind::record)
                    s.eval_record(r, t);
                else
                    s.eval_alert(r, t);
            }
            r.next_due = floor_to(now, every) + every;
        }
        next = std::min(next, r.next_due);
    }
    s.settle();
    if (s.dirty)
        s.save(now);
    return next == INT64_MAX ? now + default_every_ms : next;
}

void rule_engine::render_rules(std::string& out, const rules_filter& f) const
{
    // Groups by where a rule came from and how often it runs, in the order the set lists them.
    struct group
    {
        std::string source;
        int64_t every;
        std::vector<const rule_state*> rules;
    };
    std::vector<group> groups;
    for (const auto& r : m->rules)
    {
        const bool alert = r->def.k == rule_def::kind::alert;
        if ((alert && !f.alerts) || (!alert && !f.records))
            continue;
        auto g = std::find_if(groups.begin(), groups.end(),
                              [&](const group& x) { return x.source == r->def.source && x.every == r->def.every_ms; });
        if (g == groups.end())
        {
            groups.push_back({r->def.source, r->def.every_ms, {}});
            g = groups.end() - 1;
        }
        g->rules.push_back(r.get());
    }
    out += "{\"groups\":[";
    for (size_t gi = 0; gi < groups.size(); ++gi)
    {
        const group& g = groups[gi];
        if (gi)
            out += ',';
        std::string name = g.source == "builtin" ? "socketley" : g.source.substr(g.source.rfind('/') + 1);
        const bool split = std::count_if(groups.begin(), groups.end(), [&](const group& x) { return x.source == g.source; }) > 1;
        if (split)
            name += " every " + duration_text(g.every);
        out += "{\"name\":";
        json::quote_into(out, name);
        out += ",\"file\":";
        json::quote_into(out, g.source == "builtin" ? std::string_view() : std::string_view(g.source));
        out += ",\"rules\":[";
        double total = 0;
        int64_t last = 0;
        for (size_t ri = 0; ri < g.rules.size(); ++ri)
        {
            const rule_state& r = *g.rules[ri];
            total += r.eval_seconds;
            last = std::max(last, r.last_eval_ms);
            if (ri)
                out += ',';
            const bool alert = r.def.k == rule_def::kind::alert;
            out += "{";
            if (alert)
            {
                alert_state worst = alert_state::inactive;
                for (const auto& [ls, a] : r.alerts)
                    worst = std::max(worst, a.state);
                out += "\"state\":";
                json::quote_into(out, state_name(worst));
                out += ',';
            }
            out += "\"name\":";
            json::quote_into(out, r.def.name);
            out += ",\"query\":";
            json::quote_into(out, r.def.expr);
            if (alert)
            {
                out += ",\"duration\":";
                json_seconds(static_cast<double>(r.def.for_ms) / 1000, out);
                out += ",\"keepFiringFor\":";
                json_seconds(static_cast<double>(r.def.keep_ms) / 1000, out);
            }
            // The rule's own labels as written, their templates unexpanded.
            out += ",\"labels\":{";
            bool first = true;
            const auto put = [&](std::string_view k, std::string_view v) {
                if (!first)
                    out += ',';
                first = false;
                json::quote_into(out, k);
                out += ':';
                json::quote_into(out, v);
            };
            bool sev = !alert;
            for (const auto& [k, t] : r.def.labels)
            {
                if (!sev && k > "severity")
                {
                    put("severity", r.def.severity);
                    sev = true;
                }
                put(k, t.raw);
            }
            if (!sev)
                put("severity", r.def.severity);
            out += '}';
            if (alert)
            {
                out += ",\"annotations\":{";
                first = true;
                for (const auto& [k, t] : r.def.annotations)
                    put(k, t.raw);
                out += '}';
                if (!f.exclude_alerts)
                {
                    out += ",\"alerts\":[";
                    bool fa = true;
                    for (const auto& [ls, a] : r.alerts)
                    {
                        if (a.dead)
                            continue;
                        if (!fa)
                            out += ',';
                        fa = false;
                        render_alert(ls, a, out);
                    }
                    out += ']';
                }
            }
            out += ",\"health\":";
            json::quote_into(out, !r.evaluated ? "unknown" : r.last_error.empty() ? "ok" : "err");
            if (!r.last_error.empty())
            {
                out += ",\"lastError\":";
                json::quote_into(out, r.last_error);
            }
            out += ",\"evaluationTime\":";
            json_seconds(r.eval_seconds, out);
            out += ",\"lastEvaluation\":\"";
            rfc3339(r.evaluated ? r.last_eval_ms : 0, out);
            out += "\",\"type\":";
            out += alert ? "\"alerting\"" : "\"recording\"";
            out += '}';
        }
        out += "],\"interval\":";
        json_seconds(static_cast<double>(g.every) / 1000, out);
        out += ",\"limit\":0,\"evaluationTime\":";
        json_seconds(total, out);
        out += ",\"lastEvaluation\":\"";
        rfc3339(last, out);
        out += "\"}";
    }
    out += "]}";
}

void rule_engine::render_alerts(std::string& out) const
{
    out += "{\"alerts\":[";
    bool first = true;
    for (const auto& r : m->rules)
        for (const auto& [ls, a] : r->alerts)
        {
            if (a.dead)
                continue;
            if (!first)
                out += ',';
            first = false;
            render_alert(ls, a, out);
        }
    out += "]}";
}

void rule_engine::each_alert(const std::function<void(const alert_event&)>& fn) const
{
    for (const auto& r : m->rules)
        for (const auto& [ls, a] : r->alerts)
            if (!a.dead)
                fn(alert_event{r->def.name, r->def.severity, ls, a.annotations, a.value, a.state, a.state, a.active_at,
                               a.fired_at, a.resolved_at, a.inhibited, false});
}

void rule_engine::render_alerts_text(std::string& out) const
{
    for (const auto& r : m->rules)
        for (const auto& [ls, a] : r->alerts)
        {
            if (a.dead)
                continue;
            out += state_name(a.state);
            out += '\t';
            out += label_value(ls, "alertname");
            out += '\t';
            out += label_value(ls, "severity");
            out += '\t';
            bool first = true;
            for (const auto& l : ls)
                if (l.name != "alertname" && l.name != "severity")
                {
                    out += first ? "" : ",";
                    out += l.name + "=" + l.value;
                    first = false;
                }
            for (const auto& [k, v] : a.annotations)
                if (k == "summary")
                    out += "\t" + v;
            out += '\n';
        }
}

size_t rule_engine::rule_count() const { return m->rules.size(); }

size_t rule_engine::active_alerts() const
{
    size_t n = 0;
    for (const auto& r : m->rules)
        n += r->alerts.size();
    return n;
}

const rule_stats& rule_engine::stats() const { return m->st; }

query_limits& rule_engine::limits() { return m->eng.limits(); }

}   // namespace socketley::metrics
