#include "metrics_promql.h"
#include "metrics_regex.h"
#include "metrics_text.h"

#include <cctype>
#include <charconv>
#include <cmath>
#include <limits>

namespace socketley::metrics
{

namespace
{

using V = value_type;

constexpr func_info functions[] = {
    {"abs", fn::abs, {V::vector}, 1, 0, V::vector},
    {"ceil", fn::ceil, {V::vector}, 1, 0, V::vector},
    {"floor", fn::floor, {V::vector}, 1, 0, V::vector},
    {"exp", fn::exp, {V::vector}, 1, 0, V::vector},
    {"ln", fn::ln, {V::vector}, 1, 0, V::vector},
    {"log2", fn::log2, {V::vector}, 1, 0, V::vector},
    {"log10", fn::log10, {V::vector}, 1, 0, V::vector},
    {"sqrt", fn::sqrt, {V::vector}, 1, 0, V::vector},
    {"sgn", fn::sgn, {V::vector}, 1, 0, V::vector},
    {"acos", fn::acos, {V::vector}, 1, 0, V::vector},
    {"acosh", fn::acosh, {V::vector}, 1, 0, V::vector},
    {"asin", fn::asin, {V::vector}, 1, 0, V::vector},
    {"asinh", fn::asinh, {V::vector}, 1, 0, V::vector},
    {"atan", fn::atan, {V::vector}, 1, 0, V::vector},
    {"atanh", fn::atanh, {V::vector}, 1, 0, V::vector},
    {"cos", fn::cos, {V::vector}, 1, 0, V::vector},
    {"cosh", fn::cosh, {V::vector}, 1, 0, V::vector},
    {"sin", fn::sin, {V::vector}, 1, 0, V::vector},
    {"sinh", fn::sinh, {V::vector}, 1, 0, V::vector},
    {"tan", fn::tan, {V::vector}, 1, 0, V::vector},
    {"tanh", fn::tanh, {V::vector}, 1, 0, V::vector},
    {"deg", fn::deg, {V::vector}, 1, 0, V::vector},
    {"rad", fn::rad, {V::vector}, 1, 0, V::vector},
    {"pi", fn::pi, {}, 0, 0, V::scalar},
    {"round", fn::round, {V::vector, V::scalar}, 2, 1, V::vector},
    {"clamp", fn::clamp, {V::vector, V::scalar, V::scalar}, 3, 0, V::vector},
    {"clamp_min", fn::clamp_min, {V::vector, V::scalar}, 2, 0, V::vector},
    {"clamp_max", fn::clamp_max, {V::vector, V::scalar}, 2, 0, V::vector},
    {"time", fn::time, {}, 0, 0, V::scalar},
    {"timestamp", fn::timestamp, {V::vector}, 1, 0, V::vector},
    {"vector", fn::vector, {V::scalar}, 1, 0, V::vector},
    {"scalar", fn::scalar, {V::vector}, 1, 0, V::scalar},
    {"absent", fn::absent, {V::vector}, 1, 0, V::vector},
    {"absent_over_time", fn::absent_over_time, {V::matrix}, 1, 0, V::vector},
    {"label_replace", fn::label_replace, {V::vector, V::string, V::string, V::string, V::string}, 5, 0, V::vector},
    {"label_join", fn::label_join, {V::vector, V::string, V::string, V::string}, 4, -1, V::vector},
    {"sort", fn::sort, {V::vector}, 1, 0, V::vector},
    {"sort_desc", fn::sort_desc, {V::vector}, 1, 0, V::vector},
    {"histogram_quantile", fn::histogram_quantile, {V::scalar, V::vector}, 2, 0, V::vector},
    {"day_of_month", fn::day_of_month, {V::vector}, 1, 1, V::vector},
    {"day_of_week", fn::day_of_week, {V::vector}, 1, 1, V::vector},
    {"day_of_year", fn::day_of_year, {V::vector}, 1, 1, V::vector},
    {"days_in_month", fn::days_in_month, {V::vector}, 1, 1, V::vector},
    {"hour", fn::hour, {V::vector}, 1, 1, V::vector},
    {"minute", fn::minute, {V::vector}, 1, 1, V::vector},
    {"month", fn::month, {V::vector}, 1, 1, V::vector},
    {"year", fn::year, {V::vector}, 1, 1, V::vector},
    {"rate", fn::rate, {V::matrix}, 1, 0, V::vector},
    {"irate", fn::irate, {V::matrix}, 1, 0, V::vector},
    {"increase", fn::increase, {V::matrix}, 1, 0, V::vector},
    {"delta", fn::delta, {V::matrix}, 1, 0, V::vector},
    {"idelta", fn::idelta, {V::matrix}, 1, 0, V::vector},
    {"deriv", fn::deriv, {V::matrix}, 1, 0, V::vector},
    {"predict_linear", fn::predict_linear, {V::matrix, V::scalar}, 2, 0, V::vector},
    {"resets", fn::resets, {V::matrix}, 1, 0, V::vector},
    {"changes", fn::changes, {V::matrix}, 1, 0, V::vector},
    {"avg_over_time", fn::avg_over_time, {V::matrix}, 1, 0, V::vector},
    {"min_over_time", fn::min_over_time, {V::matrix}, 1, 0, V::vector},
    {"max_over_time", fn::max_over_time, {V::matrix}, 1, 0, V::vector},
    {"sum_over_time", fn::sum_over_time, {V::matrix}, 1, 0, V::vector},
    {"count_over_time", fn::count_over_time, {V::matrix}, 1, 0, V::vector},
    {"last_over_time", fn::last_over_time, {V::matrix}, 1, 0, V::vector},
    {"quantile_over_time", fn::quantile_over_time, {V::scalar, V::matrix}, 2, 0, V::vector},
    {"stddev_over_time", fn::stddev_over_time, {V::matrix}, 1, 0, V::vector},
    {"stdvar_over_time", fn::stdvar_over_time, {V::matrix}, 1, 0, V::vector},
    {"present_over_time", fn::present_over_time, {V::matrix}, 1, 0, V::vector},
};

constexpr struct
{
    std::string_view name;
    agg_op op;
} aggregators[] = {
    {"sum", agg_op::sum},         {"avg", agg_op::avg},           {"min", agg_op::min},
    {"max", agg_op::max},         {"count", agg_op::count},       {"stddev", agg_op::stddev},
    {"stdvar", agg_op::stdvar},   {"topk", agg_op::topk},         {"bottomk", agg_op::bottomk},
    {"quantile", agg_op::quantile}, {"count_values", agg_op::count_values}, {"group", agg_op::group},
};

enum class tk : uint8_t
{
    eof, ident, number, duration, string, lparen, rparen, lbrace, rbrace, lbracket, rbracket, comma, colon, at,
    assign, eql, neq, re, nre, lss, lte, gtr, gte, add, sub, mul, div, mod, pow,
};

struct token
{
    tk       kind{tk::eof};
    uint32_t pos{0};
    std::string_view text;
    double   num{0};
    int64_t  ms{0};
    std::string str;
};

struct parse_fail
{
    uint32_t pos;
    std::string msg;
};

bool ieq(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if ((a[i] | 0x20) != (b[i] | 0x20))
            return false;
    return true;
}

bool ident_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':'; }
bool ident_char(char c) { return ident_start(c) || (c >= '0' && c <= '9'); }
bool digit(char c) { return c >= '0' && c <= '9'; }
// Prometheus holds a duration in Go's time.Duration, nanoseconds in an int64, so about 292 years is the most it takes.
constexpr int64_t max_duration_ms = std::numeric_limits<int64_t>::max() / 1'000'000;
// What may not follow a number or a duration: a letter, a digit or an underscore, though a subquery's colon may.
bool word_char(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || digit(c); }

bool valid_label_name(std::string_view s)
{
    if (s.empty() || digit(s[0]))
        return false;
    for (char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || digit(c)))
            return false;
    return true;
}

void append_utf8(std::string& out, uint32_t r)
{
    if (r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF))
        r = 0xFFFD;
    if (r < 0x80)
        out += static_cast<char>(r);
    else if (r < 0x800)
    {
        out += static_cast<char>(0xC0 | (r >> 6));
        out += static_cast<char>(0x80 | (r & 0x3F));
    }
    else if (r < 0x10000)
    {
        out += static_cast<char>(0xE0 | (r >> 12));
        out += static_cast<char>(0x80 | ((r >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (r & 0x3F));
    }
    else
    {
        out += static_cast<char>(0xF0 | (r >> 18));
        out += static_cast<char>(0x80 | ((r >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((r >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (r & 0x3F));
    }
}

// The milliseconds a run of `<digits><unit>` pieces at the front of `s` spell, units in falling order, or 0 chars.
size_t scan_duration(std::string_view s, int64_t& ms)
{
    static constexpr struct { std::string_view u; int64_t ms; } units[] = {
        {"y", 365LL * 86400000}, {"w", 7LL * 86400000}, {"d", 86400000}, {"h", 3600000},
        {"ms", 1}, {"m", 60000}, {"s", 1000},
    };
    // The order a duration must write its units in, ms after s.
    static constexpr int rank[] = {0, 1, 2, 3, 6, 4, 5};
    size_t i = 0;
    int last = -1;
    ms = 0;
    while (i < s.size() && digit(s[i]))
    {
        size_t j = i;
        int64_t n = 0;
        while (j < s.size() && digit(s[j]))
        {
            if (n > std::numeric_limits<int64_t>::max() / 10)
                return 0;
            n = n * 10 + (s[j] - '0');
            ++j;
        }
        int found = -1;
        for (int u = 0; u < 7; ++u)
            if (s.substr(j).starts_with(units[u].u) && !(units[u].u == "m" && s.substr(j).starts_with("ms")))
            {
                found = u;
                break;
            }
        if (found < 0 || rank[found] <= last)
            return 0;
        last = rank[found];
        if (n > (std::numeric_limits<int64_t>::max() - ms) / units[found].ms)
            return 0;
        ms += n * units[found].ms;
        i = j + units[found].u.size();
    }
    if (i < s.size() && word_char(s[i]))
        return 0;
    return i;
}

class lexer
{
public:
    explicit lexer(std::string_view q) : m_q(q) {}

    void next(token& t)
    {
        skip();
        t.pos = static_cast<uint32_t>(m_pos);
        t.str.clear();
        if (m_pos >= m_q.size())
        {
            t.kind = tk::eof;
            t.text = {};
            return;
        }
        const size_t from = m_pos;
        const char c = m_q[m_pos];
        auto one = [&](tk k, size_t n = 1) {
            t.kind = k;
            m_pos += n;
            t.text = m_q.substr(from, n);
        };
        auto two = [&](char second) { return m_pos + 1 < m_q.size() && m_q[m_pos + 1] == second; };
        switch (c)
        {
            case '(': return one(tk::lparen);
            case ')': return one(tk::rparen);
            case '{': return one(tk::lbrace);
            case '}': return one(tk::rbrace);
            case '[': ++m_brackets; return one(tk::lbracket);
            case ']': if (m_brackets) --m_brackets; return one(tk::rbracket);
            case ',': return one(tk::comma);
            case '@': return one(tk::at);
            case '+': return one(tk::add);
            case '-': return one(tk::sub);
            case '*': return one(tk::mul);
            case '/': return one(tk::div);
            case '%': return one(tk::mod);
            case '^': return one(tk::pow);
            case '=':
                if (two('=')) return one(tk::eql, 2);
                if (two('~')) return one(tk::re, 2);
                return one(tk::assign);
            case '!':
                if (two('=')) return one(tk::neq, 2);
                if (two('~')) return one(tk::nre, 2);
                throw parse_fail{t.pos, "unexpected character after '!': " + std::string(m_q.substr(m_pos + 1, 1))};
            case '<':
                if (two('=')) return one(tk::lte, 2);
                return one(tk::lss);
            case '>':
                if (two('=')) return one(tk::gte, 2);
                return one(tk::gtr);
            case '"': case '\'': return quoted(t, c);
            case '`':
            {
                const size_t end = m_q.find('`', m_pos + 1);
                if (end == std::string_view::npos)
                    throw parse_fail{t.pos, "unterminated raw string"};
                t.kind = tk::string;
                t.str.assign(m_q.substr(m_pos + 1, end - m_pos - 1));
                m_pos = end + 1;
                t.text = m_q.substr(from, m_pos - from);
                return;
            }
            default: break;
        }
        if (c == ':' && (m_brackets || m_pos + 1 >= m_q.size() || !ident_start(m_q[m_pos + 1])))
            return one(tk::colon);
        if (digit(c) || (c == '.' && m_pos + 1 < m_q.size() && digit(m_q[m_pos + 1])))
            return number(t);
        if (ident_start(c))
        {
            while (m_pos < m_q.size() && ident_char(m_q[m_pos]))
                ++m_pos;
            t.kind = tk::ident;
            t.text = m_q.substr(from, m_pos - from);
            return;
        }
        throw parse_fail{t.pos, "unexpected character: '" + std::string(1, c) + "'"};
    }

    size_t pos() const { return m_pos; }

private:
    void skip()
    {
        while (m_pos < m_q.size())
        {
            const char c = m_q[m_pos];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                ++m_pos;
            else if (c == '#')
            {
                while (m_pos < m_q.size() && m_q[m_pos] != '\n')
                    ++m_pos;
            }
            else
                break;
        }
    }

    void number(token& t)
    {
        const size_t from = m_pos;
        const std::string_view rest = m_q.substr(m_pos);
        int64_t ms = 0;
        if (const size_t n = scan_duration(rest, ms))
        {
            if (ms > max_duration_ms)
                throw parse_fail{t.pos, "duration out of range: \"" + std::string(rest.substr(0, n)) + "\""};
            t.kind = tk::duration;
            t.ms = ms;
            m_pos += n;
            t.text = m_q.substr(from, n);
            return;
        }
        size_t i = 0;
        bool parsed = false;
        if (rest.size() > 1 && rest[0] == '0' && (rest[1] == 'x' || rest[1] == 'X'))
        {
            i = 2;
            uint64_t v = 0;
            bool any = false;
            while (i < rest.size() && std::isxdigit(static_cast<unsigned char>(rest[i])))
            {
                const char h = rest[i];
                const int d = h <= '9' ? h - '0' : (h | 0x20) - 'a' + 10;
                if (v > (static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) >> 4))
                    throw parse_fail{t.pos, "error parsing number: value out of range"};
                v = v * 16 + static_cast<uint64_t>(d);
                any = true;
                ++i;
            }
            if (!any)
                throw parse_fail{t.pos, "bad number or duration syntax: \"" + std::string(rest.substr(0, i)) + "\""};
            t.num = static_cast<double>(v);
            parsed = true;
        }
        else
        {
            while (i < rest.size() && digit(rest[i]))
                ++i;
            if (i < rest.size() && rest[i] == '.')
            {
                ++i;
                while (i < rest.size() && digit(rest[i]))
                    ++i;
            }
            if (i < rest.size() && (rest[i] == 'e' || rest[i] == 'E'))
            {
                size_t j = i + 1;
                if (j < rest.size() && (rest[j] == '+' || rest[j] == '-'))
                    ++j;
                if (j < rest.size() && digit(rest[j]))
                {
                    while (j < rest.size() && digit(rest[j]))
                        ++j;
                    i = j;
                }
            }
            const std::string_view lit = rest.substr(0, i);
            // Go's ParseInt with base 0 comes first, so a leading zero is octal there as here.
            bool octal = lit.size() > 1 && lit[0] == '0';
            for (char ch : lit)
                octal = octal && ch >= '0' && ch <= '7';
            uint64_t v = 0;
            for (char ch : lit.substr(1))
                if (octal && v > (static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) >> 3))
                    octal = false;
                else if (octal)
                    v = v * 8 + static_cast<uint64_t>(ch - '0');
            // An octal literal past int64 fails Go's ParseInt, and ParseFloat then reads it as decimal.
            if (octal)
            {
                t.num = static_cast<double>(v);
                parsed = true;
            }
            else
                parsed = parse_go_float(lit, t.num);
        }
        if (!parsed || (i < rest.size() && word_char(rest[i])))
        {
            size_t e = i;
            while (e < rest.size() && word_char(rest[e]))
                ++e;
            throw parse_fail{t.pos, "bad number or duration syntax: \"" + std::string(rest.substr(0, e)) + "\""};
        }
        t.kind = tk::number;
        m_pos += i;
        t.text = m_q.substr(from, i);
    }

    void quoted(token& t, char q)
    {
        const size_t from = m_pos++;
        auto hex = [](char h) {
            if (h >= '0' && h <= '9') return h - '0';
            if (h >= 'a' && h <= 'f') return h - 'a' + 10;
            if (h >= 'A' && h <= 'F') return h - 'A' + 10;
            return -1;
        };
        while (true)
        {
            if (m_pos >= m_q.size() || m_q[m_pos] == '\n')
                throw parse_fail{t.pos, "unterminated quoted string"};
            const char c = m_q[m_pos++];
            if (c == q)
                break;
            if (c != '\\')
            {
                t.str += c;
                continue;
            }
            if (m_pos >= m_q.size())
                throw parse_fail{t.pos, "unterminated quoted string"};
            const char e = m_q[m_pos++];
            switch (e)
            {
                case 'a': t.str += '\a'; break;
                case 'b': t.str += '\b'; break;
                case 'f': t.str += '\f'; break;
                case 'n': t.str += '\n'; break;
                case 'r': t.str += '\r'; break;
                case 't': t.str += '\t'; break;
                case 'v': t.str += '\v'; break;
                case '\\': t.str += '\\'; break;
                case '"': case '\'': t.str += e; break;
                case 'x': case 'u': case 'U':
                {
                    const int n = e == 'x' ? 2 : e == 'u' ? 4 : 8;
                    uint32_t v = 0;
                    for (int k = 0; k < n; ++k)
                    {
                        if (m_pos >= m_q.size() || hex(m_q[m_pos]) < 0)
                            throw parse_fail{t.pos, "invalid escape sequence in string"};
                        v = v * 16 + static_cast<uint32_t>(hex(m_q[m_pos++]));
                    }
                    if (e == 'x')
                        t.str += static_cast<char>(v);
                    else
                        append_utf8(t.str, v);
                    break;
                }
                default:
                    if (e >= '0' && e <= '7')
                    {
                        uint32_t v = static_cast<uint32_t>(e - '0');
                        for (int k = 0; k < 2; ++k)
                        {
                            if (m_pos >= m_q.size() || m_q[m_pos] < '0' || m_q[m_pos] > '7')
                                throw parse_fail{t.pos, "invalid escape sequence in string"};
                            v = v * 8 + static_cast<uint32_t>(m_q[m_pos++] - '0');
                        }
                        if (v > 255)
                            throw parse_fail{t.pos, "invalid escape sequence in string"};
                        t.str += static_cast<char>(v);
                        break;
                    }
                    throw parse_fail{t.pos, "unknown escape sequence " + std::string(1, e)};
            }
        }
        t.kind = tk::string;
        t.text = m_q.substr(from, m_pos - from);
    }

    std::string_view m_q;
    size_t m_pos{0};
    int m_brackets{0};
};

bool is_comparison(bin_op o) { return o >= bin_op::eq && o <= bin_op::le; }
bool is_set(bin_op o) { return o >= bin_op::land; }

std::string describe(const token& t)
{
    switch (t.kind)
    {
        case tk::eof: return "end of input";
        case tk::ident: return "identifier \"" + std::string(t.text) + "\"";
        case tk::number: return "number \"" + std::string(t.text) + "\"";
        case tk::duration: return "duration \"" + std::string(t.text) + "\"";
        case tk::string: return "string " + std::string(t.text);
        case tk::lparen: return "\"(\"";
        case tk::rparen: return "right parenthesis \")\"";
        case tk::lbrace: return "\"{\"";
        case tk::rbrace: return "\"}\"";
        case tk::lbracket: return "\"[\"";
        case tk::rbracket: return "\"]\"";
        case tk::comma: return "\",\"";
        case tk::colon: return "\":\"";
        case tk::at: return "\"@\"";
        default: return "<op:" + std::string(t.text) + ">";
    }
}

class parser
{
public:
    explicit parser(std::string_view q) : m_lx(q) { m_lx.next(m_t); }

    std::unique_ptr<expr_node> parse()
    {
        if (m_t.kind == tk::eof)
            fail("no expression found in input", 0);
        auto e = expr(0);
        if (m_t.kind != tk::eof)
            fail("unexpected " + describe(m_t));
        return e;
    }

private:
    [[noreturn]] void fail(std::string msg, uint32_t pos) { throw parse_fail{pos, std::move(msg)}; }
    [[noreturn]] void fail(std::string msg) { fail(std::move(msg), m_t.pos); }
    void advance() { m_lx.next(m_t); }
    bool ident(std::string_view kw) const { return m_t.kind == tk::ident && ieq(m_t.text, kw); }
    void expect(tk k, const char* context)
    {
        if (m_t.kind != k)
            fail("unexpected " + describe(m_t) + " in " + context);
        advance();
    }

    // The binding of the operator at the current token, 0 when it is none.
    int precedence(bin_op& op) const
    {
        switch (m_t.kind)
        {
            case tk::eql: op = bin_op::eq; return 3;
            case tk::neq: op = bin_op::ne; return 3;
            case tk::lss: op = bin_op::lt; return 3;
            case tk::lte: op = bin_op::le; return 3;
            case tk::gtr: op = bin_op::gt; return 3;
            case tk::gte: op = bin_op::ge; return 3;
            case tk::add: op = bin_op::add; return 4;
            case tk::sub: op = bin_op::sub; return 4;
            case tk::mul: op = bin_op::mul; return 5;
            case tk::div: op = bin_op::div; return 5;
            case tk::mod: op = bin_op::mod; return 5;
            case tk::pow: op = bin_op::pow; return 6;
            case tk::ident:
                if (ieq(m_t.text, "or")) { op = bin_op::lor; return 1; }
                if (ieq(m_t.text, "and")) { op = bin_op::land; return 2; }
                if (ieq(m_t.text, "unless")) { op = bin_op::lunless; return 2; }
                if (ieq(m_t.text, "atan2")) { op = bin_op::atan2; return 5; }
                return 0;
            default: return 0;
        }
    }

    std::unique_ptr<expr_node> expr(int min_prec)
    {
        if (++m_depth > 200)
            fail("query nests too deeply");
        auto lhs = unary();
        while (true)
        {
            bin_op op;
            const int p = precedence(op);
            if (!p || p < min_prec)
                break;
            const uint32_t op_pos = m_t.pos;
            advance();
            auto n = std::make_unique<expr_node>();
            n->k = expr_node::kind::binary;
            n->op = op;
            n->pos = op_pos;
            bool matching = false;
            if (ident("bool"))
            {
                if (!is_comparison(op))
                    fail("bool modifier can only be used on comparison operators");
                n->return_bool = true;
                advance();
            }
            if (ident("on") || ident("ignoring"))
            {
                n->on = ident("on");
                advance();
                label_list(n->match_labels);
                matching = true;
                if (ident("group_left") || ident("group_right"))
                {
                    n->cardinality = ident("group_left") ? card::many_to_one : card::one_to_many;
                    advance();
                    if (m_t.kind == tk::lparen)
                        label_list(n->include);
                }
            }
            auto rhs = expr(op == bin_op::pow ? p : p + 1);
            check_binary(*n, *lhs, *rhs, matching);
            n->type = lhs->type == V::scalar && rhs->type == V::scalar ? V::scalar : V::vector;
            n->args.push_back(std::move(lhs));
            n->args.push_back(std::move(rhs));
            lhs = std::move(n);
        }
        --m_depth;
        return lhs;
    }

    void check_binary(expr_node& n, const expr_node& l, const expr_node& r, bool matching)
    {
        const bool ok = [](V t) { return t == V::scalar || t == V::vector; }(l.type) &&
                        [](V t) { return t == V::scalar || t == V::vector; }(r.type);
        if (!ok)
            fail("binary expression must contain only scalar and instant vector types", n.pos);
        const bool scalars = l.type == V::scalar || r.type == V::scalar;
        if (is_comparison(n.op) && l.type == V::scalar && r.type == V::scalar && !n.return_bool)
            fail("comparisons between scalars must use BOOL modifier", n.pos);
        if (is_set(n.op))
        {
            static constexpr std::string_view names[] = {"and", "or", "unless"};
            const auto name = names[static_cast<int>(n.op) - static_cast<int>(bin_op::land)];
            if (scalars)
                fail("set operator \"" + std::string(name) + "\" not allowed in binary scalar expression", n.pos);
            if (n.cardinality != card::one_to_one)
                fail("no grouping allowed for \"" + std::string(name) + "\" operation", n.pos);
            n.cardinality = card::many_to_many;
        }
        if (matching && scalars)
            fail("vector matching only allowed between instant vectors", n.pos);
        if (n.on)
            for (const auto& i : n.include)
                for (const auto& m : n.match_labels)
                    if (i == m)
                        fail("label \"" + i + "\" must not occur in ON and GROUP clause at once", n.pos);
    }

    std::unique_ptr<expr_node> unary()
    {
        if (m_t.kind == tk::add || m_t.kind == tk::sub)
        {
            const bool neg = m_t.kind == tk::sub;
            const uint32_t pos = m_t.pos;
            advance();
            auto operand = expr(6);
            if (operand->type != V::scalar && operand->type != V::vector)
                fail("unary expression only allowed on expressions of type scalar or instant vector", pos);
            if (!neg)
                return operand;
            if (operand->k == expr_node::kind::number)
            {
                operand->num = -operand->num;
                operand->pos = pos;
                return operand;
            }
            auto n = std::make_unique<expr_node>();
            n->k = expr_node::kind::unary;
            n->pos = pos;
            n->type = operand->type;
            n->args.push_back(std::move(operand));
            return n;
        }
        return postfix(primary());
    }

    int64_t duration_or_number(const char* context)
    {
        if (m_t.kind == tk::duration)
        {
            const int64_t ms = m_t.ms;
            advance();
            return ms;
        }
        if (m_t.kind == tk::number && std::isfinite(m_t.num) &&
            std::fabs(m_t.num) * 1000 <= static_cast<double>(max_duration_ms))
        {
            const auto ms = static_cast<int64_t>(std::llround(m_t.num * 1000));
            advance();
            return ms;
        }
        fail("unexpected " + describe(m_t) + " in " + context + ", expected duration");
    }

    std::unique_ptr<expr_node> postfix(std::unique_ptr<expr_node> e)
    {
        while (true)
        {
            if (m_t.kind == tk::lbracket)
            {
                const uint32_t pos = m_t.pos;
                advance();
                if (e->k != expr_node::kind::vector_sel)
                {
                    if (m_t.kind == tk::colon || ((m_t.kind == tk::duration || m_t.kind == tk::number) && peek_colon()))
                        fail("subqueries are not supported", pos);
                    fail("ranges only allowed for vector selectors", pos);
                }
                if (e->offset_ms)
                    fail("no offset modifiers allowed before range", pos);
                const int64_t r = duration_or_number("range");
                if (m_t.kind == tk::colon)
                    fail("subqueries are not supported", pos);
                expect(tk::rbracket, "range");
                if (r <= 0)
                    fail("duration must be greater than 0", pos);
                e->k = expr_node::kind::matrix_sel;
                e->range_ms = r;
                e->type = V::matrix;
                continue;
            }
            if (ident("offset"))
            {
                const uint32_t pos = m_t.pos;
                advance();
                if (e->k != expr_node::kind::vector_sel && e->k != expr_node::kind::matrix_sel)
                    fail("offset modifier must be preceded by an instant vector selector or range vector selector",
                         pos);
                if (e->offset_ms)
                    fail("offset may not be set multiple times", pos);
                bool neg = false;
                if (m_t.kind == tk::sub || m_t.kind == tk::add)
                {
                    neg = m_t.kind == tk::sub;
                    advance();
                }
                const int64_t o = duration_or_number("offset");
                e->offset_ms = neg ? -o : o;
                continue;
            }
            if (m_t.kind == tk::at)
                fail("the @ modifier is not supported");
            return e;
        }
    }

    // Whether a subquery's colon follows the range at the current token.
    bool peek_colon()
    {
        lexer probe = m_lx;
        token t;
        probe.next(t);
        return t.kind == tk::colon;
    }

    std::unique_ptr<expr_node> primary()
    {
        auto n = std::make_unique<expr_node>();
        n->pos = m_t.pos;
        switch (m_t.kind)
        {
            case tk::number:
                n->k = expr_node::kind::number;
                n->type = V::scalar;
                n->num = m_t.num;
                advance();
                return n;
            case tk::string:
                n->k = expr_node::kind::string;
                n->type = V::string;
                n->str = std::move(m_t.str);
                advance();
                return n;
            case tk::lparen:
            {
                advance();
                auto inner = expr(0);
                expect(tk::rparen, "paren expression");
                n->k = expr_node::kind::paren;
                n->type = inner->type;
                n->args.push_back(std::move(inner));
                return n;
            }
            case tk::lbrace:
                n->k = expr_node::kind::vector_sel;
                n->type = V::vector;
                matchers(*n, {});
                return n;
            case tk::ident: break;
            default: fail("unexpected " + describe(m_t));
        }
        const std::string_view word = m_t.text;
        if (ieq(word, "inf") || ieq(word, "nan"))
        {
            n->k = expr_node::kind::number;
            n->type = V::scalar;
            n->num = ieq(word, "inf") ? std::numeric_limits<double>::infinity()
                                      : std::numeric_limits<double>::quiet_NaN();
            advance();
            return n;
        }
        lexer probe = m_lx;
        token after;
        probe.next(after);
        for (const auto& a : aggregators)
            if (ieq(word, a.name) &&
                (after.kind == tk::lparen ||
                 (after.kind == tk::ident && (ieq(after.text, "by") || ieq(after.text, "without")))))
                return aggregate(std::move(n), a.op);
        if (after.kind == tk::lparen)
            return call(std::move(n));
        n->k = expr_node::kind::vector_sel;
        n->type = V::vector;
        const std::string name(word);
        advance();
        matchers(*n, name);
        return n;
    }

    void label_list(std::vector<std::string>& out)
    {
        expect(tk::lparen, "grouping opts");
        while (m_t.kind != tk::rparen)
        {
            if (m_t.kind == tk::ident && valid_label_name(m_t.text))
                out.emplace_back(m_t.text);
            else if (m_t.kind == tk::string)
                out.push_back(m_t.str);
            else
                fail("unexpected " + describe(m_t) + " in grouping opts, expected label");
            advance();
            if (m_t.kind == tk::comma)
                advance();
            else if (m_t.kind != tk::rparen)
                fail("unexpected " + describe(m_t) + " in grouping opts, expected \")\" or \",\"");
        }
        advance();
    }

    void matchers(expr_node& n, const std::string& name)
    {
        std::string inner_name;
        if (m_t.kind == tk::lbrace)
        {
            advance();
            while (m_t.kind != tk::rbrace)
            {
                std::string label;
                const uint32_t lpos = m_t.pos;
                if (m_t.kind == tk::string)
                {
                    label = std::move(m_t.str);
                    advance();
                    if (m_t.kind == tk::comma || m_t.kind == tk::rbrace)
                    {
                        // A quoted string alone in the braces is the metric's name, as Prometheus 3 writes UTF-8 names.
                        if (!inner_name.empty() || !name.empty())
                            fail("metric name must not be set twice", lpos);
                        inner_name = label;
                        n.matchers.push_back({std::string(name_label), match_op::eq, label});
                        if (m_t.kind == tk::comma)
                            advance();
                        continue;
                    }
                }
                else if (m_t.kind == tk::ident && valid_label_name(m_t.text))
                {
                    label.assign(m_t.text);
                    advance();
                }
                else
                    fail("unexpected " + describe(m_t) + " in label matching, expected label");
                match_op op;
                switch (m_t.kind)
                {
                    case tk::assign: op = match_op::eq; break;
                    case tk::neq: op = match_op::ne; break;
                    case tk::re: op = match_op::re; break;
                    case tk::nre: op = match_op::nre; break;
                    default:
                        fail("unexpected " + describe(m_t) + " in label matching, expected one of \"=\", \"!=\", "
                             "\"=~\" or \"!~\"");
                }
                advance();
                if (m_t.kind != tk::string)
                    fail("unexpected " + describe(m_t) + " in label matching, expected string");
                const uint32_t vpos = m_t.pos;
                std::string value = std::move(m_t.str);
                advance();
                if (op == match_op::re || op == match_op::nre)
                {
                    regex r;
                    std::string why;
                    if (!r.compile(value, why))
                        fail(why, vpos);
                }
                if (label == name_label && !name.empty())
                    fail("metric name must not be set twice: \"" + name + "\" or \"" + value + "\"", lpos);
                n.matchers.push_back({std::move(label), op, std::move(value)});
                if (m_t.kind == tk::comma)
                    advance();
                else if (m_t.kind != tk::rbrace)
                    fail("unexpected " + describe(m_t) + " in label matching, expected \",\" or \"}\"");
            }
            advance();
        }
        if (!name.empty())
            n.matchers.insert(n.matchers.begin(), {std::string(name_label), match_op::eq, name});
        bool non_empty = false;
        for (const auto& m : n.matchers)
        {
            switch (m.op)
            {
                case match_op::eq: non_empty = non_empty || !m.value.empty(); break;
                case match_op::ne: non_empty = non_empty || m.value.empty(); break;
                case match_op::re:
                case match_op::nre:
                {
                    regex r;
                    std::string why;
                    const bool empty_ok = r.compile(m.value, why) && r.matches_empty();
                    non_empty = non_empty || (m.op == match_op::re ? !empty_ok : empty_ok);
                    break;
                }
            }
        }
        if (!non_empty)
            fail("vector selector must contain at least one non-empty matcher", n.pos);
    }

    std::unique_ptr<expr_node> aggregate(std::unique_ptr<expr_node> n, agg_op op)
    {
        n->k = expr_node::kind::aggregate;
        n->agg = op;
        n->type = V::vector;
        advance();
        bool grouped = false;
        auto grouping = [&] {
            if (ident("by") || ident("without"))
            {
                if (grouped)
                    fail("aggregation must only contain one grouping clause");
                n->without = ident("without");
                advance();
                label_list(n->grouping);
                grouped = true;
            }
        };
        grouping();
        expect(tk::lparen, "aggregation");
        const bool param = op == agg_op::topk || op == agg_op::bottomk || op == agg_op::quantile ||
                           op == agg_op::count_values;
        std::vector<std::unique_ptr<expr_node>> args;
        if (m_t.kind != tk::rparen)
        {
            args.push_back(expr(0));
            while (m_t.kind == tk::comma)
            {
                advance();
                args.push_back(expr(0));
            }
        }
        expect(tk::rparen, "aggregation");
        const size_t want = param ? 2 : 1;
        if (args.size() != want)
            fail("wrong number of arguments for aggregate expression provided, expected " + std::to_string(want) +
                     ", got " + std::to_string(args.size()),
                 n->pos);
        grouping();
        if (args.back()->type != V::vector)
            fail("expected type instant vector in aggregation expression, got " +
                     std::string(type_name(args.back()->type)),
                 args.back()->pos);
        if (param)
        {
            const V want_t = op == agg_op::count_values ? V::string : V::scalar;
            if (args[0]->type != want_t)
                fail("expected type " + std::string(type_name(want_t)) + " in aggregation parameter, got " +
                         std::string(type_name(args[0]->type)),
                     args[0]->pos);
        }
        n->args = std::move(args);
        return n;
    }

    std::unique_ptr<expr_node> call(std::unique_ptr<expr_node> n)
    {
        const std::string name(m_t.text);
        const func_info* f = find_function(name);
        if (!f)
            fail("unknown function with name \"" + name + "\"");
        advance();
        expect(tk::lparen, "function call");
        if (m_t.kind != tk::rparen)
        {
            n->args.push_back(expr(0));
            while (m_t.kind == tk::comma)
            {
                advance();
                n->args.push_back(expr(0));
            }
        }
        expect(tk::rparen, "function call");
        n->k = expr_node::kind::call;
        n->func = f;
        n->type = f->ret;
        const size_t got = n->args.size();
        if (f->variadic == 0 && got != f->nargs)
            fail("expected " + std::to_string(f->nargs) + " argument(s) in call to \"" + name + "\", got " +
                     std::to_string(got),
                 n->pos);
        if (f->variadic != 0 && got < static_cast<size_t>(f->nargs - 1))
            fail("expected at least " + std::to_string(f->nargs - 1) + " argument(s) in call to \"" + name +
                     "\", got " + std::to_string(got),
                 n->pos);
        if (f->variadic > 0 && got > static_cast<size_t>(f->nargs))
            fail("expected at most " + std::to_string(f->nargs) + " argument(s) in call to \"" + name + "\", got " +
                     std::to_string(got),
                 n->pos);
        for (size_t i = 0; i < got; ++i)
        {
            const V want = f->args[std::min<size_t>(i, f->nargs - 1)];
            if (n->args[i]->type != want)
                fail("expected type " + std::string(type_name(want)) + " in call to function \"" + name + "\", got " +
                         std::string(type_name(n->args[i]->type)),
                     n->args[i]->pos);
        }
        return n;
    }

    lexer m_lx;
    token m_t;
    int m_depth{0};
};

}   // namespace

const func_info* find_function(std::string_view name)
{
    for (const auto& f : functions)
        if (f.name == name)
            return &f;
    return nullptr;
}

std::string_view type_name(value_type t)
{
    switch (t)
    {
        case V::scalar: return "scalar";
        case V::vector: return "instant vector";
        case V::matrix: return "range vector";
        case V::string: return "string";
        default: return "none";
    }
}

bool parse_duration(std::string_view s, int64_t& ms)
{
    return !s.empty() && scan_duration(s, ms) == s.size();
}

bool parse_promql(std::string_view query, size_t max_length, std::unique_ptr<expr_node>& out, query_error& err)
{
    err = {};
    if (query.size() > max_length)
    {
        err.type = "bad_data";
        err.message = "query length " + std::to_string(query.size()) + " exceeds the limit of " +
                      std::to_string(max_length) + " bytes";
        return false;
    }
    try
    {
        parser p(query);
        out = p.parse();
        return true;
    }
    catch (const parse_fail& f)
    {
        // Prometheus says where as line:column, both from 1, the column counted in bytes.
        size_t line = 1, col_from = 0;
        for (size_t i = 0; i < f.pos && i < query.size(); ++i)
            if (query[i] == '\n')
            {
                ++line;
                col_from = i + 1;
            }
        err.type = "bad_data";
        err.position = f.pos;
        err.message = std::to_string(line) + ":" + std::to_string(f.pos - col_from + 1) + ": parse error: " + f.msg;
        return false;
    }
}

}   // namespace socketley::metrics
