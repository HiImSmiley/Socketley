#include "s3_select.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <utility>
#include <vector>

#include "checksum.h"
#include "s3_xml.h"
#include "s3_xml_tree.h"
#include "../../shared/json/json_doc.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/util/ascii.h"

namespace socketley::storage
{

namespace
{

// ─── Errors ─────────────────────────────────────────────────────────────────

struct select_code
{
    std::string_view code;
    std::string_view message;
};

// The codes S3 Select answers with that the catalogue does not hold, every one of them status 400.
constexpr select_code select_codes[] = {
    {"MissingRequiredParameter", "The SelectRequest entity is missing a required parameter. Check the service documentation and try again."},
    {"ObjectSerializationConflict", "InputSerialization and OutputSerialization can only specify one format each."},
    {"InvalidExpressionType", "The ExpressionType is invalid. Only SQL expressions are supported."},
    {"InvalidCompressionFormat", "The file is not in a supported compression format. Only NONE is supported."},
    {"InvalidFileHeaderInfo", "The FileHeaderInfo is invalid. Only NONE, USE, and IGNORE are supported."},
    {"InvalidJsonType", "The JsonType is invalid. Only DOCUMENT and LINES are supported."},
    {"InvalidQuoteFields", "The QuoteFields is invalid. Only ALWAYS and ASNEEDED are supported."},
    {"InvalidRequestParameter", "The value of a parameter in SelectRequest element is invalid. Check the service API documentation and try again."},
    {"UnsupportedScanRangeInput", "Scan range queries are not supported on this type of object."},
    {"ExpressionTooLong", "The SQL expression is too long: The maximum byte-length for the SQL expression is 256 KB."},
    {"OverMaxRecordSize", "The length of a record in the input or result is greater than maxCharsPerRecord of 1 MB."},
    {"CSVParsingError", "Encountered an error parsing the CSV file. Check the file and try again."},
    {"JSONParsingError", "Encountered an error parsing the JSON file. Check the file and try again."},
    {"MissingHeaders", "Some headers in the query are missing from the file. Check the file and try again."},
    {"InvalidColumnIndex", "The column index is invalid. Please check the service documentation and try again."},
    {"InvalidDataSource", "Invalid data source type. Only S3Object is supported."},
    {"InvalidTableAlias", "The SQL expression contains an invalid table alias."},
    {"InvalidDataType", "The SQL expression contains an invalid data type."},
    {"CastFailed", "Attempt to convert from one data type to another using CAST failed in the SQL expression."},
    {"IntegerOverflow", "Int overflow or underflow in the SQL expression."},
    {"LikeInvalidInputs", "Invalid argument given to the LIKE clause in the SQL expression."},
    {"IncorrectSqlFunctionArgumentType", "Incorrect type of arguments in function call in the SQL expression."},
    {"EvaluatorInvalidArguments", "Incorrect number of arguments in the function call in the SQL expression."},
    {"UnsupportedSqlOperation", "Encountered an unsupported SQL operation."},
    {"UnsupportedSqlStructure", "Encountered an unsupported SQL structure. Check the SQL Reference."},
    {"LexerInvalidChar", "The SQL expression contains an invalid character."},
    {"LexerInvalidOperator", "The SQL expression contains an invalid operator."},
    {"LexerInvalidLiteral", "The SQL expression contains an invalid literal."},
    {"ParseExpectedKeyword", "Did not find the expected keyword in the SQL expression."},
    {"ParseExpectedExpression", "Did not find the expected SQL expression."},
    {"ParseExpectedTypeName", "Did not find the expected type name in the SQL expression."},
    {"ParseExpectedNumber", "Did not find the expected number in the SQL expression."},
    {"ParseExpectedRightParenBuiltinFunctionCall", "Did not find the expected right parenthesis character in the SQL expression."},
    {"ParseExpectedArgumentDelimiter", "Did not find the expected argument delimiter in the SQL expression."},
    {"ParseExpectedIdentForAlias", "Did not find the expected identifier for the alias in the SQL expression."},
    {"ParseUnsupportedCallWithStar", "Only COUNT with (*) as a parameter is supported in the SQL expression."},
    {"ParseAsteriskIsNotAloneInSelectList", "Other expressions are not allowed in the SELECT list when '*' is used without dot notation in the SQL expression."},
    {"ParseEmptySelect", "The SQL expression contains an empty SELECT."},
    {"ParseSelectMissingFrom", "The SQL expression contains a missing FROM after SELECT list."},
    {"ParseUnexpectedToken", "The SQL expression contains an unexpected token."},
};

s3_error fail(std::string_view code, std::string message = {})
{
    s3_error e;
    bool known = false;
    for (const select_code& c : select_codes)
        if (c.code == code)
        {
            e     = {std::string(c.code), std::string(c.message), 400};
            known = true;
            break;
        }
    if (!known)
        e = make_error(code);
    if (!message.empty())
        e.message = std::move(message);
    return e;
}

// ─── Text ───────────────────────────────────────────────────────────────────

bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}

std::string_view trim_ws(std::string_view t)
{
    while (!t.empty() && is_space(t.front()))
        t.remove_prefix(1);
    while (!t.empty() && is_space(t.back()))
        t.remove_suffix(1);
    return t;
}

bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

// The bytes of the UTF-8 character at `i`, one for a byte that does not begin one, never past the end.
size_t char_step(std::string_view s, size_t i)
{
    const unsigned char lead = static_cast<unsigned char>(s[i]);
    const size_t n = lead < 0x80 ? 1 : (lead >> 5) == 0x6 ? 2 : (lead >> 4) == 0xE ? 3 : (lead >> 3) == 0x1E ? 4 : 1;
    return std::min(n, s.size() - i);
}

void int_to(std::string& out, int64_t v)
{
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof buf, v);
    out.append(buf, static_cast<size_t>(r.ptr - buf));
}

void real_to(std::string& out, double v)
{
    char buf[40];
    const auto r = std::to_chars(buf, buf + sizeof buf, v);
    out.append(buf, static_cast<size_t>(r.ptr - buf));
}

// ─── JSON ───────────────────────────────────────────────────────────────────

using jnode = socketley::json::jvalue;

// One complete JSON value of any kind, members kept in document order and names given twice kept twice.
bool parse_json(std::string_view text, jnode& out)
{
    socketley::json::json_policy p;
    p.max_depth    = 128;
    p.object_root  = false;
    p.unique_names = false;
    p.check_utf8   = false;
    return socketley::json::json_reader(text, p).document(out);
}

void json_node_to(std::string& out, const jnode& n)
{
    switch (n.k)
    {
        case jnode::kind::null:    out += "null"; return;
        case jnode::kind::boolean: out += n.b ? "true" : "false"; return;
        case jnode::kind::number:  out += n.s; return;
        case jnode::kind::string:  socketley::json::quote_into(out, n.s); return;
        case jnode::kind::array:
            out.push_back('[');
            for (size_t i = 0; i < n.items.size(); ++i)
            {
                if (i)
                    out.push_back(',');
                json_node_to(out, n.items[i]);
            }
            out.push_back(']');
            return;
        case jnode::kind::object:
            out.push_back('{');
            for (size_t i = 0; i < n.members.size(); ++i)
            {
                if (i)
                    out.push_back(',');
                socketley::json::quote_into(out, n.members[i].first);
                out.push_back(':');
                json_node_to(out, n.members[i].second);
            }
            out.push_back('}');
            return;
    }
}

// ─── Values ─────────────────────────────────────────────────────────────────

// MISSING is a path that names nothing, which JSON output leaves out where it writes NULL.
enum class vk : uint8_t { missing, null, boolean, integer, real, string, node };

struct value
{
    vk           k{vk::missing};
    bool         b{false};
    int64_t      i{0};
    double       d{0};
    std::string  s;
    // An array or object of the record, which outlives every value made from it.
    const jnode* n{nullptr};
};

value v_null()
{
    value v;
    v.k = vk::null;
    return v;
}

value v_bool(bool b)
{
    value v;
    v.k = vk::boolean;
    v.b = b;
    return v;
}

value v_int(int64_t i)
{
    value v;
    v.k = vk::integer;
    v.i = i;
    return v;
}

value v_real(double d)
{
    value v;
    v.k = vk::real;
    v.d = d;
    return v;
}

value v_str(std::string s)
{
    value v;
    v.k = vk::string;
    v.s = std::move(s);
    return v;
}

bool absent(const value& v)
{
    return v.k == vk::missing || v.k == vk::null;
}

bool numeric(const value& v)
{
    return v.k == vk::integer || v.k == vk::real;
}

double as_double(const value& v)
{
    return v.k == vk::integer ? static_cast<double>(v.i) : v.d;
}

// A number written as text, an integer when it is one that fits; spaces around it are allowed, words are not.
bool parse_number(std::string_view t, value& out)
{
    t = trim_ws(t);
    if (!t.empty() && t.front() == '+')
    {
        t.remove_prefix(1);
        if (!t.empty() && t.front() == '-')
            return false;
    }
    if (t.empty())
        return false;
    for (const char c : t)
        if (!is_digit(c) && c != '.' && c != '-' && c != '+' && c != 'e' && c != 'E')
            return false;
    int64_t iv = 0;
    auto r = std::from_chars(t.data(), t.data() + t.size(), iv);
    if (r.ec == std::errc{} && r.ptr == t.data() + t.size())
    {
        out = v_int(iv);
        return true;
    }
    double dv = 0;
    r = std::from_chars(t.data(), t.data() + t.size(), dv);
    if (r.ec != std::errc{} || r.ptr != t.data() + t.size())
        return false;
    out = v_real(dv);
    return true;
}

bool parse_bool(std::string_view t, bool& b)
{
    t = trim_ws(t);
    if (ascii::iequals(t, "true"))
        b = true;
    else if (ascii::iequals(t, "false"))
        b = false;
    else
        return false;
    return true;
}

bool as_number(const value& v, value& out)
{
    if (numeric(v))
    {
        out = v;
        return true;
    }
    return v.k == vk::string && parse_number(v.s, out);
}

value from_jnode(const jnode& j)
{
    switch (j.k)
    {
        case jnode::kind::null:    return v_null();
        case jnode::kind::boolean: return v_bool(j.b);
        case jnode::kind::number:
        {
            value v;
            return parse_number(j.s, v) ? v : v_null();
        }
        case jnode::kind::string:  return v_str(j.s);
        case jnode::kind::array:
        case jnode::kind::object:  break;
    }
    value v;
    v.k = vk::node;
    v.n = &j;
    return v;
}

// The value as a CSV field carries it: nothing for NULL, JSON for an array or object.
void text_to(std::string& out, const value& v)
{
    switch (v.k)
    {
        case vk::missing:
        case vk::null:    return;
        case vk::boolean: out += v.b ? "true" : "false"; return;
        case vk::integer: int_to(out, v.i); return;
        case vk::real:    real_to(out, v.d); return;
        case vk::string:  out += v.s; return;
        case vk::node:    json_node_to(out, *v.n); return;
    }
}

void json_value_to(std::string& out, const value& v)
{
    switch (v.k)
    {
        case vk::missing:
        case vk::null:    out += "null"; return;
        case vk::boolean: out += v.b ? "true" : "false"; return;
        case vk::integer: int_to(out, v.i); return;
        case vk::real:
            if (std::isfinite(v.d))
                real_to(out, v.d);
            else
                out += "null";
            return;
        case vk::string:  socketley::json::quote_into(out, v.s); return;
        case vk::node:    json_node_to(out, *v.n); return;
    }
}

int sign_of(int c)
{
    return c < 0 ? -1 : c > 0 ? 1 : 0;
}

int num_order(const value& a, const value& b)
{
    if (a.k == vk::integer && b.k == vk::integer)
        return a.i < b.i ? -1 : a.i > b.i ? 1 : 0;
    const long double x = a.k == vk::integer ? static_cast<long double>(a.i) : static_cast<long double>(a.d);
    const long double y = b.k == vk::integer ? static_cast<long double>(b.i) : static_cast<long double>(b.d);
    return x < y ? -1 : x > y ? 1 : 0;
}

// The order of two present values, a string read as a number beside a number as CSV data needs; false when they
// have none.
bool order(const value& a, const value& b, int& c)
{
    value x;
    value y;
    const value* pa = &a;
    const value* pb = &b;
    if (numeric(a) && b.k == vk::string)
    {
        if (!parse_number(b.s, y))
            return false;
        pb = &y;
    }
    else if (a.k == vk::string && numeric(b))
    {
        if (!parse_number(a.s, x))
            return false;
        pa = &x;
    }
    else if (a.k == vk::boolean && b.k == vk::string)
    {
        bool bb = false;
        if (!parse_bool(b.s, bb))
            return false;
        y  = v_bool(bb);
        pb = &y;
    }
    else if (a.k == vk::string && b.k == vk::boolean)
    {
        bool ab = false;
        if (!parse_bool(a.s, ab))
            return false;
        x  = v_bool(ab);
        pa = &x;
    }
    if (numeric(*pa) && numeric(*pb))
    {
        c = num_order(*pa, *pb);
        return true;
    }
    if (pa->k != pb->k)
        return false;
    switch (pa->k)
    {
        case vk::string:  c = sign_of(pa->s.compare(pb->s)); return true;
        case vk::boolean: c = static_cast<int>(pa->b) - static_cast<int>(pb->b); return true;
        case vk::node:
        {
            std::string l;
            std::string r;
            json_node_to(l, *pa->n);
            json_node_to(r, *pb->n);
            c = sign_of(l.compare(r));
            return true;
        }
        default: return false;
    }
}

// ─── The SQL program ────────────────────────────────────────────────────────

enum class op : uint8_t
{
    lit, ref, neg, not_, and_, or_, eq, ne, lt, le, gt, ge, add, sub, mul, div, mod, concat, like, between, in,
    is_null, is_missing, cast, lower, upper, trim, char_length, substring, coalesce, nullif, agg
};
enum class cast_to : uint8_t { integer, real, string, boolean };
enum class agg_fn : uint8_t { count_star, count, sum, avg, min, max };
enum class trim_side : uint8_t { both, leading, trailing };
enum class step_kind : uint8_t { name, index, all };

struct path_step
{
    step_kind   k{step_kind::name};
    // An unquoted name matches a member or a header whatever its case, a quoted one only exactly.
    bool        quoted{false};
    int64_t     index{0};
    std::string name;
};

enum class like_kind : uint8_t { byte, one, many };

struct like_item
{
    like_kind k{like_kind::byte};
    char      c{0};
};

struct node
{
    op       o{op::lit};
    // NOT LIKE, NOT BETWEEN, NOT IN, IS NOT.
    bool     negate{false};
    // The cast_to, trim_side or agg_fn of the node.
    uint8_t  sub{0};
    // The CSV column a reference reads, -1 until the header names it.
    int64_t  field{-1};
    uint32_t slot{0};
    uint32_t depth{1};
    value    lit;
    std::vector<uint32_t>  args;
    std::vector<path_step> path;
    // A LIKE whose pattern and escape are literals, compiled once.
    bool                   pattern_ready{false};
    std::vector<like_item> pattern;
};

struct select_item
{
    uint32_t    expr{0};
    std::string name;
};

struct program
{
    std::vector<node>        nodes;
    bool                     star{false};
    std::vector<select_item> items;
    // The path after S3Object[*] whose values are the rows, a [*] in it giving one row per element.
    std::vector<path_step>   from;
    std::string              alias;
    bool                     has_where{false};
    uint32_t                 where{0};
    int64_t                  limit{-1};
    std::vector<uint32_t>    aggs;
    bool                     aggregate{false};
};

bool like_compile(std::string_view pat, const std::string_view* esc, std::vector<like_item>& out)
{
    out.clear();
    if (esc && esc->size() != 1)
        return false;
    for (size_t i = 0; i < pat.size(); ++i)
    {
        const char c = pat[i];
        if (esc && c == (*esc)[0])
        {
            if (++i >= pat.size())
                return false;
            out.push_back({like_kind::byte, pat[i]});
        }
        else if (c == '%')
        {
            if (out.empty() || out.back().k != like_kind::many)
                out.push_back({like_kind::many, 0});
        }
        else if (c == '_')
            out.push_back({like_kind::one, 0});
        else
            out.push_back({like_kind::byte, c});
    }
    return true;
}

// Matched with one backtrack point per %, so a pattern costs at most its length times the subject's.
bool like_match(std::string_view s, const std::vector<like_item>& p)
{
    constexpr size_t none = std::numeric_limits<size_t>::max();
    size_t si = 0;
    size_t pi = 0;
    size_t star_p = none;
    size_t star_s = 0;
    while (si < s.size())
    {
        if (pi < p.size())
        {
            const like_item& it = p[pi];
            if (it.k == like_kind::one)
            {
                si += char_step(s, si);
                ++pi;
                continue;
            }
            if (it.k == like_kind::byte && it.c == s[si])
            {
                ++si;
                ++pi;
                continue;
            }
            if (it.k == like_kind::many)
            {
                star_p = pi++;
                star_s = si;
                continue;
            }
        }
        if (star_p == none)
            return false;
        pi = star_p + 1;
        star_s += char_step(s, star_s);
        si = star_s;
    }
    while (pi < p.size() && p[pi].k == like_kind::many)
        ++pi;
    return pi == p.size();
}

// ─── Lexer ──────────────────────────────────────────────────────────────────

enum class tk : uint8_t
{
    end, ident, quoted, string, number, lparen, rparen, comma, dot, lbracket, rbracket, star, plus, minus, slash,
    percent, eq, ne, lt, le, gt, ge, concat, semicolon
};

struct token
{
    tk          t{tk::end};
    std::string text;
};

bool ident_start(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool ident_char(char c)
{
    return ident_start(c) || is_digit(c);
}

bool lex(std::string_view s, std::vector<token>& out, s3_error& err)
{
    size_t i = 0;
    while (i < s.size())
    {
        const char c = s[i];
        if (is_space(c))
        {
            ++i;
            continue;
        }
        token t;
        if (ident_start(c))
        {
            const size_t b = i;
            while (i < s.size() && ident_char(s[i]))
                ++i;
            t.t    = tk::ident;
            t.text = s.substr(b, i - b);
        }
        else if (is_digit(c))
        {
            const size_t b = i;
            while (i < s.size() && is_digit(s[i]))
                ++i;
            if (i < s.size() && s[i] == '.')
            {
                ++i;
                while (i < s.size() && is_digit(s[i]))
                    ++i;
            }
            if (i < s.size() && (s[i] == 'e' || s[i] == 'E'))
            {
                ++i;
                if (i < s.size() && (s[i] == '+' || s[i] == '-'))
                    ++i;
                const size_t d = i;
                while (i < s.size() && is_digit(s[i]))
                    ++i;
                if (i == d)
                {
                    err = fail("LexerInvalidLiteral");
                    return false;
                }
            }
            if (i < s.size() && ident_char(s[i]))
            {
                err = fail("LexerInvalidLiteral");
                return false;
            }
            t.t    = tk::number;
            t.text = s.substr(b, i - b);
        }
        else if (c == '\'' || c == '"')
        {
            // A doubled quote inside stands for one.
            t.t = c == '\'' ? tk::string : tk::quoted;
            ++i;
            bool closed = false;
            while (i < s.size())
            {
                if (s[i] == c)
                {
                    if (i + 1 < s.size() && s[i + 1] == c)
                    {
                        t.text.push_back(c);
                        i += 2;
                        continue;
                    }
                    ++i;
                    closed = true;
                    break;
                }
                t.text.push_back(s[i++]);
            }
            if (!closed || (t.t == tk::quoted && t.text.empty()))
            {
                err = fail("LexerInvalidLiteral");
                return false;
            }
        }
        else
        {
            const char n = i + 1 < s.size() ? s[i + 1] : '\0';
            size_t len = 1;
            switch (c)
            {
                case '(': t.t = tk::lparen; break;
                case ')': t.t = tk::rparen; break;
                case ',': t.t = tk::comma; break;
                case '.': t.t = tk::dot; break;
                case '[': t.t = tk::lbracket; break;
                case ']': t.t = tk::rbracket; break;
                case '*': t.t = tk::star; break;
                case '+': t.t = tk::plus; break;
                case '-': t.t = tk::minus; break;
                case '/': t.t = tk::slash; break;
                case '%': t.t = tk::percent; break;
                case '=': t.t = tk::eq; break;
                case ';': t.t = tk::semicolon; break;
                case '<':
                    t.t = n == '=' ? tk::le : n == '>' ? tk::ne : tk::lt;
                    len = t.t == tk::lt ? 1 : 2;
                    break;
                case '>':
                    t.t = n == '=' ? tk::ge : tk::gt;
                    len = t.t == tk::gt ? 1 : 2;
                    break;
                case '!':
                case '|':
                    if (n != (c == '!' ? '=' : '|'))
                    {
                        err = fail("LexerInvalidOperator");
                        return false;
                    }
                    t.t = c == '!' ? tk::ne : tk::concat;
                    len = 2;
                    break;
                default:
                    err = fail("LexerInvalidChar");
                    return false;
            }
            i += len;
        }
        out.push_back(std::move(t));
    }
    out.push_back(token{});
    return true;
}

// ─── Parser ─────────────────────────────────────────────────────────────────

constexpr std::string_view reserved_words[] = {"SELECT", "FROM", "WHERE",   "LIMIT", "AND",  "OR",
                                               "NOT",    "LIKE", "BETWEEN", "IN",    "IS",   "NULL",
                                               "TRUE",   "FALSE", "MISSING", "AS",   "ESCAPE"};

bool reserved(const token& t)
{
    if (t.t != tk::ident)
        return false;
    for (const std::string_view w : reserved_words)
        if (ascii::iequals(t.text, w))
            return true;
    return false;
}

class sql_compiler
{
public:
    explicit sql_compiler(program& p) : m_p(p) {}

    bool compile(std::string_view sql, s3_error& err)
    {
        if (!lex(sql, m_toks, err))
            return false;
        if (query() == bad || !finish_program())
        {
            err = m_err;
            return false;
        }
        return true;
    }

private:
    static constexpr uint32_t bad       = std::numeric_limits<uint32_t>::max();
    // Parentheses, NOTs and signs nested past this are refused before they can exhaust the stack.
    static constexpr int      max_nest  = 128;
    // A tree deeper than this, such as a long chain of +, is refused because evaluation recurses down it.
    static constexpr uint32_t max_depth = 256;

    uint32_t error(std::string_view code, std::string message = {})
    {
        if (!m_failed)
        {
            m_failed = true;
            m_err    = fail(code, std::move(message));
        }
        return bad;
    }

    const token& cur(size_t ahead = 0) const
    {
        return m_toks[std::min(m_i + ahead, m_toks.size() - 1)];
    }

    void next()
    {
        if (m_i + 1 < m_toks.size())
            ++m_i;
    }

    bool is_kw(std::string_view kw, size_t ahead = 0) const
    {
        const token& t = cur(ahead);
        return t.t == tk::ident && ascii::iequals(t.text, kw);
    }

    bool accept_kw(std::string_view kw)
    {
        if (!is_kw(kw))
            return false;
        next();
        return true;
    }

    bool accept(tk t)
    {
        if (cur().t != t)
            return false;
        next();
        return true;
    }

    uint32_t add(node n)
    {
        for (const uint32_t a : n.args)
            n.depth = std::max(n.depth, m_p.nodes[a].depth + 1);
        if (n.depth > max_depth)
            return error("UnsupportedSqlStructure", "The SQL expression nests too deeply.");
        m_p.nodes.push_back(std::move(n));
        return static_cast<uint32_t>(m_p.nodes.size() - 1);
    }

    uint32_t make(op o, std::vector<uint32_t> args, bool negate = false, uint8_t sub = 0)
    {
        node n;
        n.o      = o;
        n.args   = std::move(args);
        n.negate = negate;
        n.sub    = sub;
        return add(std::move(n));
    }

    uint32_t literal(value v)
    {
        node n;
        n.o   = op::lit;
        n.lit = std::move(v);
        return add(std::move(n));
    }

    uint32_t expr()
    {
        if (++m_nest > max_nest)
            return error("UnsupportedSqlStructure", "The SQL expression nests too deeply.");
        const uint32_t r = disjunction();
        --m_nest;
        return r;
    }

    uint32_t disjunction()
    {
        uint32_t l = conjunction();
        while (l != bad && accept_kw("OR"))
        {
            const uint32_t r = conjunction();
            if (r == bad)
                return bad;
            l = make(op::or_, {l, r});
        }
        return l;
    }

    uint32_t conjunction()
    {
        uint32_t l = negation();
        while (l != bad && accept_kw("AND"))
        {
            const uint32_t r = negation();
            if (r == bad)
                return bad;
            l = make(op::and_, {l, r});
        }
        return l;
    }

    uint32_t negation()
    {
        if (!accept_kw("NOT"))
            return comparison();
        if (++m_nest > max_nest)
            return error("UnsupportedSqlStructure", "The SQL expression nests too deeply.");
        const uint32_t a = negation();
        --m_nest;
        return a == bad ? bad : make(op::not_, {a});
    }

    uint32_t comparison()
    {
        const uint32_t l = concatenation();
        if (l == bad)
            return bad;
        op o = op::lit;
        switch (cur().t)
        {
            case tk::eq: o = op::eq; break;
            case tk::ne: o = op::ne; break;
            case tk::lt: o = op::lt; break;
            case tk::le: o = op::le; break;
            case tk::gt: o = op::gt; break;
            case tk::ge: o = op::ge; break;
            default: break;
        }
        if (o != op::lit)
        {
            next();
            const uint32_t r = concatenation();
            return r == bad ? bad : make(o, {l, r});
        }
        if (accept_kw("IS"))
        {
            const bool neg = accept_kw("NOT");
            if (accept_kw("NULL"))
                return make(op::is_null, {l}, neg);
            if (accept_kw("MISSING"))
                return make(op::is_missing, {l}, neg);
            return error("ParseExpectedKeyword", "IS must be followed by NULL or MISSING.");
        }
        bool neg = false;
        if (is_kw("NOT") && (is_kw("LIKE", 1) || is_kw("BETWEEN", 1) || is_kw("IN", 1)))
        {
            neg = true;
            next();
        }
        if (accept_kw("LIKE"))
        {
            const uint32_t pat = concatenation();
            if (pat == bad)
                return bad;
            std::vector<uint32_t> args{l, pat};
            if (accept_kw("ESCAPE"))
            {
                const uint32_t esc = concatenation();
                if (esc == bad)
                    return bad;
                args.push_back(esc);
            }
            return make(op::like, std::move(args), neg);
        }
        if (accept_kw("BETWEEN"))
        {
            const uint32_t lo = concatenation();
            if (lo == bad)
                return bad;
            if (!accept_kw("AND"))
                return error("ParseExpectedKeyword", "BETWEEN needs AND.");
            const uint32_t hi = concatenation();
            return hi == bad ? bad : make(op::between, {l, lo, hi}, neg);
        }
        if (accept_kw("IN"))
        {
            if (!accept(tk::lparen))
                return error("ParseUnexpectedToken", "IN needs a parenthesized list.");
            std::vector<uint32_t> args{l};
            do
            {
                const uint32_t e = expr();
                if (e == bad)
                    return bad;
                args.push_back(e);
            } while (accept(tk::comma));
            if (!accept(tk::rparen))
                return error("ParseUnexpectedToken", "The IN list is not closed.");
            return make(op::in, std::move(args), neg);
        }
        return l;
    }

    uint32_t concatenation()
    {
        uint32_t l = additive();
        while (l != bad && accept(tk::concat))
        {
            const uint32_t r = additive();
            if (r == bad)
                return bad;
            l = make(op::concat, {l, r});
        }
        return l;
    }

    uint32_t additive()
    {
        uint32_t l = multiplicative();
        while (l != bad && (cur().t == tk::plus || cur().t == tk::minus))
        {
            const op o = cur().t == tk::plus ? op::add : op::sub;
            next();
            const uint32_t r = multiplicative();
            if (r == bad)
                return bad;
            l = make(o, {l, r});
        }
        return l;
    }

    uint32_t multiplicative()
    {
        uint32_t l = unary();
        while (l != bad && (cur().t == tk::star || cur().t == tk::slash || cur().t == tk::percent))
        {
            const op o = cur().t == tk::star ? op::mul : cur().t == tk::slash ? op::div : op::mod;
            next();
            const uint32_t r = unary();
            if (r == bad)
                return bad;
            l = make(o, {l, r});
        }
        return l;
    }

    uint32_t unary()
    {
        if (cur().t != tk::minus && cur().t != tk::plus)
            return primary();
        const bool minus = cur().t == tk::minus;
        next();
        if (++m_nest > max_nest)
            return error("UnsupportedSqlStructure", "The SQL expression nests too deeply.");
        const uint32_t a = unary();
        --m_nest;
        if (a == bad || !minus)
            return a;
        // A negative number is folded into its literal.
        node& n = m_p.nodes[a];
        if (n.o == op::lit && n.lit.k == vk::integer && n.lit.i != std::numeric_limits<int64_t>::min())
        {
            n.lit.i = -n.lit.i;
            return a;
        }
        if (n.o == op::lit && n.lit.k == vk::real)
        {
            n.lit.d = -n.lit.d;
            return a;
        }
        return make(op::neg, {a});
    }

    uint32_t primary()
    {
        const token& t = cur();
        switch (t.t)
        {
            case tk::number:
            {
                value v;
                if (!parse_number(t.text, v))
                    return error("LexerInvalidLiteral");
                next();
                return literal(std::move(v));
            }
            case tk::string:
            {
                value v = v_str(t.text);
                next();
                return literal(std::move(v));
            }
            case tk::lparen:
            {
                next();
                const uint32_t e = expr();
                if (e == bad)
                    return bad;
                if (!accept(tk::rparen))
                    return error("ParseUnexpectedToken", "A parenthesis is not closed.");
                return e;
            }
            case tk::ident:
                if (accept_kw("TRUE"))
                    return literal(v_bool(true));
                if (accept_kw("FALSE"))
                    return literal(v_bool(false));
                if (accept_kw("NULL"))
                    return literal(v_null());
                if (accept_kw("MISSING"))
                    return literal(value{});
                if (cur(1).t == tk::lparen)
                    return call();
                if (reserved(t))
                    return error("ParseExpectedExpression", "Did not find an expression before " + t.text + ".");
                return reference();
            case tk::quoted:
                return reference();
            default:
                return error("ParseExpectedExpression");
        }
    }

    // A name, then members by name and elements by index: s.a."b c"[0].
    uint32_t reference()
    {
        node n;
        n.o = op::ref;
        path_step first;
        first.name   = cur().text;
        first.quoted = cur().t == tk::quoted;
        n.path.push_back(std::move(first));
        next();
        for (;;)
        {
            if (cur().t == tk::dot)
            {
                if (cur(1).t != tk::ident && cur(1).t != tk::quoted)
                    return error("ParseUnexpectedToken", "A dot must be followed by a name.");
                path_step s;
                s.name   = cur(1).text;
                s.quoted = cur(1).t == tk::quoted;
                n.path.push_back(std::move(s));
                next();
                next();
                continue;
            }
            if (cur().t == tk::lbracket)
            {
                next();
                path_step s;
                if (cur().t == tk::number)
                {
                    value v;
                    if (!parse_number(cur().text, v) || v.k != vk::integer || v.i < 0)
                        return error("InvalidColumnIndex");
                    s.k     = step_kind::index;
                    s.index = v.i;
                }
                else if (cur().t == tk::string)
                {
                    s.name   = cur().text;
                    s.quoted = true;
                }
                else if (cur().t == tk::star)
                    return error("UnsupportedSqlStructure", "A wildcard path is only supported in the FROM clause.");
                else
                    return error("ParseUnexpectedToken", "A bracket must hold an index or a name.");
                next();
                if (!accept(tk::rbracket))
                    return error("ParseUnexpectedToken", "A bracket is not closed.");
                n.path.push_back(std::move(s));
                continue;
            }
            return add(std::move(n));
        }
    }

    uint32_t close_call()
    {
        if (!accept(tk::rparen))
            return error("ParseExpectedRightParenBuiltinFunctionCall");
        return 0;
    }

    uint32_t call()
    {
        const std::string name = cur().text;
        next();
        next();
        if (ascii::iequals(name, "CAST"))
        {
            const uint32_t e = expr();
            if (e == bad)
                return bad;
            if (!accept_kw("AS"))
                return error("ParseExpectedKeyword", "CAST needs AS and a type.");
            const token& t = cur();
            cast_to to = cast_to::integer;
            if (t.t != tk::ident)
                return error("ParseExpectedTypeName");
            if (ascii::iequals(t.text, "INT") || ascii::iequals(t.text, "INTEGER") || ascii::iequals(t.text, "BIGINT"))
                to = cast_to::integer;
            else if (ascii::iequals(t.text, "FLOAT") || ascii::iequals(t.text, "DECIMAL") || ascii::iequals(t.text, "DOUBLE") ||
                     ascii::iequals(t.text, "REAL") || ascii::iequals(t.text, "NUMERIC"))
                to = cast_to::real;
            else if (ascii::iequals(t.text, "STRING") || ascii::iequals(t.text, "VARCHAR") || ascii::iequals(t.text, "CHAR"))
                to = cast_to::string;
            else if (ascii::iequals(t.text, "BOOL") || ascii::iequals(t.text, "BOOLEAN"))
                to = cast_to::boolean;
            else
                return error("ParseExpectedTypeName", "CAST to " + t.text + " is not supported.");
            next();
            if (close_call() == bad)
                return bad;
            return make(op::cast, {e}, false, static_cast<uint8_t>(to));
        }
        // INT(x) and FLOAT(x), Ceph's shorthands of the casts, which its clients write.
        if (ascii::iequals(name, "INT") || ascii::iequals(name, "FLOAT"))
        {
            const uint32_t e = expr();
            if (e == bad || close_call() == bad)
                return bad;
            return make(op::cast, {e}, false,
                        static_cast<uint8_t>(ascii::iequals(name, "INT") ? cast_to::integer : cast_to::real));
        }

        static constexpr std::pair<std::string_view, agg_fn> aggregates[] = {
            {"COUNT", agg_fn::count}, {"SUM", agg_fn::sum}, {"AVG", agg_fn::avg},
            {"MIN", agg_fn::min},     {"MAX", agg_fn::max}};
        for (const auto& [agg_name, fn] : aggregates)
        {
            if (!ascii::iequals(name, agg_name))
                continue;
            node n;
            n.o = op::agg;
            if (cur().t == tk::star)
            {
                if (fn != agg_fn::count)
                    return error("ParseUnsupportedCallWithStar");
                next();
                n.sub = static_cast<uint8_t>(agg_fn::count_star);
            }
            else
            {
                const uint32_t e = expr();
                if (e == bad)
                    return bad;
                n.args.push_back(e);
                n.sub = static_cast<uint8_t>(fn);
            }
            if (close_call() == bad)
                return bad;
            n.slot = static_cast<uint32_t>(m_p.aggs.size());
            const uint32_t id = add(std::move(n));
            if (id != bad)
                m_p.aggs.push_back(id);
            return id;
        }

        if (ascii::iequals(name, "TRIM"))
        {
            // TRIM([LEADING|TRAILING|BOTH] [chars] FROM s) or TRIM(s).
            trim_side side = trim_side::both;
            bool      form = false;
            if (accept_kw("LEADING"))
            {
                side = trim_side::leading;
                form = true;
            }
            else if (accept_kw("TRAILING"))
            {
                side = trim_side::trailing;
                form = true;
            }
            else if (accept_kw("BOTH"))
                form = true;
            uint32_t chars = bad;
            uint32_t target = bad;
            if (form && accept_kw("FROM"))
                target = expr();
            else
            {
                const uint32_t e = expr();
                if (e == bad)
                    return bad;
                if (accept_kw("FROM"))
                {
                    chars  = e;
                    target = expr();
                }
                else if (form)
                    return error("ParseExpectedKeyword", "TRIM needs FROM.");
                else
                    target = e;
            }
            if (target == bad || close_call() == bad)
                return bad;
            std::vector<uint32_t> args{target};
            if (chars != bad)
                args.push_back(chars);
            return make(op::trim, std::move(args), false, static_cast<uint8_t>(side));
        }

        if (ascii::iequals(name, "SUBSTRING"))
        {
            const uint32_t s = expr();
            if (s == bad)
                return bad;
            std::vector<uint32_t> args{s};
            const bool sql_form = accept_kw("FROM");
            if (!sql_form && !accept(tk::comma))
                return error("ParseExpectedArgumentDelimiter");
            const uint32_t start = expr();
            if (start == bad)
                return bad;
            args.push_back(start);
            if (sql_form ? accept_kw("FOR") : accept(tk::comma))
            {
                const uint32_t len = expr();
                if (len == bad)
                    return bad;
                args.push_back(len);
            }
            if (close_call() == bad)
                return bad;
            return make(op::substring, std::move(args));
        }

        op o = op::lit;
        size_t min_args = 1;
        size_t max_args = 1;
        if (ascii::iequals(name, "LOWER"))
            o = op::lower;
        else if (ascii::iequals(name, "UPPER"))
            o = op::upper;
        else if (ascii::iequals(name, "CHAR_LENGTH") || ascii::iequals(name, "CHARACTER_LENGTH"))
            o = op::char_length;
        else if (ascii::iequals(name, "COALESCE"))
        {
            o        = op::coalesce;
            max_args = std::numeric_limits<size_t>::max();
        }
        else if (ascii::iequals(name, "NULLIF"))
        {
            o        = op::nullif;
            min_args = 2;
            max_args = 2;
        }
        else
            return error("UnsupportedSqlOperation", "The function " + name + " is not supported.");
        std::vector<uint32_t> args;
        if (cur().t != tk::rparen)
            for (;;)
            {
                const uint32_t e = expr();
                if (e == bad)
                    return bad;
                args.push_back(e);
                if (accept(tk::comma))
                    continue;
                if (cur().t != tk::rparen)
                    return error("ParseExpectedArgumentDelimiter");
                break;
            }
        if (close_call() == bad)
            return bad;
        if (args.size() < min_args || args.size() > max_args)
            return error("EvaluatorInvalidArguments", "Incorrect number of arguments to " + name + ".");
        return make(o, std::move(args));
    }

    // An alias after an item or after S3Object, with or without AS.
    bool alias(std::string& out)
    {
        if (accept_kw("AS"))
        {
            if ((cur().t != tk::ident || reserved(cur())) && cur().t != tk::quoted)
            {
                error("ParseExpectedIdentForAlias");
                return false;
            }
        }
        else if ((cur().t != tk::ident || reserved(cur())) && cur().t != tk::quoted)
            return true;
        out = cur().text;
        next();
        return true;
    }

    uint32_t query()
    {
        if (!accept_kw("SELECT"))
            return error("ParseExpectedKeyword", "The SQL expression must begin with SELECT.");
        if (is_kw("FROM") || cur().t == tk::end)
            return error("ParseEmptySelect");
        std::string star_alias;
        bool qualified_star = false;
        if (accept(tk::star))
            m_p.star = true;
        else if ((cur().t == tk::ident || cur().t == tk::quoted) && cur(1).t == tk::dot && cur(2).t == tk::star)
        {
            star_alias     = cur().text;
            qualified_star = true;
            m_p.star       = true;
            next();
            next();
            next();
        }
        if (m_p.star)
        {
            if (cur().t == tk::comma)
                return error("ParseAsteriskIsNotAloneInSelectList");
        }
        else
            for (;;)
            {
                if (cur().t == tk::star)
                    return error("ParseAsteriskIsNotAloneInSelectList");
                select_item item;
                item.expr = expr();
                if (item.expr == bad || !alias(item.name))
                    return bad;
                m_p.items.push_back(std::move(item));
                if (!accept(tk::comma))
                    break;
            }

        if (!accept_kw("FROM"))
            return error("ParseSelectMissingFrom");
        if (!is_kw("S3Object"))
            return error("InvalidDataSource");
        next();
        for (;;)
        {
            path_step s;
            if (accept(tk::lbracket))
            {
                if (accept(tk::star))
                    s.k = step_kind::all;
                else if (cur().t == tk::number)
                {
                    value v;
                    if (!parse_number(cur().text, v) || v.k != vk::integer || v.i < 0)
                        return error("InvalidColumnIndex");
                    s.k     = step_kind::index;
                    s.index = v.i;
                    next();
                }
                else if (cur().t == tk::string)
                {
                    s.name   = cur().text;
                    s.quoted = true;
                    next();
                }
                else
                    return error("ParseUnexpectedToken", "A bracket must hold *, an index or a name.");
                if (!accept(tk::rbracket))
                    return error("ParseUnexpectedToken", "A bracket is not closed.");
            }
            else if (cur().t == tk::dot && (cur(1).t == tk::ident || cur(1).t == tk::quoted))
            {
                s.name   = cur(1).text;
                s.quoted = cur(1).t == tk::quoted;
                next();
                next();
            }
            else
                break;
            m_p.from.push_back(std::move(s));
        }
        // S3Object[*] is each record, which is what S3Object alone already is.
        if (!m_p.from.empty() && m_p.from.front().k == step_kind::all)
            m_p.from.erase(m_p.from.begin());
        if (!alias(m_p.alias))
            return bad;
        if (qualified_star && !ascii::iequals(star_alias, m_p.alias) && !ascii::iequals(star_alias, "S3Object"))
            return error("InvalidTableAlias");

        if (accept_kw("WHERE"))
        {
            m_p.where = expr();
            if (m_p.where == bad)
                return bad;
            m_p.has_where = true;
        }
        if (accept_kw("LIMIT"))
        {
            int64_t n = -1;
            const std::string& t = cur().text;
            const auto r = std::from_chars(t.data(), t.data() + t.size(), n);
            if (cur().t != tk::number || r.ec != std::errc{} || r.ptr != t.data() + t.size() || n < 0)
                return error("ParseExpectedNumber", "LIMIT needs a non-negative integer.");
            m_p.limit = n;
            next();
        }
        accept(tk::semicolon);
        if (cur().t != tk::end)
            return error("ParseUnexpectedToken", "Unexpected " + (cur().text.empty() ? std::string("token")
                                                                                     : "'" + cur().text + "'") +
                                                     " after the query.");
        return 0;
    }

    bool has_agg(uint32_t id) const
    {
        const node& n = m_p.nodes[id];
        if (n.o == op::agg)
            return true;
        for (const uint32_t a : n.args)
            if (has_agg(a))
                return true;
        return false;
    }

    // Whether an aggregate query reads a record only inside an aggregate, and no aggregate holds another.
    bool agg_shape(uint32_t id, bool inside) const
    {
        const node& n = m_p.nodes[id];
        if (n.o == op::agg && inside)
            return false;
        if (n.o == op::ref && !inside)
            return false;
        for (const uint32_t a : n.args)
            if (!agg_shape(a, inside || n.o == op::agg))
                return false;
        return true;
    }

    bool finish_program()
    {
        for (node& n : m_p.nodes)
        {
            if (n.o != op::ref || n.path.empty())
                continue;
            const path_step& s = n.path.front();
            if (s.k == step_kind::name && !s.quoted &&
                ((!m_p.alias.empty() && ascii::iequals(s.name, m_p.alias)) || ascii::iequals(s.name, "S3Object")))
                n.path.erase(n.path.begin());
        }
        for (size_t k = 0; k < m_p.items.size(); ++k)
        {
            select_item& item = m_p.items[k];
            if (!item.name.empty())
                continue;
            const node& n = m_p.nodes[item.expr];
            if (n.o == op::ref && !n.path.empty() && n.path.back().k == step_kind::name)
                item.name = n.path.back().name;
            else
                item.name = "_" + std::to_string(k + 1);
        }
        for (const select_item& item : m_p.items)
            if (has_agg(item.expr))
                m_p.aggregate = true;
        if (m_p.aggregate)
            for (const select_item& item : m_p.items)
                if (!agg_shape(item.expr, false))
                {
                    error("UnsupportedSqlStructure",
                          "A query with an aggregate may only read a record inside one, and aggregates do not nest.");
                    return false;
                }
        if (m_p.has_where && has_agg(m_p.where))
        {
            error("UnsupportedSqlOperation", "Aggregate functions are not allowed in WHERE.");
            return false;
        }
        for (node& n : m_p.nodes)
        {
            if (n.o != op::like)
                continue;
            const node& pat = m_p.nodes[n.args[1]];
            const node* esc = n.args.size() > 2 ? &m_p.nodes[n.args[2]] : nullptr;
            if (pat.o != op::lit || pat.lit.k != vk::string || (esc && (esc->o != op::lit || esc->lit.k != vk::string)))
                continue;
            const std::string_view e = esc ? std::string_view(esc->lit.s) : std::string_view{};
            if (!like_compile(pat.lit.s, esc ? &e : nullptr, n.pattern))
            {
                error("LikeInvalidInputs");
                return false;
            }
            n.pattern_ready = true;
        }
        return true;
    }

    program&           m_p;
    std::vector<token> m_toks;
    size_t             m_i{0};
    int                m_nest{0};
    bool               m_failed{false};
    s3_error           m_err;
};

// A name `_N` that reads the Nth CSV column, 0 when it is `_0` or past any column there could be.
bool positional(std::string_view name, uint64_t& n)
{
    if (name.size() < 2 || name[0] != '_')
        return false;
    for (size_t i = 1; i < name.size(); ++i)
        if (!is_digit(name[i]))
            return false;
    n = 0;
    const auto r = std::from_chars(name.data() + 1, name.data() + name.size(), n);
    if (r.ec != std::errc{} || n > select_max_record)
        n = 0;
    return true;
}

const jnode* member_of(const jnode& obj, const path_step& s)
{
    if (obj.k != jnode::kind::object)
        return nullptr;
    for (const auto& m : obj.members)
        if (m.first == s.name)
            return &m.second;
    if (!s.quoted)
        for (const auto& m : obj.members)
            if (ascii::iequals(m.first, s.name))
                return &m.second;
    return nullptr;
}

const jnode* step_into(const jnode& n, const path_step& s)
{
    if (s.k == step_kind::index)
        return n.k == jnode::kind::array && static_cast<uint64_t>(s.index) < n.items.size()
                   ? &n.items[static_cast<size_t>(s.index)]
                   : nullptr;
    return member_of(n, s);
}

struct agg_state
{
    uint64_t count{0};
    bool     is_real{false};
    int64_t  isum{0};
    double   dsum{0};
    bool     has{false};
    value    best;
};

// The rank MIN and MAX order values of different types by: booleans, then numbers, then strings, then the rest.
int type_rank(const value& v)
{
    return v.k == vk::boolean ? 0 : numeric(v) ? 1 : v.k == vk::string ? 2 : 3;
}

}   // namespace

// ─── Request ────────────────────────────────────────────────────────────────

namespace
{

// The children of `n` named in `names` into `slots`, each at most once; false for any other child, a repeat, or text
// in an element that should only hold elements.
template <size_t N>
bool pick(const xml_node& n, const std::string_view (&names)[N], const xml_node* (&slots)[N])
{
    if (n.kids.empty() && !trim_ws(n.text).empty())
        return false;
    for (const xml_node& k : n.kids)
    {
        bool found = false;
        for (size_t i = 0; i < N; ++i)
            if (k.name == names[i])
            {
                if (slots[i])
                    return false;
                slots[i] = &k;
                found    = true;
                break;
            }
        if (!found)
            return false;
    }
    return true;
}

bool one_byte(const xml_node* n, char& out)
{
    if (!n)
        return true;
    if (n->text.size() != 1)
        return false;
    out = n->text[0];
    return true;
}

bool delimiter(const xml_node* n, std::string& out)
{
    if (!n)
        return true;
    if (n->text.empty() || n->text.size() > 2)
        return false;
    out = n->text;
    return true;
}

bool leaves(std::initializer_list<const xml_node*> nodes)
{
    for (const xml_node* n : nodes)
        if (n && !n->kids.empty())
            return false;
    return true;
}

bool parse_u64(const xml_node* n, uint64_t& out)
{
    const std::string_view t = trim_ws(n->text);
    const auto r = std::from_chars(t.data(), t.data() + t.size(), out);
    return !t.empty() && r.ec == std::errc{} && r.ptr == t.data() + t.size();
}

bool parse_input(const xml_node& in, select_request& out, s3_error& err)
{
    static constexpr std::string_view names[] = {"CompressionType", "CSV", "JSON", "Parquet"};
    const xml_node* k[std::size(names)]{};
    if (!pick(in, names, k) || !leaves({k[0]}))
    {
        err = fail("MalformedXML");
        return false;
    }
    if (k[0])
    {
        const std::string_view c = trim_ws(k[0]->text);
        if (ascii::iequals(c, "GZIP") || ascii::iequals(c, "BZIP2"))
        {
            err = fail("NotImplemented", "SelectObjectContent over a " + std::string(c) + " object is not supported.");
            return false;
        }
        if (!c.empty() && !ascii::iequals(c, "NONE"))
        {
            err = fail("InvalidCompressionFormat");
            return false;
        }
    }
    const int formats = (k[1] != nullptr) + (k[2] != nullptr) + (k[3] != nullptr);
    if (formats != 1)
    {
        err = fail(formats ? "ObjectSerializationConflict" : "MissingRequiredParameter");
        return false;
    }
    if (k[3])
    {
        err = fail("NotImplemented", "SelectObjectContent over Parquet is not supported.");
        return false;
    }
    if (k[2])
    {
        static constexpr std::string_view jnames[] = {"Type"};
        const xml_node* j[std::size(jnames)]{};
        if (!pick(*k[2], jnames, j) || !leaves({j[0]}))
        {
            err = fail("MalformedXML");
            return false;
        }
        out.input = select_format::json;
        const std::string_view t = j[0] ? trim_ws(j[0]->text) : std::string_view("DOCUMENT");
        if (ascii::iequals(t, "DOCUMENT"))
            out.json_type = select_json_type::document;
        else if (ascii::iequals(t, "LINES"))
            out.json_type = select_json_type::lines;
        else
        {
            err = fail("InvalidJsonType");
            return false;
        }
        return true;
    }
    static constexpr std::string_view cnames[] = {"FileHeaderInfo", "Comments",       "QuoteEscapeCharacter",
                                                  "RecordDelimiter", "FieldDelimiter", "QuoteCharacter",
                                                  "AllowQuotedRecordDelimiter"};
    const xml_node* c[std::size(cnames)]{};
    if (!pick(*k[1], cnames, c) || !leaves({c[0], c[1], c[2], c[3], c[4], c[5], c[6]}))
    {
        err = fail("MalformedXML");
        return false;
    }
    out.input = select_format::csv;
    select_csv_input& csv = out.csv_in;
    if (c[0])
    {
        const std::string_view h = trim_ws(c[0]->text);
        if (ascii::iequals(h, "USE"))
            csv.header = select_header::use;
        else if (ascii::iequals(h, "IGNORE"))
            csv.header = select_header::ignore;
        else if (ascii::iequals(h, "NONE"))
            csv.header = select_header::none;
        else
        {
            err = fail("InvalidFileHeaderInfo");
            return false;
        }
    }
    if (c[1])
        csv.comments = c[1]->text;
    bool allow = false;
    if (csv.comments.size() > 1 || !one_byte(c[2], csv.quote_escape) || !delimiter(c[3], csv.record_delimiter) ||
        !one_byte(c[4], csv.field_delimiter) || !one_byte(c[5], csv.quote) ||
        (c[6] && !parse_bool(c[6]->text, allow)))
    {
        err = fail("InvalidRequestParameter");
        return false;
    }
    csv.allow_quoted_record_delimiter = allow;
    return true;
}

bool parse_output(const xml_node& o, select_request& out, s3_error& err)
{
    static constexpr std::string_view names[] = {"CSV", "JSON"};
    const xml_node* k[std::size(names)]{};
    if (!pick(o, names, k))
    {
        err = fail("MalformedXML");
        return false;
    }
    if ((k[0] != nullptr) == (k[1] != nullptr))
    {
        err = fail(k[0] ? "ObjectSerializationConflict" : "MissingRequiredParameter");
        return false;
    }
    if (k[1])
    {
        static constexpr std::string_view jnames[] = {"RecordDelimiter"};
        const xml_node* j[std::size(jnames)]{};
        if (!pick(*k[1], jnames, j) || !leaves({j[0]}))
        {
            err = fail("MalformedXML");
            return false;
        }
        out.output = select_format::json;
        if (!delimiter(j[0], out.json_record_delimiter))
        {
            err = fail("InvalidRequestParameter");
            return false;
        }
        return true;
    }
    static constexpr std::string_view cnames[] = {"QuoteFields", "QuoteEscapeCharacter", "RecordDelimiter",
                                                  "FieldDelimiter", "QuoteCharacter"};
    const xml_node* c[std::size(cnames)]{};
    if (!pick(*k[0], cnames, c) || !leaves({c[0], c[1], c[2], c[3], c[4]}))
    {
        err = fail("MalformedXML");
        return false;
    }
    out.output = select_format::csv;
    select_csv_output& csv = out.csv_out;
    if (c[0])
    {
        const std::string_view q = trim_ws(c[0]->text);
        if (ascii::iequals(q, "ALWAYS"))
            csv.quote_always = true;
        else if (ascii::iequals(q, "ASNEEDED"))
            csv.quote_always = false;
        else
        {
            err = fail("InvalidQuoteFields");
            return false;
        }
    }
    if (!one_byte(c[1], csv.quote_escape) || !delimiter(c[2], csv.record_delimiter) ||
        !one_byte(c[3], csv.field_delimiter) || !one_byte(c[4], csv.quote))
    {
        err = fail("InvalidRequestParameter");
        return false;
    }
    return true;
}

}   // namespace

bool parse_select_request(std::string_view xml, select_request& out, s3_error& err)
{
    out = select_request{};
    xml_node root;
    xml_reader reader(xml);
    if (!reader.document(root) || root.name != "SelectObjectContentRequest")
    {
        err = fail("MalformedXML");
        return false;
    }
    static constexpr std::string_view names[] = {"Expression",         "ExpressionType",      "RequestProgress",
                                                 "InputSerialization", "OutputSerialization", "ScanRange"};
    const xml_node* k[std::size(names)]{};
    if (!pick(root, names, k) || !leaves({k[0], k[1]}))
    {
        err = fail("MalformedXML");
        return false;
    }
    if (!k[0] || !k[1] || !k[3] || !k[4])
    {
        err = fail("MissingRequiredParameter");
        return false;
    }
    if (!ascii::iequals(trim_ws(k[1]->text), "SQL"))
    {
        err = fail("InvalidExpressionType");
        return false;
    }
    out.expression = k[0]->text;
    if (out.expression.size() > select_max_expression)
    {
        err = fail("ExpressionTooLong");
        return false;
    }
    if (k[2])
    {
        static constexpr std::string_view pnames[] = {"Enabled"};
        const xml_node* p[std::size(pnames)]{};
        if (!pick(*k[2], pnames, p) || !leaves({p[0]}))
        {
            err = fail("MalformedXML");
            return false;
        }
        if (p[0] && !parse_bool(p[0]->text, out.progress))
        {
            err = fail("InvalidRequestParameter");
            return false;
        }
    }
    if (!parse_input(*k[3], out, err) || !parse_output(*k[4], out, err))
        return false;
    if (k[5])
    {
        static constexpr std::string_view snames[] = {"Start", "End"};
        const xml_node* s[std::size(snames)]{};
        if (!pick(*k[5], snames, s) || !leaves({s[0], s[1]}))
        {
            err = fail("MalformedXML");
            return false;
        }
        out.has_scan_start = s[0] != nullptr;
        out.has_scan_end   = s[1] != nullptr;
        if ((!s[0] && !s[1]) || (s[0] && !parse_u64(s[0], out.scan_start)) ||
            (s[1] && !parse_u64(s[1], out.scan_end)))
        {
            err = fail("InvalidRequestParameter", "ScanRange needs a Start or an End, each a non-negative integer.");
            return false;
        }
    }
    select_engine check;
    return check.init(out, err);
}

// ─── Engine ─────────────────────────────────────────────────────────────────

namespace
{

enum class cst : uint8_t { field_start, unquoted, quoted, quoted_quote, quoted_escape, after_close, comment };

struct row
{
    const std::vector<std::string>* fields{nullptr};
    size_t                          nfields{0};
    const jnode*                    doc{nullptr};
};

// A field longer than this gives its buffer back after its record, so one long record holds no memory after it.
constexpr size_t field_keep = size_t{64} << 10;
// Columns kept between records; a wider record reallocates the rest.
constexpr size_t fields_keep = 1024;

}   // namespace

struct select_engine::impl
{
    select_request req;
    program        prog;
    bool           ready{false};
    bool           failed{false};
    bool           done{false};
    bool           finished{false};
    bool           final_pass{false};
    s3_error       err;
    std::string    out;
    std::string    scratch;
    uint64_t       first{0};
    // The object offset of the next byte fed.
    uint64_t       pos{0};
    uint64_t       scan_end{std::numeric_limits<uint64_t>::max()};
    // Before the first record a ScanRange starts in, everything up to a record delimiter is passed over.
    bool           skipping{false};
    bool           skip_prev{false};
    uint64_t       rec_start{0};
    uint64_t       returned{0};
    uint64_t       emitted{0};
    std::vector<agg_state> accs;
    std::vector<value>     vals;

    // CSV.
    cst                      cs{cst::field_start};
    std::vector<std::string> fields;
    size_t                   nf{0};
    size_t                   rec_bytes{0};
    bool                     rd_pending{false};
    // The current field's last byte is a '\r' outside quotes, which a "\n" delimiter drops so CRLF files read clean.
    bool                     cr{false};
    bool                     header_pending{false};
    std::vector<std::string> header;

    // JSON.
    std::string rec;
    bool        jstarted{false};
    bool        jstring{false};
    bool        jescape{false};
    uint64_t    jdepth{0};

    void fault(std::string_view code, std::string message = {})
    {
        if (failed)
            return;
        failed = true;
        done   = true;
        err    = fail(code, std::move(message));
    }

    // ── Setup ──

    bool init(const select_request& r, s3_error& e, uint64_t object_size)
    {
        req = r;
        if (req.expression.size() > select_max_expression)
        {
            e = fail("ExpressionTooLong");
            return false;
        }
        const std::string& rd = req.csv_in.record_delimiter;
        if (rd.empty() || rd.size() > 2 || req.csv_in.comments.size() > 1 || req.csv_out.record_delimiter.empty() ||
            req.json_record_delimiter.empty())
        {
            e = fail("InvalidRequestParameter");
            return false;
        }
        sql_compiler compiler(prog);
        if (!compiler.compile(req.expression, e) || !bind(e))
            return false;

        const bool ranged = req.has_scan_start || req.has_scan_end;
        uint64_t start = 0;
        if (req.has_scan_start)
        {
            start = req.scan_start;
            if (req.has_scan_end)
                scan_end = req.scan_end;
        }
        else if (req.has_scan_end)
            start = object_size > req.scan_end ? object_size - req.scan_end : 0;
        if (req.has_scan_start && req.has_scan_end && req.scan_start > req.scan_end)
        {
            e = fail("InvalidRequestParameter", "ScanRange Start is past its End.");
            return false;
        }
        const bool csv = req.input == select_format::csv;
        if (ranged && ((!csv && req.json_type == select_json_type::document) ||
                       (csv && req.csv_in.allow_quoted_record_delimiter)))
        {
            e = fail("UnsupportedScanRangeInput");
            return false;
        }
        if (start > 0 && csv && req.csv_in.header == select_header::use)
        {
            e = fail("UnsupportedScanRangeInput", "A ScanRange past the first byte cannot read the header it names.");
            return false;
        }
        const uint64_t rd_len = csv ? rd.size() : 1;
        first     = start > 0 ? start - std::min(start, rd_len) : 0;
        skipping  = start > 0;
        pos       = first;
        rec_start = first;

        fields.resize(1);
        header_pending = csv && start == 0 && req.csv_in.header != select_header::none;
        accs.resize(prog.aggs.size());
        if (prog.limit == 0)
            done = true;
        ready = true;
        return true;
    }

    // Resolves what a CSV reference reads by position now, and refuses one that names a header there is not.
    bool bind(s3_error& e)
    {
        if (req.input != select_format::csv)
            return true;
        if (!prog.from.empty())
        {
            e = fail("UnsupportedSqlStructure", "A path after S3Object needs JSON input.");
            return false;
        }
        for (node& n : prog.nodes)
        {
            if (n.o != op::ref)
                continue;
            if (n.path.empty() || n.path.front().k != step_kind::name)
            {
                e = fail("UnsupportedSqlStructure", "A CSV record is read by column.");
                return false;
            }
            const path_step& s = n.path.front();
            uint64_t idx = 0;
            if (!s.quoted && positional(s.name, idx))
            {
                if (idx == 0)
                {
                    e = fail("InvalidColumnIndex");
                    return false;
                }
                n.field = static_cast<int64_t>(idx - 1);
            }
            else if (req.csv_in.header != select_header::use)
            {
                e = fail("MissingHeaders");
                return false;
            }
        }
        return true;
    }

    void bind_header()
    {
        for (node& n : prog.nodes)
        {
            if (n.o != op::ref || n.field >= 0)
                continue;
            const path_step& s = n.path.front();
            for (size_t i = 0; i < header.size() && n.field < 0; ++i)
                if (header[i] == s.name)
                    n.field = static_cast<int64_t>(i);
            for (size_t i = 0; i < header.size() && n.field < 0 && !s.quoted; ++i)
                if (ascii::iequals(header[i], s.name))
                    n.field = static_cast<int64_t>(i);
            if (n.field < 0)
            {
                fault("MissingHeaders", "The header has no column named " + s.name + ".");
                return;
            }
        }
    }

    void check_end()
    {
        if (rec_start > scan_end)
            done = true;
    }

    bool skip_byte(char c, std::string_view rd)
    {
        if (rd.size() == 1)
            return c == rd[0];
        const bool hit = skip_prev && c == rd[1];
        skip_prev      = c == rd[0];
        return hit;
    }

    // ── CSV ──

    void csv_feed(std::string_view in)
    {
        const std::string_view rd = req.csv_in.record_delimiter;
        for (const char c : in)
        {
            if (done)
                return;
            ++pos;
            if (skipping)
            {
                if (skip_byte(c, rd))
                {
                    skipping  = false;
                    rec_start = pos;
                    check_end();
                }
                continue;
            }
            csv_byte(c, rd);
        }
    }

    bool csv_delimits() const
    {
        return (cs != cst::quoted && cs != cst::quoted_escape) || !req.csv_in.allow_quoted_record_delimiter;
    }

    void csv_byte(char c, std::string_view rd)
    {
        if (rd.size() == 2)
        {
            if (rd_pending)
            {
                rd_pending = false;
                if (c == rd[1])
                {
                    csv_end_record();
                    return;
                }
                csv_data(rd[0]);
                if (failed)
                    return;
            }
            if (c == rd[0] && csv_delimits())
            {
                rd_pending = true;
                return;
            }
            csv_data(c);
            return;
        }
        if (c == rd[0] && csv_delimits())
            csv_end_record();
        else
            csv_data(c);
    }

    void append_plain(char c)
    {
        fields[nf].push_back(c);
        cr = c == '\r';
    }

    void append_quoted(char c)
    {
        fields[nf].push_back(c);
        cr = false;
    }

    void end_field()
    {
        ++nf;
        if (nf == fields.size())
            fields.emplace_back();
        fields[nf].clear();
        cr = false;
        cs = cst::field_start;
    }

    void csv_data(char c)
    {
        const select_csv_input& in = req.csv_in;
        if (cs == cst::comment)
            return;
        if (cs == cst::field_start && rec_bytes == 0 && !in.comments.empty() && c == in.comments[0])
        {
            cs = cst::comment;
            return;
        }
        if (++rec_bytes > select_max_record)
        {
            fault("OverMaxRecordSize");
            return;
        }
        switch (cs)
        {
            case cst::field_start:
                if (c == in.quote)
                    cs = cst::quoted;
                else if (c == in.field_delimiter)
                    end_field();
                else
                {
                    cs = cst::unquoted;
                    append_plain(c);
                }
                return;
            case cst::unquoted:
                if (c == in.field_delimiter)
                    end_field();
                else
                    append_plain(c);
                return;
            case cst::quoted:
                if (c == in.quote_escape && in.quote_escape != in.quote)
                    cs = cst::quoted_escape;
                else if (c == in.quote)
                    cs = in.quote_escape == in.quote ? cst::quoted_quote : cst::after_close;
                else
                    append_quoted(c);
                return;
            case cst::quoted_escape:
                if (c != in.quote && c != in.quote_escape)
                    append_quoted(in.quote_escape);
                append_quoted(c);
                cs = cst::quoted;
                return;
            case cst::quoted_quote:
                if (c == in.quote)
                {
                    append_quoted(c);
                    cs = cst::quoted;
                    return;
                }
                cs = cst::after_close;
                [[fallthrough]];
            case cst::after_close:
                // Bytes after a closing quote are kept as part of the field rather than refused.
                if (c == in.field_delimiter)
                    end_field();
                else
                    append_plain(c);
                return;
            case cst::comment: return;
        }
    }

    void csv_close_record()
    {
        const bool crlf  = cr && req.csv_in.record_delimiter == "\n";
        const bool blank = rec_bytes == 0 || (rec_bytes == 1 && crlf);
        if (cs != cst::comment && !blank)
        {
            if (crlf)
                fields[nf].pop_back();
            ++nf;
            csv_record();
        }
        for (size_t i = 0; i < std::min(nf + 1, fields.size()); ++i)
            if (fields[i].capacity() > field_keep)
                std::string().swap(fields[i]);
        if (fields.size() > fields_keep)
            fields.resize(fields_keep);
        cs        = cst::field_start;
        rec_bytes = 0;
        nf        = 0;
        cr        = false;
        fields[0].clear();
    }

    void csv_end_record()
    {
        csv_close_record();
        rec_start = pos;
        check_end();
    }

    void csv_record()
    {
        if (header_pending)
        {
            header_pending = false;
            if (req.csv_in.header == select_header::use)
            {
                header.assign(fields.begin(), fields.begin() + static_cast<std::ptrdiff_t>(nf));
                bind_header();
            }
            return;
        }
        run_row(row{&fields, nf, nullptr});
    }

    // ── JSON ──

    void json_lines_feed(std::string_view in)
    {
        size_t i = 0;
        while (i < in.size() && !done)
        {
            if (skipping)
            {
                const size_t nl = in.find('\n', i);
                if (nl == std::string_view::npos)
                {
                    pos += in.size() - i;
                    return;
                }
                pos += nl + 1 - i;
                i         = nl + 1;
                skipping  = false;
                rec_start = pos;
                check_end();
                continue;
            }
            const size_t nl = in.find('\n', i);
            const std::string_view span = in.substr(i, nl == std::string_view::npos ? std::string_view::npos : nl - i);
            if (rec.size() + span.size() > select_max_record)
            {
                pos += span.size();
                fault("OverMaxRecordSize");
                return;
            }
            if (nl == std::string_view::npos)
            {
                rec.append(span);
                pos += span.size();
                return;
            }
            pos += span.size() + 1;
            i = nl + 1;
            if (rec.empty())
                json_record(span);
            else
            {
                rec.append(span);
                json_record(rec);
                rec.clear();
            }
            rec_start = pos;
            check_end();
        }
    }

    void json_document_feed(std::string_view in)
    {
        constexpr size_t none = std::string_view::npos;
        size_t from = jstarted ? 0 : none;
        for (size_t i = 0; i < in.size(); ++i)
        {
            const char c = in[i];
            if (!jstarted)
            {
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                    continue;
                if (c != '{' && c != '[')
                {
                    pos += i + 1;
                    fault("JSONParsingError", "A JSON document must hold objects or arrays.");
                    return;
                }
                jstarted = true;
                jdepth   = 1;
                jstring  = false;
                jescape  = false;
                from     = i;
                continue;
            }
            if (jstring)
            {
                if (jescape)
                    jescape = false;
                else if (c == '\\')
                    jescape = true;
                else if (c == '"')
                    jstring = false;
                continue;
            }
            if (c == '"')
                jstring = true;
            else if (c == '{' || c == '[')
                ++jdepth;
            else if ((c == '}' || c == ']') && --jdepth == 0)
            {
                const std::string_view span = in.substr(from, i + 1 - from);
                jstarted = false;
                from     = none;
                if (rec.size() + span.size() > select_max_record)
                {
                    pos += i + 1;
                    fault("OverMaxRecordSize");
                    return;
                }
                if (rec.empty())
                    json_record(span);
                else
                {
                    rec.append(span);
                    json_record(rec);
                    rec.clear();
                }
                if (done)
                {
                    pos += i + 1;
                    return;
                }
            }
        }
        pos += in.size();
        if (jstarted)
        {
            const std::string_view span = in.substr(from);
            if (rec.size() + span.size() > select_max_record)
            {
                fault("OverMaxRecordSize");
                return;
            }
            rec.append(span);
        }
    }

    void json_record(std::string_view text)
    {
        if (trim_ws(text).empty())
            return;
        jnode doc;
        if (!parse_json(text, doc))
        {
            fault("JSONParsingError");
            return;
        }
        json_rows(doc, 0);
    }

    void json_rows(const jnode& n, size_t step)
    {
        if (done)
            return;
        if (step == prog.from.size())
        {
            run_row(row{nullptr, 0, &n});
            return;
        }
        const path_step& s = prog.from[step];
        if (s.k == step_kind::all)
        {
            if (n.k == jnode::kind::array)
                for (const jnode& item : n.items)
                {
                    json_rows(item, step + 1);
                    if (done)
                        return;
                }
            return;
        }
        if (const jnode* next = step_into(n, s))
            json_rows(*next, step + 1);
    }

    // ── Rows ──

    void run_row(const row& r)
    {
        if (prog.has_where)
        {
            const value w = eval(prog.where, r);
            if (failed || truth(w) != 1)
                return;
        }
        if (prog.aggregate)
        {
            accumulate(r);
            return;
        }
        emit(r);
        if (prog.limit >= 0 && ++emitted >= static_cast<uint64_t>(prog.limit))
            done = true;
    }

    void csv_out_field(std::string_view s)
    {
        const select_csv_output& o = req.csv_out;
        bool quote = o.quote_always;
        for (size_t i = 0; i < s.size() && !quote; ++i)
            quote = s[i] == o.field_delimiter || s[i] == o.quote || s[i] == '\n' || s[i] == '\r' ||
                    o.record_delimiter.find(s[i]) != std::string::npos;
        if (!quote)
        {
            out += s;
            return;
        }
        out.push_back(o.quote);
        for (const char c : s)
        {
            if (c == o.quote)
                out.push_back(o.quote_escape);
            out.push_back(c);
        }
        out.push_back(o.quote);
    }

    void csv_out_value(const value& v)
    {
        if (v.k == vk::string)
        {
            csv_out_field(v.s);
            return;
        }
        scratch.clear();
        text_to(scratch, v);
        csv_out_field(scratch);
    }

    void csv_out_node(const jnode& n)
    {
        switch (n.k)
        {
            case jnode::kind::null:   return;
            case jnode::kind::string: csv_out_field(n.s); return;
            default:
                scratch.clear();
                json_node_to(scratch, n);
                csv_out_field(scratch);
        }
    }

    void emit_star(const row& r)
    {
        const bool csv_out = req.output == select_format::csv;
        if (r.fields)
        {
            if (!csv_out)
                out.push_back('{');
            for (size_t k = 0; k < r.nfields; ++k)
            {
                if (k)
                    out.push_back(csv_out ? req.csv_out.field_delimiter : ',');
                const std::string& f = (*r.fields)[k];
                if (csv_out)
                {
                    csv_out_field(f);
                    continue;
                }
                if (k < header.size())
                    socketley::json::quote_into(out, header[k]);
                else
                    socketley::json::quote_into(out, "_" + std::to_string(k + 1));
                out.push_back(':');
                socketley::json::quote_into(out, f);
            }
            if (!csv_out)
                out.push_back('}');
            return;
        }
        const jnode& n = *r.doc;
        if (csv_out)
        {
            if (n.k == jnode::kind::object)
                for (size_t k = 0; k < n.members.size(); ++k)
                {
                    if (k)
                        out.push_back(req.csv_out.field_delimiter);
                    csv_out_node(n.members[k].second);
                }
            else
                csv_out_node(n);
            return;
        }
        if (n.k == jnode::kind::object)
            json_node_to(out, n);
        else
        {
            out += "{\"_1\":";
            json_node_to(out, n);
            out.push_back('}');
        }
    }

    void emit_values()
    {
        if (req.output == select_format::csv)
        {
            for (size_t k = 0; k < vals.size(); ++k)
            {
                if (k)
                    out.push_back(req.csv_out.field_delimiter);
                csv_out_value(vals[k]);
            }
            return;
        }
        out.push_back('{');
        bool any = false;
        for (size_t k = 0; k < vals.size(); ++k)
        {
            if (vals[k].k == vk::missing)
                continue;
            if (any)
                out.push_back(',');
            any = true;
            socketley::json::quote_into(out, prog.items[k].name);
            out.push_back(':');
            json_value_to(out, vals[k]);
        }
        out.push_back('}');
    }

    void emit(const row& r)
    {
        const size_t before = out.size();
        if (prog.star)
            emit_star(r);
        else
        {
            vals.clear();
            for (const select_item& item : prog.items)
            {
                vals.push_back(eval(item.expr, r));
                if (failed)
                    return;
            }
            emit_values();
        }
        if (out.size() - before > select_max_record)
        {
            out.resize(before);
            fault("OverMaxRecordSize");
            return;
        }
        out += req.output == select_format::csv ? req.csv_out.record_delimiter : req.json_record_delimiter;
        returned += out.size() - before;
    }

    // ── Aggregates ──

    void accumulate(const row& r)
    {
        for (const uint32_t id : prog.aggs)
        {
            const node& n = prog.nodes[id];
            agg_state& s  = accs[n.slot];
            const agg_fn fn = static_cast<agg_fn>(n.sub);
            if (fn == agg_fn::count_star)
            {
                ++s.count;
                continue;
            }
            value v = eval(n.args[0], r);
            if (failed)
                return;
            if (absent(v))
                continue;
            switch (fn)
            {
                case agg_fn::count_star:
                case agg_fn::count: ++s.count; break;
                case agg_fn::sum:
                case agg_fn::avg:
                {
                    value x;
                    if (!as_number(v, x))
                    {
                        fault("InvalidDataType", "SUM and AVG need numbers.");
                        return;
                    }
                    ++s.count;
                    s.dsum += as_double(x);
                    // An integer sum stays exact until it overflows, and turns to floating point then.
                    if (!s.is_real && (x.k != vk::integer || __builtin_add_overflow(s.isum, x.i, &s.isum)))
                        s.is_real = true;
                    break;
                }
                case agg_fn::min:
                case agg_fn::max:
                {
                    if (v.k == vk::node)
                    {
                        fault("InvalidDataType", "MIN and MAX need scalar values.");
                        return;
                    }
                    value c;
                    if (v.k != vk::string || !parse_number(v.s, c))
                        c = std::move(v);
                    if (!s.has)
                    {
                        s.best = std::move(c);
                        s.has  = true;
                        break;
                    }
                    int ord = type_rank(c) - type_rank(s.best);
                    if (ord == 0 && !order(c, s.best, ord))
                        ord = 0;
                    if (fn == agg_fn::min ? ord < 0 : ord > 0)
                        s.best = std::move(c);
                    break;
                }
            }
        }
    }

    value agg_result(const node& n) const
    {
        const agg_state& s = accs[n.slot];
        switch (static_cast<agg_fn>(n.sub))
        {
            case agg_fn::count_star:
            case agg_fn::count: return v_int(static_cast<int64_t>(s.count));
            case agg_fn::sum:
                if (!s.count)
                    return v_null();
                return s.is_real ? v_real(s.dsum) : v_int(s.isum);
            case agg_fn::avg:
                return s.count ? v_real(s.dsum / static_cast<double>(s.count)) : v_null();
            case agg_fn::min:
            case agg_fn::max: return s.has ? s.best : v_null();
        }
        return v_null();
    }

    // ── Evaluation ──

    // 1 true, 0 false, -1 unknown, as WHERE and the logical operators read a value.
    int truth(const value& v)
    {
        if (v.k == vk::boolean)
            return v.b ? 1 : 0;
        if (absent(v))
            return -1;
        bool b = false;
        if (v.k == vk::string && parse_bool(v.s, b))
            return b ? 1 : 0;
        fault("InvalidDataType", "A condition must be a boolean.");
        return -1;
    }

    static value tri(int t)
    {
        return t < 0 ? v_null() : v_bool(t == 1);
    }

    value lookup(const node& n, const row& r) const
    {
        if (r.doc)
        {
            const jnode* cur = r.doc;
            for (const path_step& s : n.path)
            {
                cur = step_into(*cur, s);
                if (!cur)
                    return {};
            }
            return from_jnode(*cur);
        }
        if (n.field < 0 || static_cast<uint64_t>(n.field) >= r.nfields || n.path.size() > 1)
            return {};
        return v_str((*r.fields)[static_cast<size_t>(n.field)]);
    }

    value compare(op o, const value& a, const value& b)
    {
        if (absent(a) || absent(b))
            return v_null();
        int c = 0;
        const bool ok = order(a, b, c);
        switch (o)
        {
            case op::eq: return v_bool(ok && c == 0);
            case op::ne: return v_bool(!ok || c != 0);
            case op::lt: return ok ? v_bool(c < 0) : v_null();
            case op::le: return ok ? v_bool(c <= 0) : v_null();
            case op::gt: return ok ? v_bool(c > 0) : v_null();
            case op::ge: return ok ? v_bool(c >= 0) : v_null();
            default: return v_null();
        }
    }

    value arith(op o, const value& a, const value& b)
    {
        if (absent(a) || absent(b))
            return v_null();
        value x;
        value y;
        if (!as_number(a, x) || !as_number(b, y))
        {
            fault("InvalidDataType", "Arithmetic needs numbers.");
            return v_null();
        }
        if (x.k == vk::integer && y.k == vk::integer)
        {
            int64_t r = 0;
            bool over = false;
            switch (o)
            {
                case op::add: over = __builtin_add_overflow(x.i, y.i, &r); break;
                case op::sub: over = __builtin_sub_overflow(x.i, y.i, &r); break;
                case op::mul: over = __builtin_mul_overflow(x.i, y.i, &r); break;
                case op::div:
                case op::mod:
                    if (y.i == 0)
                    {
                        fault("InvalidRequest", "Division by zero in the SQL expression.");
                        return v_null();
                    }
                    if (y.i == -1)
                    {
                        // Dividing by -1 is a negation, which INT64_MIN has none of.
                        over = o == op::div && x.i == std::numeric_limits<int64_t>::min();
                        r    = o == op::div && !over ? -x.i : 0;
                    }
                    else
                        r = o == op::div ? x.i / y.i : x.i % y.i;
                    break;
                default: break;
            }
            if (over)
            {
                fault("IntegerOverflow");
                return v_null();
            }
            return v_int(r);
        }
        const double dx = as_double(x);
        const double dy = as_double(y);
        switch (o)
        {
            case op::add: return v_real(dx + dy);
            case op::sub: return v_real(dx - dy);
            case op::mul: return v_real(dx * dy);
            case op::div:
            case op::mod:
                if (dy == 0)
                {
                    fault("InvalidRequest", "Division by zero in the SQL expression.");
                    return v_null();
                }
                return v_real(o == op::div ? dx / dy : std::fmod(dx, dy));
            default: return v_null();
        }
    }

    value cast(cast_to to, const value& a)
    {
        if (absent(a))
            return a;
        switch (to)
        {
            case cast_to::integer:
            {
                value x = a;
                if (a.k == vk::boolean)
                    return v_int(a.b ? 1 : 0);
                if (a.k == vk::string && !parse_number(a.s, x))
                    break;
                if (x.k == vk::integer)
                    return x;
                if (x.k != vk::real || !std::isfinite(x.d) || x.d >= 9.2233720368547758e18 || x.d < -9.2233720368547758e18)
                    break;
                return v_int(static_cast<int64_t>(std::trunc(x.d)));
            }
            case cast_to::real:
            {
                value x;
                if (a.k == vk::boolean)
                    return v_real(a.b ? 1 : 0);
                if (!as_number(a, x))
                    break;
                return v_real(as_double(x));
            }
            case cast_to::string:
            {
                std::string s;
                text_to(s, a);
                return v_str(std::move(s));
            }
            case cast_to::boolean:
            {
                bool b = false;
                if (a.k == vk::boolean)
                    return a;
                if (numeric(a))
                    return v_bool(as_double(a) != 0);
                if (a.k == vk::string && parse_bool(a.s, b))
                    return v_bool(b);
                break;
            }
        }
        fault("CastFailed");
        return v_null();
    }

    bool want_string(const value& v)
    {
        if (v.k == vk::string)
            return true;
        fault("IncorrectSqlFunctionArgumentType");
        return false;
    }

    bool want_integer(const value& v, int64_t& out)
    {
        value x;
        if (!as_number(v, x))
        {
            fault("IncorrectSqlFunctionArgumentType");
            return false;
        }
        if (x.k == vk::integer)
            out = x.i;
        else if (std::isfinite(x.d) && std::fabs(x.d) < 9.0e18)
            out = static_cast<int64_t>(std::trunc(x.d));
        else
        {
            fault("IncorrectSqlFunctionArgumentType");
            return false;
        }
        return true;
    }

    value trim(const node& n, const row& r)
    {
        const value t = eval(n.args[0], r);
        const value c = n.args.size() > 1 ? eval(n.args[1], r) : v_str(" ");
        if (failed || absent(t) || absent(c))
            return v_null();
        if (!want_string(t) || !want_string(c))
            return v_null();
        std::string_view s = t.s;
        const std::string_view set = c.s;
        auto strip = [&](bool front)
        {
            for (bool hit = true; hit && !s.empty();)
            {
                hit = false;
                for (size_t i = 0; i < set.size(); i += char_step(set, i))
                {
                    const std::string_view ch = set.substr(i, char_step(set, i));
                    if (front ? s.starts_with(ch) : s.ends_with(ch))
                    {
                        front ? s.remove_prefix(ch.size()) : s.remove_suffix(ch.size());
                        hit = true;
                        break;
                    }
                }
            }
        };
        const trim_side side = static_cast<trim_side>(n.sub);
        if (side != trim_side::trailing)
            strip(true);
        if (side != trim_side::leading)
            strip(false);
        return v_str(std::string(s));
    }

    value substring(const node& n, const row& r)
    {
        const value s = eval(n.args[0], r);
        const value a = eval(n.args[1], r);
        const value l = n.args.size() > 2 ? eval(n.args[2], r) : value{};
        if (failed || absent(s) || absent(a) || (n.args.size() > 2 && absent(l)))
            return v_null();
        int64_t start = 0;
        int64_t len   = 0;
        if (!want_string(s) || !want_integer(a, start) || (n.args.size() > 2 && !want_integer(l, len)))
            return v_null();
        // Characters numbered from 1, the window [start, start + len) clipped to them; a negative length is empty.
        int64_t stop = std::numeric_limits<int64_t>::max();
        if (n.args.size() > 2)
        {
            if (len < 0)
                return v_str({});
            if (__builtin_add_overflow(start, len, &stop))
                stop = std::numeric_limits<int64_t>::max();
        }
        const int64_t from = std::max<int64_t>(start, 1);
        if (stop <= from)
            return v_str({});
        const std::string_view text = s.s;
        size_t b = 0;
        for (int64_t k = 1; k < from && b < text.size(); ++k)
            b += char_step(text, b);
        size_t e = b;
        for (int64_t k = from; k < stop && e < text.size(); ++k)
            e += char_step(text, e);
        return v_str(std::string(text.substr(b, e - b)));
    }

    value like(const node& n, const row& r)
    {
        const value s = eval(n.args[0], r);
        const value p = eval(n.args[1], r);
        const value e = n.args.size() > 2 ? eval(n.args[2], r) : value{};
        if (failed || absent(s) || absent(p) || (n.args.size() > 2 && absent(e)))
            return v_null();
        if (s.k != vk::string || p.k != vk::string || (n.args.size() > 2 && e.k != vk::string))
        {
            fault("LikeInvalidInputs");
            return v_null();
        }
        const std::vector<like_item>* pat = &n.pattern;
        std::vector<like_item> built;
        if (!n.pattern_ready)
        {
            const std::string_view esc = e.s;
            if (!like_compile(p.s, n.args.size() > 2 ? &esc : nullptr, built))
            {
                fault("LikeInvalidInputs");
                return v_null();
            }
            pat = &built;
        }
        return v_bool(like_match(s.s, *pat) != n.negate);
    }

    value eval(uint32_t id, const row& r)
    {
        const node& n = prog.nodes[id];
        switch (n.o)
        {
            case op::lit: return n.lit;
            case op::ref: return lookup(n, r);
            case op::neg:
            {
                const value a = eval(n.args[0], r);
                if (absent(a))
                    return v_null();
                value x;
                if (!as_number(a, x))
                {
                    fault("InvalidDataType", "Negation needs a number.");
                    return v_null();
                }
                if (x.k == vk::real)
                    return v_real(-x.d);
                if (x.i == std::numeric_limits<int64_t>::min())
                {
                    fault("IntegerOverflow");
                    return v_null();
                }
                return v_int(-x.i);
            }
            case op::not_:
            {
                const int t = truth(eval(n.args[0], r));
                return t < 0 ? v_null() : v_bool(t == 0);
            }
            case op::and_:
            {
                const int a = truth(eval(n.args[0], r));
                if (a == 0)
                    return v_bool(false);
                const int b = truth(eval(n.args[1], r));
                return b == 0 ? v_bool(false) : tri(a < 0 || b < 0 ? -1 : 1);
            }
            case op::or_:
            {
                const int a = truth(eval(n.args[0], r));
                if (a == 1)
                    return v_bool(true);
                const int b = truth(eval(n.args[1], r));
                return b == 1 ? v_bool(true) : tri(a < 0 || b < 0 ? -1 : 0);
            }
            case op::eq:
            case op::ne:
            case op::lt:
            case op::le:
            case op::gt:
            case op::ge: return compare(n.o, eval(n.args[0], r), eval(n.args[1], r));
            case op::add:
            case op::sub:
            case op::mul:
            case op::div:
            case op::mod: return arith(n.o, eval(n.args[0], r), eval(n.args[1], r));
            case op::concat:
            {
                const value a = eval(n.args[0], r);
                const value b = eval(n.args[1], r);
                if (absent(a) || absent(b))
                    return v_null();
                if (a.k == vk::node || b.k == vk::node)
                {
                    fault("InvalidDataType", "|| needs strings.");
                    return v_null();
                }
                std::string s;
                text_to(s, a);
                text_to(s, b);
                return v_str(std::move(s));
            }
            case op::like: return like(n, r);
            case op::between:
            {
                const value x  = eval(n.args[0], r);
                const int   lo = truth(compare(op::ge, x, eval(n.args[1], r)));
                const int   hi = truth(compare(op::le, x, eval(n.args[2], r)));
                const int   t  = lo == 0 || hi == 0 ? 0 : lo < 0 || hi < 0 ? -1 : 1;
                return tri(t < 0 || !n.negate ? t : 1 - t);
            }
            case op::in:
            {
                const value x = eval(n.args[0], r);
                int t = 0;
                for (size_t k = 1; k < n.args.size() && t != 1; ++k)
                {
                    const int e = truth(compare(op::eq, x, eval(n.args[k], r)));
                    if (e == 1 || e < 0)
                        t = e;
                }
                return tri(t < 0 || !n.negate ? t : 1 - t);
            }
            case op::is_null: return v_bool(absent(eval(n.args[0], r)) != n.negate);
            case op::is_missing: return v_bool((eval(n.args[0], r).k == vk::missing) != n.negate);
            case op::cast: return cast(static_cast<cast_to>(n.sub), eval(n.args[0], r));
            case op::lower:
            case op::upper:
            {
                value a = eval(n.args[0], r);
                if (absent(a) || !want_string(a))
                    return v_null();
                for (char& c : a.s)
                    c = n.o == op::lower ? ascii::lower(c) : ascii::upper(c);
                return a;
            }
            case op::trim: return trim(n, r);
            case op::char_length:
            {
                const value a = eval(n.args[0], r);
                if (absent(a) || !want_string(a))
                    return v_null();
                int64_t count = 0;
                for (const char c : a.s)
                    count += (static_cast<unsigned char>(c) & 0xC0) != 0x80;
                return v_int(count);
            }
            case op::substring: return substring(n, r);
            case op::coalesce:
                for (const uint32_t a : n.args)
                {
                    value v = eval(a, r);
                    if (!absent(v))
                        return v;
                }
                return v_null();
            case op::nullif:
            {
                value a = eval(n.args[0], r);
                const value b = eval(n.args[1], r);
                return truth(compare(op::eq, a, b)) == 1 ? v_null() : a;
            }
            case op::agg: return final_pass ? agg_result(n) : v_null();
        }
        return v_null();
    }
};

select_engine::select_engine() : m_impl(std::make_unique<impl>()) {}

select_engine::~select_engine() = default;

bool select_engine::init(const select_request& req, s3_error& err, uint64_t object_size)
{
    m_impl = std::make_unique<impl>();
    return m_impl->init(req, err, object_size);
}

uint64_t select_engine::first_offset() const
{
    return m_impl->first;
}

void select_engine::feed(std::string_view bytes)
{
    impl& m = *m_impl;
    if (!m.ready || m.done || m.finished || bytes.empty())
        return;
    if (m.req.input == select_format::csv)
        m.csv_feed(bytes);
    else if (m.req.json_type == select_json_type::lines)
        m.json_lines_feed(bytes);
    else
        m.json_document_feed(bytes);
}

bool select_engine::finish()
{
    impl& m = *m_impl;
    if (!m.ready)
        return false;
    if (m.finished)
        return !m.failed;
    m.finished = true;
    if (!m.done && !m.skipping)
    {
        if (m.req.input == select_format::csv)
        {
            if (m.rd_pending)
            {
                m.rd_pending = false;
                m.csv_data(m.req.csv_in.record_delimiter[0]);
            }
            if (!m.failed)
                m.csv_close_record();
        }
        else if (m.req.json_type == select_json_type::lines)
        {
            if (!m.rec.empty())
                m.json_record(m.rec);
            m.rec.clear();
        }
        else if (m.jstarted)
            m.fault("JSONParsingError", "The JSON document ends inside a value.");
    }
    if (m.prog.aggregate && !m.failed && m.prog.limit != 0)
    {
        m.final_pass = true;
        m.emit(row{});
    }
    return !m.failed;
}

std::string select_engine::take_output()
{
    std::string r;
    r.swap(m_impl->out);
    return r;
}

bool select_engine::done() const
{
    return m_impl->done;
}

bool select_engine::failed() const
{
    return m_impl->failed;
}

const s3_error& select_engine::error() const
{
    return m_impl->err;
}

uint64_t select_engine::bytes_scanned() const
{
    return m_impl->pos - m_impl->first;
}

uint64_t select_engine::bytes_processed() const
{
    return bytes_scanned();
}

uint64_t select_engine::bytes_returned() const
{
    return m_impl->returned;
}

// ─── Event stream ───────────────────────────────────────────────────────────

namespace
{

void put_be(std::string& out, uint64_t v, int bytes)
{
    for (int i = bytes - 1; i >= 0; --i)
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

// A header whose value is a string, type 7, with a name of at most 255 bytes and a value of at most 65535.
void put_header(std::string& out, std::string_view name, std::string_view val)
{
    name = name.substr(0, 255);
    val  = val.substr(0, 65535);
    out.push_back(static_cast<char>(name.size()));
    out.append(name);
    out.push_back(static_cast<char>(7));
    put_be(out, val.size(), 2);
    out.append(val);
}

std::string crc32_be(std::string_view bytes)
{
    checksum_stream c(checksum_algo::crc32);
    c.update(bytes.data(), bytes.size());
    return c.peek_raw();
}

// The prelude of both lengths and their CRC, the headers, the payload, and the CRC of everything before it.
std::string event_message(std::string_view headers, std::string_view payload)
{
    std::string out;
    out.reserve(16 + headers.size() + payload.size());
    put_be(out, 12 + headers.size() + payload.size() + 4, 4);
    put_be(out, headers.size(), 4);
    const std::string prelude_crc = crc32_be(out);
    out += prelude_crc;
    out.append(headers);
    out.append(payload);
    const std::string message_crc = crc32_be(out);
    out += message_crc;
    return out;
}

}   // namespace

std::string select_event(std::string_view event_type, std::string_view payload, std::string_view content_type)
{
    std::string headers;
    put_header(headers, ":message-type", "event");
    put_header(headers, ":event-type", event_type);
    if (!content_type.empty())
        put_header(headers, ":content-type", content_type);
    return event_message(headers, payload);
}

std::string select_records_event(std::string_view records)
{
    return select_event("Records", records, "application/octet-stream");
}

std::string select_details_xml(std::string_view element, uint64_t scanned, uint64_t processed, uint64_t returned)
{
    std::string x(xml_decl);
    x += '<';
    x += element;
    x += "><BytesScanned>";
    x += std::to_string(scanned);
    x += "</BytesScanned><BytesProcessed>";
    x += std::to_string(processed);
    x += "</BytesProcessed><BytesReturned>";
    x += std::to_string(returned);
    x += "</BytesReturned></";
    x += element;
    x += '>';
    return x;
}

std::string select_stats_event(uint64_t scanned, uint64_t processed, uint64_t returned)
{
    return select_event("Stats", select_details_xml("Stats", scanned, processed, returned), "text/xml");
}

std::string select_progress_event(uint64_t scanned, uint64_t processed, uint64_t returned)
{
    return select_event("Progress", select_details_xml("Progress", scanned, processed, returned), "text/xml");
}

std::string select_cont_event()
{
    return select_event("Cont", {}, {});
}

std::string select_end_event()
{
    return select_event("End", {}, {});
}

std::string select_error_event(std::string_view code, std::string_view message)
{
    std::string headers;
    put_header(headers, ":message-type", "error");
    put_header(headers, ":error-code", code);
    put_header(headers, ":error-message", message);
    return event_message(headers, {});
}

}   // namespace socketley::storage
