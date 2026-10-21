#include "mail_sieve.h"

#include <algorithm>
#include <array>
#include <deque>
#include <functional>

#include "mail_compose.h"
#include "mail_mime.h"
#include "smtp_session.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail::sieve
{

namespace
{

constexpr size_t max_script = 64u << 10;
constexpr int max_depth = 32;
constexpr size_t max_redirects = 4;
constexpr uint64_t max_steps = 1000000;
constexpr size_t max_var_len = 4096;
constexpr size_t max_vars = 128;
constexpr size_t max_expanded = 64u << 10;
constexpr size_t max_list_bytes = 1u << 20;
constexpr size_t max_match_vars = 10;
// What one step buys: bytes scanned or decoded, and turns of the wildcard matcher.
constexpr uint64_t bytes_per_step = 512;
constexpr uint64_t glob_per_step = 256;

// ─── capabilities ──────────────────────────────────────────────────────────

enum cap : uint32_t
{
    c_fileinto = 1u << 0,
    c_reject = 1u << 1,
    c_ereject = 1u << 2,
    c_envelope = 1u << 3,
    c_encoded = 1u << 4,
    c_imap4flags = 1u << 5,
    c_copy = 1u << 6,
    c_vacation = 1u << 7,
    c_vacation_seconds = 1u << 8,
    c_subaddress = 1u << 9,
    c_body = 1u << 10,
    c_relational = 1u << 11,
    c_numeric = 1u << 12,
    c_variables = 1u << 13,
    c_date = 1u << 14,
    c_mailbox = 1u << 15,
};

struct cap_name
{
    std::string_view name;
    uint32_t bits;
};

// The comparators every script has are listed so that requiring them is no error.
constexpr cap_name cap_names[] = {
    {"fileinto", c_fileinto},
    {"reject", c_reject},
    {"ereject", c_ereject},
    {"envelope", c_envelope},
    {"encoded-character", c_encoded},
    {"imap4flags", c_imap4flags},
    {"copy", c_copy},
    {"vacation", c_vacation},
    {"vacation-seconds", c_vacation | c_vacation_seconds},
    {"subaddress", c_subaddress},
    {"body", c_body},
    {"relational", c_relational},
    {"comparator-i;ascii-numeric", c_numeric},
    {"variables", c_variables},
    {"date", c_date},
    {"mailbox", c_mailbox},
    {"comparator-i;octet", 0},
    {"comparator-i;ascii-casemap", 0},
};

// ─── text helpers ──────────────────────────────────────────────────────────

bool is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

bool is_wsp(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && is_wsp(s.front()))
        s.remove_prefix(1);
    while (!s.empty() && is_wsp(s.back()))
        s.remove_suffix(1);
    return s;
}

int hex_digit(char c)
{
    if (is_digit(c))
        return c - '0';
    const char l = socketley::ascii::lower(c);
    return l >= 'a' && l <= 'f' ? l - 'a' + 10 : -1;
}

void append_utf8(std::string& out, uint32_t cp)
{
    if (cp < 0x80)
        out += static_cast<char>(cp);
    else if (cp < 0x800)
    {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
    else if (cp < 0x10000)
    {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
    else
    {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// The bytes of the UTF-8 character at `i`, one where it is malformed.
size_t utf8_len(std::string_view s, size_t i)
{
    const auto c = static_cast<unsigned char>(s[i]);
    const size_t n = c < 0x80 ? 1 : c >= 0xF0 && c < 0xF8 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
    if (i + n > s.size())
        return 1;
    for (size_t k = 1; k < n; ++k)
        if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80)
            return 1;
    return n;
}

// `s` cut to at most `n` bytes, between whole UTF-8 characters.
void clip(std::string& s, size_t n)
{
    if (s.size() <= n)
        return;
    size_t k = n;
    while (k > 0 && (static_cast<unsigned char>(s[k]) & 0xC0) == 0x80)
        --k;
    s.resize(k);
}

bool valid_identifier(std::string_view s)
{
    if (s.empty() || !(is_alpha(s[0]) || s[0] == '_'))
        return false;
    return std::all_of(s.begin(), s.end(), [](char c) { return is_alpha(c) || is_digit(c) || c == '_'; });
}

std::string fnv_hex(std::string_view s)
{
    uint64_t h = 1469598103934665603ull;
    for (const unsigned char c : s)
        h = (h ^ c) * 1099511628211ull;
    static constexpr char digits[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i, h >>= 4)
        out[static_cast<size_t>(i)] = digits[h & 15];
    return out;
}

std::string at_line(int line, std::string_view why)
{
    return "line " + std::to_string(line) + ": " + std::string(why);
}

// ─── lexer ─────────────────────────────────────────────────────────────────

enum class tok : uint8_t { ident, tag, number, string, lbracket, rbracket, lparen, rparen, lbrace, rbrace, comma, semi, end };

struct token
{
    tok t{tok::end};
    int line{0};
    std::string text;
    uint64_t n{0};
};

bool lex(std::string_view s, std::vector<token>& out, std::string& err)
{
    int line = 1;
    size_t i = 0;
    const auto fail = [&](std::string_view why) {
        err = at_line(line, why);
        return false;
    };
    while (i < s.size())
    {
        const char c = s[i];
        if (c == '\n')
        {
            ++line;
            ++i;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\r')
        {
            ++i;
            continue;
        }
        if (c == '#')
        {
            while (i < s.size() && s[i] != '\n')
                ++i;
            continue;
        }
        if (c == '/' && i + 1 < s.size() && s[i + 1] == '*')
        {
            const size_t end = s.find("*/", i + 2);
            if (end == std::string_view::npos)
                return fail("a comment that is never closed");
            line += static_cast<int>(std::count(s.begin() + static_cast<ptrdiff_t>(i),
                                                s.begin() + static_cast<ptrdiff_t>(end), '\n'));
            i = end + 2;
            continue;
        }
        token t;
        t.line = line;
        if (is_alpha(c) || c == '_')
        {
            size_t j = i;
            while (j < s.size() && (is_alpha(s[j]) || is_digit(s[j]) || s[j] == '_'))
                ++j;
            t.text = lower(s.substr(i, j - i));
            if (t.text == "text" && j < s.size() && s[j] == ':')
            {
                // A multi-line string: its lines up to one holding a lone dot, a leading dot doubled.
                size_t k = j + 1;
                while (k < s.size() && (s[k] == ' ' || s[k] == '\t'))
                    ++k;
                if (k < s.size() && s[k] == '#')
                    while (k < s.size() && s[k] != '\n')
                        ++k;
                if (k < s.size() && s[k] == '\r')
                    ++k;
                if (k >= s.size() || s[k] != '\n')
                    return fail("text: is not followed by the end of its line");
                ++k;
                ++line;
                t.text.clear();
                for (;;)
                {
                    const size_t nl = s.find('\n', k);
                    std::string_view l = s.substr(k, nl == std::string_view::npos ? std::string_view::npos : nl - k);
                    if (l.ends_with('\r'))
                        l.remove_suffix(1);
                    if (l == ".")
                    {
                        i = nl == std::string_view::npos ? s.size() : nl + 1;
                        line += nl == std::string_view::npos ? 0 : 1;
                        break;
                    }
                    if (nl == std::string_view::npos)
                        return fail("a text: string not ended by a line holding a dot");
                    if (l.starts_with(".."))
                        l.remove_prefix(1);
                    t.text.append(l).append("\r\n");
                    k = nl + 1;
                    ++line;
                }
                t.t = tok::string;
                out.push_back(std::move(t));
                continue;
            }
            t.t = tok::ident;
            i = j;
            out.push_back(std::move(t));
            continue;
        }
        if (c == ':')
        {
            size_t j = i + 1;
            if (j >= s.size() || !(is_alpha(s[j]) || s[j] == '_'))
                return fail("a colon not followed by a tag's name");
            while (j < s.size() && (is_alpha(s[j]) || is_digit(s[j]) || s[j] == '_'))
                ++j;
            t.t = tok::tag;
            t.text = lower(s.substr(i + 1, j - i - 1));
            i = j;
            out.push_back(std::move(t));
            continue;
        }
        if (is_digit(c))
        {
            uint64_t v = 0;
            while (i < s.size() && is_digit(s[i]))
            {
                if (v > (UINT64_MAX - 9) / 10)
                    return fail("a number too large");
                v = v * 10 + static_cast<uint64_t>(s[i] - '0');
                ++i;
            }
            if (i < s.size())
            {
                const char q = socketley::ascii::upper(s[i]);
                const int shift = q == 'K' ? 10 : q == 'M' ? 20 : q == 'G' ? 30 : 0;
                if (shift)
                {
                    if (v > (UINT64_MAX >> shift))
                        return fail("a number too large");
                    v <<= shift;
                    ++i;
                }
            }
            t.t = tok::number;
            t.n = v;
            out.push_back(std::move(t));
            continue;
        }
        if (c == '"')
        {
            ++i;
            for (;;)
            {
                if (i >= s.size())
                {
                    line = t.line;
                    return fail("a string that is never closed");
                }
                char d = s[i++];
                if (d == '"')
                    break;
                if (d == '\\')
                {
                    if (i >= s.size())
                        continue;
                    d = s[i++];
                }
                if (d == '\n')
                    ++line;
                t.text += d;
            }
            t.t = tok::string;
            out.push_back(std::move(t));
            continue;
        }
        switch (c)
        {
            case '[': t.t = tok::lbracket; break;
            case ']': t.t = tok::rbracket; break;
            case '(': t.t = tok::lparen; break;
            case ')': t.t = tok::rparen; break;
            case '{': t.t = tok::lbrace; break;
            case '}': t.t = tok::rbrace; break;
            case ',': t.t = tok::comma; break;
            case ';': t.t = tok::semi; break;
            default: return fail("a character that is no part of the language");
        }
        ++i;
        out.push_back(std::move(t));
    }
    token e;
    e.line = line;
    out.push_back(std::move(e));
    return true;
}

// The ${hex:...} and ${unicode:...} of encoded-character written out; false for a code point Unicode has none of.
bool decode_encoded(std::string& s)
{
    if (s.find("${") == std::string::npos)
        return true;
    std::string out;
    size_t i = 0;
    while (i < s.size())
    {
        const size_t at = s.find("${", i);
        if (at == std::string::npos)
        {
            out.append(s, i, std::string::npos);
            break;
        }
        out.append(s, i, at - i);
        const size_t close = s.find('}', at);
        const std::string_view inner = close == std::string::npos ? std::string_view{}
                                                                  : std::string_view(s).substr(at + 2, close - at - 2);
        const bool hex = inner.size() >= 4 && socketley::ascii::iequals(inner.substr(0, 4), "hex:");
        const bool uni = inner.size() >= 8 && socketley::ascii::iequals(inner.substr(0, 8), "unicode:");
        if (hex || uni)
        {
            std::string_view seq = inner.substr(hex ? 4 : 8);
            std::string bytes;
            bool ok = true, any = false, bad_cp = false;
            while (ok)
            {
                while (!seq.empty() && is_wsp(seq.front()))
                    seq.remove_prefix(1);
                if (seq.empty())
                    break;
                size_t n = 0;
                uint64_t v = 0;
                while (n < seq.size() && hex_digit(seq[n]) >= 0)
                {
                    v = std::min<uint64_t>(v * 16 + static_cast<uint64_t>(hex_digit(seq[n])), 0x7FFFFFFFull);
                    ++n;
                }
                if (n == 0 || (n < seq.size() && !is_wsp(seq[n])) || (hex && n > 2))
                {
                    ok = false;
                    break;
                }
                if (hex)
                    bytes += static_cast<char>(v);
                else if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF))
                    bad_cp = true;
                else
                    append_utf8(bytes, static_cast<uint32_t>(v));
                any = true;
                seq.remove_prefix(n);
            }
            if (ok && any)
            {
                if (bad_cp)
                    return false;
                out += bytes;
                i = close + 1;
                continue;
            }
        }
        out += "${";
        i = at + 2;
    }
    s = std::move(out);
    return true;
}

// ─── the tree ──────────────────────────────────────────────────────────────

// A string of the script, and whether it names variables that a run substitutes.
struct str
{
    std::string s;
    bool vars{false};
};
using strs = std::vector<str>;

enum class cmp : uint8_t { octet, casemap, numeric };
enum class mtype : uint8_t { is, contains, matches, count, value };
enum class rel : uint8_t { gt, ge, lt, le, eq, ne };
enum class apart : uint8_t { all, localpart, domain, user, detail };
enum class transform : uint8_t { text, raw, content };

struct match
{
    cmp c{cmp::casemap};
    mtype t{mtype::is};
    rel r{rel::eq};
};

enum class tk : uint8_t
{
    yes,
    no,
    not_,
    allof,
    anyof,
    address,
    envelope,
    header,
    exists,
    size,
    body,
    string,
    date,
    currentdate,
    hasflag,
    mailboxexists
};

struct test_node
{
    tk k{tk::yes};
    int line{0};
    match m;
    apart ap{apart::all};
    transform tr{transform::text};
    bool over{false}, zone_set{false}, original_zone{false};
    uint64_t limit{0};
    str zone, part;
    // Header names, envelope parts, sources, variables or mailboxes, by the test.
    strs a;
    strs keys, types;
    std::vector<test_node> kids;
};

enum class ck : uint8_t
{
    if_,
    stop,
    keep,
    discard,
    redirect,
    fileinto,
    reject,
    ereject,
    vacation,
    set,
    setflag,
    addflag,
    removeflag
};

enum set_mod : uint8_t
{
    m_lower = 1,
    m_upper = 2,
    m_lowerfirst = 4,
    m_upperfirst = 8,
    m_quotewildcard = 16,
    m_length = 32
};

struct cmd_node
{
    ck k{ck::stop};
    int line{0};
    // An if's conditions and blocks, one block more than conditions where it has an else.
    std::vector<test_node> conds;
    std::vector<std::vector<cmd_node>> blocks;
    // The folder, address, reason or variable name, and set's value.
    str a, b;
    // Flags, or vacation's addresses.
    strs list;
    bool copy{false}, create{false}, has_flags{false}, has_var{false}, mime{false};
    uint8_t mods{0};
    uint64_t seconds{7 * 86400};
    bool has_subject{false}, has_from{false}, has_handle{false};
    str subject, from, handle;
};

constexpr std::string_view date_parts[] = {"year", "month", "day", "date", "julian", "hour", "minute",
                                           "second", "time", "iso8601", "std11", "zone", "weekday"};

bool known_date_part(std::string_view p)
{
    return std::any_of(std::begin(date_parts), std::end(date_parts),
                       [p](std::string_view d) { return socketley::ascii::iequals(p, d); });
}

// "+hhmm" or "-hhmm" as minutes east of UTC.
bool parse_zone(std::string_view z, int& minutes)
{
    if (z.size() != 5 || (z[0] != '+' && z[0] != '-'))
        return false;
    for (size_t i = 1; i < 5; ++i)
        if (!is_digit(z[i]))
            return false;
    const int h = (z[1] - '0') * 10 + (z[2] - '0');
    const int m = (z[3] - '0') * 10 + (z[4] - '0');
    if (h > 23 || m > 59)
        return false;
    minutes = (z[0] == '-' ? -1 : 1) * (h * 60 + m);
    return true;
}

// ─── parser ────────────────────────────────────────────────────────────────

struct garg
{
    enum class kind : uint8_t { strings, number, tag } k{kind::strings};
    int line{0};
    bool bracketed{false};
    std::vector<std::string> s;
    uint64_t n{0};
    std::string tag;
};

struct parser
{
    const std::vector<token>& t;
    std::string& err;
    size_t i{0};
    uint32_t caps{0};
    bool past_require{false};

    const token& peek() const { return t[i]; }

    bool fail(int line, std::string_view why)
    {
        if (err.empty())
            err = at_line(line, why);
        return false;
    }

    bool need(uint32_t c, int line, std::string_view what, std::string_view ext)
    {
        if (caps & c)
            return true;
        return fail(line, std::string(what) + " needs require \"" + std::string(ext) + "\"");
    }

    str mk(std::string s) const
    {
        str out;
        out.vars = (caps & c_variables) && s.find("${") != std::string::npos;
        out.s = std::move(s);
        return out;
    }

    bool string_token(std::string& s, int line)
    {
        if ((caps & c_encoded) && !decode_encoded(s))
            return fail(line, "an encoded character that is no Unicode code point");
        return true;
    }

    bool parse_args(std::vector<garg>& out)
    {
        for (;;)
        {
            const token& k = peek();
            garg a;
            a.line = k.line;
            if (k.t == tok::string)
            {
                std::string s = k.text;
                if (!string_token(s, k.line))
                    return false;
                a.s.push_back(std::move(s));
                ++i;
            }
            else if (k.t == tok::lbracket)
            {
                a.bracketed = true;
                ++i;
                for (;;)
                {
                    if (peek().t != tok::string)
                        return fail(peek().line, "a string list holds strings");
                    std::string s = peek().text;
                    if (!string_token(s, peek().line))
                        return false;
                    a.s.push_back(std::move(s));
                    ++i;
                    if (peek().t == tok::comma)
                    {
                        ++i;
                        continue;
                    }
                    if (peek().t == tok::rbracket)
                    {
                        ++i;
                        break;
                    }
                    return fail(peek().line, "a string list not closed by ]");
                }
            }
            else if (k.t == tok::number)
            {
                a.k = garg::kind::number;
                a.n = k.n;
                ++i;
            }
            else if (k.t == tok::tag)
            {
                a.k = garg::kind::tag;
                a.tag = k.text;
                ++i;
            }
            else
                return true;
            out.push_back(std::move(a));
        }
    }

    bool parse_tests(std::vector<test_node>& kids, int depth)
    {
        if (peek().t == tok::ident)
        {
            kids.emplace_back();
            return parse_test(kids.back(), depth);
        }
        if (peek().t != tok::lparen)
            return true;
        ++i;
        for (;;)
        {
            kids.emplace_back();
            if (!parse_test(kids.back(), depth))
                return false;
            if (peek().t == tok::comma)
            {
                ++i;
                continue;
            }
            if (peek().t == tok::rparen)
            {
                ++i;
                return true;
            }
            return fail(peek().line, "a test list not closed by )");
        }
    }

    bool parse_test(test_node& out, int depth)
    {
        if (depth > max_depth)
            return fail(peek().line, "nested deeper than 32");
        if (peek().t != tok::ident)
            return fail(peek().line, "a test was expected");
        const std::string id = peek().text;
        const int line = peek().line;
        ++i;
        std::vector<garg> a;
        if (!parse_args(a) || !parse_tests(out.kids, depth + 1))
            return false;
        return build_test(id, line, a, out);
    }

    // ── arguments ──

    bool str_arg(const std::vector<garg>& a, size_t& k, str& out, int line, std::string_view what)
    {
        if (k >= a.size() || a[k].k != garg::kind::strings || a[k].bracketed || a[k].s.size() != 1)
            return fail(k < a.size() ? a[k].line : line, std::string(what) + " expects a string");
        out = mk(a[k].s[0]);
        ++k;
        return true;
    }

    bool list_arg(const std::vector<garg>& a, size_t& k, strs& out, int line, std::string_view what)
    {
        if (k >= a.size() || a[k].k != garg::kind::strings)
            return fail(k < a.size() ? a[k].line : line, std::string(what) + " expects a string list");
        out.clear();
        for (const auto& s : a[k].s)
            out.push_back(mk(s));
        ++k;
        return true;
    }

    bool num_arg(const std::vector<garg>& a, size_t& k, uint64_t& out, int line, std::string_view what)
    {
        if (k >= a.size() || a[k].k != garg::kind::number)
            return fail(k < a.size() ? a[k].line : line, std::string(what) + " expects a number");
        out = a[k].n;
        ++k;
        return true;
    }

    bool done(const std::vector<garg>& a, size_t k, std::string_view what)
    {
        if (k != a.size())
            return fail(a[k].line, "too many arguments to " + std::string(what));
        return true;
    }

    // 1 when `tag` is a comparator, match type or address part and was read, 0 when it is none of them, -1 on error.
    int common(std::string_view tag, const std::vector<garg>& a, size_t& k, int line, match& m, uint8_t& seen,
               apart* ap)
    {
        if (tag == "comparator")
        {
            if (seen & 1)
                return bad(line, "more than one comparator");
            seen |= 1;
            if (k >= a.size() || a[k].k != garg::kind::strings || a[k].bracketed || a[k].s.size() != 1)
                return bad(line, ":comparator expects a string");
            const std::string name = lower(a[k].s[0]);
            ++k;
            if (name == "i;octet")
                m.c = cmp::octet;
            else if (name == "i;ascii-casemap")
                m.c = cmp::casemap;
            else if (name == "i;ascii-numeric")
            {
                if (!need(c_numeric, line, "i;ascii-numeric", "comparator-i;ascii-numeric"))
                    return -1;
                m.c = cmp::numeric;
            }
            else
                return bad(line, "unknown comparator \"" + name + "\"");
            return 1;
        }
        const bool is_mt = tag == "is" || tag == "contains" || tag == "matches" || tag == "count" || tag == "value";
        if (is_mt)
        {
            if (seen & 2)
                return bad(line, "more than one match type");
            seen |= 2;
            if (tag == "is")
                m.t = mtype::is;
            else if (tag == "contains")
                m.t = mtype::contains;
            else if (tag == "matches")
                m.t = mtype::matches;
            else
            {
                if (!need(c_relational, line, std::string(":") + std::string(tag), "relational"))
                    return -1;
                m.t = tag == "count" ? mtype::count : mtype::value;
                if (k >= a.size() || a[k].k != garg::kind::strings || a[k].bracketed || a[k].s.size() != 1)
                    return bad(line, std::string(":") + std::string(tag) + " expects a relational operator");
                const std::string op = lower(a[k].s[0]);
                ++k;
                if (op == "gt")
                    m.r = rel::gt;
                else if (op == "ge")
                    m.r = rel::ge;
                else if (op == "lt")
                    m.r = rel::lt;
                else if (op == "le")
                    m.r = rel::le;
                else if (op == "eq")
                    m.r = rel::eq;
                else if (op == "ne")
                    m.r = rel::ne;
                else
                    return bad(line, "unknown relational operator \"" + op + "\"");
            }
            return 1;
        }
        if (ap && (tag == "all" || tag == "localpart" || tag == "domain" || tag == "user" || tag == "detail"))
        {
            if (seen & 4)
                return bad(line, "more than one address part");
            seen |= 4;
            if ((tag == "user" || tag == "detail") &&
                !need(c_subaddress, line, std::string(":") + std::string(tag), "subaddress"))
                return -1;
            *ap = tag == "all"         ? apart::all
                  : tag == "localpart" ? apart::localpart
                  : tag == "domain"    ? apart::domain
                  : tag == "user"      ? apart::user
                                       : apart::detail;
            return 1;
        }
        return 0;
    }

    int bad(int line, std::string_view why)
    {
        fail(line, why);
        return -1;
    }

    bool check_match(const match& m, int line)
    {
        if (m.c == cmp::numeric && (m.t == mtype::contains || m.t == mtype::matches))
            return fail(line, "i;ascii-numeric compares no substrings, so :contains and :matches are not for it");
        return true;
    }

    bool unknown_tag(std::string_view tag, int line, std::string_view what)
    {
        return fail(line, "unknown tag :" + std::string(tag) + " for " + std::string(what));
    }

    bool build_test(const std::string& id, int line, const std::vector<garg>& a, test_node& out)
    {
        out.line = line;
        const bool takes_tests = id == "not" || id == "allof" || id == "anyof";
        if (!takes_tests && !out.kids.empty())
            return fail(line, id + " takes no test");
        size_t k = 0;
        uint8_t seen = 0;
        if (id == "true" || id == "false")
        {
            out.k = id == "true" ? tk::yes : tk::no;
            return done(a, 0, id);
        }
        if (id == "not")
        {
            out.k = tk::not_;
            if (out.kids.size() != 1)
                return fail(line, "not takes one test");
            return done(a, 0, id);
        }
        if (id == "allof" || id == "anyof")
        {
            out.k = id == "allof" ? tk::allof : tk::anyof;
            if (out.kids.empty())
                return fail(line, id + " takes a list of tests");
            return done(a, 0, id);
        }
        // The tagged arguments, then the positional ones each test takes.
        const auto tags = [&](apart* ap, const std::function<int(const std::string&, size_t&)>& own) {
            while (k < a.size() && a[k].k == garg::kind::tag)
            {
                const std::string tag = a[k].tag;
                const int tl = a[k].line;
                ++k;
                const int r = common(tag, a, k, tl, out.m, seen, ap);
                if (r < 0)
                    return false;
                if (r > 0)
                    continue;
                const int o = own ? own(tag, k) : 0;
                if (o < 0)
                    return false;
                if (o == 0)
                    return unknown_tag(tag, tl, id);
            }
            return check_match(out.m, line);
        };
        if (id == "address" || id == "envelope")
        {
            out.k = id == "address" ? tk::address : tk::envelope;
            if (out.k == tk::envelope && !need(c_envelope, line, "envelope", "envelope"))
                return false;
            if (!tags(&out.ap, nullptr) || !list_arg(a, k, out.a, line, id) || !list_arg(a, k, out.keys, line, id))
                return false;
            if (out.k == tk::envelope)
                for (const auto& p : out.a)
                    if (!p.vars && !socketley::ascii::iequals(p.s, "from") && !socketley::ascii::iequals(p.s, "to"))
                        return fail(line, "unknown envelope part \"" + p.s + "\"");
            return done(a, k, id);
        }
        if (id == "header")
        {
            out.k = tk::header;
            if (!tags(nullptr, nullptr) || !list_arg(a, k, out.a, line, id) || !list_arg(a, k, out.keys, line, id))
                return false;
            return done(a, k, id);
        }
        if (id == "exists")
        {
            out.k = tk::exists;
            if (!tags(nullptr, nullptr))
                return false;
            if (seen)
                return fail(line, "exists takes no comparator or match type");
            if (!list_arg(a, k, out.a, line, id))
                return false;
            return done(a, k, id);
        }
        if (id == "size")
        {
            out.k = tk::size;
            bool got = false;
            while (k < a.size() && a[k].k == garg::kind::tag)
            {
                const std::string& tag = a[k].tag;
                if ((tag != "over" && tag != "under") || got)
                    return fail(a[k].line, "size takes one of :over and :under");
                out.over = tag == "over";
                got = true;
                ++k;
            }
            if (!got)
                return fail(line, "size takes :over or :under");
            if (!num_arg(a, k, out.limit, line, id))
                return false;
            return done(a, k, id);
        }
        if (id == "body")
        {
            out.k = tk::body;
            if (!need(c_body, line, "body", "body"))
                return false;
            bool got = false;
            const auto own = [&](const std::string& tag, size_t& kk) -> int {
                if (tag != "raw" && tag != "text" && tag != "content")
                    return 0;
                if (got)
                    return bad(line, "body takes one transform");
                got = true;
                out.tr = tag == "raw" ? transform::raw : tag == "text" ? transform::text : transform::content;
                if (out.tr == transform::content && !list_arg(a, kk, out.types, line, ":content"))
                    return -1;
                return 1;
            };
            if (!tags(nullptr, own) || !list_arg(a, k, out.keys, line, id))
                return false;
            if (out.m.t == mtype::count)
                return fail(line, "body does not take :count");
            return done(a, k, id);
        }
        if (id == "string")
        {
            out.k = tk::string;
            if (!need(c_variables, line, "string", "variables"))
                return false;
            if (!tags(nullptr, nullptr) || !list_arg(a, k, out.a, line, id) || !list_arg(a, k, out.keys, line, id))
                return false;
            return done(a, k, id);
        }
        if (id == "date" || id == "currentdate")
        {
            out.k = id == "date" ? tk::date : tk::currentdate;
            if (!need(c_date, line, id, "date"))
                return false;
            const auto own = [&](const std::string& tag, size_t& kk) -> int {
                if (tag == "zone")
                {
                    if (out.zone_set || out.original_zone)
                        return bad(line, "more than one zone");
                    out.zone_set = true;
                    if (!str_arg(a, kk, out.zone, line, ":zone"))
                        return -1;
                    int z = 0;
                    if (!out.zone.vars && !parse_zone(out.zone.s, z))
                        return bad(line, "a zone is written +hhmm or -hhmm");
                    return 1;
                }
                if (tag == "originalzone" && out.k == tk::date)
                {
                    if (out.zone_set || out.original_zone)
                        return bad(line, "more than one zone");
                    out.original_zone = true;
                    return 1;
                }
                return 0;
            };
            if (!tags(nullptr, own))
                return false;
            if (out.k == tk::date)
            {
                out.a.emplace_back();
                if (!str_arg(a, k, out.a.back(), line, "date's header name"))
                    return false;
            }
            if (!str_arg(a, k, out.part, line, "the date part") || !list_arg(a, k, out.keys, line, id))
                return false;
            if (!out.part.vars && !known_date_part(out.part.s))
                return fail(line, "unknown date part \"" + out.part.s + "\"");
            return done(a, k, id);
        }
        if (id == "hasflag")
        {
            out.k = tk::hasflag;
            if (!need(c_imap4flags, line, "hasflag", "imap4flags"))
                return false;
            if (!tags(nullptr, nullptr))
                return false;
            if (a.size() - k == 2)
            {
                if (!need(c_variables, line, "hasflag of a variable", "variables") ||
                    !list_arg(a, k, out.a, line, id))
                    return false;
                for (auto& v : out.a)
                {
                    if (!valid_identifier(v.s))
                        return fail(line, "\"" + v.s + "\" is no variable name");
                    v.s = lower(v.s);
                    v.vars = false;
                }
            }
            if (!list_arg(a, k, out.keys, line, id))
                return false;
            return done(a, k, id);
        }
        if (id == "mailboxexists")
        {
            out.k = tk::mailboxexists;
            if (!need(c_mailbox, line, "mailboxexists", "mailbox") || !list_arg(a, k, out.a, line, id))
                return false;
            return done(a, k, id);
        }
        return fail(line, "unknown test \"" + id + "\"");
    }

    // ── commands ──

    bool parse_commands(std::vector<cmd_node>& out, int depth, bool top)
    {
        while (peek().t != tok::end && peek().t != tok::rbrace)
        {
            if (peek().t != tok::ident)
                return fail(peek().line, "a command was expected");
            const std::string id = peek().text;
            const int line = peek().line;
            ++i;
            std::vector<garg> a;
            std::vector<test_node> tests;
            if (!parse_args(a) || !parse_tests(tests, depth + 1))
                return false;
            std::vector<cmd_node> block;
            bool has_block = false;
            if (peek().t == tok::semi)
                ++i;
            else if (peek().t == tok::lbrace)
            {
                if (depth + 1 > max_depth)
                    return fail(peek().line, "nested deeper than 32");
                ++i;
                if (!parse_commands(block, depth + 1, false))
                    return false;
                if (peek().t != tok::rbrace)
                    return fail(peek().line, "a block not closed by }");
                ++i;
                has_block = true;
            }
            else
                return fail(peek().line, "a command not ended by ; or a block");
            const bool control = id == "if" || id == "elsif" || id == "else";
            if (control != has_block)
                return fail(line, control ? id + " takes a block" : id + " takes no block");
            if (id == "require")
            {
                if (!top || past_require)
                    return fail(line, "require comes before every other command");
                if (!tests.empty() || a.size() != 1 || a[0].k != garg::kind::strings)
                    return fail(line, "require takes a string list");
                for (const auto& name : a[0].s)
                {
                    const auto hit = std::find_if(std::begin(cap_names), std::end(cap_names),
                                                  [&](const cap_name& c) { return c.name == lower(name); });
                    if (hit == std::end(cap_names))
                        return fail(line, "unsupported extension \"" + name + "\"");
                    caps |= hit->bits;
                }
                continue;
            }
            past_require = true;
            if (id == "elsif" || id == "else")
            {
                if (out.empty() || out.back().k != ck::if_ || out.back().blocks.size() != out.back().conds.size())
                    return fail(line, id + " that follows no if");
                if (id == "elsif")
                {
                    if (tests.size() != 1 || !a.empty())
                        return fail(line, "elsif takes one test");
                    out.back().conds.push_back(std::move(tests.front()));
                }
                else if (!tests.empty() || !a.empty())
                    return fail(line, "else takes no test");
                out.back().blocks.push_back(std::move(block));
                continue;
            }
            cmd_node c;
            c.line = line;
            if (id == "if")
            {
                if (tests.size() != 1 || !a.empty())
                    return fail(line, "if takes one test");
                c.k = ck::if_;
                c.conds.push_back(std::move(tests.front()));
                c.blocks.push_back(std::move(block));
                out.push_back(std::move(c));
                continue;
            }
            if (!tests.empty())
                return fail(line, id + " takes no test");
            if (!build_command(id, line, a, c))
                return false;
            out.push_back(std::move(c));
        }
        return true;
    }

    bool flags_tag(const std::vector<garg>& a, size_t& k, cmd_node& c, int line)
    {
        if (!need(c_imap4flags, line, ":flags", "imap4flags"))
            return false;
        if (c.has_flags)
            return fail(line, "more than one :flags");
        c.has_flags = true;
        return list_arg(a, k, c.list, line, ":flags");
    }

    bool build_command(const std::string& id, int line, const std::vector<garg>& a, cmd_node& c)
    {
        size_t k = 0;
        if (id == "stop" || id == "discard")
        {
            c.k = id == "stop" ? ck::stop : ck::discard;
            return done(a, 0, id);
        }
        if (id == "keep" || id == "fileinto")
        {
            c.k = id == "keep" ? ck::keep : ck::fileinto;
            if (c.k == ck::fileinto && !need(c_fileinto, line, "fileinto", "fileinto"))
                return false;
            while (k < a.size() && a[k].k == garg::kind::tag)
            {
                const std::string& tag = a[k].tag;
                const int tl = a[k].line;
                ++k;
                if (tag == "flags")
                {
                    if (!flags_tag(a, k, c, tl))
                        return false;
                }
                else if (tag == "copy" && c.k == ck::fileinto)
                {
                    if (!need(c_copy, tl, ":copy", "copy"))
                        return false;
                    c.copy = true;
                }
                else if (tag == "create" && c.k == ck::fileinto)
                {
                    if (!need(c_mailbox, tl, ":create", "mailbox"))
                        return false;
                    c.create = true;
                }
                else
                    return unknown_tag(tag, tl, id);
            }
            if (c.k == ck::fileinto)
            {
                if (!str_arg(a, k, c.a, line, id))
                    return false;
                if (!c.a.vars && c.a.s.empty())
                    return fail(line, "fileinto names no mailbox");
            }
            return done(a, k, id);
        }
        if (id == "redirect")
        {
            c.k = ck::redirect;
            while (k < a.size() && a[k].k == garg::kind::tag)
            {
                const int tl = a[k].line;
                if (a[k].tag != "copy")
                    return unknown_tag(a[k].tag, tl, id);
                if (!need(c_copy, tl, ":copy", "copy"))
                    return false;
                c.copy = true;
                ++k;
            }
            if (!str_arg(a, k, c.a, line, id))
                return false;
            address addr;
            if (!c.a.vars && !(parse_mailbox(c.a.s, addr) && !addr.domain.empty()))
                return fail(line, "redirect to \"" + c.a.s + "\", which is no address");
            return done(a, k, id);
        }
        if (id == "reject" || id == "ereject")
        {
            c.k = id == "reject" ? ck::reject : ck::ereject;
            if (!need(id == "reject" ? c_reject : c_ereject, line, id, id))
                return false;
            if (!str_arg(a, k, c.a, line, id))
                return false;
            return done(a, k, id);
        }
        if (id == "vacation")
        {
            c.k = ck::vacation;
            if (!need(c_vacation, line, "vacation", "vacation"))
                return false;
            bool timed = false;
            while (k < a.size() && a[k].k == garg::kind::tag)
            {
                const std::string tag = a[k].tag;
                const int tl = a[k].line;
                ++k;
                if (tag == "days" || tag == "seconds")
                {
                    if (tag == "seconds" && !need(c_vacation_seconds, tl, ":seconds", "vacation-seconds"))
                        return false;
                    if (timed)
                        return fail(tl, "vacation takes one of :days and :seconds");
                    timed = true;
                    uint64_t n = 0;
                    if (!num_arg(a, k, n, tl, ":" + tag))
                        return false;
                    // A day at least and a year at most, as RFC 5230 lets a site bound them.
                    constexpr uint64_t year = 365ull * 86400;
                    c.seconds = tag == "days" ? std::clamp<uint64_t>(n, 1, 365) * 86400 : std::min(n, year);
                }
                else if (tag == "subject")
                {
                    if (c.has_subject)
                        return fail(tl, "more than one :subject");
                    if (!str_arg(a, k, c.subject, tl, ":subject"))
                        return false;
                    c.has_subject = true;
                }
                else if (tag == "from")
                {
                    if (c.has_from)
                        return fail(tl, "more than one :from");
                    if (!str_arg(a, k, c.from, tl, ":from"))
                        return false;
                    c.has_from = true;
                }
                else if (tag == "handle")
                {
                    if (c.has_handle)
                        return fail(tl, "more than one :handle");
                    if (!str_arg(a, k, c.handle, tl, ":handle"))
                        return false;
                    c.has_handle = true;
                }
                else if (tag == "addresses")
                {
                    if (!list_arg(a, k, c.list, tl, ":addresses"))
                        return false;
                }
                else if (tag == "mime")
                    c.mime = true;
                else
                    return unknown_tag(tag, tl, id);
            }
            if (!str_arg(a, k, c.a, line, id))
                return false;
            return done(a, k, id);
        }
        if (id == "set")
        {
            c.k = ck::set;
            if (!need(c_variables, line, "set", "variables"))
                return false;
            while (k < a.size() && a[k].k == garg::kind::tag)
            {
                const std::string& tag = a[k].tag;
                const int tl = a[k].line;
                ++k;
                const uint8_t bit = tag == "lower"           ? m_lower
                                    : tag == "upper"         ? m_upper
                                    : tag == "lowerfirst"    ? m_lowerfirst
                                    : tag == "upperfirst"    ? m_upperfirst
                                    : tag == "quotewildcard" ? m_quotewildcard
                                    : tag == "length"        ? m_length
                                                             : 0;
                if (!bit)
                    return unknown_tag(tag, tl, id);
                // Two modifiers of one precedence cannot both apply.
                uint8_t rival = bit;
                if (bit & (m_lower | m_upper))
                    rival = m_lower | m_upper;
                else if (bit & (m_lowerfirst | m_upperfirst))
                    rival = m_lowerfirst | m_upperfirst;
                if (c.mods & rival)
                    return fail(tl, "two modifiers of one precedence");
                c.mods |= bit;
            }
            if (!str_arg(a, k, c.a, line, id) || !str_arg(a, k, c.b, line, id))
                return false;
            if (!valid_identifier(c.a.s))
                return fail(line, "\"" + c.a.s + "\" is no variable name");
            c.a.s = lower(c.a.s);
            c.a.vars = false;
            return done(a, k, id);
        }
        if (id == "setflag" || id == "addflag" || id == "removeflag")
        {
            c.k = id == "setflag" ? ck::setflag : id == "addflag" ? ck::addflag : ck::removeflag;
            if (!need(c_imap4flags, line, id, "imap4flags"))
                return false;
            if (a.size() == 2)
            {
                if (!need(c_variables, line, id + " of a variable", "variables") ||
                    !str_arg(a, k, c.a, line, id))
                    return false;
                if (!valid_identifier(c.a.s))
                    return fail(line, "\"" + c.a.s + "\" is no variable name");
                c.a.s = lower(c.a.s);
                c.a.vars = false;
                c.has_var = true;
            }
            if (!list_arg(a, k, c.list, line, id))
                return false;
            return done(a, k, id);
        }
        return fail(line, "unknown command \"" + id + "\"");
    }

    // A reject beside keep, fileinto, redirect, vacation or another reject that every run reaches.
    bool check_conflicts(const std::vector<cmd_node>& top)
    {
        bool rejects = false, others = false;
        for (const auto& c : top)
        {
            if (c.k == ck::stop)
                break;
            const bool reject = c.k == ck::reject || c.k == ck::ereject;
            const bool other = c.k == ck::keep || c.k == ck::fileinto || c.k == ck::redirect || c.k == ck::vacation;
            if (reject && rejects)
                return fail(c.line, "a second reject");
            if ((reject && others) || (other && rejects))
                return fail(c.line, "reject cannot be used with keep, fileinto, redirect or vacation");
            rejects = rejects || reject;
            others = others || other;
        }
        return true;
    }
};

// ─── addresses ─────────────────────────────────────────────────────────────

struct parsed_address
{
    std::string local, domain;
    bool at{false};
};

struct atok
{
    // 'w' a word, 'q' a quoted string, 'l' a domain literal, or the special character itself.
    char k;
    std::string text;
};

void address_tokens(std::string_view v, std::vector<atok>& out)
{
    for (size_t i = 0; i < v.size();)
    {
        const char c = v[i];
        if (is_wsp(c))
        {
            ++i;
            continue;
        }
        if (c == '(')
        {
            int depth = 0;
            for (; i < v.size(); ++i)
            {
                if (v[i] == '\\')
                    ++i;
                else if (v[i] == '(')
                    ++depth;
                else if (v[i] == ')' && --depth == 0)
                {
                    ++i;
                    break;
                }
            }
            continue;
        }
        if (c == '"')
        {
            atok t{'q', {}};
            for (++i; i < v.size() && v[i] != '"'; ++i)
            {
                if (v[i] == '\\' && i + 1 < v.size())
                    ++i;
                if (v[i] != '\r' && v[i] != '\n')
                    t.text += v[i];
            }
            ++i;
            out.push_back(std::move(t));
            continue;
        }
        if (c == '[')
        {
            const size_t close = v.find(']', i);
            const size_t end = close == std::string_view::npos ? v.size() : close + 1;
            out.push_back({'l', std::string(v.substr(i, end - i))});
            i = end;
            continue;
        }
        if (c == '<' || c == '>' || c == '@' || c == ',' || c == ';' || c == ':' || c == '.')
        {
            out.push_back({c, {}});
            ++i;
            continue;
        }
        size_t j = i;
        while (j < v.size() && !is_wsp(v[j]) && std::string_view("()<>@,;:.\"[]").find(v[j]) == std::string_view::npos)
            ++j;
        if (j == i)
            ++j;
        out.push_back({'w', std::string(v.substr(i, j - i))});
        i = j;
    }
}

parsed_address addr_spec(const std::vector<atok>& t, size_t from, size_t to)
{
    parsed_address a;
    size_t last_at = to;
    for (size_t k = from; k < to; ++k)
        if (t[k].k == '@')
            last_at = k;
    const auto text = [&](size_t b, size_t e) {
        std::string s;
        for (size_t k = b; k < e; ++k)
            s += t[k].k == 'w' || t[k].k == 'q' || t[k].k == 'l' ? t[k].text : std::string(1, t[k].k);
        return s;
    };
    a.local = text(from, last_at);
    if (last_at < to)
    {
        a.at = true;
        a.domain = text(last_at + 1, to);
    }
    return a;
}

// The addresses of an RFC 5322 address list: display names, comments and routes dropped, groups opened.
void parse_addresses(std::string_view v, std::vector<parsed_address>& out)
{
    std::vector<atok> t;
    address_tokens(v, t);
    bool in_group = false;
    size_t i = 0;
    while (i < t.size())
    {
        size_t j = i;
        while (j < t.size() && t[j].k != ',' && t[j].k != ';' && t[j].k != ':' && t[j].k != '<')
            ++j;
        if (j < t.size() && t[j].k == ':' && !in_group)
        {
            in_group = true;
            i = j + 1;
            continue;
        }
        if (j < t.size() && t[j].k == '<')
        {
            size_t close = j + 1;
            while (close < t.size() && t[close].k != '>')
                ++close;
            // A source route ends at the last colon inside the brackets.
            size_t start = j + 1;
            for (size_t k = j + 1; k < close; ++k)
                if (t[k].k == ':')
                    start = k + 1;
            out.push_back(addr_spec(t, start, close));
            i = close;
            while (i < t.size() && t[i].k != ',' && t[i].k != ';')
                ++i;
            if (i < t.size())
            {
                if (t[i].k == ';')
                    in_group = false;
                ++i;
            }
            continue;
        }
        if (j > i)
            out.push_back(addr_spec(t, i, j));
        if (j < t.size() && t[j].k == ';')
            in_group = false;
        i = j + 1;
    }
}

// The part of `a` an address test compares, none where the address has no such part.
bool address_part(const parsed_address& a, apart p, std::string& out)
{
    switch (p)
    {
        case apart::all: out = a.at ? a.local + "@" + a.domain : a.local; return true;
        case apart::localpart: out = a.local; return true;
        case apart::domain:
            if (!a.at)
                return false;
            out = a.domain;
            return true;
        case apart::user: out = a.local.substr(0, a.local.find('+')); return true;
        case apart::detail:
        {
            const size_t plus = a.local.find('+');
            if (plus == std::string::npos)
                return false;
            out = a.local.substr(plus + 1);
            return true;
        }
    }
    return false;
}

// ─── dates ─────────────────────────────────────────────────────────────────

int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void civil_from_days(int64_t z, int64_t& y, unsigned& m, unsigned& d)
{
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const auto doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
}

bool small_number(std::string_view s, int& out, size_t max_digits)
{
    if (s.empty() || s.size() > max_digits)
        return false;
    out = 0;
    for (const char c : s)
    {
        if (!is_digit(c))
            return false;
        out = out * 10 + (c - '0');
    }
    return true;
}

// An RFC 5322 date, the obsolete forms among it, as unix time and the zone it was written in.
bool parse_date(std::string_view v, int64_t& t, int& zone)
{
    std::string clean;
    int depth = 0;
    for (const char c : v)
    {
        if (c == '(')
            ++depth;
        else if (c == ')' && depth > 0)
            --depth;
        else if (depth == 0)
            clean += c == ',' ? ' ' : c;
    }
    std::vector<std::string_view> w;
    std::string_view rest = clean;
    while (!rest.empty())
    {
        rest = trim(rest);
        if (rest.empty())
            break;
        size_t n = 0;
        while (n < rest.size() && !is_wsp(rest[n]))
            ++n;
        w.push_back(rest.substr(0, n));
        rest.remove_prefix(n);
    }
    size_t k = 0;
    if (k < w.size() && !w[k].empty() && is_alpha(w[k][0]))
        ++k;
    if (w.size() < k + 4)
        return false;
    int day = 0, year = 0, hour = 0, minute = 0, second = 0;
    if (!small_number(w[k], day, 2) || day < 1 || day > 31)
        return false;
    static constexpr std::string_view months[] = {"jan", "feb", "mar", "apr", "may", "jun",
                                                  "jul", "aug", "sep", "oct", "nov", "dec"};
    unsigned month = 0;
    for (unsigned mi = 0; mi < 12; ++mi)
        if (socketley::ascii::iequals(w[k + 1], months[mi]))
            month = mi + 1;
    if (!month || !small_number(w[k + 2], year, 4))
        return false;
    if (w[k + 2].size() == 2)
        year += year < 50 ? 2000 : 1900;
    else if (w[k + 2].size() == 3)
        year += 1900;
    const std::string_view time = w[k + 3];
    const size_t c1 = time.find(':');
    const size_t c2 = c1 == std::string_view::npos ? c1 : time.find(':', c1 + 1);
    if (c1 == std::string_view::npos || !small_number(time.substr(0, c1), hour, 2) ||
        !small_number(time.substr(c1 + 1, c2 == std::string_view::npos ? std::string_view::npos : c2 - c1 - 1),
                      minute, 2) ||
        (c2 != std::string_view::npos && !small_number(time.substr(c2 + 1), second, 2)))
        return false;
    if (hour > 23 || minute > 59 || second > 60)
        return false;
    zone = 0;
    if (w.size() > k + 4)
    {
        const std::string_view z = w[k + 4];
        if ((z[0] == '+' || z[0] == '-') && z.size() == 5)
        {
            int hh = 0, mm = 0;
            if (!small_number(z.substr(1, 2), hh, 2) || !small_number(z.substr(3, 2), mm, 2) || mm > 59)
                return false;
            zone = (z[0] == '-' ? -1 : 1) * (hh * 60 + mm);
        }
        else
        {
            static constexpr std::pair<std::string_view, int> names[] = {
                {"ut", 0},          {"gmt", 0},         {"z", 0},           {"est", -5 * 60}, {"edt", -4 * 60},
                {"cst", -6 * 60},   {"cdt", -5 * 60},   {"mst", -7 * 60},   {"mdt", -6 * 60}, {"pst", -8 * 60},
                {"pdt", -7 * 60}};
            for (const auto& [name, off] : names)
                if (socketley::ascii::iequals(z, name))
                    zone = off;
        }
    }
    t = days_from_civil(year, month, static_cast<unsigned>(day)) * 86400 + hour * 3600 + minute * 60 + second -
        static_cast<int64_t>(zone) * 60;
    return true;
}

// The part of time `t` RFC 5260 names, as it reads in `zone`.
bool date_part(int64_t t, int zone, std::string_view part, std::string& out)
{
    const int64_t local = t + static_cast<int64_t>(zone) * 60;
    int64_t days = local / 86400;
    int64_t secs = local % 86400;
    if (secs < 0)
    {
        secs += 86400;
        --days;
    }
    int64_t y = 0;
    unsigned m = 0, d = 0;
    civil_from_days(days, y, m, d);
    if (y < 0 || y > 9999)
        return false;
    const int hh = static_cast<int>(secs / 3600), mi = static_cast<int>(secs / 60 % 60), ss = static_cast<int>(secs % 60);
    const int wd = static_cast<int>(((days % 7) + 7 + 4) % 7);
    const int za = zone < 0 ? -zone : zone;
    char buf[64];
    const std::string p = lower(part);
    if (p == "year")
        std::snprintf(buf, sizeof buf, "%04d", static_cast<int>(y));
    else if (p == "month")
        std::snprintf(buf, sizeof buf, "%02u", m);
    else if (p == "day")
        std::snprintf(buf, sizeof buf, "%02u", d);
    else if (p == "date")
        std::snprintf(buf, sizeof buf, "%04d-%02u-%02u", static_cast<int>(y), m, d);
    else if (p == "julian")
        std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(days + 40587));
    else if (p == "hour")
        std::snprintf(buf, sizeof buf, "%02d", hh);
    else if (p == "minute")
        std::snprintf(buf, sizeof buf, "%02d", mi);
    else if (p == "second")
        std::snprintf(buf, sizeof buf, "%02d", ss);
    else if (p == "time")
        std::snprintf(buf, sizeof buf, "%02d:%02d:%02d", hh, mi, ss);
    else if (p == "iso8601")
        std::snprintf(buf, sizeof buf, "%04d-%02u-%02uT%02d:%02d:%02d%c%02d:%02d", static_cast<int>(y), m, d, hh, mi,
                      ss, zone < 0 ? '-' : '+', za / 60, za % 60);
    else if (p == "std11")
    {
        static constexpr const char* wdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        static constexpr const char* mons[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        std::snprintf(buf, sizeof buf, "%s, %02u %s %04d %02d:%02d:%02d %c%02d%02d", wdays[wd], d, mons[m - 1],
                      static_cast<int>(y), hh, mi, ss, zone < 0 ? '-' : '+', za / 60, za % 60);
    }
    else if (p == "zone")
        std::snprintf(buf, sizeof buf, "%c%02d%02d", zone < 0 ? '-' : '+', za / 60, za % 60);
    else if (p == "weekday")
        std::snprintf(buf, sizeof buf, "%d", wd);
    else
        return false;
    out = buf;
    return true;
}

// ─── comparators ───────────────────────────────────────────────────────────

int compare3(std::string_view a, std::string_view b, cmp c)
{
    if (c == cmp::numeric)
    {
        // The leading digits as a number, a string with none being greater than every number.
        const auto num = [](std::string_view s) -> std::string_view {
            size_t n = 0;
            while (n < s.size() && is_digit(s[n]))
                ++n;
            if (n == 0)
                return {};
            s = s.substr(0, n);
            while (s.size() > 1 && s[0] == '0')
                s.remove_prefix(1);
            return s;
        };
        const std::string_view x = num(a), y = num(b);
        if (x.empty() || y.empty())
            return x.empty() == y.empty() ? 0 : x.empty() ? 1 : -1;
        if (x.size() != y.size())
            return x.size() < y.size() ? -1 : 1;
        const int r = x.compare(y);
        return r < 0 ? -1 : r > 0 ? 1 : 0;
    }
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i)
    {
        auto x = static_cast<unsigned char>(a[i]), y = static_cast<unsigned char>(b[i]);
        if (c == cmp::casemap)
        {
            x = static_cast<unsigned char>(socketley::ascii::lower(static_cast<char>(x)));
            y = static_cast<unsigned char>(socketley::ascii::lower(static_cast<char>(y)));
        }
        if (x != y)
            return x < y ? -1 : 1;
    }
    return a.size() == b.size() ? 0 : a.size() < b.size() ? -1 : 1;
}

bool relate(int r, rel op)
{
    switch (op)
    {
        case rel::gt: return r > 0;
        case rel::ge: return r >= 0;
        case rel::lt: return r < 0;
        case rel::le: return r <= 0;
        case rel::eq: return r == 0;
        case rel::ne: return r != 0;
    }
    return false;
}

bool contains(std::string_view hay, std::string_view needle, cmp c)
{
    if (needle.empty())
        return true;
    if (c == cmp::octet)
        return hay.find(needle) != std::string_view::npos;
    const auto eq = [](char x, char y) { return socketley::ascii::lower(x) == socketley::ascii::lower(y); };
    const auto hash = [](char x) { return std::hash<char>{}(socketley::ascii::lower(x)); };
    const std::boyer_moore_horspool_searcher<std::string_view::const_iterator, decltype(hash), decltype(eq)> s(
        needle.begin(), needle.end(), hash, eq);
    return std::search(hay.begin(), hay.end(), s) != hay.end();
}

struct glob_tok
{
    char c;
    // 0 a literal character, 1 a star, 2 a question mark.
    uint8_t k;
};

// Whether `s` matches the wildcard pattern `pat`, with one backtrack point on the last star so a pattern costs at
// most its length times the string's; `work` counts the steps and gives up past `budget`.
bool glob(std::string_view pat, std::string_view s, bool fold, std::vector<std::pair<size_t, size_t>>* caps,
          uint64_t& work, uint64_t budget)
{
    std::vector<glob_tok> p;
    std::vector<uint32_t> wild;
    p.reserve(pat.size());
    wild.reserve(pat.size());
    uint32_t nwild = 0;
    for (size_t i = 0; i < pat.size(); ++i)
    {
        const char c = pat[i];
        if (c == '\\' && i + 1 < pat.size())
            p.push_back({pat[++i], 0});
        else
            p.push_back({c, static_cast<uint8_t>(c == '*' ? 1 : c == '?' ? 2 : 0)});
        wild.push_back(p.back().k ? nwild++ : 0);
    }
    if (caps)
        caps->assign(nwild, {0, 0});
    const auto step = [&](size_t at) { return fold ? utf8_len(s, at) : size_t{1}; };
    constexpr size_t none = static_cast<size_t>(-1);
    size_t pi = 0, si = 0, star = none, star_si = 0;
    while (si < s.size())
    {
        if (++work > budget)
            return false;
        if (pi < p.size())
        {
            const glob_tok& g = p[pi];
            if (g.k == 1)
            {
                star = pi;
                star_si = si;
                if (caps)
                    (*caps)[wild[pi]] = {si, si};
                ++pi;
                continue;
            }
            if (g.k == 2)
            {
                const size_t n = step(si);
                if (caps)
                    (*caps)[wild[pi]] = {si, si + n};
                si += n;
                ++pi;
                continue;
            }
            if (fold ? socketley::ascii::lower(g.c) == socketley::ascii::lower(s[si]) : g.c == s[si])
            {
                ++pi;
                ++si;
                continue;
            }
        }
        if (star == none)
            return false;
        star_si += step(star_si);
        if (caps)
            (*caps)[wild[star]].second = star_si;
        si = star_si;
        pi = star + 1;
    }
    while (pi < p.size() && p[pi].k == 1)
    {
        if (caps)
            (*caps)[wild[pi]] = {s.size(), s.size()};
        ++pi;
    }
    return pi == p.size();
}

// ─── the run ───────────────────────────────────────────────────────────────

struct xlist
{
    std::vector<std::string_view> v;
    std::deque<std::string> own;
};

}   // namespace

struct script::program
{
    std::vector<cmd_node> top;
    uint32_t caps{0};
};

namespace
{

struct runner
{
    runner(const script::program& prog, const message& msg, const context& ctx) : p(prog), m(msg), c(ctx) {}

    const script::program& p;
    const message& m;
    const context& c;
    std::vector<action> actions;
    std::string error;
    uint64_t steps{0};
    bool stopped{false}, implicit_keep{true}, rejected{false}, delivered{false}, vacationed{false}, discarded{false};
    size_t redirects{0};
    std::vector<std::string> flags;
    std::vector<std::pair<std::string, std::string>> vars;
    std::array<std::string, max_match_vars> mv;
    size_t mv_count{0};

    bool headers_read{false};
    std::vector<std::pair<std::string_view, std::string_view>> headers;
    std::vector<std::string> decoded;
    std::vector<uint8_t> have_decoded;
    bool mime_read{false};
    mime::part root;
    bool text_read{false};
    std::vector<std::string> texts;

    bool fail(int line, std::string_view why)
    {
        if (error.empty())
            error = at_line(line, why);
        return false;
    }

    bool ok() const { return error.empty(); }

    bool step(int line, uint64_t n = 1)
    {
        steps += n;
        if (steps > max_steps)
            return fail(line, "the script ran past its 1,000,000 steps");
        return true;
    }

    // ── variables ──

    const std::string* variable(std::string_view name) const
    {
        for (const auto& [k, v] : vars)
            if (socketley::ascii::iequals(k, name))
                return &v;
        return nullptr;
    }

    // What ${name} stands for, or nothing where it is no reference and stays as written.
    std::optional<std::string_view> reference(std::string_view name) const
    {
        if (!name.empty() && std::all_of(name.begin(), name.end(), is_digit))
        {
            size_t n = 0;
            for (const char d : name)
            {
                n = n * 10 + static_cast<size_t>(d - '0');
                if (n >= max_match_vars)
                    return std::string_view{};
            }
            return n < mv_count ? std::string_view(mv[n]) : std::string_view{};
        }
        if (!valid_identifier(name))
            return std::nullopt;
        const std::string* v = variable(name);
        return v ? std::string_view(*v) : std::string_view{};
    }

    std::string_view expand(const str& s, std::string& scratch, int line)
    {
        if (!s.vars)
            return s.s;
        scratch.clear();
        size_t i = 0;
        while (i < s.s.size())
        {
            const size_t at = s.s.find("${", i);
            if (at == std::string::npos)
            {
                scratch.append(s.s, i, std::string::npos);
                break;
            }
            scratch.append(s.s, i, at - i);
            const size_t close = s.s.find('}', at + 2);
            const std::optional<std::string_view> v =
                close == std::string::npos ? std::nullopt
                                           : reference(std::string_view(s.s).substr(at + 2, close - at - 2));
            if (v)
            {
                scratch += *v;
                i = close + 1;
            }
            else
            {
                scratch += "${";
                i = at + 2;
            }
            if (scratch.size() > max_expanded)
            {
                fail(line, "a string longer than 64 KiB once its variables are put in");
                return {};
            }
        }
        step(line, 1 + scratch.size() / bytes_per_step);
        return scratch;
    }

    bool expand_list(const strs& l, xlist& out, int line)
    {
        size_t total = 0;
        out.v.reserve(l.size());
        for (const auto& s : l)
        {
            if (!s.vars)
            {
                out.v.push_back(s.s);
                continue;
            }
            out.own.emplace_back();
            const std::string_view r = expand(s, out.own.back(), line);
            if (!ok())
                return false;
            total += r.size();
            if (total > max_list_bytes)
                return fail(line, "a string list longer than 1 MiB once its variables are put in");
            out.v.push_back(r);
        }
        return ok();
    }

    bool set_variable(std::string_view name, std::string value, int line)
    {
        clip(value, max_var_len);
        for (auto& [k, v] : vars)
            if (k == name)
            {
                v = std::move(value);
                return true;
            }
        if (vars.size() >= max_vars)
            return fail(line, "more than 128 variables");
        vars.emplace_back(std::string(name), std::move(value));
        return true;
    }

    // ── the message ──

    void read_headers()
    {
        if (headers_read)
            return;
        headers_read = true;
        headers = split_headers(header_block(m.bytes));
        decoded.assign(headers.size(), {});
        have_decoded.assign(headers.size(), 0);
    }

    static std::string unfolded(std::string_view v)
    {
        std::string out;
        out.reserve(v.size());
        for (const char ch : v)
            if (ch != '\r' && ch != '\n')
                out += ch;
        return std::string(trim(out));
    }

    std::string_view header_text(size_t idx)
    {
        if (!have_decoded[idx])
        {
            decoded[idx] = mime::decode_words(unfolded(headers[idx].second));
            have_decoded[idx] = 1;
        }
        return decoded[idx];
    }

    bool named(size_t idx, std::string_view name) const
    {
        return socketley::ascii::iequals(trim(headers[idx].first), name);
    }

    // The headers read, and a walk over them charged to the run.
    bool scan(int line)
    {
        read_headers();
        return step(line, 1 + headers.size() / 32);
    }

    // The index of the first header named `name`, the count of headers where there is none.
    size_t first_index(std::string_view name, int line)
    {
        if (!scan(line))
            return headers.size();
        for (size_t i = 0; i < headers.size(); ++i)
            if (named(i, name))
                return i;
        return headers.size();
    }

    // The first value of a header, decoded; empty where the message has none.
    std::string first_header(std::string_view name, int line)
    {
        const size_t i = first_index(name, line);
        return i < headers.size() ? std::string(header_text(i)) : std::string();
    }

    bool has_header(std::string_view name, int line) { return first_index(name, line) < headers.size(); }

    void addresses_of(std::string_view name, std::vector<parsed_address>& out, int line)
    {
        if (!scan(line))
            return;
        for (size_t i = 0; i < headers.size(); ++i)
            if (named(i, name))
            {
                if (!step(line, headers[i].second.size() / bytes_per_step))
                    return;
                parse_addresses(unfolded(headers[i].second), out);
            }
    }

    void read_mime()
    {
        if (mime_read)
            return;
        mime_read = true;
        root = mime::parse(m.bytes);
    }

    std::string part_text(const mime::part& q) const
    {
        const std::string_view body = m.bytes.substr(q.body_off, q.body_len);
        std::string charset;
        for (const auto& [k, v] : q.params)
            if (k == "charset")
                charset = v;
        return mime::to_utf8(mime::decoded_body(body, q.encoding), charset);
    }

    // Each leaf part's decoded text where `want` takes the part, a multipart's prologue and epilogue and an enclosed
    // message's header standing for those.
    void collect(const mime::part& q, const std::function<bool(const mime::part&)>& want, std::vector<std::string>& out,
                 int line)
    {
        if (!ok() || !step(line, 1 + q.body_len / bytes_per_step))
            return;
        if (q.multipart() && !q.children.empty())
        {
            if (want(q))
            {
                const size_t first = q.children.front().header_off, end = q.body_off + q.body_len;
                const mime::part& last = q.children.back();
                const size_t tail = last.body_off + last.body_len;
                out.push_back(std::string(m.bytes.substr(q.body_off, first - q.body_off)) +
                              std::string(m.bytes.substr(tail, end - tail)));
            }
            for (const auto& ch : q.children)
                collect(ch, want, out, line);
            return;
        }
        if (q.message() && !q.children.empty())
        {
            if (want(q))
                out.emplace_back(m.bytes.substr(q.children.front().header_off, q.children.front().header_len));
            collect(q.children.front(), want, out, line);
            return;
        }
        if (want(q))
            out.push_back(part_text(q));
    }

    // ── matching ──

    bool one(std::string_view value, std::string_view key, const match& mt, int line)
    {
        switch (mt.t)
        {
            case mtype::is: return compare3(value, key, mt.c) == 0;
            case mtype::contains:
                if (!step(line, value.size() / bytes_per_step))
                    return false;
                return contains(value, key, mt.c);
            case mtype::value: return relate(compare3(value, key, mt.c), mt.r);
            case mtype::count: return false;
            case mtype::matches:
            {
                const bool want = (p.caps & c_variables) != 0;
                std::vector<std::pair<size_t, size_t>> caps;
                uint64_t work = 0;
                const uint64_t budget = (max_steps - std::min(steps, max_steps)) * glob_per_step;
                const bool hit = glob(key, value, mt.c != cmp::octet, want ? &caps : nullptr, work, budget);
                if (!step(line, work / glob_per_step))
                    return false;
                if (work > budget)
                {
                    fail(line, "the script ran past its 1,000,000 steps");
                    return false;
                }
                if (hit && want)
                {
                    mv_count = std::min(max_match_vars, caps.size() + 1);
                    mv[0] = std::string(value);
                    clip(mv[0], max_var_len);
                    for (size_t k = 1; k < mv_count; ++k)
                    {
                        mv[k] = std::string(value.substr(caps[k - 1].first, caps[k - 1].second - caps[k - 1].first));
                        clip(mv[k], max_var_len);
                    }
                }
                return hit;
            }
        }
        return false;
    }

    bool compare(const std::vector<std::string_view>& values, const xlist& keys, const match& mt, int line,
                 size_t count)
    {
        if (mt.t == mtype::count)
        {
            const std::string n = std::to_string(count);
            for (const auto key : keys.v)
            {
                if (!step(line))
                    return false;
                if (relate(compare3(n, key, mt.c), mt.r))
                    return true;
            }
            return false;
        }
        for (const auto value : values)
            for (const auto key : keys.v)
            {
                if (!step(line))
                    return false;
                if (one(value, key, mt, line))
                    return true;
                if (!ok())
                    return false;
            }
        return false;
    }

    bool compare(const std::vector<std::string_view>& values, const xlist& keys, const match& mt, int line)
    {
        return compare(values, keys, mt, line, values.size());
    }

    // ── tests ──

    bool test(const test_node& t)
    {
        if (!ok() || !step(t.line))
            return false;
        switch (t.k)
        {
            case tk::yes: return true;
            case tk::no: return false;
            case tk::not_:
            {
                const bool r = test(t.kids.front());
                return ok() && !r;
            }
            case tk::allof:
                for (const auto& k : t.kids)
                    if (!test(k))
                        return false;
                return ok();
            case tk::anyof:
                for (const auto& k : t.kids)
                    if (test(k))
                        return true;
                return false;
            case tk::address:
            case tk::envelope: return address_test(t);
            case tk::header:
            {
                xlist names, keys;
                if (!expand_list(t.a, names, t.line) || !expand_list(t.keys, keys, t.line))
                    return false;
                std::vector<std::string_view> values;
                for (const auto name : names.v)
                {
                    if (!scan(t.line))
                        return false;
                    for (size_t i = 0; i < headers.size(); ++i)
                        if (named(i, name))
                            values.push_back(header_text(i));
                }
                return compare(values, keys, t.m, t.line);
            }
            case tk::exists:
            {
                xlist names;
                if (!expand_list(t.a, names, t.line))
                    return false;
                for (const auto name : names.v)
                    if (!has_header(name, t.line))
                        return false;
                return ok();
            }
            case tk::size: return t.over ? m.bytes.size() > t.limit : m.bytes.size() < t.limit;
            case tk::body: return body_test(t);
            case tk::string:
            {
                xlist src, keys;
                if (!expand_list(t.a, src, t.line) || !expand_list(t.keys, keys, t.line))
                    return false;
                const size_t nonempty = static_cast<size_t>(
                    std::count_if(src.v.begin(), src.v.end(), [](std::string_view s) { return !s.empty(); }));
                return compare(src.v, keys, t.m, t.line, nonempty);
            }
            case tk::date:
            case tk::currentdate: return date_test(t);
            case tk::hasflag:
            {
                xlist keys;
                if (!expand_list(t.keys, keys, t.line))
                    return false;
                std::vector<std::string> have;
                if (t.a.empty())
                    have = flags;
                else
                    for (const auto& v : t.a)
                        if (const std::string* val = variable(v.s))
                            add_flags(have, *val);
                std::vector<std::string> split;
                for (const auto key : keys.v)
                    add_flags(split, key);
                xlist ks;
                for (const auto& s : split)
                    ks.v.push_back(s);
                std::vector<std::string_view> values(have.begin(), have.end());
                return compare(values, ks, t.m, t.line);
            }
            case tk::mailboxexists:
            {
                xlist names;
                if (!expand_list(t.a, names, t.line))
                    return false;
                for (const auto name : names.v)
                    if (c.mailbox_exists && !c.mailbox_exists(name))
                        return false;
                return true;
            }
        }
        return false;
    }

    bool address_test(const test_node& t)
    {
        xlist names, keys;
        if (!expand_list(t.a, names, t.line) || !expand_list(t.keys, keys, t.line))
            return false;
        std::deque<std::string> store;
        std::vector<std::string_view> values;
        std::string part;
        const auto add = [&](const parsed_address& a) {
            if (address_part(a, t.ap, part))
            {
                store.push_back(std::move(part));
                values.push_back(store.back());
            }
        };
        for (const auto name : names.v)
        {
            if (!step(t.line))
                return false;
            if (t.k == tk::envelope)
            {
                const bool from = socketley::ascii::iequals(name, "from");
                if (!from && !socketley::ascii::iequals(name, "to"))
                    continue;
                const std::string_view e = from ? m.envelope_from : m.envelope_to;
                // The null reverse-path is the empty string, whatever part is asked of it.
                if (e.empty())
                {
                    values.push_back({});
                    continue;
                }
                parsed_address a;
                const size_t at = e.rfind('@');
                a.local = std::string(e.substr(0, at));
                if (at != std::string_view::npos)
                {
                    a.at = true;
                    a.domain = std::string(e.substr(at + 1));
                }
                add(a);
                continue;
            }
            std::vector<parsed_address> list;
            addresses_of(name, list, t.line);
            if (!ok() || !step(t.line, list.size()))
                return false;
            for (const auto& a : list)
                add(a);
        }
        return compare(values, keys, t.m, t.line);
    }

    bool body_test(const test_node& t)
    {
        xlist keys;
        if (!expand_list(t.keys, keys, t.line))
            return false;
        std::vector<std::string_view> values;
        std::vector<std::string> parts;
        if (t.tr == transform::raw)
        {
            const std::string_view head = header_block(m.bytes);
            values.push_back(head.size() < m.bytes.size() ? m.bytes.substr(head.size()) : std::string_view{});
            if (!step(t.line, values.back().size() / bytes_per_step))
                return false;
        }
        else if (t.tr == transform::text)
        {
            read_mime();
            if (!text_read)
            {
                text_read = true;
                collect(root, [](const mime::part& q) { return q.type == "text"; }, texts, t.line);
            }
            values.assign(texts.begin(), texts.end());
        }
        else
        {
            xlist types;
            if (!expand_list(t.types, types, t.line))
                return false;
            read_mime();
            const auto want = [&](const mime::part& q) {
                for (const auto ty : types.v)
                {
                    const size_t slash = ty.find('/');
                    if (ty.empty() ||
                        (slash == std::string_view::npos && socketley::ascii::iequals(ty, q.type)) ||
                        (slash != std::string_view::npos && socketley::ascii::iequals(ty.substr(0, slash), q.type) &&
                         socketley::ascii::iequals(ty.substr(slash + 1), q.subtype)))
                        return true;
                }
                return false;
            };
            collect(root, want, parts, t.line);
            values.assign(parts.begin(), parts.end());
        }
        if (!ok())
            return false;
        return compare(values, keys, t.m, t.line);
    }

    bool date_test(const test_node& t)
    {
        xlist keys;
        std::string part_s, zone_s, name_s;
        if (!expand_list(t.keys, keys, t.line))
            return false;
        const std::string_view part = expand(t.part, part_s, t.line);
        int zone = c.zone_min;
        if (t.zone_set && !parse_zone(expand(t.zone, zone_s, t.line), zone))
            return false;
        if (!ok())
            return false;
        int64_t when = c.now_s;
        if (t.k == tk::date)
        {
            const std::string_view name = expand(t.a.front(), name_s, t.line);
            if (!ok())
                return false;
            const size_t idx = first_index(name, t.line);
            int original = 0;
            if (idx == headers.size() || !parse_date(header_text(idx), when, original))
                return false;
            if (t.original_zone)
                zone = original;
        }
        std::string value;
        std::vector<std::string_view> values;
        if (date_part(when, zone, part, value))
            values.push_back(value);
        return compare(values, keys, t.m, t.line);
    }

    // ── flags ──

    static void add_flags(std::vector<std::string>& set, std::string_view list)
    {
        size_t total = 0;
        for (const auto& f : set)
            total += f.size() + 1;
        while (!list.empty())
        {
            list = trim(list);
            size_t n = 0;
            while (n < list.size() && !is_wsp(list[n]))
                ++n;
            const std::string_view f = list.substr(0, n);
            list.remove_prefix(n);
            if (f.empty() || total + f.size() + 1 > max_var_len)
                continue;
            if (std::none_of(set.begin(), set.end(),
                             [f](const std::string& g) { return socketley::ascii::iequals(f, g); }))
            {
                set.emplace_back(f);
                total += f.size() + 1;
            }
        }
    }

    static void remove_flags(std::vector<std::string>& set, std::string_view list)
    {
        std::vector<std::string> gone;
        add_flags(gone, list);
        std::erase_if(set, [&](const std::string& f) {
            return std::any_of(gone.begin(), gone.end(),
                               [&](const std::string& g) { return socketley::ascii::iequals(f, g); });
        });
    }

    static std::string joined(const std::vector<std::string>& set)
    {
        std::string out;
        for (const auto& f : set)
            out += (out.empty() ? "" : " ") + f;
        return out;
    }

    bool flags_of(const cmd_node& k, std::vector<std::string>& out)
    {
        if (!k.has_flags)
        {
            out = flags;
            return true;
        }
        xlist l;
        if (!expand_list(k.list, l, k.line))
            return false;
        out.clear();
        for (const auto f : l.v)
            add_flags(out, f);
        return true;
    }

    // ── commands ──

    bool may_deliver(int line)
    {
        if (rejected)
            return fail(line, "reject cannot be used with keep, fileinto, redirect or vacation");
        return true;
    }

    void block(const std::vector<cmd_node>& cmds)
    {
        for (const auto& k : cmds)
        {
            if (stopped || !ok())
                return;
            command(k);
        }
    }

    void command(const cmd_node& k)
    {
        if (!step(k.line))
            return;
        std::string s1;
        switch (k.k)
        {
            case ck::if_:
                for (size_t i = 0; i < k.blocks.size(); ++i)
                {
                    if (i < k.conds.size())
                    {
                        const bool hit = test(k.conds[i]);
                        if (!ok())
                            return;
                        if (!hit)
                            continue;
                    }
                    block(k.blocks[i]);
                    return;
                }
                return;
            case ck::stop: stopped = true; return;
            case ck::keep:
            case ck::fileinto:
            {
                if (!may_deliver(k.line))
                    return;
                std::vector<std::string> f;
                if (!flags_of(k, f))
                    return;
                std::string folder;
                if (k.k == ck::fileinto)
                {
                    folder = std::string(expand(k.a, s1, k.line));
                    if (!ok())
                        return;
                    if (folder.empty())
                    {
                        fail(k.line, "fileinto names no mailbox");
                        return;
                    }
                }
                delivered = true;
                const action::kind kind = k.k == ck::keep ? action::kind::keep : action::kind::fileinto;
                if (!k.copy)
                    implicit_keep = false;
                for (auto& a : actions)
                    if (a.k == kind && a.arg == folder)
                    {
                        for (const auto& g : f)
                            add_flags(a.flags, g);
                        a.copy = a.copy && k.copy;
                        a.create = a.create || k.create;
                        return;
                    }
                action a;
                a.k = kind;
                a.arg = std::move(folder);
                a.copy = k.copy;
                a.create = k.create;
                a.flags = std::move(f);
                actions.push_back(std::move(a));
                return;
            }
            case ck::redirect:
            {
                if (!may_deliver(k.line))
                    return;
                const std::string_view to = expand(k.a, s1, k.line);
                if (!ok())
                    return;
                address addr;
                if (!parse_mailbox(to, addr) || addr.domain.empty())
                {
                    fail(k.line, "redirect to \"" + std::string(to) + "\", which is no address");
                    return;
                }
                delivered = true;
                if (!k.copy)
                    implicit_keep = false;
                const std::string text = addr.text();
                for (auto& a : actions)
                    if (a.k == action::kind::redirect && socketley::ascii::iequals(a.arg, text))
                    {
                        a.copy = a.copy && k.copy;
                        return;
                    }
                if (redirects >= max_redirects)
                {
                    fail(k.line, "more than 4 redirects");
                    return;
                }
                ++redirects;
                action a;
                a.k = action::kind::redirect;
                a.arg = text;
                a.copy = k.copy;
                actions.push_back(std::move(a));
                return;
            }
            case ck::discard:
                implicit_keep = false;
                if (!discarded)
                {
                    discarded = true;
                    action a;
                    a.k = action::kind::discard;
                    actions.push_back(std::move(a));
                }
                return;
            case ck::reject:
            case ck::ereject:
            {
                if (rejected)
                {
                    fail(k.line, "a second reject");
                    return;
                }
                if (delivered || vacationed)
                {
                    fail(k.line, "reject cannot be used with keep, fileinto, redirect or vacation");
                    return;
                }
                const std::string_view reason = expand(k.a, s1, k.line);
                if (!ok())
                    return;
                rejected = true;
                implicit_keep = false;
                action a;
                a.k = action::kind::reject;
                a.arg = std::string(reason);
                a.ereject = k.k == ck::ereject;
                actions.push_back(std::move(a));
                return;
            }
            case ck::vacation: vacation_command(k); return;
            case ck::set:
            {
                std::string v(expand(k.b, s1, k.line));
                if (!ok())
                    return;
                if (k.mods & (m_lower | m_upper))
                    for (char& ch : v)
                        ch = k.mods & m_lower ? socketley::ascii::lower(ch) : socketley::ascii::upper(ch);
                if ((k.mods & (m_lowerfirst | m_upperfirst)) && !v.empty())
                    v[0] = k.mods & m_lowerfirst ? socketley::ascii::lower(v[0]) : socketley::ascii::upper(v[0]);
                if (k.mods & m_quotewildcard)
                {
                    std::string q;
                    for (const char ch : v)
                    {
                        if (ch == '*' || ch == '?' || ch == '\\')
                            q += '\\';
                        q += ch;
                    }
                    v = std::move(q);
                }
                if (k.mods & m_length)
                    v = std::to_string(std::count_if(v.begin(), v.end(), [](char ch) {
                        return (static_cast<unsigned char>(ch) & 0xC0) != 0x80;
                    }));
                set_variable(k.a.s, std::move(v), k.line);
                return;
            }
            case ck::setflag:
            case ck::addflag:
            case ck::removeflag:
            {
                xlist l;
                if (!expand_list(k.list, l, k.line))
                    return;
                std::vector<std::string> target;
                if (k.has_var)
                {
                    if (const std::string* v = variable(k.a.s))
                        add_flags(target, *v);
                }
                else
                    target = flags;
                if (k.k == ck::setflag)
                    target.clear();
                for (const auto f : l.v)
                {
                    if (k.k == ck::removeflag)
                        remove_flags(target, f);
                    else
                        add_flags(target, f);
                }
                if (k.has_var)
                    set_variable(k.a.s, joined(target), k.line);
                else
                    flags = std::move(target);
                return;
            }
        }
    }

    bool own_address(std::string_view a, const std::vector<std::string>& extra) const
    {
        const auto same = [a](std::string_view b) { return !b.empty() && socketley::ascii::iequals(a, b); };
        return same(m.envelope_to) || std::any_of(c.own.begin(), c.own.end(), same) ||
               std::any_of(extra.begin(), extra.end(), same);
    }

    // Whether RFC 5230 lets this message be answered at all.
    bool answerable(const std::vector<std::string>& extra, int line)
    {
        const std::string_view from = m.envelope_from;
        if (from.empty())
            return false;
        const std::string local = lower(from.substr(0, from.rfind('@')));
        if (local == "mailer-daemon" || local == "listserv" || local == "majordomo" || local.starts_with("owner-") ||
            local.ends_with("-request") || local.ends_with("-owner"))
            return false;
        if (own_address(from, extra))
            return false;
        const std::string submitted = first_header("Auto-Submitted", line);
        if (has_header("Auto-Submitted", line) &&
            lower(trim(submitted.substr(0, submitted.find_first_of(";(")))) != "no")
            return false;
        if (has_header("List-Id", line) || has_header("List-Unsubscribe", line))
            return false;
        const std::string precedence = lower(first_header("Precedence", line));
        if (precedence == "bulk" || precedence == "list" || precedence == "junk")
            return false;
        static constexpr std::string_view recipients[] = {"To",        "Cc",        "Bcc",
                                                          "Resent-To", "Resent-Cc", "Resent-Bcc"};
        std::vector<parsed_address> list;
        for (const auto name : recipients)
            addresses_of(name, list, line);
        for (const auto& a : list)
            if (a.at && own_address(a.local + "@" + a.domain, extra))
                return true;
        return false;
    }

    void vacation_command(const cmd_node& k)
    {
        if (rejected)
        {
            fail(k.line, "reject cannot be used with keep, fileinto, redirect or vacation");
            return;
        }
        if (vacationed)
        {
            fail(k.line, "a second vacation");
            return;
        }
        vacationed = true;
        struct vacation v;
        std::string s;
        v.reason = std::string(expand(k.a, s, k.line));
        if (k.has_subject)
            v.subject = std::string(expand(k.subject, s, k.line));
        if (k.has_from)
            v.from = std::string(expand(k.from, s, k.line));
        if (k.has_handle)
            v.handle = std::string(expand(k.handle, s, k.line));
        xlist addrs;
        if (!ok() || !expand_list(k.list, addrs, k.line))
            return;
        for (const auto a : addrs.v)
        {
            address parsed;
            v.addresses.push_back(parse_mailbox(a, parsed) ? parsed.text() : std::string(a));
        }
        if (!answerable(v.addresses, k.line) || !ok())
            return;
        v.mime = k.mime;
        v.seconds = static_cast<uint32_t>(k.seconds);
        v.to = std::string(m.envelope_from);
        // An empty :handle names no handle, so the caller's memory is never keyed on nothing.
        if (v.handle.empty())
            v.handle = fnv_hex(v.subject + '\0' + v.from + '\0' + v.reason + '\0' + (v.mime ? '1' : '0'));
        if (!k.has_subject)
        {
            const std::string original = first_header("Subject", k.line);
            v.subject = original.empty() ? "Automated reply" : "Auto: " + original;
        }
        action a;
        a.k = action::kind::vacation;
        a.arg = v.reason;
        a.v = std::move(v);
        actions.push_back(std::move(a));
    }
};

}   // namespace

script::script() : p_(std::make_unique<program>()) {}
script::~script() = default;

std::shared_ptr<const script> script::compile(std::string_view text, std::string& err)
{
    err.clear();
    if (text.size() > max_script)
    {
        err = "line 1: the script is larger than 64 KiB";
        return nullptr;
    }
    try
    {
        std::vector<token> toks;
        if (!lex(text, toks, err))
            return nullptr;
        std::shared_ptr<script> s(new script());
        parser ps{toks, err};
        if (!ps.parse_commands(s->p_->top, 0, true))
            return nullptr;
        if (ps.peek().t != tok::end)
        {
            ps.fail(ps.peek().line, "a } that closes no block");
            return nullptr;
        }
        if (!ps.check_conflicts(s->p_->top))
            return nullptr;
        s->p_->caps = ps.caps;
        return s;
    }
    catch (const std::exception&)
    {
        err = "line 1: out of memory compiling the script";
        return nullptr;
    }
}

outcome script::run(const message& m, const context& c) const
{
    outcome out;
    try
    {
        runner r(*p_, m, c);
        r.block(p_->top);
        if (r.ok())
        {
            out.actions = std::move(r.actions);
            if (r.implicit_keep)
            {
                action a;
                a.k = action::kind::keep;
                a.flags = std::move(r.flags);
                out.actions.push_back(std::move(a));
            }
            return out;
        }
        out.error = std::move(r.error);
    }
    catch (const std::exception&)
    {
        out.error = "line 1: out of memory running the script";
    }
    out.actions.clear();
    out.actions.emplace_back();
    return out;
}

std::string_view extensions()
{
    return "fileinto reject ereject envelope encoded-character imap4flags copy vacation vacation-seconds subaddress "
           "body relational comparator-i;ascii-numeric variables date mailbox";
}

}   // namespace socketley::mail::sieve
