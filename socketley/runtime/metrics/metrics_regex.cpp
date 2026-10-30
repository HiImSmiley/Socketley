#include "metrics_regex.h"

#include <algorithm>

namespace socketley::metrics
{

namespace
{

constexpr uint32_t max_rune   = 0x10FFFF;
constexpr uint32_t bad_rune   = 0xFFFD;
constexpr int      max_repeat = 1000;
constexpr size_t   max_prog   = 20000;
constexpr int      max_depth  = 500;

enum op : uint8_t { op_rune = 1, op_class, op_any, op_any_nonl, op_split, op_jmp, op_save, op_assert, op_match };
enum assert_kind : uint32_t { at_bot, at_eot, at_bol, at_eol, at_word, at_nonword };

using ranges = std::vector<std::pair<uint32_t, uint32_t>>;

// The rune at s[i] and its width; a byte that starts no valid UTF-8 sequence is U+FFFD of width 1, as in Go.
uint32_t decode(std::string_view s, size_t i, size_t& w)
{
    const auto b0 = static_cast<unsigned char>(s[i]);
    w = 1;
    if (b0 < 0x80)
        return b0;
    int len = 0;
    uint32_t r = 0, lo = 0;
    if ((b0 & 0xE0) == 0xC0) { len = 2; r = b0 & 0x1F; lo = 0x80; }
    else if ((b0 & 0xF0) == 0xE0) { len = 3; r = b0 & 0x0F; lo = 0x800; }
    else if ((b0 & 0xF8) == 0xF0) { len = 4; r = b0 & 0x07; lo = 0x10000; }
    else return bad_rune;
    if (i + static_cast<size_t>(len) > s.size())
        return bad_rune;
    for (int k = 1; k < len; ++k)
    {
        const auto b = static_cast<unsigned char>(s[i + static_cast<size_t>(k)]);
        if ((b & 0xC0) != 0x80)
            return bad_rune;
        r = (r << 6) | (b & 0x3F);
    }
    if (r < lo || r > max_rune || (r >= 0xD800 && r <= 0xDFFF))
        return bad_rune;
    w = static_cast<size_t>(len);
    return r;
}

void encode(std::string& out, uint32_t r)
{
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

bool is_word(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool is_letter(uint32_t r) { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'); }

void normalize(ranges& rs)
{
    std::sort(rs.begin(), rs.end());
    size_t o = 0;
    for (size_t i = 0; i < rs.size(); ++i)
    {
        if (o && rs[i].first <= rs[o - 1].second + 1)
            rs[o - 1].second = std::max(rs[o - 1].second, rs[i].second);
        else
            rs[o++] = rs[i];
    }
    rs.resize(o);
}

void negate(ranges& rs)
{
    normalize(rs);
    ranges out;
    uint32_t next = 0;
    for (auto [lo, hi] : rs)
    {
        if (lo > next)
            out.emplace_back(next, lo - 1);
        next = hi + 1;
    }
    if (next <= max_rune)
        out.emplace_back(next, max_rune);
    rs.swap(out);
}

// ASCII case folding, which is all a label value's patterns need of RE2's Unicode folding.
void add_folds(ranges& rs)
{
    const size_t n = rs.size();
    for (size_t i = 0; i < n; ++i)
    {
        const auto [lo, hi] = rs[i];
        const uint32_t a = std::max<uint32_t>(lo, 'a'), b = std::min<uint32_t>(hi, 'z');
        if (a <= b)
            rs.emplace_back(a - 32, b - 32);
        const uint32_t c = std::max<uint32_t>(lo, 'A'), d = std::min<uint32_t>(hi, 'Z');
        if (c <= d)
            rs.emplace_back(c + 32, d + 32);
    }
}

bool in_ranges(const ranges& rs, uint32_t r)
{
    size_t lo = 0, hi = rs.size();
    while (lo < hi)
    {
        const size_t mid = (lo + hi) / 2;
        if (rs[mid].second < r)
            lo = mid + 1;
        else if (rs[mid].first > r)
            hi = mid;
        else
            return true;
    }
    return false;
}

struct rnode
{
    enum kind_t : uint8_t { empty, lit, cls, any, cat, alt, rep, cap, assertion };
    kind_t   kind{empty};
    uint32_t rune{0};
    bool     fold{false};
    bool     nl{true};
    int      min{0}, max{-1};
    bool     greedy{true};
    uint32_t idx{0};    // a class's, a group's or an assertion's number
    std::vector<uint32_t> kids;
};

struct reflags
{
    bool i{false}, m{false}, s{true}, U{false};
};

class rparser
{
public:
    rparser(std::string_view p, std::vector<rnode>& nodes, std::vector<ranges>& classes,
            std::vector<std::string>& names)
        : m_p(p), m_nodes(nodes), m_classes(classes), m_names(names)
    {
    }

    bool parse(uint32_t& root, std::string& why)
    {
        root = alternation(0);
        if (m_err.empty() && m_pos < m_p.size())
            fail("unexpected )");
        if (!m_err.empty())
        {
            why = "error parsing regexp: " + m_err + ": `" + std::string(m_p) + "`";
            return false;
        }
        return true;
    }

private:
    uint32_t add(rnode n)
    {
        m_nodes.push_back(std::move(n));
        return static_cast<uint32_t>(m_nodes.size() - 1);
    }
    uint32_t fail(const char* what)
    {
        if (m_err.empty())
            m_err = what;
        m_pos = m_p.size();
        return add({});
    }
    bool eof() const { return m_pos >= m_p.size(); }
    char peek() const { return m_p[m_pos]; }

    uint32_t alternation(int depth)
    {
        if (depth > max_depth)
            return fail("expression nests too deeply");
        std::vector<uint32_t> kids{concatenation(depth)};
        while (!eof() && peek() == '|')
        {
            ++m_pos;
            kids.push_back(concatenation(depth));
        }
        if (kids.size() == 1)
            return kids[0];
        rnode n;
        n.kind = rnode::alt;
        n.kids = std::move(kids);
        return add(std::move(n));
    }

    uint32_t concatenation(int depth)
    {
        rnode n;
        n.kind = rnode::cat;
        while (!eof() && peek() != '|' && peek() != ')')
            n.kids.push_back(repetition(depth));
        if (n.kids.size() == 1)
            return n.kids[0];
        if (n.kids.empty())
            return add({});
        return add(std::move(n));
    }

    // `{n}`, `{n,}` or `{n,m}` at m_pos, read into min and max without moving when it is not one.
    bool braces(size_t& end, int& min, int& max) const
    {
        size_t i = m_pos + 1;
        auto number = [&](int& out) {
            const size_t from = i;
            long v = 0;
            while (i < m_p.size() && m_p[i] >= '0' && m_p[i] <= '9')
            {
                v = std::min<long>(v * 10 + (m_p[i] - '0'), 100000);
                ++i;
            }
            out = static_cast<int>(v);
            return i > from;
        };
        if (!number(min))
            return false;
        max = min;
        if (i < m_p.size() && m_p[i] == ',')
        {
            ++i;
            if (i < m_p.size() && m_p[i] == '}')
                max = -1;
            else if (!number(max))
                return false;
        }
        if (i >= m_p.size() || m_p[i] != '}')
            return false;
        end = i + 1;
        return true;
    }

    uint32_t repetition(int depth)
    {
        bool repeatable = true;
        uint32_t a = atom(depth, repeatable);
        bool repeated = false;
        while (!eof())
        {
            int min = 0, max = -1;
            const char c = peek();
            if (c == '*')
                ++m_pos;
            else if (c == '+')
            {
                min = 1;
                ++m_pos;
            }
            else if (c == '?')
            {
                max = 1;
                ++m_pos;
            }
            else if (c == '{')
            {
                size_t end = 0;
                if (!braces(end, min, max))
                    break;
                if (min > max_repeat || max > max_repeat || (max >= 0 && max < min))
                    return fail("invalid repeat count");
                m_pos = end;
            }
            else
                break;
            if (repeated)
                return fail("invalid nested repetition operator");
            if (!repeatable)
                return fail("missing argument to repetition operator");
            bool greedy = true;
            if (!eof() && peek() == '?')
            {
                greedy = false;
                ++m_pos;
            }
            if (m_flags.U)
                greedy = !greedy;
            rnode n;
            n.kind = rnode::rep;
            n.min = min;
            n.max = max;
            n.greedy = greedy;
            n.kids = {a};
            a = add(std::move(n));
            repeated = true;
        }
        return a;
    }

    uint32_t literal(uint32_t r)
    {
        rnode n;
        n.kind = rnode::lit;
        n.rune = r;
        n.fold = m_flags.i && is_letter(r);
        return add(n);
    }

    uint32_t klass(ranges rs)
    {
        if (m_flags.i)
            add_folds(rs);
        normalize(rs);
        m_classes.push_back(std::move(rs));
        rnode n;
        n.kind = rnode::cls;
        n.idx = static_cast<uint32_t>(m_classes.size() - 1);
        return add(n);
    }

    uint32_t assertion(uint32_t kind)
    {
        rnode n;
        n.kind = rnode::assertion;
        n.idx = kind;
        return add(n);
    }

    uint32_t atom(int depth, bool& repeatable)
    {
        const char c = peek();
        switch (c)
        {
            case '(': return group(depth, repeatable);
            case '[': return bracket();
            case '.':
            {
                ++m_pos;
                rnode n;
                n.kind = rnode::any;
                n.nl = m_flags.s;
                return add(n);
            }
            case '^': ++m_pos; return assertion(m_flags.m ? at_bol : at_bot);
            case '$': ++m_pos; return assertion(m_flags.m ? at_eol : at_eot);
            case '\\': return escape();
            case '*': case '+': case '?': return fail("missing argument to repetition operator");
            case '{':
            {
                size_t end = 0;
                int a = 0, b = 0;
                if (braces(end, a, b))
                    return fail("missing argument to repetition operator");
                ++m_pos;
                return literal('{');
            }
            default:
            {
                size_t w = 0;
                const uint32_t r = decode(m_p, m_pos, w);
                m_pos += w;
                return literal(r);
            }
        }
    }

    uint32_t group(int depth, bool& repeatable)
    {
        ++m_pos;
        std::string name;
        bool capture = true;
        const reflags saved = m_flags;
        if (!eof() && peek() == '?')
        {
            const std::string_view rest = m_p.substr(m_pos);
            if (rest.starts_with("?P<") || rest.starts_with("?<"))
            {
                m_pos += rest[1] == 'P' ? 3 : 2;
                while (!eof() && is_word(static_cast<unsigned char>(peek())))
                    name += m_p[m_pos++];
                if (name.empty() || eof() || peek() != '>')
                    return fail("invalid named capture");
                ++m_pos;
                if (std::find(m_names.begin(), m_names.end(), name) != m_names.end())
                    return fail("duplicate capture group name");
            }
            else
            {
                ++m_pos;
                bool neg = false, any = false;
                reflags f = m_flags;
                while (true)
                {
                    if (eof())
                        return fail("missing closing )");
                    const char c = m_p[m_pos++];
                    if (c == 'i') f.i = !neg;
                    else if (c == 'm') f.m = !neg;
                    else if (c == 's') f.s = !neg;
                    else if (c == 'U') f.U = !neg;
                    else if (c == '-' && !neg) { neg = true; any = false; continue; }
                    else if ((c == ')' || c == ':') && (any || !neg))
                    {
                        if (c == ')')
                        {
                            // A flag group sets the flags for the rest of the group it stands in.
                            m_flags = f;
                            repeatable = false;
                            return add({});
                        }
                        m_flags = f;
                        capture = false;
                        break;
                    }
                    else
                        return fail("invalid or unsupported Perl syntax");
                    any = true;
                }
            }
        }
        uint32_t index = 0;
        if (capture)
        {
            index = static_cast<uint32_t>(m_names.size());
            m_names.push_back(name);
        }
        const uint32_t inner = alternation(depth + 1);
        m_flags = saved;
        if (eof() || peek() != ')')
            return fail("missing closing )");
        ++m_pos;
        if (!capture)
            return inner;
        rnode n;
        n.kind = rnode::cap;
        n.idx = index;
        n.kids = {inner};
        return add(std::move(n));
    }

    static bool perl_class(char c, ranges& rs)
    {
        ranges r;
        switch (c | 0x20)
        {
            case 'd': r = {{'0', '9'}}; break;
            case 's': r = {{'\t', '\n'}, {'\f', '\r'}, {' ', ' '}}; break;
            case 'w': r = {{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}}; break;
            default: return false;
        }
        if (c >= 'A' && c <= 'Z')
            negate(r);
        rs.insert(rs.end(), r.begin(), r.end());
        return true;
    }

    static int hexval(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // One rune an escape at m_pos (past its backslash) stands for, or false when it stands for none.
    bool escaped_rune(uint32_t& r)
    {
        if (eof())
        {
            fail("trailing backslash at end of expression");
            return false;
        }
        const char c = m_p[m_pos++];
        switch (c)
        {
            case 'a': r = 7; return true;
            case 'f': r = 12; return true;
            case 't': r = 9; return true;
            case 'n': r = 10; return true;
            case 'r': r = 13; return true;
            case 'v': r = 11; return true;
            case 'x':
            {
                if (!eof() && peek() == '{')
                {
                    ++m_pos;
                    uint64_t v = 0;
                    size_t digits = 0;
                    while (!eof() && hexval(peek()) >= 0)
                    {
                        v = std::min<uint64_t>(v * 16 + static_cast<uint64_t>(hexval(m_p[m_pos++])), max_rune + 1ull);
                        ++digits;
                    }
                    if (!digits || eof() || peek() != '}' || v > max_rune)
                        break;
                    ++m_pos;
                    r = static_cast<uint32_t>(v);
                    return true;
                }
                if (m_pos + 2 > m_p.size() || hexval(m_p[m_pos]) < 0 || hexval(m_p[m_pos + 1]) < 0)
                    break;
                r = static_cast<uint32_t>(hexval(m_p[m_pos]) * 16 + hexval(m_p[m_pos + 1]));
                m_pos += 2;
                return true;
            }
            case '1': case '2': case '3': case '4': case '5': case '6': case '7':
                // A single non-zero digit would be a backreference, which RE2 has not.
                if (eof() || peek() < '0' || peek() > '7')
                    break;
                [[fallthrough]];
            case '0':
            {
                uint32_t v = static_cast<uint32_t>(c - '0');
                for (int k = 0; k < 2 && !eof() && peek() >= '0' && peek() <= '7'; ++k)
                    v = v * 8 + static_cast<uint32_t>(m_p[m_pos++] - '0');
                r = v;
                return true;
            }
            default:
                if (static_cast<unsigned char>(c) < 0x80 && !is_word(static_cast<unsigned char>(c)))
                {
                    r = static_cast<unsigned char>(c);
                    return true;
                }
        }
        fail("invalid escape sequence");
        return false;
    }

    uint32_t escape()
    {
        ++m_pos;
        if (eof())
            return fail("trailing backslash at end of expression");
        const char c = peek();
        switch (c)
        {
            case 'A': ++m_pos; return assertion(at_bot);
            case 'z': ++m_pos; return assertion(at_eot);
            case 'b': ++m_pos; return assertion(at_word);
            case 'B': ++m_pos; return assertion(at_nonword);
            case 'p': case 'P': return fail("invalid character class range");
            case 'Q':
            {
                ++m_pos;
                rnode n;
                n.kind = rnode::cat;
                while (!eof() && !m_p.substr(m_pos).starts_with("\\E"))
                {
                    size_t w = 0;
                    const uint32_t r = decode(m_p, m_pos, w);
                    m_pos += w;
                    n.kids.push_back(literal(r));
                }
                if (!eof())
                    m_pos += 2;
                return add(std::move(n));
            }
            default: break;
        }
        ranges rs;
        if (perl_class(c, rs))
        {
            ++m_pos;
            return klass(std::move(rs));
        }
        uint32_t r = 0;
        if (!escaped_rune(r))
            return add({});
        return literal(r);
    }

    bool class_rune(uint32_t& r)
    {
        if (peek() == '\\')
        {
            ++m_pos;
            return escaped_rune(r);
        }
        size_t w = 0;
        r = decode(m_p, m_pos, w);
        m_pos += w;
        return true;
    }

    uint32_t bracket()
    {
        static constexpr struct { std::string_view name; std::pair<uint32_t, uint32_t> r[4]; } posix[] = {
            {"alnum", {{'0', '9'}, {'A', 'Z'}, {'a', 'z'}}},
            {"alpha", {{'A', 'Z'}, {'a', 'z'}}},
            {"ascii", {{0, 0x7F}}},
            {"blank", {{'\t', '\t'}, {' ', ' '}}},
            {"cntrl", {{0, 0x1F}, {0x7F, 0x7F}}},
            {"digit", {{'0', '9'}}},
            {"graph", {{'!', '~'}}},
            {"lower", {{'a', 'z'}}},
            {"print", {{' ', '~'}}},
            {"punct", {{'!', '/'}, {':', '@'}, {'[', '`'}, {'{', '~'}}},
            {"space", {{'\t', '\r'}, {' ', ' '}}},
            {"upper", {{'A', 'Z'}}},
            {"word", {{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}}},
            {"xdigit", {{'0', '9'}, {'A', 'F'}, {'a', 'f'}}},
        };
        ++m_pos;
        bool neg = false;
        if (!eof() && peek() == '^')
        {
            neg = true;
            ++m_pos;
        }
        ranges rs;
        bool first = true;
        while (true)
        {
            if (eof())
                return fail("missing closing ]");
            const char c = peek();
            if (c == ']' && !first)
            {
                ++m_pos;
                break;
            }
            first = false;
            const std::string_view rest = m_p.substr(m_pos);
            if (rest.starts_with("[:"))
            {
                const size_t end = rest.find(":]", 2);
                if (end != std::string_view::npos)
                {
                    std::string_view name = rest.substr(2, end - 2);
                    const bool pneg = name.starts_with('^');
                    if (pneg)
                        name.remove_prefix(1);
                    ranges pr;
                    for (const auto& p : posix)
                        if (p.name == name)
                            for (const auto& r : p.r)
                                if (r.second)
                                    pr.push_back(r);
                    if (pr.empty())
                        return fail("invalid character class range");
                    if (pneg)
                        negate(pr);
                    rs.insert(rs.end(), pr.begin(), pr.end());
                    m_pos += end + 2;
                    continue;
                }
            }
            if (c == '\\' && m_pos + 1 < m_p.size() && perl_class(m_p[m_pos + 1], rs))
            {
                m_pos += 2;
                continue;
            }
            uint32_t lo = 0, hi = 0;
            if (!class_rune(lo))
                return add({});
            hi = lo;
            if (m_pos + 1 < m_p.size() && peek() == '-' && m_p[m_pos + 1] != ']')
            {
                ++m_pos;
                if (!class_rune(hi))
                    return add({});
                if (hi < lo)
                    return fail("invalid character class range");
            }
            rs.emplace_back(lo, hi);
        }
        if (m_flags.i)
            add_folds(rs);
        if (neg)
            negate(rs);
        normalize(rs);
        m_classes.push_back(std::move(rs));
        rnode n;
        n.kind = rnode::cls;
        n.idx = static_cast<uint32_t>(m_classes.size() - 1);
        return add(n);
    }

    std::string_view m_p;
    size_t m_pos{0};
    std::vector<rnode>& m_nodes;
    std::vector<ranges>& m_classes;
    std::vector<std::string>& m_names;
    reflags m_flags;
    std::string m_err;
};

class rcompiler
{
public:
    rcompiler(const std::vector<rnode>& nodes, std::vector<ranges>& classes, std::vector<regex::inst>& prog)
        : m_nodes(nodes), m_classes(classes), m_prog(prog)
    {
    }

    bool compile(uint32_t root)
    {
        emit(op_save, 0);
        node(root, 0);
        emit(op_save, 1);
        emit(op_match);
        return !m_big;
    }

private:
    uint32_t emit(uint8_t o, uint32_t x = 0, uint32_t y = 0)
    {
        if (m_prog.size() >= max_prog)
        {
            m_big = true;
            return static_cast<uint32_t>(m_prog.size() - 1);
        }
        m_prog.push_back({o, x, y});
        return static_cast<uint32_t>(m_prog.size() - 1);
    }
    uint32_t here() const { return static_cast<uint32_t>(m_prog.size()); }

    void node(uint32_t i, int depth)
    {
        if (m_big || depth > max_depth * 2)
        {
            m_big = true;
            return;
        }
        const rnode& n = m_nodes[i];
        switch (n.kind)
        {
            case rnode::empty: break;
            case rnode::lit:
                if (n.fold)
                {
                    const uint32_t lower = n.rune | 0x20;
                    m_classes.push_back({{lower - 32, lower - 32}, {lower, lower}});
                    emit(op_class, static_cast<uint32_t>(m_classes.size() - 1));
                }
                else
                    emit(op_rune, n.rune);
                break;
            case rnode::cls: emit(op_class, n.idx); break;
            case rnode::any: emit(n.nl ? op_any : op_any_nonl); break;
            case rnode::assertion: emit(op_assert, n.idx); break;
            case rnode::cat:
                for (uint32_t k : n.kids)
                    node(k, depth + 1);
                break;
            case rnode::alt:
            {
                std::vector<uint32_t> jumps;
                for (size_t k = 0; k + 1 < n.kids.size() && !m_big; ++k)
                {
                    const uint32_t s = emit(op_split);
                    node(n.kids[k], depth + 1);
                    jumps.push_back(emit(op_jmp));
                    if (m_big)
                        return;
                    m_prog[s].x = s + 1;
                    m_prog[s].y = here();
                }
                node(n.kids.back(), depth + 1);
                if (m_big)
                    return;
                for (uint32_t j : jumps)
                    m_prog[j].x = here();
                break;
            }
            case rnode::cap:
                emit(op_save, 2 * n.idx);
                node(n.kids[0], depth + 1);
                emit(op_save, 2 * n.idx + 1);
                break;
            case rnode::rep:
            {
                for (int k = 0; k < n.min && !m_big; ++k)
                    node(n.kids[0], depth + 1);
                if (n.max < 0)
                {
                    const uint32_t s = emit(op_split);
                    node(n.kids[0], depth + 1);
                    emit(op_jmp, s);
                    if (m_big)
                        return;
                    m_prog[s].x = n.greedy ? s + 1 : here();
                    m_prog[s].y = n.greedy ? here() : s + 1;
                    break;
                }
                std::vector<uint32_t> splits;
                for (int k = n.min; k < n.max && !m_big; ++k)
                {
                    splits.push_back(emit(op_split));
                    node(n.kids[0], depth + 1);
                }
                if (m_big)
                    return;
                for (uint32_t s : splits)
                {
                    m_prog[s].x = n.greedy ? s + 1 : here();
                    m_prog[s].y = n.greedy ? here() : s + 1;
                }
                break;
            }
        }
    }

    const std::vector<rnode>& m_nodes;
    std::vector<ranges>& m_classes;
    std::vector<regex::inst>& m_prog;
    bool m_big{false};
};

// The bytes a node matches when it matches exactly one string, appended to `out`.
bool literal_of(const std::vector<rnode>& nodes, uint32_t i, std::string& out)
{
    const rnode& n = nodes[i];
    if (n.kind == rnode::empty)
        return true;
    if (n.kind == rnode::lit && !n.fold)
    {
        encode(out, n.rune);
        return true;
    }
    if (n.kind != rnode::cat)
        return false;
    for (uint32_t k : n.kids)
        if (!literal_of(nodes, k, out))
            return false;
    return true;
}

bool is_any_star(const std::vector<rnode>& nodes, uint32_t i, int min)
{
    const rnode& n = nodes[i];
    return n.kind == rnode::rep && n.min == min && n.max < 0 && nodes[n.kids[0]].kind == rnode::any &&
           nodes[n.kids[0]].nl;
}

}   // namespace

bool regex::compile(std::string_view pattern, std::string& why)
{
    *this = regex{};
    std::vector<rnode> nodes;
    m_names.push_back({});
    uint32_t root = 0;
    rparser p(pattern, nodes, m_classes, m_names);
    if (!p.parse(root, why))
        return false;
    m_groups = static_cast<int>(m_names.size());
    rcompiler c(nodes, m_classes, m_prog);
    if (!c.compile(root))
    {
        why = "error parsing regexp: expression too large: `" + std::string(pattern) + "`";
        return false;
    }

    // The shapes Grafana's variables produce answer without the machine: a literal, `.*`, `.+`, a prefix or a set.
    if (m_groups == 1)
    {
        const rnode& r = nodes[root];
        std::string lit;
        if (literal_of(nodes, root, lit))
        {
            m_shape = shape::literal;
            m_lit = std::move(lit);
        }
        else if (is_any_star(nodes, root, 0))
            m_shape = shape::anything;
        else if (is_any_star(nodes, root, 1))
            m_shape = shape::nonempty;
        else if (r.kind == rnode::cat && r.kids.size() >= 2)
        {
            lit.clear();
            const bool head = is_any_star(nodes, r.kids.front(), 0);
            const bool tail = is_any_star(nodes, r.kids.back(), 0);
            const size_t from = head ? 1 : 0, to = r.kids.size() - (tail ? 1 : 0);
            bool ok = (head || tail) && from < to;
            for (size_t k = from; ok && k < to; ++k)
                ok = literal_of(nodes, r.kids[k], lit);
            if (ok)
            {
                m_shape = head && tail ? shape::contains : head ? shape::suffix : shape::prefix;
                m_lit = std::move(lit);
            }
        }
        else if (r.kind == rnode::alt && r.kids.size() <= 64)
        {
            std::vector<std::string> lits;
            for (uint32_t k : r.kids)
            {
                lits.emplace_back();
                if (!literal_of(nodes, k, lits.back()))
                {
                    lits.clear();
                    break;
                }
            }
            if (!lits.empty())
            {
                m_shape = shape::literals;
                m_lits = std::move(lits);
            }
        }
    }
    m_matches_empty = matches(std::string_view{});
    return true;
}

int regex::group_named(std::string_view name) const
{
    for (size_t i = 1; i < m_names.size(); ++i)
        if (m_names[i] == name)
            return static_cast<int>(i);
    return -1;
}

bool regex::fast(std::string_view s) const
{
    switch (m_shape)
    {
        case shape::literal: return s == m_lit;
        case shape::anything: return true;
        case shape::nonempty: return !s.empty();
        case shape::prefix: return s.starts_with(m_lit);
        case shape::suffix: return s.ends_with(m_lit);
        case shape::contains: return s.find(m_lit) != std::string_view::npos;
        case shape::literals:
            for (const auto& l : m_lits)
                if (s == l)
                    return true;
            return false;
        case shape::program: break;
    }
    return false;
}

bool regex::matches(std::string_view s) const
{
    if (m_prog.empty())
        return false;
    if (m_shape != shape::program)
        return fast(s);
    return run(s, nullptr, 0);
}

bool regex::matches(std::string_view s, std::vector<int>& groups) const
{
    groups.assign(static_cast<size_t>(m_groups) * 2, -1);
    if (m_prog.empty())
        return false;
    if (m_shape != shape::program)
    {
        if (!fast(s))
            return false;
        groups[0] = 0;
        groups[1] = static_cast<int>(s.size());
        return true;
    }
    return run(s, groups.data(), static_cast<int>(groups.size()));
}

bool regex::run(std::string_view s, int* out, int ncap) const
{
    const auto np = static_cast<uint32_t>(m_prog.size());
    const auto nc = static_cast<size_t>(ncap);
    for (auto& l : m_lists)
    {
        l.dense.resize(np);
        l.sparse.resize(np);
        l.caps.resize(np * nc);
        l.n = 0;
    }
    m_cur.assign(nc, -1);
    scratch* clist = &m_lists[0];
    scratch* nlist = &m_lists[1];

    auto check = [&](uint32_t kind, size_t pos) {
        const bool before = pos > 0 && is_word(static_cast<unsigned char>(s[pos - 1]));
        const bool after = pos < s.size() && is_word(static_cast<unsigned char>(s[pos]));
        switch (kind)
        {
            case at_bot: return pos == 0;
            case at_eot: return pos == s.size();
            case at_bol: return pos == 0 || s[pos - 1] == '\n';
            case at_eol: return pos == s.size() || s[pos] == '\n';
            case at_word: return before != after;
            default: return before == after;
        }
    };
    // Every thread the instruction `pc0` leads to without reading, in priority order, each with its groups.
    auto follow = [&](scratch* l, uint32_t pc0, size_t pos) {
        constexpr uint64_t restore = 1ull << 63;
        m_stack.clear();
        m_stack.push_back(pc0);
        while (!m_stack.empty())
        {
            const uint64_t e = m_stack.back();
            m_stack.pop_back();
            if (e & restore)
            {
                m_cur[(e >> 32) & 0xFFFF] = static_cast<int>(static_cast<uint32_t>(e));
                continue;
            }
            const auto pc = static_cast<uint32_t>(e);
            const uint32_t d = l->sparse[pc];
            if (d < l->n && l->dense[d] == pc)
                continue;
            l->sparse[pc] = l->n;
            l->dense[l->n] = pc;
            const uint32_t slot = l->n++;
            const inst& in = m_prog[pc];
            switch (in.op)
            {
                case op_jmp: m_stack.push_back(in.x); break;
                case op_split:
                    m_stack.push_back(in.y);
                    m_stack.push_back(in.x);
                    break;
                case op_save:
                    if (in.x < nc)
                    {
                        m_stack.push_back(restore | (static_cast<uint64_t>(in.x) << 32) |
                                          static_cast<uint32_t>(m_cur[in.x]));
                        m_cur[in.x] = static_cast<int>(pos);
                    }
                    m_stack.push_back(pc + 1);
                    break;
                case op_assert:
                    if (check(in.x, pos))
                        m_stack.push_back(pc + 1);
                    break;
                default:
                    if (nc)
                        std::copy(m_cur.begin(), m_cur.end(), l->caps.begin() + static_cast<ptrdiff_t>(slot * nc));
                    break;
            }
        }
    };

    follow(clist, 0, 0);
    size_t pos = 0;
    while (true)
    {
        if (pos == s.size())
        {
            for (uint32_t i = 0; i < clist->n; ++i)
                if (m_prog[clist->dense[i]].op == op_match)
                {
                    if (nc)
                        std::copy_n(clist->caps.begin() + static_cast<ptrdiff_t>(i * nc), nc, out);
                    return true;
                }
            return false;
        }
        if (clist->n == 0)
            return false;
        size_t w = 0;
        const uint32_t r = decode(s, pos, w);
        nlist->n = 0;
        for (uint32_t i = 0; i < clist->n; ++i)
        {
            const uint32_t pc = clist->dense[i];
            const inst& in = m_prog[pc];
            bool ok = false;
            switch (in.op)
            {
                case op_rune: ok = r == in.x; break;
                case op_class: ok = in_ranges(m_classes[in.x], r); break;
                case op_any: ok = true; break;
                case op_any_nonl: ok = r != '\n'; break;
                default: break;
            }
            if (!ok)
                continue;
            if (nc)
                std::copy_n(clist->caps.begin() + static_cast<ptrdiff_t>(i * nc), nc, m_cur.begin());
            follow(nlist, pc + 1, pos + w);
        }
        std::swap(clist, nlist);
        pos += w;
    }
}

}   // namespace socketley::metrics
