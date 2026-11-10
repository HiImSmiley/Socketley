#include "lua_template.h"

#include <algorithm>
#include <cctype>
#include <vector>

namespace socketley::lua_template
{

namespace
{

bool lua_name(std::string_view s)
{
    static constexpr std::string_view keywords[] = {"and",  "break", "do",     "else", "elseif", "end",   "false",
                                                    "for",  "function", "goto", "if",   "in",     "local", "nil",
                                                    "not",  "or",    "repeat", "return", "then",  "true",  "until",
                                                    "while"};
    if (s.empty() || std::isdigit(static_cast<unsigned char>(s[0])))
        return false;
    for (const char ch : s)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_')
            return false;
    return std::find(std::begin(keywords), std::end(keywords), s) == std::end(keywords);
}

// A Lua string literal of `s`, on one line whatever it holds.
std::string literal(std::string_view s)
{
    std::string out = "\"";
    for (const char ch : s)
    {
        const auto u = static_cast<unsigned char>(ch);
        if (ch == '"' || ch == '\\')
            out += {'\\', ch};
        else if (ch == '\n')
            out += "\\n";
        else if (u < 32 || u == 127)
        {
            out += '\\';
            out += static_cast<char>('0' + u / 100);
            out += static_cast<char>('0' + u / 10 % 10);
            out += static_cast<char>('0' + u % 10);
        }
        else
            out += ch;
    }
    return out + "\"";
}

size_t lines_in(std::string_view s)
{
    return static_cast<size_t>(std::count(s.begin(), s.end(), '\n'));
}

std::string_view stripped(std::string_view v)
{
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front())))
        v.remove_prefix(1);
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
        v.remove_suffix(1);
    return v;
}

// Where a placeholder's default begins: its first bar outside a string, since Lua has no operator of that name.
size_t default_bar(std::string_view s)
{
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (quote && s[i] == '\\')
            ++i;
        else if (quote && s[i] == quote)
            quote = 0;
        else if (!quote && (s[i] == '"' || s[i] == '\''))
            quote = s[i];
        else if (!quote && s[i] == '|')
            return i;
    }
    return std::string_view::npos;
}

// A name, its parts after dots, looked up so that one missing anywhere is no value rather than an error; a part
// may hold a hyphen, as a field's name does. Anything else is a Lua expression.
std::string name_lookup(std::string_view e, bool& named)
{
    named = !e.empty() && !std::isdigit(static_cast<unsigned char>(e[0])) &&
            e.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") == std::string_view::npos &&
            e.front() != '.' && e.back() != '.' && e.find("..") == std::string_view::npos;
    if (!named)
        return "(" + std::string(e) + ")";
    std::vector<std::string_view> parts;
    for (std::string_view rest = e; !rest.empty();)
    {
        const size_t dot = rest.find('.');
        parts.push_back(rest.substr(0, dot));
        rest = dot == std::string_view::npos ? std::string_view{} : rest.substr(dot + 1);
    }
    std::string code = lua_name(parts[0]) ? std::string(parts[0]) : "_E[" + literal(parts[0]) + "]";
    if (parts.size() == 1)
        return code;
    code = "_p(" + code;
    for (size_t i = 1; i < parts.size(); ++i)
        code += ", " + literal(parts[i]);
    return code + ")";
}

}   // namespace

bool compile(std::string_view t, std::string_view name, bool keep_unsubscribe, std::string& code, std::string& why)
{
    code = "local _o, _v, _p, _E = ... ";
    std::string text;
    // The code keeps the template's line numbers, a line ahead where a comment had to be ended.
    size_t ahead = 0;
    const auto align = [&](size_t lines) {
        const size_t k = std::min(lines, ahead);
        ahead -= k;
        code.append(lines - k, '\n');
    };
    const auto flush = [&] {
        if (!text.empty())
            code += "_o(" + literal(text) + ") ";
        align(lines_in(text));
        text.clear();
    };
    size_t i = 0;
    while (i < t.size())
    {
        const size_t at = t.find('{', i);
        if (at == std::string_view::npos || at + 1 >= t.size())
        {
            text.append(t.substr(i));
            break;
        }
        text.append(t.substr(i, at - i));
        const char next = t[at + 1];
        if (next == '%')
        {
            const size_t close = t.find("%}", at + 2);
            if (close == std::string_view::npos)
            {
                why = std::string(name) + ":" + std::to_string(1 + lines_in(t.substr(0, at))) + ": {% is never closed by %}";
                return false;
            }
            size_t end = close + 2;
            // A tag alone on its line takes the line with it, so a loop writes no empty lines.
            const size_t nl = t.rfind('\n', at);
            const size_t line_start = nl == std::string_view::npos ? 0 : nl + 1;
            size_t after = end;
            while (after < t.size() && (t[after] == ' ' || t[after] == '\t' || t[after] == '\r'))
                ++after;
            bool ate_line = false;
            if (t.substr(line_start, at - line_start).find_first_not_of(" \t") == std::string_view::npos &&
                (after == t.size() || t[after] == '\n'))
            {
                text.resize(text.size() - (at - line_start));
                ate_line = after < t.size();
                end = after + (ate_line ? 1 : 0);
            }
            flush();
            const std::string_view body = t.substr(at + 2, close - at - 2);
            const bool comment = !ate_line && body.find("--") != std::string_view::npos;
            code += std::string(body) + (ate_line || comment ? "\n" : " ");
            ahead += comment;
            i = end;
            continue;
        }
        if (next != '{')
        {
            text += '{';
            i = at + 1;
            continue;
        }
        const bool raw = at + 2 < t.size() && t[at + 2] == '{';
        const std::string_view closer = raw ? "}}}" : "}}";
        const size_t from = at + (raw ? 3 : 2), close = t.find(closer, from);
        if (close == std::string_view::npos)
        {
            text.append(t.substr(at, from - at));
            i = from;
            continue;
        }
        const size_t end = close + closer.size();
        const std::string_view inner = t.substr(from, close - from);
        const size_t bar = default_bar(inner);
        const std::string_view expr = stripped(inner.substr(0, bar));
        // Braces that hold nothing are text, as in a style sheet's example.
        if (expr.empty())
        {
            text.append(t.substr(at, end - at));
            i = end;
            continue;
        }
        if (keep_unsubscribe && expr == "unsubscribe" && bar == std::string_view::npos)
        {
            text += "{{unsubscribe}}";
            i = end;
            continue;
        }
        flush();
        bool named = false;
        const std::string value = name_lookup(expr, named);
        code += "_v(" + value + ", " + literal(expr) + ", " +
                (bar == std::string_view::npos ? std::string("nil") : literal(stripped(inner.substr(bar + 1)))) + ", " +
                (raw ? "true" : "false") + ", " + (named ? "true" : "false") + ") ";
        align(lines_in(t.substr(at, end - at)) - lines_in(value));
        i = end;
    }
    flush();
    return true;
}

}   // namespace socketley::lua_template
