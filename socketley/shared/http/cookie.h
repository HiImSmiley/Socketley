#pragma once

#include <algorithm>
#include <initializer_list>
#include <string>
#include <string_view>

#include "../util/text_list.h"

namespace socketley::http
{

// Calls `visit` with the value of every cookie named `name` in a Cookie header, in order, until it answers true, and
// says whether one did; a browser sends one cookie of a name per domain and path it was set for, so a caller that
// verifies takes the first that verifies rather than the first there is.
// At most max_cookies_of_a_name are visited: a browser sends a handful, and a caller that verifies spends a signature
// check on each, so 85 forged session cookies in one head cost 4-6 ms of the loop before it was refused.
inline constexpr int max_cookies_of_a_name = 8;

template <class F>
bool for_each_cookie(std::string_view header, std::string_view name, F&& visit)
{
    int left = max_cookies_of_a_name;
    while (!header.empty() && left > 0)
    {
        std::string_view part = take_item(header, ';');
        while (!part.empty() && (part.front() == ' ' || part.front() == '\t'))
            part.remove_prefix(1);
        if (part.size() > name.size() && part.starts_with(name) && part[name.size()] == '=')
        {
            if (visit(part.substr(name.size() + 1)))
                return true;
            --left;
        }
    }
    return false;
}

// The first value of `name`, empty when there is none; for a caller that only asks whether one was sent.
inline std::string_view cookie_value(std::string_view header, std::string_view name)
{
    std::string_view out;
    for_each_cookie(header, name, [&](std::string_view v) {
        out = v;
        return true;
    });
    return out;
}

// A Cookie header's value without the cookies named in `names`, the others as they came; empty when none is left.
inline std::string without_cookies(std::string_view header, std::initializer_list<std::string_view> names)
{
    std::string out;
    while (!header.empty())
    {
        const std::string_view part = trim_blanks(take_item(header, ';'));
        if (part.empty() || std::find(names.begin(), names.end(), trim_blanks(part.substr(0, part.find('=')))) != names.end())
            continue;
        if (!out.empty())
            out += "; ";
        out.append(part);
    }
    return out;
}

} // namespace socketley::http
