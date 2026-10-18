#pragma once

#include <string_view>

namespace socketley::http
{

// Calls `visit` with the value of every cookie named `name` in a Cookie header, in order, until it answers true, and
// says whether one did; a browser sends one cookie of a name per domain and path it was set for, so a caller that
// verifies takes the first that verifies rather than the first there is.
template <class F>
bool for_each_cookie(std::string_view header, std::string_view name, F&& visit)
{
    while (!header.empty())
    {
        const size_t semi = header.find(';');
        std::string_view part = header.substr(0, semi);
        header = semi == std::string_view::npos ? std::string_view{} : header.substr(semi + 1);
        while (!part.empty() && (part.front() == ' ' || part.front() == '\t'))
            part.remove_prefix(1);
        if (part.size() > name.size() && part.starts_with(name) && part[name.size()] == '=' &&
            visit(part.substr(name.size() + 1)))
            return true;
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

} // namespace socketley::http
