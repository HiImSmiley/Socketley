#pragma once
// A request's path as a site of files reads it: decoded, made plain, and kept away from where a site's secrets sit.
#include <string>
#include <string_view>

#include "url.h"

namespace socketley::http
{

// A path with a segment that starts with a dot -- .env, .git/config, .htpasswd -- which is where a site's secrets sit
// beside its pages, so none is served; .well-known is the one such directory meant for the public.
inline bool hidden_path(std::string_view path)
{
    size_t i = 0;
    while (i < path.size())
    {
        while (i < path.size() && path[i] == '/')
            ++i;
        const size_t end = path.find('/', i);
        const std::string_view seg = path.substr(i, end == std::string_view::npos ? std::string_view::npos : end - i);
        if (!seg.empty() && seg.front() == '.' && seg != ".well-known")
            return true;
        if (end == std::string_view::npos)
            break;
        i = end;
    }
    return false;
}

// `raw` decoded into `out` as one absolute path with single slashes, a trailing one kept; false for one that names
// nothing under a root: no leading slash, a NUL, or a "." or ".." segment, which a decoded %2e%2e spells as well.
inline bool site_path(std::string_view raw, std::string& out)
{
    // Nothing to decode or merge, and no dot segment: most paths, taken as they are.
    if (!raw.empty() && raw.front() == '/' && raw.find_first_of(std::string_view("%\0", 2)) == std::string_view::npos &&
        raw.find("//") == std::string_view::npos && raw.find("/.") == std::string_view::npos)
    {
        out.assign(raw);
        return true;
    }
    std::string decoded;
    if (raw.empty() || raw.front() != '/' || !percent_decode(raw, decoded, false, bad_escape::keep))
        return false;
    out.clear();
    out.reserve(decoded.size());
    for (std::string_view rest = decoded; !rest.empty();)
    {
        const size_t slash = rest.find('/');
        const std::string_view seg = rest.substr(0, slash);
        rest = slash == std::string_view::npos ? std::string_view{} : rest.substr(slash + 1);
        if (seg.empty())
            continue;
        if (seg == "." || seg == ".." || seg.find('\0') != std::string_view::npos)
            return false;
        out.push_back('/');
        out.append(seg);
    }
    // A trailing slash names a directory's index, so it survives the merge.
    if (out.empty() || decoded.back() == '/')
        out.push_back('/');
    return true;
}

}   // namespace socketley::http
