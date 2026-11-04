#pragma once
// What a web runtime decides about a file by its name alone: whether a build stamped its content into the name, and so
// how long a browser may keep it without asking.
#include <string_view>

namespace socketley::web
{

// Whether the last part of a name's stem, after a '.' or a '-', is a content hash a build put there -- main.3f9a1c2b.js,
// index-B_x3-9Qa.js, app.min.<sha256>.css.  A word in a name is not one: a hash has digits and letters both and no run
// of four lowercase letters, so holiday-2024-beach.jpg stays a name its owner may replace.
inline bool hashed_name(std::string_view name)
{
    if (const size_t slash = name.rfind('/'); slash != std::string_view::npos)
        name.remove_prefix(slash + 1);
    const size_t ext = name.rfind('.');
    if (ext == std::string_view::npos || ext == 0)
        return false;
    const std::string_view stem = name.substr(0, ext);
    for (size_t at = stem.size(); at-- > 0;)
    {
        if (stem[at] != '.' && stem[at] != '-')
            continue;
        const std::string_view tok = stem.substr(at + 1);
        if (tok.size() < 8)
            continue;
        if (tok.size() > 64)
            return false;
        int digits = 0, letters = 0, lower_run = 0, longest_run = 0;
        bool ok = true;
        for (const char c : tok)
        {
            const bool digit = c >= '0' && c <= '9';
            const bool lower = c >= 'a' && c <= 'z';
            const bool upper = c >= 'A' && c <= 'Z';
            if (!digit && !lower && !upper && c != '_' && c != '-')
            {
                ok = false;
                break;
            }
            digits += digit;
            letters += lower || upper;
            lower_run = lower ? lower_run + 1 : 0;
            longest_run = lower_run > longest_run ? lower_run : longest_run;
        }
        // Hex has no letter past f, so four in a row of it is still a hash; a word is not.
        const bool hex_only = tok.find_first_not_of("0123456789abcdef") == std::string_view::npos;
        return ok && digits >= 2 && letters >= 2 && (hex_only || longest_run < 4);
    }
    return false;
}

// The types a build stamps: what a page loads, never the page, nor a document someone links to by its name.
inline bool stamped_type(std::string_view type)
{
    return type.starts_with("application/javascript") || type.starts_with("text/css") || type.starts_with("font/") ||
           type == "application/wasm" || type.starts_with("image/") || type.starts_with("application/json");
}

// A stamped asset is kept a year without a question, since a new build is a new name; everything else is asked about
// on each use, which costs a 304 and never shows a page older than the files.
inline std::string_view cache_control(std::string_view path, std::string_view type)
{
    if (stamped_type(type) && hashed_name(path))
        return "public, max-age=31536000, immutable";
    return "no-cache";
}

}   // namespace socketley::web
