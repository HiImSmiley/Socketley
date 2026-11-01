#pragma once
// Content codings a client accepts (RFC 9110 12.5.3), asked when a runtime has a file's compressed copy beside it.
// Only ever encodings this server sends; nothing here decodes what a client sends.
#include <string_view>

#include "../util/text_list.h"

namespace socketley::http
{

// Whether `coding` is in an Accept-Encoding list with a weight above zero; `*` names it too, unless it is listed with
// q=0 on its own.
inline bool accepts_coding(std::string_view list, std::string_view coding)
{
    const auto lower_eq = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); ++i)
        {
            char c = a[i];
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
            if (c != b[i])
                return false;
        }
        return true;
    };
    const auto trim = [](std::string_view v) {
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
            v.remove_prefix(1);
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
            v.remove_suffix(1);
        return v;
    };
    // Whether a weight is zero: q=0, q=0., q=0.0, q=0.00 or q=0.000.
    const auto zero = [&](std::string_view params) {
        for (std::string_view rest = params; !rest.empty();)
        {
            std::string_view p = trim(socketley::take_item(rest, ';'));
            if (p.size() < 2 || (p[0] != 'q' && p[0] != 'Q') || p[1] != '=')
                continue;
            p.remove_prefix(2);
            if (p.empty() || p[0] != '0')
                return false;
            for (size_t i = 1; i < p.size(); ++i)
                if (p[i] != '.' && p[i] != '0')
                    return false;
            return true;
        }
        return false;
    };
    bool named = false, star = false, refused = false;
    while (!list.empty())
    {
        const std::string_view item = trim(socketley::take_item(list));
        const size_t semi = item.find(';');
        const std::string_view name = trim(item.substr(0, semi));
        const bool z = semi != std::string_view::npos && zero(item.substr(semi + 1));
        if (lower_eq(name, coding))
        {
            named = !z;
            refused = z;
        }
        else if (name == "*")
            star = !z;
    }
    return named || (star && !refused);
}

// Whether a media type is compressed in its own format, so no copy of it beside it is ever worth looking for.
inline bool compressed_type(std::string_view type)
{
    if (type.starts_with("image/"))
        return type != "image/svg+xml" && type != "image/bmp" && type != "image/x-icon";
    if (type.starts_with("audio/"))
        return type != "audio/wav";
    return type.starts_with("video/") || type.starts_with("font/woff") || type == "application/zip" ||
           type == "application/pdf";
}

}   // namespace socketley::http
