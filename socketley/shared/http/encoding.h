#pragma once
// Content codings a client accepts (RFC 9110 12.5.3), and the compressed copy beside a file a runtime sends for one.
// Only ever encodings this server sends; nothing here decodes what a client sends.
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <utility>

#include "../util/text_list.h"
#include "mime.h"

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

// The compressed copy beside `rel`, beneath `root_fd`, that a client asking with `accepts` takes, br before gzip: its
// coding, with its path in `at`, its statx in `copy` and the file's in `file`, the last also when no copy is sent and
// `file_known` then says so.  Never a copy older than the file, which a build that changed one and not the other
// leaves behind, nor one beside a format compressed already.
inline std::string_view pick_copy(int root_fd, std::string_view rel, std::string_view accepts, std::string& at,
                                  struct statx& file, struct statx& copy, bool& file_known)
{
    file_known = false;
    if (rel.empty() || accepts.empty() || compressed_type(content_type_of(rel)))
        return {};
    constexpr unsigned want = STATX_TYPE | STATX_INO | STATX_MTIME | STATX_SIZE;
    at.assign(rel);
    if (::statx(root_fd, at.c_str(), 0, want, &file) != 0 || !S_ISREG(file.stx_mode))
        return {};
    file_known = true;
    static constexpr std::pair<std::string_view, std::string_view> copies[] = {{"br", ".br"}, {"gzip", ".gz"}};
    for (const auto& [coding, ext] : copies)
    {
        if (!accepts_coding(accepts, coding))
            continue;
        at.resize(rel.size());
        at.append(ext);
        if (::statx(root_fd, at.c_str(), 0, want, &copy) == 0 && S_ISREG(copy.stx_mode) &&
            (copy.stx_mtime.tv_sec > file.stx_mtime.tv_sec ||
             (copy.stx_mtime.tv_sec == file.stx_mtime.tv_sec && copy.stx_mtime.tv_nsec >= file.stx_mtime.tv_nsec)))
            return coding;
    }
    return {};
}

}   // namespace socketley::http
