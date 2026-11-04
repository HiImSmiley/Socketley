#pragma once
// The media type a file is served as, by its extension, for every runtime that hands a browser a file of its own.

#include <cctype>
#include <string_view>
#include <utility>

namespace socketley::http
{

// `name` is a file name or a path; text is said to be UTF-8, and anything unknown is opaque bytes.
inline std::string_view content_type_of(std::string_view name)
{
    const size_t dot = name.rfind('.');
    if (dot == std::string_view::npos || name.find('/', dot) != std::string_view::npos || name.size() - dot > 12)
        return "application/octet-stream";
    char e[12];
    const std::string_view ext = name.substr(dot + 1);
    for (size_t i = 0; i < ext.size(); ++i)
        e[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(ext[i])));
    const std::string_view x(e, ext.size());
    static constexpr std::pair<std::string_view, std::string_view> types[] = {
        {"html", "text/html; charset=utf-8"},        {"htm", "text/html; charset=utf-8"},
        {"css", "text/css; charset=utf-8"},          {"js", "application/javascript; charset=utf-8"},
        {"mjs", "application/javascript; charset=utf-8"},
        {"json", "application/json; charset=utf-8"}, {"map", "application/json; charset=utf-8"},
        {"txt", "text/plain; charset=utf-8"},        {"md", "text/markdown; charset=utf-8"},
        {"csv", "text/csv; charset=utf-8"},          {"xml", "application/xml"},
        {"yml", "text/yaml; charset=utf-8"},         {"yaml", "text/yaml; charset=utf-8"},
        {"srt", "text/plain; charset=utf-8"},        {"vtt", "text/vtt; charset=utf-8"},
        {"png", "image/png"},                        {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},                      {"gif", "image/gif"},
        {"svg", "image/svg+xml"},                    {"ico", "image/x-icon"},
        {"webp", "image/webp"},                      {"avif", "image/avif"},
        {"heic", "image/heic"},                      {"bmp", "image/bmp"},
        {"woff2", "font/woff2"},                     {"woff", "font/woff"},
        {"ttf", "font/ttf"},                         {"otf", "font/otf"},
        {"wasm", "application/wasm"},                {"pdf", "application/pdf"},
        {"zip", "application/zip"},                  {"mp4", "video/mp4"},
        {"m4v", "video/mp4"},                        {"mov", "video/quicktime"},
        {"mkv", "video/x-matroska"},                 {"webm", "video/webm"},
        {"avi", "video/x-msvideo"},                  {"mp3", "audio/mpeg"},
        {"m4a", "audio/mp4"},                        {"aac", "audio/aac"},
        {"flac", "audio/flac"},                      {"ogg", "audio/ogg"},
        {"opus", "audio/ogg"},                       {"wav", "audio/wav"},
        {"webmanifest", "application/manifest+json"}, {"jsonld", "application/ld+json"},
        {"rss", "application/rss+xml"},              {"atom", "application/atom+xml"},
        {"ics", "text/calendar; charset=utf-8"},     {"xhtml", "application/xhtml+xml"},
    };
    for (const auto& [k, v] : types)
        if (k == x)
            return v;
    return "application/octet-stream";
}

}   // namespace socketley::http
