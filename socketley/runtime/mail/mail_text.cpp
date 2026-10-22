#include "mail_text.h"

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

#include "mail_compose.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail
{

namespace
{

// The ranges of `msg` that are searched as written: all of it but the bodies of parts that are not text.
std::vector<std::pair<size_t, size_t>> written_ranges(std::string_view msg, const mime::part* root)
{
    std::vector<std::pair<size_t, size_t>> skip;
    const auto walk = [&](const auto& self, const mime::part& p, int depth) -> void {
        if (depth > 32)
            return;
        for (const auto& c : p.children)
            self(self, c, depth + 1);
        if (p.children.empty() && p.type != "text" && !p.multipart() && !p.message() &&
            p.body_off + p.body_len <= msg.size())
            skip.emplace_back(p.body_off, p.body_off + p.body_len);
    };
    if (root)
        walk(walk, *root, 0);
    std::sort(skip.begin(), skip.end());
    std::vector<std::pair<size_t, size_t>> out;
    size_t at = 0;
    for (const auto& [b, e] : skip)
    {
        if (b > at)
            out.emplace_back(at, b);
        at = std::max(at, e);
    }
    if (at < msg.size())
        out.emplace_back(at, msg.size());
    return out;
}

// Each text part's text with its transfer encoding and charset undone, given to `take`.
template <typename F>
void decoded_texts(std::string_view msg, const mime::part& p, F&& take, int depth = 0)
{
    if (depth > 32)
        return;
    for (const auto& c : p.children)
        decoded_texts(msg, c, take, depth + 1);
    if (!p.children.empty() || p.type != "text" || p.body_off + p.body_len > msg.size())
        return;
    std::string charset;
    for (const auto& [k, v] : p.params)
        if (socketley::ascii::iequals(k, "charset"))
            charset = v;
    take(mime::to_utf8(mime::decoded_body(msg.substr(p.body_off, p.body_len), p.encoding), charset));
}

bool decoded_has(std::string_view msg, const mime::part* root, std::string_view needle)
{
    if (!root)
        return false;
    bool found = false;
    decoded_texts(msg, *root, [&](const std::string& t) { found = found || contains_ci(t, needle); });
    return found;
}

bool written_has(std::string_view msg, const mime::part* root, size_t from, std::string_view needle)
{
    for (const auto& [b, e] : written_ranges(msg, root))
        if (e > from && contains_ci(msg.substr(std::max(b, from), e - std::max(b, from)), needle))
            return true;
    return false;
}

// A trigram's key, its letters of either case alike.
uint32_t trigram(unsigned char a, unsigned char b, unsigned char c)
{
    using socketley::ascii::lower;
    return static_cast<uint32_t>(static_cast<unsigned char>(lower(static_cast<char>(a)))) << 16 |
           static_cast<uint32_t>(static_cast<unsigned char>(lower(static_cast<char>(b)))) << 8 |
           static_cast<unsigned char>(lower(static_cast<char>(c)));
}

// The bits a trigram sets in a filter of 2^`log` bits, three of them.
template <typename F>
void bits_of(uint32_t key, unsigned log, F&& each)
{
    uint64_t h = key * 0x9E3779B97F4A7C15ull;
    h ^= h >> 29;
    const uint32_t mask = (1u << log) - 1;
    const uint32_t h1 = static_cast<uint32_t>(h), h2 = static_cast<uint32_t>(h >> 32) | 1;
    for (uint32_t i = 0; i < 3; ++i)
        each((h1 + i * h2) & mask);
}

constexpr char filter_format = 1;
// Past this many bytes a message's filter says it may hold anything, which a search then reads.
constexpr size_t filter_most_bytes = 1u << 20;

}   // namespace

bool contains_ci(std::string_view hay, std::string_view needle)
{
    // Knuth-Morris-Pratt, so a long needle of a repeated letter costs the haystack's length and not its product.
    const size_t m = needle.size();
    if (m == 0)
        return true;
    if (hay.size() < m)
        return false;
    using socketley::ascii::lower;
    std::vector<size_t> fail(m, 0);
    for (size_t i = 1, k = 0; i < m; ++i)
    {
        while (k > 0 && lower(needle[i]) != lower(needle[k]))
            k = fail[k - 1];
        if (lower(needle[i]) == lower(needle[k]))
            ++k;
        fail[i] = k;
    }
    for (size_t i = 0, k = 0; i < hay.size(); ++i)
    {
        while (k > 0 && lower(hay[i]) != lower(needle[k]))
            k = fail[k - 1];
        if (lower(hay[i]) == lower(needle[k]) && ++k == m)
            return true;
    }
    return false;
}

bool header_has(std::string_view head, std::string_view name, std::string_view needle)
{
    for (const auto& [n, v] : split_headers(head))
    {
        std::string_view nn = n;
        while (!nn.empty() && (nn.back() == ' ' || nn.back() == '\t'))
            nn.remove_suffix(1);
        if (!name.empty() && !socketley::ascii::iequals(nn, name))
            continue;
        if (contains_ci(v, needle) || (v.find("=?") != std::string_view::npos && contains_ci(mime::decode_words(v), needle)))
            return true;
    }
    return false;
}

bool body_has(std::string_view msg, std::string_view head, const mime::part* root, std::string_view needle)
{
    return written_has(msg, root, head.size(), needle) || decoded_has(msg, root, needle);
}

bool text_has(std::string_view msg, std::string_view head, const mime::part* root, std::string_view needle)
{
    return written_has(msg, root, 0, needle) || header_has(head, {}, needle) || decoded_has(msg, root, needle);
}

std::string text_filter(std::string_view msg, std::string_view head, const mime::part* root)
{
    // What a search reads: the message as written, and what differs from it as a client reads it.
    std::vector<std::string> read_as;
    // A header's value also with its folds undone and its encoded words decoded.
    for (const auto& [n, v] : split_headers(head))
    {
        std::string unfolded;
        if (v.find("\r\n") != std::string_view::npos)
        {
            for (size_t i = 0; i < v.size(); ++i)
                if (v[i] == '\r' && i + 1 < v.size() && v[i + 1] == '\n')
                    ++i;
                else
                    unfolded += v[i];
        }
        if (v.find("=?") != std::string_view::npos)
        {
            read_as.push_back(mime::decode_words(v));
            if (!unfolded.empty())
                read_as.push_back(mime::decode_words(unfolded));
        }
        if (!unfolded.empty())
            read_as.push_back(std::move(unfolded));
    }
    // A text part whose decoding changes nothing is read as written already.
    const auto walk = [&](const auto& self, const mime::part& p, int depth) -> void {
        if (depth > 32)
            return;
        for (const auto& c : p.children)
            self(self, c, depth + 1);
        if (!p.children.empty() || p.type != "text" || p.body_off + p.body_len > msg.size())
            return;
        std::string charset;
        for (const auto& [k, v] : p.params)
            if (socketley::ascii::iequals(k, "charset"))
                charset = v;
        const bool plain_bytes = p.encoding.empty() || socketley::ascii::iequals(p.encoding, "7bit") ||
                                 socketley::ascii::iequals(p.encoding, "8bit") ||
                                 socketley::ascii::iequals(p.encoding, "binary");
        const bool plain_charset = charset.empty() || socketley::ascii::iequals(charset, "us-ascii") ||
                                   socketley::ascii::iequals(charset, "utf-8");
        if (!plain_bytes || !plain_charset)
            read_as.push_back(mime::to_utf8(mime::decoded_body(msg.substr(p.body_off, p.body_len), p.encoding), charset));
    };
    if (root)
        walk(walk, *root, 0);
    std::vector<std::string_view> pieces;
    for (const auto& [b, e] : written_ranges(msg, root))
        pieces.push_back(msg.substr(b, e - b));
    for (const auto& r : read_as)
        pieces.push_back(r);
    size_t bytes = 0;
    for (const auto p : pieces)
        bytes += p.size();
    if (bytes > filter_most_bytes)
        return std::string{filter_format, 0};
    // Two bits a byte read, between 1,024 and 32,768 of them, are some five a trigram in a message's text: a word of
    // eight letters it does not hold gets through about once in a million.
    unsigned log = 10;
    while (log < 15 && (size_t{1} << log) < bytes * 2)
        ++log;
    std::string out(2 + ((size_t{1} << log) >> 3), '\0');
    out[0] = filter_format;
    out[1] = static_cast<char>(log);
    for (const auto p : pieces)
        for (size_t i = 0; i + 3 <= p.size(); ++i)
            bits_of(trigram(static_cast<unsigned char>(p[i]), static_cast<unsigned char>(p[i + 1]),
                            static_cast<unsigned char>(p[i + 2])),
                    log, [&](uint32_t bit) { out[2 + (bit >> 3)] |= static_cast<char>(1u << (bit & 7)); });
    return out;
}

bool may_hold(std::string_view filter, std::string_view needle)
{
    if (needle.size() < 3 || filter.size() < 2 || filter[0] != filter_format)
        return true;
    const auto log = static_cast<unsigned>(static_cast<unsigned char>(filter[1]));
    if (log < 10 || log > 15 || filter.size() != 2 + ((size_t{1} << log) >> 3))
        return true;
    for (size_t i = 0; i + 3 <= needle.size(); ++i)
    {
        bool all = true;
        bits_of(trigram(static_cast<unsigned char>(needle[i]), static_cast<unsigned char>(needle[i + 1]),
                        static_cast<unsigned char>(needle[i + 2])),
                log, [&](uint32_t bit) { all = all && (filter[2 + (bit >> 3)] & (1u << (bit & 7))); });
        if (!all)
            return false;
    }
    return true;
}

}   // namespace socketley::mail
