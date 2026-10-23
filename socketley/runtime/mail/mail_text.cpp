#include "mail_text.h"

#include <algorithm>
#include <cmath>
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

// A trigram's key mixed into the hash its bits are drawn from.
uint64_t mixed(uint32_t key)
{
    uint64_t h = key * 0x9E3779B97F4A7C15ull;
    return h ^ h >> 29;
}

// The bits a trigram of hash `h` sets in a filter of 2^`log` bits, three of them.
template <typename F>
void bits_of(uint64_t h, unsigned log, F&& each)
{
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
    // The needle in lower case and its failure table, on the stack for a needle of the length searches have.
    constexpr size_t on_stack = 64;
    char low_here[on_stack];
    size_t fail_here[on_stack];
    std::string low_heap;
    std::vector<size_t> fail_heap;
    char* low = low_here;
    size_t* fail = fail_here;
    if (m > on_stack)
    {
        low_heap.resize(m);
        fail_heap.resize(m);
        low = low_heap.data();
        fail = fail_heap.data();
    }
    for (size_t i = 0; i < m; ++i)
        low[i] = lower(needle[i]);
    fail[0] = 0;
    for (size_t i = 1, k = 0; i < m; ++i)
    {
        while (k > 0 && low[i] != low[k])
            k = fail[k - 1];
        if (low[i] == low[k])
            ++k;
        fail[i] = k;
    }
    for (size_t i = 0, k = 0; i < hay.size(); ++i)
    {
        const char c = lower(hay[i]);
        while (k > 0 && c != low[k])
            k = fail[k - 1];
        if (c == low[k] && ++k == m)
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
    const auto each_trigram = [&](auto&& take) {
        for (const auto p : pieces)
            for (size_t i = 0; i + 3 <= p.size(); ++i)
                take(mixed(trigram(static_cast<unsigned char>(p[i]), static_cast<unsigned char>(p[i + 1]),
                                   static_cast<unsigned char>(p[i + 2]))));
    };
    // How many different trigrams the message holds, from the share of a map of 65,536 bits they leave clear.
    std::vector<uint64_t> seen(1024, 0);
    each_trigram([&](uint64_t h) { seen[(h >> 6) & 1023] |= uint64_t{1} << (h & 63); });
    size_t clear = 0;
    for (const uint64_t w : seen)
        clear += 64 - static_cast<size_t>(__builtin_popcountll(w));
    const double distinct = clear ? -65536.0 * std::log(static_cast<double>(clear) / 65536.0) : 65536.0;
    // Five bits or more for each, between 1,024 and 32,768 of them: a word of eight letters the message does not hold
    // gets through about once in a million.
    unsigned log = 10;
    while (log < 15 && static_cast<double>(size_t{1} << log) < 5 * distinct)
        ++log;
    std::string out(2 + ((size_t{1} << log) >> 3), '\0');
    out[0] = filter_format;
    out[1] = static_cast<char>(log);
    each_trigram([&](uint64_t h) {
        bits_of(h, log, [&](uint32_t bit) { out[2 + (bit >> 3)] |= static_cast<char>(1u << (bit & 7)); });
    });
    return out;
}

bool may_hold(std::string_view filter, std::string_view needle)
{
    return may_hold(filter, trigrams_of(needle));
}

std::vector<uint64_t> trigrams_of(std::string_view needle)
{
    std::vector<uint64_t> out;
    for (size_t i = 0; i + 3 <= needle.size(); ++i)
        out.push_back(mixed(trigram(static_cast<unsigned char>(needle[i]), static_cast<unsigned char>(needle[i + 1]),
                                    static_cast<unsigned char>(needle[i + 2]))));
    return out;
}

bool may_hold(std::string_view filter, const std::vector<uint64_t>& grams)
{
    if (grams.empty() || filter.size() < 2 || filter[0] != filter_format)
        return true;
    const auto log = static_cast<unsigned>(static_cast<unsigned char>(filter[1]));
    if (log < 10 || log > 15 || filter.size() != 2 + ((size_t{1} << log) >> 3))
        return true;
    const auto* bits = reinterpret_cast<const unsigned char*>(filter.data() + 2);
    for (const uint64_t h : grams)
    {
        bool all = true;
        bits_of(h, log, [&](uint32_t bit) { all = all && (bits[bit >> 3] & (1u << (bit & 7))); });
        if (!all)
            return false;
    }
    return true;
}

}   // namespace socketley::mail
