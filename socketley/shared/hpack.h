#pragma once
// HPACK, RFC 7541: the header compression of HTTP/2. A decoder with the dynamic table a peer's encoder keeps in step
// with, Huffman strings included, and an encoder that never indexes, so it has no table to keep and every block it
// writes stands on its own.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::hpack
{

struct header
{
    std::string name;
    std::string value;
};

// Opens a Huffman-coded string into `out`; false for padding longer than 7 bits or not all ones, or for EOS.
bool huffman_decode(std::string_view in, std::string& out);

class decoder
{
public:
    enum class result : uint8_t
    {
        ok,
        // Not HPACK, or naming an entry that is not there: the connection cannot go on (COMPRESSION_ERROR).
        error,
        // Decoded whole, so the table is still in step, but the list is longer than `max_list` allows.
        too_large,
    };

    // `table_max` is the SETTINGS_HEADER_TABLE_SIZE this side announced, which a size update may not exceed.
    explicit decoder(size_t table_max = 4096) : m_limit(table_max), m_max(table_max) {}

    // One header block, its fields appended to `out` in order. A list is counted as RFC 9113 counts it: each field's
    // name and value and 32 more.
    result decode(std::string_view block, std::vector<header>& out, size_t max_list);

    size_t table_size() const { return m_size; }

private:
    bool entry(uint64_t index, const header*& h) const;
    void insert(header h);
    void evict();

    std::deque<header> m_table;   // newest first
    size_t m_size{0};
    size_t m_limit;               // what the settings allow
    size_t m_max;                 // what the encoder last chose, up to m_limit
};

// Appends a field as a literal never added to a table: indexed by the static table when name and value are one of
// its entries, by its name's index when only the name is, and spelled out otherwise. Names are written as given, so
// they must already be lowercase.
void encode(std::string& out, std::string_view name, std::string_view value);

}   // namespace socketley::hpack
