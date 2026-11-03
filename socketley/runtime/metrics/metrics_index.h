#pragma once
// The series a store knows: every label string interned once, each label set mapped to a dense u32 id through a flat
// table, and per label pair the ascending ids that carry it, which a selector's matchers are answered from.
//
// Thread-safety: one thread only, the store's loop; nothing here locks.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "metrics_types.h"

namespace socketley::metrics
{

inline constexpr uint32_t no_series = 0xFFFFFFFFu;

// Whether `ls` is sorted by name, its names unique and none of its values empty.
bool is_normal(const label_set& ls);
// `in` sorted with its empty values dropped into `out`; false when two labels share a name.
bool normalize(const label_set& in, label_set& out);

// Open addressing over one word per slot: the high half of a key's hash beside its value, probed linearly.
class flat_slots
{
public:
    static constexpr uint32_t none = 0xFFFFFFFFu;

    template <class Eq>
    uint32_t find(uint64_t h, Eq&& eq) const
    {
        if (m_s.empty())
            return none;
        const auto tag = static_cast<uint32_t>(h >> 32);
        const size_t mask = m_s.size() - 1;
        for (size_t i = tag & mask;; i = (i + 1) & mask)
        {
            const uint64_t s = m_s[i];
            if (s == 0)
                return none;
            if (static_cast<uint32_t>(s >> 32) == tag && eq(static_cast<uint32_t>(s) - 1))
                return static_cast<uint32_t>(s) - 1;
        }
    }

    // `v` under `h`, which must not be there yet.
    void insert(uint64_t h, uint32_t v);
    size_t bytes() const { return m_s.capacity() * sizeof(uint64_t); }

private:
    void place(uint32_t tag, uint32_t v);
    std::vector<uint64_t> m_s;
    size_t m_used{0};
};

class series_index
{
public:
    series_index();
    ~series_index();
    series_index(const series_index&) = delete;
    series_index& operator=(const series_index&) = delete;

    // The id of the normal label set `ls`, no_series when it is unknown.
    uint32_t find(const label_set& ls) const;
    // The normal label set `ls`, unknown so far, added under the next id.
    uint32_t add(const label_set& ls);
    uint32_t size() const { return static_cast<uint32_t>(m_ser_off.size() - 1); }

    // The labels of `id`, made on the first ask and kept, so the reference lives as long as the index.
    const label_set& labels(uint32_t id) const;

    // Each label of `id` handed to `f(name, value)` in name order, the views valid until the next add().
    template <class F>
    void each_label(uint32_t id, F&& f) const
    {
        for (uint32_t i = m_ser_off[id]; i < m_ser_off[id + 1]; i += 2)
            f(symbol(m_pairs[i]), symbol(m_pairs[i + 1]));
    }

    // The ids every matcher accepts, ascending; an empty value matches a missing label.
    void match(std::span<const matcher> ms, std::vector<uint32_t>& out) const;

    void label_names(std::vector<std::string>& out) const;
    void label_values(std::string_view name, std::vector<std::string>& out) const;

    // What the index holds on the heap.
    size_t bytes() const;

private:
    struct posting
    {
        uint32_t name;
        uint32_t value;
        std::vector<uint32_t> ids;
    };
    struct name_entry
    {
        uint32_t name;
        std::vector<uint32_t> postings;
    };
    struct compiled;

    std::string_view symbol(uint32_t s) const
    {
        return std::string_view(m_sym_bytes).substr(m_sym_off[s], m_sym_off[s + 1] - m_sym_off[s]);
    }
    uint32_t find_symbol(std::string_view s) const;
    uint32_t intern(std::string_view s);
    uint64_t key_hash(const label_set& ls) const;
    const name_entry* name_of(std::string_view name) const;
    uint32_t posting_of(uint32_t name, uint32_t value) const;
    // A matcher's regex in RE2 syntax, matched in linear time by metrics_regex, compiled once for a few dozen patterns.
    const compiled& compiled_for(std::string_view pattern) const;

    // Symbols: their bytes back to back, the start of each, and the table that finds one by its bytes.
    std::string m_sym_bytes;
    std::vector<uint32_t> m_sym_off;
    flat_slots m_sym_table;

    // Series: name and value symbols in pairs, the start of each series' pairs, and the table over their hashes.
    std::vector<uint32_t> m_pairs;
    std::vector<uint32_t> m_ser_off;
    flat_slots m_ser_table;

    std::vector<posting> m_postings;
    flat_slots m_pair_table;
    std::vector<name_entry> m_names;
    // Per symbol, the index of its name_entry plus one, 0 when no label has it as a name.
    std::vector<uint32_t> m_name_of_sym;

    mutable std::vector<std::unique_ptr<label_set>> m_label_cache;
    // What the label sets in m_label_cache hold, counted as each is made, since bytes() is asked on every tick.
    mutable size_t m_label_cache_bytes{0};
    mutable std::string m_key;
    mutable std::vector<std::unique_ptr<compiled>> m_regexes;
    mutable size_t m_regex_next{0};
};

}   // namespace socketley::metrics
