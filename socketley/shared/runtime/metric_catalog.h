#pragma once
// What each runtime type's stats figures are as Prometheus series: a family per figure with its type and help, one
// catch-all family per type for the figures it does not name, and a walk that hands every series to a sink -- the
// daemon's /metrics writes them as text, and a metrics runtime can store them as they come.
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "latency_histogram.h"
#include "runtime_definitions.h"

namespace socketley::metric_catalog
{

enum class kind : uint8_t { counter, gauge, untyped, histogram };

// The name the exposition format's TYPE line gives a kind.
const char* kind_name(kind k);

// How a figure that comes again, from the next shard of a runtime, is folded into the one before.
enum class merge : uint8_t { sum, first, max };

struct family
{
    std::string_view name;
    kind             type{kind::untyped};
    std::string_view help;
};

struct label
{
    std::string_view name;
    std::string_view value;
};

// One sample, its views valid only while the sink is called.
struct series
{
    const family*          fam{nullptr};
    std::span<const label> labels;
    double                 value{0};
    // The value exactly, past what a double holds, when it is a whole number that is not negative.
    uint64_t               integer{0};
    bool                   integral{false};
    // A histogram's `_bucket`, `_sum` or `_count`, which the series' name is the family's name followed by.
    std::string_view       suffix{};

    static series of(const family& f, std::span<const label> ls, uint64_t v, std::string_view suffix = {})
    {
        return {&f, ls, static_cast<double>(v), v, true, suffix};
    }
    static series of(const family& f, std::span<const label> ls, double v, std::string_view suffix = {})
    {
        return {&f, ls, v, 0, false, suffix};
    }
};

// A callable taken by reference, so a walk calls its sink without a std::function's allocation.
class sink_ref
{
public:
    template <class F>
        requires(!std::is_same_v<std::remove_cvref_t<F>, sink_ref>)
    sink_ref(F& f) : m_ctx(&f), m_fn([](void* c, const series& s) { (*static_cast<F*>(c))(s); }) {}
    void operator()(const series& s) const { m_fn(m_ctx, s); }

private:
    void* m_ctx;
    void (*m_fn)(void*, const series&);
};

// One figure of a type's stats text and the series it becomes.
struct field
{
    // The key in the text, or the start of every key it takes when `prefix` is set.
    std::string_view key;
    // Empty for a figure left to the type's catch-all family, named here only for how its shards merge.
    family           fam;
    // A family several figures share is told apart by this label, or by the rest of a prefixed key.
    std::string_view label_name{};
    std::string_view label_value{};
    merge            how{merge::sum};
    bool             prefix{false};
    // Named and still in the catch-all as well, because a series the catch-all carried before stays.
    bool             also_stat{false};
};

struct type_entry
{
    runtime_type           type;
    std::span<const field> fields;
    // The `name`/`stat` family of every numeric figure no field names.
    family                 stat;
    // The shared table's byte counts as fields `bytes_in` and `bytes_out`, which no type's text carries.
    bool                   shared_bytes{false};
};

// The catalog of a type, null for one it has none for.
const type_entry* entry_for(runtime_type t);

// Every type the catalog knows, in the order /metrics writes them.
std::span<const type_entry> types();

struct source;
void emit(const type_entry& e, std::span<const source> runtimes, sink_ref out);

// One runtime's numeric figures, out of its published stats text, each shard's section folded into one.
class figures
{
public:
    // `detail` is the text a worker published, kept here because the figures name its keys.
    void parse(runtime_type t, std::string detail, uint64_t bytes_in = 0, uint64_t bytes_out = 0);

    bool get(std::string_view key, uint64_t& out) const;
    bool empty() const { return m_entry == nullptr; }

private:
    friend void emit(const type_entry&, std::span<const source>, sink_ref);
    friend void emit_histogram(const field&, uint16_t, const source&, sink_ref);

    // A key by its place in the text, which a view would lose when a short text moves with its figures.
    struct other
    {
        uint32_t off;
        uint32_t len;
        uint64_t value;
        // The prefixed field it belongs to, or -1 for the catch-all.
        int16_t  prefix_field;
        merge    how;
    };

    std::string_view key_of(const other& o) const { return std::string_view(m_text).substr(o.off, o.len); }
    void put(std::string_view key, uint64_t v, bool sharded);
    // A figure of a named field, false when no field names `key`.
    bool put_field(std::string_view key, uint64_t v, int& index);

    const type_entry*     m_entry{nullptr};
    std::string           m_text;
    // Indexed by field, a figure each named field has at most, and whether it was seen.
    std::vector<uint64_t> m_slot;
    std::vector<uint8_t>  m_has;
    // Everything else numeric, in the order the text first gave it.
    std::vector<other>    m_other;
    // The histogram fields' figures, each shard's folded in, by field.
    struct histogram_slot
    {
        uint16_t          field;
        latency_histogram h;
    };
    std::vector<histogram_slot> m_hist;
    // A histogram field's line, false when `key` names none.
    bool put_histogram(std::string_view key, std::string_view value);
};

// A runtime as a walk reads it: the value of its `name` label and its figures.
struct source
{
    std::string_view name;
    const figures*   fig{nullptr};
};

// Every series of these runtimes of one type, family after family, so that each family's series come together.
void emit(const type_entry& e, std::span<const source> runtimes, sink_ref out);

}   // namespace socketley::metric_catalog
