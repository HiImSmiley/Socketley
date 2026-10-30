#pragma once
// What the metrics runtime's store, its query language and its rules agree on: a series is a sorted set of labels,
// its samples are milliseconds and doubles, and a coarser tier holds one aggregate per step.
#include <bit>
#include <cmath>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::metrics
{

struct label
{
    std::string name;
    std::string value;
    bool operator==(const label&) const = default;
};

// Sorted by name, names unique, the metric's name under `__name__`; an empty value is the same as no label.
using label_set = std::vector<label>;

inline constexpr std::string_view name_label = "__name__";

inline std::string_view label_value(const label_set& ls, std::string_view name)
{
    for (const auto& l : ls)
        if (l.name == name)
            return l.value;
    return {};
}

struct sample
{
    int64_t t{0};   // milliseconds since the epoch
    double  v{0};
};

// Prometheus's staleness marker: a NaN no arithmetic produces, written when a series vanishes from its target.
inline constexpr uint64_t stale_bits = 0x7ff0000000000002ull;
inline double stale_nan() { return std::bit_cast<double>(stale_bits); }
inline bool   is_stale(double v) { return std::bit_cast<uint64_t>(v) == stale_bits; }

// One step of a coarser tier: what the raw samples in (t - step, t] were, left-open as a Prometheus 3 range is, `inc`
// the counter increase across the step with resets folded in and measured from the previous step's last sample.
// NaN, the staleness marker among them, takes no part, so `count` counts the other samples and a step holding only NaN
// has no point; a series that ended inside a step still has that step's `last`.
struct agg_point
{
    int64_t t{0};
    double  min{0};
    double  max{0};
    double  sum{0};
    double  count{0};
    double  last{0};
    double  inc{0};
};

enum class metric_type : uint8_t { untyped, counter, gauge, histogram, summary };

enum class match_op : uint8_t { eq, ne, re, nre };

struct matcher
{
    std::string name;
    match_op    op{match_op::eq};
    std::string value;
};

// What the query engine reads; the store implements it, and a test can with a vector.
class series_source
{
public:
    virtual ~series_source() = default;

    // The ids of the series every matcher accepts that hold a sample in [mint, maxt], ascending.
    virtual void select(std::span<const matcher> ms, int64_t mint, int64_t maxt, std::vector<uint32_t>& out) = 0;
    virtual const label_set& labels(uint32_t id) const = 0;

    // The raw samples of `id` in [mint, maxt], ascending, appended to `out`.
    virtual void samples(uint32_t id, int64_t mint, int64_t maxt, std::vector<sample>& out) = 0;

    // The step of the coarsest tier no coarser than `resolution` that still holds data back to `mint`; 0 is raw.
    virtual int64_t tier_for(int64_t mint, int64_t resolution) const = 0;
    // The points of `id` in tier `step` whose steps end in (mint, maxt], ascending, each with a count above zero.
    virtual void aggregates(uint32_t id, int64_t step, int64_t mint, int64_t maxt, std::vector<agg_point>& out) = 0;

    virtual void label_names(std::vector<std::string>& out) const = 0;
    virtual void label_values(std::string_view name, std::vector<std::string>& out) const = 0;
    virtual metric_type type_of(std::string_view metric) const = 0;
    virtual std::string_view help_of(std::string_view metric) const = 0;
};

}  // namespace socketley::metrics
