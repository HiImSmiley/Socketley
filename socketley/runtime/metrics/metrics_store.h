#pragma once
// The metrics runtime's store: samples appended into fixed-size head chunks, each aligned left-open two hours
// (start, start + 2h] cut into an immutable block, blocks merged into longer ones, downsampled into tiers and deleted
// past their retention, and all of it read back as one series_source.
//
// Under its directory:
//   blocks/<kind>_<mint>_<maxt>.blk   immutable blocks, `raw` or `s<step>` for a tier
//   head/<window>.log                 each window not yet cut: series, closed chunks, and with `durable` every sample
//   meta                              each metric's type and help
//
// Thread-safety:
// Every public member is called from one thread, the runtime's loop.
// One background thread cuts, merges and downsamples, reading only what is immutable once handed to it.
// What it makes is swapped in by tick(), and the loop waits for it nowhere but in stop().
// A reference from labels() lives as long as the store; the vectors the queries fill are the caller's.
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "metrics_block.h"
#include "metrics_index.h"
#include "metrics_types.h"

namespace socketley::metrics
{

struct tier_config
{
    int64_t step{0};   // ms
    int64_t keep{0};   // ms
};

struct store_config
{
    int64_t keep_raw{30 * day_ms};
    // Ascending steps: the first divides two hours and is built from raw at each cut, each later one divides a day
    // and is a multiple of the one before, built from it once a day of it is merged.
    std::vector<tier_config> tiers{{5 * minute_ms, 365 * day_ms}, {hour_ms, 5 * 365 * day_ms}};
    // New series past this many in the head are refused.
    uint32_t max_series{200'000};
    // Every sample logged as it comes, so a crash loses none; without it a crash loses the open head chunks.
    bool durable{false};
};

struct store_stats
{
    uint64_t series{0};
    uint64_t head_series{0};
    uint64_t samples_appended{0};
    // A time not after the series' last.
    uint64_t refused_out_of_order{0};
    // A time in a window already cut, or too far from the epoch.
    uint64_t refused_too_old{0};
    uint64_t refused_series{0};
    uint64_t bytes_on_disk{0};
    uint64_t bytes_in_ram{0};
    uint64_t blocks{0};
    // Whether a checkpoint holds maintenance off.
    bool held{false};
    uint64_t blocks_refused{0};
    uint64_t head_windows{0};
    uint64_t head_chunks{0};
    uint64_t maintenance_failures{0};
};

class store final : public series_source
{
public:
    store();
    ~store() override;
    store(const store&) = delete;
    store& operator=(const store&) = delete;

    // The store under `dir`, made when absent, its blocks checked and its head logs replayed; false with `why`.
    bool open(const std::string& dir, const store_config& cfg, std::string& why);

    // The id of `ls`, made when new; no_series when it would pass max_series or two labels share a name.
    uint32_t get_or_create(const label_set& ls);
    uint32_t find(const label_set& ls) const;

    // False, counted, when `t` is not after the series' last or lies in a window already cut.
    bool append(uint32_t id, int64_t t, double v);
    // The staleness marker, appended as a sample.
    bool mark_stale(uint32_t id, int64_t t);

    void set_meta(std::string_view metric, metric_type type, std::string_view help);

    // Finished maintenance swapped in, the head logs written, expired blocks deleted and due work started; the time it
    // wants the next tick by.
    int64_t tick(int64_t now);
    // Whether background work is in flight, which a later tick() takes in.
    bool busy() const;
    // Everything in the head written to its files and synced, and no maintenance started before `hold_until`, so a
    // copy of the directory taken now holds every sample and no block is replaced under it.
    void checkpoint(int64_t hold_until);

    // The background work finished and taken in, the open chunks logged and every file synced; nothing may follow.
    void stop();

    store_stats stats() const;

    // ── series_source ──
    void select(std::span<const matcher> ms, int64_t mint, int64_t maxt, std::vector<uint32_t>& out) override;
    const label_set& labels(uint32_t id) const override;
    void samples(uint32_t id, int64_t mint, int64_t maxt, std::vector<sample>& out) override;
    int64_t tier_for(int64_t mint, int64_t resolution) const override;
    void aggregates(uint32_t id, int64_t step, int64_t mint, int64_t maxt, std::vector<agg_point>& out) override;
    void label_names(std::vector<std::string>& out) const override;
    void label_values(std::string_view name, std::vector<std::string>& out) const override;
    metric_type type_of(std::string_view metric) const override;
    std::string_view help_of(std::string_view metric) const override;

    struct impl;

private:
    std::unique_ptr<impl> m;
};

}   // namespace socketley::metrics
