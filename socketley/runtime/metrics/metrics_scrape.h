#pragma once
// The Prometheus endpoints a metrics runtime scrapes: a file of targets read again when it changes, one connection kept
// per target, each scraped at its own interval staggered across it, and a cache per target from the bytes a series
// is written as to its id, so a label is parsed only for a series not seen before.
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../../shared/http/outbound_http.h"
#include "../../shared/persist/file_stamp.h"
#include "../../shared/util/transparent_string.h"
#include "metrics_store.h"
#include "metrics_text.h"

namespace socketley::metrics
{

// One line of a --scrape file.
struct target_config
{
    std::string name;
    std::string url;
    socketley::http_target where;
    int64_t every_ms{0};
    int64_t timeout_ms{0};
    // The token sent as `Authorization: Bearer`, read from the file bearer= names.
    std::string bearer;
    // The line's own labels, sorted, without job and instance.
    label_set labels;
};

// `name url [every=dur] [timeout=dur] [bearer=file] [label=value ...]` a line, `#` beginning a comment; false with `why`.
bool parse_targets(std::string_view text, int64_t default_every_ms, std::vector<target_config>& out, std::string& why);

struct scrape_figures
{
    uint64_t scrapes{0};
    uint64_t failures{0};
    uint64_t samples{0};
    // New series a target named past --max-series.
    uint64_t series_refused{0};
    uint64_t lines_refused{0};
};

class scraper
{
public:
    // The most bytes a scrape's answer may hold.
    static constexpr size_t max_body = 16u << 20;

    scraper(event_loop& loop, file_io& io, hash_pool& resolver, store& s, std::string owner);
    ~scraper();

    // The targets the file names now, each kept as it was where its line did not change; false with `why`.
    bool configure(std::string path, int64_t default_every_ms, std::string& why);
    // The file read again when it changed, a broken one said in the log and the targets before kept.
    void refresh(int64_t default_every_ms);

    // The earliest time a target is due, INT64_MAX for none.
    int64_t next_due() const;
    // Every target due by `now` begun, stamped with the time it was due.
    void run_due(int64_t now);
    // A scrape past its timeout ended as failed, and stalled connections let go.
    void tick(int64_t now);
    // Whether a scrape is in flight, which the tick then watches.
    bool busy() const;
    void stop();

    size_t size() const { return m_targets.size(); }
    size_t up() const;
    const scrape_figures& figures() const { return m_fig; }
    const std::string& path() const { return m_path; }

    // The Prometheus API's activeTargets entries, appended to `out` as a JSON array's members.
    void targets_json(std::string& out, bool& first) const;
    // One line a target, for the CLI.
    void targets_text(std::string& out) const;

private:
    struct target;
    void start(target& t, int64_t stamp);
    void finish(target& t, const socketley::http_answer& a);
    void fail(target& t, std::string why);
    void put_up(target& t, double up, double secs, double samples);

    event_loop& m_loop;
    file_io& m_io;
    hash_pool& m_resolver;
    store& m_store;
    std::string m_owner;
    std::string m_path;
    std::optional<socketley::file_stamp> m_stamp;
    std::vector<std::unique_ptr<target>> m_targets;
    text_parser m_parser;
    scrape_figures m_fig;
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::metrics
