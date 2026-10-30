#pragma once
// A metrics runtime's logs (--logs): every line the daemon and its workers write, kept a file a day and answered with a
// subset of LogQL over Loki's HTTP API, so Grafana's Loki data source reads it as it reads a Loki.
//
// A file is records of `u32 length | u32 crc32c | i64 ms | u8 level | u16 runtime length | runtime | text`; a torn
// tail is where a crash cut it and reads as its end. A line's labels are job="socketley", instance, name (the runtime,
// absent for the daemon's own) and level.
//
// LogQL taken: a selector `{label="v", label!="v", label=~"re", label!~"re"}`, line filters `|= "s"`, `!= "s"`,
// `|~ "re"`, `!~ "re"` (a regex found anywhere in the line), and over them `count_over_time(...[d])`,
// `rate(...[d])`, `bytes_over_time(...[d])`, `bytes_rate(...[d])`, with `sum|count|min|max|avg [by|without (...)]`
// around them. Anything without a selector is PromQL and goes to the metrics engine.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "metrics_regex.h"
#include "metrics_types.h"

namespace socketley::metrics
{

struct log_view
{
    int64_t t{0};
    std::string_view level;
    std::string_view runtime;
    std::string_view text;
};

struct log_stats
{
    uint64_t lines{0};
    uint64_t bytes_on_disk{0};
    uint64_t files{0};
    uint64_t torn{0};
};

class log_store
{
public:
    log_store() = default;
    ~log_store();
    log_store(const log_store&) = delete;
    log_store& operator=(const log_store&) = delete;

    // `dir` made when absent, its files counted; false with `why`.
    bool open(const std::string& dir, int64_t keep_ms, std::string& why);
    bool is_open() const { return m_open; }
    void append(int64_t t, std::string_view level, std::string_view runtime, std::string_view text);
    // What was appended written to its file.
    void flush();
    // The days past --logs-keep removed.
    void retain(int64_t now);
    void close();

    // The lines in [mint, maxt] that `keep` takes, newest first when `backward`, `each` until it says stop.
    void scan(int64_t mint, int64_t maxt, bool backward, const std::function<bool(const log_view&)>& each) const;
    int64_t last_t() const { return m_last_t; }
    const log_stats& stats() const { return m_st; }

private:
    std::string path_of(int64_t day) const;
    void read_file(const std::string& path, std::vector<std::pair<size_t, size_t>>& recs, std::string& data) const;

    std::string m_dir;
    int64_t m_keep_ms{0};
    bool m_open{false};
    int m_fd{-1};
    int64_t m_day{INT64_MIN};
    std::string m_buf;
    int64_t m_last_t{INT64_MIN};
    mutable log_stats m_st;
};

// A LogQL query parsed: the selector, the line filters, and the function over them when it is a metric query.
struct logql
{
    std::vector<matcher> selector;
    // The selector's regexes compiled, beside it, null for one that is no regex.
    std::vector<std::shared_ptr<regex>> selector_re;
    struct filter
    {
        enum class kind : uint8_t { contains, not_contains, re, not_re };
        kind k{kind::contains};
        std::string text;
        std::shared_ptr<regex> re;
    };
    std::vector<filter> filters;

    // count_over_time, rate, bytes_over_time or bytes_rate; empty for a log query.
    std::string fn;
    int64_t range_ms{0};
    // sum, count, min, max, avg; empty for none.
    std::string agg;
    bool without{false};
    std::vector<std::string> grouping;
};

// False with `why` (Loki's message style) when `q` is not in the subset; `is_log` false when it has no selector.
bool parse_logql(std::string_view q, logql& out, bool& is_log, std::string& why);

// The labels of a line, sorted.
void log_labels(const log_view& l, std::string_view instance, label_set& out);
bool logql_matches(const logql& q, const label_set& labels, std::string_view text);

// The `data` member of Loki's query_range answer: streams for a log query, a matrix for a metric query over
// [start, end] at `step`; `limit` lines at most for a log query.
void logql_range(const log_store& s, const logql& q, std::string_view instance, int64_t start, int64_t end,
                 int64_t step, size_t limit, bool backward, std::string& out);
// The same at one time: a metric query's vector, or a log query's newest `limit` lines up to `t`.
void logql_instant(const log_store& s, const logql& q, std::string_view instance, int64_t t, size_t limit,
                   std::string& out);
// The label names, or one label's values, of the lines in [start, end], as Loki's `data` arrays.
void log_label_names(const log_store& s, std::string_view instance, int64_t start, int64_t end, std::string& out);
void log_label_values(const log_store& s, std::string_view instance, std::string_view name, int64_t start, int64_t end,
                      std::string& out);

}   // namespace socketley::metrics
