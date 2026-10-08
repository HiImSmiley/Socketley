#pragma once
// The dashboard's figures over the last day: a point every `step` seconds for each runtime and for the daemon as a
// whole, kept by the metrics endpoint's thread alone -- so without a lock -- and written to the state directory so a
// restart of the daemon keeps them.
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace history
{

inline constexpr int64_t step = 10;
inline constexpr int64_t span = 86400;

// What a runtime's counters and processes say at one instant.
struct reading
{
    uint64_t connections{0};
    uint64_t messages{0};
    uint64_t bytes_in{0};
    uint64_t bytes_out{0};
    double cpu_seconds{0};
    uint64_t rss_bytes{0};
};

// One point: connections and memory as they were, the rest per second since the point before, CPU in percent of one.
struct point
{
    int64_t at{0};
    float conn{0}, msg{0}, in{0}, out{0}, cpu{0}, rss{0};
};

class keeper
{
public:
    // `path` is the file the points are kept in, empty for none.
    explicit keeper(std::string path) : m_path(std::move(path)) {}

    // Every runtime's reading at `now_ms`, by name, and the daemon's under the empty name; a runtime not among them
    // keeps its points until the last is a day old.
    void record(int64_t now_ms, const std::vector<std::pair<std::string, reading>>& readings);

    // `name`'s last `range` seconds in `points` buckets as JSON: {"from":,"step":,"conn":[],"msg":[],"in":[],"out":[],
    // "cpu":[],"rss":[]}, a bucket's mean, null for one without a point; empty for a name with no points.
    std::string query(std::string_view name, int64_t now_s, int64_t range, size_t points) const;

    // The file's points of the last day; a file that is not one is ignored.
    void load(int64_t now_s);
    // Written whole beside the file and renamed over it.
    bool save() const;

private:
    struct series
    {
        std::deque<point> points;
        reading last;
        int64_t last_ms{0};
    };
    std::string m_path;
    std::unordered_map<std::string, series> m_series;
};

}   // namespace history
