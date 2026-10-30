#pragma once
// This daemon's own series, as its /metrics would write them, taken without text: the daemon answers each pull with
// the families and label sets it has not sent yet, the values that changed and the series that went, and this side
// keeps the rest and appends every series at the time the pull was scheduled for.
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/ipc/worker_protocol.h"
#include "metrics_store.h"

namespace socketley::metrics
{

struct local_stats
{
    uint64_t frames{0};
    uint64_t bytes{0};
    uint64_t resyncs{0};
    // Pulls the daemon did not answer in time, after which the next one asks for everything.
    uint64_t lost{0};
    // Pulls that a lifecycle change asked for between two ticks.
    uint64_t extra{0};
    uint64_t series{0};
    int64_t  last_ms{0};
};

class local_feed
{
public:
    explicit local_feed(store& s) : m_store(s) {}

    // The frame asking for `stamp`, empty while a pull of its kind is still owed an answer; an `extra` one appends
    // only what is new or changed, for a runtime that came, went or changed state between two ticks.
    std::string pull(int64_t stamp, bool extra, int64_t now);
    // A pull the control socket would not take, so the next asks for everything.
    void refused(int64_t stamp);
    // A frame applied, and its series appended at the stamp it was asked for.
    void on_feed(std::string_view payload);
    // Whether the daemon's runtimes, by name and state, are other than the last map said, so a pull is worth it now.
    bool runtimes_changed(std::string_view runtime_map_payload);

    const local_stats& stats() const { return m_stats; }
    std::string_view instance() const { return m_instance; }

    // How long a pull may go unanswered before it is taken as lost.
    static constexpr int64_t answer_ms = 15'000;

private:
    friend struct feed_visitor;

    struct family
    {
        std::string name;
        std::string help;
        metric_type type{metric_type::untyped};
    };
    struct key
    {
        uint32_t series{no_series};
        double   v{0};
        bool     live{false};
        // Given a value by the frame being applied: new, or changed since the last.
        bool     moved{false};
    };
    struct pending
    {
        int64_t stamp;
        int64_t asked;
        bool    extra;
    };

    void append(int64_t stamp, bool only_moved);

    store& m_store;
    std::vector<family> m_fams;
    std::vector<key> m_keys;
    std::vector<pending> m_pending;
    std::string m_instance;
    bool m_resync{true};
    // The names and states of the daemon's runtimes, as the last map said them.
    std::string m_runtimes;
    local_stats m_stats;
    // The series ids a resync left behind, marked stale once the new set is known.
    std::vector<uint32_t> m_before;
    // up{job="socketley"}: 1 for each pull answered, 0 for each lost, as a scraped target has.
    uint32_t m_up{no_series};
    // Whether a resync has been applied since this process started.
    bool m_started{false};
    void put_up(int64_t stamp, double v);
    label_set m_scratch;
};

}   // namespace socketley::metrics
