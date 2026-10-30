#pragma once
// What the daemon remembers of one metrics runtime's local feed: each family and label set it has been sent under an
// id, and the value last sent, so the next answer carries only what is new, changed or gone.
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <memory>

#include "../shared/ipc/worker_protocol.h"
#include "../shared/runtime/metric_catalog.h"
#include "../shared/util/transparent_string.h"

class runtime_manager;
class series_feed;

// The daemon's half of every local feed: the walk /metrics makes, its slow facts kept from one answer to the next.
class series_walk
{
public:
    explicit series_walk(runtime_manager& manager);
    ~series_walk();

    // The series_feed frame answering a series_pull `payload`, `state` made or started over as it asks; empty for a
    // pull that does not read.
    std::string answer(std::shared_ptr<void>& state, std::string_view payload);

private:
    struct facts;
    runtime_manager& m_manager;
    std::unique_ptr<facts> m_facts;
    std::string m_state_dir;
    std::string m_instance;
};

class series_feed
{
public:
    // The sink a walk hands every series to, building the frame answering `ticket`.
    class encoder
    {
    public:
        encoder(series_feed& feed) : m_feed(feed) {}
        void operator()(const socketley::metric_catalog::series& s);

    private:
        series_feed& m_feed;
    };

    // Begins an answer; `resync` forgets everything sent before, so ids start over.
    void begin(bool resync);
    // The frame's payload, with what went since the last answer and the ids it held freed for the next.
    std::string finish(uint64_t ticket, std::string_view instance);

    size_t keys() const { return m_keys.size(); }

private:
    struct key
    {
        uint32_t id;
        uint64_t bits;
        uint64_t seen;
    };

    void add(const socketley::metric_catalog::series& s);

    std::unordered_map<std::string, key, string_hash, string_equal> m_keys;
    // A family by its name, which the catalog's tables and the walk's own keep alive for the whole process.
    std::unordered_map<std::string_view, uint32_t> m_fams;
    std::vector<uint32_t> m_free;
    uint32_t m_next_key{0};
    uint64_t m_gen{0};
    uint8_t m_flags{0};
    std::string m_buf;
    worker_proto::series_feed_writer m_w;
};
