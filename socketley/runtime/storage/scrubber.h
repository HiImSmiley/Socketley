#pragma once
// The scrub of a storage shard: every version it holds read back at a steady pace, a whole pass in a period, and its
// bytes checked against the MD5 its header names, so a file the disk changed is found before a client reads it.
//
// ─── THE FILE ───────────────────────────────────────────────────────────────
//   <dir>/.scrub.<shard>   when the pass began, the passes made, and the last key read, by bucket and key in hex
//
// A multipart object is checked part by part against the ETag its parts make; an SSE-S3 or SSE-KMS one in its
// plaintext; an SSE-C one, whose key only its client has, and an object whose parts are not recorded, are passed over.
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>

#include "object_store.h"
#include "sse.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"

namespace socketley::storage
{

struct scrub_counters
{
    uint64_t objects{0};
    uint64_t bytes{0};
    uint64_t corrupt{0};
    uint64_t skipped{0};
    uint64_t passes{0};
    // How long the last whole pass took.
    uint64_t last_pass_ms{0};
};

class scrubber
{
public:
    using key_opener = std::function<bool(const object_meta& m, sse_key& out)>;
    // A version whose bytes are not what its header says.
    struct finding
    {
        std::string bucket;
        std::string key;
        std::string version_id;
        object_meta meta;
    };

    scrubber(event_loop& loop, file_io& io, object_store& store, hash_pool& hashes, key_opener keys,
             std::function<void(finding)> corrupt);
    ~scrubber();

    scrubber(const scrubber&)            = delete;
    scrubber& operator=(const scrubber&) = delete;

    // A whole pass in `secs`, 0 for none.
    void set_period(uint64_t secs) { m_period_ms = secs * 1000; }
    bool enabled() const { return m_period_ms != 0; }
    // Reads where the last run got to; blocking, so it runs at open.
    void open(const std::string& dir, uint32_t shard);
    // Once a second: the pace's budget is refilled and the next version read.
    void tick();
    void stop();

    const scrub_counters& counters() const { return m_c; }

    // The least a pass reads a second, so a small store is checked soon after its period begins.
    static constexpr uint64_t min_rate = 1u << 20;

private:
    struct job;
    void next();
    void check(std::string version_id);
    void opened(const std::shared_ptr<job>& j, open_result o);
    void read(const std::shared_ptr<job>& j);
    // Moves past every part read to its end; and whether all was read and its MD5 is the header's.
    static void next_part(job& j);
    static bool whole(job& j);
    void done(const std::shared_ptr<job>& j, bool corrupt, bool skipped);
    void save() const;

    event_loop&   m_loop;
    file_io&      m_io;
    object_store& m_store;
    hash_pool&    m_hashes;
    key_opener    m_keys;
    std::function<void(finding)> m_corrupt;
    scrub_counters m_c;
    uint64_t      m_period_ms{0};
    std::string   m_path;
    // The pass: when it began, the last key all of whose versions were read, and the versions of the key being read.
    int64_t       m_pass_began{0};
    std::string   m_bucket;
    std::string   m_key;
    std::deque<std::string> m_versions;
    std::string   m_current_bucket;
    std::string   m_current_key;
    // Bytes this second may still read, and whether a version is being read.
    int64_t       m_budget{0};
    bool          m_busy{false};
    // The version being read, whose reader and job hold each other while a read is out.
    std::weak_ptr<job> m_job;
    bool          m_stopped{false};
    int64_t       m_saved_ms{0};
    // The corrupt copies already told, by bucket, key, version and time, so a pass after tells only new ones.
    std::unordered_set<std::string> m_told;
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::storage
