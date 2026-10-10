#pragma once
// The compression of a storage shard's cold versions: each version in the clear and of one part, once it has gone
// unwritten for the age asked for, is read, compressed chunk by chunk on a helper thread, written beside itself and
// put in its place under its key's lane, so a reader holds either file whole.  A version that does not get an
// eighth shorter is left as it is.
//
// ─── THE FILE ───────────────────────────────────────────────────────────────
//   <dir>/.compact.<shard>   the times of the versions passes took, and the last key read, by bucket and key in hex
//
// Each pass takes the versions written between the end of the last one's window and the age ago, so each version is
// looked at once.
#include <cstdint>
#include <deque>
#include <memory>
#include <string>

#include "object_store.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"

namespace socketley::storage
{

struct compact_counters
{
    uint64_t objects{0};
    // Versions read and left as they were, because they did not get shorter or changed while being read.
    uint64_t skipped{0};
    uint64_t failed{0};
    // The bytes of the versions compressed, and what they take on disk now.
    uint64_t bytes_in{0};
    uint64_t bytes_out{0};
    uint64_t passes{0};
};

class compactor
{
public:
    compactor(event_loop& loop, file_io& io, object_store& store, hash_pool& hashes);
    ~compactor();

    compactor(const compactor&)            = delete;
    compactor& operator=(const compactor&) = delete;

    // Versions unwritten for `secs` are compressed, 0 for none.
    // Saturated, since an age past what milliseconds can count is one that never comes.
    void set_age(uint64_t secs) { m_age_ms = secs > UINT64_MAX / 1000 ? UINT64_MAX : secs * 1000; }
    bool enabled() const { return m_age_ms != 0; }
    // Reads where the last run got to; blocking, so it runs at open.
    void open(const std::string& dir, uint32_t shard);
    // Once a second: the pace's budget is refilled and the next version taken.
    void tick();
    void stop();

    const compact_counters& counters() const { return m_c; }

    // What a pass reads a second at most, and the least a version holds to be worth it.
    static constexpr uint64_t rate     = 64u << 20;
    static constexpr uint64_t min_size = 4096;

private:
    struct job;
    struct candidate
    {
        std::string bucket, key, version_id;
        object_meta meta;
    };
    void next();
    void start(candidate c);
    void read(const std::shared_ptr<job>& j);
    void squeezed(const std::shared_ptr<job>& j, uint64_t n);
    void finish(const std::shared_ptr<job>& j);
    void synced(const std::shared_ptr<job>& j);
    void done(const std::shared_ptr<job>& j, int outcome);
    void save() const;

    event_loop&   m_loop;
    file_io&      m_io;
    object_store& m_store;
    hash_pool&    m_hashes;
    uint32_t      m_lane{0};
    compact_counters m_c;
    uint64_t      m_age_ms{0};
    std::string   m_path;
    // The pass takes versions written after `m_low` and up to `m_high`, the latter 0 between passes.
    int64_t       m_low{0};
    int64_t       m_high{0};
    std::string   m_bucket;
    std::string   m_key;
    std::deque<candidate> m_queue;
    // A version being read that waits for the next second's budget.
    std::shared_ptr<job> m_paused;
    int64_t       m_budget{0};
    bool          m_busy{false};
    bool          m_stopped{false};
    int64_t       m_saved_ms{0};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::storage
