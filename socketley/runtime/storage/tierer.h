#pragma once
// The tiers a bucket's lifecycle moves versions to: other S3 endpoints, named as storage classes.  A version due to
// move is read and written to its tier with a signed PUT, and once the tier has it, its file here is put back as its
// header alone, under its key's lane while it is still the version that was read.  A read of a moved version goes
// to the tier a window at a time, so nothing a client sees changes but the storage class.
//
// ─── WHERE A VERSION GOES ───────────────────────────────────────────────────
//   <tier path>/<bucket>/<mtime ms>-<md5 hex>-<version id, or _>/<key>
//
// so the same version made on every node of a cluster is one object at the tier.  What the tier holds that no
// version here is any more, after a grace, is removed by a walk of its listing, which each shard makes of the keys
// it owns.
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "body_reader.h"
#include "object_store.h"
#include "outbound_http.h"
#include "replicator.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"

namespace socketley::storage
{

struct tier_counters
{
    // Versions moved to a tier, their bytes, and moves that did not finish.
    uint64_t moved{0};
    uint64_t bytes{0};
    uint64_t failed{0};
    // Windows read back from a tier for a client, and those that did not come.
    uint64_t reads{0};
    uint64_t read_failures{0};
    // Objects at a tier no version here is any more, removed there.
    uint64_t swept{0};
};

class tierer
{
public:
    // The most moves a shard makes at once, and connections it keeps to one tier.
    static constexpr size_t moves_at_once = 4;
    static constexpr size_t peers_per_tier = 8;
    // The largest version a single PUT moves.
    static constexpr uint64_t max_move = 5ull << 30;

    tierer(event_loop& loop, file_io& io, object_store& store, hash_pool& hashes);
    ~tierer();

    tierer(const tierer&)            = delete;
    tierer& operator=(const tierer&) = delete;

    // The tiers, each an endpoint whose URL path names the bucket, and a prefix in it, the versions go to.
    void set_tiers(std::vector<replication_target> tiers);
    bool has_tier(std::string_view name) const;
    bool enabled() const { return !m_tiers.empty(); }
    // The lifecycle's day, which the sweep's pace and grace follow.
    void set_day_ms(int64_t day_ms) { m_day_ms = day_ms; }

    // Moves version `version_id` of `key` (the object, when empty), which the index has as `m`, to `tier`; a version
    // already moving, moved, or one that cannot be is passed over.
    void move(const std::string& bucket, const std::string& key, const std::string& version_id, const object_meta& m,
              const std::string& tier);
    // Whether `m` is a version the move takes: in the clear or compressed, of one PUT's size, with its parts in its
    // header.
    static bool movable(const object_meta& m);

    // The plaintext [first, first + len) of the moved version `m`, null when its tier is not one of these.
    std::shared_ptr<body_reader> reader(const object_meta& m, uint64_t first, uint64_t len);

    // Once a second: stalled exchanges are ended and the sweep goes on.
    void tick();
    void stop();

    const tier_counters& counters() const { return m_c; }
    uint64_t moving() const { return m_moving.size(); }

private:
    struct tier
    {
        replication_target t;
        // The bucket at the endpoint, and the prefix of every key there, empty or ending in '/'.
        std::string bucket;
        std::string prefix;
        std::vector<std::unique_ptr<http_peer>> peers;
        // Exchanges waiting for a connection.
        std::deque<std::pair<http_request, std::function<void(http_answer)>>> waiting;
        bool list_told{false};
    };
    struct job;
    struct sweep;

    tier* find(std::string_view name);
    // Runs `rq` on a free connection of `t`, or once one is free.
    void exchange(tier& t, http_request rq, std::function<void(http_answer)> done);
    void pump(tier& t);
    std::string head(const tier& t, std::string_view method, const std::string& key, const std::string& query,
                     std::vector<std::pair<std::string, std::string>> headers, uint64_t length) const;
    void next_move();
    void opened(const std::shared_ptr<job>& j, open_result o);
    void uploaded(const std::shared_ptr<job>& j, http_answer a);
    void done(const std::shared_ptr<job>& j, bool moved);
    void sweep_next();
    void sweep_page(http_answer a);

    event_loop&   m_loop;
    file_io&      m_io;
    object_store& m_store;
    hash_pool&    m_hashes;
    std::vector<std::unique_ptr<tier>> m_tiers;
    tier_counters m_c;
    int64_t       m_day_ms{86400000};
    // Moves waiting and in flight, by bucket, key and version, so each is made once.
    std::deque<std::shared_ptr<job>> m_queue;
    std::unordered_set<std::string> m_moving;
    size_t        m_active{0};
    // The sweep of the tiers' listings: the tier being walked and where its listing is, and when the next begins.
    std::unique_ptr<sweep> m_sweep;
    std::chrono::steady_clock::time_point m_next_sweep{};
    bool          m_stopped{false};
    std::string   m_hosts_file;
    hash_pool     m_resolver{1};
    bool          m_resolver_attached{false};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
};

}   // namespace socketley::storage
