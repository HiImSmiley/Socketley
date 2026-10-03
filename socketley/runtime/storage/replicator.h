#pragma once
// The replication of a storage runtime's buckets to other S3 endpoints: a durable outbox per shard, filled by the
// owner of a key before the change is answered, and the signed requests that empty it, each on the loop.
//
// ─── THE OUTBOX ─────────────────────────────────────────────────────────────
//   <dir>/.replicate/outbox.<shard>   an entry is one version or delete marker for one destination bucket: 'P' or
//                                     'M', then the target, the bucket, the key, the version id, the destination
//                                     bucket and the storage class, each length-prefixed
//
// A version is written PENDING and becomes COMPLETED once every destination has it, or FAILED once one refused it; its
// entry is retired after its status is written, so a crash between the two copies the version again.
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "object_store.h"
#include "outbound_http.h"
#include "outbox.h"
#include "s3_replication.h"
#include "sse.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"

namespace socketley::storage
{

// An S3 endpoint replicas are written to, the region its signatures name and the credentials it signs with.
struct replication_target
{
    std::string name;
    http_target http;
    std::string region;
    std::string access_key;
    std::string secret;
};

// The targets a file's text names, one `name url region access_key secret [ca=file]` per line, a field beginning with
// '#' beginning a comment; false with `why` for a line that is none of these or a name given twice.
bool parse_replication_targets(std::string_view text, std::vector<replication_target>& out, std::string& why);

// The same read from `path`.
bool load_replication_targets(const std::string& path, std::vector<replication_target>& out, std::string& why);

struct replication_counters
{
    // Versions and delete markers a destination took, those it refused for good, and attempts that are tried again.
    uint64_t completed{0};
    uint64_t failed{0};
    uint64_t retries{0};
    // Body bytes a destination took.
    uint64_t bytes{0};
};

class replicator
{
public:
    // The pause after a target's first failure, doubled by each further one up to the cap.
    static constexpr int64_t backoff_first_ms = 250;
    static constexpr int64_t backoff_cap_ms   = 8000;
    // How long a destination may take to answer a request it has whole, which for a large completion is a while.
    static constexpr int answer_secs = 120;

    // What opens an encrypted version's data key, false when it cannot be opened here.
    using key_opener = std::function<bool(const object_meta& m, sse_key& out)>;

    // `owner` is the handler the timer's completion is delivered to, which hands it to on_timer().
    replicator(event_loop& loop, file_io& io, io_handler* owner, object_store& store, hash_pool& hashes,
               key_opener keys);
    ~replicator();

    replicator(const replicator&)            = delete;
    replicator& operator=(const replicator&) = delete;

    void set_targets(std::vector<replication_target> targets);
    bool has_target(std::string_view name) const;

    // Opens the shard's outbox under `dir`, queues again what it holds, and queues every version of a replicated
    // bucket still PENDING with nothing queued for it; blocking, so it runs at start.
    bool open(const std::string& dir, uint32_t shard, const outbox::change_made& made, std::string& err);

    // Queues version `version_id` of `key`, with its tags, or the delete marker it is when `marker`, for every rule of
    // `cfg` that replicates it; true when anything was queued, whose entries sync() then waits for.
    bool enqueue(const replication_config& cfg, const std::string& bucket, const std::string& key,
                 const std::string& version_id, bool marker, std::string_view tags);
    // The same for a change about to be made, its entries written and their sync started beside the change's, held
    // back until settle(); returns the change's ticket, 0 when nothing would be copied.
    uint64_t stage(std::string_view check, const replication_config& cfg, const std::string& bucket,
                   const std::string& key, const std::string& version_id, bool marker, std::string_view tags);
    // Runs `then` once the entries of the change `ticket` names are synced.
    void staged(uint64_t ticket, std::function<void()> then) { m_box.staged(ticket, std::move(then)); }
    // The change was made or not: its copies are queued or dropped, and `then` runs once that record is synced.
    void settle(uint64_t ticket, bool made, std::function<void()> then);
    // Runs `then` once every entry queued so far is synced.
    void sync(std::function<void()> then) { m_box.sync(std::move(then)); }

    // Whether `req` is the timer's, which the owner then hands to on_timer().
    bool owns(const io_request* req) const { return req == &m_timer_req; }
    void on_timer();

    // Every copy in progress is given up and nothing new is started.
    void stop();

    const replication_counters& counters() const { return m_c; }
    // Versions and delete markers waiting to be copied, across every target.
    uint64_t pending() const { return m_pending; }

private:
    struct task
    {
        uint64_t    id{0};
        bool        marker{false};
        std::string bucket;
        std::string key;
        std::string version_id;
        std::string dest_bucket;
        std::string storage_class;
    };
    struct job;
    // One target's queue, the one copy it has in flight, and its pause after a failure.
    struct lane
    {
        replication_target target;
        std::unique_ptr<http_peer> peer;
        std::deque<task> q;
        std::shared_ptr<job> active;
        uint32_t    failures{0};
        std::chrono::steady_clock::time_point next_try{};
    };
    // How a copy ended: the destination has it, refused it for good, or should be asked again.
    enum class outcome : uint8_t { done, refused, retry };

    lane* find_lane(std::string_view name);
    // The lane and the copies `cfg` makes of a version or delete marker, none when no rule or no target takes it.
    lane* tasks_for(const replication_config& cfg, const std::string& bucket, const std::string& key,
                    const std::string& version_id, bool marker, std::string_view tags, std::vector<task>& out);
    // An entry's bytes in the outbox.
    static std::string encode_task(const lane& l, const task& t);
    // Queues `t` for `l`, written to the outbox unless it came from there.
    void push(lane& l, task t, bool from_outbox);
    void start(lane& l);
    // The copy at the front of `l`'s queue ended so; `l` goes on with the next one once its status is written.
    void ended(lane& l, outcome o, uint64_t bytes);
    void back_off(lane& l);
    void arm_timer();
    // Writes `status` into the version, and runs `then` with whether it was written or is moot.
    void set_status(const std::string& bucket, const std::string& key, const std::string& version_id,
                    std::string_view status, std::function<void(bool)> then);

    // The steps of one copy, in replicator.cpp.
    void run_marker(lane& l, const std::shared_ptr<job>& j);
    void run_put(lane& l, const std::shared_ptr<job>& j);
    void opened(lane& l, const std::shared_ptr<job>& j, open_result o);
    void send_single(lane& l, const std::shared_ptr<job>& j);
    void mpu_create(lane& l, const std::shared_ptr<job>& j);
    void mpu_part(lane& l, const std::shared_ptr<job>& j);
    void mpu_complete(lane& l, const std::shared_ptr<job>& j);
    // Gives up the upload a failed copy began, then ends the copy so.
    void mpu_abort(lane& l, const std::shared_ptr<job>& j, outcome o);
    // A signed request of `method` for `path_and_query` with `headers`, its body `length` bytes long.
    std::string signed_head(const lane& l, std::string_view method, const std::string& path, const std::string& query,
                            std::vector<std::pair<std::string, std::string>> headers, uint64_t length) const;
    // A body source that reads [first, first + len) of the job's version as plaintext.
    http_body_source body_of(const std::shared_ptr<job>& j, uint64_t first, uint64_t len);
    void exchange(lane& l, const std::shared_ptr<job>& j, http_request rq,
                  std::function<void(lane&, const std::shared_ptr<job>&, http_answer)> then);
    // What an answer that is not a 2xx comes to.
    static outcome judge(const http_answer& a);

    event_loop&   m_loop;
    file_io&      m_io;
    io_handler*   m_owner;
    object_store& m_store;
    hash_pool&    m_hashes;
    key_opener    m_keys;
    std::vector<std::unique_ptr<lane>> m_lanes;
    replication_counters m_c;
    uint64_t      m_pending{0};
    // Destinations still to take each version, by bucket, key and version id, so its status is written once.
    std::unordered_map<std::string, uint32_t> m_open;
    // The copies of each change staged and not yet settled, by ticket.
    struct staged_copies
    {
        lane* l{nullptr};
        std::vector<task> tasks;
    };
    std::unordered_map<uint64_t, staged_copies> m_staged;
    bool          m_stopped{false};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    outbox        m_box;

    // One thread that resolves hosts, and the test aid's hosts file (SOCKETLEY_STORAGE_REPLICATION_HOSTS).
    hash_pool     m_resolver{1};
    std::string   m_hosts_file;

    io_request    m_timer_req{};
    struct __kernel_timespec m_timer_ts{};
    bool          m_timer_armed{false};
};

}   // namespace socketley::storage
