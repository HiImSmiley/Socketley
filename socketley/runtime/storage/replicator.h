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
#include <unordered_set>
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
    // Another node of this runtime's cluster, which is sent every change of every bucket rather than a rule's.
    bool        node{false};
};

// A change another node of the cluster is sent, of one of the kinds the replicator's outbox names.
struct cluster_change
{
    // 'p' a version or object, 'm' a delete marker, 'g' its tags, 'd' an object of a bucket that keeps no versions
    // removed, 'x' a version removed for good, 'l' a version's lock, 'b' a bucket made, removed or configured.
    char        kind{0};
    std::string bucket;
    std::string key;
    std::string version_id;
    // The marker's or removal's stamp, in cluster_stamp_text()'s form.
    std::string stamp;
    // The tags of a 'g', and the record of an 'l' or a 'b', as the node's endpoint for them takes it.
    std::string payload;
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
    // Changes another node of the cluster took, and those it refused for good, which the four above do not count.
    uint64_t node_sent{0};
    uint64_t node_failed{0};
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
    // The other nodes of the cluster, each a target every change is sent to.
    void set_nodes(std::vector<replication_target> nodes);
    bool has_nodes() const { return m_nodes > 0; }

    // Opens the shard's outbox under `dir`, queues again what it holds, and queues every version of a replicated
    // bucket still PENDING with nothing queued for it; blocking, so it runs at start.
    bool open(const std::string& dir, uint32_t shard, const outbox::change_made& made, std::string& err);

    // Queues version `version_id` of `key`, with its tags, or the delete marker it is when `marker`, for every rule of
    // `cfg` that replicates it; true when anything was queued, whose entries sync() then waits for.
    bool enqueue(const replication_config& cfg, const std::string& bucket, const std::string& key,
                 const std::string& version_id, bool marker, std::string_view tags);
    // Queues the tags `tags` of version `version_id` of `key`, an empty set for tags removed, for every rule of `cfg`
    // that replicates the version as tagged so; true when anything was queued.
    bool enqueue_tags(const replication_config& cfg, const std::string& bucket, const std::string& key,
                      const std::string& version_id, std::string_view tags);
    // The same for a change about to be made, by `cfg` when it is given and to every other node as `node` when it is
    // given, its entries written and their sync started beside the change's, held back until settle(); returns the
    // change's ticket, 0 when nothing would be copied, and says in `copied` whether `cfg` copies it.
    uint64_t stage(std::string_view check, const replication_config* cfg, const std::string& bucket,
                   const std::string& key, const std::string& version_id, bool marker, std::string_view tags,
                   const cluster_change* node = nullptr, bool* copied = nullptr);
    // Queues `c` for every other node of the cluster; true when there is one.
    bool enqueue_nodes(const cluster_change& c);
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
    // Versions and delete markers waiting to be copied, across every target, and changes waiting for another node.
    uint64_t pending() const { return m_pending - m_node_pending; }
    uint64_t node_pending() const { return m_node_pending; }
    // Connections made to every target, and requests that went on one kept from the request before.
    uint64_t connects() const;
    uint64_t reuses() const;

private:
    struct task
    {
        uint64_t    id{0};
        bool        marker{false};
        // A version's tags, set or removed, rather than the version itself; `tags` is the set in tags_of()'s encoding.
        bool        tagging{false};
        std::string bucket;
        std::string key;
        std::string version_id;
        std::string dest_bucket;
        std::string storage_class;
        std::string tags;
        // A change for another node of the cluster, of cluster_change's kind, with its stamp and its record in `tags`.
        char        node_kind{0};
        std::string stamp;
        // When it was first answered with what waits for another change, which is given up on later.
        std::chrono::steady_clock::time_point waiting_since{};
    };
    struct job;
    // One target's queue, the copies it has in flight, each on a connection of its own, and its pause after a failure.
    struct lane
    {
        replication_target target;
        std::vector<std::unique_ptr<http_peer>> peers;
        std::deque<task> q;
        std::vector<std::shared_ptr<job>> active;
        // The keys of the copies in flight, by bucket NUL key, and whether one of them is a bucket's change.
        std::unordered_set<std::string> busy;
        bool        barrier{false};
        uint32_t    failures{0};
        std::chrono::steady_clock::time_point next_try{};
    };
    // The most copies a target has in flight, since each waits on the target's disk, and how far into its queue a
    // start looks for one whose key has none in flight.
    static constexpr size_t lane_width = 16;
    static constexpr size_t lane_scan  = 256;
    // How a copy ended: the destination has it, refused it for good, or should be asked again.
    enum class outcome : uint8_t { done, refused, retry };

    // The most a change sent to another node holds, a bucket's document being the largest.
    static constexpr size_t max_record_bytes = 2u << 20;

    lane* find_lane(std::string_view name, bool node);
    void add_lanes(std::vector<replication_target> targets, bool nodes);
    // The lane and the copies `cfg` makes of a version or delete marker, none when no rule or no target takes it.
    lane* tasks_for(const replication_config& cfg, const std::string& bucket, const std::string& key,
                    const std::string& version_id, bool marker, std::string_view tags, std::vector<task>& out);
    // An entry's bytes in the outbox.
    static std::string encode_task(const lane& l, const task& t);
    // Queues `t` for `l`, written to the outbox unless it came from there.
    void push(lane& l, task t, bool from_outbox);
    void start(lane& l);
    // Starts the steps of a copy.
    void run(lane& l, const std::shared_ptr<job>& j);
    // The connection a new copy of `l` goes on, one no copy in flight has.
    size_t free_slot(lane& l);
    std::unique_ptr<http_peer> new_peer(const replication_target& t);
    // The copy `j` of `l` ended so; `l` goes on with the next ones once its status is written.
    void ended(lane& l, const std::shared_ptr<job>& j, outcome o, uint64_t bytes);
    // Puts a copy that is tried again back at the front of its queue.
    void requeue(lane& l, const std::shared_ptr<job>& j);
    // Takes a copy out of its lane's flight.
    static void land(lane& l, const std::shared_ptr<job>& j);
    void back_off(lane& l);
    void arm_timer();
    // Writes `status` into the version, and runs `then` with whether it was written or is moot.
    void set_status(const std::string& bucket, const std::string& key, const std::string& version_id,
                    std::string_view status, std::function<void(bool)> then);

    // The steps of one copy, in replicator.cpp.
    void run_marker(lane& l, const std::shared_ptr<job>& j);
    void run_tags(lane& l, const std::shared_ptr<job>& j);
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
    // What an answer that is not a 2xx comes to, and the same for a change sent to another node.
    static outcome judge(const http_answer& a);
    static outcome judge_node(task& t, const http_answer& a);
    static outcome judge_of(task& t, const http_answer& a);
    // How long a change sent to another node waits for a bucket another of its changes makes or empties.
    static constexpr std::chrono::minutes node_wait_limit{15};
    // The steps of a change sent to another node, in replicator.cpp.
    void run_node(lane& l, const std::shared_ptr<job>& j);
    // A change for another node as each of its lanes queues it.
    static task node_task(const cluster_change& c);
    // The request that applies a record at a node's endpoint for a bucket's or a version's change.
    http_request node_record(const lane& l, const task& t) const;

    event_loop&   m_loop;
    file_io&      m_io;
    io_handler*   m_owner;
    object_store& m_store;
    hash_pool&    m_hashes;
    key_opener    m_keys;
    std::vector<std::unique_ptr<lane>> m_lanes;
    // How many of the lanes, the last ones, are the cluster's other nodes.
    size_t        m_nodes{0};
    replication_counters m_c;
    uint64_t      m_pending{0};
    uint64_t      m_node_pending{0};
    // Destinations still to take each version, by bucket, key and version id, so its status is written once.
    std::unordered_map<std::string, uint32_t> m_open;
    // The copies of each change staged and not yet settled, by ticket.
    struct staged_copies
    {
        lane* l{nullptr};
        std::vector<task> tasks;
        // The copies of the change for the other nodes, one per node.
        std::vector<std::pair<lane*, task>> node_tasks;
    };
    std::unordered_map<uint64_t, staged_copies> m_staged;
    bool          m_stopped{false};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    outbox        m_box;

    // One thread that resolves hosts, and the test aid's hosts file (SOCKETLEY_STORAGE_REPLICATION_HOSTS).
    hash_pool     m_resolver{1};
    bool          m_resolver_attached{false};
    std::string   m_hosts_file;

    io_request    m_timer_req{};
    struct __kernel_timespec m_timer_ts{};
    bool          m_timer_armed{false};
};

}   // namespace socketley::storage
