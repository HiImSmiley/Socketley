#pragma once
// One sync job at work: it walks its directory, asks its index what it last carried, and sends the difference;
// between walks inotify names the files that changed, and only those are looked at.
//
// The walk is sliced over loop turns rather than done at once, so a directory of a million files does not stop the
// runtime from answering a `stop` while it is counted. Several exchanges are in flight per target, each on a
// connection outbound_http keeps, never two about one file; a target that is unreachable holds up only its own queue.
//
// A failure is not a failed runtime: it is counted, logged once while its reason stays the same, raised as an alert
// while it lasts, and tried again by a walk soon after. Nothing is removed from a target unless it is provably gone
// here, since a removal is the one thing a sync does that cannot be undone.
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "sync_index.h"

#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"
#include "../storage/outbound_http.h"

class sync_instance;

namespace socketley::sync
{

struct sync_stats
{
    // What the index holds, over every target.
    uint64_t indexed{0};
    uint64_t carried{0};
    uint64_t removed{0};
    uint64_t bytes_carried{0};
    uint64_t waiting{0};
    uint64_t failures{0};
    // Failures since the last thing that went through, which is what an alert is raised on.
    uint64_t failing{0};
    // Directories inotify is watching, 0 when the walk on --every is all that sees a change.
    uint64_t watched{0};
    // What `inout` brought here from the storage, and took away here because the storage no longer had it.
    uint64_t brought{0};
    uint64_t removed_here{0};
    // Files both sides changed since they were last the same, the storage's copy kept beside this side's.
    uint64_t conflicts{0};
    // Seconds since the last walk of the directory ended, and what went wrong last.
    uint64_t    last_run_secs{0};
    std::string last_error;
};

// What signs for a target and where its bucket is.
struct sync_credentials
{
    std::string access_key;
    std::string secret;
    std::string session_token;
    std::string region{"us-east-1"};
};

// Reads a credentials file: `key = value` lines, '#' to the end of a line a comment.
bool read_sync_credentials(const std::string& path, sync_credentials& out, std::string& why);

class sync_run : public io_handler
{
public:
    sync_run(sync_instance& rt, event_loop& loop);
    ~sync_run() override;

    sync_run(const sync_run&)            = delete;
    sync_run& operator=(const sync_run&) = delete;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;

    size_t open_connections() const;
    const sync_stats& stats() const { return m_stats; }
    // Whether the ring owes this run nothing, so a stopped one can be freed.
    bool drained() const;

private:
    // What one file still owes one target.
    struct job
    {
        // 'p' to carry it there, 'd' to take it away.
        char        kind{'p'};
        std::string path;
        uint64_t    size{0};
        int64_t     mtime_ns{0};
    };

    // A file carried in parts: which, from what descriptor, the upload's id and the parts the target has taken.
    struct upload
    {
        job j;
        std::shared_ptr<int> fd;
        std::string id;
        uint64_t part{0};
        std::vector<std::string> etags;
    };

    // A file the storage has that this side is to have, brought in pieces into a file of its own below --dir and
    // given its name once it is whole.
    struct fetch
    {
        // Where it goes below --dir, and which object it is, as the index names it: the same but for a conflict.
        std::string rel, key_rel;
        std::string etag;
        uint64_t size{0}, got{0};
        std::string temp;
        int fd{-1};
        bool conflict{false};
        // This side's file as it was when the fetch was decided, so one changed meanwhile is not written over.
        bool here{false};
        uint64_t here_size{0};
        int64_t here_mtime{0};
    };

    // One exchange at a time, on a connection kept between them, and the path it is about.
    struct lane
    {
        std::unique_ptr<socketley::storage::http_peer> peer;
        bool busy{false};
        std::string path;
        std::unique_ptr<upload> mpu;
        std::unique_ptr<fetch> get;
    };

    struct target
    {
        // Moved and never copied: the lanes are its own, and a vector that grows would otherwise try to copy them.
        target() = default;
        target(const target&) = delete;
        target& operator=(const target&) = delete;
        target(target&&) = default;
        target& operator=(target&&) = default;

        // As it was written on the command line, which is what the index keys by.
        std::string name;
        std::string bucket;
        // What stands before the bucket: a URL, a host and port, or the name of a runtime of this daemon.
        std::string where;
        // A runtime is named rather than addressed, and the daemon's map says its port only once it has arrived.
        bool        addressed{false};
        // The runtime of this daemon it names, empty for an address.
        std::string runtime;
        socketley::storage::http_target http;
        sync_credentials cred;
        // The exchanges in flight to it, one per lane, each on a connection of its own; empty until it is addressed.
        std::vector<std::unique_ptr<lane>> lanes;
        std::deque<job> queue;
        // Said once per walk, so a host that is down does not fill the log.
        bool told{false};
    };

    bool resolve_targets(std::string& why);
    // The target's address, looked up in the daemon's map when a runtime was named; false while it is not known yet.
    bool ensure_address(target& t);
    void begin_walk();
    // Takes the next slice of the walk; true once the walk has ended.
    bool walk_slice();
    void end_walk();
    // Queues what one path owes each target, as the walk would for it alone.
    void check_path(const std::string& rel);
    // Whether a path the index holds is gone from this side for certain, rather than unreadable or excluded now.
    bool provably_gone(const std::string& rel) const;
    // Whether `full` resolves to a place below --dir, with the place it resolves to in `real`.
    bool inside(const std::string& full, std::string* real) const;

    // inotify: one watch per directory the walk passes, a read standing on the descriptor, and what it said.
    void watch_dir(const std::string& rel);
    void arm_watch();
    void on_watch(int64_t res);
    void pump(target& t);
    // A walk in retry_secs, whatever --every says, for what a target refused or did not answer.
    void owe_retry();
    // A request for `rel`'s key, signed, with `extra` among its headers and `body` held whole.
    socketley::storage::http_request signed_request(const target& t, std::string_view method, const std::string& rel,
                                                    std::string_view query,
                                                    std::vector<std::pair<std::string, std::string>> extra,
                                                    std::string body = {}) const;
    // [off, off + len) of `fd` as the request's body.
    void body_from(const target& t, socketley::storage::http_request& rq, const std::shared_ptr<int>& fd,
                   uint64_t off, uint64_t len) const;
    void carry(target& t, lane& l, const job& j);
    void begin_upload(target& t, lane& l, const job& j, std::shared_ptr<int> fd);
    void send_part(target& t, lane& l);
    void complete_upload(target& t, lane& l);
    // Gives up on the upload in progress and asks the target to drop its parts; with `why`, that is the failure.
    void abort_upload(target& t, lane& l, const std::string& why);
    void remove(target& t, lane& l, const job& j);
    // What an exchange came to: a file the target now holds, or an answer that is not that.
    void carried(target& t, lane& l, const job& j, std::string etag);
    void refused(target& t, lane& l, const job& j, const socketley::storage::http_answer& a);
    // Whether `rel` is one of --exclude's patterns.
    bool excluded(const std::string& rel) const;

    // ── the storage's side, for --mode inout: listed, set against the index and this side, and brought here ──
    struct remote_obj
    {
        std::string etag;
        uint64_t size{0};
    };
    bool two_way() const;
    void begin_pull();
    void list_page(target& t, lane& l);
    void decide_pull(target& t);
    void pump_fetch(target& t);
    void fetch_range(target& t, lane& l);
    void fetch_done(target& t, lane& l, bool ok);
    void finish_pull();
    // A request of the bucket itself rather than of a key in it, as a listing is.
    socketley::storage::http_request signed_bucket_request(const target& t, std::string_view query) const;
    bool m_pull_due{false};
    bool m_pulling{false};
    std::string m_list_token;
    std::unordered_map<std::string, remote_obj> m_remote;
    std::deque<fetch> m_fetches;
    // The key an object is written under: --prefix and the path below --dir.
    std::string key_of(const std::string& rel) const;
    // A failure: counted, kept as the last error, and logged once per change of what it says.
    void note(const std::string& what);
    // Something the operator should know that is no failure of the job: logged once, and not counted.
    void say(const std::string& what);

    sync_instance& m_rt;
    event_loop&    m_loop;
    file_io        m_io;
    hash_pool      m_resolver;
    sync_index     m_index;
    std::vector<target> m_targets;
    std::vector<std::string> m_exclude;

    // The walk in progress, and what it has seen, so what it has not seen is what is gone.
    bool m_walking{false};
    std::unique_ptr<std::filesystem::recursive_directory_iterator> m_iter;
    std::vector<std::string> m_seen;
    std::chrono::steady_clock::time_point m_walk_started{};
    std::chrono::steady_clock::time_point m_last_walk{};
    std::chrono::steady_clock::time_point m_last_tick{};
    // A walk owed after a target stopped answering, so a job with --every never still tries again.
    std::chrono::steady_clock::time_point m_retry_at{};

    int m_inotify{-1};
    bool m_watch_armed{false};
    // Said once: the watches ran out, so changes below the rest are seen at the next walk only.
    bool m_watch_full{false};
    std::unique_ptr<char[]> m_watch_buf;
    std::unordered_map<int, std::string> m_watches;
    // Paths inotify named, looked at once the walk in progress, if any, is over.
    std::unordered_set<std::string> m_changed;
    // A directory came or went, or the kernel dropped events: only a walk can say what changed.
    bool m_rewalk{false};
    // The last failure written to the log, so one that repeats each walk is said once.
    std::string m_logged;

    // The timeout that turns the loop when nothing else would.
    void arm_tick(bool soon);
    // One turn's work: the walk's next slice, what inotify named, the queues, and the walks owed.
    void turn();
    __kernel_timespec m_tick_ts{};
    io_request m_tick_req{};
    bool m_tick_armed{false};

    // --dir as the filesystem names it, links resolved, which every link's target is held against.
    std::string m_root_real;

    sync_stats m_stats;
    bool       m_stopped{false};
};

}   // namespace socketley::sync
