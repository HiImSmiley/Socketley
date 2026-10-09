#pragma once
// One sync job at work: it walks its directory, asks its index what it last carried, and sends the difference.
//
// The walk is sliced over loop turns rather than done at once, so a directory of a million files does not stop the
// runtime from answering a `stop` while it is counted. One exchange is in flight per target, on the connection
// outbound_http keeps between them; a target that is unreachable holds up only its own queue.
//
// A failure to carry one file is not a failed runtime: it is counted, logged once, and tried again at the next walk.
// Only a configuration that cannot work -- a directory that is gone, credentials that are refused -- stops the job.
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <string>
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

    struct target
    {
        // As it was written on the command line, which is what the index keys by.
        std::string name;
        std::string bucket;
        // What stands before the bucket: a URL, a host and port, or the name of a runtime of this daemon.
        std::string where;
        // A runtime is named rather than addressed, and the daemon's map says its port only once it has arrived.
        bool        addressed{false};
        socketley::storage::http_target http;
        sync_credentials cred;
        std::unique_ptr<socketley::storage::http_peer> peer;
        std::deque<job> queue;
        bool in_flight{false};
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
    void pump(target& t);
    void carry(target& t, const job& j);
    void remove(target& t, const job& j);
    void finished(target& t, const job& j, const socketley::storage::http_answer& a);
    // Whether `rel` is one of --exclude's patterns.
    bool excluded(const std::string& rel) const;
    // The key an object is written under: --prefix and the path below --dir.
    std::string key_of(const std::string& rel) const;
    void note(const std::string& what);

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

    sync_stats m_stats;
    bool       m_stopped{false};
};

}   // namespace socketley::sync
