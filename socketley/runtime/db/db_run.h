#pragma once
// The database's running half: its listener, its connections and the HTTP it speaks on them, who is asking, the
// documents it keeps, the changes it streams, and the calls a script's socketley.db and the daemon send it.
//
// An answer waits until what it rests on is on the disk: a write's own record, or the last change a read saw. One
// sync of the newest segment runs at a time, off the loop, and takes every record written while the one before ran.
// Changes are streamed to feeds and replicas once they are on the disk; a replica follows another database's stream
// on a thread of its own and writes what it is told.
#include <optional>
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <chrono>
#include <vector>

#include <sys/socket.h>
#include <time.h>

#include "db_schema.h"
#include "../../shared/http/conn_server.h"
#include "db_shard.h"
#include "db_store.h"
#include "../idp/idp_session.h"
#include "../../shared/lua/db_call.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/runtime/latency_histogram.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/ipc/request_channel.h"
#include "../../shared/persist/file_stamp.h"

class db_instance;

namespace socketley::db
{

class db_run : public io_handler, public request_origin, public socketley::http::conn_hooks
{
public:
    db_run(db_instance& owner, event_loop& loop);
    ~db_run() override;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool drained() const;
    size_t conn_count() const { return m_http.size(); }
    std::string stats() const;

    // A call through the request channel, `{"method":...}` from socketley.db or `{"backup":...}` from the daemon,
    // answered under `ticket` as {"status":..,"body":..}.
    void call(uint64_t ticket, std::string_view json);
    // Another shard's write, taken by shard 0 and answered under `ticket` once it is on the disk.
    void cross_call(uint64_t ticket, std::string_view payload);
    // Shard 0's word that more of its log is on the disk, which a reading shard takes in.
    void nudged();
    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;

    // One request as the HTTP side and a script both put it: a method, a path below the database, and a body.
    struct answer
    {
        int status{200};
        std::string body;
        // An ETag for a document's version, and the change the answer may not be given before it is on the disk.
        uint64_t version{0};
        uint64_t needs{0};
        // The shard, plus one, the request is taken to: shard 0 for a write sent to a shard that reads its log.
        uint32_t forward{0};
    };
    // An answer whose body grows in the buffer the last one left, so a body is not built in a new one each time.
    answer spare_answer();
    // `sibling` when another shard sent it, which is never sent on.
    answer execute(const principal& who, std::string_view method, std::string_view path, std::string_view body,
                   std::string_view if_match, std::string_view if_none_match, bool sibling = false);

private:
    // A connection, and what it keeps when it streams changes.
    struct conn : socketley::http::server_conn
    {
        // A stream of changes: of one collection, or of all for a key or a replica, as `who` may see them.
        bool feed{false};
        bool all{false};
        bool replica{false};
        std::string coll;
        principal who;
        // A whole copy being sent before the changes after it: the documents, and how far it has come.
        std::vector<copy_job::item> dump;
        size_t dump_at{0};
        uint64_t dump_seq{0};
        // Where the stream stands: the last change offered to it and how many of its documents, and whether the
        // changes after them wait in the history for what it holds to drain.
        uint64_t at_seq{0};
        size_t at_skip{0};
        bool behind{false};
        // The turn stamp of the request being answered.
        uint64_t began_ns{0};
        // A read answered once the documents it needed from the disk were brought through the ring: those, by where
        // they lie, and how many times it has been tried.
        std::vector<store::fetched_doc> fetched;
        uint32_t probes{0};
    };

    struct request
    {
        std::string method;
        std::string path;
        std::string query;
        std::string body;
        std::string cookie;
        std::string authorization;
        std::string content_type;
        std::string if_match;
        std::string if_none_match;
        std::string last_event_id;
        std::string origin;
        std::string host;
    };

    // What waits for the disk: a connection's answer, or a channel call's.
    struct waiter
    {
        uint64_t needs{0};
        std::shared_ptr<conn> c;
        std::string held;
        uint64_t ticket{0};
        bool call{false};
    };

    std::shared_ptr<socketley::http::server_conn> make_conn() override;
    void serve(const std::shared_ptr<socketley::http::server_conn>& c) override;
    void accepted(const std::shared_ptr<socketley::http::server_conn>& c) override;
    bool written(const std::shared_ptr<socketley::http::server_conn>& c) override;
    bool keeps_open(const socketley::http::server_conn& c) const override;
    void closing(const std::shared_ptr<socketley::http::server_conn>& c) override;
    void arm_tick();
    void tick();

    int take_request(conn& c, request& rq, int& refusal);
    void handle(const std::shared_ptr<conn>& c, request& rq);
    // The documents a read could not take from memory brought through the ring, and the read made again with them.
    void fetch_and_retry(const std::shared_ptr<conn>& c, const request& rq, std::vector<location> wanted);
    // A response's head appended to `o`, with an ETag for `version` when it is one.
    void put_head(std::string& o, const conn& c, int status, std::string_view type, size_t length,
                  std::string_view extra, uint64_t version = 0) const;
    void respond(const std::shared_ptr<conn>& c, int status, std::string_view body, std::string_view extra = {},
                 uint64_t version = 0, bool head_only = false);
    std::string cors(const request& rq) const;
    bool who_of(const request& rq, principal& who, bool& by_cookie, std::string& refusal);
    void reload_files(std::string& why);

    // The disk: a sync begun when something waits on more than is there, and what then may be answered.
    void finish_turn();
    void synced(bool ok, uint64_t covered);
    void hold(waiter w);
    // Changes on the disk told to every stream that may see them, and kept for one that resumes.
    void publish();
    // Whether a stream is open on any shard of this runtime, or closed within resume_secs, which is when a resume may
    // come; the history is kept to history_bytes then and to idle_history_bytes otherwise.
    bool feeds_near(int64_t now);
    void feeds_here(int64_t now);
    void trim_history(size_t cap);
    // A stream's changes from `since` on, or a reset and a whole copy when they are no longer kept.
    void open_feed(const std::shared_ptr<conn>& c, const request& rq, std::string coll, bool all, bool replica);
    void open_feed_at(const std::shared_ptr<conn>& c, const request& rq, std::string coll, bool all, bool replica);
    void send_event(conn& c, const event& e);
    void pump_dump(const std::shared_ptr<conn>& c);
    // The stream's changes after its place, from the history, until it holds its window; a reset when they are gone.
    void pump_history(const std::shared_ptr<conn>& c);
    // A change's document, seen or not, counted as past for the stream's place.
    static void offered(conn& c, uint64_t seq);
    bool sees(const conn& c, const event& e) const;

    // Work off the loop: a merge or a backup on a thread, told back through an eventfd.
    void start_job(std::unique_ptr<copy_job> job, uint64_t ticket);
    void jobs_done();
    void maybe_merge();
    void scheduled_backup();
    void arm_wake();

    // A request taken to shard 0: a connection waits for the answer as it waits for a sync, a call for its ticket.
    struct crossed
    {
        std::weak_ptr<conn> c;
        uint64_t ticket{0};
        bool head{false};
        std::string allow;
    };
    bool cross(uint32_t shard, const crossing& what, crossed then);
    void deliver(const crossed& to, int status, std::string_view body, uint64_t version);
    // Shard 0's log on the disk up to its latest change: said to the shards that read it, which take it in before
    // they answer, so a read sees every write answered before it began.
    void publish_log();
    // How many streams this reading shard holds, said in its slot for shard 0 when it changes.
    void tell_feeds();
    // The channel address of shard `shard` of this runtime.
    const std::string& target_of(uint32_t shard);
    void nudge(uint32_t shard);
    void catch_up();
    void try_follow();
    uint64_t log_word(uint32_t k) const;

    // A replica's thread, following the stream of the database it copies, and the changes it hands the loop.
    void replica_main();
    void take_replicated();

    db_instance& m_owner;
    event_loop& m_loop;
    file_io m_io;
    socketley::http::conn_server m_http;
    store m_store;
    socketley::idp::session_verifier m_idp;
    std::vector<service_key> m_keys;
    std::vector<std::string> m_origins;
    std::optional<socketley::file_stamp> m_schema_stamp;
    std::optional<socketley::file_stamp> m_keys_stamp;
    int64_t m_files_checked{0};
    std::string m_schema_error;
    std::string m_keys_error;
    bool m_broken{false};

    // The connections streaming changes, so a change is offered to them and not to every connection; one closed stays
    // until the walk after it, since close_conn() may run inside a walk.
    std::vector<std::shared_ptr<conn>> m_feeds;
    // This shard's place among the runtime's: shard 0 writes, any other reads its log once it is open.
    uint32_t m_shard{0};
    uint32_t m_shards{1};
    bool m_reader{false};
    bool m_ready{false};
    uint64_t m_seen_layout{0};
    std::string m_follow_error;
    uint64_t m_told_durable{0}, m_told_layout{0};
    // The streams this reading shard told shard 0 it holds, in its own slot's first word.
    size_t m_told_feeds{0};
    std::unordered_map<uint64_t, crossed> m_crossed;
    uint64_t m_next_cookie{1};
    // One nudge in flight per reading shard, and whether more log came since: each parks a ticket on this shard's
    // channel until answered, and one per sync filled the table the reading shards' writes are parked in.
    std::vector<uint8_t> m_nudge_flying, m_nudge_owed;
    std::vector<std::chrono::steady_clock::time_point> m_nudge_sent;
    std::vector<std::string> m_targets;
    // The buffer the last answer's body was built in, kept for the next.
    std::string m_spare;

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};

    std::vector<waiter> m_waiting;
    uint64_t m_durable{0};
    bool m_sync_inflight{false};
    // A look again armed while a segment's seal holds the next sync back.
    bool m_seal_poll{false};
    // Changes written and not yet on the disk, and those on it kept for a stream that resumes.
    std::deque<event> m_unpublished;
    std::deque<event> m_history;
    size_t m_history_bytes{0};
    uint64_t m_history_from{1};
    // When this shard last held a stream, in wall seconds; the runtime's latest is in the shards' common word.
    int64_t m_feed_seen{0};

    // Jobs off the loop, and the eventfd they and the replica's thread wake it through.
    struct job_slot
    {
        std::unique_ptr<copy_job> job;
        std::thread th;
        std::atomic<bool> done{false};
        uint64_t ticket{0};
    };
    std::vector<std::unique_ptr<job_slot>> m_jobs;
    int m_wake_fd{-1};
    io_request m_wake_req{};
    uint64_t m_wake_buf{0};
    bool m_wake_armed{false};
    int64_t m_next_backup{0};
    // Backups the daemon asked for, by the number it was told, and how each ended.
    struct backup_result
    {
        bool done{false};
        bool ok{false};
        std::string file;
        std::string why;
        size_t documents{0};
    };
    std::unordered_map<uint64_t, backup_result> m_backups;
    uint64_t m_next_backup_id{1};

    std::thread m_replica;
    std::atomic<bool> m_replica_stop{false};
    std::mutex m_replica_mu;
    // Filled by the thread: changes, a reset before a whole copy, and the mark of where that copy was taken.
    std::vector<event> m_replica_in;
    bool m_replica_reset{false};
    uint64_t m_replica_mark{0};
    std::string m_replica_state;
    std::atomic<uint64_t> m_replica_seq{0};
    std::atomic<bool> m_replica_connected{false};

    bool m_stopped{false};

    struct counters
    {
        uint64_t reads{0}, writes{0}, queries{0}, syncs{0}, refused{0}, conflicts{0}, calls{0}, expired{0}, events{0},
            backups{0}, backup_failures{0}, replicated{0}, resets{0}, crossed{0}, crossings_served{0},
            caught_up{0}, reopened{0}, fetched{0}, nudges{0};
    } m_c;
    // A request taken to its answer put out, a wait for the disk or for shard 0 included, in loop turns.
    socketley::latency_histogram m_lat;
    void answered(const conn& c);
    std::string latency_line() const;
};

}   // namespace socketley::db
