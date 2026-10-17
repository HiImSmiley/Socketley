#pragma once
// The database's running half: its listener, its connections and the HTTP it speaks on them, who is asking, the
// documents it keeps, the changes it streams, and the calls a script's socketley.db and the daemon send it.
//
// An answer waits until what it rests on is on the disk: a write's own record, or the last change a read saw. One
// sync of the newest segment runs at a time, off the loop, and takes every record written while the one before ran.
// Changes are streamed to feeds and replicas once they are on the disk; a replica follows another database's stream
// on a thread of its own and writes what it is told.
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>
#include <time.h>

#include "db_schema.h"
#include "db_store.h"
#include "../idp/idp_session.h"
#include "../../shared/db_call.h"
#include "../../shared/event_loop.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/file_io.h"

class db_instance;

namespace socketley::db
{

class db_run : public io_handler
{
public:
    db_run(db_instance& owner, event_loop& loop);
    ~db_run() override;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool drained() const;
    size_t conn_count() const { return m_conns.size(); }
    std::string stats() const;

    // A call through the request channel, `{"method":...}` from socketley.db or `{"backup":...}` from the daemon,
    // answered under `ticket` as {"status":..,"body":..}.
    void call(uint64_t ticket, std::string_view json);

    // One request as the HTTP side and a script both put it: a method, a path below the database, and a body.
    struct answer
    {
        int status{200};
        std::string body;
        // An ETag for a document's version, and the change the answer may not be given before it is on the disk.
        uint64_t version{0};
        uint64_t needs{0};
    };
    answer execute(const principal& who, std::string_view method, std::string_view path, std::string_view body,
                   std::string_view if_match, std::string_view if_none_match);

private:
    struct conn
    {
        uint64_t id{0};
        int fd{-1};
        io_request rd{}, wr{};
        bool rd_pending{false}, wr_pending{false}, dead{false};
        // An answer waits for the disk, so nothing more is read off this connection meanwhile.
        bool waiting{false};
        bool keep_alive{true};
        std::string in;
        std::string out;
        size_t out_off{0};
        int64_t last{0};
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
        char rbuf[16384];
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

    void arm_accept();
    void accept_done(struct io_uring_cqe* cqe);
    std::shared_ptr<conn> conn_of(io_request* req);
    void arm_read(const std::shared_ptr<conn>& c);
    void read_done(const std::shared_ptr<conn>& c, int res);
    void serve(const std::shared_ptr<conn>& c);
    void resume(const std::shared_ptr<conn>& c);
    void flush(const std::shared_ptr<conn>& c);
    void write_done(const std::shared_ptr<conn>& c, int res);
    void close_conn(const std::shared_ptr<conn>& c);
    void arm_tick();
    void tick();

    int take_request(conn& c, request& rq, int& refusal);
    void handle(const std::shared_ptr<conn>& c, request& rq);
    std::string head(const conn& c, int status, std::string_view type, size_t length, std::string_view extra) const;
    void respond(const std::shared_ptr<conn>& c, int status, std::string_view body, std::string_view extra = {});
    std::string cors(const request& rq) const;
    bool who_of(const request& rq, principal& who, bool& by_cookie, std::string& refusal);
    void reload_files(std::string& why);

    // The disk: a sync begun when something waits on more than is there, and what then may be answered.
    void finish_turn();
    void synced(bool ok, uint64_t covered);
    void hold(waiter w);
    // Changes on the disk told to every stream that may see them, and kept for one that resumes.
    void publish();
    // A stream's changes from `since` on, or a reset and a whole copy when they are no longer kept.
    void open_feed(const std::shared_ptr<conn>& c, const request& rq, std::string coll, bool all, bool replica);
    void send_event(conn& c, const event& e);
    void pump_dump(const std::shared_ptr<conn>& c);
    bool sees(const conn& c, const event& e) const;

    // Work off the loop: a merge or a backup on a thread, told back through an eventfd.
    void start_job(std::unique_ptr<copy_job> job, uint64_t ticket);
    void jobs_done();
    void maybe_merge();
    void scheduled_backup();
    void arm_wake();

    // A replica's thread, following the stream of the database it copies, and the changes it hands the loop.
    void replica_main();
    void take_replicated();

    db_instance& m_owner;
    event_loop& m_loop;
    file_io m_io;
    store m_store;
    socketley::idp::session_verifier m_idp;
    std::vector<service_key> m_keys;
    std::vector<std::string> m_origins;
    int64_t m_schema_mtime{-1};
    int64_t m_keys_mtime{-1};
    int64_t m_files_checked{0};
    std::string m_schema_error;
    std::string m_keys_error;
    bool m_broken{false};

    int m_listen_fd{-1};
    io_request m_accept_req{};
    bool m_accept_pending{false};
    std::unordered_map<uint64_t, std::shared_ptr<conn>> m_conns;
    // The connections streaming changes, so a change is offered to them and not to every connection; one closed stays
    // until the walk after it, since close_conn() may run inside a walk.
    std::vector<std::shared_ptr<conn>> m_feeds;
    std::vector<std::shared_ptr<conn>> m_closing;
    uint64_t m_next_id{1};

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};

    std::vector<waiter> m_waiting;
    uint64_t m_durable{0};
    bool m_sync_inflight{false};
    // Changes written and not yet on the disk, and those on it kept for a stream that resumes.
    std::deque<event> m_unpublished;
    std::deque<event> m_history;
    size_t m_history_bytes{0};
    uint64_t m_history_from{1};

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
            feeds{0}, backups{0}, backup_failures{0}, replicated{0}, resets{0};
    } m_c;
};

}   // namespace socketley::db
