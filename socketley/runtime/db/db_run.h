#pragma once
// The database's running half: its listener, its connections and the HTTP it speaks on them, who is asking, the
// documents it keeps, and the calls a script's socketley.db sends it.
//
// A write is answered once a sync of the journal that began after it ends: one sync is on the disk at a time and takes
// every write made while the one before ran, so a burst costs a few syncs rather than one each, and reads go on
// being answered meanwhile.
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>
#include <time.h>

#include "db_schema.h"
#include "db_store.h"
#include "../idp/idp_session.h"
#include "../../shared/event_loop.h"
#include "../../shared/db_call.h"
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

    // A script's call, `{"op":...}`, answered through the request channel under `ticket` as {"status":..,...}.
    void call(uint64_t ticket, std::string_view json);

    // One request as the HTTP side and a script both put it: a method, a path below the database, and a body.
    struct answer
    {
        int status{200};
        std::string body;
        // An ETag for a document's version, and whether the answer waits for the journal's sync.
        uint64_t version{0};
        bool durable{false};
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
        // A write's answer waits for the turn's sync, so nothing more is read off this connection meanwhile.
        bool waiting{false};
        bool keep_alive{true};
        std::string in;
        std::string out;
        // The answer held until the sync.
        std::string held;
        size_t out_off{0};
        int64_t last{0};
        char rbuf[16384];
    };

    struct request
    {
        std::string method;
        std::string path;
        std::string body;
        std::string cookie;
        std::string authorization;
        std::string content_type;
        std::string if_match;
        std::string if_none_match;
        std::string origin;
        std::string host;
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

    // The request at the front of `in`: 1 taken, 0 not whole yet, -1 malformed.
    int take_request(conn& c, request& rq, int& refusal);
    void handle(const std::shared_ptr<conn>& c, request& rq);
    std::string head(const conn& c, int status, std::string_view type, size_t length, std::string_view extra) const;
    void respond(const std::shared_ptr<conn>& c, int status, std::string_view body, std::string_view extra = {});
    // The CORS fields for a request's Origin, empty when it is not one this database answers.
    std::string cors(const request& rq) const;

    // Who a request is, from a key or a provider's token in Authorization or the provider's cookie; false with the
    // answer when it names somebody and does not prove it.
    bool who_of(const request& rq, principal& who, bool& by_cookie, std::string& refusal);
    // The answers of one sync, given once it is done: its own success, or the refusal every one of them becomes.
    void answer_synced(std::vector<std::shared_ptr<conn>>& held, std::vector<std::pair<uint64_t, std::string>>& calls,
                       bool ok);
    // The schema and keys files read again when they changed, at most once a second.
    void reload_files(bool first, std::string& why);
    void finish_turn();

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
    // The journal could not be synced: what is answered from memory may not be on the disk, so nothing is.
    bool m_broken{false};

    int m_listen_fd{-1};
    io_request m_accept_req{};
    bool m_accept_pending{false};
    std::unordered_map<uint64_t, std::shared_ptr<conn>> m_conns;
    std::vector<std::shared_ptr<conn>> m_closing;
    uint64_t m_next_id{1};

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};

    // What waits for the next sync: connections, and a script's calls by their tickets; and what the sync on the disk
    // now will answer, while the next turns' writes gather for the one after it.
    std::vector<std::shared_ptr<conn>> m_held;
    std::vector<std::pair<uint64_t, std::string>> m_held_calls;
    std::vector<std::shared_ptr<conn>> m_syncing;
    std::vector<std::pair<uint64_t, std::string>> m_syncing_calls;
    bool m_sync_inflight{false};

    bool m_stopped{false};

    struct counters
    {
        uint64_t reads{0}, writes{0}, queries{0}, syncs{0}, refused{0}, conflicts{0}, calls{0};
    } m_c;
};

}   // namespace socketley::db
