#pragma once
// The connections of a runtime that answers on a TCP port, over the ring: the listener and its accepts, every
// connection's one read and one write in flight, the requests it pipelines answered in order, and a connection
// let go only once the ring owes it nothing. The runtime says what a connection holds and answers what was read;
// db and idp each kept a copy of this, and a fix to one did not reach the other.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>

#include "../loop/event_loop.h"
#include "../loop/event_loop_definitions.h"

class runtime_instance;

namespace socketley::http
{

struct server_conn
{
    uint64_t id{0};
    int fd{-1};
    sockaddr_storage peer{};
    io_request rd{}, wr{};
    bool rd_pending{false}, wr_pending{false}, dead{false};
    // An answer is made on a later turn, so nothing more is read off this connection meanwhile.
    bool waiting{false};
    bool keep_alive{true};
    std::string in;
    // What the runtime has answered and is not yet going out; it appends here at any time.
    std::string out;
    // What the ring is sending, swapped in from `out`, which nothing touches until it has gone: an append to the
    // buffer a send still reads could move it under the kernel.
    std::string sending;
    size_t sent{0};
    int64_t last{0};
    char rbuf[16384];

    // The bytes answered and not yet gone, in flight or after it.
    size_t unsent() const { return sending.size() - sent + out.size(); }

    virtual ~server_conn() = default;
};

// What the runtime decides about its connections.
class conn_hooks
{
public:
    virtual ~conn_hooks() = default;
    // A new connection of the runtime's own kind, with whatever it keeps beside the common part.
    virtual std::shared_ptr<server_conn> make_conn() = 0;
    // The requests `c->in` holds answered into `c->out`, in order, until one waits or the bytes run out.
    virtual void serve(const std::shared_ptr<server_conn>& c) = 0;
    // Called once a connection is open and reading.
    virtual void accepted(const std::shared_ptr<server_conn>&) {}
    // Called when everything answered went; true when the runtime goes on writing to it itself.
    virtual bool written(const std::shared_ptr<server_conn>&) { return false; }
    // Whether a connection stays open with nothing left to write and no keep-alive, as a stream does.
    virtual bool keeps_open(const server_conn&) const { return false; }
    // Called as a connection is let go, before its descriptor closes.
    virtual void closing(const std::shared_ptr<server_conn>&) {}
};

class conn_server
{
public:
    conn_server(event_loop& loop, io_handler* owner, runtime_instance& rt, conn_hooks& hooks, size_t max_conns);

    // The port on `addr` (network order), every shard's at once when `shared`; -1 with `why` when it cannot be.
    bool listen_tcp(uint32_t addr, uint16_t port, bool shared, std::string& why);
    void start_accepting();
    // Stops accepting and closes every connection; what the ring still owes them is waited for by drained().
    void stop();
    bool listening() const { return m_listen_fd >= 0; }

    // True when the completion was one of this server's, and it is taken; the owner's own requests go first.
    bool on_cqe(io_request* req, struct io_uring_cqe* cqe);
    // A listener whose accept the ring had no room for is asked again here.
    void on_loop_turn();

    // What `out` holds sent, and a connection whose answers are done closed unless it is kept alive.
    void flush(const std::shared_ptr<server_conn>& c);
    // A connection whose answer waited takes up its requests again.
    void resume(const std::shared_ptr<server_conn>& c);
    void close_conn(const std::shared_ptr<server_conn>& c);
    // Those with nothing to do for longer than `idle_secs` closed.
    void sweep(int64_t now, int64_t idle_secs);

    size_t size() const { return m_conns.size(); }
    bool empty() const { return m_conns.empty(); }
    template <class F>
    void for_each(F&& f) const
    {
        for (const auto& [id, c] : m_conns)
            f(c);
    }

private:
    void arm_accept();
    void accept_done(struct io_uring_cqe* cqe);
    std::shared_ptr<server_conn> conn_of(io_request* req);
    void arm_read(const std::shared_ptr<server_conn>& c);
    void read_done(const std::shared_ptr<server_conn>& c, int res);
    void write_done(const std::shared_ptr<server_conn>& c, int res);

    event_loop& m_loop;
    io_handler* m_owner;
    runtime_instance& m_rt;
    conn_hooks& m_hooks;
    size_t m_max_conns;

    int m_listen_fd{-1};
    io_request m_accept_req{};
    bool m_accept_pending{false};
    bool m_stopped{false};
    std::unordered_map<uint64_t, std::shared_ptr<server_conn>> m_conns;
    // Let go, and still owed a read or a write by the ring.
    std::vector<std::shared_ptr<server_conn>> m_closing;
    uint64_t m_next_id{1};
};

}   // namespace socketley::http
