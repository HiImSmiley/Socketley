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
    io_request rd{}, wr{}, cn{};
    bool rd_pending{false}, wr_pending{false}, cn_pending{false}, dead{false};
    // The far side wrote its last and this one may still write, for a runtime whose read_ended() keeps it open.
    bool read_eof{false};
    // An answer is made on a later turn, so nothing more is read off this connection meanwhile.
    bool waiting{false};
    // Nothing is read while more than conn_server::out_max is owed to the client; its going takes reading up again.
    bool held{false};
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
    // The far side wrote its last; true keeps the connection open for what is still to be written, which the runtime
    // then closes itself.
    virtual bool read_ended(const std::shared_ptr<server_conn>&) { return false; }
    // Whether a connection that is not kept alive may have its last answer sent by send() and be closed in that turn;
    // false for one whose written() still has work after its last answer.
    virtual bool fin_at_once(const server_conn&) const { return true; }
    // A dial() came to `res`: 0 connected and reading, or a negative errno, after which the connection is let go.
    virtual void connected(const std::shared_ptr<server_conn>&, int /*res*/) {}
};

class conn_server
{
public:
    // What may be owed to one client before its next request waits for it to read.
    static constexpr size_t out_max = 1u << 20;
    conn_server(event_loop& loop, io_handler* owner, runtime_instance& rt, conn_hooks& hooks, size_t max_conns);

    // The port on `addr` (network order), every shard's at once when `shared`; -1 with `why` when it cannot be.
    bool listen_tcp(uint32_t addr, uint16_t port, bool shared, std::string& why);
    // A Unix socket at `path`, made 0660 in place of whatever was there; false with `why` when it cannot be.
    bool listen_unix(const std::string& path, std::string& why);
    // A connection to `addr`, from the IPv4 source `from_v4` (network order) unless it is 0, its outcome told by the
    // hooks' connected(); null with `why` when none could be begun.
    std::shared_ptr<server_conn> dial(const sockaddr_storage& addr, socklen_t len, std::string& why, uint32_t from_v4 = 0);
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
    // Whether a runtime's serve() takes the next request: not after one that closes the connection, nor while the
    // client owes reading more than out_max of the answers.
    static bool takes_more(const server_conn& c)
    {
        return !c.dead && !c.waiting && c.keep_alive && !c.in.empty() && c.unsent() <= out_max;
    }
    // A connection whose answer waited takes up its requests again.
    void resume(const std::shared_ptr<server_conn>& c);
    void close_conn(const std::shared_ptr<server_conn>& c);
    // Those with nothing to do for longer than `idle_secs` closed.
    void sweep(int64_t now, int64_t idle_secs);
    // The accept again, once one that ran out of descriptors may succeed.
    void resume_accept();

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
    void connect_done(const std::shared_ptr<server_conn>& c, int res);
    // After serve(): the next read, unless the connection waits, closes, or owes its client too much.
    void after_serve(const std::shared_ptr<server_conn>& c);
    // A connection that is not kept alive, its last answer sent by a direct send() and closed in this turn, so the FIN
    // leaves before the client's and the TIME-WAIT is this side's; false, and nothing done, unless nothing is in flight.
    bool finish_now(const std::shared_ptr<server_conn>& c);
    // The connection let go of by the ring at last: nothing of it is in flight any more.
    void forget_if_idle(const std::shared_ptr<server_conn>& c);

    event_loop& m_loop;
    io_handler* m_owner;
    runtime_instance& m_rt;
    conn_hooks& m_hooks;
    size_t m_max_conns;

    int m_listen_fd{-1};
    std::string m_unix_path;
    io_request m_accept_req{};
    bool m_accept_pending{false};
    // The last accept failed for want of descriptors and none is armed.
    bool m_accept_starved{false};
    bool m_stopped{false};
    std::unordered_map<uint64_t, std::shared_ptr<server_conn>> m_conns;
    // Let go, and still owed a read or a write by the ring.
    std::vector<std::shared_ptr<server_conn>> m_closing;
    uint64_t m_next_id{1};
};

}   // namespace socketley::http
