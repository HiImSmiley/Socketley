#pragma once
// A request one runtime makes of another, and the answer coming back later.
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// `server --cache <name>` used to be four lines:
//
//     auto* cache_rt = get_runtime_manager()->get(cname);
//     auto* cache    = static_cast<cache_instance*>(cache_rt);
//     std::string resp = cache->execute(msg.substr(6));
//     send_to(sender, resp);
//
// The server took a pointer to another runtime's object, ran that runtime's
// command interpreter on its own stack — inside the completion handler that had
// just read the client's bytes — and wrote the answer back.  It worked, and it
// was the last thing in the tree holding the daemon to a single address space.
// A pointer cannot be sent over a socket.  A command and its answer can.
//
// This is the same move endpoint_table.h makes for proxy backends, one step
// further along: there the answer is a host and a port, small enough to publish
// in advance; here the answer has to be computed per request, so what is
// published is *who can compute it*, and the request goes to them as bytes.
//
// ─── WHAT MAKES IT ASYNCHRONOUS, AND WHY THAT MATTERS ───────────────────────
//
// post() never returns an answer.  It takes the request and says whether it was
// accepted; the answer arrives later at request_origin::on_request_reply(), on
// a different turn of the event loop, carrying nothing but the cookie the
// caller posted with.
//
// That shape is the whole point.  A call that returns the answer can only ever
// be implemented by computing it before returning, which is the thing being
// removed.  A call that promises an answer *later* can be implemented by
// executing it in this process now, or by writing it to a socket and waiting —
// and the asking side cannot tell the difference, so the day the cache moves
// into its own process nothing on the asking side changes.
//
// The deferral is real and not a formality: an accepted request is queued and a
// no-op is put in the ring, and the queue is not touched again until that
// completion comes back.  So the cache's interpreter runs inside a completion
// the *channel* owns, never inside the server's read handler, and the server's
// message path is exactly as long as it was before.  It costs one SQE and one
// CQE per drained batch — not per request — and one round trip of latency on
// the answer.  That is the honest price, and it is paid by `cache` commands
// alone.
//
// ─── ORDERING ───────────────────────────────────────────────────────────────
//
// One queue, drained front to back, so replies to one origin come back in the
// order it posted them.  This is a promise of the channel and not an accident
// of the in-process transport: a client that pipelines `cache get a` and
// `cache get b` down one socket has no other way to tell which answer is which,
// and a socket-backed transport has to keep it too — one pipelined connection
// per target, replies in order, which is what the cache's own wire protocol
// already does.
//
// Nothing is promised about the order of a cache reply against other traffic on
// the same connection.  A broadcast goes to everyone but the sender and a cache
// reply goes to the sender alone, so there is no interleaving to define.
//
// ─── LIFETIME ───────────────────────────────────────────────────────────────
//
// Who may free what, stated once:
//
//   * The channel owns its queue entries, and each carries its own copy of the
//     target name and the payload.  Nothing in the queue points into a
//     connection struct, so a connection can be closed, pooled and handed to
//     the next client with a request of its own still in flight — which is
//     exactly what happens when a client aborts mid-request.
//
//   * An origin is a pointer, so it is registered.  The first post() registers
//     it; drop_origin() revokes it, and from that moment every queued request
//     it made is discarded and no reply is delivered to it.  A runtime must
//     call drop_origin() before it is destroyed — teardown() and the destructor
//     both, because a runtime can be freed without ever having been stopped.
//     This is deliberately the same arrangement event_loop uses for io_handler:
//     registering implicitly, because forgetting to register would silently
//     swallow the work, and revoking explicitly, because forgetting to revoke
//     only costs the check.
//
//   * A sink is a pointer too, and the manager republishes the whole table on
//     every membership change — create, start, stop, remove, rename — exactly
//     as it republishes the endpoint table.  The lookup happens when a request
//     is drained, not when it is posted, so a cache that stops in between is
//     answered "no such target" rather than reached through a stale pointer.
//
//   * The channel's own no-op is an ordinary submission with an ordinary owner
//     token.  If the channel is detached while one is in flight the loop drops
//     that completion like any other, and attach() clears the armed flag once
//     the loop says nothing is outstanding — the same recovery every runtime
//     here performs on its timers.
//
// ─── BOUNDS ─────────────────────────────────────────────────────────────────
//
// The queue is capped in entries and in bytes, and post() refuses beyond either.
// Without that, one client pipelining `cache` commands down a socket is a
// memory-exhaustion path: the server reads as fast as the client writes and the
// queue only drains once per loop turn.  What a refusal means is the caller's
// business — the server closes the connection rather than answer out of order.
//
// The cap is split in two, because two very different things share it.  A
// request a client is holding a socket open for is worth refusing loudly; a
// server's `--cache` auto-store, which nobody asked for and nobody is waiting
// on, is worth dropping quietly.  Left to compete on equal terms the second
// starves the first: one 16 KB read is two thousand messages and two thousand
// stores, and the `cache get` behind them would be refused for traffic the
// client did not send.  So background work may only fill the queue to
// MAX_PENDING_BACKGROUND and the rest is reserved.
//
// A dropped background request is real loss — the synchronous version stored
// every message, because it stored them on the message path — and it is counted
// rather than hidden.  It is also what any out-of-process implementation would
// have to do: a fire-and-forget write to a socket whose buffer is full has the
// same three choices and blocking is not one of them.
//
// One more bound, on time rather than memory: a drain answers at most
// MAX_DRAIN_BATCH requests per wakeup and re-arms for the rest, so a burst
// cannot hold the event loop for as long as it takes to serve all of it.

#include <cstddef>
#include <cstdint>
#include <deque>
#include <unordered_map>
#include <string>
#include <string_view>
#include <vector>

#include "endpoint_table.h"
#include "event_loop_definitions.h"

class event_loop;

enum class request_status : uint8_t
{
    ok = 0,
    no_target,    // nothing answers to that name — never started, or stopped in between
    overloaded,   // the channel was full when the request was posted
    dropped       // the channel gave the request up: it was detached under it
};

// What a request is worth under pressure.  See the bounds note above.
enum class request_class : uint8_t
{
    client = 0,   // somebody is holding a socket open for the answer
    background    // nobody is waiting; droppable, and dropped first
};

const char* request_status_text(request_status st);

// What answers requests addressed to a runtime name.  A cache registers itself
// through runtime_instance::as_request_sink(); across a process boundary the
// daemon would register a socket-backed sink instead and nothing on the asking
// side would change.
//
// ─── WHAT SUCH A SINK WOULD SPEAK, AND WHAT IT MUST NOT ─────────────────────
//
// Settled on 2026-08-03, because the obvious two answers are both wrong and
// each looks right until it is tried.
//
// NOT the cache's text protocol.  Its replies are not self-delimiting: ten
// commands answer over several lines and end with `end\n`, so a client can
// only tell where one reply stops if it knows, per command, which kind it is.
// That puts the cache's command table in a second place, where it will rot.
//
// NOT RESP either, which would be self-delimiting.  Translating the payload
// into it is the problem: cache_instance::process_command() splits a line
// positionally — command to the first space, key to the second, and everything
// after that is the value, spaces included, so `SET k hello world` stores
// "hello world".  Producing RESP arrays from that needs an arity table per
// command, which is the same duplication by another route.
//
// The transport with neither difficulty is the one already carrying the
// endpoint table into workers: shared/worker_protocol.h, length-prefixed
// frames with a message kind.  The request is a frame, the reply is a frame,
// and nothing on either side has to know what a cache command means.  What is
// missing is the other end — a cache that runs in a worker at all — so the
// sink is written after that exists and not before.
//
// A payload is what would arrive on the target's own port — for the cache, a
// newline-delimited command stream, answered line by line with the replies
// concatenated in order.  One line in and one line out is the ordinary case and
// the whole of what `cache <cmd>` needs; a caller with a run of commands sends
// them together and pays for one queue entry instead of one per command, which
// is what keeps the `--cache` auto-store from filling the queue on a burst.
// Several commands are answered once, with the replies concatenated in the
// order the commands were given — the same bytes the target's own socket would
// have put on the wire.
//
// The answer is appended to `out` rather than returned, so a transport that
// already has a buffer does not pay for a second one.
class request_sink
{
public:
    virtual ~request_sink() = default;
    virtual void serve_request(std::string_view payload, std::string& out) = 0;

    // ─── A SINK THAT CANNOT ANSWER ON THIS THREAD ───────────────────────────
    //
    // serve_request() fills `out` before it returns, which a runtime in this
    // process can always do: it reads its own memory.  One on the other side of
    // a process boundary cannot, and the only ways to pretend otherwise are to
    // block the event loop or to lie about the answer.  This project has
    // already paid for the first once — an fsync on this thread stalled every
    // runtime the daemon held for up to 9.6 ms — and will not pay for it again.
    //
    // So a sink may say it cannot answer inline.  The channel then parks the
    // request against a ticket and hands it over; the sink completes it later
    // through request_channel::complete_deferred(), on whatever turn of the
    // loop its own transport reports.  Nothing on the ASKING side changes: the
    // origin still gets on_request_reply() with the cookie it posted, and it
    // cannot tell the two paths apart, which is the whole point.
    //
    // Default: inline, so every sink that exists today is untouched.
    virtual bool serves_inline() const { return true; }

    // Take a request this sink promised to complete later.  Returning false
    // means it could not even accept it — the channel then answers the origin
    // `no_target` rather than parking something nobody will ever complete.
    virtual bool serve_deferred(uint64_t /*ticket*/, std::string_view /*payload*/)
    { return false; }
};

// What asks.  The reply lands here on a later turn of the loop, carrying the
// cookie the request was posted with and nothing else — by the time it arrives
// the connection that asked may be gone, and a cookie is the only thing that
// survives being stale.
class request_origin
{
public:
    virtual ~request_origin() = default;
    virtual void on_request_reply(uint64_t cookie, request_status st,
                                  std::string_view reply) = 0;
};

class request_channel : public io_handler
{
public:
    // Deliberately generous: one 16 KB read of `cache get k` lines is well over
    // a thousand requests, a multishot recv can deliver several such buffers
    // before the drain runs, and a client is entitled to pipeline all of it.
    // What these stop is the client that keeps doing it.
    static constexpr size_t MAX_PENDING            = 32768;
    static constexpr size_t MAX_PENDING_BYTES      = 16u << 20;
    static constexpr size_t MAX_PENDING_BACKGROUND = (MAX_PENDING * 3) / 4;
    static constexpr size_t MAX_DRAIN_BATCH        = 4096;

    ~request_channel() override;

    // Give the channel the ring it wakes itself with.  Until this is called
    // post() refuses everything, which is what a manager with no event loop
    // behind it should do.
    void attach(event_loop& loop);

    // Stop using the ring.  Every queued request is answered `dropped` — an
    // origin that is told nothing waits for ever — and the owner registration
    // is given back.  Call before the ring is shut down.
    void detach();

    // ── The sink table ──────────────────────────────────────────────────────
    // Rebuilt wholesale by runtime_manager::publish_endpoints(); see there for
    // the moments that happens.
    void clear_sinks();
    void register_sink(std::string_view name, request_sink* sink);
    void drop_sink(const request_sink* sink);

    // Ask `target` to answer `payload`.  False means the request was not taken
    // — no ring, or the queue is full — and no reply will ever be delivered for
    // it, so the caller has to answer for it itself.  True means exactly one
    // on_request_reply() will follow, whatever becomes of the target.
    bool post(request_origin* origin, uint64_t cookie,
              std::string_view target, std::string_view payload,
              request_class cls = request_class::client);

    // Revoke an origin: its queued requests are discarded and no reply is
    // delivered to it again.  Must be called before the origin is destroyed.
    void drop_origin(const request_origin* origin);

    // Finish a request a sink took through serve_deferred().  Delivers the
    // reply to the origin that asked, if it is still alive — the same liveness
    // check the inline path makes, for the same reason: the runtime that asked
    // may have been removed in between, and a ticket is the only thing that
    // survives being stale.
    //
    // An unknown ticket is ignored rather than treated as an error: a sink that
    // answers twice, or answers after drop_origin() has withdrawn the request,
    // is not doing anything the channel cannot absorb.
    void complete_deferred(uint64_t ticket, request_status st,
                           std::string_view reply);

    size_t parked_count() const { return m_parked.size(); }

    void on_cqe(struct io_uring_cqe* cqe) override;

    // Diagnostics.  Counters rather than gauges where a gauge would only ever
    // read zero from outside a drain.
    size_t   pending()        const { return m_queue.size(); }
    size_t   pending_bytes()  const { return m_bytes; }
    size_t   sink_count()     const { return m_sinks.size(); }
    uint64_t stat_posted()    const { return m_stat_posted; }
    uint64_t stat_refused()   const { return m_stat_refused; }
    // Background requests the queue had no room for.  Real loss, so it is
    // counted where somebody can see it rather than swallowed — and counted in
    // requests, which for a batched caller is not the same as the number of
    // commands lost; a server reports it under a name that says so.
    uint64_t stat_dropped_bg() const { return m_stat_dropped_bg; }
    uint64_t stat_served()    const { return m_stat_served; }
    uint64_t stat_no_target() const { return m_stat_no_target; }
    uint64_t stat_wakeups()   const { return m_stat_wakeups; }

private:
    // Put a no-op in the ring so the loop comes back to us.  False means it did
    // not reach the ring, which is why post() calls this *before* it queues
    // anything: an entry nothing will come back for is an answer nobody ever
    // gets.
    bool kick();
    void drain();

    struct entry
    {
        request_origin* origin{nullptr};
        uint64_t        cookie{0};
        std::string     target;
        std::string     payload;
    };

    std::deque<entry> m_queue;
    endpoint_table::transparent_map<request_sink*> m_sinks;

    // Requests handed to a sink that could not answer inline, waiting for it to
    // call complete_deferred().
    //
    // Bounded, because a remote that never answers must not grow this without
    // limit — beyond the cap a deferral is refused and the origin is told
    // `overloaded`, which is a true statement about the channel.  What is still
    // owed here is a DEADLINE: a sink whose peer disappears silently leaves its
    // ticket parked until the origin goes away and drop_origin() sweeps it.
    // That is the common case and it is covered; the uncommon one — an origin
    // that outlives an unanswered request for ever — is not, and the channel
    // has a loop to arm a timer on when somebody needs it.
    static constexpr size_t MAX_PARKED = 4096;
    struct parked_request
    {
        request_origin* origin{nullptr};
        uint64_t        cookie{0};
    };
    std::unordered_map<uint64_t, parked_request> m_parked;
    uint64_t m_next_ticket{1};

    // Origins allowed to receive a reply.  A flat vector because there is one
    // entry per runtime that asks anything of another — a handful — and the
    // check runs once per reply, not per byte.
    std::vector<request_origin*> m_origins;
    bool origin_live(const request_origin* o) const;

    size_t      m_bytes{0};
    event_loop* m_loop{nullptr};
    io_request  m_wake{};
    // "The ring owes us a wakeup."  Raised only when the submission was really
    // queued and lowered only by its completion, so a failed submit can never
    // leave the queue with nothing coming for it.
    bool m_wake_armed{false};
    bool m_draining{false};

    uint64_t m_stat_posted{0};
    uint64_t m_stat_refused{0};
    uint64_t m_stat_dropped_bg{0};
    uint64_t m_stat_served{0};
    uint64_t m_stat_no_target{0};
    uint64_t m_stat_wakeups{0};
    uint64_t m_stat_deferred{0};
    uint64_t m_stat_deferred_refused{0};
};
