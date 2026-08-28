#pragma once
// A request one runtime makes of another, answered on a later turn, so an
// asking side cannot tell "computed here" from "written to a socket".
//
// One queue drained front to back; it owns copies, and an origin must call
// drop_origin() before it dies.  Background work has a lower cap so a --cache
// auto-store cannot starve the `cache get` a client is waiting on.

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

// What answers requests for a runtime name; a payload is what would arrive on
// the target's own port, and the answer is appended to `out`.
class request_sink
{
public:
    virtual ~request_sink() = default;
    virtual void serve_request(std::string_view payload, std::string& out) = 0;

    // A sink across a boundary cannot fill `out` before returning, so it may
    // say so and the channel parks the request against a ticket.
    virtual bool serves_inline() const { return true; }

    // False means it could not even accept it, and the origin is answered
    // `no_target`.  The name is passed because the default sink is registered
    // under none and forwards for every name.
    virtual bool serve_deferred(uint64_t /*ticket*/, std::string_view /*target*/,
                                std::string_view /*payload*/)
    { return false; }
};

// What asks.  The reply carries the cookie and nothing else, because by then
// the connection that asked may be gone.
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
    // Generous on purpose: one 16 KB read is over a thousand requests, and a
    // client may pipeline all of it.  These stop the client that keeps doing it.
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

    // Where a request goes when nobody here holds the name.  Unset in the
    // daemon, which holds the whole map; a worker points it at the control
    // socket and also registers its OWN name, or a request for itself would go
    // to the daemon and come straight back.
    void set_default_sink(request_sink* sink) { m_default_sink = sink; }
    request_sink* default_sink() const { return m_default_sink; }

    // False means not taken and no reply will ever come; true means exactly one
    // on_request_reply(), whatever becomes of the target.
    bool post(request_origin* origin, uint64_t cookie,
              std::string_view target, std::string_view payload,
              request_class cls = request_class::client);

    // Revoke an origin: its queued requests are discarded and no reply is
    // delivered to it again.  Must be called before the origin is destroyed.
    void drop_origin(const request_origin* origin);

    // Finishes a deferred request if its origin is still alive.  An unknown
    // ticket is ignored: answering twice is nothing the channel cannot absorb.
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
    // Real loss, counted where somebody can see it -- in requests, which for a
    // batched caller is not the number of commands lost.
    uint64_t stat_dropped_bg() const { return m_stat_dropped_bg; }
    uint64_t stat_served()    const { return m_stat_served; }
    uint64_t stat_no_target() const { return m_stat_no_target; }
    uint64_t stat_wakeups()   const { return m_stat_wakeups; }

private:
    // A no-op so the loop comes back; post() calls it BEFORE queueing, because
    // an entry nothing returns for is an answer nobody gets.
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

    // Not cleared by clear_sinks(): the table is rebuilt on every membership
    // change and the fallback is a property of the process, not of the map.
    request_sink* m_default_sink{nullptr};

    // Bounded so a remote that never answers cannot grow this.  No deadline
    // yet: a parked ticket is swept when its origin goes, which covers the
    // common case and not an origin that outlives the request for ever.
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
