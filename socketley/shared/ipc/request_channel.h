#pragma once
// A request one runtime makes of another, answered on a later turn from one
// queue in order, so an asking side cannot tell "computed here" from "written
// to a socket".

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <unordered_map>
#include <string>
#include <string_view>
#include <vector>

#include "../loop/liburing_version.h"   // must precede <liburing.h>; see that file
#include <liburing.h>

#include "../net/endpoint_table.h"
#include "../loop/event_loop_definitions.h"

class event_loop;

enum class request_status : uint8_t
{
    ok = 0,
    no_target,    // nothing answers to that name — never started, or stopped in between
    overloaded,   // the channel, or the way to the runtime, was full when the request was posted
    dropped       // the channel gave the request up: it was detached under it
};

// What a request is worth under pressure.  See the bounds note above.
enum class request_class : uint8_t
{
    client = 0,   // somebody is holding a socket open for the answer
    background    // nobody is waiting; droppable, and dropped first
};

const char* request_status_text(request_status st);

// Which bound answered a request `overloaded`, each counted apart so `stats` names the one that refused.
enum class overload_bound : uint8_t
{
    queue = 0,          // the queue's count of requests
    queue_bytes,        // the queue's bytes
    parked,             // the table of requests whose answer comes on a later turn
    wakeup,             // the ring took no wakeup for the queue
    way,                // the socket the request goes out on had no room
    answer_way,         // the socket an answer goes back on had no room
    count_
};

// The `stats` key of a bound, without its "requests_overloaded_" prefix.
const char* overload_bound_name(overload_bound b);

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

    // False means it could not even accept it and the origin is answered as
    // refusal() says, with the name passed because the default sink forwards
    // for every name.
    virtual bool serve_deferred(uint64_t /*ticket*/, std::string_view /*target*/,
                                std::string_view /*payload*/)
    { return false; }

    // Why serve_deferred() just refused a payload of `size` for `target`: `overloaded` when the way is there but full.
    virtual request_status refusal(std::string_view /*target*/, size_t /*size*/) const
    { return request_status::no_target; }

    // The longest payload a request to `target` may have for this sink to carry it now.
    virtual size_t request_room(std::string_view /*target*/) const { return SIZE_MAX; }
};

// A sink whose every answer comes on a later turn, so the inline path is never taken.
class deferred_request_sink : public request_sink
{
public:
    void serve_request(std::string_view, std::string& out) final { out.clear(); }
    bool serves_inline() const final { return false; }
};

// What asks, whose reply carries the cookie and nothing else, because by then
// the connection that asked may be gone.
class request_origin
{
public:
    virtual ~request_origin() = default;
    virtual void on_request_reply(uint64_t cookie, request_status st,
                                  std::string_view reply) = 0;

    // The longest answer the way back can carry, so a sink can decline what it could not take back once given up.
    virtual size_t reply_room(uint64_t /*cookie*/) const { return SIZE_MAX; }
};

class request_channel : public io_handler
{
public:
    // Generous on purpose, since one 16 KB read is over a thousand requests a
    // client may pipeline.
    static constexpr size_t MAX_PENDING            = 32768;
    static constexpr size_t MAX_PENDING_BYTES      = 16u << 20;
    // A client's requests may hold more, as one crosses in pieces up to 256 MiB, and a lone one goes at any size.
    static constexpr size_t MAX_PENDING_CLIENT_BYTES = 256u << 20;
    static constexpr size_t MAX_PENDING_BACKGROUND = (MAX_PENDING * 3) / 4;
    static constexpr size_t MAX_DRAIN_BATCH        = 4096;
    // The parked table, bounded because a remote that never answers must not grow it, and split as the queue is.
    static constexpr size_t MAX_PARKED             = 4096;
    static constexpr size_t MAX_PARKED_BACKGROUND  = (MAX_PARKED * 3) / 4;

    ~request_channel() override;

    // Give the channel the ring it wakes itself with, until which post()
    // refuses everything.
    void attach(event_loop& loop);

    // Stop using the ring, answering every queued request `dropped` because an
    // origin that is told nothing waits for ever.
    void detach();

    // ── The sink table ──────────────────────────────────────────────────────
    // Rebuilt wholesale by runtime_manager::publish_endpoints(); see there for
    // the moments that happens.
    void clear_sinks();
    void register_sink(std::string_view name, request_sink* sink);
    void drop_sink(const request_sink* sink);

    // Where a request goes when nobody here holds the name; a worker also
    // registers its OWN name, or a request for itself would round-trip.
    void set_default_sink(request_sink* sink) { m_default_sink = sink; }
    request_sink* default_sink() const { return m_default_sink; }

    // False means not taken and no reply will ever come; true means exactly one
    // on_request_reply(), whatever becomes of the target.
    bool post(request_origin* origin, uint64_t cookie,
              std::string_view target, std::string_view payload,
              request_class cls = request_class::client);
    // The same, the payload taken over rather than copied.
    bool post_owned(request_origin* origin, uint64_t cookie,
                    std::string_view target, std::string&& payload,
                    request_class cls = request_class::client);

    // Revoke an origin, discarding its queued requests, and call it before the
    // origin is destroyed.
    void drop_origin(const request_origin* origin);

    // Finishes a deferred request if its origin is still alive, ignoring an
    // unknown ticket.
    void complete_deferred(uint64_t ticket, request_status st,
                           std::string_view reply);

    // The longest answer a parked ticket's way back can carry, 0 once it is not parked.
    size_t reply_room(uint64_t ticket) const;
    // The longest payload a request to `target` can carry the way it would go now.
    size_t request_room(std::string_view target) const;

    // Park a request that arrived from outside this channel, so its answer
    // comes through complete_deferred() like any other; 0 when the table is
    // full, which for background work is a quarter short of it.
    //
    // `sink` is remembered rather than passed through: a target that really
    // goes can then be answered at the moment it goes, instead of at the
    // deadline below.
    uint64_t park(request_origin* origin, uint64_t cookie,
                  const request_sink* sink,
                  request_class cls = request_class::client);

    // How long a parked request may go unanswered before its origin is told
    // `dropped`.  Longer than any budget a caller sets on top of it, so the
    // caller's own answer -- with the caller's own reason -- comes first, and
    // this one catches what has none.
    static constexpr uint32_t parked_deadline_secs = 30;

    // Take back a ticket park() handed out when the sink would not take the
    // request, because nothing is going to complete it.
    void withdraw(uint64_t ticket);

    size_t parked_count() const { return m_parked.size(); }

    void on_cqe(struct io_uring_cqe* cqe) override;

    // Diagnostics, as counters rather than gauges where a gauge would only
    // ever read zero from outside a drain.
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
    // Parked requests answered by something other than their target: the
    // deadline, a sink that went, or a detach.
    uint64_t stat_parked_dropped() const { return m_stat_parked_dropped; }

    // Count a request answered overloaded at `b`, and say so in the log the first time each bound refuses.
    void note_overloaded(overload_bound b);
    uint64_t stat_overloaded(overload_bound b) const { return m_stat_overloaded[static_cast<size_t>(b)]; }
    // Every bound's count together, so a caller can tell a refusal at a bound from one for want of a target.
    uint64_t stat_overloaded_total() const
    {
        uint64_t n = 0;
        for (const uint64_t c : m_stat_overloaded)
            n += c;
        return n;
    }
    // One `requests_overloaded_<bound>:N` line per bound, every bound always listed, and the most ever parked at once.
    std::string bound_stats() const;

private:
    // A no-op so the loop comes back; post() calls it BEFORE queueing, because
    // an entry nothing returns for is an answer nobody gets.
    bool kick();
    // Whether a request of this size and class may be queued now, counting the refusal when not.
    bool admit(request_origin* origin, std::string_view target, size_t size, request_class cls);
    void enqueue(request_origin* origin, uint64_t cookie, std::string_view target,
                 std::string&& payload, request_class cls);
    void drain();

    // Come back for parked requests that have waited too long.  Armed only
    // while something is parked and re-armed from its own firing, so a channel
    // nobody defers on puts nothing in the ring.
    void arm_park_sweep();

    // Answer every parked ticket the predicate picks, `dropped`, and say how
    // many.  Collected before any is answered, because answering runs the
    // origin's callback and that may park again under the iterator.
    template <class Pick>
    size_t drop_parked(Pick pick);

    struct entry
    {
        request_origin* origin{nullptr};
        uint64_t        cookie{0};
        std::string     target;
        std::string     payload;
        request_class   cls{request_class::client};
    };

    std::deque<entry> m_queue;
    endpoint_table::transparent_map<request_sink*> m_sinks;

    // Not cleared by clear_sinks(): the table is rebuilt on every membership
    // change and the fallback is a property of the process, not of the map.
    request_sink* m_default_sink{nullptr};

    // Swept because bounding it was never enough: a ticket was given up only
    // when its ORIGIN went, and the origin is the side still waiting.  Measured
    // against a cache worker under SIGSTOP -- which accepts and never answers,
    // the one shape a crash does not produce -- a client's `cache get` was
    // never answered and the connection it was owed on was held open for good.
    struct parked_request
    {
        request_origin*     origin{nullptr};
        uint64_t            cookie{0};
        const request_sink* sink{nullptr};
        std::chrono::steady_clock::time_point armed{};
    };
    std::unordered_map<uint64_t, parked_request> m_parked;
    uint64_t m_next_ticket{1};

    // Origins allowed to receive a reply, as a flat vector because there is
    // one entry per runtime that asks anything of another.
    std::vector<request_origin*> m_origins;
    bool origin_live(const request_origin* o) const;

    size_t      m_bytes{0};
    event_loop* m_loop{nullptr};
    io_request  m_wake{};
    io_request  m_sweep{};
    struct __kernel_timespec m_sweep_ts{};
    bool        m_sweep_armed{false};
    // Reused, so a sweep of four thousand tickets allocates nothing.
    std::vector<uint64_t> m_sweep_due;
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
    uint64_t m_stat_parked_dropped{0};
    uint64_t m_stat_overloaded[static_cast<size_t>(overload_bound::count_)]{};
    size_t   m_parked_most{0};
};
