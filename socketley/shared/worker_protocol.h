#pragma once
// The wire between the daemon and a runtime worker process.
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// endpoint_table.h removed the last pointer a proxy held into another runtime,
// which is what made moving one into its own process possible at all.  This is
// the other half: once the proxy is a separate process, everything the daemon
// used to do by calling a method has to become a message.  Configuration,
// membership changes, start/stop, and the figures `stats` and `inspect` print
// all cross here.
//
// ─── WHY A LENGTH-PREFIXED FRAME WITH A VERSION IN EVERY ONE ────────────────
//
// The daemon and the worker are the same binary today, but they are two
// processes with independent lifetimes, and an upgrade replaces the binary on
// disk while a worker forked from the old one is still running.  A receiver
// must therefore be able to make sense of a frame it does not understand, and
// the only way to do that is to know how long it is without knowing what is in
// it.  So the header is fixed width and carries the length: an unknown type is
// skipped by its length rather than desynchronising the stream, and a newer
// version's extra trailing bytes are ignored the same way.
//
// The version travels in every frame rather than only in the handshake because
// the handshake is exactly what is missing when a supervisor re-attaches to a
// worker it did not fork.
//
// ─── WHAT DOES NOT CROSS ────────────────────────────────────────────────────
//
// No descriptors.  A worker opens its own listening socket from the port in its
// config; nothing is passed with SCM_RIGHTS on THIS socket.  That is deliberate
// and it is not only about simplicity: an SQE carries a descriptor NUMBER that
// the kernel resolves later, on another thread under SQPOLL, so a descriptor
// sent across a boundary and closed on one side does not cancel the submissions
// naming it — it redirects them to whatever inherits the number.  This project
// has paid for that lesson more than once.  Ports are values; descriptors are
// not.
//
// A connection being handed from one runtime to another does cross, and it does
// so on its own channel with its own rule: see shared/conn_transfer.h, where
// the hazard above is what the two-call relinquish protocol exists to answer.
// It is a separate channel on purpose.  This one carries control frames whose
// delivery is best-effort — push_stats drops a frame the daemon is not draining
// — and a descriptor cannot be dropped, because dropping it is losing a
// connection that neither side is serving any more.
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace worker_proto
{

// Bumped when the meaning of an existing frame type changes.  Adding a new type
// does not need a bump: an old receiver skips what it does not know.
inline constexpr uint16_t version = 1;

// The header is 8 bytes: [u32 payload_len][u16 version][u16 type].
inline constexpr size_t header_size = 8;

// A frame big enough to be nonsense is refused rather than allocated.  The
// largest legitimate payload is an endpoint table or a config blob; both are
// far below this.
inline constexpr uint32_t max_payload = 8u * 1024u * 1024u;

enum class frame_type : uint16_t
{
    // worker → daemon
    hello   = 1,   // payload: u32 pid
    stats   = 2,   // payload: see encode_stats
    state   = 3,   // payload: u8 runtime_state

    // daemon → worker
    config    = 16,  // payload: runtime_config JSON (state_persistence's format)
    endpoints = 17,  // payload: see encode_endpoints
    start     = 18,  // payload: empty
    stop      = 19,  // payload: empty
    shutdown  = 20,  // payload: empty
    publish   = 21,  // payload: see encode_publish
    chan_req  = 22,  // payload: see encode_chan_request
    deliver   = 23,  // payload: raw message bytes; see below

    // worker → daemon, again
    chan_rep  = 4,   // payload: see encode_chan_reply
};

// ── deliver: `socketley send <name> <message>` for a runtime in a worker ────
//
// The message a server broadcasts to its connections, or a client writes to its
// peer.  It needs no encoder: the payload IS the message, and the frame header
// already carries the length, so nothing has to be escaped, quoted or parsed.
//
// It exists because `send` acts on connections, and the connections are in the
// worker.  cmd_send() reached the placeholder — which has the name, the port and
// the state but not one connection — called lua_broadcast() on it and returned
// 0.  The CLI said nothing, the exit status said success, and the message went
// nowhere.  A `send` that reports success and delivers nothing is the shape of
// wrong this tree is least willing to ship.

// ── What a worker's exit status means ───────────────────────────────────────
//
// A child that dies is restarted by default, which is right for a crash and
// wrong for a configuration it can never accept: forking it five more times
// produces five more copies of the same refusal.  So the one case the worker
// can recognise about itself says so on the way out, and the supervisor leaves
// the runtime `failed` instead of retrying.  Everything else keeps the old
// policy, because everything else might work on the next try.
inline constexpr int exit_config_refused = 3;

// ── Frame encoding ──────────────────────────────────────────────────────────

inline void put_u16(std::string& out, uint16_t v)
{
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}

inline void put_u32(std::string& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

inline void put_u64(std::string& out, uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

// Strings carry their own length, so a name with a space or a newline in it is
// not a parsing problem and no escaping rule has to be agreed between builds.
inline void put_str(std::string& out, std::string_view s)
{
    const uint32_t n = static_cast<uint32_t>(s.size());
    put_u32(out, n);
    out.append(s);
}

inline std::string frame(frame_type type, std::string_view payload)
{
    std::string out;
    out.reserve(header_size + payload.size());
    put_u32(out, static_cast<uint32_t>(payload.size()));
    put_u16(out, version);
    put_u16(out, static_cast<uint16_t>(type));
    out.append(payload);
    return out;
}

// ── Frame decoding ──────────────────────────────────────────────────────────

struct reader
{
    const char* p{nullptr};
    const char* end{nullptr};
    bool ok{true};

    reader(const char* data, size_t len) : p(data), end(data + len) {}

    uint16_t u16()
    {
        if (end - p < 2) { ok = false; return 0; }
        uint16_t v = static_cast<uint16_t>(static_cast<unsigned char>(p[0])) |
                     static_cast<uint16_t>(static_cast<unsigned char>(p[1])) << 8;
        p += 2;
        return v;
    }

    uint32_t u32()
    {
        if (end - p < 4) { ok = false; return 0; }
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<uint32_t>(static_cast<unsigned char>(p[i])) << (8 * i);
        p += 4;
        return v;
    }

    uint64_t u64()
    {
        if (end - p < 8) { ok = false; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(static_cast<unsigned char>(p[i])) << (8 * i);
        p += 8;
        return v;
    }

    uint8_t u8()
    {
        if (end - p < 1) { ok = false; return 0; }
        return static_cast<uint8_t>(*p++);
    }

    // How much of the payload is still unread.  For the one thing the header
    // above promises and no decoder could otherwise honour: a field appended by
    // a newer sender is skipped by an older receiver, and a field absent from
    // an older sender must not be read as a truncation by a newer one.
    size_t left() const { return ok ? static_cast<size_t>(end - p) : 0; }

    // Bounds-checked against the buffer, not just against the declared length:
    // the length is attacker-adjacent in the sense that it arrives from another
    // process, and a truncated frame must fail rather than read past the end.
    std::string_view str()
    {
        const uint32_t n = u32();
        if (!ok || static_cast<size_t>(end - p) < n) { ok = false; return {}; }
        std::string_view s(p, n);
        p += n;
        return s;
    }
};

// Pulls one whole frame off the front of `buf`.  Returns false when there is
// not a complete frame yet and leaves `buf` untouched; the caller keeps reading.
//
// `frame_version` is reported rather than enforced here so the caller can
// decide per type whether it can still act on it.
inline bool take_frame(std::string& buf, frame_type& type, uint16_t& frame_version,
                       std::string& payload, bool& fatal)
{
    fatal = false;
    if (buf.size() < header_size)
        return false;

    reader r(buf.data(), buf.size());
    const uint32_t len = r.u32();
    frame_version      = r.u16();
    type               = static_cast<frame_type>(r.u16());

    if (len > max_payload)
    {
        // Not recoverable: the stream is either corrupt or from something that
        // is not a worker, and there is no resynchronisation point to seek to.
        fatal = true;
        return false;
    }

    if (buf.size() < header_size + len)
        return false;

    payload.assign(buf, header_size, len);
    buf.erase(0, header_size + len);
    return true;
}

// ── Endpoint table payload ──────────────────────────────────────────────────
//
// The table is rebuilt on the far side rather than shared, because a
// shared_ptr to an immutable snapshot is exactly the thing that does not
// survive a process boundary.  What survives is what endpoint_table.h says is
// the whole of the answer: a host and a port, per name and per group.

struct endpoint_wire
{
    std::string name;   // runtime name, or group name
    std::string host;
    uint16_t    port{0};
};

inline std::string encode_endpoints(const std::vector<endpoint_wire>& names,
                                    const std::vector<endpoint_wire>& groups)
{
    std::string out;
    put_u32(out, static_cast<uint32_t>(names.size()));
    for (const auto& e : names)
    {
        put_str(out, e.name);
        put_str(out, e.host);
        put_u16(out, e.port);
    }
    put_u32(out, static_cast<uint32_t>(groups.size()));
    for (const auto& e : groups)
    {
        put_str(out, e.name);
        put_str(out, e.host);
        put_u16(out, e.port);
    }
    return out;
}

inline bool decode_endpoints(std::string_view payload,
                             std::vector<endpoint_wire>& names,
                             std::vector<endpoint_wire>& groups)
{
    reader r(payload.data(), payload.size());
    names.clear();
    groups.clear();

    const uint32_t n_names = r.u32();
    if (!r.ok) return false;
    // A count is not a reservation: it arrives from another process and
    // reserving on it would let a corrupt frame ask for an arbitrary
    // allocation.  Growth is bounded by the bytes actually present instead.
    for (uint32_t i = 0; i < n_names && r.ok; ++i)
    {
        endpoint_wire e;
        e.name = std::string(r.str());
        e.host = std::string(r.str());
        e.port = r.u16();
        if (!r.ok) return false;
        names.push_back(std::move(e));
    }

    const uint32_t n_groups = r.u32();
    if (!r.ok) return false;
    for (uint32_t i = 0; i < n_groups && r.ok; ++i)
    {
        endpoint_wire e;
        e.name = std::string(r.str());
        e.host = std::string(r.str());
        e.port = r.u16();
        if (!r.ok) return false;
        groups.push_back(std::move(e));
    }

    return r.ok;
}

// ── Stats payload ───────────────────────────────────────────────────────────
//
// The four counters plus the active-connection count and the detail text —
// which is precisely what runtime_instance publishes for off-thread readers
// already.  That is not a coincidence: a reader in another process is a reader
// off the event-loop thread, with the same prohibition on walking the
// runtime's containers and more reason to respect it.
//
// ─── WHY THE MOMENT TRAVELS WITH THE FIGURES ────────────────────────────────
//
// `stats` reports how old these are, and there is exactly one moment that can
// honestly answer that: the one at which the worker read its counters.  Every
// later moment the daemon has access to is contaminated by how long the frame
// spent in the socket — which is not bounded by the publish interval but by how
// often the daemon happens to drain, up to a full health tick.  Stamping it on
// arrival made a figure that had been sitting unread for a second read as new,
// and the label then said a stopped worker had published moments ago.
//
// CLOCK_MONOTONIC is system-wide on Linux and the worker is a plain fork+exec
// of the daemon, so the two processes count from the same zero and the
// subtraction is meaningful across the boundary.  Wall-clock would not be: an
// interval measured against a clock that steps reads as hours old or as
// arriving from the future.

struct stats_wire
{
    uint64_t    total_connections{0};
    uint64_t    total_messages{0};
    uint64_t    bytes_in{0};
    uint64_t    bytes_out{0};
    uint64_t    active_connections{0};
    std::string detail;

    // steady_clock nanoseconds at the instant the counters above were read, or
    // 0 from a sender that predates the field.
    uint64_t    taken_ns{0};
};

inline std::string encode_stats(const stats_wire& s)
{
    std::string out;
    put_u64(out, s.total_connections);
    put_u64(out, s.total_messages);
    put_u64(out, s.bytes_in);
    put_u64(out, s.bytes_out);
    put_u64(out, s.active_connections);
    put_str(out, s.detail);
    // Appended last, which is what makes it survive an upgrade in both
    // directions: an old daemon reading a new worker's frame stops after the
    // detail and never sees these eight bytes, and take_frame() has already
    // consumed them by the payload length, so ignoring them costs it no
    // synchronisation.  Inserting the field anywhere earlier would instead have
    // that daemon read the stamp as a counter.
    put_u64(out, s.taken_ns);
    return out;
}

inline bool decode_stats(std::string_view payload, stats_wire& s)
{
    reader r(payload.data(), payload.size());
    s.total_connections  = r.u64();
    s.total_messages     = r.u64();
    s.bytes_in           = r.u64();
    s.bytes_out          = r.u64();
    s.active_connections = r.u64();
    s.detail             = std::string(r.str());
    if (!r.ok)
        return false;

    // Optional, not truncation.  A worker forked from the binary that was on
    // disk before this field existed sends a payload that ends at the detail,
    // and a daemon that treated that as a short frame would drop every figure
    // that worker ever reports — the whole of `stats` for that runtime, to gain
    // a timestamp.  Absent means "not stamped"; the reader decides what to do.
    s.taken_ns = r.left() >= 8 ? r.u64() : 0;
    return r.ok;
}

// ── Published message payload ───────────────────────────────────────────────
//
// A cache's PUBLISH reaches every runtime's subscribe callbacks, and the daemon
// used to deliver it by calling into each instance.  A worker is not an
// instance the daemon can call into, so the three strings travel instead —
// which is all a subscriber is ever handed anyway.
//
// One-way and best-effort, like every other frame on this socket.  A subscriber
// is told what was published, not asked about it: there is no reply, nothing
// waits, and a frame dropped because the child is not reading is a message that
// subscriber does not see — the same outcome as a subscriber that was not
// running yet.  Unlike the endpoint table there is nothing to re-send it from,
// because a publish is an event and not a state.
//
// All three strings are length-prefixed, so a message with a NUL or a newline
// in it is not a parsing problem: a cache value is arbitrary bytes.

struct publish_wire
{
    std::string cache_name;
    std::string channel;
    std::string message;
};

inline std::string encode_publish(std::string_view cache_name,
                                  std::string_view channel,
                                  std::string_view message)
{
    std::string out;
    out.reserve(12 + cache_name.size() + channel.size() + message.size());
    put_str(out, cache_name);
    put_str(out, channel);
    put_str(out, message);
    return out;
}

inline bool decode_publish(std::string_view payload, publish_wire& p)
{
    reader r(payload.data(), payload.size());
    p.cache_name = std::string(r.str());
    p.channel    = std::string(r.str());
    p.message    = std::string(r.str());
    return r.ok;
}

// ── A request one runtime makes of another, across the process boundary ─────
//
// request_channel has always promised that a target on the other side of a
// process boundary would be reached by a socket-backed sink "and nothing on the
// asking side changes".  This is the wire that carries it, and it is
// deliberately this one rather than the target's own client protocol.
//
// NOT the cache's text protocol: its replies are not self-delimiting — ten
// commands answer over several lines ending in `end\n` — so a client could only
// find the end of a reply by knowing which command produced it, which puts the
// cache's command table in a second place.
//
// NOT RESP either, though RESP is self-delimiting: producing it is the problem.
// process_command() splits a line positionally, command to the first space, key
// to the second, and the rest is the value with its spaces intact, so
// `SET k hello world` stores "hello world".  Turning that into arrays needs an
// arity table per command — the same duplication by another road.
//
// A length-prefixed frame has neither difficulty.  The payload is whatever
// would have arrived on the target's own port and is passed through untouched;
// the ticket is what pairs an answer with its question, and it is the channel's
// own, so nothing here has to understand a single command.
struct chan_request_wire
{
    uint64_t    ticket{0};
    std::string target;    // runtime name the request is addressed to
    std::string payload;
};

struct chan_reply_wire
{
    uint64_t    ticket{0};
    uint8_t     status{0};  // request_status, as a number
    std::string payload;
};

inline std::string encode_chan_request(uint64_t ticket, std::string_view target,
                                       std::string_view payload)
{
    std::string out;
    out.reserve(16 + target.size() + payload.size());
    put_u64(out, ticket);
    put_str(out, target);
    put_str(out, payload);
    return out;
}

inline bool decode_chan_request(std::string_view payload, chan_request_wire& q)
{
    reader r(payload.data(), payload.size());
    q.ticket  = r.u64();
    q.target  = std::string(r.str());
    q.payload = std::string(r.str());
    return r.ok;
}

inline std::string encode_chan_reply(uint64_t ticket, uint8_t status,
                                     std::string_view payload)
{
    std::string out;
    out.reserve(13 + payload.size());
    put_u64(out, ticket);
    out.push_back(static_cast<char>(status));
    put_str(out, payload);
    return out;
}

inline bool decode_chan_reply(std::string_view payload, chan_reply_wire& p)
{
    reader r(payload.data(), payload.size());
    p.ticket  = r.u64();
    p.status  = static_cast<uint8_t>(r.u8());
    p.payload = std::string(r.str());
    return r.ok;
}

} // namespace worker_proto
