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
};

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

struct stats_wire
{
    uint64_t    total_connections{0};
    uint64_t    total_messages{0};
    uint64_t    bytes_in{0};
    uint64_t    bytes_out{0};
    uint64_t    active_connections{0};
    std::string detail;
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
    return r.ok;
}

} // namespace worker_proto
