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
#include <memory>
#include <utility>
#include "conn_identity.h"
#include "route_table.h"
// The cluster snapshot travels whole, in the structs the daemon already has it
// in — see the note above encode_cluster_view.  This is the same reason
// route_table.h is included above rather than a flat copy of a declaration
// being made here.
#include "cluster_view.h"
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
    reload    = 24,  // payload: empty; re-run the script, then answer `routes`
    runtime_map = 25,  // payload: see encode_runtime_map
    cluster     = 26,  // payload: see encode_cluster_view

    // worker → daemon, again
    chan_rep  = 4,   // payload: see encode_chan_reply
    routes    = 5,   // payload: see encode_routes
    reload_err = 6,  // payload: why a `reload` failed; see below
    start_err  = 7,  // payload: why `start`'s on_start raised; see below
    deliver_to = 8,  // payload: see encode_deliver_to
    send_ref   = 9,  // payload: see encode_send_ref
    map_req    = 10, // payload: see encode_map_request
    route_up   = 11, // payload: see encode_route_frame

    // daemon → worker, again
    deliver_ref = 27,  // payload: see encode_send_ref — the same frame coming
                       // back down, which is why it is one codec and two names
    map_rep     = 28,  // payload: see encode_map_reply
    route_down  = 29,  // payload: see encode_route_frame -- the same
                       // codec travelling the other leg, for the
                       // reason send_ref/deliver_ref are one codec
};

// ── reload_err: the answer `reload-lua` had no way to hear ──────────────────
//
// A worker's reload either loads the file or leaves the previous script in
// force, and until this frame existed the only record of the second outcome was
// a WARN in the daemon's log.  cmd_reload_lua waited for the `routes` frame,
// got one either way — the declaration in force is still the right answer — and
// returned 0 with an empty reply.  The operator was told their edit had taken
// effect by a command that knew it had not.
//
// The payload is the diagnostic, verbatim, and the frame is only sent when the
// reload failed: a worker that reloaded cleanly sends nothing, so success costs
// no frame and the daemon's "did anything go wrong" is "did one arrive".  It is
// written before the `routes` frame that ends the daemon's wait, so by the time
// cmd_reload_lua stops waiting it has already been read.

// ── start_err: the same answer, for the command that started the runtime ────
//
// on_start runs inside `create -s` as well as inside `reload-lua`, and for a
// runtime in a worker it runs out here.  The child's start() does not fail on a
// raise — see runtime_instance::start(), the listener is up and the state is
// `running` several lines before on_start is called — so the `state` frame that
// follows says `running`, await_startup() answers `serving`, and until this
// frame existed the daemon had no way to learn that the script's set-up had not
// happened.  `create -s` therefore exited 0 in silence for a runtime with none
// of its subscriptions, timers or connections established.
//
// A separate frame from reload_err rather than a reuse of it.  The two are read
// by different commands at different moments and cleared on different asks —
// reload_err is cleared by send_reload() so that "nothing since the ask" is what
// success looks like — and one member serving both would report a startup
// failure as the answer to the first reload that came along.
//
// Same three rules as reload_err: the payload is the diagnostic verbatim, it is
// sent only when on_start raised, and it is written before the `state` frame
// that ends await_startup(), so it has been read by the time the daemon stops
// waiting.

// ── routes: what a runtime in a worker says it will answer ──────────────────
//
// A script's `routes` declaration is produced by running the script, and a
// worker's script runs in the worker.  The placeholder only checks that the
// file parses — it builds no interpreter, so it has no declaration and
// publish_endpoints() published none.  A gateway in front of such a runtime
// then forwarded every method to it instead of refusing the undeclared ones at
// the edge with a 405: the enforcement quietly stopped existing, which is the
// worst way for a gate to fail.
//
// So the worker sends its declaration up once, after the script has loaded, and
// the daemon puts it where publish_endpoints() looks.  The alternative — having
// the placeholder run the script too — is the one thing --daemon-process exists
// to avoid: every top-level side effect would happen twice, in two processes.

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

    // Nothing left to read.  Used to make a field optional: a frame from a
    // build that did not write it ends here, and the reader stops rather than
    // failing.
    bool done() const { return p >= end; }

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

using route_decl_wire = std::vector<
    std::pair<std::string, std::shared_ptr<const route_table>>>;

// Declared here, defined below the frame that uses it.  encode_endpoints
// appends the route declarations after the two endpoint blocks, so it calls
// this before the file has read it; the definition stays where it is because
// it belongs beside decode_routes, which is the half that has to agree with it.
inline std::string encode_routes(const route_table& rt);

inline std::string encode_endpoints(const std::vector<endpoint_wire>& names,
                                    const std::vector<endpoint_wire>& groups,
                                    const route_decl_wire& name_routes  = {},
                                    const route_decl_wire& group_routes = {})
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

    // The declarations, by name and by group.
    //
    // Left out for a long time, and the gap was invisible because it only shows
    // where the PROXY is in a worker: the daemon builds an endpoint_table with
    // set_name_routes() and a proxy in this process reads the same object.  One
    // in a worker gets this frame instead, and this frame carried a host and a
    // port and nothing else — so its gate had nothing to enforce and forwarded
    // every method, while `stats` reported declared_routes:0.
    //
    // Appended after the two blocks above rather than folded into them, so a
    // worker built before this field reads the endpoints it understands and
    // stops at the end of them.
    put_u32(out, static_cast<uint32_t>(name_routes.size()));
    for (const auto& [n, rt] : name_routes)
    {
        put_str(out, n);
        put_str(out, encode_routes(*rt));
    }
    put_u32(out, static_cast<uint32_t>(group_routes.size()));
    for (const auto& [g, rt] : group_routes)
    {
        put_str(out, g);
        put_str(out, encode_routes(*rt));
    }
    return out;
}

// A route declaration on the wire.  Flat and self-describing: a count, then
// per route a path, a prefix flag and its methods.  Nothing here validates —
// the table's own add() does that on the way in, and it is the same code on
// both sides.
inline std::string encode_routes(const route_table& rt)
{
    std::string out;
    put_u32(out, static_cast<uint32_t>(rt.all().size()));
    for (const auto& d : rt.all())
    {
        put_str(out, d.path);
        out.push_back(d.prefix ? 1 : 0);
        put_u32(out, static_cast<uint32_t>(d.methods.size()));
        for (const auto& m : d.methods)
            put_str(out, m);
    }
    return out;
}

inline bool decode_routes(std::string_view payload, route_table& out)
{
    reader r(payload.data(), payload.size());
    out.clear();

    const uint32_t n = r.u32();
    if (!r.ok) return false;

    // Rebuilt through add(), not assigned: every bound and every rejection the
    // declaration was subject to when the script made it applies again here,
    // so a frame cannot install a table the local build would have refused.
    for (uint32_t i = 0; i < n && r.ok; ++i)
    {
        const std::string path(r.str());
        if (!r.ok) return false;
        const bool prefix = r.u8() != 0;
        (void)prefix;   // carried by the path's trailing '*', see route_table::add

        const uint32_t nm = r.u32();
        if (!r.ok) return false;
        std::vector<std::string> methods;
        for (uint32_t j = 0; j < nm && r.ok; ++j)
            methods.emplace_back(r.str());
        if (!r.ok) return false;

        if (out.add(prefix ? path + "*" : path, methods) != route_table::add_result::ok)
            return false;
    }
    return r.ok;
}

inline bool decode_endpoints(std::string_view payload,
                             std::vector<endpoint_wire>& names,
                             std::vector<endpoint_wire>& groups,
                             route_decl_wire& name_routes,
                             route_decl_wire& group_routes)
{
    reader r(payload.data(), payload.size());
    names.clear();
    groups.clear();
    name_routes.clear();
    group_routes.clear();

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

    // The declarations, if this frame carries them.  A frame from a build that
    // predates the field simply ends here, and the two maps stay empty — which
    // is the behaviour that build had.
    if (!r.done())
    {
        const uint32_t n_nr = r.u32();
        if (!r.ok) return false;
        for (uint32_t i = 0; i < n_nr && r.ok; ++i)
        {
            std::string nm(r.str());
            std::string blob(r.str());
            if (!r.ok) return false;
            auto rt = std::make_shared<route_table>();
            if (!decode_routes(blob, *rt))
                return false;
            name_routes.emplace_back(std::move(nm),
                                     std::shared_ptr<const route_table>(std::move(rt)));
        }

        const uint32_t n_gr = r.u32();
        if (!r.ok) return false;
        for (uint32_t i = 0; i < n_gr && r.ok; ++i)
        {
            std::string g(r.str());
            std::string blob(r.str());
            if (!r.ok) return false;
            auto rt = std::make_shared<route_table>();
            if (!decode_routes(blob, *rt))
                return false;
            group_routes.emplace_back(std::move(g),
                                      std::shared_ptr<const route_table>(std::move(rt)));
        }
    }

    return r.ok;
}

// ── deliver_to: the same verb, going the other way ──────────────────────────
//
// `deliver` above is the daemon telling one worker to write a message to its
// connections, and the payload IS the message because the socket says which
// runtime is meant.  Going up, it does not: a script in a worker names the
// runtime it is sending to, and that runtime is any of them.
//
// So the name travels, and the frame is a separate type rather than the same
// one with a second reading.  One type meaning two things depending on which
// end read it is the sort of economy that survives until somebody loops a
// socket back on itself.
//
// Fire and forget, like `deliver` and like every other message frame here.  The
// caller's error cases — no such runtime, not running, not a kind of runtime
// that has connections — are answered on the asking side out of the replica the
// map frame installs, so what crosses is only the cases that cannot be:
// delivery to a runtime in a THIRD process, and delivery to one in the daemon.
//
// What `true` means degrades by exactly one hop, and it is worth saying which.
// In the daemon it means "handed to the process that holds the connections";
// out here it means "handed to the daemon, which knows which process that is".
// Neither is an acknowledgement — the daemon's own send has never waited for
// one — and the alternative to the extra hop is a round trip on the data path,
// which is the thing this design says no to everywhere else.

inline std::string encode_deliver_to(std::string_view name, std::string_view message)
{
    std::string out;
    out.reserve(8 + name.size() + message.size());
    put_str(out, name);
    put_str(out, message);
    return out;
}

inline bool decode_deliver_to(std::string_view payload, std::string& name,
                              std::string& message)
{
    reader r(payload.data(), payload.size());
    name    = std::string(r.str());
    message = std::string(r.str());
    return r.ok;
}

// ── map_req / map_rep: the four calls that CHANGE the runtime map ───────────
//
// socketley.create, .start, .stop and .remove from a script running in a
// worker.  Every one of them alters the map, and the map lives in the daemon:
// answering them against the worker's own copy would build a runtime the daemon
// never hears about, or flip a placeholder that binds nothing.  So they are not
// answered here — they are asked.
//
// ─── WHY THIS ONE WAITS, WHEN deliver_to DOES NOT ───────────────────────────
//
// deliver_to is fire-and-forget because `self.send` has nothing to tell the
// script afterwards.  These four do: `if socketley.create(...) then` is how
// they are written, and a value that says "accepted" rather than "done" is a
// lie the script cannot see through.
//
// The objection to waiting was stated one file over: a runtime does not make a
// synchronous request of another process, because it blocks the loop serving
// every connection this worker holds.  That is right about the DATA path, which
// is what it was written about -- socketley.get() runs per message, and a
// worker answering ~131k requests a second spends ~7.6 us on each.
//
// These four are not on it.  They run in on_start, or on a rare control
// message, and never per message.  Measured on this box, AF_UNIX socketpair,
// a 128-byte frame there and back: 9.95 / 10.20 / 10.52 us over three runs of
// 20000.  That is the cost of one or two requests, once, on a path a script
// reaches deliberately -- against socketley.http(), which this same file ships
// and which blocks the identical loop for a network round trip, three orders of
// magnitude longer.
//
// So the wait is bounded and it is the script's own callback deadline that
// bounds it: a map request cannot outlive the callback that made it.
//
// ─── THE FIFTH OP, AND WHY IT IS ON THIS SOCKET ─────────────────────────────
//
// `route` joined the four in 2026-08.  It is not a map mutation, and the names
// here (`map_req`, map_mutate, m_map_sink) were chosen when it was only the
// four -- so what this socket actually is, is the worker's SYNCHRONOUS
// ask-the-daemon channel, and the map calls were its first four users.
//
// It belongs here rather than on a channel of its own for the same reason the
// four do not travel the control socket: a worker cannot block on that
// descriptor at all, its writes being queued for the ring and its reads being a
// standing recv that a direct read would race. That reasoning is about the
// descriptor, not about what is asked over it, so a second socket with the
// identical property would be a second thing to create, place at fork, drain in
// both startup waits, and tear down -- four places to forget, for no
// difference. `route` gets an op, and `config` carries its argument blob.
//
// What it must NOT be used for is the per-message path. `data`, `write`,
// `close` and `drop` are route_up/route_down frames on the control socket
// precisely because they are frequent and answer nothing; see route_op.
//
// `ticket` correlates, because frames interleave.  A worker waiting on a reply
// still receives publishes, deliveries and stats requests, and a reply left
// over from a call that already timed out must not be read as the answer to
// this one.
inline std::string encode_map_request(uint64_t ticket, std::string_view op,
                                      std::string_view name, std::string_view config)
{
    std::string out;
    out.reserve(20 + op.size() + name.size() + config.size());
    put_u64(out, ticket);
    put_str(out, op);       // "create"|"start"|"stop"|"remove"|"route"
    put_str(out, name);
    put_str(out, config);   // create: the runtime_config JSON
                            // route:  see encode_route_ask
                            // empty for the other three
    return out;
}

inline bool decode_map_request(std::string_view payload, uint64_t& ticket,
                               std::string& op, std::string& name,
                               std::string& config)
{
    reader r(payload.data(), payload.size());
    ticket = r.u64();
    op     = std::string(r.str());
    name   = std::string(r.str());
    config = std::string(r.str());
    return r.ok;
}

// The answer carries the reason, not only the verdict.  A script that gets
// `false` and nothing else has to guess between "a runtime by that name exists"
// and "the port is taken", and the daemon is the only side that knows.
inline std::string encode_map_reply(uint64_t ticket, bool ok, std::string_view err)
{
    std::string out;
    out.reserve(13 + err.size());
    put_u64(out, ticket);
    out.push_back(ok ? '\1' : '\0');
    put_str(out, err);
    return out;
}

inline bool decode_map_reply(std::string_view payload, uint64_t& ticket,
                             bool& ok, std::string& err)
{
    reader r(payload.data(), payload.size());
    ticket = r.u64();
    ok     = r.u8() != 0;
    err    = std::string(r.str());
    return r.ok;
}

// ── send_ref / deliver_ref: a message for a connection in another shard ─────
//
// `self.send(id, msg)` where `id` names a client of a SIBLING shard.  The two
// names are one codec because they are one message travelling in two legs: up
// from the shard that was asked, and down to the shard that owns the socket.
//
// The daemon does not have to search for the owner.  A conn_ref's serial
// carries the minting shard in its top six bits — see conn_identity.h — so the
// second leg goes to exactly one worker.  That is the whole reason the shard
// index went into the serial rather than into a table somewhere.
//
// Nothing is answered, and that is a decision rather than an omission.  A
// `send` on this tree's own in-process path returns "queued", not "delivered":
// send_to() can still drop the connection for exceeding its write-queue bound,
// and the caller learns that from the connection going away.  Answering across
// a process boundary would therefore have to answer a question the local path
// does not answer either — and it would cost a Lua callback a round trip,
// which is the thing this design has spent two steps avoiding.  What the
// caller IS told is whether the ref named a connection this runtime has at
// all, and that is decided locally against the published client list.
inline std::string encode_send_ref(const conn_ref& ref, std::string_view message)
{
    std::string out;
    out.reserve(conn_ref_wire_size + 4 + message.size());
    put_conn_ref(out, ref);
    put_str(out, message);
    return out;
}

inline bool decode_send_ref(std::string_view payload, conn_ref& ref,
                            std::string& message)
{
    const char* p   = payload.data();
    const char* end = payload.data() + payload.size();
    if (!take_conn_ref(p, end, ref))
        return false;
    reader r(p, static_cast<size_t>(end - p));
    message = std::string(r.str());
    return r.ok;
}

// ── route_up / route_down: a connection served by one runtime, answered by
//    another ───────────────────────────────────────────────────────────────
//
// `self.route(client_id, "other")`.  The origin keeps the socket and stays in
// the data path; the target gets a handle, its on_connect, and every message
// that arrives.  That is conn_transfer.h's RELAY shape, and the choice between
// relay and handover is made there rather than here -- read it before adding a
// sixth op to this list.
//
// ─── FIVE OPS BECAUSE THERE ARE FIVE METHODS ────────────────────────────────
//
// server_instance declares exactly five cross-runtime methods, every one of
// them already taking a conn_ref rather than a descriptor, and this enum is one
// op per method with nothing left over:
//
//     open  -> accept_routed(ref, from)      on the TARGET
//     data  -> deliver_routed(ref, payload)  on the TARGET
//     close -> release_routed(ref)           on the TARGET
//     write -> write_to_ref(ref, payload)    on the ORIGIN
//     drop  -> drop_route(ref)               on the ORIGIN
//
// The direction is carried, not inferred.  Inferring it from `ref.owner ==
// my_owner_key()` reads correctly and is wrong for one case that already
// exists in process: a runtime routing a connection to ITSELF, where both
// halves of that test are true at once.  A byte costs less than the paragraph
// explaining why the inference is safe, and the inference would not have been.
//
// ─── WHY `open` IS NOT HERE ─────────────────────────────────────────────────
//
// It is, as an op -- but the ASK that produces it travels the map socket as a
// synchronous request, not as one of these frames.  These five are all
// fire-and-forget, and `route()` is the one call in the set that owes its
// script a true answer: it is written `if self.route(fd, "other") then`.
//
// The other four owe nothing.  `unroute()` decides from this runtime's own
// table whether there was a route to remove, and is right about that without
// asking anyone; `drop` and `close` are teardown, where there is no caller left
// to answer; and `data` is the per-message path, where a round trip would cost
// what this whole design has spent three steps avoiding -- see the note on
// send_ref, which declines to answer for the same reason and says so at more
// length.
enum class route_op : uint8_t
{
    open  = 1,
    data  = 2,
    close = 3,
    write = 4,
    drop  = 5,

    // ── The sixth, which is not about one connection ────────────────────────
    //
    // `from` has stopped or been removed; `to` must let go of every routing
    // relationship it has with it, in both directions.  `ref` is unused and the
    // payload is empty.
    //
    // It exists because the origin cannot be the one to tell.  Measured: a
    // stopped worker's teardown posts its `close` frames through the writer,
    // which submits at the end of a loop turn -- and the daemon does not wait,
    // so reconcile_proxy_workers() has already retired the supervisor and
    // closed the socket by the time they are written.  The frames go into a
    // descriptor nobody reads.
    //
    // Fixing the race would not have been enough, and that is the part worth
    // keeping: a worker that is KILLED never runs teardown at all.  Any design
    // where the departing runtime does the telling is wrong for that case, and
    // the in-process version never had to face it because one process losing
    // its memory takes both ends of the route with it.  So the daemon tells
    // everyone, from what it knows rather than from what the departing runtime
    // manages to say on its way out.
    forget = 6,
};

// `to` is the runtime the op is performed on, `from` the one that asked.  Both
// are names rather than shard indices, because the two ends are different
// RUNTIMES here and not two shards of one -- send_ref's trick of reading the
// owning shard out of the ref's top six bits answers a question this frame is
// not asking.  The daemon resolves `to` through the map it is the authority
// for, which is also what stops a worker addressing a runtime that has gone.
inline std::string encode_route_frame(std::string_view to, std::string_view from,
                                      route_op op, const conn_ref& ref,
                                      std::string_view payload)
{
    std::string out;
    out.reserve(conn_ref_wire_size + 13 + to.size() + from.size() + payload.size());
    put_str(out, to);
    put_str(out, from);
    out.push_back(static_cast<char>(op));
    put_conn_ref(out, ref);
    put_str(out, payload);
    return out;
}

inline bool decode_route_frame(std::string_view payload_in, std::string& to,
                               std::string& from, route_op& op, conn_ref& ref,
                               std::string& payload)
{
    reader r(payload_in.data(), payload_in.size());
    to   = std::string(r.str());
    from = std::string(r.str());
    const uint8_t raw = r.u8();
    if (!r.ok)
        return false;
    // Refuse an op this build does not know rather than defaulting to one it
    // does.  The two ends are separate processes with independent lifetimes and
    // an upgrade can replace the binary under one of them -- the same rule
    // conn_transfer.h states for its own framing, and the reason both carry a
    // length prefix.  Defaulting would turn a newer peer's sixth op into a
    // `data` delivery of the wrong bytes.
    if (raw < static_cast<uint8_t>(route_op::open) ||
        raw > static_cast<uint8_t>(route_op::forget))
        return false;
    op = static_cast<route_op>(raw);

    const char* p   = r.p;   // reader leaves its cursor public; conn_ref is
    const char* end = r.end; // taken by the pointer pair, as decode_send_ref does
    if (!take_conn_ref(p, end, ref))
        return false;
    reader r2(p, static_cast<size_t>(end - p));
    payload = std::string(r2.str());
    return r2.ok;
}

// The argument to the `route` op above: which connection, and who owns it.
// Rides in the map request's `config` field, which is a string and is therefore
// allowed to be bytes -- the four map ops put JSON there and this one does not,
// so the field is opaque to the transport and read by whoever handles the op.
//
// The target runtime is NOT in here: it is the request's `name`, which is where
// every other op puts the runtime it is about, and duplicating it would create
// two answers to one question.
inline std::string encode_route_ask(const conn_ref& ref, std::string_view origin)
{
    std::string out;
    out.reserve(conn_ref_wire_size + 4 + origin.size());
    put_conn_ref(out, ref);
    put_str(out, origin);
    return out;
}

inline bool decode_route_ask(std::string_view payload, conn_ref& ref,
                             std::string& origin)
{
    const char* p   = payload.data();
    const char* end = payload.data() + payload.size();
    if (!take_conn_ref(p, end, ref))
        return false;
    reader r(p, static_cast<size_t>(end - p));
    origin = std::string(r.str());
    return r.ok;
}

// ── The runtime map, replicated ─────────────────────────────────────────────
//
// The endpoint table above says where a runtime can be REACHED.  This says what
// runtimes there are, which is a different question and the one the management
// half of the Lua API asks: socketley.list() and socketley.get() read the map,
// and a worker had none — so both were refused out here, along with everything
// else that reaches for it.
//
// Six of the seven fields are a transcription rather than a design: they are
// exactly what socketley.get() returns, read off lua_context.cpp.  The seventh
// is the group, which socketley.get() does not report and the cluster calls
// cannot be answered without — a group is the only thing `socketley.cluster.
// group(name)` is about, and it is a property of the runtime rather than of the
// cluster, so it belongs in this frame and not in whatever carries the cluster
// view later.
//
// Nothing else crosses, because nothing else is answered from the map: a
// runtime's stats text, its flags and its script are answered by `stats` and
// `inspect`, which are commands the daemon serves and not calls a script makes.
//
// ─── WHY A REPLICA AND NOT A LOOKUP ─────────────────────────────────────────
//
// The other shape available was a request/reply per call, on the chan_req wire
// that already exists.  It was not taken.  socketley.get() returns a value to a
// script that is mid-expression, so a lookup would have to block the worker's
// event loop on the daemon for the length of a round trip — on the DATA path, in
// a callback, which is the synchronous cross-runtime call this design has said
// no to everywhere else.  A pushed table costs the worker nothing at the moment
// of the call and costs the daemon one frame per worker when the map moves.
//
// ─── WHAT IT COSTS IN TRUTH ─────────────────────────────────────────────────
//
// The replica is as old as the last push.  That is not a new compromise: the
// daemon's own answer for a runtime in a worker is already a pushed figure —
// reported_connection_count() reads what the stats frame last carried, up to a
// publish interval old — so a script in the daemon and a script in a worker are
// reading the same kind of number, one hop further apart.  Membership changes
// are pushed as they happen; the counts ride the same frame on the health tick.
// Nothing here invalidates and nothing refreshes on demand: see the note on
// runtime_manager::install_replica for what that buys.
//
// The state and type travel as u8 for the same reason the `state` frame's do:
// this header knows nothing about runtime_definitions.h, and both enums are
// append-only, so a value from a newer sender reads as a number this build has
// no name for rather than as a different runtime.

struct runtime_wire
{
    std::string name;
    uint8_t     type{0};    // runtime_type
    uint8_t     state{0};   // runtime_state
    uint16_t    port{0};
    uint64_t    connections{0};
    std::string owner;      // empty when the runtime has no parent
    std::string group;      // empty when the runtime is in no group
};

inline std::string encode_runtime_map(const std::vector<runtime_wire>& rts)
{
    std::string out;
    put_u32(out, static_cast<uint32_t>(rts.size()));
    for (const auto& r : rts)
    {
        put_str(out, r.name);
        out.push_back(static_cast<char>(r.type));
        out.push_back(static_cast<char>(r.state));
        put_u16(out, r.port);
        put_u64(out, r.connections);
        put_str(out, r.owner);
        put_str(out, r.group);
    }
    return out;
}

inline bool decode_runtime_map(std::string_view payload, std::vector<runtime_wire>& rts)
{
    reader r(payload.data(), payload.size());
    rts.clear();

    const uint32_t n = r.u32();
    if (!r.ok) return false;

    // Not reserved on the count, for the reason decode_endpoints gives: the
    // number arrives from another process and reserving on it would let a
    // corrupt frame ask for an arbitrary allocation.
    for (uint32_t i = 0; i < n && r.ok; ++i)
    {
        runtime_wire e;
        e.name        = std::string(r.str());
        e.type        = r.u8();
        e.state       = r.u8();
        e.port        = r.u16();
        e.connections = r.u64();
        e.owner       = std::string(r.str());
        e.group       = std::string(r.str());
        if (!r.ok) return false;
        rts.push_back(std::move(e));
    }
    return r.ok;
}

// ── The cluster, as a worker is allowed to see it ───────────────────────────
//
// The runtime map above answers what this daemon holds.  This answers what the
// CLUSTER holds, and it is a separate frame because it is a separate fact with
// a separate clock: a remote daemon joining or leaving moves nothing in the
// local map, and a worker holding a map that is perfectly current can still be
// describing a cluster that no longer exists.
//
// Three fields, and none of them is derivable from anything a worker already
// has: this daemon's cluster NAME, the address it advertises — which is the
// `host` of every LOCAL member, so a worker guessing 127.0.0.1 would hand a
// script an address no other node can reach — and get_all_daemons() verbatim.
// See shared/cluster_view.h, which is where the reasoning for the shape lives
// and which the daemon and the worker both build against.
//
// ─── WHY NOT A cluster_discovery IN THE WORKER ──────────────────────────────
//
// Because it publishes.  A cluster_discovery claims this node's name in the
// shared directory, and claim_is_ours() is what tells "me, restarted" from
// "somebody else with my name" — so a worker running one would read as a second
// daemon to every other member of the cluster.  A worker is a reader and gets a
// reader's object.
//
// ─── WHAT TRAVELS AND WHAT DOES NOT ─────────────────────────────────────────
//
// The structs are cluster_discovery's own, not a flat copy: the daemon builds
// this straight out of get_all_daemons(), and a second pair of structs with the
// same fields is a conversion nobody would keep correct.  Every field of them
// crosses, heartbeat included — it is read by nothing in the Lua surface today,
// and leaving it at zero would be a field that is silently wrong rather than
// merely absent, which is the trade this tree makes the other way round.
//
// The cost of carrying it is that the payload changes on every scan even when
// the cluster has not, so the per-child dedupe cannot suppress this frame the
// way it suppresses an unchanged runtime map.  That is one frame per worker per
// scan interval on a CLUSTERED daemon and none at all on the ordinary one,
// which is the shape worth paying: a daemon that is not in a cluster never
// sends this frame at all.
//
// An EMPTY view — no daemon name — is how "this daemon is not in a cluster any
// more" crosses.  The worker takes it as a withdrawal rather than as a cluster
// of one with no name, and its four cluster calls go back to refusing.

inline std::string encode_cluster_view(const cluster_view& v)
{
    std::string out;
    put_str(out, v.daemon_name);
    put_str(out, v.host);
    put_u32(out, static_cast<uint32_t>(v.remote.size()));
    for (const auto& d : v.remote)
    {
        put_str(out, d.name);
        put_str(out, d.host);
        put_u64(out, static_cast<uint64_t>(d.heartbeat));
        put_u32(out, static_cast<uint32_t>(d.runtimes.size()));
        for (const auto& r : d.runtimes)
        {
            put_str(out, r.daemon_name);
            put_str(out, r.host);
            put_str(out, r.name);
            put_str(out, r.type);
            put_str(out, r.group);
            put_u16(out, r.port);
            put_str(out, r.state);
            put_u64(out, static_cast<uint64_t>(r.connections));
        }
    }
    return out;
}

inline bool decode_cluster_view(std::string_view payload, cluster_view& v)
{
    reader r(payload.data(), payload.size());
    v.daemon_name = std::string(r.str());
    v.host        = std::string(r.str());
    v.remote.clear();

    const uint32_t nd = r.u32();
    if (!r.ok) return false;

    // Not reserved on either count, for the reason decode_endpoints gives: both
    // arrive from another process, and reserving on them would let a corrupt
    // frame ask for an arbitrary allocation.
    for (uint32_t i = 0; i < nd && r.ok; ++i)
    {
        remote_daemon d;
        d.name      = std::string(r.str());
        d.host      = std::string(r.str());
        d.heartbeat = static_cast<time_t>(r.u64());
        const uint32_t nr = r.u32();
        if (!r.ok) return false;
        for (uint32_t j = 0; j < nr && r.ok; ++j)
        {
            remote_runtime rt;
            rt.daemon_name = std::string(r.str());
            rt.host        = std::string(r.str());
            rt.name        = std::string(r.str());
            rt.type        = std::string(r.str());
            rt.group       = std::string(r.str());
            rt.port        = r.u16();
            rt.state       = std::string(r.str());
            rt.connections = static_cast<size_t>(r.u64());
            if (!r.ok) return false;
            d.runtimes.push_back(std::move(rt));
        }
        if (!r.ok) return false;
        v.remote.push_back(std::move(d));
    }
    return r.ok;
}

// ── The floor on how often a worker may publish ─────────────────────────────
//
// Not a timer any more.  A worker publishes when the part of `stats` it alone
// can compute has CHANGED, and this is the shortest interval two such publishes
// may be — so a runtime under continuous traffic rebuilds its detail text four
// times a second rather than once per completion, and an idle one publishes
// nothing at all.
//
// It is also the floor the daemon coalesces its runtime-map pushes to, and that
// is why the number is here rather than in proxy_worker.cpp: the map carries
// the connection counts, and a daemon coalescing on a different period than the
// one figures move at is either sending the same numbers twice or holding new
// ones back.
inline constexpr int stats_interval_ms = 250;

// ── Stats payload ───────────────────────────────────────────────────────────
//
// The four counters plus the active-connection count and the detail text —
// which is precisely what runtime_instance publishes for off-thread readers
// already.  That is not a coincidence: a reader in another process is a reader
// off the event-loop thread, with the same prohibition on walking the
// runtime's containers and more reason to respect it.
//
// ─── WHY THERE IS NO LONGER A MOMENT TRAVELLING WITH THE FIGURES ────────────
//
// This frame used to carry the instant its counters were read, because `stats`
// printed how old they were and only the worker could answer that honestly.
// The counters are in shared memory now — see shard_stats.h — and are summed by
// whoever prints them, so there is no interval between reading and printing and
// nothing to date.  `figures:pushed` and `figures_age_ms` went with it.
//
// The counters that remain in this struct are the fallback for a runtime whose
// region could not be created, and the reason the change test in push_stats()
// notices a counter moving.  `detail` is the part of `stats` no shared counter
// can carry: a walk of one process's own tables.

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
    // Trailing bytes a newer sender appended are left where they are: the frame
    // header carries the length, so take_frame() has already consumed them and
    // ignoring them costs this reader no synchronisation.  That is what the
    // timestamp this frame used to end with relied on, and it is still what a
    // field added after `detail` would rely on.
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
