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
#include "route_table.h"
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

    // worker → daemon, again
    chan_rep  = 4,   // payload: see encode_chan_reply
    routes    = 5,   // payload: see encode_routes
    reload_err = 6,  // payload: why a `reload` failed; see below
    start_err  = 7,  // payload: why `start`'s on_start raised; see below
    deliver_to = 8,  // payload: see encode_deliver_to
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

// ── How often a worker publishes, and why the daemon needs the number ───────
//
// The worker's own publish timer, and the floor the daemon coalesces its
// runtime-map pushes to.  One constant, because the two have to agree: the map
// carries the connection counts, the counts arrive in these frames, and a
// daemon coalescing on a different period than the one new figures arrive at is
// either sending the same numbers twice or holding new ones back.
//
// It lived in proxy_worker.cpp, which is the one file the daemon cannot read it
// from.
inline constexpr int stats_interval_ms = 250;

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
