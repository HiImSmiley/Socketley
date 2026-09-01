#pragma once
// Everything the daemon used to do to a proxy by calling a method, once that
// proxy is its own process: a length-prefixed frame carrying its version in
// every one, so an unknown type is skipped rather than desynchronising the
// stream, and carrying no descriptors, because ports are values and
// descriptors are not.
#include <cstdint>
#include <cstring>
#include <string>
#include <memory>
#include <utility>
#include "conn_identity.h"
#include "route_table.h"
// The cluster snapshot travels whole, in the structs the daemon already holds
// it in.
#include "cluster_view.h"
#include <string_view>
#include <vector>

namespace worker_proto
{

// Bumped when the meaning of an existing frame type changes, not when one is
// added, since an old receiver skips what it does not know.
inline constexpr uint16_t version = 2;

// The header is 8 bytes: [u32 payload_len][u16 version][u16 type].
inline constexpr size_t header_size = 8;

// A frame big enough to be nonsense is refused rather than allocated, well
// above the largest legitimate payload.
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
    config_err = 12, // payload: why a `config` was refused; see below

    // daemon → worker, again
    deliver_ref = 27,  // payload: see encode_send_ref — the same frame coming
                       // back down, which is why it is one codec and two names
    map_rep     = 28,  // payload: see encode_map_reply
    cluster_ev  = 31,  // payload: see encode_cluster_event
    route_down  = 29,  // payload: see encode_route_frame -- the same
                       // codec travelling the other leg, for the
                       // reason send_ref/deliver_ref are one codec
};

// reload_err carries the diagnostic verbatim and is sent only when the reload
// failed, before the `routes` frame that ends the daemon's wait, so success
// costs no frame.

// start_err is the same answer for `create -s`, a separate frame from
// reload_err because the two are read by different commands at different
// moments and cleared on different asks.

// routes carries what a runtime in a worker says it will answer, sent up once
// after the script loads, because the placeholder has no interpreter and a
// gateway with no declaration forwards every method.

// deliver is `socketley send` for a runtime in a worker, needing no encoder
// because the payload is the message and the header carries the length.

// ── What a worker's exit status means ───────────────────────────────────────
// A child that dies is restarted by default, except for the one case it can
// recognise about itself, where forking again would only produce the same
// refusal.
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

    // Nothing left to read, which makes a field optional: a frame from a build
    // that did not write it ends here and the reader stops rather than
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

    // How much of the payload is still unread, so a newer sender's extra field
    // is skipped and an older sender's missing one is not read as a
    // truncation.
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

// Pulls one whole frame off the front of `buf`, leaving it untouched when
// there is not a complete one, and reporting `frame_version` rather than
// enforcing it.
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
// The table is rebuilt on the far side rather than shared, because a
// shared_ptr to an immutable snapshot does not survive a process boundary and
// a host and a port do.

struct endpoint_wire
{
    std::string name;   // runtime name, or group name
    std::string host;
    uint16_t    port{0};

    // The node this runtime also listens on, for a caller already on this box.
    // Carried in a block of its own at the end of the frame rather than beside
    // the port, so a build that predates it reads the endpoints and stops --
    // the same rule the route declarations landed under.
    std::string unix_path;
};

using route_decl_wire = std::vector<
    std::pair<std::string, std::shared_ptr<const route_table>>>;

// Declared here and defined below the frame that uses it, because the
// definition belongs beside decode_routes, which is the half that has to agree
// with it.
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

    // The declarations by name and by group, appended after the two blocks
    // above so a worker built before this field reads the endpoints it
    // understands and stops.
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

    // The nodes, last and only for the names that have one, because most
    // runtimes do not and a pair per name would be a block of empty strings.
    uint32_t n_nodes = 0;
    for (const auto& e : names)
        if (!e.unix_path.empty())
            ++n_nodes;
    put_u32(out, n_nodes);
    for (const auto& e : names)
    {
        if (e.unix_path.empty())
            continue;
        put_str(out, e.name);
        put_str(out, e.unix_path);
    }
    return out;
}

// A route declaration on the wire, flat and self-describing, validating
// nothing because the table's own add() does that on both sides.
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
    // A count is not a reservation, because it arrives from another process,
    // so growth is bounded by the bytes actually present.
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

    // The declarations, if this frame carries them, since a frame from a build
    // that predates the field simply ends here.
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

        // And the nodes, under the same rule one block further in: a frame
        // from a build that predates them ends before this count.
        if (!r.done())
        {
            const uint32_t n_nodes = r.u32();
            if (!r.ok) return false;
            for (uint32_t i = 0; i < n_nodes && r.ok; ++i)
            {
                std::string nm(r.str());
                std::string path(r.str());
                if (!r.ok) return false;
                for (auto& e : names)
                    if (e.name == nm)
                    {
                        e.unix_path = std::move(path);
                        break;
                    }
            }
        }
    }

    return r.ok;
}

// deliver_to is the same verb going up, a separate type because the name has
// to travel, and fire-and-forget like every other message frame -- so `true`
// means handed to the daemon, which knows which process holds the connections.

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

// The worker's synchronous ask-the-daemon channel, whose first four users were
// the map mutations and whose fifth is `route`: it waits because a script is
// mid-expression, it costs about 10 us on a path no message travels, and
// `ticket` correlates because frames interleave.
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

// The answer carries the reason and not only the verdict, because the daemon
// is the only side that knows which refusal it was.
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

// send_ref / deliver_ref are one message in two legs, routed to exactly one
// worker by the shard in the conn_ref's serial, answering nothing because the
// in-process path answers "queued" rather than "delivered" either.
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

// config_err is the reason a worker would not serve its configuration, written
// before the exit because a socket outlives the process that wrote into it
// until the peer reads it.
//    another ───────────────────────────────────────────────────────────────
// route_up / route_down carry one op per cross-runtime method server_instance
// declares, with the direction carried rather than inferred, because a runtime
// routing a connection to itself makes `ref.owner == my_owner_key()` true on
// both halves.
// ─── WHY `open` IS NOT HERE ─────────────────────────────────────────────────
// `route` is an op, but the ask travels the map socket as a synchronous
// request, because it is the one call in the set that owes its script a true
// answer.
enum class route_op : uint8_t
{
    open  = 1,
    data  = 2,
    close = 3,
    write = 4,
    drop  = 5,

    // The sixth op is not about one connection: `from` has stopped and `to`
    // must let go, told by the daemon because a killed worker runs no teardown
    // at all and a stopped one writes into a descriptor nobody reads.
    forget = 6,

    // The seventh addresses a runtime and carries no ref, and it is here
    // rather than on the deliver sink because deliver honours `--mode in` and
    // would silently narrow self.owner_broadcast().
    broadcast = 7,
};

// `to` is the runtime the op is performed on and `from` the one that asked,
// both names because the two ends are different runtimes and the daemon
// resolves `to` through the map it is the authority for.
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
    // does, or a newer peer's sixth op becomes a `data` delivery of the wrong
    // bytes.
    if (raw < static_cast<uint8_t>(route_op::open) ||
        raw > static_cast<uint8_t>(route_op::broadcast))
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

// The argument to the `route` op, riding in the map request's `config` field,
// with the target runtime left in the request's `name` where every other op
// puts it.
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

// cluster_ev carries an observation only the daemon can make, with
// on_group_change's members resolved here so a script in a worker is handed
// the same table a script in the daemon is.
using cluster_ev_member = ::cluster_ev_member;
using cluster_ev_wire   = ::cluster_ev_wire;

inline std::string encode_cluster_event(const cluster_ev_wire& e)
{
    std::string out;
    out.push_back(static_cast<char>(e.kind));
    put_str(out, e.daemon_name);
    put_str(out, e.host);
    put_str(out, e.group_name);
    put_u32(out, static_cast<uint32_t>(e.members.size()));
    for (const auto& m : e.members)
    {
        put_str(out, m.daemon);
        put_str(out, m.host);
        put_u16(out, m.port);
    }
    return out;
}

inline bool decode_cluster_event(std::string_view payload, cluster_ev_wire& e)
{
    reader r(payload.data(), payload.size());
    e.kind        = r.u8();
    e.daemon_name = std::string(r.str());
    e.host        = std::string(r.str());
    e.group_name  = std::string(r.str());
    const uint32_t n = r.u32();
    if (!r.ok)
        return false;
    // Bounded before it is reserved, so a corrupt frame cannot ask for more
    // members than the payload could hold.
    if (n > payload.size() / 6)
        return false;
    e.members.clear();
    e.members.reserve(n);
    for (uint32_t i = 0; i < n; ++i)
    {
        cluster_ev_member m;
        m.daemon = std::string(r.str());
        m.host   = std::string(r.str());
        m.port   = r.u16();
        if (!r.ok)
            return false;
        e.members.push_back(std::move(m));
    }
    return r.ok;
}

// ── The runtime map, replicated ─────────────────────────────────────────────
// What runtimes there are, which the endpoint table does not answer, pushed as
// a whole map rather than asked per call so socketley.get() never blocks a
// worker's loop on a round trip -- at the price of a replica as old as the
// last push.  State travels as u8 because that enum is append-only; the type
// travels by name, as the cluster snapshot's already does, because a
// registered type's id is assigned per process and two manifest sets disagree.

struct runtime_wire
{
    std::string name;
    std::string type;       // type_to_string(runtime_type)
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
        put_str(out, r.type);
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
        e.type        = std::string(r.str());
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

// The cluster as a worker is allowed to see it: a separate frame because a
// remote daemon joining moves nothing in the local map, carrying
// cluster_discovery's own structs verbatim, because a worker running a
// discovery of its own would claim the node name and read as a second daemon.

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

// The shortest interval two publishes may be, which is also the floor the
// daemon coalesces its map pushes to, because the map carries the connection
// counts and two different periods either resend numbers or hold new ones
// back.
inline constexpr int stats_interval_ms = 250;

// ── Stats payload ───────────────────────────────────────────────────────────
// The four counters, the active count and the detail text -- which is what
// runtime_instance already publishes for off-thread readers -- with no moment
// travelling alongside them, because the counters are summed out of shared
// memory at print time and the ones here are only the fallback.

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
    // Trailing bytes a newer sender appended are left where they are, because
    // the frame header carries the length and take_frame() has already
    // consumed them.
    return r.ok;
}

// ── Published message payload ───────────────────────────────────────────────
// A publish travels as its three length-prefixed strings, one-way and
// best-effort like every frame on this socket, with nothing to re-send it from
// -- because a publish is an event rather than a state.

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

// A length-prefixed frame carrying whatever would have arrived on the target's
// own port, rather than the cache's text protocol, whose replies are not
// self-delimiting, or RESP, which needs an arity table per command to produce.
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
