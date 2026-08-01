#pragma once
// Where the runtimes a proxy forwards to actually are: a snapshot of
// name → endpoint and group → endpoints, built by the daemon and handed to the
// runtimes that need it.
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// An @group backend used to be resolved by calling into runtime_manager on the
// connection path: take its mutex, walk every runtime in the daemon, keep the
// ones whose group tag matches, and read get_port() off each *live instance
// pointer*.  Two things are wrong with that, and only one of them is about
// speed.
//
// The first is that a proxy reaches into other runtimes' objects to do it.
// Nothing crosses that boundary except a host and a port — the pointer exists
// solely to fetch a number — and holding one is what makes the daemon a single
// address space rather than a supervisor.  A pointer cannot be sent over a
// socket; a host and a port can.  So the proxy is handed the answer instead of
// the means to compute it, and with that it needs no manager at all.
//
// The second is that the answer is rebuilt from scratch every time although it
// changes only when a runtime starts, stops, is created, removed or renamed, or
// when the cluster's view of a remote daemon changes.  Those are the moments
// the table is republished — a few per minute at most — and between them the
// proxy reads its own copy with no lock in sight.
//
// The snapshot is shared, not copied per runtime: it is immutable once
// published, so every reader can hold the same one, and a reader that is
// mid-request when a new table arrives keeps the one it started with rather
// than watching endpoints appear underneath it.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Declared routes travel in this snapshot too — see the second half of the
// class.  Held by pointer so that this header does not have to know what a
// route is; shared/route_table.h owns that, and includes this one for the
// transparent hash below.
class route_table;

// Transparent hash for heterogeneous lookup (avoids string copies on find).
// Lives here rather than in runtime_manager.h because the lookups on the
// connection path are the ones that must not allocate, and they are here.
struct runtime_string_hash
{
    using is_transparent = void;

    size_t operator()(std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }

    size_t operator()(const std::string& s) const noexcept
    {
        return std::hash<std::string_view>{}(s);
    }
};

struct runtime_string_equal
{
    using is_transparent = void;

    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept
    {
        return lhs == rhs;
    }
};

struct runtime_endpoint
{
    std::string host;
    uint16_t    port{0};
};

class endpoint_table
{
public:
    template <typename Map>
    using transparent_map = std::unordered_map<std::string, Map,
                                               runtime_string_hash, runtime_string_equal>;

    void set_name(std::string name, runtime_endpoint ep)
    {
        m_by_name.insert_or_assign(std::move(name), std::move(ep));
    }

    void add_to_group(std::string_view group, runtime_endpoint ep)
    {
        auto it = m_by_group.find(group);
        if (it == m_by_group.end())
            it = m_by_group.emplace(std::string(group), std::vector<runtime_endpoint>{}).first;
        it->second.push_back(std::move(ep));
    }

    // nullptr rather than an empty endpoint: "this name is not in the table" and
    // "this name resolves to port 0" are different answers, and only the second
    // is a configuration error worth reporting.
    const runtime_endpoint* find_name(std::string_view name) const
    {
        const auto it = m_by_name.find(name);
        return (it == m_by_name.end()) ? nullptr : &it->second;
    }

    const std::vector<runtime_endpoint>* find_group(std::string_view group) const
    {
        const auto it = m_by_group.find(group);
        return (it == m_by_group.end()) ? nullptr : &it->second;
    }

    size_t name_count()  const { return m_by_name.size(); }
    size_t group_count() const { return m_by_group.size(); }

    // ── What each of those endpoints says it will answer ────────────────────
    //
    // The same snapshot, because it is the same question asked one step
    // further: not "where is this runtime" but "which requests will it take".
    // Both change at exactly the same moments — a runtime starting, stopping,
    // being created, removed, renamed or reloaded — and publishing them apart
    // would let a proxy hold this table's endpoints beside the last table's
    // routes, which is the drift the whole design exists to prevent.
    //
    // A shared_ptr because one declaration is read by every proxy that names
    // the runtime, and none of them modifies it: the pointer is what makes
    // "immutable once published, shared not copied" true of the routes as well.
    // A runtime whose script declares nothing has no entry here at all, which
    // is what tells a proxy to forward as it always did.
    void set_name_routes(std::string name, std::shared_ptr<const route_table> rt)
    {
        m_routes_by_name.insert_or_assign(std::move(name), std::move(rt));
    }

    void set_group_routes(std::string group, std::shared_ptr<const route_table> rt)
    {
        m_routes_by_group.insert_or_assign(std::move(group), std::move(rt));
    }

    const route_table* find_name_routes(std::string_view name) const
    {
        const auto it = m_routes_by_name.find(name);
        return (it == m_routes_by_name.end()) ? nullptr : it->second.get();
    }

    const route_table* find_group_routes(std::string_view group) const
    {
        const auto it = m_routes_by_group.find(group);
        return (it == m_routes_by_group.end()) ? nullptr : it->second.get();
    }

    bool any_routes() const
    {
        return !m_routes_by_name.empty() || !m_routes_by_group.empty();
    }

    // For a reader that has to send the whole table somewhere rather than ask
    // it questions — the daemon encoding it onto a worker's control socket.
    // Const throughout: the table is immutable once published, and a caller
    // able to walk it mutably could change what another runtime is already
    // routing from.
    const transparent_map<runtime_endpoint>& names() const { return m_by_name; }
    const transparent_map<std::vector<runtime_endpoint>>& groups() const { return m_by_group; }

private:
    transparent_map<runtime_endpoint>              m_by_name;
    transparent_map<std::vector<runtime_endpoint>> m_by_group;

    transparent_map<std::shared_ptr<const route_table>> m_routes_by_name;
    // Per group, the union of what its members declare — merged once here
    // rather than once per proxy, and a union rather than an intersection for
    // the reason route_table::merge gives.
    transparent_map<std::shared_ptr<const route_table>> m_routes_by_group;
};
