#pragma once
// Where the runtimes a proxy forwards to actually are, as a snapshot of name
// and group to endpoint that the daemon republishes on the few events that
// change it, immutable and shared so no reader takes a lock or reaches into
// another runtime's objects.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Declared routes travel in this snapshot too, held by pointer so this header
// need not know what a route is.
class route_table;

// Transparent hash for heterogeneous lookup, here rather than in
// runtime_manager.h because the lookups that must not allocate are here.
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

    // A second way to the same runtime, for callers already on this box: the
    // node it also listens on.  Empty means there is none, and `port == 0`
    // with a path in `host` still means a runtime that has ONLY a node --
    // those are two different runtimes, not two spellings of one.
    std::string unix_path;
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

    // The node of a runtime listening at exactly this address, or empty.  By
    // host AND port: a port alone would match a foreign service on another
    // interface, and the whole point of the address form is that it names an
    // address rather than a runtime.
    std::string_view find_node_at(std::string_view host, uint16_t port) const
    {
        if (port == 0)
            return {};
        for (const auto& [_, ep] : m_by_name)
            if (ep.port == port && ep.host == host && !ep.unix_path.empty())
                return ep.unix_path;
        return {};
    }

    const std::vector<runtime_endpoint>* find_group(std::string_view group) const
    {
        const auto it = m_by_group.find(group);
        return (it == m_by_group.end()) ? nullptr : &it->second;
    }

    size_t name_count()  const { return m_by_name.size(); }
    size_t group_count() const { return m_by_group.size(); }

    // The same snapshot asked one step further -- which requests an endpoint
    // will take -- published together so no proxy holds this table's endpoints
    // beside the last table's routes.
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

    // For a reader that has to send the whole table somewhere, const
    // throughout because a mutable walk could change what another runtime is
    // already routing from.
    const transparent_map<runtime_endpoint>& names() const { return m_by_name; }
    const transparent_map<std::vector<runtime_endpoint>>& groups() const { return m_by_group; }

    // The declarations too, without which the encoder could only carry hosts
    // and ports.
    const transparent_map<std::shared_ptr<const route_table>>& name_routes() const
    { return m_routes_by_name; }
    const transparent_map<std::shared_ptr<const route_table>>& group_routes() const
    { return m_routes_by_group; }

private:
    transparent_map<runtime_endpoint>              m_by_name;
    transparent_map<std::vector<runtime_endpoint>> m_by_group;

    transparent_map<std::shared_ptr<const route_table>> m_routes_by_name;
    // Per group, the union of what its members declare — merged once here
    // rather than once per proxy, and a union rather than an intersection for
    // the reason route_table::merge gives.
    transparent_map<std::shared_ptr<const route_table>> m_routes_by_group;
};
