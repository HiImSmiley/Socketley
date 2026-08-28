#pragma once
// A path and the methods allowed on it, declared by the handler and published
// to the proxy so the two cannot drift, as an optimisation and not as input
// validation.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "endpoint_table.h"   // runtime_string_hash / runtime_string_equal

// Exact, or a literal prefix ("/static/*") -- anything richer is a second
// parser to keep in step with the handler's own router.
struct route_decl
{
    std::string              path;
    bool                     prefix{false};
    // Uppercased, deduplicated, in the order declared — the order is what the
    // Allow header is built from, so it is the order the operator wrote.
    std::vector<std::string> methods;
};

class route_table
{
public:
    // Bounds, not tuning knobs: a generated table must not become unbounded work.
    static constexpr size_t MAX_ROUTES  = 512;
    static constexpr size_t MAX_METHODS = 16;
    static constexpr size_t MAX_PATH    = 512;

    enum class add_result : uint8_t
    {
        ok,
        bad_path,      // empty, no leading '/', too long, or a byte a path may not carry
        bad_method,    // not a token, or none given
        too_many,      // MAX_ROUTES / MAX_METHODS
        duplicate,     // this path is declared twice in one script
    };

    // `path` is as the handler sees it, after the proxy has stripped its own
    // /<name>/ prefix.
    add_result add(std::string_view path, const std::vector<std::string>& methods)
    {
        if (m_routes.size() >= MAX_ROUTES)
            return add_result::too_many;
        if (methods.empty() || methods.size() > MAX_METHODS)
            return add_result::bad_method;

        bool is_prefix = false;
        std::string_view p = path;
        if (!p.empty() && p.back() == '*')
        {
            is_prefix = true;
            p.remove_suffix(1);
        }
        if (!path_ok(p))
            return add_result::bad_path;

        route_decl d;
        d.path   = std::string(p);
        d.prefix = is_prefix;

        for (const auto& m : methods)
        {
            if (!method_token_ok(m))
                return add_result::bad_method;
            std::string up(m);
            for (auto& c : up)
                c = to_upper(c);
            bool seen = false;
            for (const auto& have : d.methods)
                if (have == up) { seen = true; break; }
            if (!seen)
                d.methods.push_back(std::move(up));
        }

        // Twice in one script is a typo; across runtimes it is a group, which
        // merge_alternative() unions deliberately.
        if (find_exact(d.path, d.prefix) != nullptr)
            return add_result::duplicate;

        const uint32_t idx = static_cast<uint32_t>(m_routes.size());
        m_routes.push_back(std::move(d));
        if (is_prefix)
            insert_prefix(idx);
        else
            m_exact.emplace(m_routes[idx].path, idx);
        return add_result::ok;
    }

    // Fold in a runtime that could receive the same request; nothing may be
    // refused that either might have served, so a path only one declares is
    // dropped and a path both declare keeps the union of their methods.
    void merge_alternative(const route_table& other)
    {
        std::vector<route_decl> kept;
        kept.reserve(m_routes.size());

        for (const auto& mine : m_routes)
        {
            const route_decl* theirs = other.find_exact(mine.path, mine.prefix);
            if (!theirs)
                continue;

            route_decl d = mine;
            for (const auto& m : theirs->methods)
            {
                bool seen = false;
                for (const auto& have : d.methods)
                    if (have == m) { seen = true; break; }
                if (!seen && d.methods.size() < MAX_METHODS)
                    d.methods.push_back(m);
            }
            kept.push_back(std::move(d));
        }

        reindex(std::move(kept));
    }

    void clear()
    {
        m_routes.clear();
        m_exact.clear();
        m_prefixes.clear();
    }

    // Every declaration in the order they were added, because one made in a
    // worker has to reach the daemon that publishes it.
    const std::vector<route_decl>& all() const { return m_routes; }

    bool   empty() const { return m_routes.empty(); }
    // Reported by a proxy's `stats` as declared_routes; see there for why a
    // number nobody can see is a feature nobody can debug.
    size_t size()  const { return m_routes.size(); }

    // nullptr means no declaration covers this and the caller forwards rather
    // than 404s, with `path` already stripped of its query string.
    const route_decl* find(std::string_view path) const
    {
        if (const auto it = m_exact.find(path); it != m_exact.end())
            return &m_routes[it->second];
        // Longest first, so "/api/v2/*" beats "/api/*" for a path under both.
        for (const uint32_t idx : m_prefixes)
        {
            const auto& r = m_routes[idx];
            if (path.size() >= r.path.size() && path.compare(0, r.path.size(), r.path) == 0)
                return &r;
        }
        return nullptr;
    }

    // HEAD wherever GET is declared and OPTIONS always, both RFC 9110 -- a 405
    // on a CORS preflight means the real request is never sent at all.
    static bool method_allowed(const route_decl& r, std::string_view method)
    {
        if (method == "OPTIONS")
            return true;
        for (const auto& m : r.methods)
            if (m == method)
                return true;
        if (method == "HEAD")
            for (const auto& m : r.methods)
                if (m == "GET")
                    return true;
        return false;
    }

    // Required by RFC 9110 and free here; lists the two implied methods too.
    static std::string allow_header(const route_decl& r)
    {
        std::string out;
        bool has_head = false, has_get = false, has_options = false;
        for (const auto& m : r.methods)
        {
            if (m == "HEAD")    has_head = true;
            if (m == "GET")     has_get = true;
            if (m == "OPTIONS") has_options = true;
        }
        for (const auto& m : r.methods)
        {
            if (!out.empty()) out += ", ";
            out += m;
        }
        if (has_get && !has_head)
        {
            if (!out.empty()) out += ", ";
            out += "HEAD";
        }
        if (!has_options)
        {
            if (!out.empty()) out += ", ";
            out += "OPTIONS";
        }
        return out;
    }

    // RFC 9110 method names are tokens, and anything else would reach an Allow
    // header, where a CR is response splitting with the gateway as the
    // vehicle.
    static bool method_token_ok(std::string_view s)
    {
        if (s.empty() || s.size() > 24)
            return false;
        for (char c : s)
        {
            const unsigned char u = static_cast<unsigned char>(c);
            if (u <= 0x20 || u >= 0x7F)
                return false;
            switch (c)
            {
                case '(': case ')': case ',': case '/': case ':': case ';':
                case '<': case '=': case '>': case '?': case '@': case '[':
                case '\\': case ']': case '{': case '}': case '"':
                    return false;
                default: break;
            }
        }
        return true;
    }

private:
    static char to_upper(char c)
    {
        return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
    }

    static bool path_ok(std::string_view p)
    {
        if (p.empty() || p.size() > MAX_PATH || p.front() != '/')
            return false;
        for (char c : p)
        {
            const unsigned char u = static_cast<unsigned char>(c);
            // A request line is split on spaces, and '?'/'#' are not path.
            if (u <= 0x20 || u == 0x7F || c == '?' || c == '#')
                return false;
        }
        return true;
    }

    const route_decl* find_exact(std::string_view path, bool prefix) const
    {
        for (const auto& r : m_routes)
            if (r.prefix == prefix && r.path == path)
                return &r;
        return nullptr;
    }

    route_decl* find_exact_mutable(std::string_view path, bool prefix)
    {
        for (auto& r : m_routes)
            if (r.prefix == prefix && r.path == path)
                return &r;
        return nullptr;
    }

    // Replace the routes and rebuild both lookup structures, which the index
    // by position requires nothing bypass.
    void reindex(std::vector<route_decl>&& routes)
    {
        m_routes = std::move(routes);
        m_exact.clear();
        m_prefixes.clear();
        for (uint32_t i = 0; i < m_routes.size(); ++i)
        {
            if (m_routes[i].prefix)
                insert_prefix(i);
            else
                m_exact.emplace(m_routes[i].path, i);
        }
    }

    void insert_prefix(uint32_t idx)
    {
        const size_t len = m_routes[idx].path.size();
        auto pos = m_prefixes.begin();
        while (pos != m_prefixes.end() && m_routes[*pos].path.size() >= len)
            ++pos;
        m_prefixes.insert(pos, idx);
    }

    // Indices, not pointers: the vector reallocates as routes are added, and a
    // table is copied wholesale when a proxy merges its backends' declarations.
    std::vector<route_decl>                       m_routes;
    endpoint_table::transparent_map<uint32_t>     m_exact;
    std::vector<uint32_t>                         m_prefixes;   // longest first
};

// The path part of a request target; comparing the whole target would forward
// every request carrying a query string.
inline std::string_view route_path_only(std::string_view target)
{
    const auto q = target.find_first_of("?#");
    return (q == std::string_view::npos) ? target : target.substr(0, q);
}
