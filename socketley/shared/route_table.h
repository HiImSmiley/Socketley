#pragma once
// What a runtime says it will answer: a path, and the methods allowed on it.
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// A proxy in front of an HTTP handler can refuse a request the handler was
// always going to refuse — a DELETE on a login endpoint that takes POST and GET
// — and refusing it at the edge costs no connect, no pooled socket, no round
// trip and no work in the handler.  What the proxy cannot do is *know* which
// methods those are.
//
// Configured on the proxy, that method list is a second copy of something the
// handler already states in its own code: one truth written down in two
// runtimes, and soon in two processes.  Two copies drift.  The handler grows
// PATCH, the proxy goes on refusing it, and what the operator sees is a 405
// that neither side can explain alone — the handler's code plainly accepts
// PATCH, and the proxy is plainly doing what it was told.
//
// So the declaration belongs to the handler and is *published* to the proxy.
// That is the move shared/endpoint_table.h already makes for "where is this
// runtime": the answer is handed over as data instead of being derived
// independently in two places.  A route table travels inside that same snapshot
// rather than beside it, because a proxy holding new endpoints and stale routes
// would be precisely the drift this exists to end.
//
// ─── WHAT IT DELIBERATELY DOES NOT HOLD ─────────────────────────────────────
//
// A path and a set of methods.  Not content types, not schemas, not roles, not
// parameter types, not rate limits.  The two it holds are the two the proxy can
// check from the request line it has already parsed, without reading a body and
// without knowing anything about the application.  Everything past them is a
// rule that has to be kept right in two runtimes at once, and a declaration that
// grows enough of them is a gateway configuration language whose every sentence
// is a second place to be wrong.  Policy that needs more than the request line
// has somewhere to live already: the filter chain (proxy_instance::
// run_request_filters), which runs in the proxy and is written once.
//
// ─── AND IT IS NOT INPUT VALIDATION ─────────────────────────────────────────
//
// The proxy can confirm the method is one the handler declared.  It cannot
// confirm the body is a well-formed login, and it is not the only way in: a
// socketley server listens on its own port, and a request that arrives there
// never passed an edge at all.  A handler that stops checking because "the
// gateway checks" is safe only for as long as every request comes through the
// gateway, which is a property of the deployment and not of the code.  The
// declaration is an optimisation and a statement of intent; the handler is
// still the authority on its own input.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "endpoint_table.h"   // runtime_string_hash / runtime_string_equal

// One declared route.
//
// `prefix` is a path declared with a trailing '*' — "/static/*" — and `path`
// then holds what comes before it.  That is the whole of the pattern language,
// on purpose: exact, or a literal prefix.  Anything richer (captures, regular
// expressions, typed segments) is a second parser to keep in step with whatever
// the handler's own router does, and a mismatch between the two is a request
// refused at the edge that the handler would have served.
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
    // Bounds, not tuning knobs.  A declaration is walked once per publication
    // and looked up once per request; these exist so that a script with a
    // generated routing table cannot turn either into unbounded work, and so
    // that a refusal names a number rather than being a mystery.
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

    // `path` is as the *handler* sees it — the path a request carries after the
    // proxy has stripped its own /<name>/ prefix.  A declaration is written in
    // the handler's script, so it can only be about the handler's own paths.
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

        // Twice in one script is a typo, and the two are usually different —
        // that is the point of writing it twice.  Silently unioning them would
        // make the wider of the two win with nothing on screen to say so, so
        // this is refused where the operator can still see it.  Across
        // runtimes it is not a typo but a group with two members that answer
        // the same path, and merge() below unions those deliberately.
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

    // Fold in another runtime that could receive the same request: a second
    // member of the same group, or a second backend of the same proxy.  The
    // result describes both, and both halves of it follow from one rule —
    // nothing may be refused that *either* of them might have served.
    //
    //   A path only one of them declares is DROPPED.  A declaration speaks
    //   about the paths it names and says nothing about the others, so a
    //   runtime that never mentioned /login may well serve /login; refusing a
    //   method there because its neighbour declared the path would refuse at
    //   the edge what the request's actual target was going to answer.  This is
    //   why folding in a runtime that declares nothing leaves nothing behind,
    //   which is exactly right: it has told us nothing, so nothing can be
    //   refused on its account.
    //
    //   A path both declare keeps the UNION of their methods.  Selection picks
    //   a target per connection and this side cannot know which — that is what
    //   round-robin means — so only a method neither would take may be refused.
    //
    // Order matters only for the Allow header, which lists this table's methods
    // before the ones folded in.  Callers fold in a deterministic order (backend
    // configuration order; group members by name) so that the header a client
    // gets does not depend on the order a hash map happened to be walked in.
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

    // Every declaration, in the order they were added.  Needed because a
    // declaration made in a worker has to reach the daemon, which publishes it
    // to whoever routes to that runtime — see worker_protocol's encode_routes.
    const std::vector<route_decl>& all() const { return m_routes; }

    bool   empty() const { return m_routes.empty(); }
    // Reported by a proxy's `stats` as declared_routes; see there for why a
    // number nobody can see is a feature nobody can debug.
    size_t size()  const { return m_routes.size(); }

    // The route a request path falls under, or nullptr for a path nobody
    // declared.
    //
    // nullptr means "no declaration covers this", and the caller forwards — it
    // does NOT mean "not found".  A declaration is a statement about the paths
    // it names and says nothing whatever about the ones it does not: a handler
    // is free to answer paths it never declared, and a gateway that turned
    // silence into a 404 would make declaring one route the act of hiding every
    // other.  Enforcement is opt-in per path, one path at a time.
    //
    // `path` must already have had its query string removed; see
    // route_path_only().
    const route_decl* find(std::string_view path) const
    {
        if (const auto it = m_exact.find(path); it != m_exact.end())
            return &m_routes[it->second];
        // Longest first, so "/api/v2/*" beats "/api/*" for a path under both.
        // m_prefixes is kept in that order at insert time; there are few of
        // them and this runs once per request.
        for (const uint32_t idx : m_prefixes)
        {
            const auto& r = m_routes[idx];
            if (path.size() >= r.path.size() && path.compare(0, r.path.size(), r.path) == 0)
                return &r;
        }
        return nullptr;
    }

    // Whether this route admits this method.
    //
    // Two methods are admitted beyond what was declared, and both are RFC
    // 9110, not politeness:
    //
    //   HEAD, wherever GET is declared (§9.3.2).  A HEAD is a GET whose
    //   response body is dropped; a handler that serves GET serves HEAD
    //   whether or not it thought about it, and refusing HEAD at the edge
    //   breaks every cache validator and link checker there is.
    //
    //   OPTIONS, always (§9.3.7).  A route that declares only POST would
    //   otherwise have the proxy answer 405 to the CORS *preflight* a browser
    //   sends before the POST — and the POST is then never sent at all.  What
    //   the operator sees is a CORS error on a request their code never made,
    //   and nothing in either runtime's logs mentions a preflight.  The gate
    //   never refuses OPTIONS; proxy_instance decides separately whether to
    //   answer it from the declaration or forward it.
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

    // The value of the Allow header a 405 carries.  RFC 9110 §15.5.6 requires
    // one, and it is free here: the declaration *is* the list.  Without it a
    // client is told no and not told what would have worked, which is the
    // difference between a diagnosable failure and an afternoon.
    //
    // The two implied methods above are listed too — a client that is told GET
    // is allowed and HEAD is not has been told something untrue.
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

    // RFC 9110 §9 method names are tokens.  A declaration carrying anything
    // else would end up in an Allow header this proxy emits, and a header value
    // with a CR in it is response splitting with the gateway as the vehicle.
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
            // Control bytes and space would make the declaration unmatchable
            // against a request line, which is split on spaces; '?' and '#'
            // are not part of a path at all and a declaration carrying one
            // would never match anything.
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

    // Replace the routes and rebuild both lookup structures from them.  The
    // index is by position, so nothing may edit m_routes without coming
    // through here or through add().
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

// The path part of a request target, which is the only part a declaration
// speaks about.  "/endpoint/login?next=/home" is the login route; a gate that
// compared the whole target would forward every request that carried a query
// string, which is most of them.
inline std::string_view route_path_only(std::string_view target)
{
    const auto q = target.find_first_of("?#");
    return (q == std::string_view::npos) ? target : target.substr(0, q);
}
