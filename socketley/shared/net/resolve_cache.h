#pragma once

// One resolved address per host:port, kept for as long as it is worth reusing.
//
// glibc caches nothing: every getaddrinfo is a fresh question for whatever
// /etc/resolv.conf names, and it blocks the thread that asks -- which in every
// runtime here is the event loop.  A box with a caching stub answers in well
// under a millisecond; a container pointed straight at a network resolver pays
// a round trip per call, and one whose resolver does not answer pays the
// ceiling in shared/ipc/worker_env.h.
//
// WHY ONLY ONE CALLER.  Every other resolver in this tree is already bounded
// by something the caller owns: a client re-resolves at most once per second
// of reconnect backoff and clears its address deliberately, so a container
// that moved is followed; a server's upstreams, a proxy's names and a cache's
// master are looked up off the loop by async_resolver.h; the rest run once at
// start.  socketley.http() was the exception --
// it resolved on every call, with no bound at all, and the comment above it
// says a resolver escapes both the call's deadline and the callback budget.
// Handing this to the others would undo decisions they made on purpose.
//
// The lifetime is a floor on how often we ASK, not a claim about the record:
// getaddrinfo does not hand back the TTL it was given, so there is nothing
// here to honour.  It is the slow way to notice a moved endpoint; the fast one
// is drop(), called when a connect to the cached address is refused -- the
// same rule client_instance and server_instance apply to their own.

#include <chrono>
#include <cstring>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <vector>

namespace socketley
{

class resolve_cache
{
public:
    // What the caller actually used out of the addrinfo list: the first entry,
    // which is all socketley_http_call ever read.
    struct entry
    {
        sockaddr_storage addr{};
        socklen_t        len{0};
        int              family{0};
    };

    using clock = std::chrono::steady_clock;

    explicit resolve_cache(std::chrono::milliseconds lifetime,
                           size_t capacity = 32)
        : m_lifetime(lifetime), m_capacity(capacity ? capacity : 1) {}

    // True when a live answer is held, in which case `out` is filled.
    bool get(std::string_view key, entry& out)
    {
        const auto now = clock::now();
        for (auto it = m_rows.begin(); it != m_rows.end(); ++it)
        {
            if (it->key != key)
                continue;
            // Found but stale: dropped here rather than left for the sweep, so
            // a key asked for repeatedly cannot hold a dead row forever.
            if (now >= it->expires)
            {
                m_rows.erase(it);
                return false;
            }
            out = it->value;
            return true;
        }
        return false;
    }

    void put(std::string_view key, const entry& value)
    {
        const auto now = clock::now();
        const auto expires = now + m_lifetime;

        for (auto& row : m_rows)
            if (row.key == key)
            {
                row.value = value;
                row.expires = expires;
                return;
            }

        // Room is made from what has already expired before anything live is
        // given up, so a burst of one-off hosts cannot evict the one host a
        // script actually loops on.
        if (m_rows.size() >= m_capacity)
        {
            for (auto it = m_rows.begin(); it != m_rows.end();)
                it = (now >= it->expires) ? m_rows.erase(it) : it + 1;
        }
        if (m_rows.size() >= m_capacity)
        {
            auto oldest = m_rows.begin();
            for (auto it = m_rows.begin(); it != m_rows.end(); ++it)
                if (it->expires < oldest->expires)
                    oldest = it;
            m_rows.erase(oldest);
        }

        m_rows.push_back(row{ std::string(key), value, expires });
    }

    // The address that just refused goes with the attempt, which is the rule
    // the client and the server already follow at their own reconnects: a
    // lifetime is the slow way to notice a moved endpoint and a failed connect
    // is the fast one, so the next call asks again instead of waiting it out.
    void drop(std::string_view key)
    {
        for (auto it = m_rows.begin(); it != m_rows.end(); ++it)
            if (it->key == key)
            {
                m_rows.erase(it);
                return;
            }
    }

    size_t size() const { return m_rows.size(); }

private:
    struct row
    {
        std::string       key;
        entry             value;
        clock::time_point expires;
    };

    std::vector<row>          m_rows;
    std::chrono::milliseconds m_lifetime;
    size_t                    m_capacity;
};

}   // namespace socketley
