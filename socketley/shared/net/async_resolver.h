#pragma once
// Host names resolved without the event loop waiting: the loop's own resolver is asked first (dns_client), and only
// a name it cannot say about goes to the system's on a thread of its own, its answer taken up by the caller on a later
// turn, so a resolver that hangs costs the loop nothing either way.
//
// The caller asks again until the answer is there -- a timer or a retry it already has -- which is also what reads
// the loop resolver's answer off its socket.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "dns_client.h"
#include "endpoint.h"

namespace socketley
{

class async_resolver
{
public:
    using address = endpoint;

    enum class state : uint8_t { pending, ready, failed };

    // The port written into an address the lookup gave, which asks for none.
    static void set_port(address& a, uint16_t port)
    {
        if (a.addr.ss_family == AF_INET)
            reinterpret_cast<sockaddr_in*>(&a.addr)->sin_port = htons(port);
        else if (a.addr.ss_family == AF_INET6)
            reinterpret_cast<sockaddr_in6*>(&a.addr)->sin6_port = htons(port);
    }

    // What is known of `host` for `family` (AF_INET, AF_INET6 or AF_UNSPEC): a lookup is started when there is
    // none or the last answer is older than `fresh`, and `out` holds the addresses when the state is ready.
    state lookup(const std::string& host, int family, std::vector<address>& out,
                 std::chrono::seconds fresh = std::chrono::seconds(30))
    {
        const std::string key = host + '\n' + std::to_string(family);
        const auto now = std::chrono::steady_clock::now();
        auto& e = m_entries[key];
        if (e && e->done.load(std::memory_order_acquire))
        {
            // A failure is held a second only, so a name that comes up is found by the next tick that asks.
            if (now - e->at < (e->addrs.empty() ? std::min(fresh, std::chrono::seconds(1)) : fresh))
            {
                if (e->addrs.empty())
                    return state::failed;
                out = e->addrs;
                return state::ready;
            }
            e.reset();
        }
        if (!e)
        {
            // Bounded, since names come from configuration and a map of them is that small.
            if (m_entries.size() > max_entries)
                prune(now, fresh);
            e = std::make_shared<entry>();
            e->at = now;
            e->on_loop = true;
        }
        if (e->on_loop)
        {
            std::vector<address> got;
            switch (dns_client::here().ask(host, family, got))
            {
                case dns_client::state::pending:
                    return state::pending;
                case dns_client::state::ready:
                    e->on_loop = false;
                    e->addrs   = got;
                    e->at      = now;
                    e->done.store(true, std::memory_order_release);
                    out = std::move(got);
                    return state::ready;
                case dns_client::state::unsure:
                    e->on_loop = false;
                    auto job = e;
                    std::thread([job, host, family]() { answer(*job, host, family); }).detach();
                    break;
            }
        }
        return state::pending;
    }

    // The same question answered on the calling thread, for a start path that waits for its dial anyway.
    state lookup_now(const std::string& host, int family, std::vector<address>& out)
    {
        if (m_entries.size() > max_entries)
            prune(std::chrono::steady_clock::now(), std::chrono::seconds(30));
        auto e = std::make_shared<entry>();
        answer(*e, host, family);
        m_entries[host + '\n' + std::to_string(family)] = e;
        if (e->addrs.empty())
            return state::failed;
        out = e->addrs;
        return state::ready;
    }

    // Forgets what is known of `host`, so the next lookup asks again at once, as after a connect that failed.
    void forget(const std::string& host)
    {
        for (auto it = m_entries.begin(); it != m_entries.end();)
            it = it->first.compare(0, host.size() + 1, host + '\n') == 0 && it->second &&
                         it->second->done.load(std::memory_order_acquire)
                     ? m_entries.erase(it) : std::next(it);
    }

private:
    struct entry
    {
        std::atomic<bool>                     done{false};
        std::chrono::steady_clock::time_point at{};
        std::vector<address>                  addrs;
        // Still with the loop's resolver, which no thread touches.
        bool                                  on_loop{false};
    };

    static constexpr size_t max_entries = 1024;

    static void answer(entry& e, const std::string& host, int family)
    {
        e.addrs = resolve_all(host, nullptr, family);
        e.at = std::chrono::steady_clock::now();
        e.done.store(true, std::memory_order_release);
    }

    void prune(std::chrono::steady_clock::time_point now, std::chrono::seconds fresh)
    {
        for (auto it = m_entries.begin(); it != m_entries.end();)
            it = !it->second || (it->second->done.load(std::memory_order_acquire) && now - it->second->at >= fresh)
                     ? m_entries.erase(it) : std::next(it);
    }

    std::unordered_map<std::string, std::shared_ptr<entry>> m_entries;
};

}  // namespace socketley
