#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace socketley
{

// Failed sign-ins counted per address: past `tries` within `window` from the first of them, the address is barred
// until that window ends, and at most `cap` addresses are remembered.
class failure_bar
{
public:
    using clock = std::chrono::steady_clock;

    failure_bar(uint32_t tries, clock::duration window, size_t cap = 16384)
        : m_tries(tries), m_window(window), m_cap(cap)
    {
    }

    // Whole seconds until `key` may try again, at least one, and 0 while it may now.
    int64_t barred_for(const std::string& key, clock::time_point now)
    {
        const auto it = m_misses.find(key);
        if (it == m_misses.end())
            return 0;
        if (now - it->second.first >= m_window)
        {
            m_misses.erase(it);
            return 0;
        }
        if (it->second.count < m_tries)
            return 0;
        return std::max<int64_t>(1, std::chrono::ceil<std::chrono::seconds>(it->second.first + m_window - now).count());
    }

    void missed(const std::string& key, clock::time_point now)
    {
        if (m_misses.size() >= m_cap && !m_misses.contains(key))
            make_room(now);
        misses& m = m_misses[key];
        if (m.count == 0 || now - m.first >= m_window)
        {
            m.count = 0;
            m.first = now;
        }
        ++m.count;
    }

    void clear() { m_misses.clear(); }

private:
    struct misses
    {
        uint32_t          count{0};
        clock::time_point first{};
    };

    // An eighth goes at once, the expired and then the oldest, so a flood of new keys pays a scan per thousands of
    // them and not one each.
    void make_room(clock::time_point now)
    {
        std::erase_if(m_misses, [&](const auto& m) { return now - m.second.first >= m_window; });
        if (m_misses.size() < m_cap)
            return;
        std::vector<clock::time_point> firsts;
        firsts.reserve(m_misses.size());
        for (const auto& [k, m] : m_misses)
            firsts.push_back(m.first);
        const size_t cut = firsts.size() / 8;
        std::nth_element(firsts.begin(), firsts.begin() + static_cast<std::ptrdiff_t>(cut), firsts.end());
        const auto before = firsts[cut];
        std::erase_if(m_misses, [&](const auto& m) { return m.second.first < before; });
        if (m_misses.size() >= m_cap)
            m_misses.erase(m_misses.begin());
    }

    uint32_t                                 m_tries;
    clock::duration                          m_window;
    size_t                                   m_cap;
    std::unordered_map<std::string, misses> m_misses;
};

} // namespace socketley
