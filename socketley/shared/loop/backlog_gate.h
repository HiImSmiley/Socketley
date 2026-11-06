#pragma once
// Admission to a capped outgoing queue, and the warning that goes with a refusal.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>

#include "../util/logging.h"

struct backlog_gate
{
    bool     full{false};
    uint64_t refused{0};

    // Warned once per stall, cleared only at half the cap: a queue held at the
    // cap reopens on every partial send, and clearing there warned per frame.
    // `lost` names what a refusal costs in the line that says it is over.
    bool admit(size_t pending, size_t add, size_t cap, const char* stalled,
               const char* lost = "frame(s) were refused")
    {
        if (pending + add > cap)
        {
            if (!full)
            {
                LOG_WARN(stalled);
                full = true;
            }
            ++refused;
            return false;
        }
        if (full && pending + add <= cap / 2)
        {
            LOG_WARN(("backlog drained; " + std::to_string(refused) + " " + lost +
                      " while it was full").c_str());
            full    = false;
            refused = 0;
        }
        return true;
    }
};

// The bytes of a queue that are owed to an asker, by where each such frame ends in the queue's stream, so a frame
// nobody waits on can be held to its cap beside them rather than behind them.
class owed_bytes
{
public:
    // A frame of `n` bytes just queued, ending the `total` bytes queued over the queue's life.
    void add(uint64_t total, size_t n)
    {
        if (n == 0)
            return;
        m_marks.push_back({total, n});
        m_sum += n;
    }

    // Those still unsent once the first `sent` bytes of the stream have gone.
    size_t pending(uint64_t sent)
    {
        while (!m_marks.empty() && m_marks.front().end <= sent)
        {
            m_sum -= m_marks.front().n;
            m_marks.pop_front();
        }
        if (m_marks.empty())
            return 0;
        const uint64_t start = m_marks.front().end - m_marks.front().n;
        return m_sum - (sent > start ? static_cast<size_t>(sent - start) : 0);
    }

    void clear()
    {
        m_marks.clear();
        m_sum = 0;
    }

private:
    struct mark
    {
        uint64_t end;
        size_t   n;
    };
    std::deque<mark> m_marks;
    size_t           m_sum{0};
};
