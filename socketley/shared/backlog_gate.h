#pragma once
// Admission to a capped outgoing queue, and the warning that goes with a refusal.
#include <cstddef>
#include <cstdint>
#include <string>

#include "logging.h"

struct backlog_gate
{
    bool     full{false};
    uint64_t refused{0};

    // Warned once per stall, cleared only at half the cap: a queue held at the
    // cap reopens on every partial send, and clearing there warned per frame.
    bool admit(size_t pending, size_t add, size_t cap, const char* stalled)
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
            LOG_WARN(("backlog drained; " + std::to_string(refused) +
                      " frame(s) were refused while it was full").c_str());
            full    = false;
            refused = 0;
        }
        return true;
    }
};
