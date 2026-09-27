#pragma once
// Whether a write may skip the ring and go by send(): only on a loop serving
// one connection one answer per turn.  On a busier loop the ring puts many
// writes into an io_uring_enter the loop makes anyway, and a spinning loop
// serving several connections takes them one per turn, which looks the same
// by the count alone.
#include <cstdint>

namespace socketley
{

struct direct_send_gate
{
    uint32_t this_turn{0};
    uint32_t last_turn{0};
    int      last_fd{-1};

    // Asked once for every write a turn starts, direct or not, so the count
    // and the last connection are the turn's writes whichever way they went.
    bool admit(int fd)
    {
        const bool same = fd == last_fd;
        last_fd = fd;
        return this_turn++ == 0 && last_turn <= 1 && same;
    }

    void next_turn() { last_turn = this_turn; this_turn = 0; }
};

} // namespace socketley
