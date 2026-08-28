#pragma once
// A teardown may only be deferred to an operation something is obliged to
// report; an armed read on a closing connection is not one.
#include <cstdint>

namespace socketley::reach
{

// What is outstanding on one connection, sorted by who must report it.
struct owed
{
    bool write{false};        // an error is still an answer
    bool zc_notif{false};     // not implied by write: the first completion
                              // clears that while the kernel is still DMA-ing
    bool file_read{false};    // depends on neither socket nor peer
    bool splice_in{false};
    bool splice_out{false};
    bool connect{false};      // or the poll standing in for one
    bool promised_reply{false};   // one reply per request, back into this loop

    // Only the peer or the socket can end this, so it is never owed.  A member
    // rather than an omission, so the exclusion reads as the rule it is.
    bool read{false};
};

inline constexpr bool ring_will_report(const owed& o)
{
    return o.write || o.zc_notif || o.file_read || o.splice_in || o.splice_out ||
           o.connect || o.promised_reply;
}

enum class verdict : uint8_t
{
    keep,     // not closing, or something owed is outstanding

    // Closing, nothing owed, output still queued.  Flush, then ASK AGAIN: a
    // flush that reached the ring becomes `keep`, one that submitted nothing
    // becomes `finish`, because nothing would wake it either.
    flush,

    // Closing and unreachable.  Taking the armed read back is the teardown's
    // own job, and every runtime's teardown already does it.
    finish
};

inline constexpr verdict classify(bool closing, const owed& o, bool has_output)
{
    if (!closing || ring_will_report(o))
        return verdict::keep;
    return has_output ? verdict::flush : verdict::finish;
}

}   // namespace socketley::reach
