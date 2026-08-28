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

    // Only the peer or the socket can end this, so it is never owed.
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

    // Closing, nothing owed, output still queued: flush and ask again, because
    // a flush that reached the ring is `keep` and one that submitted nothing
    // is `finish`.
    flush,

    // Closing and unreachable; taking the armed read back is the teardown's
    // own job.
    finish
};

inline constexpr verdict classify(bool closing, const owed& o, bool has_output)
{
    if (!closing || ring_will_report(o))
        return verdict::keep;
    return has_output ? verdict::flush : verdict::finish;
}

}   // namespace socketley::reach
