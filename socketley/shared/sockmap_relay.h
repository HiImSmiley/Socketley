// A BPF sockhash + stream-verdict program that relays a TCP pair's bytes
// inside the kernel, so a proxy pair in steady state needs no userspace read,
// copy or send per message.
#pragma once

#include <cstdint>

namespace socketley {

// Loads one verdict program and two maps once, then moves a proxy's TCP pairs
// into and out of the kernel path; every proxy leg calls the same instance.
class sockmap_relay
{
public:
    sockmap_relay() = default;
    ~sockmap_relay();
    sockmap_relay(const sockmap_relay&) = delete;
    sockmap_relay& operator=(const sockmap_relay&) = delete;

    // Loads the maps and program and attaches the verdict; true when the
    // kernel path is usable, false with a reason set when it is not.  Idempotent.
    bool init();
    bool available() const { return m_ok; }
    // Why init() failed, for the one-line log the caller writes on fallback.
    const char* unavailable_reason() const { return m_reason; }

    // Puts both sockets in the maps so bytes read on one are sent on the other,
    // and kicks each so bytes already queued do not wait for the next packet.
    // False on any error, leaving neither in the map, so the caller falls back.
    bool enter(int fd_a, int fd_b);
    // Takes both sockets back out; bytes then reach userspace again.  Safe on a
    // socket that is not in the map.
    void leave(int fd_a, int fd_b);

    // One direction's counters when a pair entered the map: what the source
    // had received and userspace already relayed, and what the destination had
    // queued to send, so later totals are read against them.
    struct direction_base
    {
        uint64_t rx{0};
        uint64_t tx{0};
    };
    static direction_base base(int src_fd, int dst_fd);

    // Bytes of this direction the kernel still holds: received by the source
    // and not yet sent by the destination, including the redirect's own
    // workqueue, which neither SIOCINQ nor SIOCOUTQ counts.  src_fin removes
    // the one sequence number a received FIN takes.
    static uint64_t held(int src_fd, int dst_fd, const direction_base& b, bool src_fin);
    // True once everything the source received has reached the destination's
    // send queue, which is when the source's FIN may be passed on.
    static bool drained(int src_fd, int dst_fd, const direction_base& b, bool src_fin);
    // Bytes the source received since the base, the kernel-relayed total.
    static uint64_t relayed(int src_fd, const direction_base& b, bool src_fin);

private:
    bool insert_one(int fd);
    void delete_one(int fd);

    int  m_peer_map{-1};   // cookie(sock) -> peer fd, no program: the redirect target
    int  m_verd_map{-1};   // cookie(sock) -> sock fd, carries the verdict program
    int  m_prog{-1};
    bool m_ok{false};
    const char* m_reason{"not initialised"};
};

}  // namespace socketley
