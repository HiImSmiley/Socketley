#pragma once
// The end of a connection whose last answer is written, so that closing it throws none of that answer away.
//
// A close() with input still unread makes the kernel reset the connection and purge what it has not yet delivered, and
// so does input that arrives after shutdown(SHUT_RD) once the FIN is out; under kernel TLS a FIN also throws away the
// records the kernel took on a full socket and has not handed to TCP.  So a connection ends here: its write side shut
// (under kernel TLS only once the socket's queue is empty), what its peer still sends read and dropped, and the
// descriptor closed once nothing it was sent is unacknowledged or the peer has closed as well -- or once its send queue
// has not moved for `stall`, a peer that stopped reading, or it sent more than `drain_limit`.
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include <linux/time_types.h>

#include "../loop/event_loop_definitions.h"

class event_loop;

namespace socketley
{

// What the kernel says of a socket's send side: all the decisions here read.
struct send_look
{
    // A TCP socket, whose close can reset; a unix socket's cannot, its bytes being in the peer's queue already.
    bool     tcp{false};
    // Bytes sent and not acknowledged, or not sent yet (SIOCOUTQ).
    uint32_t owed{0};
    // Since the kernel last sent data on it (tcpi_last_data_sent), which a zero window stops and a slow reader does not.
    uint32_t idle_ms{0};
    // tcpi_state.
    uint8_t  state{0};
};

// One look at `fd`; tcp false when it is not a TCP socket or cannot be asked.
send_look look_at_send(int fd);

// The peer is owed something and nothing has been sent it for `bound`: it has stopped reading.
inline bool send_stalled(const send_look& l, std::chrono::milliseconds bound)
{
    return l.tcp && l.owed > 0 && l.idle_ms >= static_cast<uint64_t>(bound.count());
}
// The same asked of `fd`, false for a socket that owes nothing or is not TCP.
bool send_stalled(int fd, std::chrono::milliseconds bound);

// The peer's FIN has arrived, so it sends nothing more that a close could be reset by.
bool peer_has_closed(uint8_t tcpi_state);

class orderly_close final : public io_handler
{
public:
    // How long a send queue that does not move is waited on, and how much a peer may send meanwhile.
    static constexpr auto     stall       = std::chrono::seconds(10);
    static constexpr uint64_t drain_limit = 64ull << 20;
    // How much is read away once nothing sent is unacknowledged, past which a reset loses nothing of ours.
    static constexpr uint64_t settled_limit = 1ull << 20;
    // How many ends are held at once; past it one is closed as it comes.
    static constexpr size_t   max_held    = 16384;

    explicit orderly_close(event_loop& loop) : m_loop(loop) {}
    // Closes what is still held, which only a loop going away leaves.
    ~orderly_close() override;
    orderly_close(const orderly_close&)            = delete;
    orderly_close& operator=(const orderly_close&) = delete;

    // `fd` is this object's from here, with nothing of the ring's naming it; `kernel_tls` when the kernel encrypts its
    // records, whose FIN then waits for its queue to empty.
    void take(int fd, bool kernel_tls);
    size_t held() const { return m_held.size(); }
    // Ends taken in all, and those that had to wait for their peer.
    uint64_t taken() const { return m_taken; }
    uint64_t waited() const { return m_waited; }

    void on_cqe(struct io_uring_cqe* cqe) override;

private:
    struct entry
    {
        io_request req{};
        __kernel_timespec ts{};
        int  fd{-1};
        bool kernel_tls{false};
        bool write_shut{false};
        uint64_t drained{0};
        std::chrono::milliseconds wait{10};
        size_t index{0};
    };
    // One step of an end: true once its descriptor is closed.
    bool advance(entry& e);
    bool arm(entry& e);
    void drop(entry* e);

    event_loop& m_loop;
    std::vector<std::unique_ptr<entry>> m_held;
    uint64_t m_taken{0};
    uint64_t m_waited{0};
};

}   // namespace socketley
