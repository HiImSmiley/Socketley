#pragma once
// The tunnel's multiplexing: many byte streams over one connection, either side opening them, each with its own
// credit so one slow reader holds back only its own stream.  Pure: bytes in, events and bytes out, no socket.
//
// ─── THE WIRE ───────────────────────────────────────────────────────────────
//   frame   u32 length | u8 type | u32 stream | length bytes of payload, big-endian
//   HELLO   stream 0: u8 version, then name/value strings, each u16 length and bytes
//   OPEN    a new stream: its target, a u16 length and bytes, and what the opener says of the peer
//   DATA    bytes of a stream, never more than the credit the far side gave it
//   WINDOW  u32 more credit for a stream
//   CLOSE   the sender writes no more on the stream; the stream ends when both have closed
//   RESET   u8 code: the stream is gone at once, either way
//   PING    8 bytes, answered by a PONG with the same 8
//   GOAWAY  no new streams; a string saying why
//
// The side that dialled opens odd streams, the side that accepted even ones, so both can open without asking.
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace socketley::tunnel
{

inline constexpr uint8_t version = 1;
inline constexpr size_t header_size = 9;
// The largest payload a frame carries, and what a stream may have in flight before the reader grants more.
inline constexpr uint32_t max_payload = 64 * 1024;
inline constexpr uint32_t initial_window = 256 * 1024;
inline constexpr size_t max_target = 255;
inline constexpr size_t max_hello = 4096;

enum class frame_type : uint8_t
{
    hello  = 1,
    open   = 2,
    data   = 3,
    window = 4,
    close  = 5,
    reset  = 6,
    ping   = 7,
    pong   = 8,
    goaway = 9,
    // A UDP datagram of a flow, named by its service; no stream, no credit, and dropped rather than queued when full.
    datagram = 10,
};

enum class reset_code : uint8_t
{
    refused     = 1,   // the target is not one this side offers or allows
    unreachable = 2,   // the target could not be reached
    gone        = 3,   // the local socket failed or closed abruptly
    limit       = 4,   // too many streams
};

using fields = std::vector<std::pair<std::string, std::string>>;

// What the far side did, told as it is read.
class events
{
public:
    virtual ~events() = default;
    virtual void on_hello(const fields& f) = 0;
    virtual void on_open(uint32_t stream, std::string_view target, std::string_view peer) = 0;
    virtual void on_data(uint32_t stream, std::string_view bytes) = 0;
    // The far side writes no more on the stream.
    virtual void on_close(uint32_t stream) = 0;
    virtual void on_reset(uint32_t stream, reset_code code) = 0;
    // The far side gave more credit, so data held back for it may go now.
    virtual void on_window(uint32_t stream) = 0;
    virtual void on_pong(std::string_view token) = 0;
    virtual void on_goaway(std::string_view why) = 0;
    // A datagram of `flow` for `service`; a side that carries no UDP has nothing to do with it.
    virtual void on_datagram(uint32_t, std::string_view, std::string_view) {}
};

class session
{
public:
    // `dialled` for the side that made the connection, which opens odd streams.
    session(bool dialled, events& ev, uint32_t max_streams = 1024);

    // Bytes read from the connection, with what the protocol answers by itself (a pong, a refused stream) appended
    // to `out`; false, with error() set, once the far side broke the protocol, after which the connection is to be
    // closed.  Events are told from inside, and a handler may call every method here but feed.
    bool feed(std::string_view bytes, std::string& out);
    const std::string& error() const { return m_error; }

    // What goes out on the connection, appended to `out`.
    void hello(const fields& f, std::string& out);
    // A new stream to `target`, its id; 0 when the far side said goaway or the streams are at their limit.
    uint32_t open(std::string_view target, std::string_view peer, std::string& out);
    // As much of `bytes` as the stream's credit allows sent, the count; 0 for a stream not open for writing.
    size_t send(uint32_t stream, std::string_view bytes, std::string& out);
    void close(uint32_t stream, std::string& out);
    void reset(uint32_t stream, reset_code code, std::string& out);
    // `n` bytes of the stream's data handed on, which gives the far side credit back once half of it is used.
    void consumed(uint32_t stream, size_t n, std::string& out);
    void ping(std::string_view token, std::string& out);
    // A datagram of `flow` for `service` sent; false for a flow of 0, a service no open could name, or bytes past a
    // frame, which the caller drops as a full socket would.
    bool datagram(uint32_t flow, std::string_view service, std::string_view bytes, std::string& out);
    void goaway(std::string_view why, std::string& out);

    // What the stream may still be sent, 0 for one not open for writing.
    uint32_t credit(uint32_t stream) const;
    bool is_open(uint32_t stream) const { return m_streams.contains(stream); }
    size_t stream_count() const { return m_streams.size(); }
    // What feed() holds of a frame not yet whole, which the caller's buffer need not.
    size_t buffered() const { return m_in.size(); }

private:
    struct stream_state
    {
        uint32_t send_credit{initial_window};
        // What the far side may still send, and what has been consumed since credit was last given back.
        uint32_t recv_credit{initial_window};
        uint32_t unacked{0};
        bool sent_close{false};
        bool got_close{false};
    };

    bool frame(frame_type t, uint32_t stream, std::string_view payload, std::string& out);
    bool fail(std::string why);
    void put(frame_type t, uint32_t stream, std::string_view payload, std::string& out) const;
    // A stream both sides have closed is forgotten.
    void settle(uint32_t stream);
    bool ours(uint32_t stream) const { return (stream & 1) == (m_dialled ? 1u : 0u); }

    bool m_dialled;
    events& m_ev;
    uint32_t m_max_streams;
    uint32_t m_next;
    uint32_t m_highest_theirs{0};
    bool m_said_goaway{false};
    bool m_got_goaway{false};
    bool m_got_hello{false};
    std::string m_in;
    std::string m_error;
    std::unordered_map<uint32_t, stream_state> m_streams;
};

// The HTTP/1.1 upgrade a dialling side opens with and the answer it waits for.
inline constexpr std::string_view upgrade_token = "socketley-tunnel/1";

}   // namespace socketley::tunnel
