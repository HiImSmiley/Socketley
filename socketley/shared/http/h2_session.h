#pragma once
// The state an HTTP/2 connection and its streams carry, apart from the bytes: windows, the HPACK decoder, the block
// being gathered over CONTINUATIONs, the flood counters, and what a stream still owes the wire. None of it is any
// one runtime's -- the storage speaks HTTP/2 today and an entrance proxy has the same state to keep -- so it lives
// here with the frame codec (h2_frame.h) and HPACK (hpack.h) rather than beside the first runtime that needed it.
//
// A session is a template on what the host hangs off a stream id: the storage gives it a connection of its own with
// no socket, so that every operation runs as it does over HTTP/1.1. A template and not an interface because this is
// walked once per frame, and a virtual call per frame is a cost the hot path does not have to carry.
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

#include "h2_frame.h"
#include "hpack.h"
#include "http_framing.h"

namespace socketley::h2
{

// What a stream may send before its window is given back, which is what a browser's upload has in flight on it.
constexpr uint32_t stream_window   = 4u << 20;
// The connection's, across its streams: several uploads at once each keep their window full.
constexpr uint32_t conn_window     = 32u << 20;
constexpr uint32_t max_streams     = 128;
constexpr size_t   header_list_max = 64 * 1024;
// A header block gathered over CONTINUATIONs: past this, or past this many frames, it is a flood.
constexpr size_t   block_max       = header_list_max + 16 * 1024;
constexpr int      continuations_max = 64;
// Control frames the peer may make this side answer, and streams it may reset, in each ten seconds.
constexpr uint32_t pings_max       = 200;
constexpr uint32_t settings_max    = 200;
constexpr uint32_t resets_max      = 400;
constexpr uint32_t empty_data_max  = 1000;
constexpr size_t   max_head        = 32 * 1024;

struct stream
{
    uint32_t sid{0};
    // DATA received and not yet handed to the phase, and how far it has been.
    // Held as the frames brought it, so taking the front never moves the rest; only what the phase could not take
    // at once is held at all.
    std::deque<std::string> rxq;
    size_t      rx_head{0};
    size_t      rx_bytes{0};
    // What this side may still receive on the stream, and what was taken and not yet given back.
    int64_t     recv_avail{stream_window};
    uint32_t    rx_unacked{0};
    bool        remote_closed{false};
    // A body with no content-length is handed over as chunked framing, which the phases read.
    bool        synth_chunked{false};
    bool        chunk_end_given{false};
    bool        has_cl{false};
    uint64_t    cl{0};
    uint64_t    data_in{0};

    // Going out: HEADERS already framed, which no window holds, then the body's bytes waiting for windows.
    std::string hdr;
    std::string tx;
    size_t      tx_off{0};
    int64_t     send_win{h2::default_window};
    enum class out_state : uint8_t { head, body, dechunk } os{out_state::head};
    std::string head_acc;
    http_chunked_decoder dechunk;
    std::string dechunk_in;
    bool        end_pending{false};
    bool        local_closed{false};
    // RST_STREAM was sent or received, so none is sent again.
    bool        reset{false};
    bool        queued{false};

    size_t tx_left() const { return tx.size() - tx_off; }
};

// `S` is what the host keeps per stream; the session only holds it and hands it back by stream id.
template <class S>
struct session
{
    bool     preface_ok{false};
    bool     got_settings{false};
    uint32_t peer_init_win{h2::default_window};
    uint32_t peer_max_frame{h2::default_frame};
    hpack::decoder dec{4096};
    int64_t  send_win{h2::default_window};
    int64_t  recv_avail{conn_window};
    uint32_t recv_unacked{0};
    uint32_t last_sid{0};
    bool     goaway_sent{false};
    bool     peer_goaway{false};
    bool     close_when_flushed{false};
    bool     dying{false};
    bool     first_block{true};
    // A header block being gathered over CONTINUATIONs.
    uint32_t cont_sid{0};
    std::string cont_buf;
    bool     cont_end_stream{false};
    bool     cont_trailers{false};
    // The block's stream named itself as its dependency, and is reset once the block is read.
    bool     cont_refuse{false};
    int      cont_frames{0};

    // Streams the peer may have open at once, announced in SETTINGS and held to in headers_in.  A session's own,
    // because what a stream costs its host differs: the storage keeps a socket-less conn per stream, an entrance a
    // client connection with a descriptor.
    uint32_t max_live{max_streams};

    std::unordered_map<uint32_t, S> streams;
    // Streams with something to send, in turn.
    std::deque<uint32_t> rr;
    // Frames of the connection's own, sent before any stream's.
    std::string ctl;

    std::chrono::steady_clock::time_point began{};
    std::chrono::steady_clock::time_point window_start{};
    uint32_t pings{0}, settings{0}, resets{0}, empty_data{0}, strays{0};
};

template <class S>
void enqueue(session<S>& s, stream& st)
{
    if (st.queued)
        return;
    st.queued = true;
    s.rr.push_back(st.sid);
}

// The flood counters start again every ten seconds.
template <class S>
void tick_window(session<S>& s)
{
    const auto now = std::chrono::steady_clock::now();
    if (now - s.window_start > std::chrono::seconds(10))
    {
        s.window_start = now;
        s.pings = s.settings = s.resets = s.empty_data = s.strays = 0;
    }
}

}   // namespace socketley::h2
