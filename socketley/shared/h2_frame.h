#pragma once
// HTTP/2's frames, RFC 9113 section 4 and 6: the nine-byte head every frame begins with, and the frames a server
// writes, built into a string. Free functions over bytes, with nothing of a connection in them, so a test or a fuzz
// target reads them alone.
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

namespace socketley::h2
{

constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr size_t   head_len        = 9;
constexpr uint32_t default_window  = 65535;
constexpr uint32_t default_frame   = 16384;
constexpr uint32_t max_window      = 0x7fffffff;

enum type : uint8_t
{
    DATA          = 0x0,
    HEADERS       = 0x1,
    PRIORITY      = 0x2,
    RST_STREAM    = 0x3,
    SETTINGS      = 0x4,
    PUSH_PROMISE  = 0x5,
    PING          = 0x6,
    GOAWAY        = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION  = 0x9,
};

enum flag : uint8_t
{
    END_STREAM  = 0x1,
    ACK         = 0x1,
    END_HEADERS = 0x4,
    PADDED      = 0x8,
    PRIORITY_F  = 0x20,
};

enum error : uint32_t
{
    NO_ERROR            = 0x0,
    PROTOCOL_ERROR      = 0x1,
    INTERNAL_ERROR      = 0x2,
    FLOW_CONTROL_ERROR  = 0x3,
    SETTINGS_TIMEOUT    = 0x4,
    STREAM_CLOSED       = 0x5,
    FRAME_SIZE_ERROR    = 0x6,
    REFUSED_STREAM      = 0x7,
    CANCEL              = 0x8,
    COMPRESSION_ERROR   = 0x9,
    CONNECT_ERROR       = 0xa,
    ENHANCE_YOUR_CALM   = 0xb,
    INADEQUATE_SECURITY = 0xc,
    HTTP_1_1_REQUIRED   = 0xd,
};

enum setting : uint16_t
{
    HEADER_TABLE_SIZE      = 0x1,
    ENABLE_PUSH            = 0x2,
    MAX_CONCURRENT_STREAMS = 0x3,
    INITIAL_WINDOW_SIZE    = 0x4,
    MAX_FRAME_SIZE         = 0x5,
    MAX_HEADER_LIST_SIZE   = 0x6,
};

struct frame_head
{
    uint32_t len{0};
    uint8_t  type{0};
    uint8_t  flags{0};
    uint32_t sid{0};
};

inline uint32_t rd32(const char* p)
{
    return static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24 | static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16 |
           static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8 | static_cast<uint8_t>(p[3]);
}

inline void put32(std::string& o, uint32_t v)
{
    o += static_cast<char>(v >> 24);
    o += static_cast<char>(v >> 16);
    o += static_cast<char>(v >> 8);
    o += static_cast<char>(v);
}

// The head of the frame at `p`, which holds head_len bytes; the stream id's reserved bit is dropped.
inline frame_head parse_head(const char* p)
{
    frame_head h;
    h.len   = static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 16 | static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 8 |
              static_cast<uint8_t>(p[2]);
    h.type  = static_cast<uint8_t>(p[3]);
    h.flags = static_cast<uint8_t>(p[4]);
    h.sid   = rd32(p + 5) & 0x7fffffffu;
    return h;
}

inline void put_head(std::string& o, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid)
{
    o += static_cast<char>(len >> 16);
    o += static_cast<char>(len >> 8);
    o += static_cast<char>(len);
    o += static_cast<char>(type);
    o += static_cast<char>(flags);
    put32(o, sid & 0x7fffffffu);
}

inline void put_settings(std::string& o, std::initializer_list<std::pair<uint16_t, uint32_t>> s)
{
    put_head(o, static_cast<uint32_t>(s.size() * 6), SETTINGS, 0, 0);
    for (const auto& [id, v] : s)
    {
        o += static_cast<char>(id >> 8);
        o += static_cast<char>(id);
        put32(o, v);
    }
}

inline void put_settings_ack(std::string& o) { put_head(o, 0, SETTINGS, ACK, 0); }

inline void put_ping_ack(std::string& o, std::string_view opaque)
{
    put_head(o, 8, PING, ACK, 0);
    o.append(opaque.substr(0, 8));
}

inline void put_window_update(std::string& o, uint32_t sid, uint32_t inc)
{
    put_head(o, 4, WINDOW_UPDATE, 0, sid);
    put32(o, inc & 0x7fffffffu);
}

inline void put_rst(std::string& o, uint32_t sid, uint32_t code)
{
    put_head(o, 4, RST_STREAM, 0, sid);
    put32(o, code);
}

inline void put_goaway(std::string& o, uint32_t last_sid, uint32_t code)
{
    put_head(o, 8, GOAWAY, 0, 0);
    put32(o, last_sid & 0x7fffffffu);
    put32(o, code);
}

inline void put_data(std::string& o, uint32_t sid, std::string_view payload, bool end)
{
    put_head(o, static_cast<uint32_t>(payload.size()), DATA, end ? END_STREAM : 0, sid);
    o.append(payload);
}

// A header block as HEADERS and as many CONTINUATIONs as `max_frame` makes it, written together, since nothing may
// come between them on the connection.
inline void put_header_block(std::string& o, uint32_t sid, std::string_view block, bool end_stream, uint32_t max_frame)
{
    bool first = true;
    do
    {
        const std::string_view part = block.substr(0, max_frame);
        block.remove_prefix(part.size());
        uint8_t flags = block.empty() ? END_HEADERS : 0;
        if (first && end_stream)
            flags |= END_STREAM;
        put_head(o, static_cast<uint32_t>(part.size()), first ? HEADERS : CONTINUATION, flags, sid);
        o.append(part);
        first = false;
    } while (!block.empty());
}

// A frame's payload without its padding, and HEADERS's without its priority fields; false when the padding is longer
// than the frame, which is a PROTOCOL_ERROR.
inline bool unpad(const frame_head& h, std::string_view& payload)
{
    if (h.flags & PADDED)
    {
        if (payload.empty())
            return false;
        const size_t pad = static_cast<uint8_t>(payload[0]);
        payload.remove_prefix(1);
        if (pad > payload.size())
            return false;
        payload.remove_suffix(pad);
    }
    if (h.type == HEADERS && (h.flags & PRIORITY_F))
    {
        if (payload.size() < 5)
            return false;
        payload.remove_prefix(5);
    }
    return true;
}

}   // namespace socketley::h2
