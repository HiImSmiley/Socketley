// ═══════════════════════════════════════════════════════════════════
//  socketley/ws_client.h — Cross-platform WebSocket + TCP client (Tier 2)
//
//  Header-only client for Socketley server runtimes.
//  Supports WebSocket (RFC 6455) and raw TCP (newline-delimited text).
//  Works on Windows, macOS, and Linux. C++17, zero external deps.
//  Embedded SHA-1 + Base64 for WebSocket handshake (no OpenSSL needed).
//
//  Example:
//    #include <socketley/ws_client.h>
//    int main() {
//        socketley::ws_client c;
//        if (!c.connect("192.168.1.100", 8080)) return 1;
//        c.send("hello");
//        auto msg = c.recv();
//        // msg.data == server response
//    }
//    // MSVC:  cl /std:c++17 app.cpp
//    // clang: clang++ -std=c++17 app.cpp
// ═══════════════════════════════════════════════════════════════════
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <random>
#include <array>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <cerrno>
  #include <signal.h>
#endif

namespace socketley {

// ── Platform abstraction ────────────────────────────────────────

namespace detail {
namespace platform {

#ifdef _WIN32
    using socket_t = SOCKET;
    static constexpr socket_t invalid_socket = INVALID_SOCKET;

    inline bool wsa_init()
    {
        WSADATA wsa;
        return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }

    inline void wsa_cleanup() { WSACleanup(); }

    inline void close_socket(socket_t s) { closesocket(s); }

    inline int sock_recv(socket_t s, char* buf, int len)
    {
        return ::recv(s, buf, len, 0);
    }

    inline int sock_send(socket_t s, const char* buf, int len)
    {
        return ::send(s, buf, len, 0);
    }
#else
    using socket_t = int;
    static constexpr socket_t invalid_socket = -1;

    inline bool wsa_init() { return true; }
    inline void wsa_cleanup() {}

    inline void close_socket(socket_t s) { ::close(s); }

    inline int sock_recv(socket_t s, char* buf, int len)
    {
        return static_cast<int>(::recv(s, buf, static_cast<size_t>(len), 0));
    }

    inline int sock_send(socket_t s, const char* buf, int len)
    {
        int flags = 0;
#ifdef __linux__
        flags = MSG_NOSIGNAL;
#endif
        return static_cast<int>(::send(s, buf, static_cast<size_t>(len), flags));
    }
#endif

    inline socket_t tcp_connect(const std::string& host, uint16_t port)
    {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        char port_str[8];
        std::snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(port));

        if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0 || !res)
            return invalid_socket;

        socket_t fd = invalid_socket;
        for (auto* rp = res; rp; rp = rp->ai_next)
        {
            fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == invalid_socket)
                continue;

            if (::connect(fd, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0)
                break;

            close_socket(fd);
            fd = invalid_socket;
        }

        freeaddrinfo(res);

        if (fd == invalid_socket)
            return invalid_socket;

        // TCP_NODELAY
        int opt = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&opt), sizeof(opt));

#if defined(__APPLE__)
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                   reinterpret_cast<const char*>(&opt), sizeof(opt));
#endif

        return fd;
    }

    inline bool send_all(socket_t s, const char* data, size_t len)
    {
        size_t sent = 0;
        while (sent < len)
        {
            int n = sock_send(s, data + sent, static_cast<int>(len - sent));
            if (n <= 0)
                return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

} // namespace platform

// ── Embedded SHA-1 (RFC 3174) ───────────────────────────────────

namespace sha1 {

struct context
{
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
};

inline uint32_t rotl(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

inline void transform(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];

    for (int i = 0; i < 16; i++)
    {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(block[i * 4 + 3]);
    }

    for (int i = 16; i < 80; i++)
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = state[0], b = state[1], c = state[2],
             d = state[3], e = state[4];

    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;             k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else              { f = b ^ c ^ d;             k = 0xCA62C1D6; }

        uint32_t temp = rotl(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c;
    state[3] += d; state[4] += e;
}

inline void init(context& ctx)
{
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xEFCDAB89;
    ctx.state[2] = 0x98BADCFE;
    ctx.state[3] = 0x10325476;
    ctx.state[4] = 0xC3D2E1F0;
    ctx.count = 0;
}

inline void update(context& ctx, const uint8_t* data, size_t len)
{
    size_t idx = static_cast<size_t>(ctx.count % 64);
    ctx.count += len;

    for (size_t i = 0; i < len; i++)
    {
        ctx.buffer[idx++] = data[i];
        if (idx == 64)
        {
            transform(ctx.state, ctx.buffer);
            idx = 0;
        }
    }
}

inline void final(context& ctx, uint8_t digest[20])
{
    uint64_t bits = ctx.count * 8;
    size_t idx = static_cast<size_t>(ctx.count % 64);

    ctx.buffer[idx++] = 0x80;
    if (idx > 56)
    {
        while (idx < 64) ctx.buffer[idx++] = 0;
        transform(ctx.state, ctx.buffer);
        idx = 0;
    }
    while (idx < 56) ctx.buffer[idx++] = 0;

    for (int i = 7; i >= 0; i--)
        ctx.buffer[56 + (7 - i)] = static_cast<uint8_t>((bits >> (i * 8)) & 0xFF);

    transform(ctx.state, ctx.buffer);

    for (int i = 0; i < 5; i++)
    {
        digest[i * 4]     = static_cast<uint8_t>((ctx.state[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = static_cast<uint8_t>((ctx.state[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = static_cast<uint8_t>((ctx.state[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = static_cast<uint8_t>(ctx.state[i] & 0xFF);
    }
}

inline std::array<uint8_t, 20> hash(const void* data, size_t len)
{
    context ctx;
    init(ctx);
    update(ctx, static_cast<const uint8_t*>(data), len);
    std::array<uint8_t, 20> digest;
    final(ctx, digest.data());
    return digest;
}

} // namespace sha1

// ── Embedded Base64 encoder ─────────────────────────────────────

namespace base64 {

inline std::string encode(const uint8_t* data, size_t len)
{
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < len)
    {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                      static_cast<uint32_t>(data[i + 2]);
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += table[n & 0x3F];
        i += 3;
    }

    if (i + 1 == len)
    {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += '=';
        out += '=';
    }
    else if (i + 2 == len)
    {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8);
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += '=';
    }

    return out;
}

} // namespace base64

// ── WebSocket constants ─────────────────────────────────────────

static constexpr uint8_t WS_OP_TEXT  = 0x1;
static constexpr uint8_t WS_OP_CLOSE = 0x8;
static constexpr uint8_t WS_OP_PING  = 0x9;
static constexpr uint8_t WS_OP_PONG  = 0xA;
static constexpr uint64_t WS_MAX_PAYLOAD = 16 * 1024 * 1024;
static constexpr const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ── Random mask generator ───────────────────────────────────────

inline std::array<uint8_t, 4> random_mask()
{
    thread_local std::mt19937 rng(std::random_device{}());
    uint32_t val = rng();
    return {
        static_cast<uint8_t>(val & 0xFF),
        static_cast<uint8_t>((val >> 8) & 0xFF),
        static_cast<uint8_t>((val >> 16) & 0xFF),
        static_cast<uint8_t>((val >> 24) & 0xFF)
    };
}

// ── WebSocket accept key computation ────────────────────────────

inline std::string ws_compute_accept(const std::string& client_key)
{
    std::string combined = client_key + WS_GUID;
    auto digest = sha1::hash(combined.data(), combined.size());
    return base64::encode(digest.data(), digest.size());
}

} // namespace detail

// ── Public types ────────────────────────────────────────────────

enum class ws_mode { websocket, raw_tcp };

struct ws_message
{
    std::string data;
    bool is_close{false};
    bool is_ping{false};
    bool error{false};
};

// ── WebSocket + TCP client ──────────────────────────────────────

class ws_client
{
public:
    ws_client() = default;

    ~ws_client() { close(); }

    // Non-copyable, movable
    ws_client(const ws_client&) = delete;
    ws_client& operator=(const ws_client&) = delete;

    ws_client(ws_client&& o) noexcept
        : m_fd(o.m_fd), m_host(std::move(o.m_host)), m_port(o.m_port),
          m_mode(o.m_mode), m_path(std::move(o.m_path)),
          m_buf(std::move(o.m_buf))
    {
        o.m_fd = detail::platform::invalid_socket;
    }

    ws_client& operator=(ws_client&& o) noexcept
    {
        if (this != &o)
        {
            close();
            m_fd = o.m_fd;
            m_host = std::move(o.m_host);
            m_port = o.m_port;
            m_mode = o.m_mode;
            m_path = std::move(o.m_path);
            m_buf = std::move(o.m_buf);
            o.m_fd = detail::platform::invalid_socket;
        }
        return *this;
    }

    bool connect(const std::string& host, uint16_t port,
                 ws_mode mode = ws_mode::websocket,
                 const std::string& path = "/")
    {
        close();
        detail::platform::wsa_init();

        m_host = host;
        m_port = port;
        m_mode = mode;
        m_path = path;

        m_fd = detail::platform::tcp_connect(host, port);
        if (m_fd == detail::platform::invalid_socket)
            return false;

        if (mode == ws_mode::websocket)
        {
            if (!do_handshake())
            {
                detail::platform::close_socket(m_fd);
                m_fd = detail::platform::invalid_socket;
                return false;
            }
        }

        return true;
    }

    void close()
    {
        if (m_fd != detail::platform::invalid_socket)
        {
            if (m_mode == ws_mode::websocket)
            {
                // Send close frame (best-effort)
                auto frame = build_close_frame();
                detail::platform::send_all(m_fd, frame.data(), frame.size());
            }
            detail::platform::close_socket(m_fd);
            m_fd = detail::platform::invalid_socket;
        }
        m_buf.clear();
    }

    bool reconnect()
    {
        if (m_host.empty())
            return false;
        return connect(m_host, m_port, m_mode, m_path);
    }

    bool is_connected() const
    {
        return m_fd != detail::platform::invalid_socket;
    }

    bool send(const std::string& message)
    {
        if (m_fd == detail::platform::invalid_socket)
            return false;

        if (m_mode == ws_mode::raw_tcp)
        {
            std::string msg = message + "\n";
            return detail::platform::send_all(m_fd, msg.data(), msg.size());
        }

        // WebSocket: build masked text frame
        auto frame = build_text_frame(message);
        return detail::platform::send_all(m_fd, frame.data(), frame.size());
    }

    bool send_ping(const std::string& payload = "")
    {
        if (m_fd == detail::platform::invalid_socket ||
            m_mode != ws_mode::websocket)
            return false;

        auto frame = build_control_frame(detail::WS_OP_PING, payload);
        return detail::platform::send_all(m_fd, frame.data(), frame.size());
    }

    ws_message recv()
    {
        if (m_fd == detail::platform::invalid_socket)
            return {"", false, false, true};

        if (m_mode == ws_mode::raw_tcp)
            return recv_raw_tcp();

        return recv_websocket();
    }

    void set_recv_timeout(uint32_t ms)
    {
        if (m_fd == detail::platform::invalid_socket)
            return;
#ifdef _WIN32
        DWORD tv = ms;
        setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        struct timeval tv{};
        tv.tv_sec = static_cast<long>(ms / 1000);
        tv.tv_usec = static_cast<long>((ms % 1000) * 1000);
        setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
    }

    ws_mode mode() const { return m_mode; }
    const std::string& host() const { return m_host; }
    uint16_t port() const { return m_port; }

private:
    detail::platform::socket_t m_fd{detail::platform::invalid_socket};
    std::string m_host;
    uint16_t m_port{0};
    ws_mode m_mode{ws_mode::websocket};
    std::string m_path;
    std::string m_buf;

    // ── WebSocket handshake ─────────────────────────────────────

    bool do_handshake()
    {
        // Generate random 16-byte key, base64-encode it
        std::array<uint8_t, 16> key_bytes;
        {
            thread_local std::mt19937 rng(std::random_device{}());
            for (auto& b : key_bytes)
                b = static_cast<uint8_t>(rng() & 0xFF);
        }
        std::string client_key = detail::base64::encode(key_bytes.data(), key_bytes.size());
        std::string expected_accept = detail::ws_compute_accept(client_key);

        // Build HTTP upgrade request
        std::string req = "GET " + m_path + " HTTP/1.1\r\n"
                          "Host: " + m_host + ":" + std::to_string(m_port) + "\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n"
                          "Sec-WebSocket-Key: " + client_key + "\r\n"
                          "Sec-WebSocket-Version: 13\r\n"
                          "\r\n";

        if (!detail::platform::send_all(m_fd, req.data(), req.size()))
            return false;

        // Read response until \r\n\r\n
        std::string response;
        for (;;)
        {
            char tmp[1024];
            int n = detail::platform::sock_recv(m_fd, tmp, sizeof(tmp));
            if (n <= 0)
                return false;
            response.append(tmp, static_cast<size_t>(n));

            if (response.find("\r\n\r\n") != std::string::npos)
                break;
            if (response.size() > 8192)
                return false;
        }

        // Verify 101 status
        if (response.find("101") == std::string::npos)
            return false;

        // Verify Sec-WebSocket-Accept
        std::string accept_header = "Sec-WebSocket-Accept: ";
        size_t pos = response.find(accept_header);
        if (pos == std::string::npos)
            return false;

        size_t val_start = pos + accept_header.size();
        size_t val_end = response.find("\r\n", val_start);
        if (val_end == std::string::npos)
            return false;

        std::string accept_value = response.substr(val_start, val_end - val_start);
        if (accept_value != expected_accept)
            return false;

        // Save any data after the handshake headers
        size_t body_start = response.find("\r\n\r\n") + 4;
        if (body_start < response.size())
            m_buf.append(response.data() + body_start, response.size() - body_start);

        return true;
    }

    // ── Frame building (client → server: masked) ────────────────

    static std::string build_text_frame(const std::string& payload)
    {
        return build_data_frame(detail::WS_OP_TEXT, payload);
    }

    static std::string build_data_frame(uint8_t opcode, const std::string& payload)
    {
        std::string frame;
        size_t len = payload.size();

        // Header
        frame += static_cast<char>(0x80 | opcode); // FIN + opcode

        // Length + mask bit
        if (len <= 125)
        {
            frame += static_cast<char>(0x80 | static_cast<uint8_t>(len));
        }
        else if (len <= 65535)
        {
            frame += static_cast<char>(0x80 | 126);
            frame += static_cast<char>((len >> 8) & 0xFF);
            frame += static_cast<char>(len & 0xFF);
        }
        else
        {
            frame += static_cast<char>(0x80 | 127);
            for (int i = 7; i >= 0; i--)
                frame += static_cast<char>((len >> (i * 8)) & 0xFF);
        }

        // Mask key
        auto mask = detail::random_mask();
        frame.append(reinterpret_cast<const char*>(mask.data()), 4);

        // Masked payload
        size_t offset = frame.size();
        frame.append(payload);
        for (size_t i = 0; i < len; i++)
            frame[offset + i] ^= static_cast<char>(mask[i & 3]);

        return frame;
    }

    static std::string build_control_frame(uint8_t opcode, const std::string& payload)
    {
        // Control frames: max 125 bytes payload
        std::string p = payload.size() > 125 ? payload.substr(0, 125) : payload;
        return build_data_frame(opcode, p);
    }

    static std::string build_close_frame()
    {
        return build_control_frame(detail::WS_OP_CLOSE, "");
    }

    // ── Frame parsing (server → client: unmasked) ───────────────

    struct parsed_frame
    {
        uint8_t opcode;
        std::string payload;
        size_t consumed;
    };

    bool parse_frame(parsed_frame& out)
    {
        const char* data = m_buf.data();
        size_t len = m_buf.size();

        if (len < 2)
            return false;

        uint8_t b0 = static_cast<uint8_t>(data[0]);
        uint8_t b1 = static_cast<uint8_t>(data[1]);

        out.opcode = b0 & 0x0F;
        bool masked = (b1 & 0x80) != 0;
        uint64_t payload_len = b1 & 0x7F;
        size_t header_size = 2;

        if (payload_len == 126)
        {
            if (len < 4) return false;
            payload_len = (static_cast<uint64_t>(static_cast<uint8_t>(data[2])) << 8) |
                           static_cast<uint64_t>(static_cast<uint8_t>(data[3]));
            header_size = 4;
        }
        else if (payload_len == 127)
        {
            if (len < 10) return false;
            payload_len = 0;
            for (int i = 0; i < 8; i++)
                payload_len = (payload_len << 8) |
                    static_cast<uint64_t>(static_cast<uint8_t>(data[2 + i]));
            header_size = 10;
        }

        if (payload_len > detail::WS_MAX_PAYLOAD)
            return false;

        size_t mask_size = masked ? 4 : 0;
        size_t total = header_size + mask_size + static_cast<size_t>(payload_len);
        if (len < total)
            return false;

        const char* payload_start = data + header_size + mask_size;
        out.payload.resize(static_cast<size_t>(payload_len));

        if (masked)
        {
            const uint8_t* mask_key =
                reinterpret_cast<const uint8_t*>(data + header_size);
            for (uint64_t i = 0; i < payload_len; i++)
                out.payload[i] = payload_start[i] ^ static_cast<char>(mask_key[i & 3]);
        }
        else
        {
            std::memcpy(out.payload.data(), payload_start,
                        static_cast<size_t>(payload_len));
        }

        out.consumed = total;
        return true;
    }

    // ── Receive helpers ─────────────────────────────────────────

    bool read_more()
    {
        char tmp[8192];
        int n = detail::platform::sock_recv(m_fd, tmp, sizeof(tmp));
        if (n <= 0)
            return false;
        m_buf.append(tmp, static_cast<size_t>(n));
        return true;
    }

    ws_message recv_websocket()
    {
        for (;;)
        {
            parsed_frame frame;
            if (parse_frame(frame))
            {
                m_buf.erase(0, frame.consumed);

                if (frame.opcode == detail::WS_OP_PING)
                {
                    // Auto-respond with pong
                    auto pong = build_control_frame(detail::WS_OP_PONG, frame.payload);
                    detail::platform::send_all(m_fd, pong.data(), pong.size());
                    // Return ping to caller
                    return {std::move(frame.payload), false, true, false};
                }

                if (frame.opcode == detail::WS_OP_PONG)
                {
                    // Ignore pong, read next frame
                    continue;
                }

                if (frame.opcode == detail::WS_OP_CLOSE)
                {
                    // Respond with close and disconnect
                    auto close_frame = build_close_frame();
                    detail::platform::send_all(m_fd, close_frame.data(),
                                               close_frame.size());
                    detail::platform::close_socket(m_fd);
                    m_fd = detail::platform::invalid_socket;
                    return {"", true, false, false};
                }

                // Text frame
                return {std::move(frame.payload), false, false, false};
            }

            // Need more data
            if (!read_more())
                return {"", false, false, true};
        }
    }

    ws_message recv_raw_tcp()
    {
        for (;;)
        {
            size_t pos = m_buf.find('\n');
            if (pos != std::string::npos)
            {
                std::string line = m_buf.substr(0, pos);
                m_buf.erase(0, pos + 1);
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                return {std::move(line), false, false, false};
            }

            if (!read_more())
                return {"", false, false, true};
        }
    }
};

} // namespace socketley
