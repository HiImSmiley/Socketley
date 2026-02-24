// ═══════════════════════════════════════════════════════════════════
//  socketley/cache_client.h — Cross-platform cache client (Tier 2)
//
//  Header-only TCP client for Socketley cache runtimes.
//  Speaks the text protocol: "COMMAND args\n" → response lines.
//  Works on Windows, macOS, and Linux. C++17, zero external deps.
//
//  Example:
//    #include <socketley/cache_client.h>
//    int main() {
//        socketley::cache_client c;
//        if (!c.connect("192.168.1.100", 9000)) return 1;
//        c.set("key", "hello");
//        auto r = c.get("key");
//        // r.value == "hello"
//    }
//    // MSVC:  cl /std:c++17 app.cpp
//    // clang: clang++ -std=c++17 app.cpp
// ═══════════════════════════════════════════════════════════════════
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

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
        // macOS: suppress SIGPIPE per-socket
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
} // namespace detail

// ── Result type ─────────────────────────────────────────────────

struct cache_result
{
    bool ok{false};
    std::string value;
    std::vector<std::string> values;
    int64_t integer{0};

    bool is_nil() const { return ok && value == "nil"; }
    explicit operator bool() const { return ok; }
};

// ── Cache client ────────────────────────────────────────────────

class cache_client
{
public:
    cache_client() = default;

    ~cache_client() { close(); }

    // Non-copyable, movable
    cache_client(const cache_client&) = delete;
    cache_client& operator=(const cache_client&) = delete;

    cache_client(cache_client&& o) noexcept
        : m_fd(o.m_fd), m_host(std::move(o.m_host)), m_port(o.m_port),
          m_buf(std::move(o.m_buf))
    {
        o.m_fd = detail::platform::invalid_socket;
    }

    cache_client& operator=(cache_client&& o) noexcept
    {
        if (this != &o)
        {
            close();
            m_fd = o.m_fd;
            m_host = std::move(o.m_host);
            m_port = o.m_port;
            m_buf = std::move(o.m_buf);
            o.m_fd = detail::platform::invalid_socket;
        }
        return *this;
    }

    bool connect(const std::string& host, uint16_t port)
    {
        close();
        detail::platform::wsa_init();

        m_host = host;
        m_port = port;
        m_fd = detail::platform::tcp_connect(host, port);
        return m_fd != detail::platform::invalid_socket;
    }

    void close()
    {
        if (m_fd != detail::platform::invalid_socket)
        {
            detail::platform::close_socket(m_fd);
            m_fd = detail::platform::invalid_socket;
        }
        m_buf.clear();
    }

    bool reconnect()
    {
        if (m_host.empty())
            return false;
        return connect(m_host, m_port);
    }

    bool is_connected() const
    {
        return m_fd != detail::platform::invalid_socket;
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

    const std::string& host() const { return m_host; }
    uint16_t port() const { return m_port; }

    // ── String commands ─────────────────────────────────────────

    cache_result get(const std::string& key)
    {
        return send_single("get " + key);
    }

    cache_result set(const std::string& key, const std::string& value)
    {
        return send_single("set " + key + " " + value);
    }

    cache_result del(const std::string& key)
    {
        return send_single("del " + key);
    }

    cache_result exists(const std::string& key)
    {
        return send_integer("exists " + key);
    }

    cache_result incr(const std::string& key)
    {
        return send_integer("incr " + key);
    }

    cache_result decr(const std::string& key)
    {
        return send_integer("decr " + key);
    }

    cache_result incrby(const std::string& key, int64_t delta)
    {
        return send_integer("incrby " + key + " " + std::to_string(delta));
    }

    cache_result decrby(const std::string& key, int64_t delta)
    {
        return send_integer("decrby " + key + " " + std::to_string(delta));
    }

    cache_result append(const std::string& key, const std::string& value)
    {
        return send_integer("append " + key + " " + value);
    }

    cache_result strlen(const std::string& key)
    {
        return send_integer("strlen " + key);
    }

    cache_result getset(const std::string& key, const std::string& value)
    {
        return send_single("getset " + key + " " + value);
    }

    cache_result setnx(const std::string& key, const std::string& value)
    {
        return send_integer("setnx " + key + " " + value);
    }

    cache_result setex(const std::string& key, int seconds, const std::string& value)
    {
        return send_single("setex " + key + " " + std::to_string(seconds) + " " + value);
    }

    cache_result psetex(const std::string& key, int64_t ms, const std::string& value)
    {
        return send_single("psetex " + key + " " + std::to_string(ms) + " " + value);
    }

    cache_result type(const std::string& key)
    {
        return send_single("type " + key);
    }

    // ── Multi-key ───────────────────────────────────────────────

    cache_result mget(const std::vector<std::string>& keys)
    {
        std::string cmd = "mget";
        for (auto& k : keys)
            cmd += " " + k;
        return send_multi(cmd);
    }

    cache_result mset(const std::vector<std::pair<std::string, std::string>>& kvs)
    {
        std::string cmd = "mset";
        for (auto& [k, v] : kvs)
            cmd += " " + k + " " + v;
        return send_single(cmd);
    }

    // ── Lists ───────────────────────────────────────────────────

    cache_result lpush(const std::string& key, const std::string& value)
    {
        return send_single("lpush " + key + " " + value);
    }

    cache_result rpush(const std::string& key, const std::string& value)
    {
        return send_single("rpush " + key + " " + value);
    }

    cache_result lpop(const std::string& key)
    {
        return send_single("lpop " + key);
    }

    cache_result rpop(const std::string& key)
    {
        return send_single("rpop " + key);
    }

    cache_result llen(const std::string& key)
    {
        return send_integer("llen " + key);
    }

    cache_result lindex(const std::string& key, int index)
    {
        return send_single("lindex " + key + " " + std::to_string(index));
    }

    cache_result lrange(const std::string& key, int start, int stop)
    {
        return send_multi("lrange " + key + " " + std::to_string(start) +
                          " " + std::to_string(stop));
    }

    // ── Sets ────────────────────────────────────────────────────

    cache_result sadd(const std::string& key, const std::string& member)
    {
        return send_single("sadd " + key + " " + member);
    }

    cache_result srem(const std::string& key, const std::string& member)
    {
        return send_single("srem " + key + " " + member);
    }

    cache_result sismember(const std::string& key, const std::string& member)
    {
        return send_integer("sismember " + key + " " + member);
    }

    cache_result scard(const std::string& key)
    {
        return send_integer("scard " + key);
    }

    cache_result smembers(const std::string& key)
    {
        return send_multi("smembers " + key);
    }

    // ── Hashes ──────────────────────────────────────────────────

    cache_result hset(const std::string& key, const std::string& field,
                      const std::string& value)
    {
        return send_single("hset " + key + " " + field + " " + value);
    }

    cache_result hget(const std::string& key, const std::string& field)
    {
        return send_single("hget " + key + " " + field);
    }

    cache_result hdel(const std::string& key, const std::string& field)
    {
        return send_single("hdel " + key + " " + field);
    }

    cache_result hlen(const std::string& key)
    {
        return send_integer("hlen " + key);
    }

    cache_result hgetall(const std::string& key)
    {
        return send_multi("hgetall " + key);
    }

    // ── TTL / Expiry ────────────────────────────────────────────

    cache_result expire(const std::string& key, int seconds)
    {
        return send_single("expire " + key + " " + std::to_string(seconds));
    }

    cache_result pexpire(const std::string& key, int64_t ms)
    {
        return send_single("pexpire " + key + " " + std::to_string(ms));
    }

    cache_result ttl(const std::string& key)
    {
        return send_integer("ttl " + key);
    }

    cache_result pttl(const std::string& key)
    {
        return send_integer("pttl " + key);
    }

    cache_result persist(const std::string& key)
    {
        return send_single("persist " + key);
    }

    cache_result expireat(const std::string& key, int64_t unix_seconds)
    {
        return send_integer("expireat " + key + " " + std::to_string(unix_seconds));
    }

    cache_result pexpireat(const std::string& key, int64_t unix_ms)
    {
        return send_integer("pexpireat " + key + " " + std::to_string(unix_ms));
    }

    // ── Pub/Sub ─────────────────────────────────────────────────

    cache_result publish(const std::string& channel, const std::string& message)
    {
        return send_integer("publish " + channel + " " + message);
    }

    cache_result subscribe(const std::string& channel)
    {
        return send_single("subscribe " + channel);
    }

    cache_result unsubscribe(const std::string& channel)
    {
        return send_single("unsubscribe " + channel);
    }

    // Blocking read for pub/sub messages (channel message\n)
    cache_result recv_message()
    {
        std::string line = read_line();
        if (line.empty())
            return {false, {}, {}, 0};

        // Pub/sub messages: "channel message"
        size_t sp = line.find(' ');
        cache_result r;
        r.ok = true;
        if (sp != std::string::npos)
        {
            r.values.push_back(line.substr(0, sp));
            r.value = line.substr(sp + 1);
        }
        else
        {
            r.value = std::move(line);
        }
        return r;
    }

    // ── Admin ───────────────────────────────────────────────────

    cache_result size()
    {
        return send_integer("size");
    }

    cache_result memory()
    {
        return send_integer("memory");
    }

    cache_result maxmemory()
    {
        return send_integer("maxmemory");
    }

    cache_result keys(const std::string& pattern = "*")
    {
        return send_multi("keys " + pattern);
    }

    cache_result scan(uint64_t cursor, const std::string& pattern = "*",
                      size_t count = 10)
    {
        std::string cmd = "scan " + std::to_string(cursor);
        if (pattern != "*")
            cmd += " match " + pattern;
        if (count != 10)
            cmd += " count " + std::to_string(count);

        // Scan response: first line = next cursor, then keys, then "end\n"
        if (!send_cmd(cmd))
            return {false, {}, {}, 0};

        std::string cursor_line = read_line();
        if (cursor_line.empty())
            return {false, {}, {}, 0};

        cache_result r;
        r.ok = true;

        // Parse next cursor
        try { r.integer = std::stoll(cursor_line); }
        catch (...) { r.ok = false; return r; }

        // Read keys until "end"
        for (;;)
        {
            std::string line = read_line();
            if (line.empty() || line == "end")
                break;
            r.values.push_back(std::move(line));
        }

        return r;
    }

    cache_result flush()
    {
        return send_single("flush");
    }

    cache_result load()
    {
        return send_single("load");
    }

    // ── Raw command ─────────────────────────────────────────────

    cache_result execute(const std::string& command)
    {
        return send_single(command);
    }

private:
    detail::platform::socket_t m_fd{detail::platform::invalid_socket};
    std::string m_host;
    uint16_t m_port{0};
    std::string m_buf;

    bool send_cmd(const std::string& cmd)
    {
        if (m_fd == detail::platform::invalid_socket)
            return false;
        std::string msg = cmd + "\n";
        return detail::platform::send_all(m_fd, msg.data(), msg.size());
    }

    std::string read_line()
    {
        // Check buffer first
        for (;;)
        {
            size_t pos = m_buf.find('\n');
            if (pos != std::string::npos)
            {
                std::string line = m_buf.substr(0, pos);
                m_buf.erase(0, pos + 1);
                // Strip \r if present
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                return line;
            }

            char tmp[4096];
            int n = detail::platform::sock_recv(m_fd, tmp, sizeof(tmp));
            if (n <= 0)
                return {};
            m_buf.append(tmp, static_cast<size_t>(n));
        }
    }

    bool is_error_response(const std::string& line) const
    {
        return line.compare(0, 6, "error:") == 0 ||
               line.compare(0, 7, "denied:") == 0 ||
               line.compare(0, 6, "usage:") == 0 ||
               line.compare(0, 7, "failed:") == 0;
    }

    cache_result send_single(const std::string& cmd)
    {
        if (!send_cmd(cmd))
            return {false, {}, {}, 0};

        std::string line = read_line();
        if (line.empty() && m_fd == detail::platform::invalid_socket)
            return {false, {}, {}, 0};

        cache_result r;
        r.ok = !is_error_response(line);
        r.value = std::move(line);
        return r;
    }

    cache_result send_multi(const std::string& cmd)
    {
        if (!send_cmd(cmd))
            return {false, {}, {}, 0};

        cache_result r;
        r.ok = true;

        for (;;)
        {
            std::string line = read_line();
            if (line.empty() && m_fd == detail::platform::invalid_socket)
            {
                r.ok = false;
                break;
            }
            if (line == "end")
                break;
            if (is_error_response(line))
            {
                r.ok = false;
                r.value = std::move(line);
                break;
            }
            r.values.push_back(std::move(line));
        }

        return r;
    }

    cache_result send_integer(const std::string& cmd)
    {
        cache_result r = send_single(cmd);
        if (r.ok && !r.value.empty())
        {
            try { r.integer = std::stoll(r.value); }
            catch (...) { /* leave as 0 */ }
        }
        return r;
    }
};

} // namespace socketley
