#include "lua_context.h"

#ifndef SOCKETLEY_NO_LUA

#include "runtime_instance.h"
#include "runtime_definitions.h"
#include "runtime_manager.h"
#include "cluster_discovery.h"
#include "event_loop.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../cli/command_hashing.h"
#include "../cli/runtime_type_parser.h"
#include <iostream>
#include <algorithm>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstring>
#ifndef SOCKETLEY_NO_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif

lua_context::lua_context()
{
    m_lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table,
                         sol::lib::math, sol::lib::os, sol::lib::io,
                         sol::lib::package);

    // Remove dangerous os functions — keep os.time, os.clock, os.date, os.difftime
    m_lua["os"]["execute"] = sol::nil;
    m_lua["os"]["remove"]  = sol::nil;
    m_lua["os"]["rename"]  = sol::nil;
    m_lua["os"]["tmpname"] = sol::nil;
    m_lua["os"]["exit"]    = sol::nil;
}

// ─── lua_timer: heap-allocated one-shot / repeating timer via op_timeout ───
struct lua_timer : io_handler
{
    std::shared_ptr<bool> alive;
    sol::function         fn;
    event_loop*           loop{};
    lua_context*          ctx{};
    struct __kernel_timespec ts{};
    io_request            req{};
    bool                  repeat{false};
    bool                  cancelled{false};
    int                   timer_id{0};

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        if (!*alive || cqe->res == -ECANCELED || cancelled)
        {
            // Out of the loop's owner table first: this object is about to be
            // pooled or freed, and a token left behind would let a later
            // completion be dispatched into whoever takes its place.
            if (loop) loop->deregister_owner(this);
            if (ctx) { ctx->unregister_timer(this); ctx->timer_pool_release(this); }
            else delete this;
            return;
        }
        try { fn(); } catch (const sol::error& e) {
            fprintf(stderr, "[lua] timer error: %s\n", e.what());
        }
        if (repeat && *alive && !cancelled)
            loop->submit_timeout(&ts, &req);
        else
        {
            // Out of the loop's owner table first: this object is about to be
            // pooled or freed, and a token left behind would let a later
            // completion be dispatched into whoever takes its place.
            if (loop) loop->deregister_owner(this);
            if (ctx) { ctx->unregister_timer(this); ctx->timer_pool_release(this); }
            else delete this;
        }
    }
};

lua_context::~lua_context()
{
    // Clear all timer sol::function refs BEFORE the Lua state is destroyed.
    // This prevents luaL_unref on a closed state when the timer CQE fires.
    for (auto* t : m_active_timers)
        static_cast<lua_timer*>(t)->fn = sol::nil;
    m_active_timers.clear();

    // Free all pooled timers
    for (auto* t : m_timer_pool)
        delete static_cast<lua_timer*>(t);
    m_timer_pool.clear();

    *m_alive = false;
}

void lua_context::unregister_timer(void* t)
{
    auto* timer = static_cast<lua_timer*>(t);
    if (timer->timer_id > 0)
        m_timer_map.erase(timer->timer_id);

    auto it = std::find(m_active_timers.begin(), m_active_timers.end(), t);
    if (it != m_active_timers.end())
    {
        *it = m_active_timers.back();
        m_active_timers.pop_back();
    }
}

void* lua_context::timer_pool_acquire()
{
    if (!m_timer_pool.empty())
    {
        auto* t = m_timer_pool.back();
        m_timer_pool.pop_back();
        return t;
    }
    return new lua_timer{};
}

void lua_context::timer_pool_release(void* t)
{
    auto* timer = static_cast<lua_timer*>(t);
    timer->fn = sol::nil;
    timer->cancelled = false;
    timer->timer_id = 0;
    m_timer_pool.push_back(t);
}

static const char* state_to_string(runtime_state s)
{
    switch (s)
    {
        case runtime_created: return "created";
        case runtime_running: return "running";
        case runtime_stopped: return "stopped";
        case runtime_failed:  return "failed";
    }
    return "unknown";
}

bool lua_context::load_script(std::string_view path, runtime_instance* owner)
{
    register_bindings(owner);

    // Set package.path so require() resolves modules relative to the script's directory
    {
        std::string script_dir(path);
        auto slash = script_dir.rfind('/');
        if (slash != std::string::npos)
            script_dir.resize(slash);
        else
            script_dir = ".";

        sol::optional<std::string> current_path = m_lua["package"]["path"];
        std::string new_path = script_dir + "/?.lua;" + script_dir + "/?/init.lua";
        if (current_path && !current_path->empty())
        {
            new_path += ';';
            new_path += *current_path;
        }
        m_lua["package"]["path"] = new_path;
    }

    auto result = m_lua.safe_script_file(std::string(path), sol::script_pass_on_error);
    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "[lua] script error: " << err.what() << std::endl;
        return false;
    }

    m_on_start = m_lua["on_start"];
    m_on_stop = m_lua["on_stop"];
    m_on_message = m_lua["on_message"];
    m_on_send = m_lua["on_send"];
    m_on_connect = m_lua["on_connect"];
    m_on_disconnect = m_lua["on_disconnect"];
    m_on_route = m_lua["on_route"];
    m_on_master_auth = m_lua["on_master_auth"];
    m_on_client_message = m_lua["on_client_message"];
    m_on_tick = m_lua["on_tick"];
    if (m_on_tick.valid()) {
        sol::optional<int> tms = m_lua["tick_ms"];
        m_tick_ms = (tms && *tms >= 10) ? static_cast<uint32_t>(*tms) : 100;
    }
    m_on_miss   = m_lua["on_miss"];
    m_on_write  = m_lua["on_write"];
    m_on_delete = m_lua["on_delete"];
    m_on_expire = m_lua["on_expire"];
    m_on_auth       = m_lua["on_auth"];
    m_on_websocket  = m_lua["on_websocket"];
    m_on_proxy_request  = m_lua["on_proxy_request"];
    m_on_proxy_response = m_lua["on_proxy_response"];
    m_on_cluster_join   = m_lua["on_cluster_join"];
    m_on_cluster_leave  = m_lua["on_cluster_leave"];
    m_on_group_change   = m_lua["on_group_change"];
    m_on_upstream           = m_lua["on_upstream"];
    m_on_upstream_connect   = m_lua["on_upstream_connect"];
    m_on_upstream_disconnect = m_lua["on_upstream_disconnect"];
    m_on_http_request       = m_lua["on_http_request"];

    // Build callback bitmask for O(1) has_on_*() checks
    m_callback_mask = 0;
    if (m_on_start.valid())              m_callback_mask |= CB_ON_START;
    if (m_on_stop.valid())               m_callback_mask |= CB_ON_STOP;
    if (m_on_message.valid())            m_callback_mask |= CB_ON_MESSAGE;
    if (m_on_send.valid())               m_callback_mask |= CB_ON_SEND;
    if (m_on_connect.valid())            m_callback_mask |= CB_ON_CONNECT;
    if (m_on_disconnect.valid())         m_callback_mask |= CB_ON_DISCONNECT;
    if (m_on_route.valid())              m_callback_mask |= CB_ON_ROUTE;
    if (m_on_master_auth.valid())        m_callback_mask |= CB_ON_MASTER_AUTH;
    if (m_on_client_message.valid())     m_callback_mask |= CB_ON_CLIENT_MESSAGE;
    if (m_on_tick.valid())               m_callback_mask |= CB_ON_TICK;
    if (m_on_miss.valid())               m_callback_mask |= CB_ON_MISS;
    if (m_on_write.valid())              m_callback_mask |= CB_ON_WRITE;
    if (m_on_delete.valid())             m_callback_mask |= CB_ON_DELETE;
    if (m_on_expire.valid())             m_callback_mask |= CB_ON_EXPIRE;
    if (m_on_auth.valid())               m_callback_mask |= CB_ON_AUTH;
    if (m_on_websocket.valid())          m_callback_mask |= CB_ON_WEBSOCKET;
    if (m_on_proxy_request.valid())      m_callback_mask |= CB_ON_PROXY_REQUEST;
    if (m_on_proxy_response.valid())     m_callback_mask |= CB_ON_PROXY_RESPONSE;
    if (m_on_cluster_join.valid())       m_callback_mask |= CB_ON_CLUSTER_JOIN;
    if (m_on_cluster_leave.valid())      m_callback_mask |= CB_ON_CLUSTER_LEAVE;
    if (m_on_group_change.valid())       m_callback_mask |= CB_ON_GROUP_CHANGE;
    if (m_on_upstream.valid())           m_callback_mask |= CB_ON_UPSTREAM;
    if (m_on_upstream_connect.valid())   m_callback_mask |= CB_ON_UPSTREAM_CONNECT;
    if (m_on_upstream_disconnect.valid()) m_callback_mask |= CB_ON_UPSTREAM_DISCONNECT;
    if (m_on_http_request.valid())       m_callback_mask |= CB_ON_HTTP_REQUEST;

    // The filter chain.  `filters` is an array of functions run in order before
    // a proxy chooses a backend; see proxy_instance::run_request_filters.
    //
    // A malformed entry refuses the script rather than being skipped.  The chain
    // is where authentication lives, so "the third filter was a typo and was
    // quietly dropped" is a runtime that admits everyone while looking exactly
    // like one that does not.  A script that cannot be loaded is visible at the
    // moment the operator writes it; a hole in the chain is not.
    m_filters.clear();
    {
        sol::object fobj = m_lua["filters"];
        if (fobj.valid() && fobj != sol::nil)
        {
            if (!fobj.is<sol::table>())
            {
                std::cerr << "[lua] `filters` must be a table of functions" << std::endl;
                return false;
            }
            sol::table ft = fobj.as<sol::table>();
            // The array part only, and stopping at the first hole: a chain with
            // a gap in it has an order nobody can state, which is the one thing
            // a chain has to have.
            for (size_t i = 1;; ++i)
            {
                sol::object entry = ft[i];
                if (!entry.valid() || entry == sol::nil)
                    break;
                if (!entry.is<sol::function>())
                {
                    std::cerr << "[lua] filters[" << i << "] is not a function" << std::endl;
                    return false;
                }
                m_filters.push_back(entry.as<sol::protected_function>());
            }
            if (m_filters.empty())
            {
                // `filters = { auth = f }` reads like a registration and is
                // silently nothing: the array part is empty, so the chain never
                // runs.  An empty table is a legitimate way to say "no filters"
                // and is left alone.
                bool any = false;
                ft.for_each([&](sol::object, sol::object) { any = true; });
                if (any)
                {
                    std::cerr << "[lua] `filters` has no entry at index 1 — a chain is "
                                 "an ordered array, not a keyed table" << std::endl;
                    return false;
                }
            }
        }
    }
    if (!m_filters.empty()) m_callback_mask |= CB_FILTERS;

    return true;
}

void lua_context::dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message)
{
    thread_local std::string key_buf;
    key_buf.clear();
    key_buf.reserve(cache_name.size() + 1 + channel.size());
    key_buf.append(cache_name);
    key_buf.push_back('\0');
    key_buf.append(channel);
    auto it = m_subscriptions.find(key_buf);
    if (it == m_subscriptions.end()) return;
    for (auto& fn : it->second)
    {
        try { fn(channel, message); }
        catch (const sol::error& e)
        {
            fprintf(stderr, "[lua] subscribe callback error: %s\n", e.what());
        }
    }
}

void lua_context::update_self_state(const char* state_str)
{
    sol::optional<sol::table> self = m_lua["self"];
    if (self)
        (*self)["state"] = state_str;
}

// ---------------------------------------------------------------------------
// socketley.http(opts) — synchronous HTTP/HTTPS client for Lua scripts
// opts = { url, method="GET", body="", headers={}, timeout_ms=5000 }
// Returns { ok=bool, status=int, body=string, error=string }
//
// HTTPS now verifies the chain against the system trust store *and* that the
// certificate was issued for the host in the URL. It used to do neither
// (SSL_VERIFY_NONE): that bought encryption against somebody recording the
// wire and nothing whatsoever against somebody sitting on it. Any self-signed
// certificate was accepted, so a script fetching config, polling a health
// endpoint or posting a webhook could be answered by whoever got in the middle
// — with no error, no log line, and a `result.ok` of true.
//
// STILL BLOCKS THE EVENT-LOOP THREAD. This runs on the single thread that
// serves every runtime in the daemon, so a slow host still stalls all of them.
// Making it asynchronous means driving the socket from event_loop and
// suspending the Lua callback across the round trip, which is a different
// change in a different file. What is fixed here is that the block is now
// *bounded*: DNS aside, connect, handshake, send and receive share one deadline
// of timeout_ms enforced with poll(). Before, connect() ignored timeout_ms
// entirely and sat in the kernel's SYN retry schedule for over two minutes,
// and the socket timeouts restarted on every byte, so a server trickling one
// byte at a time held the whole daemon for as long as it cared to.
//
// Residual: getaddrinfo() is still unbounded and is not counted against the
// deadline until it returns — the resolver has no per-call timeout, and giving
// it one means resolving off-thread, which is the same asynchronous rework.
//
// Keep to on_start/on_stop or low-frequency on_tick callbacks regardless.
// ---------------------------------------------------------------------------

using http_clock = std::chrono::steady_clock;

// Milliseconds left before `deadline`, never negative.
static int http_ms_left(http_clock::time_point deadline)
{
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - http_clock::now()).count();
    if (left <= 0)       return 0;
    if (left > INT_MAX)  return INT_MAX;
    return static_cast<int>(left);
}

// Wait for `fd` to become ready for `events`, or for the deadline to pass.
// Returns 1 = ready, 0 = out of time, -1 = poll failed.
static int http_wait(int fd, short events, http_clock::time_point deadline)
{
    for (;;)
    {
        int left = http_ms_left(deadline);
        if (left <= 0)
            return 0;

        struct pollfd p{};
        p.fd     = fd;
        p.events = events;

        int r = ::poll(&p, 1, left);
        if (r > 0)  return 1;
        if (r == 0) return 0;
        if (errno == EINTR)
            continue;      // a signal is not a timeout; the deadline decides
        return -1;
    }
}

// Ceiling on what one response may accumulate in daemon memory. The old loop
// appended until the peer stopped sending, so a hostile or broken endpoint
// could grow this string until the allocator gave up — on a box with no swap
// that takes the daemon down, not just the script.
static constexpr size_t http_max_response = 8u * 1024u * 1024u;

#ifndef SOCKETLEY_NO_HTTPS
// Drain OpenSSL's thread-local error queue into readable text.
//
// Every TLS failure here reported the bare string "TLS handshake failed". The
// reason — expired certificate, unknown CA, name mismatch, a plain-HTTP server
// on port 443 — was on that queue and nobody popped it. Leaving it there is a
// second bug: the queue persists, so a stale entry gets drained later and
// reported as the cause of an unrelated request's failure.
static std::string ssl_error_text()
{
    std::string out;
    char buf[256];
    for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error())
    {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty())
            out += "; ";
        out += buf;
    }
    return out;
}
#endif

static sol::table socketley_http_call(sol::state& lua, sol::table opts)
{
    sol::table result = lua.create_table();
    result["ok"]     = false;
    result["status"] = 0;
    result["body"]   = std::string{};
    result["error"]  = std::string{};

    sol::optional<std::string> url_opt = opts["url"];
    if (!url_opt || url_opt->empty()) { result["error"] = "url required"; return result; }

    std::string method  = sol::optional<std::string>(opts["method"]).value_or("GET");
    std::string url     = *url_opt;
    std::string body    = sol::optional<std::string>(opts["body"]).value_or("");
    int timeout_ms      = sol::optional<int>(opts["timeout_ms"]).value_or(5000);
    if (timeout_ms <= 0)
        timeout_ms = 5000;

    // One deadline for the whole exchange, taken before anything can block.
    // Every wait below measures against this, so the total time this call can
    // hold the event-loop thread is timeout_ms plus the resolver, rather than
    // timeout_ms per operation with no ceiling on the number of operations.
    const auto deadline = http_clock::now() + std::chrono::milliseconds(timeout_ms);

    // Parse scheme
    bool is_https = false;
    if (url.rfind("https://", 0) == 0)      { is_https = true;  url = url.substr(8); }
    else if (url.rfind("http://", 0) == 0)  {                   url = url.substr(7); }
    else { result["error"] = "unsupported scheme (use http:// or https://)"; return result; }

#ifdef SOCKETLEY_NO_HTTPS
    if (is_https) {
        result["error"] = "HTTPS not supported in this build; use io.popen(\"curl -s https://...\")";
        return result;
    }
#endif

    // Parse host:port/path.
    //
    // The last colon is not the port separator: an IPv6 literal is full of
    // colons. rfind(':') turned "[::1]:8443" into host "[::1]" — brackets and
    // all, which no resolver and no certificate ever matches — and bare "::1"
    // into host "::" with port 1. Either way the address never resolved, so
    // the IP-literal branch of the certificate check below was unreachable
    // from here.
    //
    // Two forms of the host come out of this: `host`, without brackets, which
    // is what getaddrinfo(), SNI and the certificate verifier all expect, and
    // `host_header`, which keeps them, because an unbracketed IPv6 address in
    // a Host header cannot be told from host:port.
    int port = is_https ? 443 : 80;
    std::string host, host_header, path;
    {
        auto slash = url.find('/');
        std::string authority = (slash != std::string::npos) ? url.substr(0, slash) : url;
        path = (slash != std::string::npos) ? url.substr(slash) : "/";

        std::string_view port_str;
        if (!authority.empty() && authority.front() == '[')
        {
            auto rbracket = authority.find(']');
            if (rbracket == std::string::npos) {
                result["error"] = "malformed url: '[' with no matching ']'";
                return result;
            }
            host = authority.substr(1, rbracket - 1);
            if (rbracket + 1 < authority.size())
            {
                if (authority[rbracket + 1] != ':') {
                    result["error"] = "malformed url: expected ':port' after ']'";
                    return result;
                }
                port_str = std::string_view(authority).substr(rbracket + 2);
            }
        }
        else
        {
            auto colon = authority.rfind(':');
            // Exactly one colon is a port. More than one and no brackets is an
            // unbracketed IPv6 literal — not strictly a legal URL, but it must
            // not be silently cut in half either.
            if (colon != std::string::npos && authority.find(':') == colon)
            {
                host     = authority.substr(0, colon);
                port_str = std::string_view(authority).substr(colon + 1);
            }
            else
                host = authority;
        }

        if (host.empty()) { result["error"] = "url has no host"; return result; }

        if (!port_str.empty())
        {
            // A port that does not parse used to leave the default in place and
            // quietly talk to the wrong service.
            int parsed = 0;
            auto [ptr, ec] = std::from_chars(port_str.data(),
                                             port_str.data() + port_str.size(), parsed);
            if (ec != std::errc{} || ptr != port_str.data() + port_str.size() ||
                parsed < 1 || parsed > 65535)
            {
                result["error"] = "invalid port in url: " + std::string(port_str);
                return result;
            }
            port = parsed;
        }

        host_header = (host.find(':') != std::string::npos) ? "[" + host + "]" : host;
    }

    // DNS resolve
    struct addrinfo hints{}, *addrs = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_buf[8];
    auto port_res = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
    *port_res.ptr = '\0';
    if (getaddrinfo(host.c_str(), port_buf, &hints, &addrs) != 0 || !addrs) {
        result["error"] = "DNS resolution failed for: " + host;
        return result;
    }

    // Connect.
    //
    // Non-blocking socket plus poll(), not a blocking connect() with
    // SO_SNDTIMEO: that option does not bound connect() on Linux at all. A host
    // that drops the SYN — a firewall blackholing the port is the usual way —
    // left this parked in the kernel's retry schedule for well over two
    // minutes, on the thread every other runtime needs, no matter what
    // timeout_ms said. The socket stays non-blocking for the rest of the call
    // so every later wait goes through the same deadline.
    int sock = ::socket(addrs->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) { freeaddrinfo(addrs); result["error"] = "socket() failed"; return result; }

    if (::connect(sock, addrs->ai_addr, addrs->ai_addrlen) != 0)
    {
        if (errno != EINPROGRESS)
        {
            freeaddrinfo(addrs); ::close(sock);
            result["error"] = std::string("connect() failed: ") + std::strerror(errno);
            return result;
        }

        int ready  = http_wait(sock, POLLOUT, deadline);
        int so_err = 0;
        if (ready == 1)
        {
            // Writable only means the attempt finished, not that it succeeded:
            // a refused connection reports readiness and hides ECONNREFUSED in
            // SO_ERROR, which is how a failed connect turns into a mysterious
            // empty response if nobody looks.
            socklen_t so_len = sizeof(so_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0)
                so_err = errno;
        }
        if (ready != 1 || so_err != 0)
        {
            freeaddrinfo(addrs); ::close(sock);
            result["error"] = (ready == 0)
                ? std::string("connect timed out after ") + std::to_string(timeout_ms) + "ms"
                : std::string("connect() failed: ") + std::strerror(so_err ? so_err : errno);
            return result;
        }
    }
    freeaddrinfo(addrs);

    // Build HTTP/1.0 request
    std::string req;
    req.reserve(256 + body.size());
    req.append(method);
    req.append(" ");
    req.append(path);
    req.append(" HTTP/1.0\r\n");
    req.append("Host: ");
    req.append(host_header);
    req.append("\r\n");
    if (!body.empty())
    {
        char cl_buf[24];
        auto cl_res = std::to_chars(cl_buf, cl_buf + sizeof(cl_buf), body.size());
        req.append("Content-Length: ");
        req.append(cl_buf, static_cast<size_t>(cl_res.ptr - cl_buf));
        req.append("\r\n");
    }
    sol::optional<sol::table> hdrs = opts["headers"];
    if (hdrs) {
        (*hdrs).for_each([&](sol::object k, sol::object v) {
            if (k.is<std::string>() && v.is<std::string>())
            {
                req.append(k.as<std::string>());
                req.append(": ");
                req.append(v.as<std::string>());
                req.append("\r\n");
            }
        });
    }
    req.append("Connection: close\r\n\r\n");
    req.append(body);

    // Send + receive. Both directions are poll-driven against the shared
    // deadline: the socket timeouts this used to rely on restart on every byte
    // that arrives, so a peer sending one byte per second never "times out"
    // while holding the thread forever.
    std::string response;
    std::string xfer_err;

#ifndef SOCKETLEY_NO_HTTPS
    if (is_https) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { ::close(sock); result["error"] = "SSL_CTX_new failed"; return result; }

        // ── Verification ──
        // SSL_VERIFY_PEER fails the handshake on a chain no trusted CA signed;
        // the host pin below fails it when the chain is trusted but was issued
        // to somebody else. Both are needed: a certificate for a domain the
        // attacker owns is entirely valid, and without the name check it
        // impersonates any host this script fetches.
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            std::string why = ssl_error_text();
            SSL_CTX_free(ctx); ::close(sock);
            result["error"] = "no system CA store available" + (why.empty() ? "" : ": " + why);
            return result;
        }
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
        // HTTP/1.0 with "Connection: close": a great many servers just drop the
        // TCP connection instead of sending close_notify. OpenSSL 3.0 calls
        // that a protocol error by default, which would turn a complete
        // response into "SSL_read failed" for a large slice of the internet.
        // The cost is that a truncated response is indistinguishable from a
        // complete one — the same exposure the plaintext path has always had,
        // and the reason a caller should check status and body rather than
        // trust length.
        SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

        SSL* ssl = SSL_new(ctx);
        if (!ssl) { SSL_CTX_free(ctx); ::close(sock); result["error"] = "SSL_new failed"; return result; }
        SSL_set_fd(ssl, sock);

        // An address literal is matched against the certificate's iPAddress SAN
        // and must not be sent as SNI (RFC 6066 permits host names there only).
        unsigned char ip_probe[16];
        const bool host_is_ip = inet_pton(AF_INET,  host.c_str(), ip_probe) == 1 ||
                                inet_pton(AF_INET6, host.c_str(), ip_probe) == 1;
        bool pinned;
        if (host_is_ip) {
            pinned = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host.c_str()) == 1;
        } else {
            SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            pinned = SSL_set1_host(ssl, host.c_str()) == 1 &&
                     SSL_set_tlsext_host_name(ssl, host.c_str()) == 1;
        }
        if (!pinned) {
            // Refuse rather than continue unpinned: a connection that verifies
            // the chain and not the name looks identical to a good one.
            std::string why = ssl_error_text();
            SSL_free(ssl); SSL_CTX_free(ctx); ::close(sock);
            result["error"] = "failed to pin expected certificate name for " + host
                            + (why.empty() ? "" : ": " + why);
            return result;
        }

        // Handshake, bounded by the shared deadline. The socket is
        // non-blocking, so OpenSSL hands back WANT_READ/WANT_WRITE instead of
        // sleeping inside read(), and poll() decides how long we are willing to
        // wait for the peer's next record.
        std::string tls_err;
        for (;;) {
            ERR_clear_error();
            int hr = SSL_connect(ssl);
            if (hr == 1)
                break;
            int e = SSL_get_error(ssl, hr);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                if (http_wait(sock, (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT, deadline) != 1) {
                    tls_err = "TLS handshake timed out"; break;
                }
                continue;
            }
            // The verify result carries the half of the diagnosis that never
            // reaches the error queue, so report whichever one has something.
            tls_err = "TLS handshake failed";
            long verify = SSL_get_verify_result(ssl);
            if (verify != X509_V_OK) {
                tls_err += ": certificate rejected: ";
                tls_err += X509_verify_cert_error_string(verify);
            }
            std::string why = ssl_error_text();
            if (!why.empty()) { tls_err += ": "; tls_err += why; }
            break;
        }
        if (!tls_err.empty()) {
            SSL_free(ssl); SSL_CTX_free(ctx); ::close(sock);
            result["error"] = tls_err;
            return result;
        }

        {
            size_t sent = 0;
            while (sent < req.size()) {
                ERR_clear_error();
                int w = SSL_write(ssl, req.data() + sent, static_cast<int>(req.size() - sent));
                if (w > 0) { sent += static_cast<size_t>(w); continue; }
                int e = SSL_get_error(ssl, w);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    if (http_wait(sock, (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT, deadline) != 1) {
                        xfer_err = "send timed out"; break;
                    }
                    continue;
                }
                xfer_err = "SSL_write failed";
                { std::string why = ssl_error_text(); if (!why.empty()) xfer_err += ": " + why; }
                break;
            }
        }
        if (xfer_err.empty()) {
            char buf[4096];
            for (;;) {
                ERR_clear_error();
                int n = SSL_read(ssl, buf, sizeof(buf));
                if (n > 0) {
                    if (response.size() + static_cast<size_t>(n) > http_max_response) {
                        xfer_err = "response exceeds 8MB limit"; break;
                    }
                    response.append(buf, static_cast<size_t>(n));
                    continue;
                }
                int e = SSL_get_error(ssl, n);
                if (e == SSL_ERROR_ZERO_RETURN)
                    break;                      // close_notify: response complete
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    if (http_wait(sock, (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT, deadline) != 1) {
                        xfer_err = "response timed out"; break;
                    }
                    continue;
                }
                if (e == SSL_ERROR_SYSCALL && ERR_peek_error() == 0 && !response.empty())
                    break;                      // peer closed without close_notify
                xfer_err = "SSL_read failed";
                { std::string why = ssl_error_text(); if (!why.empty()) xfer_err += ": " + why; }
                break;
            }
        }

        // One attempt only: on a non-blocking socket SSL_shutdown normally
        // wants another round trip, and we are closing the connection either
        // way — waiting for the peer's close_notify would spend the deadline we
        // just spent enforcing on nothing.
        if (SSL_shutdown(ssl) < 0) {}
        ERR_clear_error();
        SSL_free(ssl); SSL_CTX_free(ctx);
        ::close(sock);
    } else
#endif
    {
        {
            size_t s_total = 0;
            while (s_total < req.size()) {
                // MSG_NOSIGNAL for the same reason event_loop uses it: writing
                // to a peer that already closed must not raise SIGPIPE.
                ssize_t w = ::send(sock, req.data() + s_total, req.size() - s_total, MSG_NOSIGNAL);
                if (w > 0) { s_total += static_cast<size_t>(w); continue; }
                if (w < 0 && errno == EINTR) continue;
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (http_wait(sock, POLLOUT, deadline) != 1) { xfer_err = "send timed out"; break; }
                    continue;
                }
                xfer_err = std::string("send() failed: ") + std::strerror(errno);
                break;
            }
        }
        if (xfer_err.empty()) {
            char buf[4096];
            for (;;) {
                ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
                if (n > 0) {
                    if (response.size() + static_cast<size_t>(n) > http_max_response) {
                        xfer_err = "response exceeds 8MB limit"; break;
                    }
                    response.append(buf, static_cast<size_t>(n));
                    continue;
                }
                if (n == 0) break;              // peer closed — end of an HTTP/1.0 response
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (http_wait(sock, POLLIN, deadline) != 1) { xfer_err = "response timed out"; break; }
                    continue;
                }
                xfer_err = std::string("recv() failed: ") + std::strerror(errno);
                break;
            }
        }
        ::close(sock);
    }

    if (!xfer_err.empty()) { result["error"] = xfer_err; return result; }

    // Parse HTTP status line: "HTTP/1.x NNN Reason"
    int status = 0;
    auto sp1 = response.find(' ');
    if (sp1 != std::string::npos) {
        auto sp2 = response.find(' ', sp1 + 1);
        {
            auto ss = response.substr(sp1 + 1, sp2 - sp1 - 1);
            std::from_chars(ss.data(), ss.data() + ss.size(), status);
        }
    }
    auto body_start = response.find("\r\n\r\n");
    result["status"] = status;
    result["body"]   = (body_start != std::string::npos) ? response.substr(body_start + 4) : "";
    result["ok"]     = (status >= 200 && status < 300);
    return result;
}

// ─── JSON encode/decode for Lua ───────────────────────────────────────────────

static void json_encode_value(std::string& out, const sol::object& val);

static void json_encode_string(std::string& out, const std::string& s)
{
    out += '"';
    for (char c : s)
    {
        switch (c)
        {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                    out += hex;
                }
                else
                    out += c;
        }
    }
    out += '"';
}

static bool is_array_table(const sol::table& t)
{
    int expected = 1;
    for (const auto& kv : t)
    {
        if (kv.first.get_type() != sol::type::number)
            return false;
        double d = kv.first.as<double>();
        if (d != expected)
            return false;
        ++expected;
    }
    return expected > 1;
}

static void json_encode_value(std::string& out, const sol::object& val)
{
    switch (val.get_type())
    {
        case sol::type::nil:
        case sol::type::none:
            out += "null";
            break;
        case sol::type::boolean:
            out += val.as<bool>() ? "true" : "false";
            break;
        case sol::type::number:
        {
            double d = val.as<double>();
            auto i = static_cast<int64_t>(d);
            if (d == i && d >= -1e15 && d <= 1e15)
            {
                char buf[24];
                auto r = std::to_chars(buf, buf + sizeof(buf), i);
                out.append(buf, static_cast<size_t>(r.ptr - buf));
            }
            else
            {
                char buf[32];
                int n = snprintf(buf, sizeof(buf), "%.14g", d);
                out.append(buf, static_cast<size_t>(n));
            }
            break;
        }
        case sol::type::string:
            json_encode_string(out, val.as<std::string>());
            break;
        case sol::type::table:
        {
            sol::table t = val.as<sol::table>();
            if (is_array_table(t))
            {
                out += '[';
                bool first = true;
                for (const auto& kv : t)
                {
                    if (!first) out += ',';
                    first = false;
                    json_encode_value(out, kv.second);
                }
                out += ']';
            }
            else
            {
                out += '{';
                bool first = true;
                for (const auto& kv : t)
                {
                    if (!first) out += ',';
                    first = false;
                    json_encode_string(out, kv.first.as<std::string>());
                    out += ':';
                    json_encode_value(out, kv.second);
                }
                out += '}';
            }
            break;
        }
        default:
            out += "null";
            break;
    }
}

static sol::object json_decode_value(sol::state& lua, const char*& p, const char* end);

static void json_skip_ws(const char*& p, const char* end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        ++p;
}

static std::string json_decode_string(const char*& p, const char* end)
{
    if (p >= end || *p != '"') return {};
    ++p;
    std::string result;
    while (p < end && *p != '"')
    {
        if (*p == '\\' && p + 1 < end)
        {
            ++p;
            switch (*p)
            {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case '/':  result += '/';  break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                case 'u':
                {
                    if (p + 4 < end)
                    {
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i)
                        {
                            ++p;
                            cp <<= 4;
                            if (*p >= '0' && *p <= '9')      cp |= static_cast<unsigned>(*p - '0');
                            else if (*p >= 'a' && *p <= 'f') cp |= static_cast<unsigned>(*p - 'a' + 10);
                            else if (*p >= 'A' && *p <= 'F') cp |= static_cast<unsigned>(*p - 'A' + 10);
                        }
                        if (cp < 0x80)
                            result += static_cast<char>(cp);
                        else if (cp < 0x800)
                        {
                            result += static_cast<char>(0xC0 | (cp >> 6));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                        else
                        {
                            result += static_cast<char>(0xE0 | (cp >> 12));
                            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                    }
                    break;
                }
                default: result += *p; break;
            }
        }
        else
            result += *p;
        ++p;
    }
    if (p < end) ++p;
    return result;
}

static sol::object json_decode_value(sol::state& lua, const char*& p, const char* end)
{
    json_skip_ws(p, end);
    if (p >= end) return sol::nil;

    switch (*p)
    {
        case '"':
            return sol::make_object(lua, json_decode_string(p, end));
        case '{':
        {
            ++p;
            sol::table t = lua.create_table();
            json_skip_ws(p, end);
            if (p < end && *p == '}') { ++p; return t; }
            while (p < end)
            {
                json_skip_ws(p, end);
                auto key = json_decode_string(p, end);
                json_skip_ws(p, end);
                if (p < end && *p == ':') ++p;
                auto val = json_decode_value(lua, p, end);
                t[key] = val;
                json_skip_ws(p, end);
                if (p < end && *p == ',') ++p;
                else break;
            }
            if (p < end && *p == '}') ++p;
            return t;
        }
        case '[':
        {
            ++p;
            sol::table t = lua.create_table();
            json_skip_ws(p, end);
            if (p < end && *p == ']') { ++p; return t; }
            int idx = 1;
            while (p < end)
            {
                t[idx++] = json_decode_value(lua, p, end);
                json_skip_ws(p, end);
                if (p < end && *p == ',') ++p;
                else break;
            }
            if (p < end && *p == ']') ++p;
            return t;
        }
        case 't':
            if (end - p >= 4 && p[1] == 'r' && p[2] == 'u' && p[3] == 'e')
            { p += 4; return sol::make_object(lua, true); }
            return sol::nil;
        case 'f':
            if (end - p >= 5 && p[1] == 'a' && p[2] == 'l' && p[3] == 's' && p[4] == 'e')
            { p += 5; return sol::make_object(lua, false); }
            return sol::nil;
        case 'n':
            if (end - p >= 4 && p[1] == 'u' && p[2] == 'l' && p[3] == 'l')
            { p += 4; return sol::nil; }
            return sol::nil;
        default:
        {
            const char* start = p;
            if (*p == '-') ++p;
            while (p < end && *p >= '0' && *p <= '9') ++p;
            bool is_float = false;
            if (p < end && *p == '.')
            { is_float = true; ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }
            if (p < end && (*p == 'e' || *p == 'E'))
            { is_float = true; ++p; if (p < end && (*p == '+' || *p == '-')) ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }
            if (p == start) return sol::nil;

            if (is_float)
            {
                std::string num_str(start, static_cast<size_t>(p - start));
                double d = 0;
                try { d = std::stod(num_str); } catch (...) {}
                return sol::make_object(lua, d);
            }
            else
            {
                int64_t n = 0;
                std::from_chars(start, p, n);
                return sol::make_object(lua, static_cast<double>(n));
            }
        }
    }
}

void lua_context::register_bindings(runtime_instance* owner)
{
    // Register socketley.log() and management API
    sol::table sk = m_lua.create_table();
    sk["log"] = [](std::string msg) {
        std::cerr << "[lua] " << msg << std::endl;
    };

    // socketley.create(type, name, config_table) → bool
    sk["create"] = [owner](std::string type_str, std::string name, sol::optional<sol::table> config) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;

        runtime_type type;
        if (!parse_runtime_type(type_str, type)) return false;

        if (!mgr->create(type, name)) return false;

        auto* inst = mgr->get(name);
        if (!inst) return false;

        inst->set_runtime_manager(mgr);
        inst->set_event_loop(loop);
        inst->set_owner(owner->get_name());
        inst->set_lua_created(true);

        if (config) {
            sol::optional<int> port = (*config)["port"];
            if (port) inst->set_port(static_cast<uint16_t>(*port));

            sol::optional<std::string> lua_script = (*config)["config"];
            if (!lua_script) lua_script = (*config)["lua"];
            if (lua_script && !lua_script->empty())
                inst->load_lua_script(*lua_script);

            sol::optional<std::string> target = (*config)["target"];
            if (target) inst->set_target(*target);

            sol::optional<std::string> mode_str = (*config)["mode"];
            if (mode_str && type == runtime_server) {
                auto* srv = static_cast<server_instance*>(inst);
                switch (fnv1a(*mode_str)) {
                    case fnv1a("in"):     srv->set_mode(mode_in);     break;
                    case fnv1a("out"):    srv->set_mode(mode_out);    break;
                    case fnv1a("master"): srv->set_mode(mode_master); break;
                    default:              srv->set_mode(mode_inout);  break;
                }
            }

            if (type == runtime_server) {
                auto* srv = static_cast<server_instance*>(inst);
                sol::optional<std::string> http_dir = (*config)["http"];
                if (http_dir && !http_dir->empty())
                    srv->set_http_dir(*http_dir);
                sol::optional<bool> http_cache = (*config)["http_cache"];
                if (http_cache && *http_cache)
                    srv->set_http_cache(true);
            }

            sol::optional<std::string> group = (*config)["group"];
            if (group && !group->empty())
                inst->set_group(*group);

            sol::optional<std::string> on_stop_str = (*config)["on_parent_stop"];
            if (on_stop_str && fnv1a(*on_stop_str) == fnv1a("remove"))
                inst->set_child_policy(runtime_instance::child_policy::remove);

            sol::optional<bool> start = (*config)["start"];
            if (start && *start)
                mgr->start(name, *loop);
        }

        return true;
    };

    // socketley.start(name) → bool
    sk["start"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        return mgr->start(name, *loop);
    };

    // socketley.stop(name) → bool
    sk["stop"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        return mgr->stop(name, *loop);
    };

    // socketley.remove(name) → bool
    sk["remove"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        auto* inst = mgr->get(name);
        if (inst && inst->get_state() == runtime_running)
            mgr->stop(name, *loop);
        return mgr->remove(name);
    };

    // socketley.send(name, msg) → bool
    sk["send"] = [owner](std::string name, std::string msg) -> bool {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return false;
        auto* inst = mgr->get(name);
        if (!inst || inst->get_state() != runtime_running) return false;
        if (inst->get_type() == runtime_server)
            inst->lua_broadcast(msg);
        else
            inst->lua_send(msg);
        return true;
    };

    // socketley.list() → table of names
    sk["list"] = [owner, this]() -> sol::table {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return m_lua.create_table();
        std::shared_lock lock(mgr->mutex);
        auto& list = mgr->list();
        sol::table result = m_lua.create_table(static_cast<int>(list.size()), 0);
        int i = 1;
        for (const auto& [name, _] : list)
            result[i++] = name;
        return result;
    };

    // socketley.get(name) → table {name, type, state, port, connections, owner} or nil
    sk["get"] = [owner, this](std::string name) -> sol::object {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return sol::nil;
        auto* inst = mgr->get(name);
        if (!inst) return sol::nil;
        sol::table info = m_lua.create_table();
        info["name"] = std::string(inst->get_name());
        info["type"] = type_to_string(inst->get_type());
        info["state"] = state_to_string(inst->get_state());
        info["port"] = inst->get_port();
        info["connections"] = inst->get_connection_count();
        auto ow = inst->get_owner();
        info["owner"] = ow.empty() ? sol::object(sol::nil) : sol::make_object(m_lua, std::string(ow));
        return info;
    };

    sk["http"] = [this](sol::table opts) -> sol::table {
        return socketley_http_call(m_lua, opts);
    };

    // socketley.set_timeout(ms, fn) → timer_id
    sk["set_timeout"] = [this, owner](int ms, sol::function fn) -> int {
        auto* loop = owner->get_event_loop();
        if (!loop || ms <= 0) return 0;
        auto* t  = static_cast<lua_timer*>(timer_pool_acquire());
        t->alive  = m_alive;
        t->fn     = std::move(fn);
        t->loop   = loop;
        t->ctx    = this;
        t->ts     = { (long long)ms / 1000, ((long long)ms % 1000) * 1'000'000LL };
        t->req    = { t, nullptr, -1, 0, op_timeout };
        t->repeat = false;
        t->cancelled = false;
        int id = ++m_next_timer_id;
        t->timer_id = id;
        m_active_timers.push_back(t);
        m_timer_map[id] = t;
        loop->submit_timeout(&t->ts, &t->req);
        return id;
    };

    // socketley.set_interval(ms, fn) → timer_id
    sk["set_interval"] = [this, owner](int ms, sol::function fn) -> int {
        auto* loop = owner->get_event_loop();
        if (!loop || ms <= 0) return 0;
        auto* t  = static_cast<lua_timer*>(timer_pool_acquire());
        t->alive  = m_alive;
        t->fn     = std::move(fn);
        t->loop   = loop;
        t->ctx    = this;
        t->ts     = { (long long)ms / 1000, ((long long)ms % 1000) * 1'000'000LL };
        t->req    = { t, nullptr, -1, 0, op_timeout };
        t->repeat = true;
        t->cancelled = false;
        int id = ++m_next_timer_id;
        t->timer_id = id;
        m_active_timers.push_back(t);
        m_timer_map[id] = t;
        loop->submit_timeout(&t->ts, &t->req);
        return id;
    };

    // socketley.clear_timeout(id) — cancel a pending timeout
    sk["clear_timeout"] = [this](int id) {
        auto it = m_timer_map.find(id);
        if (it == m_timer_map.end()) return;
        auto* t = static_cast<lua_timer*>(it->second);
        t->cancelled = true;
        t->repeat = false;
    };

    // socketley.clear_interval(id) — cancel a repeating interval
    sk["clear_interval"] = [this](int id) {
        auto it = m_timer_map.find(id);
        if (it == m_timer_map.end()) return;
        auto* t = static_cast<lua_timer*>(it->second);
        t->cancelled = true;
        t->repeat = false;
    };

    // socketley.json_encode(value) → JSON string
    sk["json_encode"] = [](sol::object val) -> std::string {
        std::string out;
        out.reserve(256);
        json_encode_value(out, val);
        return out;
    };

    // socketley.json_decode(str) → Lua value
    sk["json_decode"] = [this](std::string str) -> sol::object {
        const char* p = str.data();
        const char* end = p + str.size();
        return json_decode_value(m_lua, p, end);
    };

    // socketley.subscribe(cache_name, channel, fn) — receive published messages
    sk["subscribe"] = [this](std::string cache_name, std::string channel, sol::function fn) {
        m_subscriptions[cache_name + '\0' + channel].push_back(std::move(fn));
    };

    // socketley.pipe(src_name, src_fd, dst_name, dst_fd) — cross-runtime zero-copy pipe
    sk["pipe"] = [owner](std::string src_name, int src_fd, std::string dst_name, int dst_fd) -> bool {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return false;
        // Same-runtime fast path
        if (src_name == dst_name && src_name == owner->get_name())
        {
            if (owner->get_type() != runtime_server) return false;
            static_cast<server_instance*>(owner)->lua_pipe(src_fd, dst_fd);
            return true;
        }
        // Cross-runtime: both must be servers
        auto* src_rt = mgr->get(src_name);
        auto* dst_rt = mgr->get(dst_name);
        if (!src_rt || !dst_rt) return false;
        if (src_rt->get_type() != runtime_server || dst_rt->get_type() != runtime_server) return false;
        // For cross-runtime, use route_client which already handles forwarding
        auto* src_srv = static_cast<server_instance*>(src_rt);
        return src_srv->route_client(src_fd, dst_name);
    };

    // ─── socketley.cluster.* — cluster introspection API ───
    sol::table cluster_tbl = m_lua.create_table();

    // socketley.cluster.daemons() → array of {name, host, runtimes}
    cluster_tbl["daemons"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local daemon entry
        {
            sol::table d = m_lua.create_table();
            d["name"] = std::string(cd->get_daemon_name());
            d["host"] = std::string(cd->get_cluster_addr());
            size_t count = 0;
            {
                std::shared_lock lock(mgr->mutex);
                count = mgr->list().size();
            }
            d["runtimes"] = static_cast<int>(count);
            result[i++] = d;
        }
        // Remote daemons
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            sol::table d = m_lua.create_table();
            d["name"] = rd.name;
            d["host"] = rd.host;
            d["runtimes"] = static_cast<int>(rd.runtimes.size());
            result[i++] = d;
        }
        return result;
    };

    // socketley.cluster.runtimes() → array of {daemon, name, type, port, group, state, connections}
    cluster_tbl["runtimes"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local runtimes
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [name, inst] : mgr->list())
            {
                sol::table r = m_lua.create_table();
                r["daemon"] = std::string(cd->get_daemon_name());
                r["name"] = std::string(name);
                r["type"] = type_to_string(inst->get_type());
                r["port"] = inst->get_port();
                r["group"] = std::string(inst->get_group());
                r["state"] = state_to_string(inst->get_state());
                r["connections"] = static_cast<int>(inst->get_connection_count());
                result[i++] = r;
            }
        }
        // Remote runtimes
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            for (const auto& rt : rd.runtimes)
            {
                sol::table r = m_lua.create_table();
                r["daemon"] = rt.daemon_name;
                r["name"] = rt.name;
                r["type"] = rt.type;
                r["port"] = rt.port;
                r["group"] = rt.group;
                r["state"] = rt.state;
                r["connections"] = static_cast<int>(rt.connections);
                result[i++] = r;
            }
        }
        return result;
    };

    // socketley.cluster.group(name) → array of {daemon, host, port, connections}
    cluster_tbl["group"] = [owner, this](std::string group_name) -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local group members
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [_, inst] : mgr->list())
            {
                if (inst->get_group() == group_name &&
                    inst->get_state() == runtime_running &&
                    inst->get_port() > 0)
                {
                    sol::table m = m_lua.create_table();
                    m["daemon"] = std::string(cd->get_daemon_name());
                    m["host"] = std::string(cd->get_cluster_addr());
                    m["port"] = inst->get_port();
                    m["connections"] = static_cast<int>(inst->get_connection_count());
                    result[i++] = m;
                }
            }
        }
        // Remote group members
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            for (const auto& rt : rd.runtimes)
            {
                if (rt.group == group_name && rt.state == "running" && rt.port > 0)
                {
                    sol::table m = m_lua.create_table();
                    m["daemon"] = rt.daemon_name;
                    m["host"] = rt.host;
                    m["port"] = rt.port;
                    m["connections"] = static_cast<int>(rt.connections);
                    result[i++] = m;
                }
            }
        }
        return result;
    };

    // socketley.cluster.stats() → {daemons, runtimes, running, groups={name=count}}
    cluster_tbl["stats"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int daemon_count = 1;  // include local
        int rt_total = 0;
        int rt_running = 0;
        std::unordered_map<std::string, int> groups;

        // Local runtimes
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [_, inst] : mgr->list())
            {
                ++rt_total;
                if (inst->get_state() == runtime_running) ++rt_running;
                auto g = inst->get_group();
                if (!g.empty()) ++groups[std::string(g)];
            }
        }

        // Remote daemons
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            ++daemon_count;
            for (const auto& rt : rd.runtimes)
            {
                ++rt_total;
                if (rt.state == "running") ++rt_running;
                if (!rt.group.empty()) ++groups[rt.group];
            }
        }

        result["daemons"] = daemon_count;
        result["runtimes"] = rt_total;
        result["running"] = rt_running;

        sol::table grp_tbl = m_lua.create_table();
        for (const auto& [name, count] : groups)
            grp_tbl[name] = count;
        result["groups"] = grp_tbl;

        return result;
    };

    sk["cluster"] = cluster_tbl;

    m_lua["socketley"] = sk;

    // Register "self" table with runtime properties and actions
    sol::table self = m_lua.create_table();
    self["name"] = std::string(owner->get_name());
    self["port"] = owner->get_port();
    self["type"] = type_to_string(owner->get_type());
    self["state"] = state_to_string(owner->get_state());

    // Register type-specific action methods
    switch (owner->get_type())
    {
        case runtime_server:
            register_server_table(owner, self);
            break;
        case runtime_client:
            register_client_table(owner, self);
            break;
        case runtime_cache:
            register_cache_table(owner, self);
            break;
        case runtime_proxy:
            register_proxy_table(owner, self);
            break;
    }

    m_lua["self"] = self;

    // Also register type-specific alias (server/client/cache/proxy) pointing to same table
    m_lua[type_to_string(owner->get_type())] = self;
}

void lua_context::register_server_table(runtime_instance* owner, sol::table& self)
{
    self["broadcast"] = [owner](std::string msg) {
        owner->lua_broadcast(msg);
    };
    self["send"] = [owner](int client_id, std::string msg) {
        owner->lua_send_to(client_id, msg);
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";

    // Client routing
    self["route"] = [owner](int client_id, std::string target) -> bool {
        return static_cast<server_instance*>(owner)->route_client(client_id, target);
    };
    self["unroute"] = [owner](int client_id) -> bool {
        return static_cast<server_instance*>(owner)->unroute_client(client_id);
    };
    self["get_route"] = [owner, this](int client_id) -> sol::object {
        auto route = static_cast<server_instance*>(owner)->get_client_route(client_id);
        if (route.empty()) return sol::nil;
        return sol::make_object(m_lua, std::string(route));
    };

    // Owner-targeted sending (sub-server → owner's clients)
    self["owner_send"] = [owner](int client_id, std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_send(client_id, msg);
    };
    self["owner_broadcast"] = [owner](std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_broadcast(msg);
    };

    // Connection control
    self["disconnect"] = [owner](int client_id) {
        static_cast<server_instance*>(owner)->lua_disconnect(client_id);
    };
    self["peer_ip"] = [owner](int client_id) -> std::string {
        return static_cast<server_instance*>(owner)->lua_peer_ip(client_id);
    };
    self["ws_headers"] = [owner, this](int client_id) -> sol::object {
        auto h = static_cast<server_instance*>(owner)->lua_ws_headers(client_id);
        if (!h.is_websocket) return sol::nil;
        sol::table t = m_lua.create_table();
        if (!h.cookie.empty())   t["cookie"]        = h.cookie;
        if (!h.origin.empty())   t["origin"]        = h.origin;
        if (!h.protocol.empty()) t["protocol"]      = h.protocol;
        if (!h.auth.empty())     t["authorization"] = h.auth;
        return t;
    };

    // Client enumeration
    self["clients"] = [owner, this]() -> sol::table {
        auto ids = static_cast<server_instance*>(owner)->lua_clients();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };

    // Targeted multicast to a subset of clients
    self["multicast"] = [owner](sol::table ids, std::string msg) {
        std::vector<int> fds;
        ids.for_each([&](sol::object, sol::object v) {
            if (v.is<int>()) fds.push_back(v.as<int>());
        });
        static_cast<server_instance*>(owner)->lua_multicast(fds, msg);
    };

    // Per-connection metadata: nil value deletes the key
    self["set_data"] = [owner](int id, std::string key, sol::optional<std::string> val) {
        if (val)
            static_cast<server_instance*>(owner)->lua_set_data(id, key, *val);
        else
            static_cast<server_instance*>(owner)->lua_del_data(id, key);
    };
    self["get_data"] = [owner, this](int id, std::string key) -> sol::object {
        auto v = static_cast<server_instance*>(owner)->lua_get_data(id, key);
        if (v.empty()) return sol::nil;
        return sol::make_object(m_lua, v);
    };

    // Upstream actions
    self["upstream_send"] = [owner](int conn_id, std::string msg) {
        static_cast<server_instance*>(owner)->lua_upstream_send(conn_id, msg);
    };
    self["upstream_broadcast"] = [owner](std::string msg) {
        static_cast<server_instance*>(owner)->lua_upstream_broadcast(msg);
    };
    self["upstreams"] = [owner, this]() -> sol::table {
        auto ids = static_cast<server_instance*>(owner)->lua_upstreams();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };

    // Multicast groups
    self["join_group"] = [owner](int fd, std::string group) {
        static_cast<server_instance*>(owner)->lua_join_group(fd, group);
    };
    self["leave_group"] = [owner](int fd, std::string group) {
        static_cast<server_instance*>(owner)->lua_leave_group(fd, group);
    };
    self["group_send"] = [owner](std::string group, std::string msg) {
        static_cast<server_instance*>(owner)->lua_group_send(group, msg);
    };

    // Zero-copy pipe pairing
    self["pipe"] = [owner](int fd_a, int fd_b) {
        static_cast<server_instance*>(owner)->lua_pipe(fd_a, fd_b);
    };
    self["unpipe"] = [owner](int fd) {
        static_cast<server_instance*>(owner)->lua_unpipe(fd);
    };
}

void lua_context::register_client_table(runtime_instance* owner, sol::table& self)
{
    self["send"] = [owner](std::string msg) {
        owner->lua_send(msg);
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";
}

void lua_context::register_cache_table(runtime_instance* owner, sol::table& self)
{
    // Strings
    self["get"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_get(key);
    };
    self["set"] = [owner](std::string key, std::string value) -> bool {
        return owner->lua_cache_set(key, value);
    };
    self["del"] = [owner](std::string key) -> bool {
        return owner->lua_cache_del(key);
    };

    // Lists
    self["lpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_lpush(key, val);
    };
    self["rpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_rpush(key, val);
    };
    self["lpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_lpop(key);
    };
    self["rpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_rpop(key);
    };
    self["llen"] = [owner](std::string key) -> int {
        return owner->lua_cache_llen(key);
    };

    // Sets
    self["sadd"] = [owner](std::string key, std::string member) -> int {
        return owner->lua_cache_sadd(key, member);
    };
    self["srem"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_srem(key, member);
    };
    self["sismember"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_sismember(key, member);
    };
    self["scard"] = [owner](std::string key) -> int {
        return owner->lua_cache_scard(key);
    };

    // Hashes
    self["hset"] = [owner](std::string key, std::string field, std::string val) -> bool {
        return owner->lua_cache_hset(key, field, val);
    };
    self["hget"] = [owner](std::string key, std::string field) -> std::string {
        return owner->lua_cache_hget(key, field);
    };
    self["hdel"] = [owner](std::string key, std::string field) -> bool {
        return owner->lua_cache_hdel(key, field);
    };
    self["hlen"] = [owner](std::string key) -> int {
        return owner->lua_cache_hlen(key);
    };

    // TTL
    self["expire"] = [owner](std::string key, int seconds) -> bool {
        return owner->lua_cache_expire(key, seconds);
    };
    self["ttl"] = [owner](std::string key) -> int {
        return owner->lua_cache_ttl(key);
    };
    self["persist"] = [owner](std::string key) -> bool {
        return owner->lua_cache_persist(key);
    };

    // Pub/Sub
    self["publish"] = [owner](std::string channel, std::string message) -> int {
        return owner->lua_cache_publish(channel, message);
    };

    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
}

void lua_context::register_proxy_table(runtime_instance* owner, sol::table& self)
{
    auto* proxy = static_cast<proxy_instance*>(owner);

    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = proxy->get_protocol() == protocol_http ? "http" : "tcp";
    self["peer_ip"] = [proxy](int client_id) -> std::string {
        return proxy->lua_peer_ip(client_id);
    };
    self["close_client"] = [proxy](int client_id) {
        proxy->lua_close_client(client_id);
    };
    self["clients"] = [proxy, this]() -> sol::table {
        auto ids = proxy->lua_clients();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };
    self["backends"] = [proxy, this]() -> sol::table {
        auto addrs = proxy->lua_backends();
        sol::table t = m_lua.create_table(static_cast<int>(addrs.size()), 0);
        for (int i = 0; i < (int)addrs.size(); ++i) t[i + 1] = addrs[i];
        return t;
    };
    self["backend_health"] = [proxy, this]() -> sol::table {
        auto health = proxy->lua_backend_health();
        sol::table t = m_lua.create_table(0, static_cast<int>(health.size()));
        for (const auto& [idx, state] : health)
            t[idx + 1] = state;
        return t;
    };
    self["stats"] = [proxy, this]() -> sol::table {
        sol::table t = m_lua.create_table(0, 6);
        t["connections"] = proxy->get_connection_count();
        t["bytes_in"] = proxy->m_stat_bytes_in.load(std::memory_order_relaxed);
        t["bytes_out"] = proxy->m_stat_bytes_out.load(std::memory_order_relaxed);
        t["total_connections"] = proxy->m_stat_total_connections.load(std::memory_order_relaxed);
        t["total_messages"] = proxy->m_stat_total_messages.load(std::memory_order_relaxed);
        auto addrs = proxy->lua_backends();
        t["backend_count"] = addrs.size();
        return t;
    };
}

#endif // SOCKETLEY_NO_LUA
