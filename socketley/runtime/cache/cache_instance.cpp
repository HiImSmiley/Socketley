#include "cache_instance.h"
#include "resp_parser.h"
#include "../../shared/event_loop.h"
#include "../../shared/lua_context.h"
#include "../../cli/command_hashing.h"

#include <unistd.h>
#include <cstring>
#include <charconv>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <liburing.h>
#include <sstream>
#include <sys/stat.h>

cache_instance::cache_instance(std::string_view name)
    : runtime_instance(runtime_cache, name), m_listen_fd(-1), m_loop(nullptr)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req = { op_accept, -1, nullptr, 0, this };
}

cache_instance::~cache_instance()
{
    if (m_listen_fd >= 0)
        close(m_listen_fd);
}

void cache_instance::set_persistent(std::string_view path)
{
    // Validate parent directory exists
    std::string p(path);
    auto slash = p.rfind('/');
    if (slash != std::string::npos && slash > 0)
    {
        std::string parent = p.substr(0, slash);
        struct stat st;
        if (stat(parent.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))
            return; // Silent reject — parent dir doesn't exist
    }
    m_persistent_path = path;
}

std::string_view cache_instance::get_persistent() const
{
    return m_persistent_path;
}

void cache_instance::set_mode(cache_mode mode)
{
    m_mode = mode;
}

cache_mode cache_instance::get_mode() const
{
    return m_mode;
}

size_t cache_instance::get_connection_count() const
{
    return m_clients.size();
}

bool cache_instance::setup(event_loop& loop)
{
    // Clear connections from a previous stop() — safe to free now.
    m_clients.clear();

    m_loop = &loop;

    uint16_t port = get_port();
    if (port == 0)
        port = 9000;

    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (m_listen_fd < 0)
        return false;

    int opt = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(m_listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (listen(m_listen_fd, 4096) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (!m_persistent_path.empty())
        m_store.load(m_persistent_path);

    // Connect to master if follower
    if (m_repl_role == repl_follower && !m_replicate_target.empty())
        connect_to_master();

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);

    if (event_loop::supports_multishot_accept())
    {
        m_accept_req.type = op_multishot_accept;
        loop.submit_multishot_accept(m_listen_fd, &m_accept_req);
        m_multishot_active = true;
    }
    else
    {
        m_accept_req.type = op_accept;
        loop.submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
        m_multishot_active = false;
    }

    // Start periodic TTL sweep (100 ms)
    m_ttl_ts = {0, 100'000'000};
    m_ttl_req = {op_timeout, -1, nullptr, 0, this};
    loop.submit_timeout(&m_ttl_ts, &m_ttl_req);

    return true;
}

void cache_instance::teardown(event_loop& loop)
{
    if (!m_persistent_path.empty())
        m_store.save(m_persistent_path);

    // Shutdown the listen socket before closing — forces the pending multishot
    // accept CQE to complete synchronously, before the deferred-delete timeout.
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close(m_listen_fd);
        m_listen_fd = -1;
    }

    // Drain: flush pending write queues with blocking writes
    if (get_drain())
    {
        for (auto& [fd, conn] : m_clients)
        {
            // Flush response_buf first
            if (!conn->response_buf.empty())
                if (::write(fd, conn->response_buf.data(), conn->response_buf.size()) < 0) break;
            while (!conn->write_queue.empty())
            {
                auto& msg = conn->write_queue.front();
                if (::write(fd, msg.data(), msg.size()) < 0) break;
                conn->write_queue.pop();
            }
        }
    }

    for (auto& [fd, conn] : m_clients)
    {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
    // Do NOT clear m_clients here — connection objects must stay alive until the
    // deferred-delete timeout fires and all pending CQEs have been processed.

    // Close replication connections
    if (m_master_fd >= 0)
    {
        shutdown(m_master_fd, SHUT_RDWR);
        close(m_master_fd);
        m_master_fd = -1;
    }
    for (int fd : m_follower_fds)
    {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
    m_follower_fds.clear();

    m_ttl_req.owner = nullptr;
    m_loop = nullptr;
    m_multishot_active = false;
}

void cache_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req || !m_loop)
        return;

    // Periodic TTL sweep timer
    if (req == &m_ttl_req)
    {
        m_store.sweep_expired();
        m_loop->submit_timeout(&m_ttl_ts, &m_ttl_req);
        return;
    }

    // Check if this is a read from master (replication)
    if (req->fd == m_master_fd && m_master_fd >= 0 &&
        (req->type == op_read || req->type == op_read_provided))
    {
        handle_master_read(cqe);
        return;
    }

    switch (req->type)
    {
        case op_accept:
        case op_multishot_accept:
            handle_accept(cqe);
            break;
        case op_read:
        case op_read_provided:
            handle_read(cqe, req);
            break;
        case op_write:
        case op_writev:
            handle_write(cqe, req);
            break;
        default:
            break;
    }
}

void cache_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    if (client_fd >= 0)
    {
        if (get_max_connections() > 0 && m_clients.size() >= get_max_connections())
        {
            close(client_fd);
            goto cache_resubmit_accept;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);

        auto conn = std::make_unique<client_connection>();
        conn->fd = client_fd;
        conn->partial.reserve(4096);
        conn->response_buf.reserve(4096);
        conn->read_req = { op_read, client_fd, conn->read_buf, sizeof(conn->read_buf), this };
        conn->write_req = { op_write, client_fd, nullptr, 0, this };

        auto* ptr = conn.get();
        m_clients[client_fd] = std::move(conn);
        if (client_fd < MAX_FDS)
            m_conn_idx[client_fd] = ptr;

        // Initialize rate limiting
        double rl = get_rate_limit();
        if (rl > 0)
        {
            ptr->rl_max = rl;
            ptr->rl_tokens = rl;
            ptr->rl_last = std::chrono::steady_clock::now();
        }

        ptr->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(client_fd, BUF_GROUP_ID, &ptr->read_req);
        else
            m_loop->submit_read(client_fd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);
    }

cache_resubmit_accept:
    if (m_multishot_active)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            if (m_listen_fd >= 0)
                m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
        }
    }
    else
    {
        if (m_listen_fd >= 0)
        {
            m_accept_addrlen = sizeof(m_accept_addr);
            m_loop->submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
        }
    }
}

void cache_instance::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
        return;
    auto* conn = m_conn_idx[fd];
    conn->read_pending = false;

    bool is_provided = (req->type == op_read_provided);

    if (cqe->res <= 0)
    {
        // Return provided buffer if kernel allocated one before error
        if (is_provided && (cqe->flags & IORING_CQE_F_BUFFER))
        {
            uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }

        // ENOBUFS: buffer pool exhausted — fall back to regular read
        if (is_provided && cqe->res == -ENOBUFS)
        {
            conn->read_pending = true;
            m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
            return;
        }

        // Connection closed or error — defer if write pending
        m_store.unsubscribe_all(fd);
        if (conn->write_pending)
        {
            conn->closing = true;
        }
        else
        {
            close(fd);
            if (fd < MAX_FDS) m_conn_idx[fd] = nullptr;
            m_clients.erase(fd);
        }
        return;
    }

    if (is_provided)
    {
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (buf_ptr)
        {
            conn->partial.append(buf_ptr, cqe->res);
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
    }
    else
    {
        conn->partial.append(conn->read_buf, cqe->res);
    }

    // Auto-detect RESP mode on first data
    if (!conn->resp_detected && !conn->partial.empty())
    {
        conn->resp_detected = true;
        if (conn->partial[0] == '*' || m_resp_forced)
            conn->resp_mode = true;
    }

    if (conn->resp_mode)
    {
        process_resp(conn);
    }
    else
    {
        size_t scan_from = 0;
        size_t pos;
        while ((pos = conn->partial.find('\n', scan_from)) != std::string::npos)
        {
            std::string_view line(conn->partial.data() + scan_from, pos - scan_from);

            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);

            process_command(conn, line);

            scan_from = pos + 1;
        }

        if (scan_from > 0)
        {
            if (scan_from >= conn->partial.size())
                conn->partial.clear();
            else
                conn->partial.erase(0, scan_from);
        }
    }

    // Flush accumulated responses as single write
    flush_responses(conn);

    if (m_loop && !conn->closing)
    {
        conn->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
        else
            m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
    }
}

void cache_instance::handle_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
        return;
    auto* conn = m_conn_idx[fd];
    conn->write_pending = false;

    // Release batch buffers
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i] = {};
    conn->write_batch_count = 0;

    if (cqe->res <= 0)
    {
        conn->closing = true;
        if (!conn->read_pending)
        {
            close(fd);
            if (fd < MAX_FDS) m_conn_idx[fd] = nullptr;
            m_clients.erase(fd);
        }
        return;
    }

    // Flush remaining queued messages
    if (!conn->write_queue.empty())
    {
        flush_write_queue(conn);
    }
    else
    {
        if (conn->closing && !conn->read_pending)
        {
            close(fd);
            if (fd < MAX_FDS) m_conn_idx[fd] = nullptr;
            m_clients.erase(fd);
        }
    }
}

// ─── Helper: parse int from string_view ───

static bool parse_int_sv(std::string_view sv, int& out)
{
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
    return ec == std::errc{} && ptr == sv.data() + sv.size();
}

std::string cache_instance::execute(std::string_view line)
{
    client_connection dummy{};
    dummy.fd = -1;
    dummy.rl_max = 0;
    process_command(&dummy, line);
    return std::move(dummy.response_buf);
}

// Zero-allocation integer append for text-mode responses
static inline void append_int_nl(std::string& buf, int64_t v)
{
    char tmp[24];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), v);
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.push_back('\n');
}

void cache_instance::process_command(client_connection* conn, std::string_view line)
{
    if (line.empty())
        return;

    // Rate limit check
    if (conn->rl_max > 0)
    {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - conn->rl_last).count();
        conn->rl_last = now;
        conn->rl_tokens += elapsed * conn->rl_max;
        if (conn->rl_tokens > conn->rl_max)
            conn->rl_tokens = conn->rl_max;
        if (conn->rl_tokens < 1.0)
        {
            conn->response_buf.append("error: rate limited\n", 20);
            return;
        }
        conn->rl_tokens -= 1.0;
    }

    m_stat_commands++;
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);

    size_t first_space = line.find(' ');
    std::string_view cmd = (first_space != std::string_view::npos)
        ? line.substr(0, first_space) : line;

    std::string_view args = (first_space != std::string_view::npos)
        ? line.substr(first_space + 1) : std::string_view{};

    auto& rb = conn->response_buf;

    // Extract key from args (up to first space)
    auto extract_key = [](std::string_view a) -> std::pair<std::string_view, std::string_view> {
        size_t sp = a.find(' ');
        if (sp == std::string_view::npos)
            return {a, {}};
        return {a.substr(0, sp), a.substr(sp + 1)};
    };

    switch (fnv1a_lower(cmd))
    {
        // ─── Strings ───

        case fnv1a("set"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            size_t space = args.find(' ');
            if (space == std::string_view::npos)
            {
                rb.append("usage: set key value\n", 21);
                return;
            }
            auto key = args.substr(0, space);
            m_store.check_expiry(key);
            if (!m_store.set(key, args.substr(space + 1)))
                rb.append("error: type conflict\n", 21);
            else
            {
                rb.append("ok\n", 3);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("get"):
        {
            m_store.check_expiry(args);
            const std::string* val = m_store.get_ptr(args);
            if (val)
            {
                m_stat_get_hits++;
                rb.append(*val);
                rb.push_back('\n');
            }
            else
            {
                m_stat_get_misses++;
                rb.append("nil\n", 4);
            }
            break;
        }
        case fnv1a("del"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            m_store.check_expiry(args);
            if (m_store.del(args))
            {
                rb.append("ok\n", 3);
                replicate_command(line);
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("exists"):
        {
            m_store.check_expiry(args);
            rb.append(m_store.exists(args) ? "1\n" : "0\n");
            break;
        }
        case fnv1a("incr"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            if (args.empty()) { rb.append("usage: incr key\n", 17); return; }
            int64_t result = 0;
            if (!m_store.incr(args, 1, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("decr"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            if (args.empty()) { rb.append("usage: decr key\n", 17); return; }
            int64_t result = 0;
            if (!m_store.incr(args, -1, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("incrby"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, delta_str] = extract_key(args);
            if (key.empty() || delta_str.empty()) { rb.append("usage: incrby key delta\n", 24); return; }
            int64_t delta = 0;
            auto [p, e] = std::from_chars(delta_str.data(), delta_str.data() + delta_str.size(), delta);
            if (e != std::errc{}) { rb.append("error: invalid delta\n", 21); return; }
            int64_t result = 0;
            if (!m_store.incr(key, delta, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("decrby"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, delta_str] = extract_key(args);
            if (key.empty() || delta_str.empty()) { rb.append("usage: decrby key delta\n", 24); return; }
            int64_t delta = 0;
            auto [p2, e2] = std::from_chars(delta_str.data(), delta_str.data() + delta_str.size(), delta);
            if (e2 != std::errc{}) { rb.append("error: invalid delta\n", 21); return; }
            int64_t result = 0;
            if (!m_store.incr(key, -delta, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("append"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, suffix] = extract_key(args);
            if (key.empty() || suffix.empty()) { rb.append("usage: append key value\n", 24); return; }
            size_t newlen = m_store.append(key, suffix);
            if (newlen == std::string::npos)
                rb.append("error: type conflict\n", 21);
            else
            {
                append_int_nl(rb, static_cast<int64_t>(newlen));
                replicate_command(line);
            }
            break;
        }
        case fnv1a("strlen"):
        {
            m_store.check_expiry(args);
            append_int_nl(rb, static_cast<int64_t>(m_store.strlen_key(args)));
            break;
        }
        case fnv1a("getset"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, newval] = extract_key(args);
            if (key.empty() || newval.empty()) { rb.append("usage: getset key newvalue\n", 27); return; }
            m_store.check_expiry(key);
            bool had_key = m_store.exists(key);
            std::string oldval;
            if (!m_store.getset(key, newval, oldval))
                rb.append("error: type conflict\n", 21);
            else
            {
                if (had_key) { rb.append(oldval); rb.push_back('\n'); }
                else rb.append("nil\n", 4);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("mget"):
        {
            // MGET key1 key2 ... → one value per line (nil if missing), then "end\n"
            std::string_view rest = args;
            while (!rest.empty())
            {
                size_t sp = rest.find(' ');
                std::string_view key = (sp == std::string_view::npos) ? rest : rest.substr(0, sp);
                m_store.check_expiry(key);
                const std::string* val = m_store.get_ptr(key);
                if (val) { rb.append(*val); rb.push_back('\n'); }
                else rb.append("nil\n", 4);
                if (sp == std::string_view::npos) break;
                rest = rest.substr(sp + 1);
            }
            rb.append("end\n", 4);
            break;
        }
        case fnv1a("mset"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            // MSET key1 val1 key2 val2 ...
            std::string_view rest = args;
            while (!rest.empty())
            {
                size_t sp1 = rest.find(' ');
                if (sp1 == std::string_view::npos) break;
                std::string_view key = rest.substr(0, sp1);
                rest = rest.substr(sp1 + 1);
                size_t sp2 = rest.find(' ');
                std::string_view val = (sp2 == std::string_view::npos) ? rest : rest.substr(0, sp2);
                m_store.check_expiry(key);
                m_store.set(key, val);
                if (sp2 == std::string_view::npos) break;
                rest = rest.substr(sp2 + 1);
            }
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("type"):
        {
            m_store.check_expiry(args);
            rb.append(m_store.type(args));
            rb.push_back('\n');
            break;
        }
        case fnv1a("keys"):
        {
            std::string_view pattern = args.empty() ? std::string_view("*") : args;
            std::vector<std::string_view> result;
            m_store.keys(pattern, result);
            for (auto& k : result) { rb.append(k); rb.push_back('\n'); }
            rb.append("end\n", 4);
            break;
        }

        // ─── Lists ───

        case fnv1a("lpush"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, val] = extract_key(args);
            if (key.empty() || val.empty())
            {
                rb.append("usage: lpush key value\n", 23);
                return;
            }
            m_store.check_expiry(key);
            if (!m_store.lpush(key, val))
                rb.append("error: type conflict\n", 21);
            else
            {
                rb.append("ok\n", 3);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("rpush"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, val] = extract_key(args);
            if (key.empty() || val.empty())
            {
                rb.append("usage: rpush key value\n", 23);
                return;
            }
            m_store.check_expiry(key);
            if (!m_store.rpush(key, val))
                rb.append("error: type conflict\n", 21);
            else
            {
                rb.append("ok\n", 3);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("lpop"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            m_store.check_expiry(args);
            std::string val;
            if (m_store.lpop(args, val))
            {
                rb.append(val);
                rb.push_back('\n');
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("rpop"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            m_store.check_expiry(args);
            std::string val;
            if (m_store.rpop(args, val))
            {
                rb.append(val);
                rb.push_back('\n');
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("llen"):
        {
            m_store.check_expiry(args);
            append_int_nl(rb, m_store.llen(args));
            break;
        }
        case fnv1a("lindex"):
        {
            auto [key, idx_str] = extract_key(args);
            if (key.empty() || idx_str.empty())
            {
                rb.append("usage: lindex key index\n", 24);
                return;
            }
            m_store.check_expiry(key);
            int idx;
            if (!parse_int_sv(idx_str, idx))
            {
                rb.append("error: invalid index\n", 21);
                return;
            }
            const std::string* val = m_store.lindex(key, idx);
            if (val)
            {
                rb.append(*val);
                rb.push_back('\n');
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("lrange"):
        {
            auto [key, rest] = extract_key(args);
            if (key.empty() || rest.empty())
            {
                rb.append("usage: lrange key start stop\n", 29);
                return;
            }
            auto [start_str, stop_str] = extract_key(rest);
            if (start_str.empty() || stop_str.empty())
            {
                rb.append("usage: lrange key start stop\n", 29);
                return;
            }
            m_store.check_expiry(key);
            int start, stop;
            if (!parse_int_sv(start_str, start) || !parse_int_sv(stop_str, stop))
            {
                rb.append("error: invalid index\n", 21);
                return;
            }
            const auto* deq = m_store.list_ptr(key);
            if (!deq || deq->empty())
            {
                rb.append("end\n", 4);
                return;
            }
            int len = static_cast<int>(deq->size());
            if (start < 0) start += len;
            if (stop < 0) stop += len;
            if (start < 0) start = 0;
            if (stop >= len) stop = len - 1;
            for (int i = start; i <= stop; i++)
            {
                rb.append((*deq)[static_cast<size_t>(i)]);
                rb.push_back('\n');
            }
            rb.append("end\n", 4);
            break;
        }

        // ─── Sets ───

        case fnv1a("sadd"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            {
                rb.append("usage: sadd key member\n", 23);
                return;
            }
            m_store.check_expiry(key);
            int result = m_store.sadd(key, member);
            if (result < 0)
                rb.append("error: type conflict\n", 21);
            else if (result == 0)
                rb.append("exists\n", 7);
            else
            {
                rb.append("ok\n", 3);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("srem"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            {
                rb.append("usage: srem key member\n", 23);
                return;
            }
            m_store.check_expiry(key);
            rb.append(m_store.srem(key, member) ? "ok\n" : "nil\n");
            break;
        }
        case fnv1a("sismember"):
        {
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            {
                rb.append("usage: sismember key member\n", 28);
                return;
            }
            m_store.check_expiry(key);
            rb.append(m_store.sismember(key, member) ? "1\n" : "0\n");
            break;
        }
        case fnv1a("scard"):
        {
            m_store.check_expiry(args);
            append_int_nl(rb, m_store.scard(args));
            break;
        }
        case fnv1a("smembers"):
        {
            m_store.check_expiry(args);
            const auto* s = m_store.set_ptr(args);
            if (!s || s->empty())
            {
                rb.append("end\n", 4);
                return;
            }
            for (const auto& member : *s)
            {
                rb.append(member);
                rb.push_back('\n');
            }
            rb.append("end\n", 4);
            break;
        }

        // ─── Hashes ───

        case fnv1a("hset"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, rest] = extract_key(args);
            if (key.empty() || rest.empty())
            {
                rb.append("usage: hset key field value\n", 28);
                return;
            }
            auto [field, val] = extract_key(rest);
            if (field.empty() || val.empty())
            {
                rb.append("usage: hset key field value\n", 28);
                return;
            }
            m_store.check_expiry(key);
            if (!m_store.hset(key, field, val))
                rb.append("error: type conflict\n", 21);
            else
            {
                rb.append("ok\n", 3);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("hget"):
        {
            auto [key, field] = extract_key(args);
            if (key.empty() || field.empty())
            {
                rb.append("usage: hget key field\n", 22);
                return;
            }
            m_store.check_expiry(key);
            const std::string* val = m_store.hget(key, field);
            if (val)
            {
                rb.append(*val);
                rb.push_back('\n');
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("hdel"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, field] = extract_key(args);
            if (key.empty() || field.empty())
            {
                rb.append("usage: hdel key field\n", 22);
                return;
            }
            m_store.check_expiry(key);
            rb.append(m_store.hdel(key, field) ? "ok\n" : "nil\n");
            break;
        }
        case fnv1a("hlen"):
        {
            m_store.check_expiry(args);
            append_int_nl(rb, m_store.hlen(args));
            break;
        }
        case fnv1a("hgetall"):
        {
            m_store.check_expiry(args);
            const auto* h = m_store.hash_ptr(args);
            if (!h || h->empty())
            {
                rb.append("end\n", 4);
                return;
            }
            for (const auto& [field, val] : *h)
            {
                rb.append(field);
                rb.push_back(' ');
                rb.append(val);
                rb.push_back('\n');
            }
            rb.append("end\n", 4);
            break;
        }

        // ─── TTL / Expiry ───

        case fnv1a("expire"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, sec_str] = extract_key(args);
            if (key.empty() || sec_str.empty())
            {
                rb.append("usage: expire key seconds\n", 26);
                return;
            }
            int seconds;
            if (!parse_int_sv(sec_str, seconds) || seconds <= 0)
            {
                rb.append("error: invalid seconds\n", 23);
                return;
            }
            rb.append(m_store.set_expiry(key, seconds) ? "ok\n" : "nil\n");
            break;
        }
        case fnv1a("ttl"):
        {
            m_store.check_expiry(args);
            int ttl = m_store.get_ttl(args);
            append_int_nl(rb, ttl);
            break;
        }
        case fnv1a("persist"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            rb.append(m_store.persist(args) ? "ok\n" : "nil\n");
            break;
        }
        case fnv1a("setnx"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, val] = extract_key(args);
            if (key.empty() || val.empty()) { rb.append("usage: setnx key value\n", 23); return; }
            bool did_set = m_store.setnx(key, val);
            rb.append(did_set ? "1\n" : "0\n");
            if (did_set) replicate_command(line);
            break;
        }
        case fnv1a("setex"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, rest] = extract_key(args);
            auto [sec_str, val] = extract_key(rest);
            if (key.empty() || sec_str.empty() || val.empty()) { rb.append("usage: setex key seconds value\n", 31); return; }
            int sec = 0;
            if (!parse_int_sv(sec_str, sec) || sec <= 0) { rb.append("error: invalid seconds\n", 23); return; }
            m_store.check_expiry(key);
            if (!m_store.set(key, val)) { rb.append("error: type conflict\n", 21); return; }
            m_store.set_expiry(key, sec);
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("psetex"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, rest] = extract_key(args);
            auto [ms_str, val] = extract_key(rest);
            if (key.empty() || ms_str.empty() || val.empty()) { rb.append("usage: psetex key milliseconds value\n", 37); return; }
            int64_t ms = 0;
            {
                auto [p, e] = std::from_chars(ms_str.data(), ms_str.data() + ms_str.size(), ms);
                if (e != std::errc{} || ms <= 0) { rb.append("error: invalid milliseconds\n", 28); return; }
            }
            m_store.check_expiry(key);
            if (!m_store.set(key, val)) { rb.append("error: type conflict\n", 21); return; }
            m_store.set_expiry_ms(key, ms);
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("pexpire"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ms_str] = extract_key(args);
            if (key.empty() || ms_str.empty()) { rb.append("usage: pexpire key ms\n", 22); return; }
            int64_t ms = 0;
            {
                auto [p, e] = std::from_chars(ms_str.data(), ms_str.data() + ms_str.size(), ms);
                if (e != std::errc{} || ms <= 0) { rb.append("error: invalid ms\n", 18); return; }
            }
            rb.append(m_store.set_expiry_ms(key, ms) ? "1\n" : "0\n");
            break;
        }
        case fnv1a("pttl"):
        {
            m_store.check_expiry(args);
            append_int_nl(rb, m_store.get_pttl(args));
            break;
        }
        case fnv1a("expireat"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ts_str] = extract_key(args);
            if (key.empty() || ts_str.empty()) { rb.append("usage: expireat key unix_seconds\n", 33); return; }
            int64_t unix_s = 0;
            {
                auto [p, e] = std::from_chars(ts_str.data(), ts_str.data() + ts_str.size(), unix_s);
                if (e != std::errc{}) { rb.append("error: invalid timestamp\n", 25); return; }
            }
            {
                int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining = unix_s - now_s;
                if (remaining <= 0) { m_store.del(key); rb.append("1\n", 2); }
                else rb.append(m_store.set_expiry(key, static_cast<int>(remaining)) ? "1\n" : "0\n");
            }
            break;
        }
        case fnv1a("pexpireat"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ts_str] = extract_key(args);
            if (key.empty() || ts_str.empty()) { rb.append("usage: pexpireat key unix_ms\n", 29); return; }
            int64_t unix_ms = 0;
            {
                auto [p, e] = std::from_chars(ts_str.data(), ts_str.data() + ts_str.size(), unix_ms);
                if (e != std::errc{}) { rb.append("error: invalid timestamp\n", 25); return; }
            }
            {
                int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining_ms = unix_ms - now_ms;
                if (remaining_ms <= 0) { m_store.del(key); rb.append("1\n", 2); }
                else rb.append(m_store.set_expiry_ms(key, remaining_ms) ? "1\n" : "0\n");
            }
            break;
        }
        case fnv1a("scan"):
        {
            // scan cursor [match pattern] [count n]
            size_t sp0 = args.find(' ');
            std::string_view cursor_str = (sp0 == std::string_view::npos) ? args : args.substr(0, sp0);
            std::string_view rest2 = (sp0 == std::string_view::npos) ? std::string_view{} : args.substr(sp0 + 1);
            uint64_t scan_cursor = 0;
            {
                auto [p, e] = std::from_chars(cursor_str.data(), cursor_str.data() + cursor_str.size(), scan_cursor);
                if (e != std::errc{}) { rb.append("error: invalid cursor\n", 22); return; }
            }
            std::string_view scan_pattern = "*";
            size_t scan_count = 10;
            while (!rest2.empty())
            {
                size_t sp2 = rest2.find(' ');
                std::string_view opt = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                if (fnv1a_lower(opt) == fnv1a("match") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    scan_pattern = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                }
                else if (fnv1a_lower(opt) == fnv1a("count") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    std::string_view cnt_str = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    size_t cnt = 10;
                    auto [p2, e2] = std::from_chars(cnt_str.data(), cnt_str.data() + cnt_str.size(), cnt);
                    if (e2 == std::errc{}) scan_count = cnt;
                }
            }
            std::vector<std::string_view> scan_keys;
            uint64_t next_cursor = m_store.scan(scan_cursor, scan_pattern, scan_count, scan_keys);
            append_int_nl(rb, static_cast<int64_t>(next_cursor));
            for (auto& k : scan_keys) { rb.append(k); rb.push_back('\n'); }
            rb.append("end\n", 4);
            break;
        }

        // ─── Admin ───

        case fnv1a("flush"):
        {
            if (m_mode != cache_mode_admin)
            {
                rb.append("denied: admin mode required\n", 28);
                return;
            }
            std::string_view path = args.empty() ? std::string_view(m_persistent_path) : args;
            if (path.empty())
            {
                rb.append("failed: no persistent path set\n", 31);
                return;
            }
            rb.append(m_store.save(path) ? "ok\n" : "failed: flush failed\n");
            break;
        }
        case fnv1a("load"):
        {
            if (m_mode != cache_mode_admin)
            {
                rb.append("denied: admin mode required\n", 28);
                return;
            }
            std::string_view path = args.empty() ? std::string_view(m_persistent_path) : args;
            if (path.empty())
            {
                rb.append("failed: no persistent path set\n", 31);
                return;
            }
            rb.append(m_store.load(path) ? "ok\n" : "failed: load failed\n");
            break;
        }
        case fnv1a("size"):
        {
            append_int_nl(rb, m_store.size());
            break;
        }

        // ─── Pub/Sub ───

        case fnv1a("subscribe"):
        {
            if (args.empty())
            {
                rb.append("usage: subscribe channel\n", 25);
                return;
            }
            m_store.subscribe(conn->fd, args);
            rb.append("ok\n", 3);
            break;
        }
        case fnv1a("unsubscribe"):
        {
            if (args.empty())
            {
                rb.append("usage: unsubscribe channel\n", 27);
                return;
            }
            m_store.unsubscribe(conn->fd, args);
            rb.append("ok\n", 3);
            break;
        }
        case fnv1a("publish"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [channel, message] = extract_key(args);
            if (channel.empty() || message.empty())
            {
                rb.append("usage: publish channel message\n", 31);
                return;
            }
            int count = publish(channel, message);
            append_int_nl(rb, count);
            break;
        }

        // ─── Memory / Maxmemory ───

        case fnv1a("maxmemory"):
        {
            append_int_nl(rb, m_store.get_max_memory());
            break;
        }
        case fnv1a("memory"):
        {
            append_int_nl(rb, m_store.get_memory_used());
            break;
        }
        case fnv1a("replicate"):
        {
            handle_replicate_request(conn);
            return;
        }
        default:
            rb.append("failed: unknown command\n", 24);
            break;
    }
}

void cache_instance::flush_responses(client_connection* conn)
{
    if (conn->response_buf.empty() || !m_loop || conn->closing)
        return;

    if (conn->write_queue.size() >= client_connection::MAX_WRITE_QUEUE)
    {
        conn->closing = true;
        return;
    }

    conn->write_queue.push(std::move(conn->response_buf));
    conn->response_buf.reserve(4096);

    if (!conn->write_pending)
        flush_write_queue(conn);
}

void cache_instance::flush_write_queue(client_connection* conn)
{
    if (!m_loop || conn->write_queue.empty())
        return;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < client_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = std::move(conn->write_queue.front());
        conn->write_queue.pop();

        conn->write_iovs[count].iov_base = conn->write_batch[count].data();
        conn->write_iovs[count].iov_len  = conn->write_batch[count].size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    if (count == 1)
    {
        conn->write_req.type = op_write;
        m_loop->submit_write(conn->fd, conn->write_batch[0].data(),
            static_cast<uint32_t>(conn->write_batch[0].size()), &conn->write_req);
    }
    else
    {
        conn->write_req.type = op_writev;
        m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }
}

// ─── Lua accessor methods ───

std::string cache_instance::lua_get(std::string_view key)
{
    m_store.check_expiry(key);
    std::string value;
    if (m_store.get(key, value))
        return value;
    return "";
}

bool cache_instance::lua_set(std::string_view key, std::string_view value)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.set(key, value);
}

bool cache_instance::lua_del(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return false;
    return m_store.del(key);
}

bool cache_instance::lua_lpush(std::string_view key, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.lpush(key, val);
}

bool cache_instance::lua_rpush(std::string_view key, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.rpush(key, val);
}

std::string cache_instance::lua_lpop(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return "";
    m_store.check_expiry(key);
    std::string val;
    if (m_store.lpop(key, val))
        return val;
    return "";
}

std::string cache_instance::lua_rpop(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return "";
    m_store.check_expiry(key);
    std::string val;
    if (m_store.rpop(key, val))
        return val;
    return "";
}

int cache_instance::lua_llen(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.llen(key);
}

#ifndef SOCKETLEY_NO_LUA
sol::table cache_instance::lua_lrange(std::string_view key, int start, int stop)
{
    m_store.check_expiry(key);
    auto* ctx = lua();
    if (!ctx)
        return sol::table();

    sol::table result = ctx->state().create_table();
    const auto* deq = m_store.list_ptr(key);
    if (!deq || deq->empty())
        return result;

    int len = static_cast<int>(deq->size());
    if (start < 0) start += len;
    if (stop < 0) stop += len;
    if (start < 0) start = 0;
    if (stop >= len) stop = len - 1;

    int lua_idx = 1;
    for (int i = start; i <= stop; i++)
        result[lua_idx++] = (*deq)[static_cast<size_t>(i)];

    return result;
}
#endif

int cache_instance::lua_sadd(std::string_view key, std::string_view member)
{
    if (m_mode == cache_mode_readonly)
        return -1;
    m_store.check_expiry(key);
    return m_store.sadd(key, member);
}

bool cache_instance::lua_srem(std::string_view key, std::string_view member)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.srem(key, member);
}

bool cache_instance::lua_sismember(std::string_view key, std::string_view member)
{
    m_store.check_expiry(key);
    return m_store.sismember(key, member);
}

int cache_instance::lua_scard(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.scard(key);
}

#ifndef SOCKETLEY_NO_LUA
sol::table cache_instance::lua_smembers(std::string_view key)
{
    m_store.check_expiry(key);
    auto* ctx = lua();
    if (!ctx)
        return sol::table();

    sol::table result = ctx->state().create_table();
    const auto* s = m_store.set_ptr(key);
    if (!s)
        return result;

    int lua_idx = 1;
    for (const auto& member : *s)
        result[lua_idx++] = member;

    return result;
}
#endif

bool cache_instance::lua_hset(std::string_view key, std::string_view field, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.hset(key, field, val);
}

std::string cache_instance::lua_hget(std::string_view key, std::string_view field)
{
    m_store.check_expiry(key);
    const std::string* val = m_store.hget(key, field);
    return val ? *val : "";
}

bool cache_instance::lua_hdel(std::string_view key, std::string_view field)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.hdel(key, field);
}

int cache_instance::lua_hlen(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.hlen(key);
}

#ifndef SOCKETLEY_NO_LUA
sol::table cache_instance::lua_hgetall(std::string_view key)
{
    m_store.check_expiry(key);
    auto* ctx = lua();
    if (!ctx)
        return sol::table();

    sol::table result = ctx->state().create_table();
    const auto* h = m_store.hash_ptr(key);
    if (!h)
        return result;

    for (const auto& [field, val] : *h)
        result[field] = val;

    return result;
}
#endif

bool cache_instance::lua_expire(std::string_view key, int seconds)
{
    if (m_mode == cache_mode_readonly)
        return false;
    return m_store.set_expiry(key, seconds);
}

int cache_instance::lua_ttl(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.get_ttl(key);
}

bool cache_instance::lua_persist(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return false;
    return m_store.persist(key);
}

bool cache_instance::store_direct(std::string_view key, std::string_view value)
{
    return m_store.set(key, value);
}

uint32_t cache_instance::get_size() const
{
    return m_store.size();
}

size_t cache_instance::store_memory_used() const
{
    return m_store.get_memory_used();
}

bool cache_instance::flush_to(std::string_view path)
{
    if (m_mode != cache_mode_admin)
        return false;
    return m_store.save(path);
}

bool cache_instance::load_from(std::string_view path)
{
    if (m_mode != cache_mode_admin)
        return false;
    return m_store.load(path);
}

// ─── RESP protocol support ───

void cache_instance::process_resp(client_connection* conn)
{
    // Fixed-size string_view array — zero heap allocations per command
    static constexpr int MAX_RESP_ARGS = 64;
    std::string_view args[MAX_RESP_ARGS];
    int argc = 0;
    size_t consumed = 0;
    size_t offset = 0;

    while (offset < conn->partial.size())
    {
        std::string_view buf(conn->partial.data() + offset, conn->partial.size() - offset);
        auto result = resp::parse_message_views(buf, args, MAX_RESP_ARGS, argc, consumed);

        if (result == resp::parse_result::incomplete)
            break;

        if (result == resp::parse_result::error)
        {
            conn->response_buf.append("-ERR protocol error\r\n");
            conn->partial.clear();
            return;
        }

        // Advance offset; args[] point into conn->partial which stays valid
        offset += consumed;

        if (argc > 0)
            process_resp_command(conn, args, argc);
    }

    // Single erase for entire batch — O(remaining) not O(n * commands)
    if (offset > 0)
    {
        if (offset >= conn->partial.size())
            conn->partial.clear();
        else
            conn->partial.erase(0, offset);
    }
}

void cache_instance::process_resp_command(client_connection* conn, std::string_view* args, int argc)
{
    if (argc == 0)
        return;

    // Rate limit check
    if (conn->rl_max > 0)
    {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - conn->rl_last).count();
        conn->rl_last = now;
        conn->rl_tokens += elapsed * conn->rl_max;
        if (conn->rl_tokens > conn->rl_max)
            conn->rl_tokens = conn->rl_max;
        if (conn->rl_tokens < 1.0)
        {
            resp::encode_error_into(conn->response_buf, "rate limited");
            return;
        }
        conn->rl_tokens -= 1.0;
    }

    m_stat_commands++;
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);

    // Dispatch via case-insensitive FNV-1a — no string allocation
    auto& rb = conn->response_buf;

    switch (fnv1a_lower(args[0]))
    {
        case fnv1a("set"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            bool nx = false, xx = false;
            int ex_sec = 0;
            int64_t px_ms = 0;
            for (int i = 3; i < argc; i++)
            {
                switch (fnv1a_lower(args[i]))
                {
                    case fnv1a("ex"):
                        if (i + 1 < argc)
                        {
                            auto [p, e] = std::from_chars(args[i+1].data(), args[i+1].data() + args[i+1].size(), ex_sec);
                            if (e == std::errc{}) i++;
                        }
                        break;
                    case fnv1a("px"):
                        if (i + 1 < argc)
                        {
                            auto [p, e] = std::from_chars(args[i+1].data(), args[i+1].data() + args[i+1].size(), px_ms);
                            if (e == std::errc{}) i++;
                        }
                        break;
                    case fnv1a("nx"): nx = true; break;
                    case fnv1a("xx"): xx = true; break;
                    default: break;
                }
            }
            m_store.check_expiry(args[1]);
            bool key_exists = m_store.exists(args[1]);
            if (nx && key_exists)  { resp::encode_null_into(rb); break; }
            if (xx && !key_exists) { resp::encode_null_into(rb); break; }
            if (!m_store.set(args[1], args[2]))
            {
                resp::encode_error_into(rb, "type conflict");
                break;
            }
            if (ex_sec > 0) m_store.set_expiry(args[1], ex_sec);
            else if (px_ms > 0) m_store.set_expiry_ms(args[1], px_ms);
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("get"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            const std::string* val = m_store.get_ptr(args[1]);
            if (val) { m_stat_get_hits++; resp::encode_bulk_into(rb, *val); }
            else { m_stat_get_misses++; resp::encode_null_into(rb); }
            break;
        }
        case fnv1a("del"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int deleted = 0;
            for (int i = 1; i < argc; i++)
            {
                m_store.check_expiry(args[i]);
                if (m_store.del(args[i])) deleted++;
            }
            resp::encode_integer_into(rb, deleted);
            break;
        }
        case fnv1a("exists"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.exists(args[1]) ? 1 : 0);
            break;
        }
        case fnv1a("incr"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], 1, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
                resp::encode_integer_into(rb, result);
            break;
        }
        case fnv1a("decr"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], -1, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
                resp::encode_integer_into(rb, result);
            break;
        }
        case fnv1a("incrby"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t delta = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), delta);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], delta, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
                resp::encode_integer_into(rb, result);
            break;
        }
        case fnv1a("decrby"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t delta = 0;
            auto [p2, e2] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), delta);
            if (e2 != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], -delta, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
                resp::encode_integer_into(rb, result);
            break;
        }
        case fnv1a("append"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            size_t newlen = m_store.append(args[1], args[2]);
            if (newlen == std::string::npos)
                resp::encode_error_into(rb, "WRONGTYPE");
            else
                resp::encode_integer_into(rb, static_cast<int64_t>(newlen));
            break;
        }
        case fnv1a("strlen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, static_cast<int64_t>(m_store.strlen_key(args[1])));
            break;
        }
        case fnv1a("getset"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            bool had_key = m_store.exists(args[1]);
            std::string oldval;
            if (!m_store.getset(args[1], args[2], oldval))
                resp::encode_error_into(rb, "WRONGTYPE");
            else if (!had_key)
                resp::encode_null_into(rb);
            else
                resp::encode_bulk_into(rb, oldval);
            break;
        }
        case fnv1a("mget"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            resp::encode_array_header_into(rb, argc - 1);
            for (int i = 1; i < argc; i++)
            {
                m_store.check_expiry(args[i]);
                const std::string* val = m_store.get_ptr(args[i]);
                if (val) resp::encode_bulk_into(rb, *val);
                else resp::encode_null_into(rb);
            }
            break;
        }
        case fnv1a("mset"):
        {
            if (argc < 3 || (argc - 1) % 2 != 0) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            for (int i = 1; i + 1 < argc; i += 2)
            {
                m_store.check_expiry(args[i]);
                m_store.set(args[i], args[i+1]);
            }
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("type"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_simple_into(rb, m_store.type(args[1]));
            break;
        }
        case fnv1a("keys"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            std::vector<std::string_view> result;
            m_store.keys(args[1], result);
            resp::encode_array_header_into(rb, static_cast<int>(result.size()));
            for (auto& k : result)
                resp::encode_bulk_into(rb, k);
            break;
        }
        case fnv1a("ping"):
        {
            if (argc > 1)
                resp::encode_bulk_into(rb, args[1]);
            else
                resp::encode_simple_into(rb, "PONG");
            break;
        }
        case fnv1a("dbsize"):
        {
            resp::encode_integer_into(rb, m_store.size());
            break;
        }
        case fnv1a("lpush"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            for (int i = 2; i < argc; i++)
            {
                if (!m_store.lpush(args[1], args[i]))
                {
                    resp::encode_error_into(rb, "type conflict");
                    return;
                }
            }
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            break;
        }
        case fnv1a("rpush"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            for (int i = 2; i < argc; i++)
            {
                if (!m_store.rpush(args[1], args[i]))
                {
                    resp::encode_error_into(rb, "type conflict");
                    return;
                }
            }
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            break;
        }
        case fnv1a("lpop"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            std::string val;
            if (m_store.lpop(args[1], val)) resp::encode_bulk_into(rb, val);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("rpop"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            std::string val;
            if (m_store.rpop(args[1], val)) resp::encode_bulk_into(rb, val);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("llen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            break;
        }
        case fnv1a("lrange"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            int start = 0, stop = 0;
            auto [p1, e1] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), start);
            auto [p2, e2] = std::from_chars(args[3].data(), args[3].data() + args[3].size(), stop);
            if (e1 != std::errc{} || e2 != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            const auto* deq = m_store.list_ptr(args[1]);
            if (!deq || deq->empty()) { resp::encode_array_header_into(rb, 0); break; }
            int len = static_cast<int>(deq->size());
            if (start < 0) start += len;
            if (stop < 0) stop += len;
            if (start < 0) start = 0;
            if (stop >= len) stop = len - 1;
            int result_len = (start > stop) ? 0 : (stop - start + 1);
            resp::encode_array_header_into(rb, result_len);
            for (int i = start; i <= stop; i++)
                resp::encode_bulk_into(rb, (*deq)[static_cast<size_t>(i)]);
            break;
        }
        case fnv1a("lindex"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            int idx = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), idx);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            const std::string* val = m_store.lindex(args[1], idx);
            if (val) resp::encode_bulk_into(rb, *val);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("sadd"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            int added = 0;
            for (int i = 2; i < argc; i++)
            {
                int r = m_store.sadd(args[1], args[i]);
                if (r < 0) { resp::encode_error_into(rb, "type conflict"); return; }
                added += r;
            }
            resp::encode_integer_into(rb, added);
            break;
        }
        case fnv1a("srem"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            int removed = 0;
            for (int i = 2; i < argc; i++)
                if (m_store.srem(args[1], args[i])) removed++;
            resp::encode_integer_into(rb, removed);
            break;
        }
        case fnv1a("sismember"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.sismember(args[1], args[2]) ? 1 : 0);
            break;
        }
        case fnv1a("scard"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.scard(args[1]));
            break;
        }
        case fnv1a("smembers"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            const auto* s = m_store.set_ptr(args[1]);
            if (!s) { resp::encode_array_header_into(rb, 0); break; }
            resp::encode_array_header_into(rb, static_cast<int>(s->size()));
            for (const auto& member : *s)
                resp::encode_bulk_into(rb, member);
            break;
        }
        case fnv1a("hset"):
        {
            if (argc < 4 || (argc - 2) % 2 != 0)
            {
                resp::encode_error_into(rb, "wrong number of arguments");
                return;
            }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            int added = 0;
            for (int i = 2; i + 1 < argc; i += 2)
            {
                if (!m_store.hset(args[1], args[i], args[i+1]))
                {
                    resp::encode_error_into(rb, "type conflict");
                    return;
                }
                added++;
            }
            resp::encode_integer_into(rb, added);
            break;
        }
        case fnv1a("hget"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            const std::string* val = m_store.hget(args[1], args[2]);
            if (val) resp::encode_bulk_into(rb, *val);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("hdel"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            int removed = 0;
            for (int i = 2; i < argc; i++)
                if (m_store.hdel(args[1], args[i])) removed++;
            resp::encode_integer_into(rb, removed);
            break;
        }
        case fnv1a("hlen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.hlen(args[1]));
            break;
        }
        case fnv1a("hgetall"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            const auto* h = m_store.hash_ptr(args[1]);
            if (!h) { resp::encode_array_header_into(rb, 0); break; }
            resp::encode_array_header_into(rb, static_cast<int>(h->size() * 2));
            for (const auto& [field, val] : *h)
            {
                resp::encode_bulk_into(rb, field);
                resp::encode_bulk_into(rb, val);
            }
            break;
        }
        case fnv1a("expire"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int sec = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), sec);
            if (e != std::errc{} || sec <= 0) { resp::encode_error_into(rb, "invalid seconds"); return; }
            resp::encode_integer_into(rb, m_store.set_expiry(args[1], sec) ? 1 : 0);
            break;
        }
        case fnv1a("ttl"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.get_ttl(args[1]));
            break;
        }
        case fnv1a("persist"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            resp::encode_integer_into(rb, m_store.persist(args[1]) ? 1 : 0);
            break;
        }
        case fnv1a("setnx"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            bool did_set = m_store.setnx(args[1], args[2]);
            resp::encode_integer_into(rb, did_set ? 1 : 0);
            break;
        }
        case fnv1a("setex"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int sec = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), sec);
            if (e != std::errc{} || sec <= 0) { resp::encode_error_into(rb, "ERR invalid expire time in SETEX"); return; }
            m_store.check_expiry(args[1]);
            if (!m_store.set(args[1], args[3])) { resp::encode_error_into(rb, "WRONGTYPE"); return; }
            m_store.set_expiry(args[1], sec);
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("psetex"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t ms = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), ms);
            if (e != std::errc{} || ms <= 0) { resp::encode_error_into(rb, "ERR invalid expire time in PSETEX"); return; }
            m_store.check_expiry(args[1]);
            if (!m_store.set(args[1], args[3])) { resp::encode_error_into(rb, "WRONGTYPE"); return; }
            m_store.set_expiry_ms(args[1], ms);
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("pexpire"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t ms = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), ms);
            if (e != std::errc{} || ms <= 0) { resp::encode_error_into(rb, "ERR invalid expire time"); return; }
            resp::encode_integer_into(rb, m_store.set_expiry_ms(args[1], ms) ? 1 : 0);
            break;
        }
        case fnv1a("pttl"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.get_pttl(args[1]));
            break;
        }
        case fnv1a("expireat"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t unix_s = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), unix_s);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR invalid timestamp"); return; }
            {
                int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining = unix_s - now_s;
                if (remaining <= 0) { m_store.del(args[1]); resp::encode_integer_into(rb, 1); }
                else resp::encode_integer_into(rb, m_store.set_expiry(args[1], static_cast<int>(remaining)) ? 1 : 0);
            }
            break;
        }
        case fnv1a("pexpireat"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t unix_ms = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), unix_ms);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR invalid timestamp"); return; }
            {
                int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining_ms = unix_ms - now_ms;
                if (remaining_ms <= 0) { m_store.del(args[1]); resp::encode_integer_into(rb, 1); }
                else resp::encode_integer_into(rb, m_store.set_expiry_ms(args[1], remaining_ms) ? 1 : 0);
            }
            break;
        }
        case fnv1a("scan"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            uint64_t scan_cursor = 0;
            {
                auto [p, e] = std::from_chars(args[1].data(), args[1].data() + args[1].size(), scan_cursor);
                if (e != std::errc{}) { resp::encode_error_into(rb, "ERR invalid cursor"); return; }
            }
            std::string_view scan_pattern = "*";
            size_t scan_count = 10;
            for (int i = 2; i < argc; i++)
            {
                if (fnv1a_lower(args[i]) == fnv1a("match") && i + 1 < argc)
                    scan_pattern = args[++i];
                else if (fnv1a_lower(args[i]) == fnv1a("count") && i + 1 < argc)
                {
                    size_t cnt = 10;
                    auto [p2, e2] = std::from_chars(args[i+1].data(), args[i+1].data() + args[i+1].size(), cnt);
                    if (e2 == std::errc{}) scan_count = cnt;
                    i++;
                }
            }
            std::vector<std::string_view> scan_keys;
            uint64_t next_cursor = m_store.scan(scan_cursor, scan_pattern, scan_count, scan_keys);
            // RESP: *2\r\n + bulk(next_cursor_str) + array(keys)
            rb.append("*2\r\n");
            char cur_buf[24];
            auto [end, ec] = std::to_chars(cur_buf, cur_buf + sizeof(cur_buf), next_cursor);
            resp::encode_bulk_into(rb, std::string_view(cur_buf, static_cast<size_t>(end - cur_buf)));
            resp::encode_array_header_into(rb, static_cast<int>(scan_keys.size()));
            for (auto& k : scan_keys)
                resp::encode_bulk_into(rb, k);
            break;
        }
        case fnv1a("subscribe"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            for (int i = 1; i < argc; i++)
                m_store.subscribe(conn->fd, args[i]);
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("unsubscribe"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            for (int i = 1; i < argc; i++)
                m_store.unsubscribe(conn->fd, args[i]);
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("publish"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            int count = publish(args[1], args[2]);
            resp::encode_integer_into(rb, count);
            break;
        }
        default:
        {
            rb.append("-ERR unknown command '", 22);
            rb.append(args[0].data(), args[0].size());
            rb.append("'\r\n", 3);
            break;
        }
    }
}

// ─── Pub/Sub publish ───

int cache_instance::publish(std::string_view channel, std::string_view message)
{
    const auto* subs = m_store.get_subscribers(channel);
    if (!subs || subs->empty())
        return 0;

    // Build the message for subscribers
    std::string msg_line;
    msg_line.reserve(8 + channel.size() + 1 + message.size() + 1);
    msg_line.append("message ");
    msg_line.append(channel.data(), channel.size());
    msg_line.push_back(' ');
    msg_line.append(message.data(), message.size());
    msg_line.push_back('\n');

    auto shared_msg = std::make_shared<const std::string>(std::move(msg_line));

    int count = 0;
    for (int fd : *subs)
    {
        if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
            continue;

        auto* sub_conn = m_conn_idx[fd];
        if (sub_conn->closing)
            continue;

        sub_conn->write_queue.push(*shared_msg);
        if (!sub_conn->write_pending)
            flush_write_queue(sub_conn);
        count++;
    }

    return count;
}

// ─── Maxmemory / Eviction ───

void cache_instance::set_max_memory(size_t bytes)
{
    m_store.set_max_memory(bytes);
}

size_t cache_instance::get_max_memory() const
{
    return m_store.get_max_memory();
}

void cache_instance::set_eviction(eviction_policy policy)
{
    m_store.set_eviction(policy);
}

eviction_policy cache_instance::get_eviction() const
{
    return m_store.get_eviction();
}

// ─── RESP mode ───

void cache_instance::set_resp_forced(bool enabled)
{
    m_resp_forced = enabled;
}

bool cache_instance::get_resp_forced() const
{
    return m_resp_forced;
}

// ─── Replication ───

void cache_instance::set_replicate_target(std::string_view host_port)
{
    m_replicate_target = host_port;
    m_repl_role = repl_follower;
}

std::string_view cache_instance::get_replicate_target() const
{
    return m_replicate_target;
}

cache_instance::repl_role cache_instance::get_repl_role() const
{
    return m_repl_role;
}

void cache_instance::replicate_command(std::string_view cmd)
{
    if (m_repl_role != repl_leader || m_follower_fds.empty())
        return;

    std::string line;
    line.reserve(cmd.size() + 1);
    line.append(cmd.data(), cmd.size());
    line.push_back('\n');

    for (auto it = m_follower_fds.begin(); it != m_follower_fds.end(); )
    {
        ssize_t sent = ::write(*it, line.data(), line.size());
        if (sent <= 0)
        {
            close(*it);
            it = m_follower_fds.erase(it);
        }
        else
            ++it;
    }
}

void cache_instance::handle_replicate_request(client_connection* conn)
{
    // Client sent "REPLICATE\n" — promote self to leader, send full dump
    if (m_repl_role == repl_follower)
    {
        conn->response_buf.append("error: this node is a follower\n", 31);
        return;
    }

    m_repl_role = repl_leader;
    m_follower_fds.push_back(conn->fd);

    // Send full dump as a series of commands
    send_full_dump(conn->fd);

    conn->response_buf.append("ok\n", 3);
}

void cache_instance::send_full_dump(int fd)
{
    // Send all data as SET/LPUSH/SADD/HSET commands
    std::string buf;
    buf.reserve(65536);

    // Access store internals via the Lua API
    // For strings: iterate via get_stats path — actually we need direct access
    // We'll use the store's public interface indirectly
    // The simplest approach: use the store save format but as text commands

    // NOTE: For a complete implementation, cache_store would expose iterators.
    // For now, this provides the framework. A full dump would require
    // cache_store to expose iteration methods. We'll add a simple one.
    (void)fd;
    (void)buf;
}

bool cache_instance::connect_to_master()
{
    if (m_replicate_target.empty())
        return false;

    // Parse host:port
    size_t colon = m_replicate_target.rfind(':');
    if (colon == std::string::npos)
        return false;

    std::string host = m_replicate_target.substr(0, colon);
    uint16_t port = 0;
    auto port_sv = std::string_view(m_replicate_target).substr(colon + 1);
    auto [p, e] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
    if (e != std::errc{})
        return false;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
    {
        close(fd);
        return false;
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        if (errno != EINPROGRESS)
        {
            close(fd);
            return false;
        }
    }

    // Send REPLICATE command
    const char* cmd = "replicate\n";
    if (::write(fd, cmd, 10) < 0) { ::close(fd); return false; }

    m_master_fd = fd;

    // Submit read for master data
    m_master_read_req = { op_read, fd, m_master_read_buf, sizeof(m_master_read_buf), this };
    if (m_loop)
        m_loop->submit_read(fd, m_master_read_buf, sizeof(m_master_read_buf), &m_master_read_req);

    // Set mode to readonly as follower
    m_mode = cache_mode_readonly;

    return true;
}

void cache_instance::handle_master_read(struct io_uring_cqe* cqe)
{
    if (cqe->res <= 0)
    {
        // Master disconnected
        close(m_master_fd);
        m_master_fd = -1;
        return;
    }

    m_master_partial.append(m_master_read_buf, cqe->res);

    // Process replicated commands
    size_t scan_from = 0;
    size_t pos;
    while ((pos = m_master_partial.find('\n', scan_from)) != std::string::npos)
    {
        std::string_view line(m_master_partial.data() + scan_from, pos - scan_from);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (!line.empty())
        {
            // Temporarily allow writes for replication
            cache_mode saved = m_mode;
            m_mode = cache_mode_readwrite;

            // Create a temporary dummy connection for process_command
            // Actually, we can just call the store methods directly
            size_t sp = line.find(' ');
            std::string_view cmd = (sp != std::string_view::npos) ? line.substr(0, sp) : line;
            std::string_view args = (sp != std::string_view::npos) ? line.substr(sp + 1) : std::string_view{};

            // Simple replication: just apply SET/DEL commands
            auto extract_key = [](std::string_view a) -> std::pair<std::string_view, std::string_view> {
                size_t s = a.find(' ');
                if (s == std::string_view::npos) return {a, {}};
                return {a.substr(0, s), a.substr(s + 1)};
            };

            switch (fnv1a_lower(cmd))
            {
                case fnv1a("set"):
                {
                    auto [key, val] = extract_key(args);
                    if (!key.empty() && !val.empty())
                        m_store.set(key, val);
                    break;
                }
                case fnv1a("del"):
                    if (!args.empty())
                        m_store.del(args);
                    break;
                case fnv1a("lpush"):
                {
                    auto [key, val] = extract_key(args);
                    if (!key.empty() && !val.empty())
                        m_store.lpush(key, val);
                    break;
                }
                case fnv1a("rpush"):
                {
                    auto [key, val] = extract_key(args);
                    if (!key.empty() && !val.empty())
                        m_store.rpush(key, val);
                    break;
                }
                case fnv1a("sadd"):
                {
                    auto [key, member] = extract_key(args);
                    if (!key.empty() && !member.empty())
                        m_store.sadd(key, member);
                    break;
                }
                case fnv1a("hset"):
                {
                    auto [key, rest] = extract_key(args);
                    auto [field, val] = extract_key(rest);
                    if (!key.empty() && !field.empty() && !val.empty())
                        m_store.hset(key, field, val);
                    break;
                }
                default:
                    break;
            }

            m_mode = saved;
        }

        scan_from = pos + 1;
    }

    if (scan_from > 0)
    {
        if (scan_from >= m_master_partial.size())
            m_master_partial.clear();
        else
            m_master_partial = m_master_partial.substr(scan_from);
    }

    // Re-submit read
    if (m_loop && m_master_fd >= 0)
        m_loop->submit_read(m_master_fd, m_master_read_buf, sizeof(m_master_read_buf), &m_master_read_req);
}

// ─── Stats ───

std::string cache_instance::get_stats() const
{
    std::string base = runtime_instance::get_stats();
    std::ostringstream out;
    out << base
        << "keys:" << m_store.size() << "\n"
        << "commands_processed:" << m_stat_commands << "\n"
        << "get_hits:" << m_stat_get_hits << "\n"
        << "get_misses:" << m_stat_get_misses << "\n"
        << "keys_expired:" << m_stat_keys_expired << "\n"
        << "mode:" << static_cast<int>(m_mode) << "\n"
        << "max_memory:" << m_store.get_max_memory() << "\n"
        << "memory_used:" << m_store.get_memory_used() << "\n"
        << "eviction:" << static_cast<int>(m_store.get_eviction()) << "\n"
        << "channels:" << m_store.channel_count() << "\n"
        << "repl_role:" << static_cast<int>(m_repl_role) << "\n"
        << "followers:" << m_follower_fds.size() << "\n";
    return out.str();
}
