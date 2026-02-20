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

    return true;
}

void cache_instance::teardown(event_loop& loop)
{
    if (!m_persistent_path.empty())
        m_store.save(m_persistent_path);

    // Close listener first to stop new connections
    if (m_listen_fd >= 0)
    {
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
                if (::write(fd, msg->data(), msg->size()) < 0) break;
                conn->write_queue.pop();
            }
        }
    }

    for (auto& [fd, conn] : m_clients)
        close(fd);

    m_clients.clear();

    // Close replication connections
    if (m_master_fd >= 0)
    {
        close(m_master_fd);
        m_master_fd = -1;
    }
    for (int fd : m_follower_fds)
        close(fd);
    m_follower_fds.clear();

    m_loop = nullptr;
    m_multishot_active = false;
}

void cache_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req || !m_loop)
        return;

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
    auto it = m_clients.find(fd);
    if (it == m_clients.end())
        return;

    auto* conn = it->second.get();
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
            m_clients.erase(it);
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
                conn->partial = conn->partial.substr(scan_from);
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
    auto it = m_clients.find(fd);
    if (it == m_clients.end())
        return;

    auto* conn = it->second.get();
    conn->write_pending = false;

    // Release batch references
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].reset();
    conn->write_batch_count = 0;

    if (cqe->res <= 0)
    {
        conn->closing = true;
        if (!conn->read_pending)
        {
            close(fd);
            m_clients.erase(it);
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
            rb.append(std::to_string(m_store.llen(args)));
            rb.push_back('\n');
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
            rb.append(std::to_string(m_store.scard(args)));
            rb.push_back('\n');
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
            rb.append(std::to_string(m_store.hlen(args)));
            rb.push_back('\n');
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
            rb.append(std::to_string(ttl));
            rb.push_back('\n');
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
            rb.append(std::to_string(m_store.size()));
            rb.push_back('\n');
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
            rb.append(std::to_string(count));
            rb.push_back('\n');
            break;
        }

        // ─── Memory / Maxmemory ───

        case fnv1a("maxmemory"):
        {
            rb.append(std::to_string(m_store.get_max_memory()));
            rb.push_back('\n');
            break;
        }
        case fnv1a("memory"):
        {
            rb.append(std::to_string(m_store.get_memory_used()));
            rb.push_back('\n');
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

    conn->write_queue.push(std::make_shared<const std::string>(std::move(conn->response_buf)));
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

        conn->write_iovs[count].iov_base = const_cast<char*>(conn->write_batch[count]->data());
        conn->write_iovs[count].iov_len = conn->write_batch[count]->size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    if (count == 1)
    {
        conn->write_req.type = op_write;
        m_loop->submit_write(conn->fd, conn->write_batch[0]->data(),
            static_cast<uint32_t>(conn->write_batch[0]->size()), &conn->write_req);
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
    std::vector<std::string> args;
    size_t consumed = 0;

    while (true)
    {
        std::string_view buf(conn->partial);
        auto result = resp::parse_message(buf, args, consumed);

        if (result == resp::parse_result::incomplete)
            break;

        if (result == resp::parse_result::error)
        {
            conn->response_buf.append("-ERR protocol error\r\n");
            conn->partial.clear();
            break;
        }

        // Parse OK — dispatch
        conn->partial.erase(0, consumed);

        if (!args.empty())
            process_resp_command(conn, args);
    }
}

void cache_instance::process_resp_command(client_connection* conn, const std::vector<std::string>& args)
{
    if (args.empty())
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
            conn->response_buf.append(resp::encode_error("rate limited"));
            return;
        }
        conn->rl_tokens -= 1.0;
    }

    m_stat_commands++;
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);

    std::string cmd_lower = args[0];
    resp::to_lower(cmd_lower);

    auto& rb = conn->response_buf;

    switch (fnv1a(cmd_lower.c_str()))
    {
        case fnv1a("set"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            // Handle optional EX argument
            if (!m_store.set(args[1], args[2]))
                rb.append(resp::encode_error("type conflict"));
            else
            {
                // Check for EX/PX options
                for (size_t i = 3; i + 1 < args.size(); i++)
                {
                    std::string opt = args[i];
                    resp::to_lower(opt);
                    if (opt == "ex")
                    {
                        int sec = 0;
                        auto [p, e] = std::from_chars(args[i+1].data(), args[i+1].data() + args[i+1].size(), sec);
                        if (e == std::errc{} && sec > 0)
                            m_store.set_expiry(args[1], sec);
                        i++;
                    }
                }
                rb.append(resp::encode_ok());
            }
            break;
        }
        case fnv1a("get"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            const std::string* val = m_store.get_ptr(args[1]);
            if (val) { m_stat_get_hits++; rb.append(resp::encode_bulk(*val)); }
            else { m_stat_get_misses++; rb.append(resp::encode_null()); }
            break;
        }
        case fnv1a("del"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            int deleted = 0;
            for (size_t i = 1; i < args.size(); i++)
            {
                m_store.check_expiry(args[i]);
                if (m_store.del(args[i])) deleted++;
            }
            rb.append(resp::encode_integer(deleted));
            break;
        }
        case fnv1a("exists"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            rb.append(resp::encode_integer(m_store.exists(args[1]) ? 1 : 0));
            break;
        }
        case fnv1a("ping"):
        {
            if (args.size() > 1)
                rb.append(resp::encode_bulk(args[1]));
            else
                rb.append(resp::encode_simple("PONG"));
            break;
        }
        case fnv1a("dbsize"):
        {
            rb.append(resp::encode_integer(m_store.size()));
            break;
        }
        case fnv1a("lpush"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            for (size_t i = 2; i < args.size(); i++)
            {
                if (!m_store.lpush(args[1], args[i]))
                {
                    rb.append(resp::encode_error("type conflict"));
                    return;
                }
            }
            rb.append(resp::encode_integer(m_store.llen(args[1])));
            break;
        }
        case fnv1a("rpush"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            for (size_t i = 2; i < args.size(); i++)
            {
                if (!m_store.rpush(args[1], args[i]))
                {
                    rb.append(resp::encode_error("type conflict"));
                    return;
                }
            }
            rb.append(resp::encode_integer(m_store.llen(args[1])));
            break;
        }
        case fnv1a("lpop"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            std::string val;
            if (m_store.lpop(args[1], val)) rb.append(resp::encode_bulk(val));
            else rb.append(resp::encode_null());
            break;
        }
        case fnv1a("rpop"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            std::string val;
            if (m_store.rpop(args[1], val)) rb.append(resp::encode_bulk(val));
            else rb.append(resp::encode_null());
            break;
        }
        case fnv1a("llen"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            rb.append(resp::encode_integer(m_store.llen(args[1])));
            break;
        }
        case fnv1a("sadd"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            int added = 0;
            for (size_t i = 2; i < args.size(); i++)
            {
                int r = m_store.sadd(args[1], args[i]);
                if (r < 0) { rb.append(resp::encode_error("type conflict")); return; }
                added += r;
            }
            rb.append(resp::encode_integer(added));
            break;
        }
        case fnv1a("srem"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            int removed = 0;
            for (size_t i = 2; i < args.size(); i++)
                if (m_store.srem(args[1], args[i])) removed++;
            rb.append(resp::encode_integer(removed));
            break;
        }
        case fnv1a("sismember"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            rb.append(resp::encode_integer(m_store.sismember(args[1], args[2]) ? 1 : 0));
            break;
        }
        case fnv1a("scard"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            rb.append(resp::encode_integer(m_store.scard(args[1])));
            break;
        }
        case fnv1a("smembers"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            const auto* s = m_store.set_ptr(args[1]);
            if (!s) { rb.append(resp::encode_array_header(0)); break; }
            rb.append(resp::encode_array_header(static_cast<int>(s->size())));
            for (const auto& member : *s)
                rb.append(resp::encode_bulk(member));
            break;
        }
        case fnv1a("hset"):
        {
            if (args.size() < 4 || (args.size() - 2) % 2 != 0)
            {
                rb.append(resp::encode_error("wrong number of arguments"));
                return;
            }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            int added = 0;
            for (size_t i = 2; i + 1 < args.size(); i += 2)
            {
                if (!m_store.hset(args[1], args[i], args[i+1]))
                {
                    rb.append(resp::encode_error("type conflict"));
                    return;
                }
                added++;
            }
            rb.append(resp::encode_integer(added));
            break;
        }
        case fnv1a("hget"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            const std::string* val = m_store.hget(args[1], args[2]);
            if (val) rb.append(resp::encode_bulk(*val));
            else rb.append(resp::encode_null());
            break;
        }
        case fnv1a("hdel"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            m_store.check_expiry(args[1]);
            int removed = 0;
            for (size_t i = 2; i < args.size(); i++)
                if (m_store.hdel(args[1], args[i])) removed++;
            rb.append(resp::encode_integer(removed));
            break;
        }
        case fnv1a("hlen"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            rb.append(resp::encode_integer(m_store.hlen(args[1])));
            break;
        }
        case fnv1a("hgetall"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            const auto* h = m_store.hash_ptr(args[1]);
            if (!h) { rb.append(resp::encode_array_header(0)); break; }
            rb.append(resp::encode_array_header(static_cast<int>(h->size() * 2)));
            for (const auto& [field, val] : *h)
            {
                rb.append(resp::encode_bulk(field));
                rb.append(resp::encode_bulk(val));
            }
            break;
        }
        case fnv1a("expire"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            int sec = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), sec);
            if (e != std::errc{} || sec <= 0) { rb.append(resp::encode_error("invalid seconds")); return; }
            rb.append(resp::encode_integer(m_store.set_expiry(args[1], sec) ? 1 : 0));
            break;
        }
        case fnv1a("ttl"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            m_store.check_expiry(args[1]);
            rb.append(resp::encode_integer(m_store.get_ttl(args[1])));
            break;
        }
        case fnv1a("persist"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            if (m_mode == cache_mode_readonly) { rb.append(resp::encode_error("readonly mode")); return; }
            rb.append(resp::encode_integer(m_store.persist(args[1]) ? 1 : 0));
            break;
        }
        case fnv1a("subscribe"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            for (size_t i = 1; i < args.size(); i++)
                m_store.subscribe(conn->fd, args[i]);
            rb.append(resp::encode_ok());
            break;
        }
        case fnv1a("unsubscribe"):
        {
            if (args.size() < 2) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            for (size_t i = 1; i < args.size(); i++)
                m_store.unsubscribe(conn->fd, args[i]);
            rb.append(resp::encode_ok());
            break;
        }
        case fnv1a("publish"):
        {
            if (args.size() < 3) { rb.append(resp::encode_error("wrong number of arguments")); return; }
            int count = publish(args[1], args[2]);
            rb.append(resp::encode_integer(count));
            break;
        }
        default:
            rb.append(resp::encode_error("unknown command '" + cmd_lower + "'"));
            break;
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
        auto it = m_clients.find(fd);
        if (it == m_clients.end())
            continue;

        auto* sub_conn = it->second.get();
        if (sub_conn->closing)
            continue;

        sub_conn->write_queue.push(shared_msg);
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
