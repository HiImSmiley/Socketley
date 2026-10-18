#include "conn_server.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "../runtime/runtime_instance.h"

namespace socketley::http
{

namespace
{

// The coarse clock, what the kernel last ticked: a connection's activity is counted in whole seconds.
int64_t now_sec()
{
    timespec ts{};
    ::clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    return static_cast<int64_t>(ts.tv_sec);
}

}   // namespace

conn_server::conn_server(event_loop& loop, io_handler* owner, runtime_instance& rt, conn_hooks& hooks,
                         size_t max_conns)
    : m_loop(loop), m_owner(owner), m_rt(rt), m_hooks(hooks), m_max_conns(max_conns)
{
}

bool conn_server::listen_tcp(uint32_t addr, uint16_t port, bool shared, std::string& why)
{
    m_listen_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    // Every shard binds the port, and the kernel spreads the connections over them.
    if (shared)
        ::setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = addr;
    a.sin_port = htons(port);
    if (::bind(m_listen_fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(m_listen_fd, 1024) < 0)
    {
        why = "port " + std::to_string(port) + " could not be bound: " + std::strerror(errno);
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    return true;
}

void conn_server::start_accepting()
{
    arm_accept();
}

void conn_server::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    if (m_listen_fd >= 0)
    {
        ::shutdown(m_listen_fd, SHUT_RDWR);
        m_loop.close_fd(m_listen_fd);
        m_listen_fd = -1;
    }
    std::vector<std::shared_ptr<server_conn>> all;
    all.reserve(m_conns.size());
    for (auto& [id, c] : m_conns)
        all.push_back(c);
    for (auto& c : all)
        close_conn(c);
}

void conn_server::on_loop_turn()
{
    if (!m_accept_pending && !m_stopped)
        arm_accept();
}

void conn_server::arm_accept()
{
    if (m_stopped || m_listen_fd < 0 || m_accept_pending)
        return;
    m_accept_req = io_request{};
    m_accept_req.owner = m_owner;
    m_accept_req.fd = m_listen_fd;
    m_accept_req.type = event_loop::supports_multishot_accept() ? op_multishot_accept : op_accept;
    m_accept_pending = m_accept_req.type == op_multishot_accept
                           ? m_loop.submit_multishot_accept(m_listen_fd, &m_accept_req)
                           : m_loop.submit_accept(m_listen_fd, nullptr, nullptr, &m_accept_req);
}

void conn_server::accept_done(struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
        m_accept_pending = false;
    const int fd = cqe->res;
    if (fd >= 0)
    {
        const size_t limit = m_rt.get_max_connections() ? m_rt.get_max_connections() : m_max_conns;
        if (m_stopped || m_conns.size() >= limit)
            m_loop.close_fd(fd);
        else
        {
            auto c = m_hooks.make_conn();
            c->id = m_next_id++;
            c->fd = fd;
            socklen_t len = sizeof c->peer;
            if (::getpeername(fd, reinterpret_cast<sockaddr*>(&c->peer), &len) < 0) {}
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->last = now_sec();
            m_conns.emplace(c->id, c);
            runtime_instance::stat_add(m_rt.m_stat_total_connections, 1);
            m_rt.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            arm_read(c);
            m_hooks.accepted(c);
        }
    }
    if (!m_accept_pending && !m_stopped && fd != -ECANCELED)
        arm_accept();
}

std::shared_ptr<server_conn> conn_server::conn_of(io_request* req)
{
    auto* raw = reinterpret_cast<server_conn*>(req->buffer);
    if (auto it = m_conns.find(raw->id); it != m_conns.end() && it->second.get() == raw)
        return it->second;
    for (const auto& c : m_closing)
        if (c.get() == raw)
            return c;
    return nullptr;
}

bool conn_server::on_cqe(io_request* req, struct io_uring_cqe* cqe)
{
    if (req == &m_accept_req)
    {
        accept_done(cqe);
        return true;
    }
    if (req->type != op_read && req->type != op_write)
        return false;
    auto c = conn_of(req);
    if (!c)
        return false;
    if (req == &c->rd)
        read_done(c, cqe->res);
    else if (req == &c->wr)
        write_done(c, cqe->res);
    return true;
}

void conn_server::arm_read(const std::shared_ptr<server_conn>& c)
{
    if (c->dead || c->rd_pending || c->fd < 0)
        return;
    c->rd = io_request{};
    c->rd.owner = m_owner;
    c->rd.buffer = reinterpret_cast<char*>(c.get());
    c->rd.fd = c->fd;
    c->rd.type = op_read;
    c->rd_pending = m_loop.submit_read(c->fd, c->rbuf, sizeof c->rbuf, &c->rd);
    if (!c->rd_pending)
        close_conn(c);
}

void conn_server::read_done(const std::shared_ptr<server_conn>& c, int res)
{
    c->rd_pending = false;
    if (c->dead)
    {
        if (!c->wr_pending)
            std::erase(m_closing, c);
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    c->last = now_sec();
    c->in.append(c->rbuf, static_cast<size_t>(res));
    runtime_instance::stat_add(m_rt.m_stat_bytes_in, static_cast<uint64_t>(res));
    m_hooks.serve(c);
    flush(c);
    if (!c->dead && !c->waiting)
        arm_read(c);
}

void conn_server::resume(const std::shared_ptr<server_conn>& c)
{
    // What the connection brought while it waited, then more of it.
    c->waiting = false;
    m_hooks.serve(c);
    flush(c);
    if (!c->dead && !c->waiting)
        arm_read(c);
}

void conn_server::flush(const std::shared_ptr<server_conn>& c)
{
    if (c->dead || c->wr_pending)
        return;
    if (c->sent >= c->sending.size())
    {
        // The last send is done with its buffer, which takes what was answered since and keeps its capacity.
        c->sending.clear();
        c->sent = 0;
        if (c->out.empty())
        {
            if (!c->keep_alive && !c->waiting && !m_hooks.keeps_open(*c))
                close_conn(c);
            return;
        }
        c->sending.swap(c->out);
    }
    c->wr = io_request{};
    c->wr.owner = m_owner;
    c->wr.buffer = reinterpret_cast<char*>(c.get());
    c->wr.fd = c->fd;
    c->wr.type = op_write;
    const size_t chunk = std::min<size_t>(c->sending.size() - c->sent, 1u << 20);
    c->wr_pending = m_loop.submit_write(c->fd, c->sending.data() + c->sent, static_cast<uint32_t>(chunk), &c->wr);
    if (!c->wr_pending)
        close_conn(c);
}

void conn_server::write_done(const std::shared_ptr<server_conn>& c, int res)
{
    c->wr_pending = false;
    if (c->dead)
    {
        if (!c->rd_pending)
            std::erase(m_closing, c);
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    c->sent += static_cast<size_t>(res);
    c->last = now_sec();
    runtime_instance::stat_add(m_rt.m_stat_bytes_out, static_cast<uint64_t>(res));
    if (c->unsent() == 0 && m_hooks.written(c))
        return;
    flush(c);
}

void conn_server::close_conn(const std::shared_ptr<server_conn>& c)
{
    if (c->dead)
        return;
    c->dead = true;
    m_hooks.closing(c);
    if (c->fd >= 0)
    {
        ::shutdown(c->fd, SHUT_RDWR);
        m_loop.close_fd(c->fd);
        c->fd = -1;
    }
    m_conns.erase(c->id);
    m_rt.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
    if (c->rd_pending || c->wr_pending)
        m_closing.push_back(c);
}

void conn_server::sweep(int64_t now, int64_t idle_secs)
{
    std::vector<std::shared_ptr<server_conn>> idle;
    for (auto& [id, c] : m_conns)
        if (now - c->last > idle_secs && !c->waiting && c->unsent() == 0 && !m_hooks.keeps_open(*c))
            idle.push_back(c);
    for (auto& c : idle)
        close_conn(c);
}

}   // namespace socketley::http
