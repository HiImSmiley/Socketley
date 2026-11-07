#include "conn_server.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../runtime/runtime_instance.h"
#include "../util/wall_clock.h"

namespace socketley::http
{

// A recv that fills one of the ring's buffers is the read that grows a connection's own buffer.
static_assert(conn_server::ring.bytes == 16384, "the ring's buffer is the first read size of server_conn::rbuf");


conn_server::conn_server(event_loop& loop, io_handler* owner, runtime_instance& rt, conn_hooks& hooks,
                         size_t max_conns)
    : m_loop(loop), m_owner(owner), m_rt(rt), m_hooks(hooks), m_max_conns(max_conns), m_reads(loop, ring)
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

bool conn_server::listen_unix(const std::string& path, std::string& why)
{
    sockaddr_un a{};
    if (path.size() >= sizeof a.sun_path)
    {
        why = "the socket path " + path + " is too long";
        return false;
    }
    m_listen_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return false;
    }
    a.sun_family = AF_UNIX;
    std::memcpy(a.sun_path, path.data(), path.size());
    ::unlink(path.c_str());
    if (::bind(m_listen_fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::chmod(path.c_str(), 0660) < 0 ||
        ::listen(m_listen_fd, 1024) < 0)
    {
        why = path + " could not be bound: " + std::strerror(errno);
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    m_unix_path = path;
    return true;
}

std::shared_ptr<server_conn> conn_server::dial(const sockaddr_storage& addr, socklen_t len, std::string& why,
                                              uint32_t from_v4)
{
    if (m_stopped)
    {
        why = "stopped";
        return nullptr;
    }
    const int fd = ::socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return nullptr;
    }
    if (from_v4 != 0 && addr.ss_family == AF_INET)
    {
        // The port is left to the connect, so a source address takes no port of its own from the ephemeral range.
        int one = 1;
        ::setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof one);
        sockaddr_in from{};
        from.sin_family = AF_INET;
        from.sin_addr.s_addr = from_v4;
        if (::bind(fd, reinterpret_cast<const sockaddr*>(&from), sizeof from) < 0)
        {
            why = std::string("no source address: ") + std::strerror(errno);
            ::close(fd);
            return nullptr;
        }
    }
    ensure_ring();
    auto c = m_hooks.make_conn();
    c->id = m_next_id++;
    c->fd = fd;
    c->peer = addr;
    c->last = wall::now_sec_coarse();
    if (addr.ss_family != AF_UNIX)
    {
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    c->cn = io_request{};
    c->cn.owner = m_owner;
    c->cn.buffer = reinterpret_cast<char*>(c.get());
    c->cn.fd = fd;
    c->cn.type = op_connect;
    c->cn_pending = m_loop.submit_connect(fd, reinterpret_cast<const sockaddr*>(&c->peer), len, &c->cn);
    if (!c->cn_pending)
    {
        ::close(fd);
        why = "the ring is full";
        return nullptr;
    }
    m_conns.emplace(c->id, c);
    m_rt.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
    return c;
}

void conn_server::connect_done(const std::shared_ptr<server_conn>& c, int res)
{
    c->cn_pending = false;
    if (c->dead)
    {
        forget_if_idle(c);
        return;
    }
    m_hooks.connected(c, res);
    if (res < 0)
    {
        close_conn(c);
        return;
    }
    if (!c->dead)
    {
        arm_read(c);
        flush(c);
    }
}

void conn_server::forget_if_idle(const std::shared_ptr<server_conn>& c)
{
    if (!c->rd.pending && !c->wr_pending && !c->cn_pending)
        std::erase(m_closing, c);
}

void conn_server::start_accepting()
{
    ensure_ring();
    arm_accept();
}

void conn_server::ensure_ring()
{
    if (m_ring_asked)
        return;
    m_ring_asked = true;
    m_reads.setup();
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
    if (!m_unix_path.empty())
        ::unlink(m_unix_path.c_str());
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
        // The flag's limit is the runtime's, the default this process's own.
        const size_t asked = m_rt.get_max_connections();
        if (m_stopped || (asked ? m_rt.connections_full(m_conns.size(), asked) : m_conns.size() >= m_max_conns))
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
            c->last = wall::now_sec_coarse();
            m_conns.emplace(c->id, c);
            runtime_instance::stat_add(m_rt.m_stat_total_connections, 1);
            m_rt.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            arm_read(c);
            m_hooks.accepted(c);
        }
    }
    // Out of descriptors, an accept again at once fails again at once, so it waits for a close or the next sweep.
    if (fd == -EMFILE || fd == -ENFILE || fd == -ENOBUFS || fd == -ENOMEM)
    {
        m_accept_starved = !m_accept_pending;
        return;
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
    if (!is_read_op(req->type) && req->type != op_write && req->type != op_connect)
        return false;
    // Not this server's: an owner with several asks each in turn, and a connection is forgotten only after its last.
    auto c = conn_of(req);
    if (!c)
        return false;
    if (req == &c->rd.req)
        read_done(c, cqe);
    else if (req == &c->wr)
        write_done(c, cqe->res);
    else if (req == &c->cn)
        connect_done(c, cqe->res);
    return true;
}

void conn_server::arm_read(const std::shared_ptr<server_conn>& c)
{
    if (c->dead || c->rd.pending || c->cn_pending || c->read_eof || c->fd < 0)
        return;
    if (c->eof_seen)
    {
        c->eof_seen = false;
        ended(c);
        return;
    }
    // A connection that streams reads the larger sizes into its own growing buffer; the first read is a single one.
    const socketley::ring_arm how{.ring = c->rbuf.size() == ring.bytes, .multishot = c->rd_heard};
    if (!m_reads.arm(c->rd, m_owner, c.get(), c->fd, how,
                     [&] { return std::pair<char*, uint32_t>{c->rbuf.data(), c->rbuf.size()}; }))
        close_conn(c);
}

bool conn_server::wants_read(const server_conn& c) const
{
    return !c.dead && !c.waiting && !c.held && (c.keep_alive || m_hooks.keeps_open(c));
}

void conn_server::ended(const std::shared_ptr<server_conn>& c)
{
    if (m_hooks.read_ended(c))
        c->read_eof = true;
    else
        close_conn(c);
}

void conn_server::read_done(const std::shared_ptr<server_conn>& c, struct io_uring_cqe* cqe)
{
    using kind = socketley::ring_bytes::kind;
    auto got = m_reads.take(c->rd, cqe);
    bool trimmed = false;
    if (!got.more)
    {
        trimmed = c->trimming;
        c->trimming = false;
    }
    if (c->dead)
    {
        got.give_back();
        forget_if_idle(c);
        return;
    }
    switch (got.what)
    {
        case kind::withdrawn:
            // Withdrawn by trim(): armed again on the first read size, with nothing lost, since nothing was read.
            if (trimmed)
                c->rbuf.reset();
            [[fallthrough]];
        case kind::no_buffer:
            if (wants_read(*c))
                arm_read(c);
            return;
        case kind::eof:
            // The end met while no read was wanted is taken up when one is, as a single read would have met it then.
            if (wants_read(*c))
                ended(c);
            else
                c->eof_seen = true;
            return;
        case kind::failed:
            close_conn(c);
            return;
        case kind::data:
            break;
    }
    const size_t n = got.size();
    runtime_instance::stat_add(m_rt.m_stat_bytes_in, n);
    // What a connection that answers no more requests is sent is read away, not kept.
    if (!c->keep_alive && !m_hooks.keeps_open(*c))
        return;
    c->last = wall::now_sec_coarse();
    // Copied, since every runtime's serve() parses `in`.
    c->in.append(got.data(), n);
    got.give_back();
    c->rd_heard = true;
    c->rbuf.took(n);
    // A recv that filled the ring's buffer is a stream, which reads the larger sizes into its own buffer.
    if (got.more && c->rbuf.size() != ring.bytes)
        m_reads.withdraw(c->rd);
    if (!wants_read(*c))
    {
        // Kept for the request that is taken next, up to a bound, past which the socket holds the rest.
        if (got.more && c->in.size() > in_max)
            m_reads.withdraw(c->rd);
        return;
    }
    m_hooks.serve(c);
    flush(c);
    after_serve(c);
}

void conn_server::resume(const std::shared_ptr<server_conn>& c)
{
    // What the connection brought while it waited, then more of it.
    c->waiting = false;
    m_hooks.serve(c);
    flush(c);
    after_serve(c);
}

void conn_server::after_serve(const std::shared_ptr<server_conn>& c)
{
    if (c->dead || c->waiting)
        return;
    // A request after one that closes the connection is not answered (RFC 9112 9.6), so none is read.
    if (!c->keep_alive && !m_hooks.keeps_open(*c))
    {
        c->in.clear();
        m_reads.withdraw(c->rd);
        return;
    }
    // A client that sends requests faster than it reads the answers is not read from until it has caught up; a stream
    // the runtime keeps open runs its own window.
    if (c->unsent() > out_max && !m_hooks.keeps_open(*c))
    {
        c->held = true;
        m_reads.withdraw(c->rd);
        return;
    }
    arm_read(c);
}

void conn_server::flush(const std::shared_ptr<server_conn>& c)
{
    if (c->dead || c->wr_pending || c->cn_pending)
        return;
    if (!c->keep_alive && finish_now(c))
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

// A FIN sent from the write's completion loses the race to a client that closes as soon as it has the answer, and its
// TIME-WAIT then makes every connect() of that client search for a port: server_instance::send_final_and_fin measured
// 78% of them on the clients at 32 connections a request.
bool conn_server::finish_now(const std::shared_ptr<server_conn>& c)
{
    if (c->dead || c->keep_alive || c->waiting || c->wr_pending || c->cn_pending || c->sent < c->sending.size() ||
        c->out.empty() || m_hooks.keeps_open(*c) || !m_hooks.fin_at_once(*c))
        return false;
    size_t off = 0;
    while (off < c->out.size())
    {
        const ssize_t n = ::send(c->fd, c->out.data() + off, c->out.size() - off, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE);
        if (n > 0)
        {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
    runtime_instance::stat_add(m_rt.m_stat_bytes_out, off);
    c->out.erase(0, off);
    // What the socket did not take goes the usual way, the FIN after it from the write's completion.
    if (!c->out.empty())
        return false;
    close_conn(c);
    return true;
}

void conn_server::write_done(const std::shared_ptr<server_conn>& c, int res)
{
    c->wr_pending = false;
    if (c->dead)
    {
        forget_if_idle(c);
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    c->sent += static_cast<size_t>(res);
    c->last = wall::now_sec_coarse();
    runtime_instance::stat_add(m_rt.m_stat_bytes_out, static_cast<uint64_t>(res));
    m_hooks.wrote(c, static_cast<size_t>(res));
    if (c->dead)
        return;
    if (c->unsent() == 0 && m_hooks.written(c))
        return;
    // Half of what held reading up is gone: the requests it brought meanwhile are answered, and reading goes on.
    if (c->held && !c->waiting && c->unsent() <= out_max / 2)
    {
        c->held = false;
        m_hooks.serve(c);
        flush(c);
        after_serve(c);
        return;
    }
    flush(c);
}

void conn_server::close_conn(const std::shared_ptr<server_conn>& c)
{
    if (c->dead)
        return;
    c->dead = true;
    m_hooks.closing(c);
    // Not shut down here: with our FIN out and the read side shut, a byte the client still sends resets the
    // connection and throws away what the kernel has not delivered of the answer, which orderly_close keeps.
    if (c->fd >= 0)
    {
        m_loop.close_fd_orderly(c->fd);
        c->fd = -1;
    }
    m_conns.erase(c->id);
    m_rt.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
    if (c->rd.pending || c->wr_pending || c->cn_pending)
        m_closing.push_back(c);
    // The descriptor just given back is room for the accept that ran out.
    resume_accept();
}

void conn_server::trim(int64_t now, int64_t quiet_secs)
{
    // What a connection keeps past a burst and before the next: more than this is given back.
    constexpr size_t keep = 64 * 1024;
    for (auto& [id, c] : m_conns)
    {
        if (c->dead || now - c->last < quiet_secs)
            continue;
        if (c->in.empty() && c->in.capacity() > keep)
            std::string().swap(c->in);
        if (!c->wr_pending && c->unsent() == 0)
        {
            if (c->sending.capacity() > keep)
            {
                std::string().swap(c->sending);
                c->sent = 0;
            }
            if (c->out.capacity() > keep)
                std::string().swap(c->out);
        }
        if (c->rd.pending && !c->rd.multi && !c->trimming && c->rbuf.size() > ring.bytes &&
            m_loop.submit_cancel_request(&c->rd.req))
            c->trimming = true;
    }
}

void conn_server::sweep(int64_t now, int64_t idle_secs)
{
    trim(now);
    std::vector<std::shared_ptr<server_conn>> idle;
    // Idle with nothing owed, or owed answers the client has not read a byte of for as long.
    for (auto& [id, c] : m_conns)
        if (now - c->last > idle_secs && !m_hooks.keeps_open(*c) && (c->unsent() > 0 || !c->waiting))
            idle.push_back(c);
    for (auto& c : idle)
        close_conn(c);
    resume_accept();
}

void conn_server::resume_accept()
{
    if (!m_accept_starved || m_accept_pending || m_stopped)
        return;
    m_accept_starved = false;
    arm_accept();
}

}   // namespace socketley::http
