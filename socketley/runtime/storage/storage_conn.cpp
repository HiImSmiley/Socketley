// The wire side of a storage run: accepting, reading, writing, HTTP framing,
// the streaming of a body into an object and of an object out to a socket.
#include "storage_run.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "s3_names.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"
#include "../../shared/random_id.h"
#include "../../shared/unix_listener.h"

namespace socketley::storage
{

namespace
{

constexpr size_t   max_head_bytes      = 32 * 1024;
constexpr size_t   pipe_bytes          = 1u << 20;
constexpr size_t   stream_chunk        = 256 * 1024;
// What a body already refused is read and thrown away up to, so the client that
// sent it hears the answer instead of a reset; beyond it the connection closes.
constexpr uint64_t discard_limit       = 64ull << 20;
constexpr int      body_stall_secs     = 60;
constexpr int      write_stall_secs    = 120;

const char* reason_phrase(int status)
{
    switch (status)
    {
        case 100: return "Continue";
        case 200: return "OK";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Payload Too Large";
        case 416: return "Range Not Satisfiable";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        case 505: return "HTTP Version Not Supported";
        case 507: return "Insufficient Storage";
        default:  return "Status";
    }
}

}   // namespace

storage_run::storage_run(storage_instance& owner, event_loop& loop, store_options opts, authenticator* auth)
    : m_owner(owner), m_loop(loop), m_io(loop, this), m_store(loop, m_io, std::move(opts)), m_auth(auth)
{
    m_rid_seq = random_u64();
    m_max_conns = m_owner.get_max_connections();
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_SPLICE_MIN"))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && v >= 0)
            m_zero_copy_min = static_cast<size_t>(v);
    }
}

storage_run::~storage_run()
{
    for (auto& [a, b] : m_pipes)
    {
        ::close(a);
        ::close(b);
    }
}

bool storage_run::open(std::string& err)
{
    recovery_report rep;
    if (!m_store.open(err, &rep))
        return false;
    LOG_INFO(("storage: " + std::to_string(rep.buckets) + " bucket(s), " +
              std::to_string(rep.objects) + " object(s) in " + m_store.options().dir +
              (rep.clean_start ? " (clean stop)" : " (recovered: " +
               std::to_string(rep.tmp_removed) + " tmp removed, " +
               std::to_string(rep.adopted) + " adopted, " +
               std::to_string(rep.dropped) + " dropped, " +
               std::to_string(rep.torn_tails) + " torn tail(s))")).c_str());
    return true;
}

bool storage_run::listen_on(int fd)
{
    m_listen_fd = fd;
    arm_accept();
    return m_accept_pending;
}

bool storage_run::drained() const
{
    return m_loop.owner_inflight(this) == 0 && !m_loop.owner_table_full();
}

std::string storage_run::new_request_id()
{
    // Sixteen hex digits, the shape S3's own have, from a counter the loop
    // steps: a syscall per request would be the most expensive thing in a HEAD.
    uint64_t x = m_rid_seq += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    x ^= x >> 31;
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string id(16, '0');
    for (int i = 15; i >= 0; --i, x >>= 4)
        id[static_cast<size_t>(i)] = digits[x & 15];
    return id;
}

std::shared_ptr<conn> storage_run::find(uint64_t id)
{
    auto it = m_conns.find(id);
    return it == m_conns.end() ? nullptr : it->second;
}

// ─── The ring ───────────────────────────────────────────────────────────────

void storage_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;

    if (file_io::owns_type(req->type))
    {
        m_io.on_cqe(cqe);
        return;
    }
    if (req == &m_accept_req)
    {
        accept_done(cqe);
        return;
    }
    if (req == &m_sweep_timer.req)
    {
        m_sweep_timer.armed = false;
        if (!m_stopped)
            sweep();
        return;
    }
    if (req == &m_accept_backoff.req)
    {
        m_accept_backoff.armed = false;
        if (!m_stopped)
            arm_accept();
        return;
    }

    // Every other request belongs to a connection, named by the back-pointer
    // the submission carried, which is alive for as long as it is owed one.
    auto* raw = reinterpret_cast<conn*>(req->buffer);
    std::shared_ptr<conn> c;
    for (auto* pool : {&m_conns})
    {
        auto it = pool->find(raw->id);
        if (it != pool->end() && it->second.get() == raw)
            c = it->second;
    }
    if (!c)
        for (const auto& cl : m_closing)
            if (cl.get() == raw)
                c = cl;
    if (!c)
        return;

    switch (req->type)
    {
        case op_read:       read_done(c, cqe); break;
        case op_write:      write_done(c, cqe); break;
        case op_splice_file: splice_in_done(c, cqe); break;
        case op_splice:     splice_out_done(c, cqe); break;
        default: break;
    }
}

void storage_run::arm_accept()
{
    if (m_stopped || m_listen_fd < 0 || m_accept_pending)
        return;
    m_accept_req = io_request{};
    m_accept_req.owner = this;
    m_accept_req.type  = op_multishot_accept;
    if (!event_loop::supports_multishot_accept())
        m_accept_req.type = op_accept;
    const bool queued = m_accept_req.type == op_multishot_accept
        ? m_loop.submit_multishot_accept(m_listen_fd, &m_accept_req)
        : m_loop.submit_accept(m_listen_fd, nullptr, nullptr, &m_accept_req);
    if (queued)
    {
        m_accept_pending = true;
        return;
    }
    // Retried on a timer, because nothing else brings a deaf listener back.
    if (!m_accept_backoff.armed)
    {
        m_accept_backoff.ts  = {0, 100000000};
        m_accept_backoff.req = io_request{};
        m_accept_backoff.req.owner = this;
        m_accept_backoff.req.type  = op_timeout;
        if (m_loop.submit_timeout(&m_accept_backoff.ts, &m_accept_backoff.req))
            m_accept_backoff.armed = true;
    }
}

void storage_run::accept_done(struct io_uring_cqe* cqe)
{
    const bool more = (cqe->flags & IORING_CQE_F_MORE) != 0;
    if (!more)
        m_accept_pending = false;

    const int fd = cqe->res;
    if (fd >= 0)
    {
        if (m_stopped)
            m_loop.close_fd(fd);
        else
            adopt(fd);
    }
    else if (fd == -EMFILE || fd == -ENFILE)
    {
        // Out of descriptors: a hot re-arm would spin, so wait a moment.
        if (!m_accept_backoff.armed && !m_stopped)
        {
            m_accept_backoff.ts  = {0, 100000000};
            m_accept_backoff.req = io_request{};
            m_accept_backoff.req.owner = this;
            m_accept_backoff.req.type  = op_timeout;
            if (m_loop.submit_timeout(&m_accept_backoff.ts, &m_accept_backoff.req))
                m_accept_backoff.armed = true;
        }
        return;
    }

    if (!m_accept_pending && !m_stopped && !m_accept_backoff.armed && fd != -ECANCELED)
        arm_accept();
}

void storage_run::adopt(int fd)
{
    if (m_max_conns > 0 && m_conns.size() >= m_max_conns)
    {
        m_loop.close_fd(fd);
        return;
    }
    if (!m_owner.get_listen_path().empty())
        socketley::unix_sock::tune_stream(fd);

    auto c = std::make_shared<conn>();
    c->run = this;
    c->id  = m_next_id++;
    c->fd  = fd;
    c->last_progress = std::chrono::steady_clock::now();
    c->request_began = c->last_progress;
    m_conns.emplace(c->id, c);
    runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
    arm_sweep();
    arm_read(c);
}

void storage_run::arm_sweep()
{
    if (m_sweep_timer.armed || m_stopped)
        return;
    m_sweep_timer.ts  = {1, 0};
    m_sweep_timer.req = io_request{};
    m_sweep_timer.req.owner = this;
    m_sweep_timer.req.type  = op_timeout;
    if (m_loop.submit_timeout(&m_sweep_timer.ts, &m_sweep_timer.req))
        m_sweep_timer.armed = true;
}

void storage_run::sweep()
{
    const auto now = std::chrono::steady_clock::now();
    const uint32_t idle = m_owner.get_idle_timeout();
    std::vector<std::shared_ptr<conn>> victims;
    for (auto& [id, c] : m_conns)
    {
        const auto quiet = std::chrono::duration_cast<std::chrono::seconds>(now - c->last_progress).count();
        bool kill = false;
        switch (c->ph)
        {
            case phase::head:
                // A head that never finishes, and a keep-alive connection left idle.
                if (!c->in.empty())
                    kill = std::chrono::duration_cast<std::chrono::seconds>(now - c->request_began).count()
                           > http_header_deadline_secs;
                else if (idle > 0)
                    kill = quiet > static_cast<long>(idle);
                break;
            case phase::body_small:
            case phase::body_put:
            case phase::body_discard:
                kill = quiet > body_stall_secs;
                break;
            case phase::respond:
                kill = quiet > write_stall_secs;
                break;
        }
        if (kill)
            victims.push_back(c);
    }
    for (auto& c : victims)
    {
        ++m_c.timeouts;
        close_conn(c);
    }
    if (!m_conns.empty())
        arm_sweep();
}

void storage_run::on_turn()
{
    m_max_conns = m_owner.get_max_connections();
}

void storage_run::stop()
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
    if (m_sweep_timer.armed)
        m_loop.submit_timeout_remove(&m_sweep_timer.req);
    if (m_accept_backoff.armed)
        m_loop.submit_timeout_remove(&m_accept_backoff.req);

    std::vector<std::shared_ptr<conn>> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c);
    for (auto& c : all)
        close_conn(c);

    // Marked clean only when nothing is half done, which is decided inside.
    m_store.close(true);
    m_loop.flush();
    m_loop.deregister_owner(this);
}

// ─── Connection lifecycle ───────────────────────────────────────────────────

void storage_run::close_conn(const std::shared_ptr<conn>& c)
{
    if (c->dead)
        return;
    c->dead    = true;
    c->closing = true;

    // Aborted but not dropped: a receive may still be landing in its buffer.
    if (c->put)
        c->put->abort();
    if (c->file_fd >= 0)
    {
        m_loop.close_fd(c->file_fd);
        c->file_fd = -1;
    }
    pipe_release(*c);
    if (c->fd >= 0)
    {
        ::shutdown(c->fd, SHUT_RDWR);
        m_loop.close_fd(c->fd);
        c->fd = -1;
    }
    c->after_write = nullptr;
    c->on_body     = nullptr;

    m_conns.erase(c->id);
    if (c->rd_pending || c->wr_pending || c->sp_in_pending || c->sp_out_pending)
        m_closing.push_back(c);
}

void storage_run::maybe_release(const std::shared_ptr<conn>& c)
{
    if (!c->dead || c->rd_pending || c->wr_pending || c->sp_in_pending || c->sp_out_pending)
        return;
    auto it = std::find(m_closing.begin(), m_closing.end(), c);
    if (it != m_closing.end())
    {
        *it = std::move(m_closing.back());
        m_closing.pop_back();
    }
}

void storage_run::arm_read(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->rd_pending || c->fd < 0)
        return;

    char*    buf = c->rbuf;
    uint32_t len = static_cast<uint32_t>(conn::rbuf_size);
    c->rd_direct = false;

    switch (c->ph)
    {
        case phase::respond:
            return;
        case phase::body_put:
            if (!c->hook && !c->req.chunked && c->put && !c->put->failed() && c->put_failed == st::ok)
            {
                // Straight into the staging buffer: the bytes are hashed where
                // they land and written from there.
                const size_t room = c->put->stage_room();
                if (room == 0)
                    return;   // the put's ready callback arms this again
                char* p = c->put->stage_ptr();
                if (!p)
                    return;
                buf = p;
                len = static_cast<uint32_t>(std::min<uint64_t>({room, c->body_left, 1u << 20}));
                c->rd_direct = true;
                if (len == 0)
                    return;
            }
            else if (c->park_off < c->park.size())
                return;   // waiting for the put to take what is parked
            break;
        default:
            break;
    }

    c->rd_req = io_request{};
    c->rd_req.owner  = this;
    c->rd_req.type   = op_read;
    c->rd_req.buffer = reinterpret_cast<char*>(c.get());
    if (!m_loop.submit_read(c->fd, buf, len, &c->rd_req))
    {
        close_conn(c);
        return;
    }
    c->rd_pending = true;
}

void storage_run::read_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe)
{
    c->rd_pending = false;
    if (c->dead)
    {
        maybe_release(c);
        return;
    }
    const int res = cqe->res;
    if (res <= 0)
    {
        // The peer went, or the socket failed: whatever it was owed is moot.
        close_conn(c);
        return;
    }
    const size_t n = static_cast<size_t>(res);
    c->last_progress = std::chrono::steady_clock::now();
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, n);
    m_c.bytes_in += n;

    switch (c->ph)
    {
        case phase::head:
            if (c->in.empty())
                c->request_began = c->last_progress;
            c->in.append(c->rbuf, n);
            process_in(c);
            return;
        case phase::body_small:
            feed_small_body(c, c->rbuf, n);
            if (!c->dead && c->ph == phase::body_small)
                arm_read(c);
            return;
        case phase::body_put:
            if (c->rd_direct)
            {
                c->rd_direct = false;
                c->body_left -= n;
                if (c->put && !c->put->failed())
                    c->put->staged(n);
                if (c->dead)
                    return;
                if (c->put_failed != st::ok || c->ph != phase::body_put)
                {
                    arm_read(c);
                    return;
                }
                if (c->body_left == 0)
                    put_body_complete(c);
                else
                    arm_read(c);
                return;
            }
            put_body_bytes(c, c->rbuf, n);
            return;
        case phase::body_discard:
            if (n >= c->body_left)
            {
                // What follows the body is the next request.
                const size_t extra = n - static_cast<size_t>(c->body_left);
                c->body_left = 0;
                if (extra)
                    c->in.append(c->rbuf + (n - extra), extra);
            }
            else
                c->body_left -= n;
            if (c->body_left == 0)
            {
                s3_error e = c->body_error;
                send_error(c, e, false);
                return;
            }
            arm_read(c);
            return;
        case phase::respond:
            return;
    }
}

// ─── Writing ────────────────────────────────────────────────────────────────

void storage_run::queue_write(const std::shared_ptr<conn>& c, std::string data)
{
    if (c->dead || data.empty())
        return;
    if (c->wbuf.empty() && c->wq.empty())
        c->wbuf = std::move(data);
    else
        c->wq += data;
    pump_write(c);
}

void storage_run::pump_write(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->wr_pending)
        return;
    if (c->woff >= c->wbuf.size())
    {
        c->wbuf.clear();
        c->woff = 0;
        if (c->wq.empty())
            return;
        c->wbuf.swap(c->wq);
        c->wq.clear();
    }
    c->wr_req = io_request{};
    c->wr_req.owner  = this;
    c->wr_req.type   = op_write;
    c->wr_req.buffer = reinterpret_cast<char*>(c.get());
    if (!m_loop.submit_write(c->fd, c->wbuf.data() + c->woff,
                             static_cast<uint32_t>(std::min<size_t>(c->wbuf.size() - c->woff, 1u << 30)),
                             &c->wr_req))
    {
        close_conn(c);
        return;
    }
    c->wr_pending = true;
}

void storage_run::write_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe)
{
    c->wr_pending = false;
    if (c->dead)
    {
        maybe_release(c);
        return;
    }
    if (cqe->res <= 0)
    {
        close_conn(c);
        return;
    }
    c->woff += static_cast<size_t>(cqe->res);
    c->last_progress = std::chrono::steady_clock::now();
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(cqe->res));
    m_c.bytes_out += static_cast<uint64_t>(cqe->res);

    if (c->woff < c->wbuf.size() || !c->wq.empty())
    {
        pump_write(c);
        return;
    }
    c->wbuf.clear();
    c->woff = 0;
    if (c->after_write)
    {
        auto f = std::move(c->after_write);
        c->after_write = nullptr;
        f();
    }
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

std::string storage_run::response_head(const conn& c, const response& r) const
{
    static thread_local int64_t cached_sec = -1;
    static thread_local std::string cached_date;
    const int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now_s != cached_sec)
    {
        cached_sec  = now_s;
        cached_date = http_date(now_s * 1000);
    }

    std::string h;
    h.reserve(256 + r.headers.size() * 48);
    h += "HTTP/1.1 " + std::to_string(r.status) + " " + (r.reason.empty() ? reason_phrase(r.status) : r.reason) + "\r\n";
    h += "Server: Socketley\r\n";
    h += "Date: " + cached_date + "\r\n";
    h += "x-amz-request-id: " + c.req.request_id + "\r\n";
    h += "x-amz-id-2: " + c.req.request_id + "\r\n";
    for (const auto& [k, v] : r.headers)
        h += k + ": " + v + "\r\n";
    if (r.status != 204 && r.status != 304 && r.status != 100)
    {
        const uint64_t len = r.has_length_override ? r.length_override : r.body.size();
        h += "Content-Length: " + std::to_string(len) + "\r\n";
    }
    h += r.close ? "Connection: close\r\n" : "Connection: keep-alive\r\n";
    h += "\r\n";
    return h;
}

void storage_run::send_response(const std::shared_ptr<conn>& c, response r)
{
    if (c->dead)
        return;
    if (r.status >= 500)
        ++m_c.server_errors;
    else if (r.status >= 400)
        ++m_c.client_errors;
    r.close = r.close || !c->req.keep_alive;

    c->ph = phase::respond;
    std::string out = response_head(*c, r);
    if (!r.head_only)
        out += r.body;
    c->close_after_write = r.close;
    c->after_write = [this, c]() { finish_request(c); };
    queue_write(c, std::move(out));
}

void storage_run::send_error(const std::shared_ptr<conn>& c, const s3_error& e, bool close,
                             std::string_view extra_name, std::string_view extra_value)
{
    response r;
    r.status = e.status;
    r.close  = close;
    r.headers.emplace_back("Content-Type", "application/xml");
    const bool head = c->req.method == "HEAD";
    std::string resource = "/" + c->req.bucket;
    if (!c->req.key.empty())
        resource += "/" + c->req.key;
    if (head)
    {
        r.head_only           = true;
        r.has_length_override = true;
        r.length_override     = 0;
    }
    else
    {
        error_context ctx;
        ctx.bucket      = c->req.bucket;
        ctx.key         = c->req.key;
        ctx.resource    = resource;
        ctx.request_id  = c->req.request_id;
        ctx.extra_name  = extra_name;
        ctx.extra_value = extra_value;
        r.body = error_xml(e, ctx);
    }
    send_response(c, std::move(r));
}

void storage_run::send_error_st(const std::shared_ptr<conn>& c, st s)
{
    send_error(c, error_for(s));
}

void storage_run::reset_request(const std::shared_ptr<conn>& c)
{
    c->req = s3_request{};
    c->body.clear();
    c->body.shrink_to_fit();
    c->body_left = 0;
    c->chunk = http_chunked_decoder{};
    c->chunk_in.clear();
    c->on_body = nullptr;
    c->put.reset();
    c->hook.reset();
    c->park.clear();
    c->park_off = 0;
    c->put_fin_called = false;
    c->put_failed = st::ok;
    c->has_expected_md5 = false;
    c->body_refused = false;
    c->body_error = {};
    c->decoded_total = 0;
    c->sent_body = 0;
    c->rd_direct = false;
}

void storage_run::finish_request(const std::shared_ptr<conn>& c)
{
    if (c->dead)
        return;
    if (c->close_after_write)
    {
        close_conn(c);
        return;
    }
    if (c->file_fd >= 0)
    {
        m_loop.close_fd(c->file_fd);
        c->file_fd = -1;
    }
    pipe_release(*c);
    reset_request(c);
    c->close_after_write = false;
    c->ph = phase::head;
    c->last_progress = std::chrono::steady_clock::now();
    c->request_began = c->last_progress;
    // A pipelined request may already be waiting behind the one just answered.
    if (!c->in.empty())
        process_in(c);
    else
        arm_read(c);
}

void storage_run::process_in(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->ph != phase::head)
        return;

    const size_t end = c->in.find("\r\n\r\n");
    if (end == std::string::npos)
    {
        if (c->in.size() > max_head_bytes)
        {
            c->req.request_id = new_request_id();
            c->req.keep_alive = false;
            send_error(c, make_error("InvalidRequest"), true);
            return;
        }
        arm_read(c);
        return;
    }
    if (!parse_head(c, end + 4))
        return;
    c->in.erase(0, end + 4);
    ++m_c.requests;
    dispatch(c);
}

bool storage_run::parse_head(const std::shared_ptr<conn>& c, size_t head_len)
{
    s3_request& r = c->req;
    r = s3_request{};
    r.request_id = new_request_id();

    const std::string_view all(c->in.data(), head_len);
    auto bad = [&](std::string_view code, bool close = true)
    {
        r.keep_alive = !close;
        send_error(c, make_error(code), close);
        return false;
    };

    if (!http_eol_framing_ok(all, true))
        return bad("InvalidRequest");

    const size_t line_end = all.find("\r\n");
    const std::string_view line = all.substr(0, line_end);
    const size_t sp1 = line.find(' ');
    const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos)
        return bad("InvalidRequest");
    r.method  = std::string(line.substr(0, sp1));
    const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    r.version = std::string(line.substr(sp2 + 1));
    if (r.version != "HTTP/1.1" && r.version != "HTTP/1.0")
    {
        r.keep_alive = false;
        response resp;
        resp.status = 505;
        resp.close  = true;
        send_response(c, std::move(resp));
        return false;
    }
    if (target.empty() || target[0] != '/')
        return bad("InvalidRequest");

    // Everything after the request line and before the blank line.
    const std::string_view block = all.substr(line_end + 2, all.size() - line_end - 2 - 4 + 2);
    const http_request_framing_scan fr = http_scan_request_headers(
        block.size() >= 2 ? block.substr(0, block.size() - 2) : block);
    if (!fr.ok)
        return bad("InvalidRequest");
    r.has_content_length = fr.has_content_length;
    r.content_length     = fr.content_length;
    r.chunked            = fr.chunked;

    size_t pos = 0;
    std::string_view rest = all.substr(line_end + 2);
    while (pos < rest.size())
    {
        size_t nl = rest.find("\r\n", pos);
        if (nl == std::string_view::npos)
            break;
        const std::string_view hl = rest.substr(pos, nl - pos);
        pos = nl + 2;
        if (hl.empty())
            break;
        const size_t colon = hl.find(':');
        if (colon == std::string_view::npos)
            return bad("InvalidRequest");
        std::string name(hl.substr(0, colon));
        for (char& ch : name)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        r.headers.emplace_back(std::move(name), std::string(http_trim_ows(hl.substr(colon + 1))));
    }
    r.refs.reserve(r.headers.size());
    for (const auto& h : r.headers)
        r.refs.push_back({h.first, h.second});

    r.host         = std::string(r.header("host"));
    r.payload_hash = std::string(r.header("x-amz-content-sha256"));
    const std::string_view conn_hdr = r.header("connection");
    if (r.version == "HTTP/1.0")
        r.keep_alive = http_list_has_token(conn_hdr, "keep-alive", 10);
    else
        r.keep_alive = !http_list_has_token(conn_hdr, "close", 5);
    r.expect_continue = http_list_has_token(r.header("expect"), "100-continue", 12);

    const size_t q = target.find('?');
    r.raw_path  = std::string(target.substr(0, q));
    r.raw_query = q == std::string_view::npos ? std::string{} : std::string(target.substr(q + 1));

    std::string path;
    if (!percent_decode(r.raw_path, path, false))
        return bad("InvalidRequest");
    const std::string_view rest_path = std::string_view(path).substr(1);
    const size_t slash = rest_path.find('/');
    r.bucket = std::string(rest_path.substr(0, slash));
    r.key    = slash == std::string_view::npos ? std::string{} : std::string(rest_path.substr(slash + 1));

    // The query as key=value pairs, a bare key meaning an empty value -- which
    // is what marks a subresource such as ?delete.
    std::string_view qs = r.raw_query;
    while (!qs.empty())
    {
        const size_t amp = qs.find('&');
        const std::string_view part = qs.substr(0, amp);
        qs = amp == std::string_view::npos ? std::string_view{} : qs.substr(amp + 1);
        if (part.empty())
            continue;
        const size_t eq = part.find('=');
        std::string k, v;
        if (!percent_decode(part.substr(0, eq), k, true) ||
            !percent_decode(eq == std::string_view::npos ? std::string_view{} : part.substr(eq + 1), v, true))
            return bad("InvalidRequest");
        r.query.emplace_back(std::move(k), std::move(v));
    }
    return true;
}

// ─── Small bodies ───────────────────────────────────────────────────────────

void storage_run::collect_body(const std::shared_ptr<conn>& c, uint64_t limit, std::function<void()> done)
{
    c->ph         = phase::body_small;
    c->body.clear();
    c->body_limit = limit;
    c->on_body    = std::move(done);
    c->chunk      = http_chunked_decoder{};
    c->chunk_in.clear();

    if (c->req.has_content_length && c->req.content_length > limit)
    {
        c->req.keep_alive = false;
        send_error(c, make_error("EntityTooLarge"), true);
        return;
    }
    c->body_left = c->req.chunked ? 0 : c->req.content_length;
    if (!c->req.chunked && c->body_left == 0)
    {
        c->ph = phase::respond;
        if (c->hook)
        {
            std::string out;
            s3_error err;
            if (!c->hook->finish(out, err))
            {
                send_error(c, err, true);
                return;
            }
            c->body += out;
        }
        auto f = std::move(c->on_body);
        c->on_body = nullptr;
        f();
        return;
    }

    // What arrived with the head is the start of the body.
    std::string pre;
    pre.swap(c->in);
    if (!pre.empty())
        feed_small_body(c, pre.data(), pre.size());
    if (!c->dead && c->ph == phase::body_small)
        arm_read(c);
}

void storage_run::feed_small_body(const std::shared_ptr<conn>& c, const char* p, size_t n)
{
    auto fail = [&](std::string_view code)
    {
        c->req.keep_alive = false;
        send_error(c, make_error(code), true);
    };

    auto take = [&](std::string_view payload) -> bool
    {
        if (c->hook)
        {
            std::string out;
            s3_error err;
            if (!c->hook->feed(payload, out, err))
            {
                c->req.keep_alive = false;
                send_error(c, err, true);
                return false;
            }
            c->body += out;
        }
        else
            c->body.append(payload);
        if (c->body.size() > c->body_limit)
        {
            fail("EntityTooLarge");
            return false;
        }
        return true;
    };

    bool complete = false;
    if (!c->req.chunked)
    {
        const size_t k = static_cast<size_t>(std::min<uint64_t>(n, c->body_left));
        if (!take(std::string_view(p, k)))
            return;
        c->body_left -= k;
        if (k < n)
            c->in.append(p + k, n - k);
        complete = c->body_left == 0;
    }
    else
    {
        c->chunk_in.append(p, n);
        std::string_view view = c->chunk_in;
        for (;;)
        {
            std::string_view out;
            const chunk_step s = http_chunked_next(c->chunk, view, out);
            if (s == chunk_step::payload)
            {
                if (!take(out))
                    return;
                continue;
            }
            if (s == chunk_step::done)
            {
                complete = true;
                if (!view.empty())
                    c->in.append(view);
                view = {};
                c->chunk_in.clear();
                break;
            }
            if (s == chunk_step::bad)
            {
                fail("InvalidRequest");
                return;
            }
            break;
        }
        if (!complete)
            c->chunk_in.erase(0, c->chunk_in.size() - view.size());
    }
    if (!complete)
        return;

    c->ph = phase::respond;
    if (c->hook)
    {
        std::string out;
        s3_error err;
        if (!c->hook->finish(out, err))
        {
            c->req.keep_alive = false;
            send_error(c, err, true);
            return;
        }
        c->body += out;
    }
    auto f = std::move(c->on_body);
    c->on_body = nullptr;
    if (f)
        f();
}

// ─── A body streaming into an object ────────────────────────────────────────

void storage_run::begin_put_body(const std::shared_ptr<conn>& c, std::shared_ptr<put_op> op)
{
    c->put = std::move(op);
    c->ph  = phase::body_put;
    c->body_left = c->req.chunked ? 0 : c->req.content_length;
    c->chunk = http_chunked_decoder{};
    c->chunk_in.clear();
    c->park.clear();
    c->park_off = 0;
    ++m_c.puts;

    std::weak_ptr<conn> weak = c;
    c->put->on_ready([this, weak]()
    {
        auto cc = weak.lock();
        if (!cc || cc->dead || cc->ph != phase::body_put)
            return;
        if (cc->park_off < cc->park.size())
            put_drain_park(cc);
        else
            arm_read(cc);
    });
    c->put->on_failed([this, weak](st why)
    {
        auto cc = weak.lock();
        if (cc && !cc->dead)
            put_failed(cc, why);
    });

    if (c->req.expect_continue)
        queue_write(c, "HTTP/1.1 100 Continue\r\n\r\n");

    // The bytes that came with the head.
    std::string pre;
    pre.swap(c->in);
    if (!c->req.chunked && !c->hook && c->body_left == 0 && pre.empty())
    {
        put_body_complete(c);
        return;
    }
    if (!pre.empty())
    {
        put_body_bytes(c, pre.data(), pre.size());
        return;
    }
    arm_read(c);
}

void storage_run::put_body_bytes(const std::shared_ptr<conn>& c, const char* p, size_t n)
{
    if (c->dead)
        return;

    // Once the answer is decided the rest is read and dropped.
    if (c->put_failed != st::ok || c->body_refused)
    {
        // Counted against what is left.
        if (!c->req.chunked)
        {
            const size_t k = static_cast<size_t>(std::min<uint64_t>(n, c->body_left));
            c->body_left -= k;
            if (k < n)
                c->in.append(p + k, n - k);
            if (c->body_left == 0)
            {
                send_error(c, c->body_error, false);
                return;
            }
        }
        arm_read(c);
        return;
    }

    bool finished = false;
    auto deliver = [&](std::string_view payload) -> bool
    {
        if (c->hook)
        {
            s3_error err;
            if (!c->hook->feed(payload, c->park, err))
            {
                put_refused(c, err);
                return false;
            }
        }
        else
            c->park.append(payload);
        return true;
    };

    if (!c->req.chunked)
    {
        const size_t k = static_cast<size_t>(std::min<uint64_t>(n, c->body_left));
        c->body_left -= k;
        if (k < n)
            c->in.append(p + k, n - k);
        if (!deliver(std::string_view(p, k)))
            return;
        finished = c->body_left == 0;
    }
    else
    {
        c->chunk_in.append(p, n);
        std::string_view view = c->chunk_in;
        for (;;)
        {
            std::string_view out;
            const chunk_step s = http_chunked_next(c->chunk, view, out);
            if (s == chunk_step::payload)
            {
                if (!deliver(out))
                    return;
                continue;
            }
            if (s == chunk_step::done)
            {
                finished = true;
                if (!view.empty())
                    c->in.append(view);
                view = {};
                c->chunk_in.clear();
                break;
            }
            if (s == chunk_step::bad)
            {
                put_refused(c, make_error("InvalidRequest"));
                return;
            }
            break;
        }
        if (!finished)
            c->chunk_in.erase(0, c->chunk_in.size() - view.size());
    }
    c->put_fin_called = finished;
    put_drain_park(c);
}

void storage_run::put_drain_park(const std::shared_ptr<conn>& c)
{
    if (c->dead || !c->put)
        return;
    while (c->park_off < c->park.size())
    {
        if (c->put->failed() || c->put_failed != st::ok)
        {
            c->park.clear();
            c->park_off = 0;
            break;
        }
        const size_t took = c->put->append(c->park.data() + c->park_off, c->park.size() - c->park_off);
        c->park_off += took;
        if (took == 0)
            return;   // resumed by the put's ready callback
        if (c->dead)
            return;
    }
    c->park.clear();
    c->park_off = 0;
    if (c->put_failed != st::ok || c->body_refused)
    {
        // The failure callback ran inside the loop above and owns what follows.
        arm_read(c);
        return;
    }
    if (c->put_fin_called)
        put_body_complete(c);
    else
        arm_read(c);
}

void storage_run::put_body_complete(const std::shared_ptr<conn>& c)
{
    if (c->dead || !c->put)
        return;
    if (c->hook)
    {
        std::string out;
        s3_error err;
        if (!c->hook->finish(out, err))
        {
            put_refused(c, err);
            return;
        }
        c->park += out;
        if (!c->park.empty())
        {
            c->put_fin_called = true;
            put_drain_park(c);
            if (c->park_off < c->park.size() || c->dead)
                return;
        }
    }
    c->ph = phase::respond;
    const md5_t* expect = c->has_expected_md5 ? &c->expected_md5 : nullptr;
    uint64_t declared = 0;
    bool     check_len = false;
    if (c->hook)
        if (auto d = c->hook->decoded_length())
        {
            declared  = *d;
            check_len = true;
        }
    if (check_len && c->put->received() != declared)
    {
        c->put->abort();
        s3_error e = make_error("IncompleteBody");
        c->req.keep_alive = false;
        send_error(c, e, true);
        return;
    }
    std::weak_ptr<conn> weak = c;
    c->put->finish(expect, [this, weak](put_result r)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (r.status != st::ok)
        {
            // A body that failed after it was all read is answered on this
            // connection, which is still in step.
            send_error_st(cc, r.status);
            return;
        }
        response resp;
        resp.status = 200;
        resp.headers.emplace_back("ETag", "\"" + r.meta.etag() + "\"");
        send_response(cc, std::move(resp));
    });
}

void storage_run::put_failed(const std::shared_ptr<conn>& c, st why)
{
    if (c->dead || c->put_failed != st::ok)
        return;
    c->put_failed = why;
    c->body_error = error_for(why);
    if (c->ph != phase::body_put)
        return;   // the completion path answers it
    // The rest of the body is read and dropped when it is a size worth reading,
    // so the client hears the answer and not a reset.
    if (!c->req.chunked && c->body_left <= discard_limit)
    {
        c->park.clear();
        c->park_off = 0;
        c->ph = phase::body_discard;
        if (c->body_left == 0)
        {
            send_error(c, c->body_error, false);
            return;
        }
        arm_read(c);
        return;
    }
    c->req.keep_alive = false;
    send_error(c, c->body_error, true);
}

void storage_run::put_refused(const std::shared_ptr<conn>& c, const s3_error& e)
{
    if (c->dead || c->body_refused)
        return;
    c->body_refused = true;
    c->body_error   = e;
    if (c->put)
        c->put->abort();
    if (c->ph == phase::body_put && !c->req.chunked && c->body_left <= discard_limit)
    {
        c->park.clear();
        c->park_off = 0;
        c->ph = phase::body_discard;
        if (c->body_left == 0)
        {
            send_error(c, e, false);
            return;
        }
        arm_read(c);
        return;
    }
    c->req.keep_alive = false;
    send_error(c, e, true);
}

// ─── An object on its way out ───────────────────────────────────────────────

bool storage_run::pipe_acquire(conn& c)
{
    if (c.pipe_rd >= 0)
        return true;
    if (!m_pipes.empty())
    {
        c.pipe_rd = m_pipes.back().first;
        c.pipe_wr = m_pipes.back().second;
        m_pipes.pop_back();
        return true;
    }
    int fds[2];
    if (::pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0)
        return false;
    if (::fcntl(fds[0], F_SETPIPE_SZ, static_cast<int>(pipe_bytes)) < 0) {}
    c.pipe_rd = fds[0];
    c.pipe_wr = fds[1];
    const int sz = ::fcntl(fds[0], F_GETPIPE_SZ);
    c.pipe_size = sz > 0 ? static_cast<uint32_t>(sz) : 65536u;
    return true;
}

void storage_run::pipe_release(conn& c)
{
    if (c.pipe_rd < 0)
        return;
    // Back in the pool only when empty and unused; anything else is closed,
    // because a pipe with bytes in it would put them in the next stream.
    if (!c.dead && c.pipe_held == 0 && !c.sp_in_pending && !c.sp_out_pending && m_pipes.size() < 64)
        m_pipes.emplace_back(c.pipe_rd, c.pipe_wr);
    else
    {
        m_loop.close_fd(c.pipe_rd);
        m_loop.close_fd(c.pipe_wr);
    }
    c.pipe_rd = c.pipe_wr = -1;
    c.pipe_held = 0;
}

void storage_run::send_file(const std::shared_ptr<conn>& c, response head, int fd, uint64_t off, uint64_t len)
{
    if (c->dead)
    {
        m_loop.close_fd(fd);
        return;
    }
    if (head.status >= 400)
        ++m_c.client_errors;
    head.close = head.close || !c->req.keep_alive;
    head.head_only = true;
    head.has_length_override = true;
    head.length_override = len;

    c->file_fd   = fd;
    c->file_off  = off;
    c->file_left = len;
    c->ph        = phase::respond;
    c->close_after_write = head.close;
    // A body worth the pipe goes file to socket in the kernel, and the rest is
    // read here and written from memory.
    c->spliced = len >= m_zero_copy_min && pipe_acquire(*c);
    if (c->spliced)
        ++m_c.zero_copy_gets;
    else
        ++m_c.copied_gets;

    c->after_write = [this, c]() { file_pump(c); };
    queue_write(c, response_head(*c, head));
}

void storage_run::file_pump(const std::shared_ptr<conn>& c)
{
    if (c->dead)
        return;
    if (c->file_left == 0)
    {
        file_done(c);
        return;
    }

    if (c->spliced)
    {
        const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(c->file_left, c->pipe_size));
        c->sp_in_req = io_request{};
        c->sp_in_req.owner  = this;
        c->sp_in_req.buffer = reinterpret_cast<char*>(c.get());
        if (!m_loop.submit_splice_file(c->file_fd, c->file_off, c->pipe_wr, n, &c->sp_in_req))
        {
            close_conn(c);
            return;
        }
        c->sp_in_pending = true;
        return;
    }

    const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(c->file_left, stream_chunk));
    c->sbuf.resize(n);
    std::weak_ptr<conn> weak = c;
    if (!m_io.pread(c->file_fd, c->sbuf.data(), n, c->file_off,
            [this, weak](int64_t res)
            {
                auto cc = weak.lock();
                if (!cc || cc->dead)
                    return;
                stream_read_done(cc, res);
            }))
        close_conn(c);
}

void storage_run::stream_read_done(const std::shared_ptr<conn>& c, int64_t res)
{
    if (res <= 0)
    {
        // The file is shorter than its header said, and the response has
        // already promised more.
        close_conn(c);
        return;
    }
    c->file_off  += static_cast<uint64_t>(res);
    c->file_left -= static_cast<uint64_t>(res);
    c->after_write = [this, c]() { file_pump(c); };
    queue_write(c, std::string(c->sbuf.data(), static_cast<size_t>(res)));
}

void storage_run::splice_in_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe)
{
    c->sp_in_pending = false;
    if (c->dead)
    {
        maybe_release(c);
        return;
    }
    if (cqe->res <= 0)
    {
        close_conn(c);
        return;
    }
    c->file_off  += static_cast<uint64_t>(cqe->res);
    c->file_left -= static_cast<uint64_t>(cqe->res);
    c->pipe_held  = static_cast<uint64_t>(cqe->res);

    c->sp_out_req = io_request{};
    c->sp_out_req.owner  = this;
    c->sp_out_req.buffer = reinterpret_cast<char*>(c.get());
    if (!m_loop.submit_splice(c->pipe_rd, c->fd, static_cast<uint32_t>(c->pipe_held), &c->sp_out_req))
    {
        close_conn(c);
        return;
    }
    c->sp_out_pending = true;
}

void storage_run::splice_out_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe)
{
    c->sp_out_pending = false;
    if (c->dead)
    {
        maybe_release(c);
        return;
    }
    if (cqe->res <= 0)
    {
        close_conn(c);
        return;
    }
    const uint64_t n = static_cast<uint64_t>(cqe->res);
    c->pipe_held = c->pipe_held >= n ? c->pipe_held - n : 0;
    c->last_progress = std::chrono::steady_clock::now();
    m_c.bytes_out += n;
    m_c.zero_copy_bytes += n;
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, n);

    if (c->pipe_held > 0)
    {
        c->sp_out_req = io_request{};
        c->sp_out_req.owner  = this;
        c->sp_out_req.buffer = reinterpret_cast<char*>(c.get());
        if (!m_loop.submit_splice(c->pipe_rd, c->fd, static_cast<uint32_t>(c->pipe_held), &c->sp_out_req))
        {
            close_conn(c);
            return;
        }
        c->sp_out_pending = true;
        return;
    }
    file_pump(c);
}

void storage_run::file_done(const std::shared_ptr<conn>& c)
{
    finish_request(c);
}

}   // namespace socketley::storage
