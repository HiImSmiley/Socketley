#include "db_run.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "db_instance.h"
#include "../../shared/http_framing.h"
#include "../../shared/logging.h"
#include "../../shared/replaced_file.h"
#include "../../shared/runtime_manager.h"

namespace socketley::db
{

namespace
{

constexpr int64_t idle_secs = 120;
constexpr size_t  max_head  = 16 * 1024;
constexpr size_t  max_body  = 4u << 20;
constexpr size_t  max_conns = 4096;

int64_t now_sec()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

const char* reason(int status)
{
    switch (status)
    {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Content Too Large";
        case 415: return "Unsupported Media Type";
        case 431: return "Request Header Fields Too Large";
        case 503: return "Service Unavailable";
        case 507: return "Insufficient Storage";
        default:  return "Error";
    }
}

std::string error_body(std::string_view code, std::string_view message)
{
    std::string out = "{\"error\":";
    write_string(code, out);
    out += ",\"message\":";
    write_string(message, out);
    out += '}';
    return out;
}

db_run::answer refused(int status, std::string_view code, std::string_view message)
{
    return db_run::answer{status, error_body(code, message), 0, false};
}

db_run::answer refused(const error& e)
{
    return refused(e.status, e.code, e.message);
}

// A path's segment with its %XX spelled out; false for a % that spells nothing or a byte no id holds.
bool unescape(std::string_view in, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] != '%')
        {
            out += in[i];
            continue;
        }
        unsigned v = 0;
        if (i + 2 >= in.size() || std::from_chars(in.data() + i + 1, in.data() + i + 3, v, 16).ptr != in.data() + i + 3)
            return false;
        out += static_cast<char>(v);
        i += 2;
    }
    return true;
}

// The version an If-Match names, "3" or 3; 0 for none or one that is not a version.
uint64_t version_of(std::string_view tag)
{
    if (tag.size() >= 2 && tag.front() == '"' && tag.back() == '"')
        tag = tag.substr(1, tag.size() - 2);
    uint64_t v = 0;
    const auto r = std::from_chars(tag.data(), tag.data() + tag.size(), v);
    return r.ec == std::errc() && r.ptr == tag.data() + tag.size() ? v : 0;
}

int64_t mtime_of(const std::string& path)
{
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
        return 0;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec + static_cast<int64_t>(st.st_size);
}

const jvalue* string_member(const jvalue& obj, std::string_view name)
{
    const jvalue* m = member(obj, name);
    return m && m->k == jvalue::kind::string ? m : nullptr;
}

}   // namespace

db_run::db_run(db_instance& owner, event_loop& loop) : m_owner(owner), m_loop(loop), m_io(loop, this) {}

db_run::~db_run()
{
    m_loop.deregister_owner(this);
}

bool db_run::start(std::string& why)
{
    if (!m_store.open(db_data_dir(m_owner.get_name()), why))
        return false;
    m_store.set_max_bytes(m_owner.get_max_bytes());
    reload_files(true, why);
    if (!why.empty())
        return false;
    m_idp.configure(m_owner.get_idp());
    for (std::string_view list = m_owner.get_origins(); !list.empty();)
    {
        const size_t comma = list.find(',');
        const std::string_view one = http_trim_ows(list.substr(0, comma));
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        if (!one.empty())
            m_origins.emplace_back(one);
    }

    const uint16_t port = m_owner.effective_port();
    m_listen_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = m_owner.bind_in_addr();
    a.sin_port = htons(port);
    if (::bind(m_listen_fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(m_listen_fd, 1024) < 0)
    {
        why = "port " + std::to_string(port) + " could not be bound: " + std::strerror(errno);
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    m_loop.register_owner(this);
    arm_accept();
    LOG_INFO(("db " + std::string(m_owner.get_name()) + ": " + std::to_string(m_store.documents()) +
              " document(s) in " + std::to_string(m_store.collections()) + " collection(s), " +
              std::to_string(m_keys.size()) + " key(s)" +
              (m_owner.get_idp().empty() ? "" : ", accounts of " + std::string(m_owner.get_idp())))
                 .c_str());
    return true;
}

void db_run::stop()
{
    if (m_stopped)
        return;
    // What was written is on the disk before anything goes, and nothing more is read to write; a sync in flight is
    // made again here, and its answers given, since its completion comes after this run is done answering.
    m_stopped = true;
    m_held.insert(m_held.begin(), m_syncing.begin(), m_syncing.end());
    m_held_calls.insert(m_held_calls.begin(), m_syncing_calls.begin(), m_syncing_calls.end());
    m_syncing.clear();
    m_syncing_calls.clear();
    finish_turn();
    if (m_listen_fd >= 0)
    {
        ::shutdown(m_listen_fd, SHUT_RDWR);
        m_loop.close_fd(m_listen_fd);
        m_listen_fd = -1;
    }
    std::vector<std::shared_ptr<conn>> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c);
    for (auto& c : all)
        close_conn(c);
    m_store.close();
}

bool db_run::drained() const
{
    return m_loop.owner_inflight(this) == 0 && !m_loop.owner_table_full();
}

void db_run::on_loop_turn()
{
    finish_turn();
    // A listener whose accept the ring had no room for is asked again here, or it would be deaf for good.
    if (!m_accept_pending && !m_stopped)
        arm_accept();
}

void db_run::finish_turn()
{
    if (m_held.empty() && m_held_calls.empty())
        return;
    // One sync on the disk at a time; what was written meanwhile waits for the next, which starts when it ends.
    if (m_sync_inflight && !m_stopped)
        return;
    std::vector<std::shared_ptr<conn>> held;
    held.swap(m_held);
    std::vector<std::pair<uint64_t, std::string>> calls;
    calls.swap(m_held_calls);
    ++m_c.syncs;
    if (m_broken || !m_store.flush())
    {
        answer_synced(held, calls, false);
        return;
    }
    // Stopping, the last records are synced here and now, since no completion will be waited for.
    if (m_stopped || m_store.journal_fd() < 0)
    {
        answer_synced(held, calls, m_store.sync());
        return;
    }
    m_syncing = std::move(held);
    m_syncing_calls = std::move(calls);
    m_sync_inflight = true;
    const bool queued = m_io.fsync(m_store.journal_fd(), true, [this](int64_t res) {
        m_sync_inflight = false;
        // A stop answered these itself, with a sync of its own.
        if (m_stopped)
            return;
        std::vector<std::shared_ptr<conn>> done;
        done.swap(m_syncing);
        std::vector<std::pair<uint64_t, std::string>> done_calls;
        done_calls.swap(m_syncing_calls);
        answer_synced(done, done_calls, res == 0);
        finish_turn();
    });
    if (!queued)
    {
        // The ring had no room: the sync is made here instead, which only blocks the loop for it.
        m_sync_inflight = false;
        std::vector<std::shared_ptr<conn>> done;
        done.swap(m_syncing);
        std::vector<std::pair<uint64_t, std::string>> done_calls;
        done_calls.swap(m_syncing_calls);
        answer_synced(done, done_calls, m_store.sync());
    }
}

void db_run::answer_synced(std::vector<std::shared_ptr<conn>>& held,
                           std::vector<std::pair<uint64_t, std::string>>& calls, bool ok)
{
    if (!ok && !m_broken)
    {
        m_broken = true;
        LOG_ERROR(("db " + std::string(m_owner.get_name()) +
                   ": the journal could not be written to the disk; nothing more is answered until a restart reads "
                   "back what is there")
                      .c_str());
    }
    for (auto& c : held)
    {
        if (c->dead)
            continue;
        if (ok)
            c->out += c->held;
        else
        {
            c->keep_alive = false;
            const std::string body = error_body("not_durable", "the change could not be written to the disk");
            c->out += head(*c, 503, "application/json", body.size(), {});
            c->out += body;
        }
        c->held.clear();
        if (!m_stopped)
            resume(c);
    }
    auto* mgr = m_owner.get_runtime_manager();
    for (auto& [ticket, reply] : calls)
        if (mgr)
            mgr->requests().complete_deferred(
                ticket, request_status::ok,
                ok ? reply
                   : "{\"status\":503,\"body\":" +
                         error_body("not_durable", "the change could not be written to the disk") + "}");
}

std::string db_run::stats() const
{
    return "documents:" + std::to_string(m_store.documents()) + "\ncollections:" + std::to_string(m_store.collections()) +
           "\nbytes:" + std::to_string(m_store.bytes()) + "\nmax_bytes:" + std::to_string(m_owner.get_max_bytes()) +
           "\nkeys:" + std::to_string(m_keys.size()) + "\nreads:" + std::to_string(m_c.reads) +
           "\nwrites:" + std::to_string(m_c.writes) + "\nqueries:" + std::to_string(m_c.queries) +
           "\nsyncs:" + std::to_string(m_c.syncs) + "\nrefused:" + std::to_string(m_c.refused) +
           "\nconflicts:" + std::to_string(m_c.conflicts) + "\nscript_calls:" + std::to_string(m_c.calls) +
           "\njournal_records:" + std::to_string(m_store.journal_records()) +
           (m_broken ? "\nbroken:the journal could not be synced; restart" : "") +
           (m_schema_error.empty() ? std::string() : "\nschema_error:" + m_schema_error) +
           (m_keys_error.empty() ? std::string() : "\nkeys_error:" + m_keys_error) + "\n";
}

void db_run::reload_files(bool first, std::string& why)
{
    const int64_t now = now_sec();
    if (!first && now == m_files_checked)
        return;
    m_files_checked = now;
    if (const std::string path(m_owner.get_schema_path()); !path.empty())
    {
        if (const int64_t mt = mtime_of(path); mt != m_schema_mtime)
        {
            m_schema_mtime = mt;
            std::string text, err;
            schema s;
            if (!read_whole_file(path, text))
                err = path + " cannot be read";
            else if (!parse_schema(text, s, err))
                err = path + " " + err;
            else if (!m_store.set_schema(s, err))
                err = path + ": " + err;
            if (!err.empty() && first)
                why = err;
            else if (!err.empty())
                LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": " + err + "; the schema before is kept").c_str());
            m_schema_error = err;
        }
    }
    if (const std::string path(m_owner.get_keys_path()); !path.empty())
    {
        if (const int64_t mt = mtime_of(path); mt != m_keys_mtime)
        {
            m_keys_mtime = mt;
            std::string text, err;
            std::vector<service_key> keys;
            if (!read_whole_file(path, text))
                err = path + " cannot be read";
            else if (!parse_keys(text, keys, err))
                err = path + " " + err;
            else
                m_keys = std::move(keys);
            if (!err.empty() && first && why.empty())
                why = err;
            else if (!err.empty())
                LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": " + err + "; the keys before are kept").c_str());
            m_keys_error = err;
        }
    }
}

// ─── Connections ────────────────────────────────────────────────────────────

void db_run::arm_accept()
{
    if (m_stopped || m_listen_fd < 0 || m_accept_pending)
        return;
    m_accept_req = io_request{};
    m_accept_req.owner = this;
    m_accept_req.fd = m_listen_fd;
    m_accept_req.type = event_loop::supports_multishot_accept() ? op_multishot_accept : op_accept;
    m_accept_pending = m_accept_req.type == op_multishot_accept
                           ? m_loop.submit_multishot_accept(m_listen_fd, &m_accept_req)
                           : m_loop.submit_accept(m_listen_fd, nullptr, nullptr, &m_accept_req);
}

void db_run::accept_done(struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
        m_accept_pending = false;
    const int fd = cqe->res;
    if (fd >= 0)
    {
        const size_t limit = m_owner.get_max_connections() ? m_owner.get_max_connections() : max_conns;
        if (m_stopped || m_conns.size() >= limit)
            m_loop.close_fd(fd);
        else
        {
            auto c = std::make_shared_for_overwrite<conn>();
            c->id = m_next_id++;
            c->fd = fd;
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->last = now_sec();
            m_conns.emplace(c->id, c);
            runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
            m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            arm_read(c);
            arm_tick();
        }
    }
    if (!m_accept_pending && !m_stopped && fd != -ECANCELED)
        arm_accept();
}

std::shared_ptr<db_run::conn> db_run::conn_of(io_request* req)
{
    auto* raw = reinterpret_cast<conn*>(req->buffer);
    if (auto it = m_conns.find(raw->id); it != m_conns.end() && it->second.get() == raw)
        return it->second;
    for (const auto& c : m_closing)
        if (c.get() == raw)
            return c;
    return nullptr;
}

void db_run::on_cqe(struct io_uring_cqe* cqe)
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
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        tick();
        return;
    }
    auto c = conn_of(req);
    if (!c)
        return;
    if (req == &c->rd)
        read_done(c, cqe->res);
    else if (req == &c->wr)
        write_done(c, cqe->res);
}

void db_run::arm_read(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->rd_pending || c->fd < 0)
        return;
    c->rd = io_request{};
    c->rd.owner = this;
    c->rd.buffer = reinterpret_cast<char*>(c.get());
    c->rd.fd = c->fd;
    c->rd.type = op_read;
    c->rd_pending = m_loop.submit_read(c->fd, c->rbuf, sizeof c->rbuf, &c->rd);
    if (!c->rd_pending)
        close_conn(c);
}

void db_run::read_done(const std::shared_ptr<conn>& c, int res)
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
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, static_cast<uint64_t>(res));
    serve(c);
    if (!c->dead && !c->waiting)
        arm_read(c);
}

// Requests in order, one at a time: a write's answer waits for the turn's sync and holds those behind it.
void db_run::serve(const std::shared_ptr<conn>& c)
{
    while (!c->dead && !c->waiting && !c->in.empty())
    {
        request rq;
        int refusal = 400;
        const int r = take_request(*c, rq, refusal);
        if (r == 0)
            break;
        if (r < 0)
        {
            c->keep_alive = false;
            respond(c, refusal, error_body("bad_request", "the request could not be read"));
            break;
        }
        runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
        handle(c, rq);
    }
    flush(c);
}

void db_run::resume(const std::shared_ptr<conn>& c)
{
    c->waiting = false;
    serve(c);
    if (!c->dead && !c->waiting)
        arm_read(c);
}

void db_run::flush(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->wr_pending)
        return;
    if (c->out_off >= c->out.size())
    {
        c->out.clear();
        c->out_off = 0;
        if (!c->keep_alive && !c->waiting)
            close_conn(c);
        return;
    }
    c->wr = io_request{};
    c->wr.owner = this;
    c->wr.buffer = reinterpret_cast<char*>(c.get());
    c->wr.fd = c->fd;
    c->wr.type = op_write;
    const size_t chunk = std::min<size_t>(c->out.size() - c->out_off, 1u << 20);
    c->wr_pending = m_loop.submit_write(c->fd, c->out.data() + c->out_off, static_cast<uint32_t>(chunk), &c->wr);
    if (!c->wr_pending)
        close_conn(c);
}

void db_run::write_done(const std::shared_ptr<conn>& c, int res)
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
    c->out_off += static_cast<size_t>(res);
    c->last = now_sec();
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(res));
    flush(c);
}

void db_run::close_conn(const std::shared_ptr<conn>& c)
{
    if (c->dead)
        return;
    c->dead = true;
    if (c->fd >= 0)
    {
        ::shutdown(c->fd, SHUT_RDWR);
        m_loop.close_fd(c->fd);
        c->fd = -1;
    }
    m_conns.erase(c->id);
    m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
    if (c->rd_pending || c->wr_pending)
        m_closing.push_back(c);
}

// Once a second while connections are open, for the idle ones; an idle database is woken by nothing.
void db_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {1, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void db_run::tick()
{
    if (m_stopped)
        return;
    const int64_t now = now_sec();
    std::vector<std::shared_ptr<conn>> idle;
    for (auto& [id, c] : m_conns)
        if (now - c->last > idle_secs && !c->waiting && c->out_off >= c->out.size())
            idle.push_back(c);
    for (auto& c : idle)
        close_conn(c);
    if (!m_conns.empty())
        arm_tick();
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

int db_run::take_request(conn& c, request& rq, int& refusal)
{
    const size_t end = c.in.find("\r\n\r\n");
    if (end == std::string::npos)
    {
        if (c.in.size() > max_head)
        {
            refusal = 431;
            return -1;
        }
        return 0;
    }
    const std::string_view head(c.in.data(), end + 2);
    if (!http_eol_framing_ok(head, true))
        return -1;
    const size_t line_end = head.find("\r\n");
    const std::string_view line = head.substr(0, line_end);
    const size_t sp1 = line.find(' ');
    const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos)
        return -1;
    rq.method.assign(line.substr(0, sp1));
    const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string_view version = line.substr(sp2 + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0")
        return -1;
    rq.path.assign(target.substr(0, target.find('?')));

    const std::string_view fields = head.substr(line_end + 2);
    const http_request_framing_scan scan = http_scan_request_headers(fields);
    if (!scan.ok || scan.transfer_encoding)
    {
        refusal = scan.ok ? 411 : 400;
        return -1;
    }
    bool close = version == "HTTP/1.0";
    size_t pos = 0;
    while (pos < fields.size())
    {
        size_t nl = fields.find("\r\n", pos);
        if (nl == std::string_view::npos)
            nl = fields.size();
        const std::string_view f = fields.substr(pos, nl - pos);
        pos = nl + 2;
        const size_t colon = f.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view value = http_trim_ows(f.substr(colon + 1));
        if (header_name_equals(f, "cookie", 6))
        {
            if (!rq.cookie.empty())
                rq.cookie += "; ";
            rq.cookie.append(value);
        }
        else if (header_name_equals(f, "authorization", 13))
            rq.authorization.assign(value);
        else if (header_name_equals(f, "content-type", 12))
            rq.content_type.assign(value);
        else if (header_name_equals(f, "if-match", 8))
            rq.if_match.assign(value);
        else if (header_name_equals(f, "if-none-match", 13))
            rq.if_none_match.assign(value);
        else if (header_name_equals(f, "origin", 6))
            rq.origin.assign(value);
        else if (header_name_equals(f, "host", 4))
            rq.host.assign(value);
        else if (header_name_equals(f, "connection", 10))
        {
            if (http_list_has_token(value, "close", 5))
                close = true;
            else if (http_list_has_token(value, "keep-alive", 10))
                close = false;
        }
    }
    const size_t body_len = scan.has_content_length ? scan.content_length : 0;
    if (body_len > max_body)
    {
        refusal = 413;
        return -1;
    }
    if (c.in.size() < end + 4 + body_len)
        return 0;
    rq.body.assign(c.in, end + 4, body_len);
    c.in.erase(0, end + 4 + body_len);
    c.keep_alive = !close;
    return 1;
}

std::string db_run::head(const conn& c, int status, std::string_view type, size_t length, std::string_view extra) const
{
    std::string o = "HTTP/1.1 " + std::to_string(status) + " " + reason(status) + "\r\nContent-Type: ";
    o += type;
    o += "\r\nContent-Length: ";
    o += std::to_string(length);
    o += "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
    o += extra;
    if (!c.keep_alive)
        o += "Connection: close\r\n";
    o += "\r\n";
    return o;
}

void db_run::respond(const std::shared_ptr<conn>& c, int status, std::string_view body, std::string_view extra)
{
    if (status >= 400)
        ++m_c.refused;
    c->out += head(*c, status, "application/json", body.size(), extra);
    c->out += body;
}

std::string db_run::cors(const request& rq) const
{
    if (rq.origin.empty())
        return {};
    for (const auto& o : m_origins)
    {
        // A named origin is answered with the browser's credentials; `*` lets any page in, but not with them.
        if (o == rq.origin)
            return "Access-Control-Allow-Origin: " + rq.origin +
                   "\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Expose-Headers: ETag\r\nVary: Origin\r\n";
        if (o == "*")
            return "Access-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: ETag\r\n";
    }
    return "Vary: Origin\r\n";
}

bool db_run::who_of(const request& rq, principal& who, bool& by_cookie, std::string& refusal)
{
    by_cookie = false;
    if (!rq.authorization.empty())
    {
        std::string_view a = rq.authorization;
        if (!a.starts_with("Bearer ") && !a.starts_with("bearer "))
        {
            refusal = "Authorization takes Bearer and a key's secret or the provider's access token";
            return false;
        }
        const std::string_view token = http_trim_ows(a.substr(7));
        for (const auto& k : m_keys)
            if (k.secret.size() == token.size() && CRYPTO_memcmp(k.secret.data(), token.data(), token.size()) == 0)
            {
                who = principal{principal::key, k.name};
                return true;
            }
        socketley::idp::session_verifier::who w;
        if (m_idp.check_bearer(token, w))
        {
            who = principal{principal::user, w.sub};
            return true;
        }
        refusal = "the bearer token is no key of this database and no access token of its provider";
        return false;
    }
    socketley::idp::session_verifier::who w;
    if (!rq.cookie.empty() && m_idp.check(rq.cookie, w))
    {
        who = principal{principal::user, w.sub};
        by_cookie = true;
        return true;
    }
    who = principal{};
    return true;
}

void db_run::handle(const std::shared_ptr<conn>& c, request& rq)
{
    std::string ignored;
    reload_files(false, ignored);
    const std::string allow = cors(rq);
    if (rq.method == "OPTIONS")
    {
        // A browser's preflight, answered for an origin this database answers at all.
        respond(c, 204, "",
                allow + (allow.starts_with("Access-Control-Allow-Origin")
                             ? "Access-Control-Allow-Methods: GET, PUT, PATCH, DELETE, POST\r\n"
                               "Access-Control-Allow-Headers: Authorization, Content-Type, If-Match, If-None-Match\r\n"
                               "Access-Control-Max-Age: 600\r\n"
                             : ""));
        return;
    }
    principal who;
    bool by_cookie = false;
    std::string why;
    if (!who_of(rq, who, by_cookie, why))
    {
        respond(c, 401, error_body("bad_credentials", why), allow + "WWW-Authenticate: Bearer\r\n");
        return;
    }
    const bool reads = rq.method == "GET" || rq.method == "HEAD";
    // A browser's cookie goes along with a form another page posts, which can say neither JSON nor this host.
    if (by_cookie && !reads)
    {
        const bool json = rq.content_type.starts_with("application/json") || rq.method == "DELETE";
        const bool same_site = rq.origin.empty() || rq.origin == "https://" + rq.host ||
                               rq.origin == "http://" + rq.host ||
                               std::find(m_origins.begin(), m_origins.end(), rq.origin) != m_origins.end();
        if (!json || !same_site)
        {
            respond(c, json ? 403 : 415,
                    error_body("cross_site", "a write signed in by the cookie is sent as application/json from this "
                                             "host or an origin of --origins"),
                    allow);
            return;
        }
    }
    if (rq.path == "/me")
    {
        if (who.kind == principal::anyone)
            respond(c, 401, error_body("sign_in", "nobody is signed in"), allow);
        else
        {
            std::string body = who.kind == principal::key ? "{\"key\":" : "{\"sub\":";
            write_string(who.sub, body);
            body += '}';
            respond(c, 200, body, allow);
        }
        return;
    }
    if (rq.path == "/" && reads)
    {
        std::string body = "{\"database\":";
        write_string(m_owner.get_name(), body);
        if (who.kind == principal::key)
        {
            body += ",\"collections\":[";
            bool first = true;
            for (const auto& name : m_store.collection_names())
            {
                body += first ? "" : ",";
                first = false;
                write_string(name, body);
            }
            body += ']';
        }
        body += '}';
        respond(c, 200, body, allow);
        return;
    }
    std::string path;
    if (!unescape(rq.path, path))
    {
        respond(c, 400, error_body("bad_path", "the path holds a % that spells no byte"), allow);
        return;
    }
    answer a = execute(who, rq.method, path, rq.body, rq.if_match, rq.if_none_match);
    std::string extra = allow;
    if (a.version)
        extra += "ETag: \"" + std::to_string(a.version) + "\"\r\n";
    if (rq.method == "HEAD")
        a.body.clear();
    if (!a.durable)
    {
        respond(c, a.status, a.body, extra);
        return;
    }
    c->held = head(*c, a.status, "application/json", a.body.size(), extra) + a.body;
    c->waiting = true;
    m_held.push_back(c);
}

db_run::answer db_run::execute(const principal& who, std::string_view method, std::string_view path,
                               std::string_view body, std::string_view if_match, std::string_view if_none_match)
{
    if (m_broken)
        return refused(503, "not_durable", "the journal could not be written to the disk; restart the database");
    const auto parse_body = [&](jvalue& out) {
        return json_reader(body).document(out);
    };
    std::vector<write_op> ops;
    error err;
    std::string coll, id;
    bool is_tx = false;
    if (path == "/tx")
    {
        if (method != "POST")
            return refused(405, "method", "a transaction is POSTed");
        is_tx = true;
        jvalue doc;
        const jvalue* list = nullptr;
        if (!parse_body(doc) || !(list = member(doc, "ops")) || list->k != jvalue::kind::array)
            return refused(400, "bad_write", "a transaction is {\"ops\":[...]}");
        for (const auto& o : list->items)
        {
            write_op op;
            const jvalue* kind = string_member(o, "op");
            const jvalue* c = string_member(o, "c");
            const jvalue* i = string_member(o, "id");
            if (!kind || !c)
                return refused(400, "bad_write", "each change names its op and its collection, c");
            op.coll = c->s;
            op.id = i ? i->s : std::string();
            if (kind->s == "put" || kind->s == "insert")
            {
                op.kind = kind->s == "put" ? write_op::put : write_op::insert;
                const jvalue* d = member(o, "doc");
                if (!d)
                    return refused(400, "bad_write", "a put or an insert carries its doc");
                op.body = *d;
            }
            else if (kind->s == "patch")
            {
                op.kind = write_op::patch;
                const jvalue* d = member(o, "changes");
                if (!d)
                    return refused(400, "bad_write", "a patch carries its changes");
                op.body = *d;
            }
            else if (kind->s == "delete")
                op.kind = write_op::del;
            else
                return refused(400, "bad_write", "an op is put, insert, patch or delete");
            if (const jvalue* v = member(o, "if"))
                op.if_v = version_of(v->s);
            if (const jvalue* v = member(o, "if_absent"); v && v->k == jvalue::kind::boolean)
                op.if_absent = v->b;
            ops.push_back(std::move(op));
        }
    }
    else
    {
        if (!path.starts_with("/c/"))
            return refused(404, "not_found", "the API is /c/<collection>[/<id>|/_query] and /tx");
        std::string_view rest = path.substr(3);
        const size_t slash = rest.find('/');
        coll = std::string(rest.substr(0, slash));
        id = slash == std::string_view::npos ? std::string() : std::string(rest.substr(slash + 1));
        if (!valid_collection(coll))
            return refused(400, "bad_collection", "a collection's name is 1 to 64 of a-z 0-9 _ -, a letter first");
        if (id == "_query")
        {
            if (method != "POST")
                return refused(405, "method", "a query is POSTed");
            jvalue q;
            query parsed;
            if (!body.empty() && !parse_body(q))
                return refused(400, "bad_query", "a query is a JSON object");
            if (!body.empty() && !store::parse_query(q, parsed, err))
                return refused(err);
            answer a;
            if (!m_store.find(who, coll, parsed, a.body, err))
                return refused(err);
            ++m_c.queries;
            return a;
        }
        if (id.empty())
        {
            if (method != "POST")
                return refused(405, "method", "a document is POSTed to its collection, or PUT at its id");
            write_op op;
            op.kind = write_op::insert;
            op.coll = coll;
            if (!parse_body(op.body))
                return refused(400, "bad_document", "a document is a JSON object");
            ops.push_back(std::move(op));
        }
        else if (method == "GET" || method == "HEAD")
        {
            answer a;
            if (!m_store.read(who, coll, id, a.body, err))
                return refused(err);
            if (const doc* d = m_store.get(coll, id))
                a.version = d->v;
            ++m_c.reads;
            return a;
        }
        else
        {
            write_op op;
            op.coll = coll;
            op.id = id;
            op.if_v = version_of(if_match);
            if (!if_match.empty() && !op.if_v && if_match != "*")
                return refused(400, "bad_precondition", "If-Match names a version, \"3\"");
            if (method == "PUT")
            {
                op.kind = write_op::put;
                op.if_absent = if_none_match == "*";
                if (!parse_body(op.body))
                    return refused(400, "bad_document", "a document is a JSON object");
            }
            else if (method == "PATCH")
            {
                op.kind = write_op::patch;
                if (!parse_body(op.body))
                    return refused(400, "bad_patch", "a patch is a JSON object of set, unset, inc, push and pull");
            }
            else if (method == "DELETE")
                op.kind = write_op::del;
            else
                return refused(405, "method", "a document is read with GET and written with PUT, PATCH and DELETE");
            ops.push_back(std::move(op));
        }
    }

    const bool existed = !is_tx && ops[0].kind == write_op::put && m_store.get(coll, ops[0].id);
    answer a;
    std::string out;
    if (!m_store.write(who, ops, out, err))
    {
        if (err.status == 409 || err.status == 412)
            ++m_c.conflicts;
        return refused(err);
    }
    ++m_c.writes;
    a.durable = true;
    if (is_tx)
    {
        a.body = "{\"results\":" + out + "}";
        return a;
    }
    // One change: its document, or its deletion, not the list a transaction answers.
    a.body = out.substr(1, out.size() - 2);
    if (ops[0].kind != write_op::del)
    {
        if (const doc* d = m_store.get(coll, ops[0].id))
            a.version = d->v;
        if (ops[0].kind == write_op::insert || (ops[0].kind == write_op::put && !existed))
            a.status = 201;
    }
    return a;
}

void db_run::call(uint64_t ticket, std::string_view json)
{
    ++m_c.calls;
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    jvalue req;
    answer a;
    const jvalue* method = nullptr;
    const jvalue* path = nullptr;
    if (!json_reader(json).document(req) || !(method = string_member(req, "method")) ||
        !(path = string_member(req, "path")))
        a = refused(400, "bad_call", "a call is {\"method\":..,\"path\":..[,\"body\":..]}");
    else
    {
        std::string body;
        if (const jvalue* b = member(req, "body"))
            write_json(*b, body);
        const jvalue* im = string_member(req, "if_match");
        const jvalue* inm = string_member(req, "if_none_match");
        // A script of this daemon is the operator's own code, as a key is.
        a = execute(principal{principal::key, "script"}, method->s, path->s, body, im ? im->s : std::string_view{},
                    inm ? inm->s : std::string_view{});
    }
    std::string reply = "{\"status\":" + std::to_string(a.status) + ",\"body\":" + (a.body.empty() ? "null" : a.body) + "}";
    if (a.durable)
        m_held_calls.emplace_back(ticket, std::move(reply));
    else
        mgr->requests().complete_deferred(ticket, request_status::ok, reply);
}

}   // namespace socketley::db
