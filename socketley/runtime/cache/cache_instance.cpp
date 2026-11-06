#include "../../shared/net/socket_tuning.h"
#include "../../shared/loop/conn_alloc.h"
#include "cache_instance.h"

#include <bit>
#include "../../shared/ipc/worker_protocol.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/net/conn_reachability.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/ipc/exit_bound.h"
#include "resp_command_table.h"
#include <random>
#include "../../shared/net/dial_address.h"
#include "../../shared/ipc/ipc_framing.h"
#include "../../shared/util/trace.h"
#include "resp_parser.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/turn_clock.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/lua/lua_context.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/invariants.h"
#include "../../shared/net/unix_listener.h"
#include "../../cli/command_hashing.h"
#include "../../shared/ipc/shard_target.h"
#include "../../shared/util/version.h"

#include <unistd.h>
#include <cmath>
#include <cstring>
#include <cerrno>
#include "../../shared/util/glob_match.h"
#include "../../shared/util/wall_clock.h"
#include "../../shared/util/number_parse.h"
#include "../../shared/ipc/one_command.h"
#include "../../shared/util/settings.h"
#include <cstdlib>
#include <cstdio>
#include <charconv>
#include <iostream>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <liburing.h>
#include <fstream>
#include <sstream>
#include <limits>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <dirent.h>
#include <csignal>
#include <poll.h>

// Each dump says in its own head what split it was written under -- count,
// index and an ownership fingerprint -- so a set that is complete and agrees
// takes the fast path and anything else has every shard read every dump and
// keep what hashes to it now, which is what makes a missing file, two sets in
// one place, a half-written set and a changed hash function all refusals or
// corrections rather than quiet losses.
inline constexpr char       shard_dump_magic[8] = { 'S','K','L','S','H','R','D','1' };
inline constexpr size_t     shard_dump_header_size = 32;

struct shard_dump_header
{
    uint32_t      count{1};
    uint32_t      index{0};
    unsigned char fingerprint[cache_fingerprint_len]{};
    bool          has_fingerprint{false};
    bool          truncated{false};
};

static std::string encode_shard_dump_header(uint32_t count, uint32_t index)
{
    std::string h(shard_dump_header_size, '\0');
    std::memcpy(h.data(), shard_dump_magic, sizeof(shard_dump_magic));
    const auto put32 = [&](size_t at, uint32_t v) {
        for (int i = 0; i < 4; ++i)
            h[at + static_cast<size_t>(i)] =
                static_cast<char>((v >> (8 * i)) & 0xFF);
    };
    put32(8,  count);
    put32(12, index);
    unsigned char fp[cache_fingerprint_len];
    cache_shard_fingerprint(fp);
    std::memcpy(h.data() + 16, fp, sizeof(fp));
    return h;
}

// Read a dump's head, where `legacy` means a file written before this header
// existed, which is a complete set of one.
static bool read_shard_dump_header(const std::string& path,
                                   shard_dump_header& out, bool& legacy)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;

    char buf[shard_dump_header_size]{};
    f.read(buf, static_cast<std::streamsize>(shard_dump_header_size));
    const std::streamsize got = f.gcount();

    // The magic with less than a whole header behind it is a torn write and not an old file.
    if (got >= static_cast<std::streamsize>(sizeof(shard_dump_magic))
        && got < static_cast<std::streamsize>(shard_dump_header_size)
        && std::memcmp(buf, shard_dump_magic, sizeof(shard_dump_magic)) == 0)
    {
        legacy = false;
        out = shard_dump_header{};
        out.truncated = true;
        return true;
    }

    if (got < static_cast<std::streamsize>(shard_dump_header_size)
        || std::memcmp(buf, shard_dump_magic, sizeof(shard_dump_magic)) != 0)
    {
        legacy = true;
        out = shard_dump_header{};
        return true;
    }

    const auto get32 = [&](size_t at) -> uint32_t {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<uint32_t>(static_cast<unsigned char>(buf[at + static_cast<size_t>(i)]))
                 << (8 * i);
        return v;
    };
    legacy      = false;
    out.count   = get32(8);
    out.index   = get32(12);
    std::memcpy(out.fingerprint, buf + 16, cache_fingerprint_len);
    out.has_fingerprint = true;
    return true;
}

// The header of a framed run of commands between two shards, a control byte no
// command can begin with followed by which interpreter the bytes are for,
// written and read by cache_instance alone.
static constexpr char shard_batch_marker = '\x01';
static constexpr std::string_view shard_batch_text = "\x01skl-shard t\n";
static constexpr std::string_view shard_batch_resp = "\x01skl-shard r\n";

// One command and not a stream of them, under the same control byte as the shard batch, for the CLI and the
// storage's notifier, whose values may hold newlines.
static constexpr std::string_view one_command_text = socketley::one_command_marker;

// A script's publishes for one sibling go when they reach the first, and a
// refused batch is given up at the second, well inside a mesh frame's 4 MiB.
static constexpr size_t lua_pub_batch_bytes = 128u << 10;
static constexpr size_t lua_pub_keep_bytes  = 1u << 20;

// `<len>\n<bytes>`, length-prefixed rather than newline-delimited because RESP
// commands contain newlines and a text value may as well.
static void append_dec(std::string& out, size_t v)
{
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof buf, v);
    out.append(buf, static_cast<size_t>(r.ptr - buf));
}

static void shard_frame_append(std::string& out, std::string_view bytes)
{
    append_dec(out, bytes.size());
    out.push_back('\n');
    out.append(bytes);
}

// Take one frame off the front, leaving `p` where it was on false, which is
// what makes a truncated or foreign reply detectable rather than
// half-consumed.
static bool shard_frame_take(const char*& p, const char* end, std::string_view& out)
{
    const char* nl = static_cast<const char*>(std::memchr(p, '\n', static_cast<size_t>(end - p)));
    if (!nl || nl == p)
        return false;

    size_t len = 0;
    for (const char* d = p; d < nl; ++d)
    {
        if (*d < '0' || *d > '9')
            return false;
        len = len * 10 + static_cast<size_t>(*d - '0');
        if (len > (32u << 20))          // nothing this side ever frames is larger
            return false;
    }
    if (static_cast<size_t>(end - (nl + 1)) < len)
        return false;

    out = std::string_view(nl + 1, len);
    p   = nl + 1 + len;
    return true;
}

cache_instance::cache_instance(std::string_view name)
    : runtime_instance(runtime_cache, name), m_listen_fd(-1), m_loop(nullptr)
{
}

cache_instance::~cache_instance()
{
    // Normally already gone, because the manager rebuilds the sink table on
    // every membership change, so this covers an instance dropped without
    // going through it.
    if (auto* mgr = get_runtime_manager())
    {
        mgr->requests().drop_sink(this);
        // And the other direction, because a cache that routes is an origin as
        // well as a sink, and an origin the channel still holds is a pointer
        // into this object after it is freed.
        mgr->requests().drop_origin(this);
    }

    close_tracked(m_listen_fd);
    close_tracked(m_cluster_listen_fd);
}

// The buffer the plain arms read into, made when an arm first needs one.
//
// It used to be made at accept, and taking that away to save an idle
// connection four kilobytes left the arms reading `&& conn->read_buf` -- which
// is null on every connection that has a buffer ring, so the last two rungs of
// the ladder were unreachable exactly when the ring was full and they were the
// point.  A cache under load then had no read armed at all on that connection
// and it went deaf: measured under the sanitizer, 2,781 of 3,000 subscribers
// answered and the rest silent.  The chain above this had already been fixed
// out of the same shape once, through an `else` rather than a null pointer.
//
// Allocating here is a malloc on a path that runs when the ring is full, which
// is rare and is not the path anybody is optimising; the idle connection that
// motivated the change still never reaches it.
static inline char* fallback_read_buf(client_connection* conn)
{
    if (!conn->read_buf)
        conn->read_buf = std::make_unique<char[]>(client_connection::READ_BUF_BYTES);
    return conn->read_buf.get();
}

void cache_instance::close_tracked(int fd)
{
    if (fd < 0)
        return;
    // m_loop while running and m_retired_loop once teardown has cleared it,
    // because the descriptors closed after a stop are the ones the ring is
    // most likely to be naming.
    event_loop* lp = m_loop ? m_loop : m_retired_loop;
    if (SOCKETLEY_LIKELY(lp != nullptr))
        lp->close_fd(fd);
    else
        close(fd);
}

void cache_instance::retire(std::shared_ptr<void> storage, io_request* const* owed, size_t count)
{
    // Nothing outstanding: the ring has no way to reach this object again, so
    // holding on to it would only leak.
    if (count == 0)
        return;

    if (m_loop)
        m_retired_loop = m_loop;

    retired_op op;
    op.storage = std::move(storage);
    constexpr size_t max_waiting = sizeof(op.waiting) / sizeof(op.waiting[0]);
    for (size_t i = 0; i < count && op.count < max_waiting; i++)
        op.waiting[op.count++] = owed[i];
    m_retired.push_back(std::move(op));
}

bool cache_instance::absorb_retired(io_request* req, struct io_uring_cqe* cqe)
{
    for (size_t i = 0; i < m_retired.size(); i++)
    {
        auto& op = m_retired[i];
        for (uint8_t k = 0; k < op.count; k++)
        {
            if (op.waiting[k] != req)
                continue;

            // A read out of the provided-buffer ring still holds one even when
            // only reporting its own cancellation, and a bundled read holds
            // several, so every restart would otherwise cost the ring buffers.
            if ((cqe->flags & IORING_CQE_F_BUFFER) && m_retired_loop)
                m_retired_loop->return_cqe_buf(cqe, req);

            // More to come, because a multishot read keeps delivering, so the
            // memory stays until that last word.
            if (cqe->flags & IORING_CQE_F_MORE)
                return true;

            op.waiting[k] = op.waiting[op.count - 1];
            op.count--;
            if (op.count == 0)
            {
                if (i + 1 != m_retired.size())
                    m_retired[i] = std::move(m_retired.back());
                m_retired.pop_back();
            }
            return true;
        }
    }
    return false;
}

std::unique_ptr<client_connection> cache_instance::pool_acquire(int fd)
{
    std::unique_ptr<client_connection> conn;
    if (!m_conn_pool.empty())
    {
        conn = std::move(m_conn_pool.back());
        m_conn_pool.pop_back();
        conn->reset(fd);
    }
    else
    {
        conn = socketley::make_connection<client_connection>();
        conn->fd = fd;
    }
    return conn;
}

void cache_instance::pool_release(std::unique_ptr<client_connection> conn)
{
    // Release fixed file slot
    if (conn->direct_fd && conn->fixed_idx >= 0 && m_loop)
    {
        m_loop->free_fixed_file_slot(static_cast<uint32_t>(conn->fixed_idx));
        conn->fixed_idx = -1;
        conn->direct_fd = false;
    }

    // The TLS session dies with the connection here rather than in reset(), so
    // a retired struct does not hold a session and two BIOs for however long
    // the ring takes -- and no completion can name it.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_context::free_ssl(conn->ssl);
        conn->ssl = nullptr;
    }
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;

    // A struct only goes back into the pool once the ring is finished with it,
    // because the pool hands structs to the very next accepted connection
    // while the kernel is still reading out of write_batch[0].
    {
        io_request* owed[2];
        size_t n = 0;
        if (conn->read_pending)
            owed[n++] = &conn->read_req;
        if (conn->write_pending)
            owed[n++] = &conn->write_req;
        if (n > 0)
        {
            retire(std::shared_ptr<void>(std::move(conn)), owed, n);
            return;
        }
    }

    // Nothing is owed, so nothing can arrive: clear the owners anyway, because
    // that is the only protection a struct sitting in the pool has if this
    // reasoning is ever wrong.
    conn->read_req.owner = nullptr;
    conn->write_req.owner = nullptr;
    conn->partial.clear();
    conn->response_buf.clear();
    conn->write_queue.clear();
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
    {
        { conn->write_batch[i].clear(); conn->write_batch_seg[i].reset(); }
        conn->write_batch_seg[i].reset();
    }
    conn->write_batch_count = 0;

    SKL_INV_POOLABLE("cache::pool_release", conn->fd,
        conn->read_pending || conn->write_pending,
        conn->read_req.owner || conn->write_req.owner);

    conn->fd = -1;
    m_conn_pool.push_back(std::move(conn));
}

void cache_instance::close_client([[maybe_unused]] client_connection* conn, int fd,
                                  [[maybe_unused]] const char* reason)
{
    // A crossing this socket was waiting on has nowhere to land now, dropped
    // in the one function every close goes through so a path added later
    // cannot forget it.
    if (conn)
        batch_drop(conn);

    m_store.unsubscribe_all(fd);
    m_store.punsubscribe_all(fd);
    // And a blocked pop on this descriptor, for the same reason and in the
    // same place: it holds the number, not the connection.
    drop_blocked(fd);
    // With a connection in hand this touches only the keys THIS client
    // watched; drop_watches is the fallback for the case without one.
    if (conn) unwatch_all(conn); else drop_watches(fd);
    // A follower registered on this descriptor goes with it, because it holds
    // no reference of its own and would otherwise point replication at a
    // number the kernel reissued.
    detach_follower(fd);
    SKL_TRACE_CLOSE(conn, fd, reason);
    // Through orderly_close, so the close resets none of the answer away -- except a copy a sibling may hold, whose
    // socket a shutdown here would end for the sibling too.
    event_loop* lp = m_loop ? m_loop : m_retired_loop;
    if (conn && fd >= 0 && lp && conn->ho_state != client_connection::handoff::sent)
        lp->close_fd_orderly(fd);
    else
        close_tracked(fd);
    if (fd >= 0 && fd < MAX_FDS) m_conn_idx[fd] = nullptr;
    auto it = m_clients.find(fd);
    if (it != m_clients.end())
    {
        pool_release(std::move(it->second));
        m_clients.erase(it);
    }
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

void cache_instance::set_persist_interval(uint32_t seconds)
{
    m_persist_interval = seconds;
}

uint32_t cache_instance::get_persist_interval() const
{
    return m_persist_interval;
}

void cache_instance::set_mode(cache_mode mode)
{
    m_mode = mode;
    m_mode_asked = mode;
}

cache_mode cache_instance::get_mode() const
{
    return m_mode;
}

size_t cache_instance::get_connection_count() const
{
    return m_clients.size();
}

// ─── ONE LISTENER, TWO PORTS ────────────────────────────────────────────────
// A sharded cache binds two listeners that are the same socket with the same
// options, so this is one function called twice rather than a second copy
// fixed once and left broken in the other place.
bool cache_instance::open_listener(uint16_t port, bool reuseport, int& out_fd)
{
    // SOCK_CLOEXEC, because a cache lives in the daemon and the daemon forks
    // workers with no use for this port and every opportunity to keep it
    // bound.
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    // SO_REUSEPORT is what SPREADS the shared port across the shards, and it is
    // exactly what the per-shard port must not have: see m_cluster_listen_fd.
    if (reuseport)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    if (!apply_congestion(fd))
    {
        close_tracked(fd);
        return false;
    }

    // No TCP_DEFER_ACCEPT, measured at +7.9% on the only shape a cache client
    // has, and removed not for the delay but because a SYN-RECV connection
    // dies with the listener unnoticed -- which for a pooled cache client is
    // discovered at the moment somebody's request is written into it.
    // No SO_RCVBUF or SO_SNDBUF: either locks its buffer on every accepted socket against autotuning, and a
    // connection then carries at most the buffer per round trip (the proxy's and the server's measured cap).

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = bind_in_addr();
    addr.sin_port = htons(port);

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        LOG_ERROR(("cache: port " + std::to_string(port) + " could not be bound: " +
                   std::string(std::strerror(errno))).c_str());
        close_tracked(fd);
        return false;
    }

    if (listen(fd, 4096) < 0)
    {
        close_tracked(fd);
        return false;
    }

    out_fd = fd;
    return true;
}



// The same questions setup() asks below, without the syscalls, so the manager
// can refuse a second claim on an address before a worker is forked to find
// out.  Kept next to setup() because the two have to agree: an answer here
// that setup() does not honour is a refusal nobody earned.
// See server_instance::effective_port(): one number, two readers.  The
// configured port, which is the one every shard binds and the one an operator
// connects to -- the per-shard cluster ports are counted up from it in
// listen_addresses() and are not what `ps` is asked for.
uint16_t cache_instance::effective_port() const
{
    if (!get_listen_path().empty())
        return 0;
    return get_port() ? get_port() : cache_default_port;
}

void cache_instance::listen_addresses(std::vector<std::string>& out) const
{
    // A listen path and a port are mutually exclusive -- listen_config_refusal
    // in setup() is what makes that true -- and cluster mode is off or refused
    // with a path, so a path is the whole answer.
    const std::string listen_path(get_listen_path());
    if (!listen_path.empty())
    {
        out.push_back("unix:" + listen_path);
        return;
    }

    // get_shards() and not m_shard_n, because this is asked of the daemon's
    // placeholder, whose setup() has never run.
    const uint16_t base   = effective_port();
    const uint32_t shards = get_shards() ? get_shards() : 1u;

    // Every shard binds the configured port through SO_REUSEPORT, which is
    // what spreads one address over them.
    out.push_back("tcp:" + std::to_string(base));

    // And in cluster mode above one shard, a port apiece on top: the formula
    // CLUSTER SLOTS publishes, so a runtime that took one of these from
    // underneath a cache would be sent keys it does not hold.
    if (cluster_mode() && shards > 1)
        for (uint32_t i = 0; i < shards; ++i)
        {
            const uint32_t p = static_cast<uint32_t>(base) + 1u + i;
            if (p <= 65535u)
                out.push_back("tcp:" + std::to_string(p));
        }
}

bool cache_instance::setup(event_loop& loop)
{
    // Nothing from the previous run is cleaned up here, because teardown()
    // hands what it cannot free to retire(); what can go is whatever the loop
    // confirms is finished with, which is the only thing that releases a
    // dropped completion's storage.
    if (!m_retired.empty() && loop.owner_drained(this))
        m_retired.clear();

    // Pre-allocate connection pool
    if (m_conn_pool.empty())
    {
        m_conn_pool.reserve(CONN_POOL_INIT);
        for (size_t i = 0; i < CONN_POOL_INIT; i++)
            m_conn_pool.push_back(socketley::make_connection<client_connection>());
    }

    m_loop = &loop;
    // Kept across teardown: a descriptor closed after a stop still has to be
    // checked against the ring, and m_loop is null exactly then.
    m_retired_loop = &loop;

    // ── This shard's slice of the keyspace ──────────────────────────────────
    // Read once here because get_shards() is not inline and the question is
    // asked per command, with 1 and 0 the unsharded answers that make every
    // routing check a single compare.
    m_shard_n = get_shards();
    m_shard_i = get_shard_index();
    if (m_shard_i >= m_shard_n)
        m_shard_i = 0;
    // Again now the shard count is known, whichever of the two the config set first.
    set_max_memory(m_max_memory);

    m_base_port = get_port();
    if (m_base_port == 0)
        m_base_port = cache_default_port;

    m_turn_cross.assign(static_cast<size_t>(m_shard_n) * 2, turn_crossing{});
    m_route_mark.assign(m_shard_n, cross_mark{});
    m_turn_cross_any = false;
    m_store.set_channel_observer(&on_channel_presence, this);

    // A replica of a cluster cache starts fenced and follows nobody, before it binds anything, so that no client
    // reaches it and no follower syncs from it until the daemon says what it is.
    if (m_cluster_incarnation != 0)
    {
        m_role = std::make_unique<socketley::cluster::replica_role>(m_cluster_incarnation);
        m_replicate_target.clear();
        m_repl_role = repl_none;
        apply_role(socketley::cluster::replica_mode::fenced, false);
    }

    // `--persistent` with more than one shard is no longer refused: each shard
    // writes its own self-describing file, and a set that cannot be trusted
    // refuses the start rather than being loaded in part.
    if (!load_shard_set())
        return false;

    // The journal replays onto the dumps just loaded, the only state it was
    // ever relative to, and one that cannot be trusted refuses the start the
    // same way an untrustworthy dump set does.
    if (m_persist_interval > 0 && !m_persistent_path.empty()
        && !journal_recover())
        return false;

    // ─── --listen unix:/path/to.sock ────────────────────────────────────────
    // Judged here rather than only in the flag parser, because setup() is the
    // one function every route to a listening socket passes through, and
    // before the TLS block so a doomed configuration loads no certificates.
    const std::string listen_path(get_listen_path());
    if (!listen_path.empty())
    {
        // The shared set — the -p conflict, --tls, and the path rules
        // re-checked because the flag parser is not on the restore path.
        if (const std::string msg = socketley::unix_sock::listen_config_refusal(
                listen_path, get_port(), get_tls()); !msg.empty())
        {
            LOG_ERROR(("cache: " + msg).c_str());
            return false;
        }
        // The set is judged by its longest member, because a shard whose node
        // does not fit is a shard nothing can reach -- and it would fail at
        // the bind, one shard in, with the others already serving.
        if (const std::string msg = socketley::unix_sock::shard_listen_path_refusal(
                listen_path, m_shard_n); !msg.empty())
        {
            LOG_ERROR(("cache: " + msg).c_str());
            return false;
        }
        // And the member only this runtime carries, because --cluster
        // advertises a port formula and a path has no successor to compute;
        // only the flag typed is refused, and the default is off here.
        if (m_cluster_forced)
        {
            LOG_ERROR("cache: --listen and --cluster cannot be combined -- "
                      "CLUSTER SLOTS advertises base+1..base+N ports computed "
                      "from the base, and a unix path has no successor to "
                      "compute.  Use -p for a clustered cache");
            return false;
        }
    }

    // ── TLS listener ────────────────────────────────────────────────────────
    // Certificates are read here at setup because that is blocking file I/O
    // and the handshake touches neither file nor socket -- and every refusal
    // returns false rather than falling through to a plaintext listener
    // `inspect` still calls encrypted.
    m_tls.reset();
    if (get_tls())
    {
        // The configuration gate has already refused --replicate here on every
        // path, and this is the belt to that braces, because setup() is what
        // actually dials the leader.
        if (m_repl_role == repl_follower && !m_replicate_target.empty())
        {
            LOG_ERROR("cache: --tls encrypts this cache's own listener, and the "
                      "replication link to its leader is dialled in cleartext -- "
                      "refusing rather than streaming the dataset off an encrypted "
                      "port unencrypted");
            return false;
        }
        auto ctx = std::make_unique<tls_context>();
        if (!ctx->init_server(get_cert_path(), get_key_path(), get_ca_path()))
        {
            // init_server has already said which file and what OpenSSL made of
            // it, so this says what it cost.
            LOG_ERROR("cache: TLS listener not started -- the certificate, key or "
                      "client CA could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    const uint16_t port = m_base_port;

    if (!listen_path.empty())
    {
        // The mechanism is shared/net/unix_listener.h's, one implementation for
        // every runtime that listens, with everything below the branch the
        // same for both families.
        // One node per shard, because a path is one listener: the second
        // process to bind the same one unlinks the first and only it stays
        // reachable.  At a single shard this is the path as typed.
        const std::string mine = socketley::unix_sock::shard_listen_path(
            listen_path, m_shard_i, m_shard_n);
        auto r = socketley::unix_sock::bind_listener(mine);
        if (r.fd < 0)
        {
            LOG_ERROR(("cache: " + r.error).c_str());
            return false;
        }
        m_listen_fd = r.fd;
        // Remembered so teardown() removes exactly the node this bind
        // created, and not whatever the configuration says by then.
        m_bound_listen_path = mine;
    }
    else if (!open_listener(port, /*reuseport=*/true, m_listen_fd))
        return false;

    // ── The per-shard port ──────────────────────────────────────────────────
    // The per-shard port is bound in addition to the shared one and only in
    // cluster mode above one shard, and a failure fails the start, because the
    // address a client is sent to is a formula no shard can verify its
    // siblings honoured.
    m_cluster_on    = cluster_mode();
    m_cluster_ports = m_cluster_on && m_shard_n > 1;

    // Said once, by shard 0, because behind one address a shard relays every
    // key it does not own and the relay costs more than the answer.
    if (m_shard_n > 1 && !m_cluster_on && m_shard_i == 0)
        LOG_WARN(("cache \"" + std::string(get_name()) + "\": "
                  + std::to_string(m_shard_n) + " shards share one address, so "
                  + std::to_string(m_shard_n - 1) + " of every "
                  + std::to_string(m_shard_n) + " keys reach a shard that does "
                  "not own them and are relayed to the one that does -- which "
                  "roughly doubles what an operation costs, so these shards buy "
                  "far less throughput than the cores they take.  "
                  + (m_no_cluster
                         ? std::string("--no-cluster keeps the shards off their own ports; drop it, "
                                       "and a cluster-aware client routes to each shard itself")
                         : std::string("A unix path has no per-shard address to publish; serve on -p, "
                                       "and a cluster-aware client routes to each shard itself"))
                  + ", or use --shards 1").c_str());

    if (m_cluster_ports)
    {
        const uint32_t wanted = static_cast<uint32_t>(port) + 1u + m_shard_i;
        if (wanted > 65535u)
        {
            LOG_ERROR(("cache: shard " + std::to_string(m_shard_i) + " of "
                       + std::to_string(m_shard_n) + " would need port "
                       + std::to_string(wanted) + ", which is not a port -- "
                       "cluster mode needs base+1..base+N below 65536, or "
                       "--no-cluster and the shards share the one port").c_str());
            close_tracked(m_listen_fd);
            m_listen_fd = -1;
            return false;
        }
        m_cluster_port = static_cast<uint16_t>(wanted);
        if (!open_listener(m_cluster_port, /*reuseport=*/false, m_cluster_listen_fd))
        {
            LOG_ERROR(("cache: shard " + std::to_string(m_shard_i) + " of "
                       + std::to_string(m_shard_n) + " could not bind its own port "
                       + std::to_string(m_cluster_port)
                       + " -- CLUSTER SLOTS would advertise an address nothing "
                         "answers on, so the cache refuses to start.  Free that "
                         "port, or add --no-cluster: with it the shards share "
                         "the one port and cross for foreign keys").c_str());
            close_tracked(m_listen_fd);
            m_listen_fd = -1;
            m_cluster_port = 0;
            return false;
        }
    }

    // A node beside the port for callers already on this box, the object the
    // server keeps and for the same reason: made once, because it owns an
    // io_request the ring may still hold, and a reset() in teardown had the
    // sanitizer reading a token out of freed storage.
    if (socketley::unix_sock::wants_companion(get_type(), get_port(), listen_path,
                                              get_tls(), is_udp(), get_shards())
        && !get_companion_path().empty())
    {
        if (!m_companion)
            m_companion = std::make_unique<socketley::unix_companion>(
                std::string(get_companion_path()),
                [this](int fd) { return adopt_client(fd, false, true); });
        m_companion->start(loop);
    }

    // The dump set was read at the top of setup(), before anything could be
    // served out of a store that is only part of what was stored.

    // Cache config values to avoid virtual calls on hot paths, through the one
    // function an `edit` on a running cache also calls -- three lines here and
    // an override that did not exist is exactly how the two came apart.
    refresh_cached_limits();
    // Seed from the store rather than clearing, because load() restores expiry
    // timestamps and forcing this false would leave restored TTL keys immortal
    // until an unrelated command flipped it back.
    m_has_ttl_keys = m_store.has_expiry_keys();

    // Connect to master if follower.
    //
    // Checked, because a follower that never reached its master looks exactly
    // like one that did until somebody writes to the master and waits: the
    // return was discarded, and `--replicate 1.2.3.4:abc` came up, stayed up
    // and logged nothing at all.
    if (m_repl_role == repl_follower && !m_replicate_target.empty() &&
        !connect_to_master())
    {
        // The dial never reached the ring -- a target with no port, no socket,
        // a refused submission.  What the ring comes back with is reported by
        // handle_master_connect(); this is the half that never got that far.
        LOG_ERROR(("cache \"" + std::string(get_name()) + "\": could not dial master \"" +
                   m_replicate_target + "\"").c_str());
        schedule_master_retry();
    }

    // Provided-buffer ring geometry, where the size decides how many commands
    // one completion can carry and the count how much concurrent traffic fits,
    // both tunable so the memory trade-off is measured rather than guessed.
    uint32_t buf_count = BUF_COUNT;
    uint32_t buf_size  = BUF_SIZE;
    if (const auto v = socketley::settings::number<uint32_t>("SOCKETLEY_CACHE_BUF_COUNT"))
        buf_count = *v;
    if (const auto v = socketley::settings::number<uint32_t>("SOCKETLEY_CACHE_BUF_SIZE"))
        buf_size = *v;
    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, buf_count, buf_size);
    // On always, for the server's reason: nothing here declines a read at a
    // watermark, so there is no second side to trade the throughput against.
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_enabled();
    // Probed by a real submission inside recv_bundle_enabled(), and off under
    // SOCKETLEY_RECV_BUNDLE=0 — which is also the A/B switch: same binary,
    // same pool geometry, only the arm differs.
    m_recv_bundle = m_recv_multishot && loop.recv_bundle_enabled();

    // A fresh accept request for this run, because the previous one may still
    // be owed a completion and re-arming would leave the listener with two
    // chains on one io_request.
    m_accept = std::make_unique<accept_op>();
    arm_listener(m_listen_fd, *m_accept, m_multishot_active);

    if (m_cluster_listen_fd >= 0)
    {
        m_cluster_accept = std::make_unique<accept_op>();
        arm_listener(m_cluster_listen_fd, *m_cluster_accept,
                     m_cluster_multishot_active);
    }

    // The TTL sweep starts only once a key carries an expiry, because a timer
    // running for every cache runtime wakes each idle loop for nothing -- and
    // the interval trades memory against CPU, never correctness, since every
    // read path checks expiry itself.
    const long sweep_ms = socketley::settings::number<long>("SOCKETLEY_CACHE_TTL_SWEEP_MS").value_or(500);
    m_ttl_sweep_ms = sweep_ms;
    // Fresh timers for this run, because the sweep that was running at the
    // stop cannot be cancelled and m_ttl_timer_armed cannot tell the
    // difference.
    m_ttl_timer = std::make_unique<timer_op>();
    m_ttl_timer->ts = { sweep_ms / 1000, (sweep_ms % 1000) * 1'000'000 };
    m_ttl_timer->req = { this, nullptr, -1, 0, op_timeout };
    m_ttl_timer_armed = false;
    if (m_has_ttl_keys)
        arm_ttl_timer();

    // A fresh journal timer per run for the same reason as the sweep's, and
    // armed only once a write is buffered, because an idle cache owes the
    // disk nothing.
    if (m_journal.is_open())
    {
        m_journal_timer = std::make_unique<timer_op>();
        m_snap_floor = uint64_t{socketley::settings::number<uint32_t>("SOCKETLEY_CACHE_SNAPSHOT_MB").value_or(64)} << 20;
        m_snap_at = snapshot_threshold();
        m_journal_timer->ts.tv_sec  = m_persist_interval;
        m_journal_timer->ts.tv_nsec = 0;
        m_journal_timer->req = { this, nullptr, -1, 0, op_timeout };
        m_journal_timer_armed  = false;
        m_journal_write_warned = false;
    }

    // Armed here for the two questions a listener has from the start: the idle
    // timeout if one was configured, and the handshake deadline on a TLS
    // listener whether one was or not.  The third -- a command left
    // half-arrived -- cannot be known yet and arms the same chain on demand.
    if (m_idle_timeout_cached > 0 || m_tls)
        arm_idle_sweep_if_needed();

    // Only where the worker's mesh carries descriptors: a sharded cache's, unless SOCKETLEY_CACHE_HANDOFF=0.
    m_handoff_on = m_shard_n > 1 && can_hand_off() && !m_tls;
    m_ho_waiting.clear();
    m_ho_sent.clear();

    return true;
}

void cache_instance::teardown(event_loop& /*loop*/)
{
    // A dump is the one exit step that grows with the data, so it widens the
    // bound a stopping worker is held to instead of being killed inside it.
    if (!m_persistent_path.empty() && socketley::widen_exit_bound)
        socketley::widen_exit_bound(socketley::dump_exit_bound_sec);

    // A snapshot still being written would land after this dump and over it.
    snapshot_abort();

    // This shard's own slice into its own file, atomically, and never the bare
    // path, because a dump has to say what split it holds.
    const bool dumped = save_shard_dump();
    if (!dumped)
        LOG_ERROR(("cache: could not write the dump for slice "
                   + std::to_string(m_shard_i) + " of "
                   + std::to_string(m_shard_n) + " beside " + m_persistent_path
                   + "; the next start will refuse the incomplete set").c_str());

    // The dump now holds every journaled effect, or it failed and the journal
    // is the only record of the tail; closed either way so the next setup()
    // reopens it against whatever is then on disk.
    journal_after_snapshot(dumped);
    m_journal.close();

    // Shutdown before closing, because a multishot accept holds its own
    // reference and close() leaves the loop owing this owner an operation
    // forever -- with the cancel now inside close_fd(), which holds the number
    // until both have reported.
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
    }

    // The same two lines for the per-shard listener, and for the same reason:
    // its multishot accept holds a reference of its own, so close() alone never
    // ends it and the terminating completion never arrives.
    if (m_cluster_listen_fd >= 0)
    {
        shutdown(m_cluster_listen_fd, SHUT_RDWR);
        close_tracked(m_cluster_listen_fd);
        m_cluster_listen_fd = -1;
    }

    // Stopped, not freed, for the reason setup() gives.
    if (m_companion)
        m_companion->stop();

    // The socket node for a unix listener, exactly the one this run bound,
    // because closing the descriptor does not unlink the path.
    if (!m_bound_listen_path.empty())
    {
        if (unlink(m_bound_listen_path.c_str()) < 0) {}
        m_bound_listen_path.clear();
    }

    // Drain: flush pending write queues with blocking writes
    if (get_drain())
    {
        // One end for every connection together, so a client that stopped reading cannot hold the stop.
        const auto drain_end = std::chrono::steady_clock::now() + socketley::drain_budget;
        for (auto& [fd, conn] : m_clients)
        {
            // These blocking writes go through the session, because the
            // buffers are plaintext and writing them as-is would downgrade the
            // port at shutdown -- and a handshake still in flight has no keys,
            // so the reply is dropped rather than sent in the clear.
            if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
            {
                if (conn->tls_state != tls_conn_ready)
                    continue;

                if (!conn->response_buf.empty())
                {
                    conn->write_queue.push(std::move(conn->response_buf));
                    conn->response_buf.clear();
                }

                bool broken = false;
                while (!conn->write_queue.empty() && !broken)
                {
                    const std::string_view msg = conn->write_queue.front().view();
                    const int n = tls_context::ssl_write(conn->ssl, msg.data(),
                                                         static_cast<int>(msg.size()));
                    // 0 is the write BIO at its cap and -1 is a dead session;
                    // neither recovers here, because nothing is going to drain
                    // it for us after this loop.
                    if (n <= 0 || static_cast<size_t>(n) != msg.size())
                        broken = true;
                    else
                        conn->write_queue.pop();

                    // Out of the BIO and onto the wire as we go, so one
                    // oversized queue cannot buffer past the cap that made
                    // ssl_write refuse in the first place.
                    char cbuf[16384];
                    for (;;)
                    {
                        const int c = tls_context::bio_read_out(conn->ssl, cbuf, sizeof(cbuf));
                        if (c <= 0)
                            break;
                        if (!socketley::write_all_until(fd, cbuf, static_cast<size_t>(c), drain_end))
                        {
                            broken = true;
                            break;
                        }
                    }
                }
                continue;
            }

            // Giving up on this client must not give up on the rest, because
            // the break used to leave the enclosing loop and cost every
            // remaining client its pending replies.
            // The queue holds the older replies, so it goes first and a failure there ends this client.
            bool queue_broken = false;
            while (!conn->write_queue.empty())
            {
                const std::string_view msg = conn->write_queue.front().view();
                if (!socketley::write_all_until(fd, msg.data(), msg.size(), drain_end))
                {
                    queue_broken = true;
                    break;
                }
                conn->write_queue.pop();
            }
            if (queue_broken)
                continue;
            if (!conn->response_buf.empty())
                socketley::write_all_until(fd, conn->response_buf.data(),
                                           conn->response_buf.size(), drain_end);
        }
    }

    m_conn_idx.clear();

    // The listener first and then everything hanging off it, each closed and
    // handed to pool_release()/retire(), so the next setup() starts from
    // nothing.
    for (auto& [fd, conn] : m_clients)
    {
        // Release fixed file slot before closing
        if (conn->direct_fd && conn->fixed_idx >= 0)
        {
            m_loop->free_fixed_file_slot(static_cast<uint32_t>(conn->fixed_idx));
            conn->fixed_idx = -1;
            conn->direct_fd = false;
        }
        // shutdown() before close() so an armed read or write is completed by
        // the kernel now rather than whenever the peer gets around to it.
        shutdown(fd, SHUT_RDWR);
        close_tracked(fd);
        // Drop the subscriptions with the socket, or a connection that later
        // lands on the same fd number inherits the dead client's channels.
        m_store.unsubscribe_all(fd);
        m_store.punsubscribe_all(fd);
        // A follower promoted from this connection must lose the descriptor
        // before the loop below sees it, or it would close the number a second
        // time.
        detach_follower(fd);
        pool_release(std::move(conn));
    }
    m_clients.clear();

    // Close replication connections
    if (m_master)
    {
        if (m_master->fd >= 0)
        {
            shutdown(m_master->fd, SHUT_RDWR);
            close_tracked(m_master->fd);
            m_master->fd = -1;
        }
        io_request* owed[1];
        size_t n = 0;
        if (m_master->read_pending)
            owed[n++] = &m_master->read_req;
        retire(std::shared_ptr<void>(std::move(m_master)), owed, n);
    }
    // A dial the ring is still holding: the connect owes a completion whatever
    // this runtime does next, and the address it is reading lives in there.
    if (m_master_dial)
    {
        if (m_master_dial->fd >= 0)
        {
            close_tracked(m_master_dial->fd);
            m_master_dial->fd = -1;
        }
        io_request* owed[1] = { &m_master_dial->req };
        retire(std::shared_ptr<void>(std::move(m_master_dial)), owed, 1);
    }
    for (auto& f : m_followers)
    {
        // The socket belonged to the client connection, which has already
        // closed it, so only the buffers are ours -- and the kernel reads
        // straight out of f->out for the duration of a write.
        f->fd = -1;
        f->dead = true;
        io_request* owed[1];
        size_t n = 0;
        if (f->write_pending)
            owed[n++] = &f->write_req;
        retire(std::shared_ptr<void>(std::move(f)), owed, n);
    }
    m_followers.clear();

    // Withdraw every timer this run armed, because nothing above reached them
    // and the self-rearming TTL sweep kept the instance in the graveyard
    // forever -- and a withdrawal brings the completion forward rather than
    // taking it away, so every `owed` count stays as it was.
    if (m_loop)
    {
        bool withdrawn = true;
        if (m_ttl_timer_armed && m_ttl_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_ttl_timer->req);
        if (m_journal_timer_armed && m_journal_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_journal_timer->req);
        if (m_idle_sweep_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_idle_sweep_timer->req);
        if (m_accept_backoff_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_accept_backoff_timer->req);
        if (m_master_retry)
            withdrawn &= m_loop->submit_timeout_remove(&m_master_retry->req);
        if (m_master_sync_deadline)
            withdrawn &= m_loop->submit_timeout_remove(&m_master_sync_deadline->req);
        if (m_role_timer_armed && m_role_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_role_timer->req);
        m_loop->flush();

        if (SOCKETLEY_UNLIKELY(!withdrawn))
            LOG_WARN("cache: a timer withdrawal did not reach the ring — this instance "
                     "stays retired until the timer fires on its own");
    }

    // The timers and the listener retired, because nothing cancels an io_uring
    // timeout and the accept completion is still owed.
    {
        io_request* owed[1];
        if (m_accept)
        {
            owed[0] = &m_accept->req;
            retire(std::shared_ptr<void>(std::move(m_accept)), owed, 1);
        }
        if (m_cluster_accept)
        {
            owed[0] = &m_cluster_accept->req;
            retire(std::shared_ptr<void>(std::move(m_cluster_accept)), owed, 1);
        }
        if (m_ttl_timer)
        {
            const size_t n = m_ttl_timer_armed ? 1 : 0;
            owed[0] = &m_ttl_timer->req;
            retire(std::shared_ptr<void>(std::move(m_ttl_timer)), owed, n);
        }
        if (m_journal_timer)
        {
            const size_t n = m_journal_timer_armed ? 1 : 0;
            owed[0] = &m_journal_timer->req;
            retire(std::shared_ptr<void>(std::move(m_journal_timer)), owed, n);
        }
        if (m_idle_sweep_timer)
        {
            owed[0] = &m_idle_sweep_timer->req;
            retire(std::shared_ptr<void>(std::move(m_idle_sweep_timer)), owed, 1);
        }
        if (m_accept_backoff_timer)
        {
            owed[0] = &m_accept_backoff_timer->req;
            retire(std::shared_ptr<void>(std::move(m_accept_backoff_timer)), owed, 1);
        }
        if (m_master_retry)
        {
            owed[0] = &m_master_retry->req;
            retire(std::shared_ptr<void>(std::move(m_master_retry)), owed, 1);
        }
        if (m_master_sync_deadline)
        {
            owed[0] = &m_master_sync_deadline->req;
            retire(std::shared_ptr<void>(std::move(m_master_sync_deadline)), owed, 1);
        }
        if (m_role_timer)
        {
            const size_t n = m_role_timer_armed ? 1 : 0;
            owed[0] = &m_role_timer->req;
            retire(std::shared_ptr<void>(std::move(m_role_timer)), owed, n);
            m_role_timer_armed = false;
        }
    }

    // Nothing may be told about a crossing after this, symmetrical with the
    // sink registration, because an origin is a bare pointer and a runtime can
    // be stopped without being destroyed.
    if (auto* mgr = get_runtime_manager())
        mgr->requests().drop_origin(this);

    // Every ticket still waiting is answered `dropped`, because a parked
    // ticket nothing completes is a leak the channel's cap only delays.
    for (auto& kv : m_batches)
        if (kv.second.ticket != 0)
            complete_ticket(kv.second.ticket, request_status::dropped, {});
    for (const deferred_request& q : m_deferred_queue)
        complete_ticket(q.ticket, request_status::dropped, {});
    m_deferred_queue.clear();
    m_deferred_inflight = 0;

    m_batches.clear();
    m_posts.clear();
    m_collect.reset();
    m_collect_fd = -1;
    for (turn_crossing& tc : m_turn_cross)
    {
        tc.payload.clear();
        tc.targets.clear();
    }
    for (cross_mark& mk : m_route_mark)
        mk = cross_mark{};
    m_turn_cross_any = false;
    m_finish_due.clear();

    m_ttl_timer_armed = false;
    m_journal_timer_armed = false;
    m_loop = nullptr;
    m_multishot_active = false;
    m_cluster_multishot_active = false;
    m_cluster_ports = false;
}

void cache_instance::arm_ttl_timer()
{
    if (m_ttl_timer_armed || !m_loop || !m_ttl_timer)
        return;
    m_ttl_timer_armed = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_ttl_timer->ts, &m_ttl_timer->req)))
    {
        // Clear the flag again, because mark_ttl_keys() only submits while it
        // is unset and one refused timeout would stop the sweep for the
        // lifetime of the runtime.
        m_ttl_timer_armed = false;
        LOG_WARN("cache: TTL sweep timer refused — expired keys keep their memory until touched");
    }
}

void cache_instance::mark_ttl_keys()
{
    m_has_ttl_keys = true;
    arm_ttl_timer();
}

void cache_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;

    // Before anything else, and before the check below that gives up while the
    // runtime is stopped: this may be the completion a previous run is still
    // owed, and it is the one that lets the memory behind it go.
    if (SOCKETLEY_UNLIKELY(!m_retired.empty()) && absorb_retired(req, cqe))
        return;

    if (!m_loop)
        return;

    // Periodic TTL sweep timer
    if (m_ttl_timer && req == &m_ttl_timer->req)
    {
        m_ttl_timer_armed = false;
        if (!m_has_ttl_keys)
            return;    // nothing to expire: stay off until mark_ttl_keys()
        bool more = false;
        auto expired_keys = m_store.sweep_some_expired(more);
        m_has_ttl_keys = m_store.has_expiry_keys();
        m_stat_keys_expired += expired_keys.size();
#ifndef SOCKETLEY_NO_LUA
        if (lua() && lua()->has_on_expire() && !expired_keys.empty())
        {
            for (const auto& key : expired_keys)
            {
                {
                    sol::protected_function_result r = lua()->on_expire()(key);
                    lua_diag::raised(r, get_name(), "on_expire");
                }
            }
        }
#endif
        // Only keep sweeping while keys with an expiry remain, since
        // sweep_expired() may have removed the last one -- soon while a sweep is under way, so a cycle over millions
        // of keys takes a second or two, a millisecond at a time.
        if (m_has_ttl_keys)
        {
            const long ms = more ? 50 : m_ttl_sweep_ms;
            m_ttl_timer->ts = { ms / 1000, (ms % 1000) * 1'000'000 };
            arm_ttl_timer();
        }
        return;
    }

    // The journal's interval flush, disarmed here and re-armed by the next
    // buffered write, because a timer that fires for an empty buffer wakes an
    // idle loop for nothing.
    if (m_journal_timer && req == &m_journal_timer->req)
    {
        m_journal_timer_armed = false;
        journal_flush_now();
        return;
    }

    if (m_snap && req == &m_snap->req)
    {
        m_snap->armed = false;
        snapshot_done();
        return;
    }

    // Read from the master, matched by request rather than fd, because the
    // link owns its request and a client may sit on the same descriptor
    // number.
    if (m_master && req == &m_master->read_req)
    {
        handle_master_read(cqe);
        return;
    }

    // Replication writes matched by request pointer, because a follower
    // reached the leader as an ordinary client and the generic write handler
    // would claim these completions.
    for (auto& f : m_followers)
    {
        if (req == &f->write_req)
        {
            handle_follower_write(cqe, *f);
            reap_followers();
            return;
        }
    }

    // Remembered before the dispatch, because the handler may release the
    // struct and the request with it.
    const int cqe_fd = (req->type == op_accept || req->type == op_multishot_accept ||
                        req->type == op_timeout)
                       ? -1 : req->fd;

    switch (req->type)
    {
        case op_accept:
        case op_multishot_accept:
            handle_accept(cqe, req);
            break;
        case op_read:
        case op_read_provided:
        case op_recv_multishot:
        case op_recv_multishot_bundle:
            handle_read(cqe, req);
            break;
        case op_write:
        case op_writev:
            handle_write(cqe, req);
            break;
        case op_connect:
            handle_master_connect(cqe, req);
            break;
        case op_timeout:
            // Before the sweeps, because it owns its request outright and a
            // fired timer that nothing claims falls through to their scans.
            if (m_master_retry && req == &m_master_retry->req)
            {
                m_master_retry.reset();
                if (!connect_to_master())
                    schedule_master_retry();
                break;
            }
            if (m_role_timer && req == &m_role_timer->req)
            {
                role_lapsed();
                break;
            }
            if (m_master_sync_deadline && req == &m_master_sync_deadline->req)
            {
                m_master_sync_deadline.reset();
                if (!m_master || m_master->synced)
                    break;                          // done, or no link left to judge
                if (m_master->bytes_seen != m_master->bytes_at_deadline)
                {
                    arm_master_sync_deadline();      // slow, not stopped
                    break;
                }
                LOG_ERROR(("cache \"" + std::string(get_name()) + "\": the master link "
                           "stood for 30s without finishing its sync — dropped, and "
                           "dialled again on a backoff").c_str());
                // Shut down rather than torn down here.  The read is still in
                // flight, so resetting the link would hand the ring a buffer
                // that is gone; a shutdown completes that read with 0, which
                // walks the drop handle_master_read() already performs -- close,
                // reset, schedule a retry -- and adds no second lifetime.
                if (m_master->fd >= 0)
                    ::shutdown(m_master->fd, SHUT_RDWR);
                break;
            }
            if (m_idle_sweep_timer && req == &m_idle_sweep_timer->req)
            {
                auto now = std::chrono::steady_clock::now();
                auto timeout = std::chrono::seconds(m_idle_timeout_cached);
                // Gated rather than left to the comparison: with no
                // --idle-timeout the timeout is zero seconds, so every
                // connection is past it and arming this sweep for the
                // handshake deadline alone would close the lot.
                const bool sweep_idle = (m_idle_timeout_cached > 0);
                const auto hs = std::chrono::seconds(tls_handshake_deadline_secs);
                // Once for the tick, not once per connection: the attack this
                // deadline exists for is many peers at once.
                uint32_t hs_dropped = 0, partial_dropped = 0;
                bool partials_left = false;
                for (auto& [cfd, cconn] : m_clients)
                {
                    // A replication follower is idle by definition, so
                    // sweeping it would tear replication down on a timer for
                    // behaving correctly.
                    if (cconn->is_follower || cconn->closing)
                        continue;
                    // A peer that has not finished its handshake is not a
                    // client yet, so this one does not wait for a timeout
                    // nobody configured.
                    if (cconn->tls_state == tls_conn_handshake &&
                        (now - cconn->handshake_since) > hs)
                    {
                        cconn->closing = true;
                        shutdown(cfd, SHUT_RD);
                        ++hs_dropped;
                        continue;
                    }
                    // A command that arrived in part and stopped.  The
                    // allowance grows with what was delivered, so a client
                    // writing a large value keeps ahead of it and one holding
                    // the socket does not.
                    if (cconn->partial_since.time_since_epoch().count() != 0)
                    {
                        const auto allowed = std::chrono::seconds(
                            client_connection::PARTIAL_BASE_SECS +
                            cconn->partial.size() / client_connection::PARTIAL_FLOOR_BPS);
                        if ((now - cconn->partial_since) > allowed)
                        {
                            cconn->closing = true;
                            shutdown(cfd, SHUT_RD);
                            ++partial_dropped;
                            continue;
                        }
                        partials_left = true;
                    }
                    if (sweep_idle && (now - cconn->last_activity) > timeout)
                    {
                        cconn->closing = true;
                        // Its close_notify first, which the end of the read waits for.
                        if (tls_say_close(cconn.get())) {}
                        shutdown(cfd, SHUT_RD);
                    }
                }
                // Decided by the walk that just finished rather than kept as a
                // count, because a connection stops holding one on any read and
                // nothing would have decremented it.
                m_partials_outstanding = partials_left;
                // Nothing is said to a peer dropped this way -- there is no
                // protocol yet to say it in -- so the log is the only record
                // that this and not something else closed it.
                if (hs_dropped > 0)
                    LOG_INFO(("cache \"" + std::string(get_name()) + "\": dropped " +
                              std::to_string(hs_dropped) + " connection(s) that did not "
                              "finish a TLS handshake within " +
                              std::to_string(tls_handshake_deadline_secs) + "s").c_str());
                if (partial_dropped > 0)
                    LOG_WARN(("cache \"" + std::string(get_name()) + "\": dropped " +
                              std::to_string(partial_dropped) + " connection(s) holding a "
                              "command that stopped arriving; the allowance is " +
                              std::to_string(client_connection::PARTIAL_BASE_SECS) +
                              "s plus one second per " +
                              std::to_string(client_connection::PARTIAL_FLOOR_BPS) + " bytes delivered").c_str());

                if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_idle_sweep_timer->ts,
                                                               &m_idle_sweep_timer->req)))
                    LOG_ERROR("cache: idle sweep timer refused — no further sweeps will run");
            }
            // The blocked-pop tick, which answers whoever has waited out their
            // timeout and re-arms only while somebody is still waiting.
            else if (m_block_timer && req == &m_block_timer->req)
            {
                sweep_blocked();
            }
            // Accept backoff expired, so the timer owes nothing more and the
            // next shortage may arm a new one.
            else if (m_accept_backoff_timer && req == &m_accept_backoff_timer->req)
            {
                m_accept_backoff_timer.reset();
                // Both listeners and one timer for the two, because the
                // shortage that armed it is EMFILE or a full queue and neither
                // is a property of one socket.
                if (m_listen_fd >= 0)
                    rearm_accept();
                if (m_cluster_listen_fd >= 0)
                    rearm_cluster_accept();
            }
            break;
        default:
            break;
    }

    // ── The chokepoint ──────────────────────────────────────────────────────
    // A connection that is closing with only a read armed is finished here,
    // because an armed read is ended by the peer or the socket and a closing
    // connection's peer has already gone -- taking the read back is
    // close_client()'s job and it already does it.
    finish_unreachable_client(cqe_fd);

#ifdef SOCKETLEY_INVARIANTS
    inv_check_reachable(cqe_fd, "cache::on_cqe");
#endif
}

// The rule and its argument live in shared/net/conn_reachability.h; what is here
// is finding the connection, naming its flags and closing it, with everything
// before the verdict a guard.
void cache_instance::finish_unreachable_client(int fd)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_LIKELY(conn == nullptr || !conn->closing))
        return;

    using socketley::reach::verdict;

    switch (socketley::reach::classify(conn->closing, conn_owed(conn),
                                       conn_has_output(conn)))
    {
        case verdict::keep:
            // A write is outstanding, and its completion comes back here to
            // ask this question again.
            return;

        case verdict::flush:
            // Bytes the client already handed us and considers answered are not
            // "nothing left": push them out and let the write completion finish
            // the teardown, exactly as the closing block in handle_read does.
            if (SOCKETLEY_UNLIKELY(!flush_write_queue(conn)))
            {
                close_client(conn, fd, "unreachable-write-submit-failed");
                return;
            }
            // A flush can legitimately submit nothing — a TLS session with a
            // reply queued while the handshake is still running has output and
            // no way to send it — and that leaves nothing to wake it either.
            if (socketley::reach::classify(conn->closing, conn_owed(conn),
                                           /*has_output=*/false) == verdict::keep)
                return;
            close_client(conn, fd, "unreachable-with-unsendable-output");
            return;

        case verdict::finish:
            close_client(conn, fd, "unreachable-closing");
            return;
    }
}

// The flags this runtime's connection carries sorted by who must report them,
// of which three are simply not reachable for a cache client.
socketley::reach::owed cache_instance::conn_owed(const client_connection* conn) const
{
    socketley::reach::owed o;
    o.write    = conn->write_pending;
    o.read     = conn->read_pending;   // not counted; see the header
    // A crossing answers through the request channel on a later turn, which
    // is what keeps a connection with its read withdrawn reachable.
    o.promised_reply = !conn->batches.empty();
    // The read a drain holds open ends at the client's EOF, which is what it
    // exists to wait for; the byte bound ends it otherwise.
    o.drain = conn->wr_shutdown && conn->read_pending &&
              conn->drained_bytes <= DRAIN_LIMIT_BYTES;
    return o;
}

#ifdef SOCKETLEY_INVARIANTS
// Invariant (1), where a cache client has no peer so the pair is a single half
// and the question is whether the ring still owes it anything.
void cache_instance::inv_check_reachable(int fd, const char* where)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;

    const auto* conn = m_conn_idx[fd];
    if (!conn)
        return;   // already torn down: nothing left that needs waking

    skl_inv::half c{};
    c.present   = true;
    c.in_flight = conn->read_pending || conn->write_pending
               || !conn->batches.empty();
    // response_buf counts as queued too: it is answers already built and not yet
    // handed to the write path, which is the same loss with one hop less.
    c.queued    = !conn->write_queue.empty() || !conn->response_buf.empty();
    c.closing   = conn->closing;
    c.fd        = conn->fd;

    SKL_INV_PAIR(where, c, skl_inv::half{});
}
#endif

// Whether the peer on `fd` is this machine, where a unix socket always is.
static bool peer_is_local(int fd)
{
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0)
        return false;
    if (ss.ss_family == AF_UNIX)
        return true;
    if (ss.ss_family == AF_INET)
        return (ntohl(reinterpret_cast<const sockaddr_in*>(&ss)->sin_addr.s_addr) >> 24) == 127;
    if (ss.ss_family == AF_INET6)
    {
        const in6_addr& a = reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(&a) ||
               (IN6_IS_ADDR_V4MAPPED(&a) && a.s6_addr[12] == 127);
    }
    return false;
}

bool cache_instance::adopt_client(int client_fd, bool from_cluster, bool from_unix, bool handed)
{
    // Reject fds beyond our O(1) lookup table — they'd become zombie connections
    if (client_fd >= MAX_FDS)
    {
        close_tracked(client_fd);
        return false;
    }

    // Protected mode: the one door every accepted connection comes through,
    // answered in a line both protocols read as an error, before a byte of
    // the peer's is.
    // A connection a sibling hands over was admitted there, and anything said to it here would reach a client the
    // sibling is still keeping if this shard refuses it.
    if (!handed && (!from_unix || from_cluster) && !m_admits_remote && !peer_is_local(client_fd))
    {
        static constexpr std::string_view denied =
            "-DENIED this cache serves only this machine: it has no password, "
            "so a peer on the network is refused unless the runtime is created "
            "with --public or with mutual TLS (--tls --ca)\r\n";
        if (::send(client_fd, denied.data(), denied.size(), MSG_NOSIGNAL | MSG_DONTWAIT) < 0) {}
        close_tracked(client_fd);
        return false;
    }

    if (connections_full(m_clients.size(), m_max_conns_cached))
    {
        close_tracked(client_fd);
        return false;
    }

    // TCP-level, so a client accepted off a unix listener would spend a
    // syscall per accept on nothing; the cluster listener is TCP by
    // construction.  A handed socket was tuned where it was accepted, and its options travel with it.
    if (!handed && (!from_unix || from_cluster))
    {
        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        // A peer that loses power sends no FIN, and a cache with no
        // --idle-timeout holds that connection -- and its entry in the
        // subscriber table -- for ever.
        socket_tuning::keepalive_dead_peer(client_fd);
    }
    else if (!handed)
        socketley::unix_sock::tune_stream(client_fd);

    if (!handed)
        stat_add(m_stat_total_connections, 1);

    auto conn = pool_acquire(client_fd);
    SKL_TRACE_SET(conn, opened_ms, ::skl_trace::now_ms());
    // Grown on demand rather than reserved: four kilobytes apiece, charged the
    // moment a socket is accepted and before it has said anything, is eight of
    // the fourteen kilobytes an idle connection cost.  A connection that does
    // work grows into the same capacity on its first command and keeps it,
    // because clear() does not give it back, so the reserve only ever bought
    // the first growth -- and bought it for every connection that never has a
    // first command.

    // Only a start without a buffer ring reads into this AT ACCEPT, so only
    // such a start pays for it there; every other connection gets it from
    // fallback_read_buf() the first time an arm actually needs one.
    if (SOCKETLEY_UNLIKELY(!m_use_provided_bufs) && !conn->read_buf)
        conn->read_buf = std::make_unique<char[]>(client_connection::READ_BUF_BYTES);
    conn->read_req = { this, conn->read_buf.get(), client_fd,
                       static_cast<uint32_t>(client_connection::READ_BUF_BYTES), op_read };
    conn->write_req = { this, nullptr, client_fd, 0, op_write };

    // Register fd in fixed file table for fget/fput-free I/O
    int slot = m_loop->alloc_fixed_file_slot();
    if (slot >= 0)
    {
        if (m_loop->update_registered_file(static_cast<uint32_t>(slot), client_fd))
        {
            conn->fixed_idx = slot;
            conn->direct_fd = true;
        }
        else
        {
            // The slot is already marked used, so a slot that cannot be
            // pointed at this fd has to go back at once: the connection never
            // learns its number, and nothing else in the process holds it.
            // Folded into one `&&` here, this leaked one of MAX_FIXED_FILES
            // per failed registration until alloc returned -1 for every later
            // connection and the cache dropped off the direct-descriptor path
            // for the rest of its life, silently.  The server's copy of these
            // eight lines has had this arm all along.
            m_loop->free_fixed_file_slot(static_cast<uint32_t>(slot));
        }
    }

    conn->cluster_port = from_cluster;
    conn->unix_peer    = from_unix && !from_cluster;

    auto* ptr = conn.get();
    m_clients[client_fd] = std::move(conn);
    if (client_fd < MAX_FDS)
        m_conn_idx[client_fd] = ptr;

    // A TLS listener gives every accepted socket a session before anything
    // else touches it, with the handshake starting on the first read
    // because the client speaks first.
    if (SOCKETLEY_UNLIKELY(m_tls != nullptr))
    {
        ptr->ssl = m_tls->create_ssl_server();
        if (SOCKETLEY_UNLIKELY(!ptr->ssl))
        {
            // No session means no encryption and so no connection, because
            // serving this client in cleartext is worse than dropping it.
            shutdown(client_fd, SHUT_RDWR);
            close_client(ptr, client_fd, "tls-session-alloc-failed");
            return false;
        }
        ptr->tls_state = tls_conn_handshake;
        ptr->handshake_since = std::chrono::steady_clock::now();
    }

    // Initialize rate limiting
    auto now_tp = std::chrono::steady_clock::now();
    if (m_rate_limit_cached > 0)
    {
        ptr->rl_max = m_rate_limit_cached;
        ptr->rl_tokens = m_rate_limit_cached;
        ptr->rl_last = now_tp;
    }

    ptr->last_activity = now_tp;

    // A connection whose first read cannot be armed can make no progress,
    // and nothing touches ptr after this, so the teardown is safe here.
    if (SOCKETLEY_UNLIKELY(!submit_client_read(ptr, client_fd)))
    {
        close_client(ptr, client_fd, "read-submit-failed");
        return false;
    }
    return true;
}

void cache_instance::handle_accept(struct io_uring_cqe* cqe, io_request* req)
{
    int client_fd = cqe->res;

    // Which of the two listeners reported, which only the request says,
    // because the completion carries the accepted descriptor rather than the
    // listening one.
    const bool from_cluster =
        (m_cluster_accept != nullptr && req == &m_cluster_accept->req);

    // False is a descriptor already dealt with, and the listener re-arms
    // either way.
    if (client_fd >= 0)
        adopt_client(client_fd, from_cluster, !m_bound_listen_path.empty());

    // EMFILE/ENFILE: backoff 100ms to avoid CPU spin when fd limit is hit
    if (client_fd == -EMFILE || client_fd == -ENFILE)
    {
        schedule_accept_backoff();
        return;
    }

    // The listener that reported and only that one, because re-arming the
    // other would give it a second chain on one io_request and one address
    // buffer.
    {
        const bool multishot = from_cluster ? m_cluster_multishot_active
                                            : m_multishot_active;
        if (!multishot || !(cqe->flags & IORING_CQE_F_MORE))
        {
            if (from_cluster) rearm_cluster_accept();
            else              rearm_accept();
        }
    }
}

void cache_instance::on_loop_turn()
{
    // First, so what this turn's parses crossed for is on its way before anything else here can run a command.
    if (m_turn_cross_any)
        post_turn_crossings();
    if (SOCKETLEY_UNLIKELY(!m_finish_due.empty()))
        finish_due();
    if (SOCKETLEY_UNLIKELY(m_cluster_ports && m_shard_i == 0 && !m_relay_said))
        relay_watch();
    publish_keyspace();
    if (SOCKETLEY_UNLIKELY(!m_lua_pub.empty()))
        flush_lua_publishes();
    // Readers an XADD has woken this turn, served now the commands are done.
    if (SOCKETLEY_UNLIKELY(!m_stream_ready.empty()))
        serve_stream_ready();
    // A direct send has no completion, so what one would have run runs here,
    // once the turn has settled what the connection wants.
    if (m_direct_fd >= 0)
    {
        const int fd = m_direct_fd;
        m_direct_fd = -1;
        if (auto* c = m_conn_idx[fd]; c && !c->write_pending)
            after_write(c, fd);
    }
    m_direct_gate.next_turn();
    if (m_companion)
        m_companion->pump();
    if (SOCKETLEY_UNLIKELY(!m_ho_waiting.empty() || !m_ho_sent.empty()))
        handoff_turn();
}

// Said once, by shard 0, when two windows in a row under load relayed at least half of what arrived on the shared
// port, since cluster mode keeps the start quiet and an ordinary client there pays for every relay silently.
void cache_instance::relay_watch()
{
    const uint64_t now = socketley::turn_clock::now_ns();
    if (m_relay_win_ns == 0 || now - m_relay_win_ns >= RELAY_WINDOW_NS)
    {
        const uint64_t cmds    = m_stat_shared_cmds - m_relay_win_cmds;
        const uint64_t relayed = m_stat_relayed_cmds - m_relay_win_relayed;
        const bool     started = m_relay_win_ns != 0;
        m_relay_win_ns       = now;
        m_relay_win_cmds     = m_stat_shared_cmds;
        m_relay_win_relayed  = m_stat_relayed_cmds;
        if (!started)
            return;
        m_relay_high = (cmds >= RELAY_WINDOW_MIN && relayed * 2 >= cmds) ? m_relay_high + 1 : 0;
        if (m_relay_high < RELAY_HIGH_WINDOWS)
            return;
        m_relay_said = true;
        const uint16_t port = m_base_port;
        LOG_WARN(("cache \"" + std::string(get_name()) + "\": " + std::to_string(relayed * 100 / cmds)
                  + "% of the commands on its shared port named a key another shard owns and were relayed "
                  "there, which costs about twice what answering them does.  A cluster-aware client routes each "
                  "key to its shard's own port (" + std::to_string(port + 1) + ".."
                  + std::to_string(port + m_shard_n) + "); "
                  + (m_handoff_on ? "SOCKETLEY_CACHE_HANDOFF hands a connection to the shard its keys keep to, and "
                                    "these connections' keys keep to none"
                                  : "SOCKETLEY_CACHE_HANDOFF, off here, hands a connection whose keys keep to one "
                                    "shard to it")
                  + ".  stats shows relayed_commands per shard").c_str());
    }
}

bool cache_instance::submit_client_read(client_connection* conn, int fd)
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return false;

    conn->read_pending = true;
    bool queued = false;
    if (conn->direct_fd)
    {
        // Bundle first and plain multishot behind it, because a refused bundle
        // is not an error and the plain arm serves the same bytes one buffer
        // per completion.
        // Every arm on `!queued` and none on `else`: the chain used to read
        // `if (!queued && m_recv_multishot) ... else if (!queued && ...)`, so
        // taking the multishot branch skipped the two behind it even when it
        // came back false.  With the bundle and the multishot both refused in
        // one turn -- one ring under pressure, two null SQEs -- the caller saw
        // false and closed a healthy client that a plain read would have
        // served.
        if (m_recv_bundle)
            queued = m_loop->submit_recv_multishot_bundle_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_recv_multishot)
            queued = m_loop->submit_recv_multishot_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_use_provided_bufs)
            queued = m_loop->submit_read_provided_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        if (!queued)
        {
            conn->read_req.type = op_read;
            queued = m_loop->submit_read_fixed_file(conn->fixed_idx, fallback_read_buf(conn),
                                                    client_connection::READ_BUF_BYTES, &conn->read_req);
        }
    }
    else
    {
        // The same chain, and it had the same dead branches.
        if (m_recv_bundle)
            queued = m_loop->submit_recv_multishot_bundle(fd, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_recv_multishot)
            queued = m_loop->submit_recv_multishot(fd, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_use_provided_bufs)
            queued = m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
        if (!queued)
        {
            conn->read_req.type = op_read;
            queued = m_loop->submit_read(fd, fallback_read_buf(conn),
                                         client_connection::READ_BUF_BYTES, &conn->read_req);
        }
    }

    // Leaving the flag set after a refusal is what turns a busy ring into a hung
    // connection: every path here treats read_pending as "a completion is on its
    // way", and none is.
    if (SOCKETLEY_UNLIKELY(!queued))
        conn->read_pending = false;
    return queued;
}

// Withdraw the read, or with none armed withhold the next one, so the kernel's
// socket buffer holds the client for as long as its crossings take.
void cache_instance::pause_read(client_connection* conn)
{
    if (conn->read_paused)
        return;
    if (!conn->read_pending)
    {
        conn->read_paused = true;
        return;
    }
    // A refused cancel leaves the read standing and the next completion asks
    // again, so nothing is lost either way.
    if (m_loop && m_loop->submit_cancel_request(&conn->read_req))
        conn->read_paused = true;
}

// The read comes back once enough crossings are answered, with false meaning
// the ring refused it.
bool cache_instance::resume_read(client_connection* conn, int fd)
{
    if (!conn->read_paused || conn->read_pending || conn->closing
        || conn->crossing_bytes >= read_buffer_bytes())
        return true;
    conn->read_paused = false;
    return submit_client_read(conn, fd);
}

void cache_instance::schedule_accept_backoff()
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return;

    // One backoff timer at a time, because a second on the same request gives
    // the listener two retry chains and the earlier timeout cannot be taken
    // back.
    if (m_accept_backoff_timer)
        return;

    m_accept_backoff_timer = std::make_unique<timer_op>();
    m_accept_backoff_timer->ts.tv_sec = 0;
    m_accept_backoff_timer->ts.tv_nsec = 100000000LL;
    m_accept_backoff_timer->req = { this, nullptr, -1, 0, op_timeout };
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_accept_backoff_timer->ts,
                                                   &m_accept_backoff_timer->req)))
    {
        m_accept_backoff_timer.reset();
        LOG_ERROR("cache: accept could not be re-armed and the retry timer was refused too — "
                  "the listener has stopped taking connections");
    }
}

// Choose the accept shape and arm it, written once for both listeners because
// which shape this kernel can do is a property of the kernel.
void cache_instance::arm_listener(int fd, accept_op& op, bool& multishot)
{
    op.req = { this, nullptr, -1, 0, op_accept };
    if (event_loop::supports_multishot_accept())
    {
        op.req.type = op_multishot_accept;
        multishot = true;
    }
    else
    {
        op.req.type = op_accept;
        multishot = false;
    }
    rearm_accept_on(fd, &op, multishot);
}

void cache_instance::rearm_accept_on(int fd, accept_op* op, bool multishot)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || fd < 0 || !op))
        return;

    bool queued;
    if (multishot)
    {
        queued = m_loop->submit_multishot_accept(fd, &op->req);
    }
    else
    {
        op->addrlen = sizeof(op->addr);
        queued = m_loop->submit_accept(fd, &op->addr, &op->addrlen, &op->req);
    }

    // The listener has no completion left to bring it back, so fall back to the
    // backoff timer rather than going deaf without a word.
    if (SOCKETLEY_UNLIKELY(!queued))
        schedule_accept_backoff();
}

void cache_instance::rearm_accept()
{
    rearm_accept_on(m_listen_fd, m_accept.get(), m_multishot_active);
}

void cache_instance::rearm_cluster_accept()
{
    rearm_accept_on(m_cluster_listen_fd, m_cluster_accept.get(),
                    m_cluster_multishot_active);
}

// Ciphertext in and plaintext into conn->partial, one call per read
// completion, which is what makes the handshake asynchronous -- the server
// runtime's implementation over the cache's connection struct and deliberately
// not a second design.
void cache_instance::tls_feed(client_connection* conn, const char* data, size_t len)
{
    // Inbound ciphertext into the read BIO, whose refusal is fatal by contract
    // because there is nowhere to hold what was not taken.
    size_t off = 0;
    while (off < len)
    {
        const int n = tls_context::bio_write_in(conn->ssl, data + off,
                                                static_cast<int>(len - off));
        if (SOCKETLEY_UNLIKELY(n <= 0))
        {
            conn->closing = true;
            return;
        }
        off += static_cast<size_t>(n);
    }

    if (conn->tls_state == tls_conn_handshake)
    {
        const int r = tls_context::do_handshake(conn->ssl);
        if (SOCKETLEY_UNLIKELY(r < 0))
        {
            // Closing but not silently, because the alert is the only
            // diagnosis the other end gets -- and this is also the path a
            // plaintext client takes, which is refused rather than downgraded.
            conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out at the end of the read

        conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning, because under
        // TLS 1.3 a client's Finished and its first command routinely arrive
        // in one packet.
    }

    // Plaintext into partial, where RESP detection and the line parser read it.
    char plain[16384];
    for (;;)
    {
        const int n = tls_context::ssl_read(conn->ssl, plain, sizeof(plain));
        if (SOCKETLEY_LIKELY(n > 0))
        {
            conn->partial.append(plain, static_cast<size_t>(n));
            // The same ceiling the cleartext path applies, checked inside the
            // loop, because one read completion can decrypt everything the
            // inbound BIO had buffered.
            if (SOCKETLEY_UNLIKELY(read_overflows(conn->partial.size(), conn->read_arrived)))
            {
                // Said out loud here as well as on the cleartext path.  The
                // two halves had the same condition and only one of them left
                // a record, so whether a closed connection could be explained
                // depended on whether the listener happened to be TLS.
                //
                // Once per connection and not once per read: this check sits
                // inside the ssl_read loop, and the ciphertext for one
                // oversized command arrives over several completions that each
                // re-enter it.  Measured before the guard: four lines for one
                // connection, against one on the cleartext path.
                if (!conn->closing)
                {
                    LOG_WARN(("cache \"" + std::string(get_name()) + "\": a client "
                              "accumulated more than " + std::to_string(read_buffer_bytes()) +
                              " bytes without a complete command; its connection is closed")
                             .c_str());
                }
                conn->closing = true;
                break;
            }
            continue;
        }
        if (n < 0)
        {
            // Either the peer's close_notify or an unusable record, recorded
            // and applied once handle_read has parsed the bytes decrypted
            // above.
            conn->tls_peer_closed = true;
        }
        break;
    }
}

void cache_instance::tls_close_when_read_is_all(client_connection* conn, int fd)
{
    // Everything here is a guard: a connection that is not closing, still owes
    // a write, or has no session is somebody else's business.
    if (!conn->closing || conn->ssl == nullptr)
        return;
    if (conn->write_pending || !conn->read_pending)
        return;
    if (fd < 0 || tls_say_close(conn))
        return;

    withdraw_read_for_close(conn, fd);
}

bool cache_instance::tls_say_close(client_connection* conn)
{
    if (!conn->closing || conn->ssl == nullptr || conn->write_pending || conn_has_output(conn) ||
        !tls_context::close_notify(conn->ssl))
        return false;
    return tls_flush(conn) && conn->write_pending;
}

void cache_instance::drain_before_close(client_connection* conn, int fd)
{
    if (!conn->closing || conn->ssl != nullptr || fd < 0)
        return;
    if (conn->write_pending || conn_has_output(conn) || !conn->read_pending)
        return;
    withdraw_read_for_close(conn, fd);
}

// Withdrawn rather than ended by shutdown(SHUT_RD): with that and the FIN out, a byte the client still sends makes the
// kernel reset the connection and throw away what it has not delivered of the answer.
void cache_instance::withdraw_read_for_close(client_connection* conn, int fd)
{
    if (conn->read_withdrawn || !conn->read_pending)
        return;
    if (m_loop && m_loop->submit_cancel_request(&conn->read_req))
    {
        conn->read_withdrawn = true;
        return;
    }
    shutdown(fd, SHUT_RD);
}

bool cache_instance::conn_has_output(const client_connection* conn) const
{
    if (!conn->write_queue.empty())
        return true;
    // A TLS connection can owe the wire bytes with an empty queue: a handshake
    // flight, an alert, a session ticket, or ciphertext that did not fit in the
    // write that just completed.
    return conn->ssl != nullptr && tls_context::has_pending_out(conn->ssl);
}

// Every byte a TLS connection sends is a record, including the ones nobody
// queued, and there is no other way onto the wire.
bool cache_instance::tls_flush(client_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !conn->ssl))
        return true;

    // One write in flight at a time, because a second submission would need a
    // second buffer and would interleave two record streams on one socket.
    if (conn->write_pending)
        return true;

    // Application data only once the handshake is done, so a reply queued
    // before a record has crossed waits rather than being handed to an SSL
    // that answers WANT_READ.
    if (conn->tls_state == tls_conn_ready)
    {
        // Room for the records of what is queued, as the proxy reserves it, so the write BIO does not regrow from empty.
        if (!conn->write_queue.empty())
        {
            const size_t plain = std::min<size_t>(conn->write_queue.bytes(),
                                                  tls_context::max_bio_buffered + conn->write_queue.front().view().size());
            tls_context::reserve_out(conn->ssl, plain + plain / 16384 * 22 + 64);
        }
        while (!conn->write_queue.empty())
        {
            const std::string_view msg = conn->write_queue.front().view();
            const int n = tls_context::ssl_write(conn->ssl, msg.data(),
                                                 static_cast<int>(msg.size()));
            if (n <= 0)
            {
                // 0 is backpressure and the same buffer is offered again once
                // the write BIO drains, which leaving the message at the front
                // of the queue arranges; -1 is fatal.
                if (n < 0)
                    conn->closing = true;
                break;
            }
            // Partial writes are not enabled on this context, so a short count
            // would mean the record layer and this queue disagree about what
            // has been sent.
            if (SOCKETLEY_UNLIKELY(static_cast<size_t>(n) != msg.size()))
            {
                conn->closing = true;
                break;
            }
            conn->write_queue.pop();
        }
    }

    if (!tls_context::has_pending_out(conn->ssl))
        return true;

    // Ciphertext copied out of the write BIO into a buffer this connection
    // owns, because the BIO's storage moves under an SQE -- and it rides in
    // write_batch[0] so the short-write retry needs no TLS case.
    std::string cipher;
    if (SOCKETLEY_UNLIKELY(tls_context::take_out(conn->ssl, cipher) == 0))
        return true;

    // Nothing is in flight (checked above), so any buffers still held are from
    // a completed write and are this function's to drop.
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        { conn->write_batch[i].clear(); conn->write_batch_seg[i].reset(); }

    conn->write_batch[0] = std::move(cipher);
    conn->write_iovs[0].iov_base = conn->write_batch[0].data();
    conn->write_iovs[0].iov_len  = conn->write_batch[0].size();
    conn->write_batch_count = 1;
    conn->write_pending = true;
    conn->write_req.type = op_write;

    const auto len = static_cast<uint32_t>(conn->write_batch[0].size());
    const bool queued = conn->direct_fd
        ? m_loop->submit_write_fixed_file(conn->fixed_idx, conn->write_batch[0].data(),
                                          len, &conn->write_req)
        : m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);

    // Nothing reached the ring, so the in-flight bookkeeping is undone and
    // reported, because a write_pending that never clears keeps the teardown
    // waiting.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        conn->write_batch[0].clear();
        conn->write_batch_count = 0;
        return false;
    }
    return true;
}

// One chain, armed by whichever question needs it first and never twice: the
// timer existing is what says it is running, since the sweep re-arms itself for
// as long as the instance lives.
void cache_instance::arm_idle_sweep_if_needed()
{
    if (!m_loop || m_idle_sweep_timer)
        return;

    auto t = std::make_unique<timer_op>();
    t->ts.tv_sec  = 30;
    t->ts.tv_nsec = 0;
    t->req = { this, nullptr, -1, 0, op_timeout };
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&t->ts, &t->req)))
    {
        LOG_ERROR("cache: idle sweep timer refused — idle connections and "
                  "half-arrived commands will not be reaped");
        return;
    }
    m_idle_sweep_timer = std::move(t);
}

// Whether this connection is still becoming commands, decided once for both
// protocols rather than by each parser.  A buffer that shrank had a command
// taken out of it, which is progress however much is left behind; a buffer that
// did not is a client that has stopped mid-command, and its clock starts.
void cache_instance::note_partial_progress(client_connection* conn, size_t before)
{
    if (conn->partial.empty())
    {
        conn->partial_since = {};
        return;
    }

    // Re-dated and not merely left running: a client pipelining steadily never
    // empties this buffer, and a clock that only stopped at empty would drop it
    // for keeping the runtime busy.
    if (conn->partial.size() < before || conn->partial_since.time_since_epoch().count() == 0)
    {
        conn->partial_since = std::chrono::steady_clock::now();
        m_partials_outstanding = true;
        arm_idle_sweep_if_needed();
    }
}

// The text line splitter, out of handle_read so a connection whose crossing
// has come back is driven by the same code, because two drivers for one parser
// stop matching.
bool cache_instance::parse_text_lines(client_connection* conn)
{
    bool   cut = false;
    size_t scan_from = 0;
    size_t pos;
    size_t search = conn->text_searched <= conn->partial.size() ? conn->text_searched : 0;
    conn->text_searched = 0;
    bool ran_out = false;
    for (;;)
    {
        if ((pos = conn->partial.find('\n', std::max(scan_from, search))) == std::string::npos)
        {
            ran_out = true;
            break;
        }
        search = 0;
        // A run of routed commands is cut here, in the loop that decides what
        // has been consumed, with the rest left in `partial` for the batch
        // after this one.
        if (SOCKETLEY_UNLIKELY(m_collect
                               && m_collect->slots.size() >= MAX_ROUTED_PER_BATCH))
        {
            cut = true;
            break;
        }

        // The same stop the RESP loop makes, for the same reason.
        if (SOCKETLEY_UNLIKELY(conn->blocked))
            break;

        // And the same one it makes for a connection already closing, for the
        // same reason: nothing after this point can be delivered, and answering
        // it anyway is memory spent on a socket that is going away.
        if (SOCKETLEY_UNLIKELY(conn->closing))
            break;

        std::string_view line(conn->partial.data() + scan_from, pos - scan_from);

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        SKL_TRACE_ADD(conn, commands_parsed, 1);
        const size_t rb_before = conn->response_buf.size();
        process_command(conn, line);
        if (conn->response_buf.size() != rb_before)
            SKL_TRACE_ADD(conn, responses_made, 1);

        scan_from = pos + 1;

        // The RESP loop's 1 MiB flush, because one read of `get k` lines
        // against a large value otherwise answered hundreds of copies of it
        // before the write-queue cap was consulted at all.
        if (SOCKETLEY_UNLIKELY(conn->response_buf.size() > (1 << 20)))
        {
            if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
            {
                conn->closing = true;
                break;
            }
            conn->response_buf.reserve(4096);
        }

        // REPLICATE takes effect on the line that carried it, so answering the
        // rest of the batch would put a second writer on the socket the dump
        // is going out on.
        if (SOCKETLEY_UNLIKELY(conn->is_follower))
            break;
    }

    if (scan_from > 0)
    {
        if (scan_from >= conn->partial.size())
            conn->partial.clear();
        else
            conn->partial.erase(0, scan_from);
    }
    // All that is left was searched, unless the loop stopped with whole lines still in it.
    if (ran_out)
        conn->text_searched = conn->partial.size();

    // Whatever was pipelined behind REPLICATE is refused, not executed.
    if (SOCKETLEY_UNLIKELY(conn->is_follower && !conn->partial.empty()))
        refuse_follower_input(conn);
    return cut;
}

// Everything a connection's buffered bytes turn into, with a crossing already
// out not stopping the next: replies go back down one pipe in order, and
// batch_finish() keeps that order, so parsing need not wait.
void cache_instance::pump(client_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(conn->closing))
        return;

    if (SOCKETLEY_UNLIKELY(conn->is_follower))
    {
        refuse_follower_input(conn);
        return;
    }

    // Around again only when the parser stopped at MAX_ROUTED_PER_BATCH, so
    // nothing parseable is left behind for a read that may never come.
    const size_t partial_before = conn->partial.size();
    for (;;)
    {
        const bool cut = conn->resp_mode ? process_resp(conn)
                                         : parse_text_lines(conn);
        route_flush(conn);
        if (SOCKETLEY_LIKELY(!cut) || conn->closing)
            break;
    }
    note_partial_progress(conn, partial_before);

    if (SOCKETLEY_UNLIKELY(conn->crossing_bytes >= read_buffer_bytes()))
        pause_read(conn);
}

void cache_instance::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    if (SOCKETLEY_UNLIKELY(fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]))
    {
        // Nobody owns this any more, but the buffer it carries belongs to a
        // ring group shared by every cache on this loop.
        if (m_loop) m_loop->return_cqe_buf(cqe, req);
        return;
    }
    auto* conn = m_conn_idx[fd];

    bool is_multishot_recv = is_multishot_recv_op(req->type);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    // For multishot recv, the read remains pending as long as MORE flag is set
    if (!is_multishot_recv)
        conn->read_pending = false;
    else if (!multishot_more)
    {
        conn->read_pending = false;
        SKL_TRACE_ADD(conn, multishot_ends, 1);
    }

    // A read being withdrawn for a handoff keeps what it brings for the sibling and runs none of it.
    if (SOCKETLEY_UNLIKELY(conn->ho_state == client_connection::handoff::withdrawing))
    {
        handoff_read(conn, fd, cqe, req);
        return;
    }

    bool is_provided = (req->type == op_read_provided || is_multishot_recv);

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        // Return any provided buffers through the loop, which knows whether
        // this completion was a bundle carrying more than the CQE names.
        if (is_provided && (cqe->flags & IORING_CQE_F_BUFFER))
            m_loop->return_cqe_buf(cqe, req);

        // ENOBUFS: buffer pool exhausted — fall back to regular read
        if (is_provided && cqe->res == -ENOBUFS)
        {
            SKL_TRACE_ADD(conn, enobufs, 1);
            conn->read_pending = true;
            // Reset the request type, because leaving it as a provided-buffer
            // type makes the handler append ring buffer 0's contents and
            // return a buffer it never took.
            conn->read_req.type = op_read;
            bool queued;
            if (conn->direct_fd)
                queued = m_loop->submit_read_fixed_file(conn->fixed_idx, fallback_read_buf(conn),
                                                        client_connection::READ_BUF_BYTES, &conn->read_req);
            else
                queued = m_loop->submit_read(fd, fallback_read_buf(conn),
                                             client_connection::READ_BUF_BYTES, &conn->read_req);
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                // The fallback is the only read left for this connection; with
                // it refused there is nothing to wake it again.
                conn->read_pending = false;
                conn->closing = true;
                if (!conn->write_pending)
                    close_client(conn, fd, "read-submit-failed");
            }
            return;
        }

        // The read pause_read() withdrew, reporting; the crossing it waited
        // for may have been answered in between, in which case it resumes here.
        if (cqe->res == -ECANCELED && conn->read_paused && !conn->closing)
        {
            if (!conn->closing && SOCKETLEY_UNLIKELY(!resume_read(conn, fd)))
                close_client(conn, fd, "read-submit-failed");
            return;
        }

        // Connection closed or error, deferred if a write is still owed, with
        // the subscriptions dropped at once.
        m_store.unsubscribe_all(fd);
        m_store.punsubscribe_all(fd);

        // Asked first, because a crossing owed to this socket outranks a write
        // in flight: flush_responses() drops a closing connection's buffer, so
        // one run in five of a twelve-command pipeline came back with the
        // first reply alone.
        if (!conn->batches.empty())
        {
            // Held and not closed, because another shard owes this socket an
            // answer and a client half-closing the moment it finished asking
            // is what a request/response client does.
            conn->peer_gone = true;
        }
        else if (conn->write_pending)
        {
            conn->closing = true;
        }
        else
        {
            close_client(conn, fd, "read-error-or-eof");
        }
        return;
    }

    // Nothing a closing connection sends is parsed, and appending it only grew
    // `partial` toward the overflow close that reset the answer away.
    if (SOCKETLEY_UNLIKELY(conn->closing && conn->ssl == nullptr))
    {
        if (is_provided)
            m_loop->return_cqe_buf(cqe, req);
        conn->drained_bytes += static_cast<size_t>(cqe->res);
        if (conn->drained_bytes > DRAIN_LIMIT_BYTES)
        {
            if (!conn->write_pending)
                close_client(conn, fd, "drain-limit");
            return;
        }
        // A withdrawn read is not armed again: the close it was withdrawn for is next.
        if (!conn->read_pending && conn->read_withdrawn)
        {
            if (!conn->write_pending)
                close_client(conn, fd, "closing-read-withdrawn");
            return;
        }
        if (!conn->read_pending && m_loop &&
            SOCKETLEY_UNLIKELY(!submit_client_read(conn, fd)))
        {
            if (!conn->write_pending)
                close_client(conn, fd, "read-submit-failed");
            return;
        }
        drain_before_close(conn, fd);
        return;
    }

    // Only update last_activity when idle timeout is configured (avoids clock_gettime syscall)
    if (SOCKETLEY_UNLIKELY(m_idle_timeout_cached > 0))
        conn->last_activity = std::chrono::steady_clock::now();

    // Wire bytes in, counted at this handler because there is no shared
    // chokepoint: what a completion contributes is decided by the branches
    // above and which completions count is a per-runtime decision that already
    // diverges.
    stat_add(m_stat_bytes_in, static_cast<uint64_t>(cqe->res));
    conn->read_arrived = static_cast<uint32_t>(cqe->res);
    // A search offset names the partial it was taken over; changed since, it names nothing.
    if (conn->partial.size() != conn->text_searched)
        conn->text_searched = 0;
    if (conn->batch_ns == 0)
        conn->batch_ns = socketley::turn_clock::now_ns();

    // On a TLS connection these bytes are ciphertext and tls_feed puts
    // plaintext into partial, so everything below reads the same buffer it
    // always did.
    if (is_provided)
    {
        // How a completion's buffers are named and sliced is the loop's rule,
        // and what stays here is where the bytes go -- with the buffer
        // returned inside the helper whatever the session made of it.
        m_loop->for_each_cqe_buf(BUF_GROUP_ID, cqe, [&](char* p, uint32_t n) {
            if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
                tls_feed(conn, p, static_cast<size_t>(n));
            else
                conn->partial.append(p, n);
        });
        SKL_TRACE_ADD(conn, bytes_read, cqe->res);
        SKL_TRACE_ADD(conn, reads, 1);
    }
    else if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_feed(conn, conn->read_buf.get(), static_cast<size_t>(cqe->res));
        SKL_TRACE_ADD(conn, bytes_read, cqe->res);
        SKL_TRACE_ADD(conn, reads, 1);
    }
    else
    {
        conn->partial.append(conn->read_buf.get(), cqe->res);
        SKL_TRACE_ADD(conn, bytes_read, cqe->res);
        SKL_TRACE_ADD(conn, reads, 1);
    }

    if (SOCKETLEY_UNLIKELY(read_overflows(conn->partial.size(), conn->read_arrived)))
    {
        // A line that never ends and nothing else, because the pump parses
        // every whole command as it arrives, crossing or no crossing.
        // The limit rather than the figure it happened to be compiled with:
        // --read-buffer moves this, and a message naming 1 MiB on an 8 MiB
        // runtime sends whoever reads it looking in the wrong place.
        //
        // Guarded like its twin in tls_feed(), because a TLS connection walks
        // BOTH: the decryptor appends and checks, and then this common check
        // runs on the same buffer.  Measured without the guard: two lines for
        // one TLS connection and one for a cleartext one.
        if (!conn->closing)
        {
            LOG_WARN(("cache \"" + std::string(get_name()) + "\": a client accumulated "
                      "more than " + std::to_string(read_buffer_bytes()) +
                      " bytes without a newline; its connection is closed").c_str());
        }
        conn->closing = true;
        if (!conn->write_pending)
        {
            close_client(conn, fd, "partial-overflow");
        }
        return;
    }

    // Auto-detect RESP mode on first data
    if (!conn->resp_detected && !conn->partial.empty())
    {
        conn->resp_detected = true;
        if (conn->partial[0] == '*' || m_resp_forced)
            conn->resp_mode = true;
    }

    // A connection promoted by REPLICATE is not a client any more, so parsing
    // what arrives on it would produce replies with nowhere to go.
    pump(conn);

    // Flush accumulated responses as single write
    if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
        conn->closing = true;

    // QUIT is honoured HERE, after the flush and not inside the command, for
    // the reason the protocol-error path had to learn: flush_responses drops a
    // closing connection's buffer, so a command that set the flag itself would
    // be answered into a buffer nobody sends.  The write-drain path closes it.
    if (SOCKETLEY_UNLIKELY(conn->quit_after_flush))
        conn->closing = true;

    // close_notify is applied here because the read that carried it can carry
    // the last command ahead of it, and then one flush covers everything the
    // record layer owes -- outside flush_responses(), which returns early on a
    // closing connection.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        if (conn->tls_peer_closed)
            conn->closing = true;
        if (SOCKETLEY_UNLIKELY(!tls_flush(conn)))
            conn->closing = true;
    }

    if (m_loop && !conn->closing)
    {
        // A pause whose cancel lost to this data is lifted here, because no crossing is left to resume it.
        const bool resumed = !conn->read_paused || resume_read(conn, fd);
        if (SOCKETLEY_UNLIKELY(!resumed)
            || (!conn->read_pending && !conn->read_paused
                && SOCKETLEY_UNLIKELY(!submit_client_read(conn, fd))))
        {
            conn->closing = true;
            if (!conn->write_pending)
                close_client(conn, fd, "read-submit-failed");
            return;
        }
        return;
    }

    // Kept reading, for drain_before_close(); a refused read falls through to
    // the close below as it always did.
    if (conn->closing && conn->ssl == nullptr && !conn->read_pending && !conn->read_paused && !conn->read_withdrawn &&
        m_loop && conn->drained_bytes <= DRAIN_LIMIT_BYTES)
        submit_client_read(conn, fd);

    // Closing with nothing left in flight, because every teardown used to run
    // out of a completion handler and a refused submission makes "the
    // completion never existed" the ordinary case.
    if (conn->closing && !conn->read_pending && !conn->write_pending)
    {
        // A queue that still holds data is not nothing in flight, and
        // conn_has_output rather than the queue alone because a session can
        // owe an alert with an empty queue.
        if (conn_has_output(conn))
        {
            if (SOCKETLEY_UNLIKELY(!flush_write_queue(conn)))
            {
                close_client(conn, fd, "write-submit-failed");
                return;
            }
            // A flush can legitimately submit nothing, and without this the
            // connection would be left closing with nothing to wake it.
            if (SOCKETLEY_UNLIKELY(!conn->write_pending))
                close_client(conn, fd, "closing-with-unsendable-output");
        }
        else if (!tls_say_close(conn))
        {
            close_client(conn, fd, "closing-nothing-in-flight");
        }
        return;
    }

    // Closing with the read as the only thing outstanding, which nothing will
    // complete unless the socket is moved.
    tls_close_when_read_is_all(conn, fd);
    drain_before_close(conn, fd);
}

void cache_instance::handle_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
        return;
    auto* conn = m_conn_idx[fd];

    conn->write_pending = false;
    SKL_TRACE_ADD(conn, writes, 1);
    if (cqe->res > 0)
        SKL_TRACE_ADD(conn, bytes_written, cqe->res);

    if (cqe->res <= 0)
    {
        SKL_TRACE_LOG("write failed fd=%d res=%d", fd, cqe->res);
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            { conn->write_batch[i].clear(); conn->write_batch_seg[i].reset(); }
        conn->write_batch_count = 0;
        conn->closing = true;
        if (!conn->read_pending)
        {
            close_client(conn, fd, "write-drained-closing");
        }
        return;
    }

    // Wire bytes out counted per completed send, with a short write's
    // remainder counted when it completes again.
    stat_add(m_stat_bytes_out, static_cast<uint64_t>(cqe->res));

    // Short write handling: resubmit remaining bytes
    if (conn->write_batch_count > 0)
    {
        size_t total_submitted = 0;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            total_submitted += conn->write_iovs[i].iov_len;

        size_t written = static_cast<size_t>(cqe->res);
        if (written < total_submitted)
        {
            // A shared segment's bytes are on the heap and stay put, an owned string's move with it.
            const uint32_t new_count = socketley::drop_written(
                conn->write_iovs, conn->write_batch_count, written,
                [&](uint32_t to, uint32_t from)
                {
                    conn->write_batch[to]     = std::move(conn->write_batch[from]);
                    conn->write_batch_seg[to] = std::move(conn->write_batch_seg[from]);
                },
                [&](uint32_t i) -> const char*
                { return conn->write_batch_seg[i] ? nullptr : conn->write_batch[i].data(); });
            for (uint32_t i = new_count; i < conn->write_batch_count; i++)
                { conn->write_batch[i].clear(); conn->write_batch_seg[i].reset(); }
            conn->write_batch_count = new_count;

            conn->write_pending = true;
            bool queued;
            if (new_count == 1)
            {
                conn->write_req.type = op_write;
                if (conn->direct_fd)
                    queued = m_loop->submit_write_fixed_file(conn->fixed_idx,
                        static_cast<const char*>(conn->write_iovs[0].iov_base),
                        static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                        &conn->write_req);
                else
                    queued = m_loop->submit_write(conn->fd,
                        static_cast<const char*>(conn->write_iovs[0].iov_base),
                        static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                        &conn->write_req);
            }
            else
            {
                conn->write_msg.msg_iov = conn->write_iovs;
                conn->write_msg.msg_iovlen = new_count;
                conn->write_req.type = op_writev;
                if (conn->direct_fd)
                    queued = m_loop->submit_sendmsg_fixed_file(conn->fixed_idx, &conn->write_msg, &conn->write_req);
                else
                    queued = m_loop->submit_sendmsg(conn->fd, &conn->write_msg, &conn->write_req);
            }
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                // The tail of a short write cannot be handed over, because
                // leaving write_pending set strands the connection halfway
                // through a reply.
                conn->write_pending = false;
                conn->closing = true;
                if (!conn->read_pending)
                    close_client(conn, fd, "write-submit-failed");
            }
            return;
        }
    }

    // Full write completed — release batch
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        { conn->write_batch[i].clear(); conn->write_batch_seg[i].reset(); }
    conn->write_batch_count = 0;

    after_write(conn, fd);
}

// What a finished write leaves to do, run from its completion or, for a direct
// send that has none, from the end of the turn that made it.
void cache_instance::after_write(client_connection* conn, int fd)
{
    // Flush whatever is still owed, asking conn_has_output rather than the
    // queue, because a TLS connection owes handshake records with nothing
    // queued at all.
    if (conn_has_output(conn))
    {
        if (SOCKETLEY_UNLIKELY(!flush_write_queue(conn)))
        {
            conn->closing = true;
            if (!conn->read_pending)
                close_client(conn, fd, "write-submit-failed");
            return;
        }
        // Same corner as in handle_read: a flush that submits nothing leaves a
        // closing connection with no completion left to finish it.
        if (SOCKETLEY_UNLIKELY(conn->closing && !conn->write_pending &&
                               !conn->read_pending))
            close_client(conn, fd, "closing-with-unsendable-output");
    }
    else
    {
        if (conn->closing && !conn->read_pending)
        {
            if (!tls_say_close(conn))
                close_client(conn, fd, "closing-after-write");
        }
        else
        {
            // Everything owed has left, which is the moment a connection can be handed on.
            if (SOCKETLEY_UNLIKELY(conn->ho_want) && !conn->closing)
            {
                try_handoff(conn, fd);
                return;
            }
            // The alert this write just carried was the last thing owed; the
            // read is all that is left and no one is going to complete it.
            tls_close_when_read_is_all(conn, fd);
            drain_before_close(conn, fd);
        }
    }
}

// ─── Helper: parse int from string_view ───

// A score is a double and is parsed whole, which from_chars cannot promise for
// doubles on every libstdc++ this builds against -- so strtod with its own end
// pointer, which reports the same thing.
static bool parse_double_sv(std::string_view sv, double& out)
{
    if (sv.empty() || sv.size() > 63)
        return false;
    char buf[64];
    std::memcpy(buf, sv.data(), sv.size());
    buf[sv.size()] = '\0';
    errno = 0;
    char* end = nullptr;
    const double v = std::strtod(buf, &end);
    if (end != buf + sv.size() || errno == ERANGE)
        return false;
    // strtod reads "nan" as a number, and NaN compares false against everything
    // -- so a bound that is NaN does not narrow a range, it opens it: measured,
    // `zrangebyscore k nan nan` answered with every member of the set.  Redis
    // refuses it for the same reason and this is where every bound comes past.
    if (std::isnan(v))
        return false;
    out = v;
    return true;
}

// A whole score prints as an integer, the way every other protocol here shows
// one, and only a fractional score pays for a decimal point.
static void append_score_bare(std::string& rb, double sc)
{
    if (sc < 9.2e18 && sc > -9.2e18
        && sc == static_cast<double>(static_cast<int64_t>(sc)))
    {
        rb.append(std::to_string(static_cast<int64_t>(sc)));
        return;
    }
    char buf[40];
    const int n = std::snprintf(buf, sizeof(buf), "%.17g", sc);
    if (n > 0)
        rb.append(buf, static_cast<size_t>(n));
}

// Redis's own wording, because a client matches the first word of an error
// reply: through encode_error_into this went out as "-ERR WRONGTYPE ...", so a
// library switching on the code saw ERR and a type conflict was indistinguish-
// able from a syntax error.  The same reason emit_moved has its own encoder.
static constexpr std::string_view wrongtype_msg =
    "WRONGTYPE Operation against a key holding the wrong kind of value";

static constexpr std::string_view oom_msg =
    "OOM command not allowed when used memory > 'maxmemory'";

// A write the store refused, told apart by what the key holds: another type is
// WRONGTYPE, and otherwise it was room, which Redis answers -OOM and which went
// out as WRONGTYPE from every push, add and move -- a client then treated a
// full store as a key of the wrong type.  `absent` is the answer when nothing
// is there and nothing was being made.
static void encode_refusal(std::string& rb, std::string_view held, std::string_view own,
                           std::string_view absent = {})
{
    if (held != "none" && held != own)
        resp::encode_error_code_into(rb, wrongtype_msg);
    else if (held == "none" && !absent.empty())
        resp::encode_error_code_into(rb, absent);
    else
        resp::encode_error_code_into(rb, oom_msg);
}

// The three-element confirmation every subscribe verb answers on Redis: the
// verb, the channel or pattern, and how many this connection now holds.  A
// client counts down from that number to know when its own batch is done, and
// +OK -- which is what this used to send -- gives it nothing to count.
// LIMIT offset count over a range already in order, a negative count meaning
// the rest of it, as Redis reads it.
static void apply_zlimit(std::vector<std::pair<std::string_view, double>>& v,
                         int64_t off, int64_t cnt)
{
    if (off < 0 || static_cast<uint64_t>(off) >= v.size())
    {
        v.clear();
        return;
    }
    v.erase(v.begin(), v.begin() + off);
    if (cnt >= 0 && static_cast<uint64_t>(cnt) < v.size())
        v.resize(static_cast<size_t>(cnt));
}

static void sub_confirm(std::string& rb, std::string_view verb,
                        std::string_view name, uint32_t count)
{
    resp::encode_array_header_into(rb, 3);
    resp::encode_bulk_into(rb, verb);
    resp::encode_bulk_into(rb, name);
    resp::encode_integer_into(rb, static_cast<int64_t>(count));
}

// The whole string or nothing, for every width the commands below store into.
// It was here, correct, and called five times: the other twenty-four sites
// spelled from_chars by hand and none of them compared the end pointer, so
// `EXPIRE k 5x` was five seconds and `INCRBY k 3q` was three.
template <typename T>
static bool parse_int_sv(std::string_view sv, T& out)
{
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
    return ec == std::errc{} && ptr == sv.data() + sv.size();
}

// The count forms of LPOP, RPOP, SPOP and SRANDMEMBER, which answer an array
// where the plain forms answer one element, and were read as the plain forms --
// so a client that asked for several got one bulk reply it could not parse.
// Each removal is replicated as its own record, the way SPOP's already was.
void cache_instance::resp_pop_count(client_connection* /*conn*/, std::string_view* args,
                                    int argc, bool left, std::string& rb)
{
    int64_t count = 0;
    if (argc > 3 || !parse_int_sv(args[2], count) || count < 0)
    { resp::encode_error_into(rb, "value is out of range, must be positive"); return; }
    std::vector<std::string> popped;
    std::string val;
    while (static_cast<int64_t>(popped.size()) < count &&
           (left ? m_store.lpop(args[1], val) : m_store.rpop(args[1], val)))
    {
        popped.push_back(std::move(val));
        // The key is the record's last field, which the reader takes whole.
        if (mutation_log_wanted())
        {
            std::string cmd = left ? "lpop " : "rpop ";
            cmd.append(args[1].data(), args[1].size());
            replicate_command(cmd);
        }
    }
    if (popped.empty() && count > 0)
    {
        if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'l')))
            resp::encode_error_code_into(rb, wrongtype_msg);
        else
            rb.append("*-1\r\n", 5);
        return;
    }
    resp::encode_array_header_into(rb, static_cast<int>(popped.size()));
    for (const auto& v : popped) resp::encode_bulk_into(rb, v);
}

void cache_instance::resp_spop_count(std::string_view* args, int argc, std::string& rb)
{
    int64_t count = 0;
    if (argc > 3 || !parse_int_sv(args[2], count) || count < 0)
    { resp::encode_error_into(rb, "value is out of range, must be positive"); return; }
    std::vector<std::string> popped;
    std::string member;
    while (static_cast<int64_t>(popped.size()) < count && m_store.spop(args[1], member))
    {
        if (mutation_log_wanted())
        {
            std::string cmd = "srem ";
            cmd.append(args[1].data(), args[1].size());
            cmd += ' '; cmd += member;
            replicate_command(cmd);
        }
        popped.push_back(std::move(member));
    }
    if (popped.empty() && SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 't')))
    { resp::encode_error_code_into(rb, wrongtype_msg); return; }
    resp::encode_array_header_into(rb, static_cast<int>(popped.size()));
    for (const auto& v : popped) resp::encode_bulk_into(rb, v);
}

// Positive: that many distinct members at most; negative: exactly that many,
// repeats allowed -- Redis's two readings of the one argument.
void cache_instance::resp_srandmember_count(std::string_view* args, int argc, std::string& rb)
{
    int64_t count = 0;
    if (argc > 3 || !parse_int_sv(args[2], count))
    { resp::encode_error_into(rb, "value is not an integer or out of range"); return; }
    if (m_has_ttl_keys) m_store.check_expiry(args[1]);
    const auto* set = m_store.set_ptr(args[1]);
    if (!set || set->empty() || count == 0)
    {
        if (!set && SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 't')))
        { resp::encode_error_code_into(rb, wrongtype_msg); return; }
        resp::encode_array_header_into(rb, 0);
        return;
    }
    std::vector<std::string_view> all;
    all.reserve(set->size());
    for (const auto& m : *set) all.emplace_back(m);
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    if (count > 0)
    {
        const size_t n = std::min(all.size(), static_cast<size_t>(count));
        for (size_t i = 0; i < n; ++i)
            std::swap(all[i], all[i + rng() % (all.size() - i)]);
        resp::encode_array_header_into(rb, static_cast<int>(n));
        for (size_t i = 0; i < n; ++i) resp::encode_bulk_into(rb, all[i]);
        return;
    }
    const uint64_t n = count == INT64_MIN ? uint64_t{1} << 62 : static_cast<uint64_t>(-count);
    if (n > (1u << 20))
    { resp::encode_error_into(rb, "value is out of range"); return; }
    resp::encode_array_header_into(rb, static_cast<int>(n));
    for (uint64_t i = 0; i < n; ++i) resp::encode_bulk_into(rb, all[rng() % all.size()]);
}

// Both UNSUBSCRIBE verbs, where naming nothing means everything held -- the
// form a client sends to leave subscriber mode -- and holding nothing is still
// answered, with a nil name, because the client waits for a reply either way.
void cache_instance::resp_unsubscribe(client_connection* conn, std::string_view* args,
                                      int argc, bool patterns, std::string& rb)
{
    const std::string_view verb = patterns ? "punsubscribe" : "unsubscribe";
    auto one = [&](std::string_view name) {
        const bool gone = patterns ? m_store.punsubscribe(conn->fd, name)
                                   : m_store.unsubscribe(conn->fd, name);
        if (gone && conn->sub_count) --conn->sub_count;
        sub_confirm(rb, verb, name, conn->sub_count);
    };
    if (argc >= 2)
    {
        for (int i = 1; i < argc; i++) one(args[i]);
        return;
    }
    const auto held = m_store.subscriptions_of(conn->fd, patterns);
    for (const auto& name : held) one(name);
    if (held.empty())
    {
        resp::encode_array_header_into(rb, 3);
        resp::encode_bulk_into(rb, verb);
        rb.append("$-1\r\n", 5);
        resp::encode_integer_into(rb, static_cast<int64_t>(conn->sub_count));
    }
}

// A score bound as ZRANGEBYSCORE spells it: a bare number is inclusive, a
// leading "(" makes it exclusive, and -inf/+inf are the open ends.
// A scan's predicates, accumulated as its options are parsed.
//
// The stateful part is one sentence -- a FIELD applies to the value predicates
// that follow it, until the next FIELD -- and it lives here because the cache
// parses its options twice, once per protocol, and two copies of that sentence
// are two chances to disagree.  Each door only says which token it saw.
//
// The arrays are what the filter's pointers point AT, so an instance of this has
// to outlive the scan call it builds.  Both doors keep it in the same block.
struct scan_preds
{
    static constexpr size_t MAX = cache_store::scan_filter::MAX_PREDICATES;
    std::string_view field[MAX]{}, value[MAX]{};
    cache_store::scan_filter::value_range range[MAX]{};
    bool   has_field[MAX]{}, has_value[MAX]{}, has_range[MAX]{};
    size_t n = 0;
    bool   too_many = false;

    // Where the next thing parsed belongs.  A FIELD always opens a predicate; a
    // value predicate joins the one the last FIELD opened, or opens one of its
    // own when no FIELD has been seen -- which is how a bare VALUEMATCH keeps
    // meaning the key's own value.
    size_t slot(bool new_group)
    {
        if (new_group || n == 0)
        {
            if (n >= MAX) { too_many = true; return MAX - 1; }
            ++n;
        }
        return n - 1;
    }

    // Some predicates naming a field and some not asks for the key's own value
    // AND a hash field at once, which nothing can be.
    bool contradictory() const
    {
        bool with = false, without = false;
        for (size_t i = 0; i < n; i++) { if (has_field[i]) with = true; else without = true; }
        return with && without;
    }

    cache_store::scan_filter build(int type_map, bool with_values) const
    {
        cache_store::scan_filter f;
        f.type_map = type_map;
        f.with_values = with_values;
        for (size_t i = 0; i < n; i++)
            f.preds[i] = { has_field[i] ? &field[i] : nullptr,
                           has_value[i] ? &value[i] : nullptr,
                           has_range[i] ? &range[i] : nullptr };
        f.pred_count = n;
        return f;
    }
};

static bool parse_score_bound(std::string_view sv, double& out, bool& inclusive)
{
    inclusive = true;
    if (!sv.empty() && sv.front() == '(')
    {
        inclusive = false;
        sv.remove_prefix(1);
    }
    if (sv.size() == 3 || sv.size() == 4)
    {
        switch (fnv1a_lower(sv))
        {
            case fnv1a("-inf"):
                out = -std::numeric_limits<double>::infinity(); return true;
            case fnv1a("+inf"):
            case fnv1a("inf"):
                out =  std::numeric_limits<double>::infinity(); return true;
            default: break;
        }
    }
    return parse_double_sv(sv, out);
}

// One score, formatted the way every reply here formats one.
static std::string score_text(double sc)
{
    std::string s;
    append_score_bare(s, sc);
    return s;
}

static void append_score(std::string& rb, double sc)
{
    append_score_bare(rb, sc);
    rb.append("\n", 1);
}


// A request payload is a command stream and not one command, which is what
// would arrive on this cache's own port -- batched because one entry per
// message lost 88% of the writes on a 200,000 message burst -- and `split` is
// the one thing separating a client stream from a replication frame, which is
// framed precisely because it contains a newline.
void cache_instance::serve_payload(std::string_view payload, std::string& out, bool split)
{
    // The re-entrant case, where a command that publishes reaches Lua and a
    // callback asks this cache another question, rare enough to pay full price
    // for.
    if (SOCKETLEY_UNLIKELY(m_serving))
    {
        client_connection nested{};
        nested.fd = -1;
        nested.rl_max = 0;
        if (split) run_request_lines(&nested, payload);
        else if (!payload.empty()) process_command(&nested, payload);
        out.append(nested.response_buf);
        return;
    }

    // One command, whole, before the line splitter can see a newline inside a
    // value and read the rest of it as the next command.
    if (SOCKETLEY_UNLIKELY(split && payload.size() > one_command_text.size()
                           && payload.front() == shard_batch_marker
                           && payload.compare(0, one_command_text.size(),
                                              one_command_text) == 0))
    {
        serve_payload(payload.substr(one_command_text.size()), out, false);
        return;
    }

    // A framed run from a sibling shard, recognised before anything else
    // parses it, because reading it as a command stream would run the marker
    // line as a command.
    if (SOCKETLEY_UNLIKELY(split && !payload.empty()
                           && payload.front() == shard_batch_marker))
    {
        struct batch_guard
        {
            bool& flag;
            ~batch_guard() { flag = false; }
        } bguard{m_serving};
        m_serving = true;

        if (serve_shard_batch(payload, out))
            return;
        // A marker this build does not know, from a sibling of another version, is refused and never run as text.
        out.append("error: a frame this cache does not read\n");
        return;
    }

    if (!m_request_conn)
        m_request_conn = socketley::make_connection<client_connection>();

    struct serving_guard
    {
        bool& flag;
        ~serving_guard() { flag = false; }
    } guard{m_serving};
    m_serving = true;

    auto* conn = m_request_conn.get();
    conn->fd = -1;
    conn->rl_max = 0;
    conn->rl_tokens = 0.0;
    conn->batches.clear();
    conn->crossing_bytes = 0;
    conn->response_buf.clear();
    if (split) run_request_lines(conn, payload);
    else if (!payload.empty()) process_command(conn, payload);
    out.append(conn->response_buf);
}

void cache_instance::serve_request(std::string_view payload, std::string& out)
{
    serve_payload(payload, out, true);
}

// One command, newlines and all — what a replication frame carries.
void cache_instance::serve_one_command(std::string_view line, std::string& out)
{
    serve_payload(line, out, false);
}

// Each shard of a sharded follower applies only the records its slice owns; a leader that knows the slice (`replicate
// <i> <n>`) sends no others, and one that does not sends the whole stream, which is checked here either way.
void cache_instance::apply_replicated(std::string_view line)
{
    std::string discard;
    // What only a record of this cache's own writes may carry -- a group's consumers and pending entries -- is
    // taken here, from the primary and from the journal, and never from a client that typed the record's verb.
    const bool was = m_applying_replicated;
    m_applying_replicated = true;
    struct restore { bool& f; bool v; ~restore() { f = v; } } back{ m_applying_replicated, was };

    if (SOCKETLEY_LIKELY(m_shard_n <= 1))
    {
        serve_one_command(line, discard);
        return;
    }

    std::string_view key;
    if (cache_record_key(line, key) && cache_shard_of(key, m_shard_n) != m_shard_i)
        return;                          // a sibling owns this one

    serve_one_command(line, discard);
}

void cache_instance::run_request_lines(client_connection* conn, std::string_view payload)
{
    size_t start = 0;
    while (start <= payload.size())
    {
        size_t nl = payload.find('\n', start);
        std::string_view line = (nl == std::string_view::npos)
            ? payload.substr(start) : payload.substr(start, nl - start);

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            process_command(conn, line);

        if (nl == std::string_view::npos)
            break;
        start = nl + 1;
    }
}

std::string cache_instance::execute(std::string_view line)
{
    std::string out;
    serve_request(line, out);
    return out;
}

// Zero-allocation integer append for text-mode responses
// EXPIREAT names an absolute instant and the store takes a relative one, so
// the difference is computed here -- saturating, because the subtraction is
// the client's number minus the clock: `EXPIREAT k -9223372036854775808`
// overflowed it and the wrap came out POSITIVE, so the key a client asked to
// delete was given a deadline 292 years out instead.
static inline int64_t saturating_until(int64_t when, int64_t now)
{
    int64_t d = 0;
    if (SOCKETLEY_UNLIKELY(__builtin_sub_overflow(when, now, &d)))
        return when > 0 ? std::numeric_limits<int64_t>::max()
                        : std::numeric_limits<int64_t>::min();
    return d;
}

static inline void append_int_nl(std::string& buf, int64_t v)
{
    char tmp[24];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), v);
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.push_back('\n');
}

// ─── CROSS-SHARD ROUTING ────────────────────────────────────────────────────
// A command naming somebody else's key is framed, grouped with every other
// command in the pipeline bound for that shard, and answered by the process
// that holds it -- all of it unreachable on an unsharded cache at one
// predicted branch.

// An error written into a plain buffer rather than a connection: a merge that
// cannot be performed has to answer the command it belongs to, and by then the
// answer is a slot, not a socket.
static void append_error_reply(std::string& out, bool resp, std::string_view why)
{
    if (resp)
        resp::encode_error_into(out, why);
    else
    {
        out.append("error: ");
        out.append(why);
        out.push_back('\n');
    }
}

// `<int>\n` in text and `:<int>\r\n` in RESP, strictly, because anything else
// is a reply this rule was not written for.
static bool parse_int_reply(std::string_view part, bool resp, int64_t& out)
{
    if (resp)
    {
        if (part.size() < 4 || part.front() != ':' || !part.ends_with("\r\n"))
            return false;
        part.remove_prefix(1);
        part.remove_suffix(2);
    }
    else
    {
        if (part.empty() || part.back() != '\n')
            return false;
        part.remove_suffix(1);
    }
    if (part.empty())
        return false;
    const auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), out);
    return ec == std::errc{} && ptr == part.data() + part.size();
}

// `*N\r\n` off the front of a RESP array, leaving the elements.
static bool take_resp_array_header(std::string_view part, int64_t& count,
                                   std::string_view& elements)
{
    if (part.empty() || part.front() != '*')
        return false;
    const size_t nl = part.find("\r\n");
    if (nl == std::string_view::npos)
        return false;
    const std::string_view digits = part.substr(1, nl - 1);
    if (digits.empty())
        return false;
    const auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), count);
    if (ec != std::errc{} || ptr != digits.data() + digits.size() || count < 0)
        return false;
    elements = part.substr(nl + 2);
    return true;
}

// Run one complete command out of this shard's store without disturbing what
// the connection has queued, in one function so a key served locally and the
// same key served across a boundary cannot disagree.
void cache_instance::run_local_raw(client_connection* conn, std::string_view raw,
                                   bool resp, std::string& out)
{
    // The reply is written into `out`'s own buffer, so a caller that keeps it
    // between calls allocates nothing.
    std::string held;
    held.swap(conn->response_buf);
    out.clear();
    conn->response_buf.swap(out);

    if (resp)
    {
        // The parser's own limit, not a second one below it: 64 refused
        // `MSET` with 32 pairs, `DEL` or `MGET` with 65 keys and `ZADD` with
        // 32 pairs, all of which Redis takes.  16 KiB of stack against a cap
        // that made valid commands protocol errors.
        //
        // Uninitialised, which the line this replaced claimed and did not get:
        // see resp::arg_slots for what declaring the array plainly cost.
        static constexpr int MAX_RESP_ARGS = resp::RESP_MAX_ARRAY_SIZE;
        resp::arg_slots  slots;
        std::string_view* args = slots.v;
        int    argc     = 0;
        size_t consumed = 0;
        const auto pr = resp::parse_message_views(raw, args, MAX_RESP_ARGS, argc, consumed, read_bulk_limit());
        if (pr == resp::parse_result::ok && argc > 0)
            process_resp_command_local(conn, args, argc);
        else if (pr == resp::parse_result::too_many_args)
            resp::encode_error_into(conn->response_buf,
                                    "too many arguments in one command");
        else if (pr == resp::parse_result::value_too_large)
            resp::encode_error_into(conn->response_buf,
                                    "value is larger than this cache accepts");
        else
            resp::encode_error_into(conn->response_buf, "protocol error");
    }
    else if (!raw.empty())
    {
        process_command_local(conn, raw);
    }

    out.swap(conn->response_buf);
    conn->response_buf.swap(held);
}

// Reserve a command's place in the reply order, where `parts` is how many
// pieces its answer needs.
void cache_instance::open_collect(client_connection* conn, bool resp)
{
    m_collect       = std::make_unique<shard_batch>();
    m_collect->slots.reserve(m_collect_hint ? m_collect_hint : 8);
    m_collect->id   = m_next_batch++;
    m_collect->fd   = conn->fd;
    m_collect->resp = resp;
    m_collect_fd    = conn->fd;
}

uint32_t cache_instance::slot_open(client_connection* conn, bool resp,
                                   cache_merge merge, uint32_t parts)
{
    if (!m_collect)
        open_collect(conn, resp);

    const uint32_t idx = static_cast<uint32_t>(m_collect->slots.size());
    reply_slot sl;
    sl.merge = merge;
    sl.parts.assign(parts, std::string{});
    sl.part_filled.assign(parts, 0);
    sl.parts_left = parts;
    m_collect->slots.push_back(std::move(sl));
    return idx;
}

void cache_instance::route_part(client_connection* conn, uint32_t owner,
                                uint32_t slot, uint32_t part,
                                std::string_view raw, bool resp)
{
    // A piece this shard owns is run here and filled now, so no crossing is
    // opened for it.
    if (owner == m_shard_i)
    {
        std::string produced;
        run_local_raw(conn, raw, resp, produced);

        reply_slot& sl = m_collect->slots[slot];
        sl.parts[part] = std::move(produced);
        if (!sl.part_filled[part])
        {
            sl.part_filled[part] = 1;
            if (sl.parts_left > 0)
                --sl.parts_left;
        }
        return;
    }

    if (reply_slot& sl = m_collect->slots[slot]; !sl.relayed && conn->fd >= 0 && !conn->cluster_port)
    {
        sl.relayed = true;
        ++m_stat_relayed_cmds;
    }

    // By the batch's protocol, which is the one its frame's header names.
    turn_crossing& tc = m_turn_cross[static_cast<size_t>(owner) * 2 + (m_collect->resp ? 1 : 0)];
    cross_mark&    mk = m_route_mark[owner];
    if (mk.bytes == SIZE_MAX)
    {
        mk.bytes   = tc.payload.size();
        mk.targets = tc.targets.size();
    }
    if (tc.payload.empty())
        tc.payload.append(m_collect->resp ? shard_batch_resp : shard_batch_text);
    shard_frame_append(tc.payload, raw);
    tc.targets.push_back(post_target{m_collect->id, slot, part});
}

// Put a finished slot's pieces together, where false is answered as an error
// for that command because a merge that guesses produces a reply the client
// cannot frame.
bool cache_instance::slot_render(const reply_slot& sl, bool resp,
                                 std::string& out) const
{
    switch (sl.merge)
    {
        case cache_merge::single:
            if (!sl.parts.empty())
                out.append(sl.parts[0]);
            return true;

        case cache_merge::elements:
        {
            // Each part is one `get` reply, which is already exactly one
            // element in both protocols, so there is nothing to parse.
            if (resp)
            {
                out.push_back('*');
                out.append(std::to_string(sl.parts.size()));
                out.append("\r\n", 2);
            }
            for (const auto& p : sl.parts)
                out.append(p);
            if (!resp)
                out.append("end\n", 4);
            return true;
        }

        case cache_merge::all_ok:
        {
            const std::string_view ok = resp ? std::string_view("+OK\r\n")
                                             : std::string_view("ok\n");
            for (const auto& p : sl.parts)
                if (p != ok)
                {
                    // The first shard that refused, in its own words, because
                    // a blanket "ok" over a partial write is the answer this
                    // cannot give.
                    out.append(p);
                    return true;
                }
            out.append(ok);
            return true;
        }

        case cache_merge::sum:
        {
            int64_t total = 0;
            for (const auto& p : sl.parts)
            {
                int64_t v = 0;
                if (!parse_int_reply(p, resp, v))
                {
                    // Not a number, so not something to add, and echoing it is
                    // honest because every shard is configured identically --
                    // at the cost of a multi-key del whose counts go with one
                    // shard's error.
                    out.append(p);
                    return true;
                }
                total += v;
            }
            if (resp)
                resp::encode_integer_into(out, total);
            else
            {
                out.append(std::to_string(total));
                out.push_back('\n');
            }
            return true;
        }

        case cache_merge::key_list:
        {
            if (resp)
            {
                int64_t     total = 0;
                std::string body;
                for (const auto& p : sl.parts)
                {
                    int64_t          n = 0;
                    std::string_view elems;
                    if (!take_resp_array_header(p, n, elems))
                        return false;
                    total += n;
                    body.append(elems);
                }
                out.push_back('*');
                out.append(std::to_string(total));
                out.append("\r\n", 2);
                out.append(body);
                return true;
            }
            // Text: each part is its shard's lines followed by `end`, and
            // there is one terminator for the runtime rather than one per
            // shard.
            for (const auto& p : sl.parts)
                if (!p.ends_with("end\n"))
                    return false;
            for (const auto& p : sl.parts)
                out.append(std::string_view(p).substr(0, p.size() - 4));
            out.append("end\n", 4);
            return true;
        }
    }
    return false;
}

// Where this shard's slice lives: at one shard the configured path unsuffixed,
// which is the contract `--persistent /x` has always had, and above one shard
// a named slice per file.
std::string cache_instance::shard_dump_path(uint32_t index) const
{
    if (m_shard_n <= 1)
        return m_persistent_path;
    return m_persistent_path + ".shard" + std::to_string(index);
}

// Write this shard's slice, atomic on its own file, which is the whole of what
// the write side owes.
bool cache_instance::save_shard_dump() const
{
    if (m_persistent_path.empty())
        return true;

    // The header goes on whichever file this is, the bare path included: a dump
    // that says it is one slice of one is still a dump that says what it is,
    // and load() skips the header by the same rule either way.
    const bool ok = m_store.save(shard_dump_path(m_shard_i),
                                 encode_shard_dump_header(m_shard_n, m_shard_i));

    // The slices this runtime no longer has go with the dump that supersedes
    // them, from shard 0 alone and only at or above the current count, or the
    // next start sees two complete sets and refuses a legitimate shrink.
    if (ok && m_shard_i == 0)
    {
        for (uint32_t j = (m_shard_n <= 1 ? 0 : m_shard_n); j < max_shards; ++j)
        {
            const std::string stale =
                m_persistent_path + ".shard" + std::to_string(j);
            if (::unlink(stale.c_str()) == 0)
                LOG_INFO(("cache: removed " + stale
                          + ", superseded by this dump").c_str());
            // Its journal goes with it: past this dump either it was empty or
            // its split refused this start, so there is no record to lose.
            if (::unlink((stale + ".journal").c_str()) == 0) {}
            for (const auto& a : journal_asides(stale + ".journal"))
                if (::unlink(a.second.c_str()) == 0) {}
        }
        // The bare name's journal is a one-shard run's, superseded the same
        // way once more than one shard writes.
        if (m_shard_n > 1)
        {
            if (::unlink((m_persistent_path + ".journal").c_str()) == 0) {}
            for (const auto& a : journal_asides(m_persistent_path + ".journal"))
                if (::unlink(a.second.c_str()) == 0) {}
        }
    }

    return ok;
}

// Gather what is on disk and decide how to read it, returning false only for a
// set that must not be loaded, because a start on a gap is refused rather than
// served from what survived.
bool cache_instance::load_shard_set()
{
    if (m_persistent_path.empty())
        return true;

    struct found { uint32_t index; std::string path; shard_dump_header hdr;
                   bool legacy; };
    std::vector<found> set;
    uint32_t declared = 0;
    bool     mixed    = false;

    // The suffixed set, whatever this run's own shard count is: a set written by
    // a run with a different N is exactly what has to be found here.
    for (uint32_t i = 0; i < max_shards; ++i)
    {
        const std::string p = m_persistent_path + ".shard" + std::to_string(i);
        shard_dump_header h{};
        bool legacy = false;
        if (!read_shard_dump_header(p, h, legacy))
            continue;                      // not there, which is not an error

        if (h.truncated)
        {
            LOG_ERROR(("cache: " + p + " ends inside its shard header; refusing to "
                       "load a torn dump").c_str());
            return false;
        }
        if (legacy)
        {
            // A file at a sharded name with no header is not something this
            // build wrote, and guessing what split it holds is the guess that
            // loses data.
            LOG_ERROR(("cache: " + p + " has no shard header; refusing to guess "
                       "which slice of the keyspace it holds").c_str());
            return false;
        }
        if (declared == 0)      declared = h.count;
        else if (h.count != declared) mixed = true;

        set.push_back(found{i, p, h, false});
    }

    // Nothing sharded on disk: the bare path, if it is there, is a complete set
    // of one written before this header existed.
    if (set.empty())
    {
        shard_dump_header h{};
        bool legacy = false;
        if (!read_shard_dump_header(m_persistent_path, h, legacy))
            return true;                   // first start, nothing to load

        if (h.truncated)
        {
            LOG_ERROR(("cache: " + m_persistent_path + " ends inside its shard header; "
                       "refusing to load a torn dump").c_str());
            return false;
        }
        if (legacy)
        {
            LOG_INFO(("cache: loading the pre-shard dump at " + m_persistent_path
                      + " as a single slice").c_str());
            h.count = 1;
            h.index = 0;
            h.has_fingerprint = false;
        }
        set.push_back(found{h.index, m_persistent_path, h, legacy});
        declared = h.count;
    }

    // ── case 2: two sets in one place ──
    if (mixed)
    {
        std::string counts;
        for (const auto& f : set)
            counts += (counts.empty() ? "" : ", ") + std::string("shard")
                    + std::to_string(f.index) + " says " + std::to_string(f.hdr.count);
        LOG_ERROR(("cache: the dumps beside " + m_persistent_path
                   + " disagree about how many shards wrote them (" + counts
                   + ").  That is two sets in one place; refusing to load either")
                  .c_str());
        return false;
    }

    // ── case 2 again: an index that cannot belong to this set ──
    for (const auto& f : set)
        if (f.hdr.index >= declared || f.index >= declared)
        {
            LOG_ERROR(("cache: " + f.path + " claims slice "
                       + std::to_string(f.hdr.index) + " of "
                       + std::to_string(declared)
                       + ", which is not a slice that set has; refusing to load")
                      .c_str());
            return false;
        }

    // ── case 1: a gap ──
    std::vector<bool> seen(declared, false);
    for (const auto& f : set)
    {
        if (seen[f.hdr.index])
        {
            LOG_ERROR(("cache: two dumps beside " + m_persistent_path
                       + " both claim slice " + std::to_string(f.hdr.index)
                       + "; refusing to load").c_str());
            return false;
        }
        seen[f.hdr.index] = true;
    }
    for (uint32_t i = 0; i < declared; ++i)
        if (!seen[i])
        {
            LOG_ERROR(("cache: the dump for slice " + std::to_string(i) + " of "
                       + std::to_string(declared) + " is missing beside "
                       + m_persistent_path
                       + ".  Its keys would be gone with nothing reporting it; "
                         "refusing to start").c_str());
            return false;
        }

    // ── case 4: is the split still the split this set was written under? ──
    unsigned char now[cache_fingerprint_len];
    cache_shard_fingerprint(now);
    bool same_function = true;
    for (const auto& f : set)
        if (f.hdr.has_fingerprint
            && std::memcmp(f.hdr.fingerprint, now, cache_fingerprint_len) != 0)
            same_function = false;

    // A set of one carries no fingerprint worth checking: at count 1 every key
    // is shard 0 whatever the function does.
    if (declared == 1 && m_shard_n == 1)
        same_function = true;

    // The fingerprint check, measured by perturbing the hash and removing it:
    // DBSIZE reported 40 and all 40 keys were unreachable, which an assertion
    // on the count also passes.
    const bool fast = (declared == m_shard_n) && same_function;

    if (fast)
    {
        for (const auto& f : set)
            if (f.hdr.index == m_shard_i)
                return m_store.load(f.path, f.legacy ? 0 : shard_dump_header_size);
        return true;
    }

    // The filter path, where every shard reads every dump and keeps what
    // hashes to it now -- slower by N once at start, and correct with no
    // special case for any way the split moved.
    if (!same_function)
        LOG_WARN(("cache: the dumps beside " + m_persistent_path + " were written "
                  "by a different ownership function; every shard will read every "
                  "dump and keep what belongs to it").c_str());
    else
        LOG_INFO(("cache: loading " + std::to_string(declared) + " dump(s) into "
                  + std::to_string(m_shard_n) + " shard(s); each shard keeps what "
                  "hashes to it").c_str());

    for (const auto& f : set)
        if (!m_store.load_owned(f.path, f.legacy ? 0 : shard_dump_header_size, m_shard_i, m_shard_n))
        {
            LOG_ERROR(("cache: " + f.path + " could not be read; refusing to start "
                       "on part of a dump").c_str());
            return false;
        }
    return true;
}

// ─── THE MUTATION JOURNAL ───────────────────────────────────────────────────
// `--persistent-interval` puts a journal beside each shard's dump: every
// accepted write is appended as the same text command replication carries,
// reaches the page cache at most one interval after it was acknowledged, and
// is truncated by the snapshot that absorbs it -- so a killed worker replays
// the tail the dump never saw instead of losing it.

std::string cache_instance::journal_path(uint32_t index) const
{
    return shard_dump_path(index) + ".journal";
}

// Judge every journal beside the dump, replay this shard's own onto the dumps
// just loaded, and leave it open for appending.
bool cache_instance::journal_recover()
{
    const std::string own      = journal_path(m_shard_i);
    const std::string own_head = encode_shard_dump_header(m_shard_n, m_shard_i);

    const auto refuse_foreign = [](const std::string& p) {
        LOG_ERROR(("cache: the journal at " + p + " was not written by this "
                   "shard split, and its records cannot be ordered against "
                   "another journal's history of the same key.  Start with "
                   "the shard count that wrote it and stop cleanly to absorb "
                   "it, or delete the .journal files to discard the "
                   "unsnapshotted tail").c_str());
        return false;
    };

    // One journal name judged: nothing there and nothing recorded are fine,
    // anything else unowned refuses, because a journal holding records under
    // another split is unsnapshotted data this run would serve without.
    const auto judge = [&](const std::string& p, const std::string& expected) {
        std::string owner;
        switch (mutation_journal::probe(p, owner))
        {
            case mutation_journal::probe_result::absent:
            case mutation_journal::probe_result::empty:
                return true;
            case mutation_journal::probe_result::unreadable:
                LOG_ERROR(("cache: " + p + " exists and could not be read; "
                           "refusing to guess whether it holds writes").c_str());
                return false;
            case mutation_journal::probe_result::not_a_journal:
                LOG_ERROR(("cache: " + p + " is not a journal this build "
                           "writes; refusing to start over it").c_str());
                return false;
            case mutation_journal::probe_result::has_records:
                if (expected.empty() || owner != expected)
                    return refuse_foreign(p);
                return true;
        }
        return false;
    };

    // A journal and what a snapshot set aside of it, judged alike.
    const auto judge_all = [&](const std::string& p, const std::string& expected) {
        if (!judge(p, expected))
            return false;
        for (const auto& a : journal_asides(p))
            if (!judge(a.second, expected))
                return false;
        return true;
    };

    // Every sharded name, where a slice of the current split is a sibling's
    // business and everything else with records belongs to another run.
    for (uint32_t j = 0; j < max_shards; ++j)
    {
        const std::string p = m_persistent_path + ".shard" + std::to_string(j)
                            + ".journal";
        const std::string expected =
            (m_shard_n > 1 && j < m_shard_n)
                ? encode_shard_dump_header(m_shard_n, j) : std::string{};
        if (!judge_all(p, expected))
            return false;
    }
    // And the bare name, which is this shard's own at one shard and a
    // one-shard run's leftover above that.
    if (!judge_all(m_persistent_path + ".journal",
                   m_shard_n <= 1 ? own_head : std::string{}))
        return false;

    std::string owner;
    const auto pr = mutation_journal::probe(own, owner);

    // A header-only journal from another split holds nothing, so it is
    // replaced rather than refused.
    if (pr == mutation_journal::probe_result::empty && owner != own_head
        && ::unlink(own.c_str()) != 0)
    {
        LOG_ERROR(("cache: could not replace the stale journal at "
                   + own).c_str());
        return false;
    }

    // What a snapshot that did not finish set aside comes before the journal written after it, oldest first.
    const auto asides = journal_asides(own);
    m_journal_gen = asides.empty() ? 0 : asides.back().first;
    std::vector<std::string> replay;
    for (const auto& a : asides)
        replay.push_back(a.second);
    if (pr == mutation_journal::probe_result::has_records)
        replay.push_back(own);

    for (const std::string& from : replay)
    {
        // Replay bypasses the mode and the global rate limit, because both
        // guard clients, and a recovery they throttle or refuse is data loss
        // with a clean exit code.
        const cache_mode saved_mode = m_mode;
        const double     saved_rate = get_global_rate_limit();
        m_mode = cache_mode_readwrite;
        set_global_rate_limit(0.0);
        m_journal_replaying = true;

        mutation_journal::replay_stats st;
        const bool ok = mutation_journal::replay(
            from, [&](std::string_view rec) { apply_replicated(rec); }, st);

        m_journal_replaying = false;
        m_mode = saved_mode;
        set_global_rate_limit(saved_rate);

        if (!ok)
        {
            LOG_ERROR(("cache: the journal at " + from + " could not be read; "
                       "refusing to start on part of a tail").c_str());
            return false;
        }

        LOG_INFO(("cache: replayed " + std::to_string(st.records)
                  + " journaled write(s) from " + from).c_str());
        if (st.torn)
            LOG_WARN(("cache: " + from + " ended mid-record; "
                      + std::to_string(st.dropped_bytes)
                      + " byte(s) after the last complete record were dropped")
                     .c_str());
    }

    // Left as it stands rather than cut to its head, because the dump on disk
    // does not hold what was just replayed; new writes append behind the last
    // complete record, and a second crash replays both from the same base.
    if (!m_journal.open_append(own, own_head))
    {
        LOG_ERROR(("cache: could not open the journal at " + own).c_str());
        return false;
    }
    return true;
}

// One accepted write into the buffer, with the relative-TTL spellings
// rewritten to pexpireat, because "pexpire k 5000" replayed an hour later
// grants an hour and the absolute deadline is what the write meant.
void cache_instance::journal_mutation(std::string_view cmd)
{
    const cache_text_parts parts = cache_split_text(cmd);
    const uint32_t         h     = fnv1a_lower(parts.cmd);

    const auto int_of = [](std::string_view sv, int64_t& out) {
        auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
        return e == std::errc{} && p == sv.data() + sv.size();
    };
    // Saturating in both directions, because the deadline an absurd TTL means
    // is "never" or "long gone", not a signed overflow.
    const auto deadline_of = [](int64_t n, bool seconds) {
        constexpr int64_t far = std::numeric_limits<int64_t>::max();
        if (seconds)
            n = n > far / 1000 ? far : n < -(far / 1000) ? -far : n * 1000;
        const int64_t now = socketley::wall::now_ms();
        return n > far - now ? far : now + n;
    };
    const auto put_pexpireat = [&](std::string_view key, int64_t at) {
        std::string rec;
        rec.reserve(10 + key.size() + 21);
        rec += "pexpireat ";
        rec.append(key.data(), key.size());
        rec += ' ';
        rec += std::to_string(at);
        m_journal.append(rec);
    };

    bool rewritten = false;
    switch (h)
    {
        case fnv1a("expire"):
        case fnv1a("pexpire"):
        {
            const size_t sp = parts.args.find(' ');
            int64_t n = 0;
            if (sp != std::string_view::npos && sp > 0
                && int_of(parts.args.substr(sp + 1), n))
            {
                put_pexpireat(parts.args.substr(0, sp),
                              deadline_of(n, h == fnv1a("expire")));
                rewritten = true;
            }
            break;
        }
        case fnv1a("setex"):
        case fnv1a("psetex"):
        {
            // "setex k n v" as the set and the deadline, the same split
            // repl_set_effect makes for SET .. EX.
            const size_t sp1 = parts.args.find(' ');
            const size_t sp2 = sp1 == std::string_view::npos
                             ? std::string_view::npos
                             : parts.args.find(' ', sp1 + 1);
            int64_t n = 0;
            if (sp2 != std::string_view::npos && sp1 > 0
                && int_of(parts.args.substr(sp1 + 1, sp2 - sp1 - 1), n))
            {
                const std::string_view key = parts.args.substr(0, sp1);
                const std::string_view val = parts.args.substr(sp2 + 1);
                std::string rec;
                rec.reserve(5 + key.size() + val.size());
                rec += "set ";
                rec.append(key.data(), key.size());
                rec += ' ';
                rec.append(val.data(), val.size());
                m_journal.append(rec);
                put_pexpireat(key, deadline_of(n, h == fnv1a("setex")));
                rewritten = true;
            }
            break;
        }
        default:
            break;
    }

    if (!rewritten)
        m_journal.append(cmd);

    if (m_journal.pending_bytes() >= journal_flush_bytes)
        journal_flush_now();
    else
        arm_journal_timer();

    if (SOCKETLEY_UNLIKELY(m_journal.bytes() >= m_snap_at))
        snapshot_start();
}

// ─── A SNAPSHOT OFF THE LOOP ────────────────────────────────────────────────

// `<journal>.<g>`, the journals snapshots set aside and did not see through, oldest first.
std::vector<std::pair<uint64_t, std::string>> cache_instance::journal_asides(const std::string& journal)
{
    std::vector<std::pair<uint64_t, std::string>> out;
    const size_t slash = journal.rfind('/');
    const std::string dir  = slash == std::string::npos ? std::string(".") : journal.substr(0, slash == 0 ? 1 : slash);
    const std::string base = (slash == std::string::npos ? journal : journal.substr(slash + 1)) + ".";
    DIR* d = ::opendir(dir.c_str());
    if (!d)
        return out;
    while (const dirent* e = ::readdir(d))
    {
        const std::string_view n(e->d_name);
        uint64_t g = 0;
        if (n.size() > base.size() && n.starts_with(base) && parse_int_sv(n.substr(base.size()), g) && g > 0)
            out.emplace_back(g, (slash == std::string::npos ? std::string() : journal.substr(0, slash + 1))
                                    + std::string(n));
    }
    ::closedir(d);
    std::ranges::sort(out);
    return out;
}

void cache_instance::journal_drop_asides(uint64_t upto) const
{
    for (const auto& a : journal_asides(journal_path(m_shard_i)))
        if (a.first <= upto && ::unlink(a.second.c_str()) != 0)
            LOG_WARN(("cache: could not remove " + a.second + ", which the dump now holds; the next start will "
                      "replay it again").c_str());
}

// A journal longer than the dump it would be replayed onto is cheaper to absorb than to keep.
uint64_t cache_instance::snapshot_threshold() const
{
    struct stat st{};
    const uint64_t dump = ::stat(shard_dump_path(m_shard_i).c_str(), &st) == 0 ? static_cast<uint64_t>(st.st_size) : 0;
    return std::max(m_snap_floor, dump);
}

// The journal so far set aside, then a child writes the dump from what memory holds at this instant and removes
// what was set aside, which nothing written after this needs.
void cache_instance::snapshot_start()
{
    m_snap_at = UINT64_MAX;
    if (m_snap || !m_loop || !m_journal.is_open() || m_persistent_path.empty())
        return;

    const std::string own   = journal_path(m_shard_i);
    const uint64_t    gen   = m_journal_gen + 1;
    const std::string aside = own + "." + std::to_string(gen);
    const std::string head  = encode_shard_dump_header(m_shard_n, m_shard_i);
    const std::string dump  = shard_dump_path(m_shard_i);
    if (!m_journal.set_aside(own, aside, head))
    {
        LOG_WARN(("cache: could not set " + own + " aside for a snapshot; it grows until the next stop").c_str());
        m_snap_at = m_journal.bytes() + m_snap_floor;
        return;
    }
    m_journal_gen = gen;
    // Named before the fork, so the child allocates as little as it can.
    std::vector<std::string> drop;
    for (const auto& a : journal_asides(own))
        if (a.first <= gen)
            drop.push_back(a.second);

    const pid_t parent = ::getpid();
    const pid_t pid    = ::fork();
    if (pid == 0)
    {
        // Dies with the worker, so a restart never races a dump from the run before; holds none of its sockets, so a
        // connection the worker closes is closed.
        if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != parent)
            ::_exit(2);
        if (::syscall(SYS_close_range, 3u, ~0u, 0u) != 0) {}
        const bool ok = m_store.save(dump, head);
        if (ok)
            for (const std::string& p : drop)
                if (::unlink(p.c_str()) != 0) {}
        ::_exit(ok ? 0 : 1);
    }
    if (pid < 0)
    {
        LOG_WARN(("cache: could not fork a snapshot of slice " + std::to_string(m_shard_i) + ": "
                  + std::strerror(errno) + "; the journal grows until the next stop").c_str());
        ++m_stat_snapshot_failures;
        m_snap_at = m_journal.bytes() + m_snap_floor;
        return;
    }

    m_snap = std::make_unique<snapshot_child>();
    m_snap->pid   = pid;
    m_snap->pidfd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    m_snap->req   = { this, nullptr, m_snap->pidfd, 0, op_poll };
    m_snap->armed = m_snap->pidfd >= 0 && m_loop->submit_poll_add(m_snap->pidfd, POLLIN, &m_snap->req);
    if (!m_snap->armed)
    {
        // Nothing would say when it ends, so it does not go on.
        snapshot_abort();
        ++m_stat_snapshot_failures;
        m_snap_at = m_journal.bytes() + m_snap_floor;
    }
}

// The child's end: a dump written and what it holds removed, or nothing changed and the next try a floor later.
void cache_instance::snapshot_done()
{
    int status = 0;
    const pid_t r = ::waitpid(m_snap->pid, &status, WNOHANG);
    if (r == 0)
    {
        m_snap->armed = m_loop && m_loop->submit_poll_add(m_snap->pidfd, POLLIN, &m_snap->req);
        if (m_snap->armed)
            return;
        snapshot_abort();
        return;
    }
    close_tracked(m_snap->pidfd);
    m_snap.reset();
    if (r > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
    {
        ++m_stat_snapshots;
        m_snap_at = snapshot_threshold();
        return;
    }
    ++m_stat_snapshot_failures;
    LOG_WARN(("cache: the snapshot of slice " + std::to_string(m_shard_i) + " beside " + m_persistent_path
              + " failed; what it set aside stays and is replayed at the next start").c_str());
    m_snap_at = m_journal.bytes() + m_snap_floor;
}

// A child still writing is stopped, before a dump of the loop's own or a stop; what it set aside stays for the next.
void cache_instance::snapshot_abort()
{
    if (!m_snap)
        return;
    if (::kill(m_snap->pid, SIGKILL) != 0) {}
    while (::waitpid(m_snap->pid, nullptr, 0) < 0 && errno == EINTR) {}
    if (m_snap->pidfd >= 0)
        close_tracked(m_snap->pidfd);
    io_request* owed[1] = { &m_snap->req };
    const size_t n = m_snap->armed ? 1 : 0;
    retire(std::shared_ptr<void>(std::move(m_snap)), owed, n);
    m_snap.reset();
}

void cache_instance::journal_flush_now()
{
    if (!m_journal.flush() && !m_journal_write_warned)
    {
        m_journal_write_warned = true;
        LOG_ERROR(("cache: could not append to the journal at "
                   + journal_path(m_shard_i)
                   + "; writes since the last flush are memory-only").c_str());
    }
}

// What the journal does once a snapshot has been attempted: a dump that
// succeeded holds every journaled effect, so the records behind it are cut
// off; one that failed leaves the journal as the only record of the tail, so
// the buffer goes to the disk instead.
void cache_instance::journal_after_snapshot(bool saved)
{
    if (!m_journal.is_open())
        return;
    if (!saved)
    {
        journal_flush_now();
        return;
    }
    if (!m_journal.reset())
        LOG_WARN(("cache: could not truncate the journal at "
                  + journal_path(m_shard_i) + " behind its snapshot; the next "
                  "start will replay writes this dump already contains")
                 .c_str());
    journal_drop_asides(UINT64_MAX);
    m_journal_gen = 0;
    m_snap_at = snapshot_threshold();
}

void cache_instance::arm_journal_timer()
{
    if (m_journal_timer_armed || !m_loop || !m_journal_timer)
        return;
    m_journal_timer_armed = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_journal_timer->ts,
                                                   &m_journal_timer->req)))
    {
        // The interval cannot be promised without a timer, so the buffer goes
        // now rather than never.
        m_journal_timer_armed = false;
        journal_flush_now();
    }
}

// ─── THE CLUSTER VIEW ───────────────────────────────────────────────────────
// CLUSTER is answered because a client has to learn the map once, and what is
// published is a formula rather than a negotiation -- so any shard can answer
// for all of them, with no failover, migration or epoch that ever changes.
uint16_t cache_instance::cluster_port_of(uint32_t shard) const
{
    // One node listens on the port the operator configured and not base+1,
    // which nothing is bound to, and that is the answer for an unsharded cache
    // and for a sharded one outside cluster mode.
    if (!m_cluster_ports)
        return m_base_port;
    return static_cast<uint16_t>(m_base_port + 1 + shard);
}

std::string cache_instance::cluster_node_id(uint32_t shard) const
{
    // Deterministic, because a node id that changed on restart would make
    // every client believe the cluster had been replaced, and derived from the
    // runtime name so two caches do not publish the same ids.
    uint64_t h = 1469598103934665603ull;
    const std::string_view nm = get_name();
    for (const char c : nm)
    {
        h ^= static_cast<uint8_t>(c);
        h *= 1099511628211ull;
    }
    h ^= 0x100u | shard;
    h *= 1099511628211ull;

    const auto mix = [](uint64_t& x) {
        x += 0x9E3779B97F4A7C15ull;
        uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    // Three draws, in statement order: the arguments of one call would be
    // evaluated in whatever order the compiler chose, and the draws are not
    // independent of each other.
    const uint64_t a = mix(h);
    const uint64_t b = mix(h);
    const uint64_t c = mix(h);

    char buf[64];
    const int n = snprintf(buf, sizeof(buf), "%016llx%016llx%016llx",
                           static_cast<unsigned long long>(a),
                           static_cast<unsigned long long>(b),
                           static_cast<unsigned long long>(c));
    // 40 hex characters exactly: shorter and redis-cli prints a ragged table,
    // longer and lettuce's parser refuses the line.
    if (n < 40)
        return std::string(buf, static_cast<size_t>(n < 0 ? 0 : n));
    return std::string(buf, 40);
}

std::string cache_instance::cluster_host(const client_connection* conn) const
{
    // The listener is bound to INADDR_ANY and cannot say which address a
    // client reached it on, but the accepted socket can, and that address is
    // reachable by construction.
    if (conn && conn->fd >= 0)
    {
        struct sockaddr_in local{};
        socklen_t len = sizeof(local);
        if (getsockname(conn->fd, reinterpret_cast<struct sockaddr*>(&local),
                        &len) == 0
            && local.sin_family == AF_INET
            && local.sin_addr.s_addr != htonl(INADDR_ANY))
        {
            char ip[INET_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip)))
                return std::string(ip);
        }
    }
    return std::string("127.0.0.1");
}

void cache_instance::emit_moved(client_connection* conn, std::string_view key,
                                uint32_t owner, bool resp)
{
    std::string msg;
    msg.reserve(48);
    msg += "MOVED ";
    msg += std::to_string(cache_slot_of(key));
    msg += ' ';
    msg += cluster_host(conn);
    msg += ':';
    msg += std::to_string(cluster_port_of(owner));

    if (resp)
    {
        // The code is MOVED, not ERR.  See encode_error_code_into().
        resp::encode_error_code_into(conn->response_buf, msg);
    }
    else
    {
        conn->response_buf.append("error: ");
        conn->response_buf.append(msg);
        conn->response_buf.push_back('\n');
    }
}

void cache_instance::emit_cluster(client_connection* conn, std::string_view sub,
                                  std::string_view arg, bool resp)
{
    auto& rb = conn->response_buf;
    // How many nodes this cache presents as, which outside cluster mode is one
    // whatever the shard count, because nothing is bound at base+1+i.
    const uint32_t n    = m_cluster_ports ? m_shard_n : 1;
    // And which of them is us, collapsed to node 0 when there is one node, or
    // all four shards would answer CLUSTER NODES with no line marked myself.
    // On the shared port in cluster mode the shard that took the connection is
    // not the address the client dialled, so that port is a node of its own
    // holding no slots, and a client mapping `myself` to where it connected
    // sends no shard's keys back through the relay.
    const bool     shared = m_cluster_ports && !conn->cluster_port;
    const uint32_t me     = !m_cluster_ports ? 0 : shared ? n : m_shard_i;
    const std::string host = cluster_host(conn);
    const uint32_t h    = fnv1a_lower(sub);

    // A line of CLUSTER NODES, which is also the whole of the text rendering.
    const auto node_line = [&](uint32_t sh) {
        std::string l;
        l += cluster_node_id(sh);
        l += ' ';
        l += host;
        l += ':';
        l += std::to_string(cluster_port_of(sh));
        // The cluster bus port, of which there is none here, but the field is
        // not optional in the format and lettuce parses it as a number.
        const uint32_t bus = static_cast<uint32_t>(cluster_port_of(sh)) + 10000u;
        l += '@';
        l += std::to_string(bus <= 65535u ? bus : 0u);
        l += (sh == me) ? " myself,master - 0 " : " master - 0 ";
        l += std::to_string(
            socketley::wall::now_ms());
        // config epoch 1 for every node, and it never changes: no slot here is
        // ever migrating, so there is nothing for an epoch to order.
        l += " 1 connected ";
        l += std::to_string(cache_shard_slot_first(sh, n));
        l += '-';
        l += std::to_string(cache_shard_slot_last(sh, n));
        l += '\n';
        return l;
    };

    switch (h)
    {
        case fnv1a("slots"):
        {
            if (resp)
            {
                resp::encode_array_header_into(rb, static_cast<int>(n));
                for (uint32_t sh = 0; sh < n; ++sh)
                {
                    resp::encode_array_header_into(rb, 3);
                    resp::encode_integer_into(rb, cache_shard_slot_first(sh, n));
                    resp::encode_integer_into(rb, cache_shard_slot_last(sh, n));
                    // host, port, id — the third element has been the node id
                    // since Redis 4 and clients index it positionally.
                    resp::encode_array_header_into(rb, 3);
                    resp::encode_bulk_into(rb, host);
                    resp::encode_integer_into(rb, cluster_port_of(sh));
                    resp::encode_bulk_into(rb, cluster_node_id(sh));
                }
            }
            else
            {
                for (uint32_t sh = 0; sh < n; ++sh)
                {
                    rb += std::to_string(cache_shard_slot_first(sh, n));
                    rb += ' ';
                    rb += std::to_string(cache_shard_slot_last(sh, n));
                    rb += ' ';
                    rb += host;
                    rb += ':';
                    rb += std::to_string(cluster_port_of(sh));
                    rb += ' ';
                    rb += cluster_node_id(sh);
                    rb += '\n';
                }
            }
            break;
        }

        case fnv1a("shards"):
        {
            if (!resp)
            {
                // The text protocol has no nested types and a client that
                // speaks CLUSTER SHARDS speaks RESP, so this is the same
                // information in the line form.
                emit_cluster(conn, "slots", arg, false);
                break;
            }
            resp::encode_array_header_into(rb, static_cast<int>(n));
            for (uint32_t sh = 0; sh < n; ++sh)
            {
                resp::encode_array_header_into(rb, 4);
                resp::encode_bulk_into(rb, "slots");
                resp::encode_array_header_into(rb, 2);
                resp::encode_integer_into(rb, cache_shard_slot_first(sh, n));
                resp::encode_integer_into(rb, cache_shard_slot_last(sh, n));
                resp::encode_bulk_into(rb, "nodes");
                resp::encode_array_header_into(rb, 1);
                resp::encode_array_header_into(rb, 14);
                resp::encode_bulk_into(rb, "id");
                resp::encode_bulk_into(rb, cluster_node_id(sh));
                resp::encode_bulk_into(rb, "port");
                resp::encode_integer_into(rb, cluster_port_of(sh));
                resp::encode_bulk_into(rb, "ip");
                resp::encode_bulk_into(rb, host);
                resp::encode_bulk_into(rb, "endpoint");
                resp::encode_bulk_into(rb, host);
                resp::encode_bulk_into(rb, "role");
                resp::encode_bulk_into(rb, "master");
                resp::encode_bulk_into(rb, "replication-offset");
                resp::encode_integer_into(rb, 0);
                resp::encode_bulk_into(rb, "health");
                resp::encode_bulk_into(rb, "online");
            }
            break;
        }

        case fnv1a("nodes"):
        {
            std::string out;
            if (shared)
            {
                const uint32_t bus = static_cast<uint32_t>(m_base_port) + 10000u;
                out += cluster_node_id(n) + ' ' + host + ':' + std::to_string(m_base_port) + '@' +
                       std::to_string(bus <= 65535u ? bus : 0u) + " myself,master - 0 " +
                       std::to_string(socketley::wall::now_ms()) + " 1 connected\n";
            }
            for (uint32_t sh = 0; sh < n; ++sh)
                out += node_line(sh);
            if (resp) resp::encode_bulk_into(rb, out);
            else      rb += out;
            break;
        }

        case fnv1a("info"):
        {
            std::string out;
            // The mode and not the shard count, because a sharded cache
            // under --no-cluster routes nothing and must say 0, and a
            // single-shard cache with --cluster speaks the protocol and says 1.
            out += m_cluster_on ? "cluster_enabled:1\r\n" : "cluster_enabled:0\r\n";
            out += "cluster_state:ok\r\n";
            out += "cluster_slots_assigned:16384\r\n";
            out += "cluster_slots_ok:16384\r\n";
            out += "cluster_slots_pfail:0\r\n";
            out += "cluster_slots_fail:0\r\n";
            out += "cluster_known_nodes:" + std::to_string(n + (shared ? 1 : 0)) + "\r\n";
            out += "cluster_size:" + std::to_string(n) + "\r\n";
            out += "cluster_current_epoch:1\r\n";
            out += "cluster_my_epoch:1\r\n";
            out += "cluster_stats_messages_sent:0\r\n";
            out += "cluster_stats_messages_received:0\r\n";
            if (resp) resp::encode_bulk_into(rb, out);
            else      rb += out;
            break;
        }

        case fnv1a("myid"):
        {
            const std::string id = cluster_node_id(me);
            if (resp) resp::encode_bulk_into(rb, id);
            else    { rb += id; rb += '\n'; }
            break;
        }

        case fnv1a("keyslot"):
        {
            // redis-cli's own way of asking, and the one command here that
            // takes an argument, which lets an operator check our slot
            // arithmetic against a real Redis.
            const int64_t slot = static_cast<int64_t>(cache_slot_of(arg));
            if (resp) resp::encode_integer_into(rb, slot);
            else    { rb += std::to_string(slot); rb += '\n'; }
            break;
        }

        case fnv1a("countkeysinslot"):
        {
            // Only answerable for a slot this shard owns, because every other
            // answer would need a crossing to produce a number nothing depends
            // on.
            // Read whole and wide: a number past 2^32 narrowed into the slot range answered for a slot nobody named.
            uint64_t wide = 0;
            const auto [end, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), wide);
            const uint32_t slot = (ec == std::errc{} && end == arg.data() + arg.size() && wide < cache_slot_count)
                                      ? static_cast<uint32_t>(wide) : cache_slot_count;
            if (slot >= cache_slot_count)
            {
                if (resp) resp::encode_error_into(rb, "invalid slot");
                else      rb += "error: invalid slot\n";
                break;
            }
            if (cache_shard_of_slot(slot, n) != me)
            {
                if (resp) resp::encode_error_into(rb,
                    "this shard does not own slot " + std::to_string(slot));
                else      rb += "error: this shard does not own that slot\n";
                break;
            }
            int64_t count = 0;
            std::vector<std::string_view> all;
            m_store.keys("*", all);
            for (const auto& k : all)
                if (cache_slot_of(k) == slot)
                    ++count;
            if (resp) resp::encode_integer_into(rb, count);
            else    { rb += std::to_string(count); rb += '\n'; }
            break;
        }

        default:
        {
            std::string msg = "unknown CLUSTER subcommand '";
            msg.append(sub);
            msg += "' -- this cache answers SLOTS, SHARDS, NODES, INFO, MYID, "
                   "KEYSLOT and COUNTKEYSINSLOT";
            if (resp) resp::encode_error_into(rb, msg);
            else    { rb += "error: "; rb += msg; rb += '\n'; }
            break;
        }
    }
}

void cache_instance::emit_unrouted(client_connection* conn, std::string_view cmd,
                                   bool resp, std::string_view why)
{
    // Named rather than swallowed, and per command rather than per connection,
    // because that is the only shape a pipelined client can read.
    if (resp)
    {
        std::string text;
        text.reserve(4 + cmd.size() + why.size());
        text.append(cmd);
        text.push_back(' ');
        text.append(why);
        resp::encode_error_into(conn->response_buf, text);
    }
    else
    {
        conn->response_buf.append("error: ");
        conn->response_buf.append(cmd);
        conn->response_buf.push_back(' ');
        conn->response_buf.append(why);
        conn->response_buf.push_back('\n');
    }
}

// ─── the ticket side ────────────────────────────────────────────────────────
// A request from another process reaches a sharded cache through the worker,
// which parks it on the channel and hands the ticket here, so a key another
// shard owns is crossed for and answered on the turn the crossing lands.

// Whether a crossing opened for `conn` has somebody to come back to: a socket
// always, the scratch connection only while a ticket is parked on it.
bool cache_instance::can_cross(const client_connection* conn) const
{
    return conn->fd >= 0
        || (m_serving_ticket != 0 && conn == m_request_conn.get());
}

bool cache_instance::serve_deferred(uint64_t ticket, std::string_view /*target*/,
                                    std::string_view payload)
{
    // A sibling's framed run names only this shard's keys and a re-entrant
    // ask has no later turn, so both finish now exactly as they did inline.
    const bool framed =
        !payload.empty() && payload.front() == shard_batch_marker
        && payload.compare(0, one_command_text.size(), one_command_text) != 0;
    if (m_serving || framed || m_shard_n <= 1)
    {
        std::string out;
        serve_payload(payload, out, true);
        complete_ticket(ticket, request_status::ok, out);
        return true;
    }

    // Behind the one waiting on a sibling rather than ahead of it, because
    // the asker pipelines by order and a local key answered first would
    // reorder its replies.
    if (m_deferred_inflight != 0)
    {
        if (m_deferred_queue.size() >= MAX_DEFERRED_QUEUE)
            return false;
        m_deferred_queue.push_back(deferred_request{ticket, std::string(payload)});
        return true;
    }

    run_deferred(ticket, payload);
    return true;
}

// One request on the scratch connection with a ticket to answer to, finished
// now when nothing crossed and from batch_finish() otherwise.
void cache_instance::run_deferred(uint64_t ticket, std::string_view payload)
{
    if (!m_request_conn)
        m_request_conn = socketley::make_connection<client_connection>();

    auto* conn = m_request_conn.get();
    conn->fd        = -1;
    conn->rl_max    = 0;
    conn->rl_tokens = 0.0;
    conn->batches.clear();
    conn->crossing_bytes = 0;
    conn->closing   = false;
    conn->response_buf.clear();

    struct ticket_guard
    {
        uint64_t& ticket;
        bool&     serving;
        ~ticket_guard() { ticket = 0; serving = false; }
    } guard{m_serving_ticket, m_serving};
    m_serving_ticket = ticket;
    m_serving        = true;

    // The CLI's one-command form, taken whole before the line splitter can
    // see a newline inside its value.
    if (payload.size() > one_command_text.size()
        && payload.compare(0, one_command_text.size(), one_command_text) == 0)
        process_command(conn, payload.substr(one_command_text.size()));
    else
        run_request_lines(conn, payload);

    route_flush(conn);
    if (!conn->batches.empty())
    {
        m_deferred_inflight = ticket;   // answered from batch_finish()
        return;
    }
    complete_ticket(ticket, request_status::ok, conn->response_buf);
}

void cache_instance::complete_ticket(uint64_t ticket, request_status st,
                                     std::string_view reply)
{
    publish_keyspace();
    if (auto* mgr = get_runtime_manager())
        mgr->requests().complete_deferred(ticket, st, reply);
}

// The requests queued behind a crossing, run once it is answered, until one
// of them opens a crossing of its own.
void cache_instance::drain_deferred()
{
    while (m_deferred_inflight == 0 && !m_deferred_queue.empty())
    {
        deferred_request q = std::move(m_deferred_queue.front());
        m_deferred_queue.pop_front();
        run_deferred(q.ticket, q.payload);
    }
}

void cache_instance::route_flush(client_connection* conn)
{
    if (SOCKETLEY_LIKELY(!m_collect))
        return;

    // A connection that has given up on the answer is not worth crossing for,
    // and the slots go with it.
    if (conn->closing)
    {
        route_unmark(m_collect.get(), {});
        m_collect.reset();
        m_collect_fd = -1;
        return;
    }

    auto  batch = std::move(m_collect);
    auto* mgr   = get_runtime_manager();
    m_collect.reset();
    m_collect_hint = static_cast<uint32_t>(std::min<size_t>(batch->slots.size(), 1024));
    const int collected_for = m_collect_fd;
    m_collect_fd = -1;

    // The batch being collected belongs to the connection being parsed and one
    // connection is parsed at a time, checked rather than assumed because the
    // cost is a reply down somebody else's socket.
    if (SOCKETLEY_UNLIKELY(collected_for != conn->fd))
    {
        LOG_WARN("cache: a routed batch was collected for another connection; "
                 "dropped rather than answered to the wrong socket");
        route_unmark(batch.get(), {});
        return;
    }

    // Nothing to post through is the one refusal known now, filled in on the spot, because the alternative is a batch
    // permanently one answer short of complete.
    if (SOCKETLEY_UNLIKELY(!mgr))
        route_unmark(batch.get(), "the shard that owns this key could not be reached");

    const uint64_t id    = batch->id;
    const size_t   resp  = batch->resp ? 1 : 0;
    size_t         bytes = 0;

    // Counted per sibling now and posted with the turn's other connections in on_loop_turn(), so the frame a batch
    // went into is the one whose answer ends its wait.
    for (uint32_t sh = 0; sh < m_shard_n; ++sh)
    {
        cross_mark& mk = m_route_mark[sh];
        if (mk.bytes == SIZE_MAX)
            continue;
        const turn_crossing& tc = m_turn_cross[static_cast<size_t>(sh) * 2 + resp];
        ++batch->outstanding;
        bytes += tc.payload.size() - mk.bytes;
        m_turn_cross_any = true;
    }

    if (batch->outstanding == 0 && conn->batches.empty())
    {
        // Nothing crossed and nothing older is out, so the connection never
        // waits.
        for (const reply_slot& sl : batch->slots)
            if (!slot_render(sl, batch->resp, conn->response_buf))
                append_error_reply(conn->response_buf, batch->resp,
                                   "this cache's shards answered in a shape "
                                   "this build cannot put back together");
        for (cross_mark& mk : m_route_mark)
            mk = cross_mark{};
        return;
    }

    // A batch answering a ticket carries what the scratch connection produced
    // ahead of the crossing, because no socket keeps it.
    if (m_serving_ticket != 0 && conn == m_request_conn.get())
    {
        batch->ticket = m_serving_ticket;
        batch->head.swap(conn->response_buf);
    }

    batch->done  = batch->outstanding == 0;
    batch->bytes = bytes;
    conn->batches.push_back(id);
    conn->crossing_bytes += bytes;
    m_batches.emplace(id, std::move(*batch));

    // A frame grown past its bounds goes now rather than at the end of the turn, which bounds what one answer carries.
    for (uint32_t sh = 0; sh < m_shard_n; ++sh)
    {
        cross_mark& mk = m_route_mark[sh];
        if (mk.bytes == SIZE_MAX)
            continue;
        mk = cross_mark{};
        const uint32_t idx = sh * 2 + static_cast<uint32_t>(resp);
        const turn_crossing& tc = m_turn_cross[idx];
        if (tc.targets.size() >= TURN_CROSS_TARGETS || tc.payload.size() >= TURN_CROSS_BYTES)
            post_turn_crossing(idx, true);
    }
}

void cache_instance::route_unmark(shard_batch* b, std::string_view why)
{
    const size_t resp = (b && b->resp) ? 1 : 0;
    for (uint32_t sh = 0; sh < m_shard_n; ++sh)
    {
        cross_mark& mk = m_route_mark[sh];
        if (mk.bytes == SIZE_MAX)
            continue;
        turn_crossing& tc = m_turn_cross[static_cast<size_t>(sh) * 2 + resp];
        if (b && !why.empty())
            for (size_t i = mk.targets; i < tc.targets.size(); ++i)
                batch_fill_error(*b, tc.targets[i].slot, tc.targets[i].part, why);
        tc.targets.resize(std::min(mk.targets, tc.targets.size()));
        // What is left is only the frame's header when no earlier batch wrote into it.
        tc.payload.resize(tc.targets.empty() ? 0 : std::min(mk.bytes, tc.payload.size()));
        mk = cross_mark{};
    }
}

// One sibling's frame for the turn, with a refusal answered at once for every batch in it, because a batch left
// waiting on a post that was never taken never completes.
void cache_instance::post_turn_crossing(uint32_t idx, bool later)
{
    turn_crossing& tc = m_turn_cross[idx];
    if (tc.targets.empty())
    {
        tc.payload.clear();
        return;
    }
    const uint32_t sh  = idx / 2;
    auto*          mgr = get_runtime_manager();
    const uint64_t cookie = m_next_cookie++;
    auto [pit, fresh] = m_posts.try_emplace(cookie);
    (void)fresh;
    pit->second.targets.assign(tc.targets.begin(), tc.targets.end());
    const bool taken = mgr && mgr->requests().post(this, cookie, shard_target(get_name(), sh), tc.payload,
                                                   request_class::client);
    tc.payload.clear();
    tc.targets.clear();
    if (taken)
        return;

    posted_group grp = std::move(pit->second);
    m_posts.erase(pit);
    settle_post(grp, request_status::no_target, {}, "the shard that owns this key could not be reached", later);
}

void cache_instance::post_turn_crossings()
{
    m_turn_cross_any = false;
    for (uint32_t idx = 0; idx < m_turn_cross.size(); ++idx)
        if (!m_turn_cross[idx].targets.empty())
            post_turn_crossing(idx);
}

void cache_instance::batch_fill_error(shard_batch& b, uint32_t slot, uint32_t part, std::string_view why)
{
    if (slot >= b.slots.size())
        return;
    reply_slot& sl = b.slots[slot];
    if (part >= sl.parts.size() || sl.part_filled[part])
        return;
    sl.parts[part].clear();
    append_error_reply(sl.parts[part], b.resp, why);
    sl.part_filled[part] = 1;
    if (sl.parts_left > 0)
        --sl.parts_left;
}

void cache_instance::batch_drop(client_connection* conn)
{
    for (const uint64_t id : conn->batches)
        m_batches.erase(id);
    conn->batches.clear();
    conn->crossing_bytes = 0;
    // The posts are left where they are, because each resolves through the
    // batch and a reply for a batch that has gone finds nothing and is
    // dropped.
}

void cache_instance::batch_finish(uint64_t id)
{
    const auto it = m_batches.find(id);
    if (it == m_batches.end())
        return;

    // A batch answering a ticket has no socket to write to: its pieces go
    // back through the channel and the next request waiting behind it runs.
    if (it->second.ticket != 0)
    {
        shard_batch b = std::move(it->second);
        m_batches.erase(it);

        std::string out;
        out.swap(b.head);
        for (const reply_slot& sl : b.slots)
            if (!slot_render(sl, b.resp, out))
                append_error_reply(out, b.resp,
                                   "this cache's shards answered in a shape this "
                                   "build cannot put back together");

        if (m_deferred_inflight == b.ticket)
            m_deferred_inflight = 0;
        complete_ticket(b.ticket, request_status::ok, out);
        drain_deferred();
        return;
    }

    const int fd = it->second.fd;
    client_connection* conn =
        (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;

    // Both halves are load-bearing, because the descriptor may already belong
    // to a client that never asked anything and would not list this batch.
    if (!conn || std::find(conn->batches.begin(), conn->batches.end(), id)
                     == conn->batches.end())
    {
        m_batches.erase(it);
        return;
    }
    it->second.done = true;

    // Rendered from the oldest batch forward and only as far as the answered
    // ones reach, because the client reads replies in the order it asked.
    while (!conn->batches.empty())
    {
        const auto head = m_batches.find(conn->batches.front());
        if (head == m_batches.end())
        {
            conn->batches.erase(conn->batches.begin());
            continue;
        }
        if (!head->second.done)
            break;
        for (const reply_slot& sl : head->second.slots)
            if (!slot_render(sl, head->second.resp, conn->response_buf))
                append_error_reply(conn->response_buf, head->second.resp,
                                   "this cache's shards answered in a shape this "
                                   "build cannot put back together");
        conn->crossing_bytes -= std::min(conn->crossing_bytes, head->second.bytes);
        m_batches.erase(head);
        conn->batches.erase(conn->batches.begin());
    }

    // Whatever the client pipelined behind the crossing runs now and may open
    // a crossing of its own, because those commands arrived before the FIN and
    // are owed answers.
    if (!conn->closing)
        pump(conn);

    if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
        conn->closing = true;
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr) && !tls_flush(conn))
        conn->closing = true;

    // Crossings still out: the hold continues and the reply that ends it comes
    // back through here, with the read returning as soon as enough of them
    // have answered.
    if (!conn->batches.empty())
    {
        if (!conn->closing && SOCKETLEY_UNLIKELY(!resume_read(conn, fd)))
            close_client(conn, fd, "read-submit-failed");
        return;
    }

    // The debt is paid so a held close can be taken, after the flush, because
    // the write completion is what actually tears the connection down.
    if (conn->peer_gone)
        conn->closing = true;

    if (conn->closing && !conn->write_pending && !conn->read_pending)
    {
        close_client(conn, fd, "crossing-answered");
        return;
    }

    if (!conn->closing && SOCKETLEY_UNLIKELY(!resume_read(conn, fd)))
        close_client(conn, fd, "read-submit-failed");
}

void cache_instance::on_request_reply(uint64_t cookie, request_status st,
                                      std::string_view reply)
{
    if (const auto lit = m_lua_pub_posts.find(cookie); lit != m_lua_pub_posts.end())
    {
        if (st != request_status::ok)
            LOG_WARN(("cache: a sibling shard did not take " + std::to_string(lit->second) +
                      " script publish(es) (" + request_status_text(st) +
                      "); its subscribers did not hear them").c_str());
        m_lua_pub_posts.erase(lit);
        return;
    }
    const auto pit = m_posts.find(cookie);
    if (pit == m_posts.end())
        return;                       // already answered, or withdrawn

    posted_group grp = std::move(pit->second);
    m_posts.erase(pit);
    settle_post(grp, st, reply, request_status_text(st));
}

// One frame's answers into the batches they belong to, each batch then one sibling nearer complete, finished in the
// order the frame met them.
void cache_instance::settle_post(const posted_group& grp, request_status st, std::string_view reply,
                                 std::string_view why, bool later)
{
    std::vector<uint64_t> touched;
    touched.swap(m_reply_touched);
    touched.clear();

    uint64_t     cur_id = 0;
    shard_batch* cur    = nullptr;
    auto batch_of = [&](uint64_t id) -> shard_batch* {
        if (id != cur_id || touched.empty())
        {
            cur_id = id;
            const auto bit = m_batches.find(id);
            cur = bit == m_batches.end() ? nullptr : &bit->second;
            // A batch that went while this crossed is skipped, its frames still read past.
            if (cur)
                touched.push_back(id);
        }
        return cur;
    };

    // One frame per command sent in the order they were sent, with unfilled pieces answered rather than left, because
    // a piece nobody fills is a client that never hears back.
    const char* p   = reply.data();
    const char* end = reply.data() + reply.size();
    size_t      i   = 0;
    if (st == request_status::ok)
    {
        for (; i < grp.targets.size(); ++i)
        {
            std::string_view one;
            if (!shard_frame_take(p, end, one))
                break;

            const post_target& t = grp.targets[i];
            shard_batch* b = batch_of(t.batch);
            if (!b || t.slot >= b->slots.size())
                continue;
            reply_slot& sl = b->slots[t.slot];
            if (t.part >= sl.parts.size() || sl.part_filled[t.part])
                continue;

            sl.parts[t.part].assign(one);
            sl.part_filled[t.part] = 1;
            if (sl.parts_left > 0)
                --sl.parts_left;
        }
        if (i < grp.targets.size())
            why = "the shard that owns this key answered in a framing this build does not read";
    }
    for (; i < grp.targets.size(); ++i)
    {
        const post_target& t = grp.targets[i];
        if (shard_batch* b = batch_of(t.batch))
            batch_fill_error(*b, t.slot, t.part, why);
    }

    // After every fill, because finishing a batch runs its connection's next commands, and those may close another
    // connection whose batch this frame also answered.
    for (const uint64_t id : touched)
    {
        const auto bit = m_batches.find(id);
        if (bit == m_batches.end())
            continue;
        shard_batch& b = bit->second;
        if (b.outstanding > 0)
            --b.outstanding;
        if (b.outstanding == 0)
        {
            if (later)
                m_finish_due.push_back(id);
            else
                batch_finish(id);
        }
    }

    if (m_reply_touched.empty())
        m_reply_touched.swap(touched);
}

void cache_instance::finish_due()
{
    std::vector<uint64_t> due;
    due.swap(m_finish_due);
    for (const uint64_t id : due)
        if (const auto bit = m_batches.find(id); bit != m_batches.end() && bit->second.outstanding == 0)
            batch_finish(id);
}

// ─── the answering side ─────────────────────────────────────────────────────

bool cache_instance::serve_shard_batch(std::string_view payload, std::string& out)
{
    bool resp;
    if (payload.rfind(shard_batch_text, 0) == 0)
        resp = false;
    else if (payload.rfind(shard_batch_resp, 0) == 0)
        resp = true;
    else
        return false;

    if (!m_request_conn)
        m_request_conn = socketley::make_connection<client_connection>();

    auto* conn = m_request_conn.get();
    conn->fd        = -1;
    conn->rl_max    = 0;
    conn->rl_tokens = 0.0;
    conn->batches.clear();
    conn->crossing_bytes = 0;
    conn->response_buf.clear();

    const char* p   = payload.data()
                    + (resp ? shard_batch_resp.size() : shard_batch_text.size());
    const char* end = payload.data() + payload.size();

    // Saved and restored rather than set and cleared, because a command served
    // here can reach Lua and a script can ask this cache another question from
    // inside it.
    const bool prev_serving = m_serving_shard_batch;
    m_serving_shard_batch   = true;
    struct batch_serving_guard
    {
        bool& flag; bool prev;
        ~batch_serving_guard() { flag = prev; }
    } sguard{m_serving_shard_batch, prev_serving};

    std::string_view one;
    std::string      produced;
    while (shard_frame_take(p, end, one))
    {
        // The same call the routing side makes for a part it owns itself, so a
        // key served here and the same key served there cannot diverge.
        run_local_raw(conn, one, resp, produced);
        shard_frame_append(out, produced);
    }
    publish_keyspace();

    conn->response_buf.clear();
    return true;
}

// The sharded scan cursor takes the top six bits of the store's cursor, which
// are free only while the store's map index fits in the two below them.
static_assert(cache_scan_shard_shift == 64 - 6,
              "the sharded scan cursor assumes six shard bits");
static_assert(cache_store::scan_last_map <= 7,
              "cache_store::scan() now walks more than eight maps, so its map "
              "index no longer fits below the six bits the sharded scan cursor "
              "takes -- a cursor would silently name another shard");

// Rebuild a RESP command from the parsed arguments, which are views into
// exactly these bytes, so one fact about one message stays in one place.
static void rebuild_resp(std::string& out, std::string_view* args, int argc)
{
    out.clear();
    out.reserve(16 + static_cast<size_t>(argc) * 24);
    out.push_back('*');
    append_dec(out, static_cast<size_t>(argc));
    out.append("\r\n", 2);
    for (int i = 0; i < argc; ++i)
    {
        out.push_back('$');
        append_dec(out, args[i].size());
        out.append("\r\n", 2);
        out.append(args[i]);
        out.append("\r\n", 2);
    }
}

// Which shard a SCAN resumes in, read off its cursor, with an unusable cursor
// answered here because the local interpreter already has the words and
// shard_scan() makes the same judgement.
uint32_t cache_instance::scan_cursor_owner(std::string_view cursor_arg) const
{
    const size_t sp = cursor_arg.find(' ');
    const std::string_view tok =
        (sp == std::string_view::npos) ? cursor_arg : cursor_arg.substr(0, sp);
    if (tok.empty())
        return m_shard_i;

    uint64_t cur = 0;
    const auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), cur);
    if (ec != std::errc{} || ptr != tok.data() + tok.size())
        return m_shard_i;

    const uint32_t sh = cache_scan_cursor_shard(cur);
    return sh < m_shard_n ? sh : m_shard_i;
}

// One SCAN page out of this shard and the cursor to resume with, which
// unsharded is m_store.scan() exactly as before and sharded is the sequential
// walk cache_shard_map.h describes.
bool cache_instance::shard_scan(uint64_t cursor, std::string_view pattern,
                                size_t count, std::vector<std::string_view>& out,
                                uint64_t& next, bool node_local,
                                const cache_store::scan_filter& filter)
{
    if (SOCKETLEY_LIKELY(m_shard_n <= 1))
    {
        next = m_store.scan(cursor, pattern, count, out,
                            filter);
        return true;
    }

    // A SCAN on the per-shard port walks this shard only, because a cluster
    // client asks each node itself -- and handing it the sequential cursor
    // would restart the walk here forever.
    if (node_local)
    {
        const uint64_t store_next =
            m_store.scan(cache_scan_cursor_store(cursor), pattern, count, out,
                         filter);
        next = store_next == 0 ? 0
                               : cache_scan_cursor_make(m_shard_i, store_next);
        return true;
    }

    const uint32_t sh = cache_scan_cursor_shard(cursor);
    if (sh >= m_shard_n)
        return false;           // a cursor from a shard set that is not this one

    const uint64_t store_next =
        m_store.scan(cache_scan_cursor_store(cursor), pattern, count, out,
                     filter);

    if (store_next != 0)
        next = cache_scan_cursor_make(m_shard_i, store_next);
    else if (m_shard_i + 1 < m_shard_n)
        next = cache_scan_cursor_make(m_shard_i + 1, 0);   // on to the next slice
    else
        next = 0;               // every shard walked
    return true;
}

// A single-key command built for the wire in whichever protocol the caller
// speaks, which is where every sub-command a multi-key command explodes into
// is built.
static void build_text_cmd(std::string& out, std::string_view verb,
                           std::string_view a, std::string_view b = {})
{
    out.clear();
    out.append(verb);
    out.push_back(' ');
    out.append(a);
    if (!b.empty() || verb == "set")
    {
        out.push_back(' ');
        out.append(b);
    }
}

static void build_resp_cmd(std::string& out, std::string_view verb,
                           std::string_view a, const std::string_view* b = nullptr)
{
    const int argc = b ? 3 : 2;
    out.clear();
    out.push_back('*');
    out.append(std::to_string(argc));
    out.append("\r\n", 2);
    const std::string_view parts[3] = { verb, a, b ? *b : std::string_view{} };
    for (int i = 0; i < argc; ++i)
    {
        out.push_back('$');
        out.append(std::to_string(parts[i].size()));
        out.append("\r\n", 2);
        out.append(parts[i]);
        out.append("\r\n", 2);
    }
}

// A ceiling on how many pieces one command may explode into, because `partial`
// is a megabyte and a limit that says so is a better answer than one
// discovered as memory.
static constexpr size_t MAX_PARTS_PER_COMMAND = 65536;

// A multi-key command on the per-shard port is served here, redirected with
// -MOVED, or refused with -CROSSSLOT -- because -MOVED for a command with keys
// on both sides would bounce the client between two shards until it ran out of
// redirects.
// One shard owns every key, or the command does not run.  Extracted from EVAL,
// which had it first, because set algebra needs exactly the same decision and
// a second copy of it is a second place for the two to drift apart.
//
// Returns true when the command has been dealt with -- refused, corrected with
// -MOVED, or sent whole to the shard that owns it -- and false when the caller
// should carry on and serve it locally.
bool cache_instance::route_all_keys_one_shard(client_connection* conn,
                                              std::string_view* args, int argc,
                                              int key_first, int key_count)
{
    if (key_count <= 0 || key_first + key_count > argc)
        return false;

    const uint32_t owner = cache_shard_of(args[key_first], m_shard_n);
    for (int i = 1; i < key_count; ++i)
        if (cache_shard_of(args[key_first + i], m_shard_n) != owner)
        {
            run_in_reply_order(conn, [&] {
                resp::encode_error_code_into(conn->response_buf,
                    "CROSSSLOT Keys in request don't hash to the same slot");
            });
            return true;
        }

    if (owner == m_shard_i)
        return false;

    // The per-shard port corrects the client's map rather than crossing,
    // exactly as a single-key command does there.
    if (conn->cluster_port)
    {
        run_in_reply_order(conn, [&] { emit_moved(conn, args[key_first], owner, true); });
        return true;
    }
    if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
    {
        run_in_reply_order(conn, [&] {
            emit_unrouted(conn, args[0], true,
                          "runs against keys another shard owns, and "
                          "this path cannot wait for it");
        });
        return true;
    }
    const uint32_t slot = slot_open(conn, true, cache_merge::single, 1);
    std::string raw;
    resp::encode_array_header_into(raw, argc);
    for (int i = 0; i < argc; ++i) resp::encode_bulk_into(raw, args[i]);
    route_part(conn, owner, slot, 0, raw, true);
    return true;
}

bool cache_instance::cluster_multi_verdict(client_connection* conn,
                                           const std::vector<std::string_view>& keys,
                                           bool resp)
{
    return cluster_multi_verdict(conn, keys.data(), keys.size(), resp);
}

bool cache_instance::cluster_multi_verdict(client_connection* conn,
                                           const std::string_view* keys, size_t nkeys,
                                           bool resp)
{
    bool any_local = false, any_foreign = false, mixed_foreign = false;
    uint32_t       foreign_owner = 0;
    std::string_view foreign_key;

    for (size_t ki = 0; ki < nkeys; ++ki)
    {
        const std::string_view k = keys[ki];
        const uint32_t o = cache_shard_of(k, m_shard_n);
        if (o == m_shard_i)
        {
            any_local = true;
            continue;
        }
        if (!any_foreign)
        {
            any_foreign   = true;
            foreign_owner = o;
            foreign_key   = k;
        }
        else if (o != foreign_owner)
        {
            mixed_foreign = true;
        }
    }

    if (!any_foreign)
        return false;

    run_in_reply_order(conn, [&] {
        if (any_local || mixed_foreign)
        {
            if (resp)
                resp::encode_error_code_into(conn->response_buf,
                    "CROSSSLOT Keys in request don't hash to the same slot");
            else
                conn->response_buf.append(
                    "error: CROSSSLOT Keys in request don't hash to the same slot\n");
        }
        else
        {
            emit_moved(conn, foreign_key, foreign_owner, resp);
        }
    });
    return true;
}

// mget and mset in the text protocol exploded into single-key commands, split
// exactly as the interpreter splits them, because the router and the store
// must read a line the same way.
// A multi-key command none of whose keys is foreign has nothing to cross for.
bool cache_instance::keys_all_local(const std::string_view* keys, size_t n) const
{
    for (size_t i = 0; i < n; ++i)
        if (cache_shard_of(keys[i], m_shard_n) != m_shard_i)
            return false;
    return true;
}

bool cache_instance::explode_text_multi(client_connection* conn, uint32_t h,
                                        std::string_view args)
{
    std::vector<std::string_view> keys, vals;
    std::string_view rest = args;

    if (h == fnv1a("mget"))
    {
        while (!rest.empty())
        {
            const size_t sp = rest.find(' ');
            const std::string_view k = (sp == std::string_view::npos) ? rest : rest.substr(0, sp);
            if (!k.empty()) keys.push_back(k);
            if (sp == std::string_view::npos) break;
            rest = rest.substr(sp + 1);
        }
    }
    else    // mset
    {
        while (!rest.empty())
        {
            const size_t sp1 = rest.find(' ');
            if (sp1 == std::string_view::npos)
                return false;       // a key without its value, which the interpreter refuses whole
            const std::string_view k = rest.substr(0, sp1);
            rest = rest.substr(sp1 + 1);
            const size_t sp2 = rest.find(' ');
            const std::string_view v = (sp2 == std::string_view::npos) ? rest : rest.substr(0, sp2);
            keys.push_back(k);
            vals.push_back(v);
            if (sp2 == std::string_view::npos) break;
            rest = rest.substr(sp2 + 1);
        }
    }

    if (keys.empty())
        return false;       // a usage error, which the interpreter answers
    // Past the ceiling is refused and not run here, where every key would land in this shard's store.
    if (keys.size() > MAX_PARTS_PER_COMMAND)
    {
        run_in_reply_order(conn, [&] {
            emit_unrouted(conn, h == fnv1a("mget") ? "mget" : "mset", false,
                          "names more keys than a sharded cache takes in one command (65536)");
        });
        return true;
    }

    // The per-shard port does not explode and cross but tells the client where
    // to go, and false means every key is this shard's.
    if (SOCKETLEY_UNLIKELY(conn->cluster_port)
        && cluster_multi_verdict(conn, keys, false))
        return true;

    // Keys that are all this shard's are what a hash tag is written to produce,
    // and false hands the whole command to the interpreter rather than one
    // crossing per key that never leaves this process.
    if (keys_all_local(keys.data(), keys.size()))
        return false;

    // A crossing needs somebody to keep waiting, which the scratch connection
    // cannot: same gate as the single-key case and the same reason.
    if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
    {
        run_in_reply_order(conn, [&] {
            emit_unrouted(conn, h == fnv1a("mget") ? "mget" : "mset", false,
                          "names keys several shards own, and this path "
                          "cannot wait for them");
        });
        return true;
    }

    // The same table, before the same irreversible step, because an `else`
    // standing for mset would quietly turn the next multi-key spelling added
    // here into a write.
    std::string_view part_cmd;
    switch (h)
    {
        case fnv1a("mget"): part_cmd = "get"; break;
        case fnv1a("mset"): part_cmd = "set"; break;
        default: return false;
    }

    const uint32_t slot = slot_open(conn, false, cache_merge_for(h),
                                    static_cast<uint32_t>(keys.size()));
    std::string raw;
    for (size_t i = 0; i < keys.size(); ++i)
    {
        if (h == fnv1a("mget")) build_text_cmd(raw, part_cmd, keys[i]);
        else                    build_text_cmd(raw, part_cmd, keys[i], vals[i]);
        route_part(conn, cache_shard_of(keys[i], m_shard_n), slot,
                   static_cast<uint32_t>(i), raw, false);
    }
    return true;
}

// mget / mset / multi-key del in RESP, the same way.
bool cache_instance::explode_resp_multi(client_connection* conn, uint32_t h,
                                        std::string_view* args, int argc)
{
    const bool is_mset = (h == fnv1a("mset"));
    const size_t n = is_mset ? static_cast<size_t>((argc - 1) / 2)
                             : static_cast<size_t>(argc - 1);

    if (n == 0)
        return false;
    if (is_mset && ((argc - 1) % 2 != 0))
        return false;       // the interpreter's own arity refusal
    if (n > MAX_PARTS_PER_COMMAND)
    {
        run_in_reply_order(conn, [&] {
            emit_unrouted(conn, args[0], true,
                          "names more keys than a sharded cache takes in one command (65536)");
        });
        return true;
    }

    // Same verdict as the text spelling over the same keys read the RESP way,
    // with the vector built only on this port.
    if (SOCKETLEY_UNLIKELY(conn->cluster_port))
    {
        if (!is_mset)
        {
            // Straight at the arguments: no copy, no allocation.
            if (cluster_multi_verdict(conn, args + 1, n, true))
                return true;
        }
        else
        {
            m_multi_keys.clear();
            for (size_t i = 0; i < n; ++i) m_multi_keys.push_back(args[1 + i * 2]);
            if (cluster_multi_verdict(conn, m_multi_keys.data(), n, true))
                return true;
        }
    }

    // Same shortcut as the text spelling, walking the arguments in place
    // because this port builds no vector to walk.
    bool local = true;
    for (size_t i = 0; i < n && local; ++i)
        local = (cache_shard_of(is_mset ? args[1 + i * 2] : args[1 + i],
                                m_shard_n) == m_shard_i);
    if (local)
        return false;

    if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
    {
        run_in_reply_order(conn, [&] {
            emit_unrouted(conn, args[0], true,
                          "names keys several shards own, and this path "
                          "cannot wait for them");
        });
        return true;
    }

    // What each multi-key spelling becomes per key: one table, decided once,
    // and BEFORE the slot is opened -- a refusal after that leaves a slot
    // nothing will ever fill while the caller answers locally as well.  A
    // chain here is what let EXISTS fall through to DEL and answer by
    // deleting, so the mapping is written where it can be read at a glance.
    std::string_view part_cmd;
    switch (h)
    {
        case fnv1a("mset"):   part_cmd = "SET";    break;
        case fnv1a("mget"):   part_cmd = "GET";    break;
        case fnv1a("exists"):
        case fnv1a("touch"):  part_cmd = "EXISTS"; break;
        case fnv1a("del"):
        case fnv1a("unlink"): part_cmd = "DEL";    break;
        // Unreachable while cache_classify_resp names the multi-key set, and
        // the local dispatch's answer if it ever stops.
        default: return false;
    }

    const uint32_t slot = slot_open(conn, true, cache_merge_for(h),
                                    static_cast<uint32_t>(n));
    std::string raw;
    for (size_t i = 0; i < n; ++i)
    {
        const std::string_view key = is_mset ? args[1 + i * 2] : args[1 + i];
        if (is_mset)
        {
            const std::string_view val = args[2 + i * 2];
            build_resp_cmd(raw, part_cmd, key, &val);
        }
        else
            build_resp_cmd(raw, part_cmd, key);
        route_part(conn, cache_shard_of(key, m_shard_n), slot,
                   static_cast<uint32_t>(i), raw, true);
    }
    return true;
}

// The same command to every shard, merged, with the local part executed in
// place, so a four-shard `dbsize` is three crossings that a pipeline shares.
bool cache_instance::answer_from_table(client_connection* conn, uint32_t h, bool bare, bool resp)
{
    const auto& tbl = shard_stats_table();
    if (!bare || !tbl.mapped() || tbl.count() != m_shard_n)
        return false;
    uint64_t v = 0;
    switch (h)
    {
        case fnv1a("dbsize"): case fnv1a("size"):
            for (uint32_t sh = 0; sh < m_shard_n; ++sh)
                v += sh == m_shard_i ? m_store.size() : tbl.word_at(sh, 0);
            break;
        case fnv1a("memory"):
            for (uint32_t sh = 0; sh < m_shard_n; ++sh)
                v += sh == m_shard_i ? m_store.get_memory_used() : tbl.word_at(sh, 1);
            break;
        case fnv1a("maxmemory"):
            v = get_max_memory();
            break;
        default:
            return false;
    }
    run_in_reply_order(conn, [&] {
        if (resp)
            resp::encode_integer_into(conn->response_buf, v);
        else
            append_int_nl(conn->response_buf, static_cast<int64_t>(v));
    });
    return true;
}

void cache_instance::publish_keyspace()
{
    if (m_shard_n <= 1)
        return;
    const uint64_t keys = m_store.size(), memory = m_store.get_memory_used();
    if (keys == m_pub_keys && memory == m_pub_memory)
        return;
    m_pub_keys   = keys;
    m_pub_memory = memory;
    shard_stats_table().publish_words(keys, memory);
}

void cache_instance::fan_all_shards(client_connection* conn, uint32_t h,
                                    std::string_view raw, bool resp)
{
    const uint32_t slot = slot_open(conn, resp, cache_merge_for(h), m_shard_n);
    for (uint32_t sh = 0; sh < m_shard_n; ++sh)
        route_part(conn, sh, slot, sh, raw, resp);
}

// The shards a publish has to reach: this one, and every sibling whose filter
// says it can hold a subscriber of the channel.  Measured with fifty channels
// over four shards, one subscriber each, that is 0.75 crossings per publish
// against 3, and a sibling with nobody on the channel is not woken for it.
void cache_instance::fan_publish(client_connection* conn, uint32_t h,
                                 std::string_view raw, bool resp,
                                 std::string_view channel)
{
    const auto& tbl = shard_stats_table();
    if (SOCKETLEY_UNLIKELY(!tbl.mapped() || tbl.count() != m_shard_n))
    {
        fan_all_shards(conn, h, raw, resp);
        return;
    }

    const uint32_t bit = shard_stats::channel_bit(channel);
    uint32_t targets[max_shards];
    uint32_t n = 0;
    for (uint32_t sh = 0; sh < m_shard_n; ++sh)
        // A shard holding a pattern subscriber cannot be filtered out: the
        // pattern matches channels that do not exist yet, so it has no bit of
        // its own to look up.  This is the whole cost of the feature, and it
        // is paid only by a cache that actually has one.
        if (sh == m_shard_i || tbl.channel_may_have(sh, bit)
            || tbl.channel_may_have(sh, shard_stats::pattern_bit))
            targets[n++] = sh;

    const uint32_t slot = slot_open(conn, resp, cache_merge_for(h), n);
    for (uint32_t i = 0; i < n; ++i)
        route_part(conn, targets[i], slot, i, raw, resp);
}

void cache_instance::on_channel_presence(void* ctx, std::string_view channel, bool present)
{
    static_cast<cache_instance*>(ctx)->channel_presence(channel, present);
}

// The same set/clear by BIT rather than by channel name, for the one bit that
// does not belong to a channel: patterns.  It goes through the same reference
// count so a shard with two pattern subscribers does not clear the bit when
// the first of them leaves.
void cache_instance::channel_presence_bit(uint32_t bit, bool present)
{
    auto& tbl = shard_stats_table();
    if (!tbl.writable())
        return;
    if (m_chan_buckets.empty())
        m_chan_buckets.assign(shard_stats::channel_bits, 0);

    uint32_t& n = m_chan_buckets[bit];
    if (present) { if (n++ == 0) tbl.channel_set(bit); }
    else if (n > 0 && --n == 0) tbl.channel_clear(bit);
}

void cache_instance::channel_presence(std::string_view channel, bool present)
{
    auto& tbl = shard_stats_table();
    if (!tbl.writable())
        return;
    if (m_chan_buckets.empty())
        m_chan_buckets.assign(shard_stats::channel_bits, 0);

    const uint32_t bit = shard_stats::channel_bit(channel);
    uint32_t&      n   = m_chan_buckets[bit];
    if (present)
    {
        if (n++ == 0)
            tbl.channel_set(bit);
    }
    else if (n > 0 && --n == 0)
        tbl.channel_clear(bit);
}

// The one place the text interpreter asks who owns a key, because an invariant
// sixty-odd handlers have to remember is one the next handler will not know
// about.
void cache_instance::process_command(client_connection* conn, std::string_view line)
{
    if (SOCKETLEY_LIKELY(m_shard_n <= 1))
    {
        process_command_local(conn, line);
        return;
    }
    if (conn->fd >= 0 && !conn->cluster_port)
        ++m_stat_shared_cmds;

    const cache_text_parts parts = cache_split_text(line);
    const uint32_t         h     = fnv1a_lower(parts.cmd);

    // A client on the per-shard port is asking this node, so DBSIZE, KEYS,
    // SCAN and FLUSH answer for it alone, while a publish still fans out and a
    // single-key command is handled by -MOVED.
    if (SOCKETLEY_UNLIKELY(conn->cluster_port))
    {
        const cache_cmd_class cc = cache_classify_text(h);
        if (cc == cache_cmd_class::keyspace || cc == cache_cmd_class::cursor_scan)
        {
            run_in_reply_order(conn, [&] { process_command_local(conn, line); });
            return;
        }
    }

    // A transaction is queued and replayed by this shard alone, so inside one -- and in the WATCH that guards it -- a
    // command naming another shard's key is refused and the transaction with it, as the RESP router refuses it:
    // routed, it ran at once outside the transaction, and a WATCH on it never heard of the owner's writes.
    {
        const bool txn_verb = h == fnv1a("multi") || h == fnv1a("exec") || h == fnv1a("discard") ||
                              h == fnv1a("unwatch") || h == fnv1a("reset") || h == fnv1a("quit");
        if (SOCKETLEY_UNLIKELY((conn->in_multi && !txn_verb) || h == fnv1a("watch")))
        {
            std::vector<std::string_view> words{ parts.cmd };
            for (std::string_view rest = parts.args; !rest.empty();)
            {
                const size_t sp = rest.find(' ');
                if (sp != 0) words.push_back(rest.substr(0, sp));
                if (sp == std::string_view::npos) break;
                rest.remove_prefix(sp + 1);
            }
            const int argc = static_cast<int>(words.size());
            const int away = h == fnv1a("watch") ? first_foreign_key(words.data(), 1, argc - 1, 1)
                                                 : resp_first_foreign_key(h, words.data(), argc);
            if (away != -1)
            {
                if (conn->in_multi)
                    conn->multi_broken = true;
                run_in_reply_order(conn, [&] {
                    if (conn->cluster_port && away >= 0)
                        emit_moved(conn, words[static_cast<size_t>(away)],
                                   cache_shard_of(words[static_cast<size_t>(away)], m_shard_n), false);
                    else
                        conn->response_buf.append("error: CROSSSLOT a transaction on a sharded cache may only name "
                                                  "keys of the shard it runs on\n");
                });
                return;
            }
            run_in_reply_order(conn, [&] { process_command_local(conn, line); });
            return;
        }
    }

    // ─── EVERY KEY ON ONE SHARD, FOR THE COMMANDS THAT NAME SEVERAL ─────────
    // RENAME, COPY, SMOVE and the set algebra read or write more than one key
    // and cannot be split across shards.  The RESP path has routed them since
    // route_all_keys_one_shard(); this one never did, because cache_classify()
    // does not name them and an unnamed command reads `unknown` -- which is
    // served here, out of this shard's slice.
    //
    // Measured on two shards with --cluster, `rename k2 k1` sent as text to
    // the shard that owns k2 while k1 belongs to the other:
    //
    //     the command answered            ok
    //     the owning shard, get k1        (nothing)
    //     this shard, get k1              MOVED ... :26602
    //
    // The value was written into this shard under a name every router sends
    // somewhere else, so it was reachable from no port at all -- and the client
    // was told the rename had happened.
    if (SOCKETLEY_UNLIKELY(m_shard_n > 1 && cache_needs_one_shard(h)))
    {
        // SMOVE's third argument is a member and not a key; every other verb
        // in the set names keys all the way down, destination included.
        const int key_cap = (h == fnv1a("smove")) ? 2 : 0;   // 0 = to the end

        // One token, and what is left after it: the same split the
        // interpreter below performs, written here because its own helper is a
        // lambda inside another function.
        const auto peel = [](std::string_view a)
            -> std::pair<std::string_view, std::string_view> {
            while (!a.empty() && a.front() == ' ') a.remove_prefix(1);
            const size_t sp = a.find(' ');
            if (sp == std::string_view::npos) return { a, {} };
            return { a.substr(0, sp), a.substr(sp + 1) };
        };

        std::string_view rest = parts.args, first;
        uint32_t owner = 0; int seen = 0; bool split = false;
        while (!rest.empty() && (key_cap == 0 || seen < key_cap))
        {
            auto [k, r] = peel(rest);
            rest = r;
            if (k.empty()) break;
            const uint32_t o = cache_shard_of(k, m_shard_n);
            if (seen == 0) { owner = o; first = k; }
            else if (o != owner) { split = true; break; }
            ++seen;
        }

        if (split)
        {
            run_in_reply_order(conn, [&] {
                emit_unrouted(conn, parts.cmd, false,
                              "names keys that do not all belong to one shard, "
                              "and it cannot be split across them");
            });
            return;
        }
        if (seen > 0 && owner != m_shard_i)
        {
            // Same two answers the single-key case gives, for the same
            // reasons: correct the map on a per-shard port, cross otherwise.
            if (conn->cluster_port)
            {
                run_in_reply_order(conn, [&] { emit_moved(conn, first, owner, false); });
                return;
            }
            if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, parts.cmd, false,
                                  "names keys another shard owns, and this path "
                                  "cannot wait for it");
                });
                return;
            }
            const uint32_t slot = slot_open(conn, false, cache_merge::single, 1);
            route_part(conn, owner, slot, 0, line, false);
            return;
        }
        // Every key here: the interpreter below is the right one.
    }

    // XREAD's streams, which the line names after STREAMS: one shard's or
    // refused, and a blocking one only at home -- the RESP router's rule.
    if (SOCKETLEY_UNLIKELY(h == fnv1a("xread") || h == fnv1a("xreadgroup")))
    {
        std::vector<std::string_view> words{ parts.cmd };
        for (std::string_view rest = parts.args; !rest.empty();)
        {
            const size_t sp = rest.find(' ');
            if (sp != 0) words.push_back(rest.substr(0, sp));
            if (sp == std::string_view::npos) break;
            rest.remove_prefix(sp + 1);
        }
        const stream_read_keys k = find_stream_read_keys(words.data(), static_cast<int>(words.size()));
        const int away = k.count > 0 ? first_foreign_key(words.data(), k.first, k.count, 1) : -1;
        if (away >= 0)
        {
            const uint32_t owner = cache_shard_of(words[static_cast<size_t>(away)], m_shard_n);
            const bool one = std::all_of(words.begin() + k.first, words.begin() + k.first + k.count,
                [&](std::string_view w) { return cache_shard_of(w, m_shard_n) == owner; });
            if (conn->cluster_port)
            {
                run_in_reply_order(conn, [&] { emit_moved(conn, words[static_cast<size_t>(away)], owner, false); });
                return;
            }
            if (!one || k.blocks || SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, parts.cmd, false,
                                  "names streams another shard owns, and a read of several "
                                  "shards or one that blocks cannot cross to them");
                });
                return;
            }
            const uint32_t slot = slot_open(conn, false, cache_merge::single, 1);
            route_part(conn, owner, slot, 0, line, false);
            return;
        }
    }

    switch (cache_classify_text(h))
    {
        case cache_cmd_class::single_key:
        {
            const std::string_view key = cache_text_key(h, parts.args);
            // No key at all is a usage error, and "usage" is the same answer in
            // every process — so it is answered here rather than crossing.
            if (!key.empty())
            {
                const uint32_t owner = cache_shard_of(key, m_shard_n);
                note_key_owner(conn, owner);
                if (owner != m_shard_i)
                {
                    // This client read the slot map and chose this shard, so a
                    // key that is not ours is a routing mistake and -MOVED is
                    // the only answer that fixes it -- crossing instead leaves
                    // the client making it forever, at 11.56 us against 8.01.
                    if (conn->cluster_port)
                    {
                        run_in_reply_order(conn, [&] {
                            emit_moved(conn, key, owner, false);
                        });
                        return;
                    }
                    // A crossing needs somebody to keep waiting, which the
                    // scratch connection has only while a ticket is parked on
                    // it, so anything else is refused by name rather than
                    // served out of this shard's slice.
                    if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
                    {
                        run_in_reply_order(conn, [&] {
                            emit_unrouted(conn, parts.cmd, false,
                                          "names a key another shard owns, and "
                                          "this path cannot wait for it");
                        });
                        return;
                    }
                    const uint32_t slot =
                        slot_open(conn, false, cache_merge::single, 1);
                    route_part(conn, owner, slot, 0, line, false);
                    return;
                }
            }
            break;
        }

        case cache_cmd_class::multi_key:
        {
            // The crossing gate lives in explode_text_multi, after the keys are known to be foreign.
            if (explode_text_multi(conn, h, parts.args))
                return;
            // Could not be split: a usage error or past the ceiling, and the
            // interpreter's own answer to it is the right one.
            break;
        }

        case cache_cmd_class::keyspace:
        {
            if (answer_from_table(conn, h, parts.args.empty(), false))
                return;
            if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, parts.cmd, false,
                                  "reads every shard's slice, and this path "
                                  "cannot wait for them");
                });
                return;
            }
            fan_all_shards(conn, h, line, false);
            return;
        }

        case cache_cmd_class::cursor_scan:
        {
            // The cursor names the shard, so there is one crossing per call
            // and the owning shard re-packs the cursor it hands back.
            const uint32_t owner = scan_cursor_owner(parts.args);
            if (owner == m_shard_i)
                break;
            if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, parts.cmd, false,
                                  "resumes in another shard, and this path "
                                  "cannot wait for it");
                });
                return;
            }
            const uint32_t slot = slot_open(conn, false, cache_merge::single, 1);
            route_part(conn, owner, slot, 0, line, false);
            return;
        }

        case cache_cmd_class::stateful:
            run_in_reply_order(conn, [&] {
                emit_unrouted(conn, parts.cmd, false,
                              "attaches a stream to one shard, which would "
                              "carry a fraction of this cache's writes");
            });
            return;

        case cache_cmd_class::fanout:
        {
            // Every shard holds its own subscribers, so a publish that stops
            // here reaches a fraction of them and returns a count describing
            // that fraction — with nothing saying so.
            if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, parts.cmd, false,
                                  "has to reach every shard's subscribers, and "
                                  "this path cannot wait for them");
                });
                return;
            }
            // The channel is the first word of the arguments; without one the
            // interpreter's usage answer is the right one, from every shard.
            const size_t sp = parts.args.find(' ');
            if (sp == std::string_view::npos)
                fan_all_shards(conn, h, line, false);
            else
                fan_publish(conn, h, line, false, parts.args.substr(0, sp));
            return;
        }

        case cache_cmd_class::connection:
        case cache_cmd_class::unknown:
            break;      // answered by whoever holds the socket
    }

    run_in_reply_order(conn, [&] { process_command_local(conn, line); });
}

void cache_instance::process_command_local(client_connection* conn, std::string_view line)
{
    if (SOCKETLEY_UNLIKELY(line.empty()))
        return;

    // A fenced replica answers no client at all, reads included, since a partitioned one is the stale copy.
    if (SOCKETLEY_UNLIKELY(m_fenced) && conn->fd >= 0)
    {
        refuse_fenced(conn, false);
        return;
    }

    // Global rate limit check (across all connections)
    if (SOCKETLEY_UNLIKELY(!check_global_rate_limit()))
    {
        conn->response_buf.append("error: rate limited\n", 20);
        return;
    }

    // Rate limit check (usually disabled)
    if (SOCKETLEY_UNLIKELY(conn->rl_max > 0))
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
    stat_add(m_stat_total_messages, 1);

    size_t first_space = line.find(' ');
    std::string_view cmd = (first_space != std::string_view::npos)
        ? line.substr(0, first_space) : line;

    std::string_view args = (first_space != std::string_view::npos)
        ? line.substr(first_space + 1) : std::string_view{};

    auto& rb = conn->response_buf;

    // The RESP interpreter's answered_expire, in this protocol's words.  The
    // two protocols differ on what EXPIRE answers -- "ok"/"nil" here against
    // 1/0 there -- and that difference is the man page's, so it is kept.  What
    // is NOT kept is answering success for a key that was never there.
    const auto answered_expire = [&](cache_store::expire_result r,
                                     std::string_view yes, std::string_view no) {
        if (r == cache_store::expire_result::no_such_key)
        { rb.append(no.data(), no.size()); return; }
        if (r == cache_store::expire_result::armed) mark_ttl_keys();
        rb.append(yes.data(), yes.size());
        replicate_command(line);
    };

    // The RESP interpreter's answered_incr, in this protocol's words: the
    // store's three answers are the same three here, and the guard that
    // refuses them lives in the store precisely so both doors say so.  Sized
    // from the literals, because a hand count one short eats the newline and
    // runs the next reply into the back of this one.
    //
    // Every caller names the store call on its own line first.  Folded into
    // the argument list it read `result` before incr() had written it --
    // argument order is unspecified, gcc chose right-to-left, and every
    // SUCCESSFUL increment answered 0.
    const auto answered_incr = [&rb](cache_store::incr_result st, int64_t result) {
        if (st == cache_store::incr_result::ok) { append_int_nl(rb, result); return true; }
        static constexpr std::string_view overflowed = "error: increment or decrement would overflow\n";
        static constexpr std::string_view not_int    = "error: not an integer\n";
        static constexpr std::string_view conflict   = "error: type conflict\n";
        static constexpr std::string_view no_room    = "error: out of memory\n";
        const std::string_view msg =
            st == cache_store::incr_result::would_overflow ? overflowed
          : st == cache_store::incr_result::wrong_type     ? conflict
          : st == cache_store::incr_result::out_of_memory  ? no_room
                                                           : not_int;
        rb.append(msg.data(), msg.size());
        return false;
    };

    // ── MULTI ───────────────────────────────────────────────────────────────
    // Ahead of the dispatch, because between MULTI and EXEC a command is not
    // run at all: it is text on a queue.  EXEC then re-enters this function
    // once per queued line with the flag down, which is why the queue is moved
    // out first -- a nested EXEC would otherwise walk a container it is
    // appending to.
    {
        const uint32_t mh = fnv1a_lower(cmd);
        if (mh == fnv1a("multi"))
        {
            if (conn->in_multi) { rb.append("error: MULTI nested\n", 20); return; }
            conn->in_multi     = true;
            conn->multi_broken = false;
            conn->multi_queue.clear();
            conn->multi_bytes  = 0;
            rb.append("ok\n", 3);
            return;
        }
        if (mh == fnv1a("watch"))
        {
            if (conn->in_multi) { rb.append("error: WATCH inside MULTI\n", 26); return; }
            // Split here rather than through extract_key(), which is defined
            // further down this file than the transaction verbs are handled.
            std::vector<std::string_view> ws;
            ws.push_back(cmd);
            std::string_view walk = args;
            while (!walk.empty())
            {
                const size_t sp = walk.find(' ');
                const std::string_view w = (sp == std::string_view::npos)
                                         ? walk : walk.substr(0, sp);
                if (!w.empty()) ws.push_back(w);
                if (sp == std::string_view::npos) break;
                walk = walk.substr(sp + 1);
            }
            if (ws.size() < 2) { rb.append("usage: watch key [key ...]\n", 27); return; }
            watch_keys(conn, ws.data(), static_cast<int>(ws.size()));
            rb.append("ok\n", 3);
            return;
        }
        if (mh == fnv1a("unwatch"))
        {
            unwatch_all(conn);
            rb.append("ok\n", 3);
            return;
        }
        if (mh == fnv1a("discard"))
        {
            if (!conn->in_multi) { rb.append("error: DISCARD without MULTI\n", 29); return; }
            conn->in_multi     = false;
            conn->multi_broken = false;
            conn->multi_queue.clear();
            conn->multi_bytes  = 0;
            unwatch_all(conn);
            rb.append("ok\n", 3);
            return;
        }
        // RESET and QUIT run even inside MULTI, where everything else is
        // queued.  RESET queued is RESET not happening: a pooling client sends
        // it precisely because it does not know what state a connection is in,
        // and if a stray MULTI is that state then the one command meant to
        // clear it would be filed behind the mess.  redis-server answers
        // +RESET at once and then "EXEC without MULTI" -- the transaction is
        // gone, not queued.  Both protocols, because both have the queue.
        if (conn->in_multi && mh != fnv1a("exec")
                           && mh != fnv1a("reset") && mh != fnv1a("quit"))
        {
            // A cap, because a client that never sends EXEC would otherwise
            // park as much memory on this connection as it can type.
            if (conn->multi_queue.size() >= client_connection::MULTI_MAX_CMDS
                || conn->multi_bytes + line.size() > client_connection::MULTI_MAX_BYTES)
            {
                conn->multi_broken = true;
                rb.append("error: transaction too large\n", 29);
                return;
            }
            conn->multi_queue.emplace_back(line);
            conn->multi_bytes += line.size();
            rb.append("queued\n", 7);
            return;
        }
        if (mh == fnv1a("exec"))
        {
            if (!conn->in_multi) { rb.append("error: EXEC without MULTI\n", 26); return; }
            std::vector<std::string> queued;
            queued.swap(conn->multi_queue);
            const bool broken = conn->multi_broken;
            const bool wdirty = conn->watch_dirty;
            conn->in_multi     = false;
            conn->multi_broken = false;
            conn->multi_bytes  = 0;
            unwatch_all(conn);
            if (wdirty)
            {
                // Its own word rather than RESP's nil array, because this
                // protocol has no types to tell "did not run" from "ran and
                // returned nothing".
                rb.append("aborted\n", 8);
                return;
            }
            if (broken)
            {
                // Nothing ran, because running part of what was asked is worse
                // than running none of it.
                rb.append("error: transaction discarded\n", 29);
                return;
            }
            conn->in_exec = true;
            for (const auto& q : queued)
                process_command_local(conn, q);
            conn->in_exec = false;
            rb.append("end\n", 4);
            return;
        }
    }

    // Extract key from args (up to first space)
    auto extract_key = [](std::string_view a) -> std::pair<std::string_view, std::string_view> {
        size_t sp = a.find(' ');
        if (sp == std::string_view::npos)
            return {a, {}};
        return {a.substr(0, sp), a.substr(sp + 1)};
    };

    // A command added here must be classified in cache_shard_map.h, because an
    // unnamed hash reads `unknown` and is served where it was asked -- right
    // for a command that does not exist and wrong for a real one.
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
            auto value = args.substr(space + 1);
            if (!m_store.set(key, value))
            {
                m_store.check_expiry(key);
                if (!m_store.set(key, value))
                {
                    // set() refuses for two unrelated reasons; the key's own
                    // type says which, so the client stops being told a memory
                    // refusal was a type conflict.
                    auto t = m_store.type(key);
                    if (t == "none" || t == "string")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    break;
                }
            }
            rb.append("ok\n", 3);
            replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(key, value, 0);
                    lua_diag::raised(r, get_name(), "on_write");
                }
            }
#endif
            break;
        }
        case fnv1a("get"):
        {
            // Combined check_expiry + get_ptr — one hash probe instead of two
            const std::string* val = m_store.check_expiry_and_get_ptr(args);
            if (val)
            {
                m_stat_get_hits++;
                rb.append(*val);
                rb.push_back('\n');
            }
            else
            {
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_miss())
                {
                    // Checked before the result is read, because on a failed
                    // call index 0 is the error object and reading it would
                    // store a Lua error message in the cache as the fetched
                    // value.
                    sol::protected_function_result res = lua()->on_miss()(args);
                    if (!lua_diag::raised(res, get_name(), "on_miss"))
                    {
                        sol::optional<std::string> fetched = res.get<sol::optional<std::string>>(0);
                        if (fetched && !fetched->empty())
                        {
                            int ttl = 0;
                            sol::optional<int> ttl_opt = res.get<sol::optional<int>>(1);
                            if (ttl_opt) ttl = *ttl_opt;
                            m_store.set(args, *fetched);
                            if (ttl > 0) { m_store.set_expiry(args, ttl); mark_ttl_keys(); }
                            m_stat_get_hits++;
                            rb.append(*fetched);
                            rb.push_back('\n');
                            break;
                        }
                    }
                }
#endif
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
            // Unlike set/lpush/sadd, del() happily removes an already-expired
            // key and reports success, so the expiry check has to happen up
            // front.
            if (m_has_ttl_keys) m_store.check_expiry(args);
            if (m_store.del(args))
            {
                rb.append("ok\n", 3);
                replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_delete())
                {
                    {
                        sol::protected_function_result r = lua()->on_delete_cb()(args);
                        lua_diag::raised(r, get_name(), "on_delete");
                    }
                }
#endif
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("exists"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            rb.append(m_store.exists(args) ? "1\n" : "0\n");
            break;
        }
        case fnv1a("incr"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            if (args.empty()) { rb.append("usage: incr key\n"); return; }
            int64_t result = 0;
            const auto st = m_store.incr(args, 1, result);
            if (answered_incr(st, result))
                replicate_command(line);
            break;
        }
        case fnv1a("decr"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            if (args.empty()) { rb.append("usage: decr key\n"); return; }
            int64_t result = 0;
            const auto st = m_store.incr(args, -1, result);
            if (answered_incr(st, result))
                replicate_command(line);
            break;
        }
        case fnv1a("incrby"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, delta_str] = extract_key(args);
            if (key.empty() || delta_str.empty()) { rb.append("usage: incrby key delta\n", 24); return; }
            int64_t delta = 0;
            if (!parse_int_sv(delta_str, delta)) { rb.append("error: invalid delta\n", 21); return; }
            int64_t result = 0;
            const auto st = m_store.incr(key, delta, result);
            if (answered_incr(st, result))
                replicate_command(line);
            break;
        }
        case fnv1a("decrby"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, delta_str] = extract_key(args);
            if (key.empty() || delta_str.empty()) { rb.append("usage: decrby key delta\n", 24); return; }
            int64_t delta = 0;
            if (!parse_int_sv(delta_str, delta)) { rb.append("error: invalid delta\n", 21); return; }
            // See the RESP twin: INT64_MIN has no negation, so `-delta` is
            // undefined before the store is reached at all.
            if (SOCKETLEY_UNLIKELY(delta == std::numeric_limits<int64_t>::min()))
            {
                static constexpr std::string_view msg = "error: decrement would overflow\n";
                rb.append(msg.data(), msg.size());
                return;
            }
            int64_t result = 0;
            const auto st = m_store.incr(key, -delta, result);
            if (answered_incr(st, result))
                replicate_command(line);
            break;
        }
        case fnv1a("append"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, suffix] = extract_key(args);
            if (key.empty() || suffix.empty()) { rb.append("usage: append key value\n", 24); return; }
            size_t newlen = m_store.append(key, suffix);
            if (newlen == cache_store::append_wrong_type)
                rb.append("error: type conflict\n", 21);
            else if (newlen == cache_store::append_denied)
                rb.append("error: out of memory\n", 21);
            else
            {
                append_int_nl(rb, static_cast<int64_t>(newlen));
                replicate_command(line);
            }
            break;
        }
        case fnv1a("strlen"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, static_cast<int64_t>(m_store.strlen_key(args)));
            break;
        }
        case fnv1a("getset"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, newval] = extract_key(args);
            if (key.empty() || newval.empty()) { rb.append("usage: getset key newvalue\n", 27); return; }
            // getset() overwrites unconditionally, so an expired key would be
            // reported as present and its stale value returned as the old one.
            if (m_has_ttl_keys) m_store.check_expiry(key);
            bool had_key = m_store.exists(key);
            std::string oldval;
            if (!m_store.getset(key, newval, oldval))
            {
                const auto t = m_store.type(key);
                if (t == "none" || t == "string")
                    rb.append("error: out of memory\n", 21);
                else
                    rb.append("error: type conflict\n", 21);
            }
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
                if (m_has_ttl_keys) m_store.check_expiry(key);
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
            // A key without its value is refused whole, rather than the pairs before it set and it dropped.
            {
                size_t words = args.empty() ? 0 : 1;
                for (const char c : args)
                    words += c == ' ';
                if (words == 0 || words % 2 != 0)
                {
                    rb.append("usage: mset key value [key value ...]\n");
                    return;
                }
            }
            // Pairs go in order up to the first the store refuses, and only those reach a follower.
            std::string_view rest = args;
            std::string_view applied_end = args.substr(0, 0);
            bool refused = false;
            while (!rest.empty())
            {
                size_t sp1 = rest.find(' ');
                if (sp1 == std::string_view::npos) break;
                std::string_view key = rest.substr(0, sp1);
                rest = rest.substr(sp1 + 1);
                size_t sp2 = rest.find(' ');
                std::string_view val = (sp2 == std::string_view::npos) ? rest : rest.substr(0, sp2);
                if (m_has_ttl_keys) m_store.check_expiry(key);
                if (!m_store.set(key, val))
                {
                    auto t = m_store.type(key);
                    if (t == "none" || t == "string")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    refused = true;
                    break;
                }
                applied_end = args.substr(0, static_cast<size_t>(val.data() + val.size() - args.data()));
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_write())
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(key, val, 0);
                        lua_diag::raised(r, get_name(), "on_write");
                    }
                }
#endif
                if (sp2 == std::string_view::npos) break;
                rest = rest.substr(sp2 + 1);
            }
            if (!refused) rb.append("ok\n", 3);
            // One key per replicated command, because `mset a 1 b 2` names
            // keys belonging to different shards and a sharded follower
            // dropped it whole -- so the effect is replicated instead, as SET
            // already does.
            {
                std::string_view r = applied_end;
                while (!r.empty())
                {
                    const size_t s1 = r.find(' ');
                    if (s1 == std::string_view::npos) break;
                    const std::string_view k = r.substr(0, s1);
                    r = r.substr(s1 + 1);
                    const size_t s2 = r.find(' ');
                    const std::string_view v =
                        (s2 == std::string_view::npos) ? r : r.substr(0, s2);
                    std::string one;
                    one.reserve(5 + k.size() + v.size());
                    one += "set ";
                    one.append(k);
                    one += ' ';
                    one.append(v);
                    replicate_command(one);
                    if (s2 == std::string_view::npos) break;
                    r = r.substr(s2 + 1);
                }
            }
            break;
        }
        case fnv1a("type"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
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
            if (!m_store.lpush(key, val))
            {
                auto t = m_store.type(key);
                if (t == "none" || t == "list")
                    rb.append("error: out of memory\n", 21);
                else
                    rb.append("error: type conflict\n", 21);
                break;
            }
            rb.append("ok\n", 3);
            replicate_command(line);
            // A client blocked on the key over RESP is waiting for exactly this element.
            while (wake_one_waiter(key)) {}
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
            if (!m_store.rpush(key, val))
            {
                auto t = m_store.type(key);
                if (t == "none" || t == "list")
                    rb.append("error: out of memory\n", 21);
                else
                    rb.append("error: type conflict\n", 21);
                break;
            }
            rb.append("ok\n", 3);
            replicate_command(line);
            // A client blocked on the key over RESP is waiting for exactly this element.
            while (wake_one_waiter(key)) {}
            break;
        }
        case fnv1a("lpop"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(args);
            if (m_store.pop_with(args, true, [&](std::string_view v) { rb.append(v); rb.push_back('\n'); }))
                replicate_command(line);   // was not replicated at all
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
            if (m_has_ttl_keys) m_store.check_expiry(args);
            if (m_store.pop_with(args, false, [&](std::string_view v) { rb.append(v); rb.push_back('\n'); }))
                replicate_command(line);   // was not replicated at all
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("llen"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
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
            if (m_has_ttl_keys) m_store.check_expiry(key);
            int idx;
            if (!parse_int_sv(idx_str, idx))
            {
                rb.append("error: invalid index\n", 21);
                return;
            }
            const auto val = m_store.lindex(key, idx);
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
            if (m_has_ttl_keys) m_store.check_expiry(key);
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
            // One walk from start rather than an index per element, which in
            // a packed list is a walk each.
            if (start <= stop)
            {
                auto e = deq->iterator_at(static_cast<size_t>(start));
                for (int i = start; i <= stop; i++, ++e)
                {
                    rb.append(*e);
                    rb.push_back('\n');
                }
            }
            rb.append("end\n", 4);
            break;
        }

        // ─── Sets ───

        // ─── Sorted sets ────────────────────────────────────────────────
        // A score is a double parsed whole, like every number here: `zadd k 1x m`
        // is refused rather than taken as 1.
        case fnv1a("zadd"):
        {
            if (m_mode == cache_mode_readonly)
            { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, rest] = extract_key(args);
            auto [score_str, member] = extract_key(rest);
            if (key.empty() || score_str.empty() || member.empty())
            { rb.append("usage: zadd key score member\n", 29); return; }
            double score = 0.0;
            if (!parse_double_sv(score_str, score))
            { rb.append("error: invalid score\n", 21); return; }
            // zadd checks expiry itself, and its answer distinguishes the two
            // meanings a bare false used to carry -- so neither the second
            // probe nor type()'s five are owed here.
            const int added = m_store.zadd(key, score, member);
            if (added < 0)
            { rb.append("error: type conflict\n", 21); return; }
            rb.append(added ? "1\n" : "0\n", 2);
            replicate_command(line);
            break;
        }
        case fnv1a("zrem"):
        {
            if (m_mode == cache_mode_readonly)
            { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            { rb.append("usage: zrem key member\n", 23); return; }
            m_store.check_expiry(key);
            if (m_store.zrem(key, member))
            { rb.append("ok\n", 3); replicate_command(line); }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("zscore"):
        {
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            { rb.append("usage: zscore key member\n", 25); return; }
            m_store.check_expiry(key);
            double sc = 0.0;
            if (!m_store.zscore(key, member, sc)) { rb.append("nil\n", 4); break; }
            append_score(rb, sc);
            break;
        }
        case fnv1a("zcard"):
        {
            auto [key, zextra] = extract_key(args);
            (void)zextra;
            if (key.empty()) { rb.append("usage: zcard key\n", 17); return; }
            m_store.check_expiry(key);
            rb.append(std::to_string(m_store.zcard(key))).append("\n", 1);
            break;
        }
        case fnv1a("zrank"):
        case fnv1a("zrevrank"):
        {
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            { rb.append("usage: zrank key member\n", 24); return; }
            m_store.check_expiry(key);
            size_t rank = 0;
            if (!m_store.zrank(key, member, rank,
                               fnv1a_lower(cmd) == fnv1a("zrevrank")))
            { rb.append("nil\n", 4); break; }
            rb.append(std::to_string(rank)).append("\n", 1);
            break;
        }
        case fnv1a("zrange"):
        case fnv1a("zrevrange"):
        {
            auto [key, zrest]      = extract_key(args);
            auto [start_s, zrest2] = extract_key(zrest);
            auto [stop_s, ztail]   = extract_key(zrest2);
            if (key.empty() || start_s.empty() || stop_s.empty())
            { rb.append("usage: zrange key start stop [withscores]\n", 42); return; }
            int64_t zstart = 0, zstop = 0;
            if (!parse_int_sv(start_s, zstart) || !parse_int_sv(stop_s, zstop))
            { rb.append("error: invalid index\n", 21); return; }
            const bool with = !ztail.empty()
                            && fnv1a_lower(ztail) == fnv1a("withscores");
            m_store.check_expiry(key);
            std::vector<std::pair<std::string_view, double>> zitems;
            m_store.zrange(key, zstart, zstop, zitems,
                           fnv1a_lower(cmd) == fnv1a("zrevrange"));
            for (const auto& [zm, zsc] : zitems)
            {
                rb.append(zm.data(), zm.size());
                if (with) { rb.append(" ", 1); append_score_bare(rb, zsc); }
                rb.append("\n", 1);
            }
            rb.append("end\n", 4);
            break;
        }
        case fnv1a("zincrby"):
        {
            if (m_mode == cache_mode_readonly)
            { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, zrest] = extract_key(args);
            auto [delta_str, member] = extract_key(zrest);
            if (key.empty() || delta_str.empty() || member.empty())
            { rb.append("usage: zincrby key delta member\n", 32); return; }
            double zdelta = 0.0;
            if (!parse_double_sv(delta_str, zdelta))
            { rb.append("error: invalid score\n", 21); return; }
            m_store.check_expiry(key);
            double zout = 0.0;
            switch (m_store.zincrby(key, zdelta, member, zout))
            {
                case cache_store::zincr_result::ok: break;
                case cache_store::zincr_result::not_a_number:
                    rb.append("error: resulting score is not a number (NaN)\n"); return;
                case cache_store::zincr_result::type_conflict:
                    rb.append("error: type conflict\n"); return;
            }
            append_score(rb, zout);
            replicate_command(line);
            break;
        }
        // Here as well as in RESP for the same reason as the set forms below:
        // replication ships a TEXT line, and a follower that cannot rename
        // keeps a key its leader no longer has.
        case fnv1a("rename"):
        case fnv1a("renamenx"):
        case fnv1a("copy"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            std::vector<std::string_view> ks;
            std::string_view walk = args;
            while (!walk.empty())
            {
                const size_t sp = walk.find(' ');
                const std::string_view w = (sp == std::string_view::npos) ? walk : walk.substr(0, sp);
                if (!w.empty()) ks.push_back(w);
                if (sp == std::string_view::npos) break;
                walk = walk.substr(sp + 1);
            }
            if (ks.size() < 2) { rb.append("usage: rename src dst\n", 22); return; }
            const uint32_t th = fnv1a_lower(cmd);
            int r;
            if (th == fnv1a("copy"))
            {
                bool replace = false;
                for (size_t i = 2; i < ks.size(); ++i)
                    if (fnv1a_lower(ks[i]) == fnv1a("replace")) replace = true;
                r = m_store.copy_key(ks[0], ks[1], replace);
            }
            else
                r = m_store.rename_key(ks[0], ks[1], th == fnv1a("renamenx"));
            if (r == -2)      rb.append("error: no such key\n", 19);
            else if (r == -3) rb.append("error: out of memory\n", 21);
            else if (r == 0)  rb.append("no\n", 3);
            else            { rb.append("ok\n", 3); replicate_command(line); }
            break;
        }
        case fnv1a("flushall"):
        case fnv1a("flushdb"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            m_store.flush_all();
            m_has_ttl_keys = false;
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("randomkey"):
        {
            const std::string_view k = m_store.random_key();
            if (k.empty()) rb.append("nil\n", 4);
            else { rb.append(k.data(), k.size()); rb.push_back('\n'); }
            break;
        }
        case fnv1a("expiretime"):
        case fnv1a("pexpiretime"):
        {
            auto [key, rest] = extract_key(args);
            (void)rest;
            if (key.empty()) key = args;
            if (key.empty()) { rb.append("usage: expiretime key\n", 22); return; }
            rb.append(std::to_string(
                m_store.expire_time(key, fnv1a_lower(cmd) == fnv1a("pexpiretime"))));
            rb.push_back('\n');
            break;
        }

        // Here as well as in RESP, because replication ships the command as a
        // TEXT line: a follower that cannot read `sinterstore d a b` holds a
        // destination the leader has and it does not.
        case fnv1a("sinter"):      case fnv1a("sunion"):      case fnv1a("sdiff"):
        case fnv1a("sinterstore"): case fnv1a("sunionstore"): case fnv1a("sdiffstore"):
        case fnv1a("smove"):
        {
            std::vector<std::string_view> ps;
            std::string_view walk = args;
            while (!walk.empty())
            {
                const size_t sp = walk.find(' ');
                const std::string_view w = (sp == std::string_view::npos) ? walk : walk.substr(0, sp);
                if (!w.empty()) ps.push_back(w);
                if (sp == std::string_view::npos) break;
                walk = walk.substr(sp + 1);
            }
            const uint32_t th = fnv1a_lower(cmd);
            if (th == fnv1a("smove"))
            {
                if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
                if (ps.size() != 3) { rb.append("usage: smove src dst member\n", 28); return; }
                const int r = m_store.smove(ps[0], ps[1], ps[2]);
                if (r < 0)      rb.append("error: type conflict\n", 21);
                else if (r == 0) rb.append("no\n", 3);
                else            { rb.append("ok\n", 3); replicate_command(line); }
                break;
            }
            const bool store = (th == fnv1a("sinterstore") || th == fnv1a("sunionstore")
                                                           || th == fnv1a("sdiffstore"));
            if (store && m_mode == cache_mode_readonly)
            { rb.append("denied: readonly mode\n", 22); return; }
            const size_t first = store ? 1u : 0u;
            if (ps.size() < first + 1)
            { rb.append("usage: sinter key [key ...]\n", 28); return; }

            std::vector<std::string> out;
            const size_t n = ps.size() - first;
            int rc;
            if (th == fnv1a("sinter") || th == fnv1a("sinterstore"))
                rc = m_store.sinter(ps.data() + first, n, out);
            else if (th == fnv1a("sunion") || th == fnv1a("sunionstore"))
                rc = m_store.sunion(ps.data() + first, n, out);
            else
                rc = m_store.sdiff(ps.data() + first, n, out);
            if (rc < 0) { rb.append("error: type conflict\n", 21); break; }

            if (!store)
            {
                for (const auto& m : out) { rb.append(m); rb.push_back('\n'); }
                rb.append("end\n", 4);
                break;
            }
            const size_t card = m_store.sreplace(ps[0], std::move(out));
            if (card == cache_store::sreplace_refused) { rb.append("error: out of memory\n", 21); break; }
            replicate_command(line);
            rb.append(std::to_string(card)); rb.push_back('\n');
            break;
        }
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
            int result = m_store.sadd(key, member);
            if (result < 0)
            {
                m_store.check_expiry(key);
                result = m_store.sadd(key, member);
            }
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
            if (m_has_ttl_keys) m_store.check_expiry(key);
            if (m_store.srem(key, member))
            {
                rb.append("ok\n", 3);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
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
            if (m_has_ttl_keys) m_store.check_expiry(key);
            rb.append(m_store.sismember(key, member) ? "1\n" : "0\n");
            break;
        }
        case fnv1a("scard"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, m_store.scard(args));
            break;
        }
        case fnv1a("smembers"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
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
            if (!m_store.hset(key, field, val))
            {
                m_store.check_expiry(key);
                if (!m_store.hset(key, field, val))
                {
                    // hset() refuses for two unrelated reasons now that
                    // overwriting a field is checked against maxmemory too; the
                    // key's own type says which, as it does for SET.
                    auto t = m_store.type(key);
                    if (t == "none" || t == "hash")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    break;
                }
            }
            rb.append("ok\n", 3);
            replicate_command(line);
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
            if (m_has_ttl_keys) m_store.check_expiry(key);
            const auto val = m_store.hget(key, field);
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
            if (m_has_ttl_keys) m_store.check_expiry(key);
            if (m_store.hdel(key, field))
            {
                rb.append("ok\n", 3);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("hlen"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, m_store.hlen(args));
            break;
        }
        case fnv1a("hgetall"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
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
            // Zero and negative are not refused: Redis deletes the key and
            // reports success, and a caller whose TTL arithmetic came out at
            // zero means "gone now", not "this call was a mistake".
            int64_t seconds = 0;
            if (!parse_int_sv(sec_str, seconds))
            {
                rb.append("error: invalid seconds\n", 23);
                return;
            }
            answered_expire(m_store.expire_in(key, seconds, false), "ok\n", "nil\n");
            break;
        }
        case fnv1a("ttl"):
        {
            const int64_t ms = m_store.expire_then_pttl(args);
            append_int_nl(rb, ms < 0 ? ms : (ms + 500) / 1000);
            break;
        }
        case fnv1a("persist"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            if (m_store.persist(args))
            {
                rb.append("ok\n", 3);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("setnx"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, val] = extract_key(args);
            if (key.empty() || val.empty()) { rb.append("usage: setnx key value\n", 23); return; }
            bool did_set = m_store.setnx(key, val);
            rb.append(did_set ? "1\n" : "0\n");
            if (did_set)
            {
                replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_write())
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(key, val, 0);
                        lua_diag::raised(r, get_name(), "on_write");
                    }
                }
#endif
            }
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
            if (!m_store.set(key, val))
            {
                m_store.check_expiry(key);
                if (!m_store.set(key, val))
                {
                    const auto t = m_store.type(key);
                    if (t == "none" || t == "string")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    return;
                }
            }
            m_store.set_expiry(key, sec);
            mark_ttl_keys();
            rb.append("ok\n", 3);
            replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(key, val, sec);
                    lua_diag::raised(r, get_name(), "on_write");
                }
            }
#endif
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
                if (!parse_int_sv(ms_str, ms) || ms <= 0) { rb.append("error: invalid milliseconds\n", 28); return; }
            }
            if (!m_store.set(key, val))
            {
                m_store.check_expiry(key);
                if (!m_store.set(key, val))
                {
                    const auto t = m_store.type(key);
                    if (t == "none" || t == "string")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    return;
                }
            }
            m_store.set_expiry_ms(key, ms);
            mark_ttl_keys();
            rb.append("ok\n", 3);
            replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(key, val, 0);
                    lua_diag::raised(r, get_name(), "on_write");
                }
            }
#endif
            break;
        }
        case fnv1a("pexpire"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ms_str] = extract_key(args);
            if (key.empty() || ms_str.empty()) { rb.append("usage: pexpire key ms\n", 22); return; }
            int64_t ms = 0;
            {
                if (!parse_int_sv(ms_str, ms)) { rb.append("error: invalid ms\n", 18); return; }
            }
            answered_expire(m_store.expire_in(key, ms, true), "1\n", "0\n");
            break;
        }
        case fnv1a("pttl"):
        {
            append_int_nl(rb, m_store.expire_then_pttl(args));
            break;
        }
        case fnv1a("expireat"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ts_str] = extract_key(args);
            if (key.empty() || ts_str.empty()) { rb.append("usage: expireat key unix_seconds\n", 33); return; }
            int64_t unix_s = 0;
            {
                if (!parse_int_sv(ts_str, unix_s)) { rb.append("error: invalid timestamp\n", 25); return; }
            }
            {
                const int64_t now_s = socketley::wall::now_sec();
                // Replicated verbatim, because the argument is an absolute
                // timestamp and the follower arrives at the same expiry
                // however long the line took.
                answered_expire(m_store.expire_in(key, saturating_until(unix_s, now_s), false),
                                "1\n", "0\n");
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
                if (!parse_int_sv(ts_str, unix_ms)) { rb.append("error: invalid timestamp\n", 25); return; }
            }
            {
                const int64_t now_ms = socketley::wall::now_ms();
                // Verbatim like expireat and, like it once was, this was not
                // replicated at all.
                answered_expire(m_store.expire_in(key, saturating_until(unix_ms, now_ms), true),
                                "1\n", "0\n");
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
                if (!parse_int_sv(cursor_str, scan_cursor)) { rb.append("error: invalid cursor\n", 22); return; }
            }
            std::string_view scan_pattern = "*";
            scan_preds sp;
            bool scan_count_given = false, scan_has_type = false, scan_with_values = false;
            int scan_type = -1;
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
                else if (fnv1a_lower(opt) == fnv1a("valuematch") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    const size_t k = sp.slot(false);
                    sp.value[k] = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    sp.has_value[k] = true;
                }
                else if (fnv1a_lower(opt) == fnv1a("withvalues"))
                    scan_with_values = true;
                else if (fnv1a_lower(opt) == fnv1a("field") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    const size_t k = sp.slot(true);
                    sp.field[k] = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    sp.has_field[k] = true;
                }
                // Two tokens, where every other option here takes one -- the
                // bounds a zset range already speaks, so there is one numeric
                // vocabulary on this port and not two.
                else if (fnv1a_lower(opt) == fnv1a("valuerange") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    std::string_view lo_s = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    sp2 = rest2.find(' ');
                    std::string_view hi_s = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    const size_t k = sp.slot(false);
                    if (lo_s.empty() || hi_s.empty()
                     || !parse_score_bound(lo_s, sp.range[k].lo, sp.range[k].lo_inclusive)
                     || !parse_score_bound(hi_s, sp.range[k].hi, sp.range[k].hi_inclusive))
                    { rb.append("error: min or max is not a float\n"); return; }
                    sp.has_range[k] = true;
                }
                else if (fnv1a_lower(opt) == fnv1a("type") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    std::string_view tn = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    scan_type = cache_store::scan_map_of_type(tn);
                    scan_has_type = true;
                }
                else if (fnv1a_lower(opt) == fnv1a("count") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    std::string_view cnt_str = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    size_t cnt = 10;
                    if (!parse_int_sv(cnt_str, cnt))
                    { rb.append("error: invalid count\n", 21); return; }
                    scan_count = cnt; scan_count_given = true;
                }
            }
            if (sp.too_many)
            { rb.append("error: too many field predicates\n"); return; }
            // Same default as the RESP door, for the same reason.
            if (sp.n != 0 && !scan_count_given)
                scan_count = 1000;
            const cache_store::scan_filter scan_filt = sp.build(
                scan_has_type ? scan_type : -1, scan_with_values);
            // Same requirement as the RESP door, for the same reason.
            const int scan_needs = scan_filt.wants_hashes() ? 3
                                 : (sp.n != 0 || scan_with_values) ? 0 : -1;
            if (sp.contradictory() ||
                (scan_has_type && (scan_type < 0 ||
                                   (scan_needs >= 0 && scan_type != scan_needs))))
            {
                rb.append("0\nend\n", 6);
                break;
            }
            std::vector<std::string_view> scan_keys;
            uint64_t next_cursor = 0;
            if (!shard_scan(scan_cursor, scan_pattern, scan_count, scan_keys, next_cursor,
                            conn->cluster_port, scan_filt))
            {
                rb.append("error: invalid cursor\n", 22);
                return;
            }
            append_int_nl(rb, static_cast<int64_t>(next_cursor));
            if (scan_with_values)
                // "key value" a line, which is how hscan already prints a pair.
                for (size_t i = 0; i + 1 < scan_keys.size(); i += 2)
                { rb.append(scan_keys[i]); rb.push_back(' ');
                  rb.append(scan_keys[i + 1]); rb.push_back('\n'); }
            else
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
            if (m_persistent_path.empty())
            {
                rb.append("failed: no persistent path set\n", 31);
                return;
            }
            // This shard's own slice into its own file, the same write
            // teardown makes, fanned out to every shard so `all_ok` says so
            // only when every shard managed it.
            snapshot_abort();
            const bool flushed = save_shard_dump();
            if (flushed)
                journal_after_snapshot(true);
            rb.append(flushed ? "ok\n" : "failed: flush failed\n");
            break;
        }
        case fnv1a("load"):
        {
            if (m_mode != cache_mode_admin)
            {
                rb.append("denied: admin mode required\n", 28);
                return;
            }
            if (m_persistent_path.empty())
            {
                rb.append("failed: no persistent path set\n", 31);
                return;
            }
            // The whole set judged as a set, so a gap or a contradiction
            // refuses rather than loading part of it, exactly as at start.
            snapshot_abort();
            const bool loaded = load_shard_set();
            // The journal's tail describes state the load just replaced, so a
            // fresh snapshot of what is now in memory supersedes it before it
            // is cut off.
            bool snapped = true;
            if (loaded && m_journal.is_open())
            {
                snapped = save_shard_dump();
                if (snapped)
                    journal_after_snapshot(true);
            }
            if (!loaded)        rb.append("failed: load failed\n");
            else if (!snapped)  rb.append("failed: snapshot after load failed\n");
            else                rb.append("ok\n", 3);
            break;
        }
        case fnv1a("size"):
        {
            // size [type t] -- the same option the RESP door's dbsize takes.
            size_t sp_t = args.find(' ');
            std::string_view opt_t = (sp_t == std::string_view::npos) ? args : args.substr(0, sp_t);
            if (!opt_t.empty() && fnv1a_lower(opt_t) == fnv1a("type") &&
                sp_t != std::string_view::npos)
            {
                std::string_view rest_t = args.substr(sp_t + 1);
                const size_t sp_n = rest_t.find(' ');
                const std::string_view tn =
                    (sp_n == std::string_view::npos) ? rest_t : rest_t.substr(0, sp_n);
                const int m = cache_store::scan_map_of_type(tn);
                append_int_nl(rb, m < 0 ? 0u : m_store.size_of_type(m));
                break;
            }
            append_int_nl(rb, m_store.size());
            break;
        }

        // Here as well as in RESP, because the text protocol is a session a
        // person types into and leaving it should not need a signal.
        case fnv1a("quit"):
        {
            rb.append("ok\n", 3);
            conn->quit_after_flush = true;
            break;
        }
        case fnv1a("reset"):
        {
            reset_connection_state(conn);
            rb.append("ok\n", 3);
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
        // The same map for the text protocol, which exists for the operator
        // holding an `nc` open and for the suite that tests it.
        case fnv1a("cluster"):
        {
            if (args.empty()) { rb.append("error: usage: cluster <slots|shards|nodes|info|myid|keyslot>\n"); break; }
            const auto [sub, rest] = extract_key(args);
            emit_cluster(conn, sub, rest, false);
            break;
        }
        case fnv1a("replicate"):
        {
            const auto [shard, rest] = extract_key(args);
            const auto [of, _more]   = extract_key(rest);
            handle_replicate_request(conn, shard, of);
            return;
        }
        // ─── Strings, the range and float spellings ───
        case fnv1a("getrange"):
        case fnv1a("substr"):
        {
            auto [key, r1]  = extract_key(args);
            auto [s_s, r2]  = extract_key(r1);
            auto [e_s, _r3] = extract_key(r2);
            if (key.empty() || s_s.empty() || e_s.empty())
            { rb.append("usage: getrange key start end\n", 30); return; }
            int64_t s = 0, e = 0;
            if (!parse_int_sv(s_s, s) || !parse_int_sv(e_s, e))
            { rb.append("error: invalid index\n", 21); return; }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            std::string out;
            if (!m_store.getrange(key, s, e, out)) { rb.append("nil\n", 4); return; }
            rb.append(out); rb.push_back('\n');
            break;
        }
        case fnv1a("setrange"):
        {
            auto [key, r1]  = extract_key(args);
            auto [off_s, v] = extract_key(r1);
            if (key.empty() || off_s.empty())
            { rb.append("usage: setrange key offset value\n", 33); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            int64_t off = 0;
            if (!parse_int_sv(off_s, off) || off < 0)
            { rb.append("error: invalid offset\n", 22); return; }
            const size_t n = m_store.setrange(key, static_cast<size_t>(off), v);
            if (n == cache_store::append_wrong_type) rb.append("error: type conflict\n", 21);
            else if (n == cache_store::append_too_long)
            {
                // Sized from the literal rather than counted by hand, because
                // the hand count was one short and ate the newline that keeps
                // this reply from running into the next one.
                static constexpr std::string_view too_long =
                    "error: string exceeds maximum allowed size\n";
                rb.append(too_long.data(), too_long.size());
            }
            else if (n == cache_store::append_denied) rb.append("error: out of memory\n", 21);
            else { rb.append(std::to_string(n)); rb.push_back('\n'); replicate_command(line); }
            break;
        }
        case fnv1a("incrbyfloat"):
        {
            auto [key, d_s] = extract_key(args);
            if (key.empty() || d_s.empty())
            { rb.append("usage: incrbyfloat key delta\n", 29); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            double d = 0, out = 0;
            if (!parse_double_sv(d_s, d)) { rb.append("error: not a float\n", 19); return; }
            if (!m_store.incrbyfloat(key, d, out)) { rb.append("error: not a float\n", 19); return; }
            const std::string txt = cache_float_text(out);
            rb.append(txt); rb.push_back('\n');
            // The result and not the command, for the reason the RESP spelling
            // gives: two builds may round the same addition differently.
            if (mutation_log_wanted())
            {
                std::string c = "set "; c.append(key.data(), key.size());
                c += ' '; c += txt;
                replicate_command(c);
            }
            break;
        }
        case fnv1a("getdel"):
        {
            auto [key, _r] = extract_key(args);
            if (key.empty()) { rb.append("usage: getdel key\n", 18); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            std::string val;
            if (!m_store.getdel(key, val)) { rb.append("nil\n", 4); return; }
            rb.append(val); rb.push_back('\n');
            if (mutation_log_wanted())
            { std::string c = "del "; c.append(key.data(), key.size()); replicate_command(c); }
            break;
        }

        // ─── Lists, the positional spellings ───
        case fnv1a("lset"):
        {
            auto [key, r1]  = extract_key(args);
            auto [idx_s, v] = extract_key(r1);
            if (key.empty() || idx_s.empty())
            { rb.append("usage: lset key index value\n", 28); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            int64_t idx = 0;
            if (!parse_int_sv(idx_s, idx)) { rb.append("error: invalid index\n", 21); return; }
            const int rc = m_store.lset(key, idx, v);
            if (rc == 0)       { rb.append("ok\n", 3); replicate_command(line); }
            else if (rc == -1) rb.append("nil\n", 4);
            else if (rc == -3) rb.append("error: out of memory\n", 21);
            else               rb.append("error: index out of range\n", 26);
            break;
        }
        case fnv1a("lrem"):
        {
            auto [key, r1]  = extract_key(args);
            auto [cnt_s, v] = extract_key(r1);
            if (key.empty() || cnt_s.empty())
            { rb.append("usage: lrem key count value\n", 28); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            int64_t cnt = 0;
            if (!parse_int_sv(cnt_s, cnt)) { rb.append("error: invalid count\n", 21); return; }
            const int gone = m_store.lrem(key, cnt, v);
            rb.append(std::to_string(gone)); rb.push_back('\n');
            if (gone > 0) replicate_command(line);
            break;
        }
        case fnv1a("ltrim"):
        {
            auto [key, r1]  = extract_key(args);
            auto [s_s, r2]  = extract_key(r1);
            auto [e_s, _r3] = extract_key(r2);
            if (key.empty() || s_s.empty() || e_s.empty())
            { rb.append("usage: ltrim key start stop\n", 28); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            int64_t s = 0, e = 0;
            if (!parse_int_sv(s_s, s) || !parse_int_sv(e_s, e))
            { rb.append("error: invalid index\n", 21); return; }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(key, 'l')))
            { rb.append("error: type conflict\n", 21); break; }
            m_store.ltrim(key, s, e);
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("linsert"):
        {
            auto [key, r1]   = extract_key(args);
            auto [where, r2] = extract_key(r1);
            auto [pivot, v]  = extract_key(r2);
            if (key.empty() || where.empty() || pivot.empty())
            { rb.append("usage: linsert key before|after pivot value\n", 44); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            const uint32_t wh = fnv1a_lower(where);
            if (wh != fnv1a("before") && wh != fnv1a("after"))
            { rb.append("usage: linsert key before|after pivot value\n", 44); return; }
            const int n = m_store.linsert(key, wh == fnv1a("before"), pivot, v);
            if (n == cache_store::linsert_refused) { rb.append("error: out of memory\n", 21); break; }
            rb.append(std::to_string(n)); rb.push_back('\n');
            if (n > 0) replicate_command(line);
            break;
        }
        // ─── Lists, the blocking pops ───
        // Here as well as in RESP because deliver_pop() formats for both, and
        // a delivery path with no command behind it is dead code.
        case fnv1a("blpop"):
        case fnv1a("brpop"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            if (SOCKETLEY_UNLIKELY(m_shard_n > 1))
            { rb.append("error: blpop is not available on a sharded cache\n"); return; }
            // A blocking pop parks a waiter on a CONNECTION and answers it
            // when a push arrives.  A cross-runtime request has none: it is
            // served on the scratch connection, which has no descriptor, and
            // the ticket it belongs to is answered and gone long before any
            // push could wake it.  Measured before this: the caller got an
            // empty answer and exit 0, which reads exactly like "the list was
            // empty" -- and the waiter and its 100 ms timer stayed behind.
            if (SOCKETLEY_UNLIKELY(conn == m_request_conn.get()))
            { rb.append("error: blpop needs a connection to wait on, and a "
                        "cross-runtime request has none\n", 79); return; }
            // Collected first, because the last word is the timeout and the
            // ones before it are the keys.
            std::vector<std::string_view> parts;
            std::string_view walk = args;
            while (!walk.empty())
            {
                auto [w, rest] = extract_key(walk);
                if (w.empty()) break;
                parts.push_back(w); walk = rest;
            }
            if (parts.size() < 2)
            { rb.append("usage: blpop key [key ...] timeout\n", 35); return; }
            double secs = 0;
            if (!parse_double_sv(parts.back(), secs) || secs < 0)
            { rb.append("error: invalid timeout\n", 23); return; }
            const bool from_head = (fnv1a_lower(cmd) == fnv1a("blpop"));
            for (size_t i = 0; i + 1 < parts.size(); ++i)
            {
                if (m_has_ttl_keys) m_store.check_expiry(parts[i]);
                std::string val;
                const bool got = from_head ? m_store.lpop(parts[i], val)
                                           : m_store.rpop(parts[i], val);
                if (got)
                {
                    rb.append(parts[i].data(), parts[i].size());
                    rb.push_back(' '); rb.append(val); rb.push_back('\n');
                    if (mutation_log_wanted())
                    {
                        std::string c = from_head ? "lpop " : "rpop ";
                        c.append(parts[i].data(), parts[i].size());
                        replicate_command(c);
                    }
                    return;
                }
            }
            // The same refusal the RESP arm gives, in this protocol's word for
            // a pop that came back with nothing.
            if (SOCKETLEY_UNLIKELY(conn->in_exec))
            {
                rb.append("nil\n", 4);
                break;
            }
            {
                // block_pop() reads args[1..argc-2] as keys, so the same shape
                // is handed to it rather than a second parking path.
                std::vector<std::string_view> as;
                as.push_back(cmd);
                for (const auto& pp : parts) as.push_back(pp);
                block_pop(conn, as.data(), static_cast<int>(as.size()), from_head);
            }
            break;
        }

        // ─── Lists, the reliable-queue move ───
        // Present in the text protocol because replication goes through it:
        // repl(args, argc) writes the command as a line, and a follower's text
        // interpreter that does not know it applies nothing at all.
        case fnv1a("rpoplpush"):
        case fnv1a("lmove"):
        {
            const bool three = (fnv1a_lower(cmd) == fnv1a("rpoplpush"));
            auto [src, r1] = extract_key(args);
            auto [dst, r2] = extract_key(r1);
            if (src.empty() || dst.empty())
            { rb.append("usage: lmove src dst left|right left|right\n", 43); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }

            bool from_head = false, to_head = true;
            if (!three)
            {
                auto [fs, r3] = extract_key(r2);
                auto [ts, _r4] = extract_key(r3);
                const uint32_t f = fnv1a_lower(fs), t = fnv1a_lower(ts);
                if ((f != fnv1a("left") && f != fnv1a("right"))
                 || (t != fnv1a("left") && t != fnv1a("right")))
                { rb.append("usage: lmove src dst left|right left|right\n", 43); return; }
                from_head = (f == fnv1a("left"));
                to_head   = (t == fnv1a("left"));
            }
            std::string moved;
            if (!m_store.lmove(src, dst, from_head, to_head, moved))
            { rb.append("nil\n", 4); return; }
            rb.append(moved); rb.push_back('\n');
            replicate_command(line);
            while (wake_one_waiter(dst)) {}
            break;
        }

        // ─── Sets, the sampling spellings ───
        case fnv1a("spop"):
        {
            auto [key, _r] = extract_key(args);
            if (key.empty()) { rb.append("usage: spop key\n", 16); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            std::string member;
            if (!m_store.spop(key, member)) { rb.append("nil\n", 4); return; }
            rb.append(member); rb.push_back('\n');
            // As the SREM it turned out to be: the member this process's
            // iteration order picked is not the one a follower would pick.
            if (mutation_log_wanted())
            {
                std::string c = "srem "; c.append(key.data(), key.size());
                c += ' '; c += member;
                replicate_command(c);
            }
            break;
        }
        case fnv1a("srandmember"):
        {
            auto [key, _r] = extract_key(args);
            if (key.empty()) { rb.append("usage: srandmember key\n", 23); return; }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            std::string member;
            if (!m_store.srandmember(key, member)) { rb.append("nil\n", 4); return; }
            rb.append(member); rb.push_back('\n');
            break;
        }

        // ─── Hashes, the field spellings ───
        case fnv1a("hexists"):
        {
            auto [key, f] = extract_key(args);
            if (key.empty() || f.empty()) { rb.append("usage: hexists key field\n", 25); return; }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            rb.append(m_store.hexists(key, f) ? "1\n" : "0\n", 2);
            break;
        }
        case fnv1a("hincrby"):
        {
            auto [key, r1] = extract_key(args);
            auto [f, d_s]  = extract_key(r1);
            if (key.empty() || f.empty() || d_s.empty())
            { rb.append("usage: hincrby key field delta\n", 31); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            int64_t d = 0, out = 0;
            if (!parse_int_sv(d_s, d)) { rb.append("error: invalid delta\n", 21); return; }
            const auto hst = m_store.hincrby(key, f, d, out);
            if (!answered_incr(hst, out)) return;
            replicate_command(line);
            break;
        }
        case fnv1a("hsetnx"):
        {
            auto [key, r1] = extract_key(args);
            auto [f, v]    = extract_key(r1);
            if (key.empty() || f.empty()) { rb.append("usage: hsetnx key field value\n", 30); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            const int rc = m_store.hsetnx(key, f, v);
            if (rc < 0)
            {
                const auto t = m_store.type(key);
                if (t == "none" || t == "hash")
                    rb.append("error: out of memory\n", 21);
                else
                    rb.append("error: type conflict\n", 21);
                return;
            }
            rb.append(rc ? "1\n" : "0\n", 2);
            if (rc == 1) replicate_command(line);
            break;
        }
        case fnv1a("hstrlen"):
        {
            auto [key, f] = extract_key(args);
            if (key.empty() || f.empty()) { rb.append("usage: hstrlen key field\n", 25); return; }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            const auto v = m_store.hget(key, f);
            rb.append(std::to_string(v ? v->size() : 0)); rb.push_back('\n');
            break;
        }
        case fnv1a("hkeys"):
        case fnv1a("hvals"):
        {
            auto [key, _r] = extract_key(args);
            if (key.empty()) { rb.append("usage: hkeys key\n", 17); return; }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            const auto* hp = m_store.hash_ptr(key);
            const bool want_keys = (fnv1a_lower(cmd) == fnv1a("hkeys"));
            if (hp) for (const auto& [f, v] : *hp)
            { rb.append(want_keys ? f : v); rb.push_back('\n'); }
            rb.append("end\n", 4);
            break;
        }
        case fnv1a("hmget"):
        {
            auto [key, rest] = extract_key(args);
            if (key.empty() || rest.empty()) { rb.append("usage: hmget key field [field ...]\n", 35); return; }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            std::string_view walk = rest;
            while (!walk.empty())
            {
                auto [f, next] = extract_key(walk);
                if (f.empty()) break;
                const auto v = m_store.hget(key, f);
                if (v) { rb.append(*v); rb.push_back('\n'); }
                else   rb.append("nil\n", 4);
                walk = next;
            }
            rb.append("end\n", 4);
            break;
        }
        case fnv1a("hmset"):
        {
            auto [key, rest] = extract_key(args);
            if (key.empty() || rest.empty())
            { rb.append("usage: hmset key field value [field value ...]\n"); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            // A field without its value is refused whole, as mset does, rather than stored with an empty one.
            {
                size_t words = 1;
                for (const char c : rest)
                    words += c == ' ';
                if (words % 2 != 0)
                { rb.append("usage: hmset key field value [field value ...]\n"); return; }
            }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            // Fields go in order up to the first the store refuses, and only those reach a follower.
            std::string_view walk = rest;
            bool refused = false;
            while (!walk.empty())
            {
                auto [f, r1] = extract_key(walk);
                auto [v, r2] = extract_key(r1);
                if (f.empty()) break;
                if (!m_store.hset(key, f, v))
                {
                    auto t = m_store.type(key);
                    if (t == "none" || t == "hash")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    refused = true;
                    break;
                }
                std::string one;
                one.reserve(8 + key.size() + f.size() + v.size());
                one += "hmset ";
                one.append(key);
                one += ' ';
                one.append(f);
                one += ' ';
                one.append(v);
                replicate_command(one);
                walk = r2;
            }
            if (!refused) rb.append("ok\n", 3);
            break;
        }
        // ─── One collection, scanned ───
        // Read-only, so replication does not need these -- they are here so
        // the two protocols do not drift, which is how a command ends up
        // meaning one thing on a port and another on a node.
        case fnv1a("hscan"):
        case fnv1a("sscan"):
        case fnv1a("zscan"):
        {
            auto [key, r1]   = extract_key(args);
            auto [cur_s, r2] = extract_key(r1);
            if (key.empty() || cur_s.empty())
            { rb.append("usage: hscan key cursor [match pat] [count n] [valuematch g]\n"); return; }
            uint64_t cur = 0;
            if (!parse_int_sv(cur_s, cur)) { rb.append("error: invalid cursor\n", 22); return; }
            // "*" and not empty: an ABSENT MATCH means everything, an explicit
            // MATCH "" means the member whose name is empty, and the store can
            // only tell them apart if the default is spelled here.
            std::string_view pat = "*"; size_t want = 10;
            std::string_view vpat; bool has_v = false, count_given = false;
            std::string_view walk = r2;
            while (!walk.empty())
            {
                auto [o, r3] = extract_key(walk);
                auto [v, r4] = extract_key(r3);
                if (o.empty()) break;
                if (v.empty()) { rb.append("error: syntax\n", 14); return; }
                const uint32_t oh = fnv1a_lower(o);
                if (oh == fnv1a("match")) pat = v;
                else if (oh == fnv1a("valuematch")) { vpat = v; has_v = true; }
                else if (oh == fnv1a("count"))
                {
                    int64_t c = 0;
                    if (!parse_int_sv(v, c) || c < 1)
                    { rb.append("error: invalid count\n", 21); return; }
                    want = static_cast<size_t>(c); count_given = true;
                }
                else { rb.append("error: syntax\n", 14); return; }
                walk = r4;
            }
            const uint32_t which = fnv1a_lower(cmd);
            // Only a hash has values to match: a set's members and a zset's
            // scores are not that, and answering as if they were would make the
            // option mean three things.
            if (has_v && which != fnv1a("hscan"))
            { rb.append("error: syntax\n", 14); return; }
            // Same rule as scan's: a selective predicate returns almost nothing
            // per page, so ten fields examined per call is not a page size.
            if (has_v && !count_given) want = 1000;
            if (m_has_ttl_keys) m_store.check_expiry(key);
            uint64_t next = 0;
            std::string listing;
            if (which == fnv1a("hscan"))
            {
                std::vector<std::pair<std::string_view, std::string_view>> got;
                next = m_store.hscan(key, cur, pat, want, got, has_v ? &vpat : nullptr);
                for (const auto& [f, v] : got)
                { listing.append(f); listing += ' '; listing.append(v); listing += '\n'; }
            }
            else if (which == fnv1a("sscan"))
            {
                std::vector<std::string_view> got;
                next = m_store.sscan(key, cur, pat, want, got);
                for (const auto& m : got) { listing.append(m); listing += '\n'; }
            }
            else
            {
                std::vector<std::pair<std::string_view, double>> got;
                next = m_store.zscan(key, cur, pat, want, got);
                for (const auto& [m, sc] : got)
                { listing.append(m); listing += ' '; append_score_bare(listing, sc);
                  listing += '\n'; }
            }
            // The cursor first on its own line, the way `scan` answers here.
            rb.append(std::to_string(next)); rb.push_back('\n');
            rb.append(listing);
            rb.append("end\n", 4);
            break;
        }

        // ─── Sorted sets, by score rather than by rank ───
        case fnv1a("zrangebyscore"):
        case fnv1a("zrevrangebyscore"):
        {
            auto [key, r1]   = extract_key(args);
            auto [a_s, r2]   = extract_key(r1);
            auto [b_s, tail] = extract_key(r2);
            if (key.empty() || a_s.empty() || b_s.empty())
            { rb.append("usage: zrangebyscore key min max [withscores]\n", 46); return; }
            const bool rev = (fnv1a_lower(cmd) == fnv1a("zrevrangebyscore"));
            double lo = 0, hi = 0; bool lo_in = true, hi_in = true;
            if (!parse_score_bound(rev ? b_s : a_s, lo, lo_in)
             || !parse_score_bound(rev ? a_s : b_s, hi, hi_in))
            { rb.append("error: min or max is not a float\n", 33); return; }
            const bool with = !tail.empty() && fnv1a_lower(tail) == fnv1a("withscores");
            m_store.check_expiry(key);
            std::vector<std::pair<std::string_view, double>> items;
            m_store.zrangebyscore(key, lo, hi, lo_in, hi_in, rev, items);
            for (const auto& [zm, zsc] : items)
            {
                rb.append(zm.data(), zm.size());
                if (with) { rb.append(" ", 1); append_score_bare(rb, zsc); }
                rb.push_back('\n');
            }
            rb.append("end\n", 4);
            break;
        }
        case fnv1a("zcount"):
        {
            auto [key, r1]  = extract_key(args);
            auto [a_s, r2]  = extract_key(r1);
            auto [b_s, _r3] = extract_key(r2);
            if (key.empty() || a_s.empty() || b_s.empty())
            { rb.append("usage: zcount key min max\n", 26); return; }
            double lo = 0, hi = 0; bool lo_in = true, hi_in = true;
            if (!parse_score_bound(a_s, lo, lo_in) || !parse_score_bound(b_s, hi, hi_in))
            { rb.append("error: min or max is not a float\n", 33); return; }
            m_store.check_expiry(key);
            rb.append(std::to_string(m_store.zcount(key, lo, hi, lo_in, hi_in)));
            rb.push_back('\n');
            break;
        }
        case fnv1a("zpopmin"):
        case fnv1a("zpopmax"):
        {
            auto [key, zrest] = extract_key(args);
            if (key.empty()) { rb.append("usage: zpopmin key [count]\n", 27); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            int64_t zcount_want = 1;
            if (!zrest.empty())
            {
                auto [cnt_s, zextra] = extract_key(zrest);
                if (!zextra.empty() || !parse_int_sv(cnt_s, zcount_want) || zcount_want < 0)
                { rb.append("error: invalid count\n", 21); return; }
            }
            const bool zpop_max = fnv1a_lower(cmd) == fnv1a("zpopmax");
            std::string member; double score = 0;
            for (int64_t n = 0; n < zcount_want && m_store.zpop(key, zpop_max, member, score); ++n)
            {
                rb.append(member); rb.push_back(' ');
                append_score_bare(rb, score); rb.push_back('\n');
                // The ZREM it turned out to be, for SPOP's reason.
                if (mutation_log_wanted())
                {
                    std::string c = "zrem "; c.append(key.data(), key.size());
                    c += ' '; c += member;
                    replicate_command(c);
                }
            }
            rb.append("end\n", 4);
            break;
        }
        case fnv1a("zremrangebyrank"):
        {
            auto [key, r1]  = extract_key(args);
            auto [s_s, r2]  = extract_key(r1);
            auto [e_s, _r3] = extract_key(r2);
            if (key.empty() || s_s.empty() || e_s.empty())
            { rb.append("usage: zremrangebyrank key start stop\n", 38); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            int64_t s = 0, e = 0;
            if (!parse_int_sv(s_s, s) || !parse_int_sv(e_s, e))
            { rb.append("error: invalid index\n", 21); return; }
            const size_t gone = m_store.zremrangebyrank(key, s, e);
            rb.append(std::to_string(gone)); rb.push_back('\n');
            if (gone > 0) replicate_command(line);
            break;
        }
        case fnv1a("zremrangebyscore"):
        {
            auto [key, r1]  = extract_key(args);
            auto [a_s, r2]  = extract_key(r1);
            auto [b_s, _r3] = extract_key(r2);
            if (key.empty() || a_s.empty() || b_s.empty())
            { rb.append("usage: zremrangebyscore key min max\n", 36); return; }
            if (m_mode == cache_mode_readonly) { rb.append("error: readonly mode\n", 21); return; }
            double lo = 0, hi = 0; bool lo_in = true, hi_in = true;
            if (!parse_score_bound(a_s, lo, lo_in) || !parse_score_bound(b_s, hi, hi_in))
            { rb.append("error: min or max is not a float\n", 33); return; }
            const size_t gone = m_store.zremrangebyscore(key, lo, hi, lo_in, hi_in);
            rb.append(std::to_string(gone)); rb.push_back('\n');
            if (gone > 0) replicate_command(line);
            break;
        }

        // ─── The handshake set, so a RESP client on a text-mode port is not
        // stranded by a command it sends before anything else ───
        case fnv1a("echo"):
        {
            rb.append(args.data(), args.size()); rb.push_back('\n');
            break;
        }
        case fnv1a("select"):
        {
            auto [idx, _r] = extract_key(args);
            int64_t db = 0;
            if (!idx.empty() && (!parse_int_sv(idx, db) || db != 0))
            { rb.append("error: DB index out of range\n", 29); return; }
            rb.append("ok\n", 3);
            break;
        }
        case fnv1a("info"):
        {
            std::string info;
            build_info_reply(info, !conn->cluster_port);
            rb.append(info);
            break;
        }
        // Streams answer in RESP and are turned into this protocol's words in
        // one place, since their replies nest where every other one is a list.
        case fnv1a("xadd"):      case fnv1a("xrange"):     case fnv1a("xrevrange"):
        case fnv1a("xlen"):      case fnv1a("xread"):      case fnv1a("xreadgroup"):
        case fnv1a("xdel"):      case fnv1a("xtrim"):      case fnv1a("xgroup"):
        case fnv1a("xsetid"):    case fnv1a("xack"):       case fnv1a("xpending"):
        case fnv1a("xclaim"):    case fnv1a("xautoclaim"): case fnv1a("xinfo"):
        case fnv1a("xapply"):
            stream_text(conn, cmd, args);
            break;
        default:
            rb.append("failed: unknown command\n", 24);
            break;
    }
}

// False only when a submission was attempted and did not reach the ring, after
// which the pending flags are cleared and the batch dropped -- because the
// difference is a closed connection rather than a hung one.
bool cache_instance::flush_responses(client_connection* conn)
{
    publish_keyspace();
    if (SOCKETLEY_UNLIKELY(conn->response_buf.empty() || !m_loop || conn->closing))
    {
        if (!conn->response_buf.empty() && (conn->closing || !m_loop))
            SKL_TRACE_LOG("flush skipped fd=%d bytes=%zu closing=%d loop=%d",
                          conn->fd, conn->response_buf.size(),
                          (int)conn->closing, (int)(m_loop != nullptr));
        return true;
    }
    SKL_TRACE_ADD(conn, bytes_queued, conn->response_buf.size());
    // Once a read's replies are out; a flush of a push no read asked for counts nothing.
    m_lat_batch.observe(std::exchange(conn->batch_ns, 0), socketley::turn_clock::now_ns());

    if (SOCKETLEY_UNLIKELY(conn->write_queue.bytes() >= write_buffer_bytes()))
    {
        // The peer has genuinely stopped reading while megabytes pile up, so
        // dropping the connection is right but must not happen quietly.
        std::cerr << "[cache] client " << conn->fd << " is not draining its socket ("
                  << conn->write_queue.bytes() << " bytes in "
                  << conn->write_queue.size() << " queued buffers), closing\n";
        conn->closing = true;
        return true;
    }

    // Fast path straight out of response_buf when nothing is queued, never on
    // a TLS connection, because response_buf is plaintext and this would put
    // an answer on an encrypted port in the clear.
    if (SOCKETLEY_LIKELY(!conn->write_pending && conn->write_queue.empty() &&
                         conn->ssl == nullptr))
    {
        // A lone answer goes by send(), sparing it the ring entry and the
        // completion; see direct_send_gate for when that is a saving.
        size_t sent = 0;
        if (m_direct_gate.admit(conn->fd))
        {
            const ssize_t n = ::send(conn->fd, conn->response_buf.data(), conn->response_buf.size(),
                                     MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n > 0)
            {
                sent = static_cast<size_t>(n);
                SKL_TRACE_ADD(conn, writes, 1);
                SKL_TRACE_ADD(conn, bytes_written, sent);
                stat_add(m_stat_bytes_out, sent);
                if (sent == conn->response_buf.size())
                {
                    conn->response_buf.clear();
                    m_direct_fd = conn->fd;
                    return true;
                }
            }
        }

        // swap and clear, not move and reserve.  The move destroyed
        // write_batch[0]'s buffer and stole response_buf's, leaving
        // response_buf empty -- so the reserve had to allocate again, and both
        // sizes are over glibc's tcache bound (1032 B), which puts the pair in
        // the small-bin path.  One free and one malloc per FLUSH, and with a
        // pipeline depth of one that is per request.
        //
        // The swap keeps both buffers alive: the batch takes the answer, and
        // response_buf takes the batch's previous allocation, cleared.  Safe
        // here and only here, because the fast path is gated on
        // !write_pending -- what write_batch[0] still holds is a write that
        // has completed.  The two settle at the largest response this
        // connection has sent, which is what reserve(4096) was already aiming
        // at from below.
        conn->write_batch[0].swap(conn->response_buf);
        conn->response_buf.clear();
        char* const rest = conn->write_batch[0].data() + sent;
        conn->write_iovs[0].iov_base = rest;
        conn->write_iovs[0].iov_len  = conn->write_batch[0].size() - sent;
        conn->write_batch_count = 1;
        conn->write_pending = true;

        auto len = static_cast<uint32_t>(conn->write_iovs[0].iov_len);
        bool queued;
        conn->write_req.type = op_write;
        if (conn->direct_fd)
            queued = m_loop->submit_write_fixed_file(conn->fixed_idx, rest, len, &conn->write_req);
        else
            queued = m_loop->submit_write(conn->fd, rest, len, &conn->write_req);

        if (SOCKETLEY_UNLIKELY(!queued))
        {
            conn->write_batch[0].clear();
            conn->write_batch_count = 0;
            conn->write_pending = false;
            return false;
        }
        return true;
    }

    // Append to the tail entry whenever that keeps it a sensible size, because
    // a pipelined client's three-byte replies turn kilobytes into thousands of
    // entries -- and only the tail, since entries are moved out before
    // submission.
    // std::move, so the entry this queues is the buffer and not a copy of it;
    // append_back() leaves the source alone either way, which is what the
    // clear() below is for.
    conn->write_queue.push_coalesced(std::move(conn->response_buf),
                                     client_connection::WRITE_COALESCE_LIMIT);
    conn->response_buf.clear();
    conn->response_buf.reserve(4096);

    if (!conn->write_pending)
        return flush_write_queue(conn);
    return true;
}

// Same contract as flush_responses above: false means nothing reached the ring
// and no completion is owed, so the caller has to stop treating the connection
// as one that is still going to be written to.
bool cache_instance::flush_write_queue(client_connection* conn)
{
    // A TLS connection's bytes go through the record layer, which is what
    // keeps every caller above from having to know which kind of connection it
    // holds.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
        return tls_flush(conn);

    if (!m_loop || conn->write_queue.empty())
        return true;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < client_connection::MAX_WRITE_BATCH)
    {
        socketley::write_chunk c = conn->write_queue.take_front();
        if (c.owns())
        {
            conn->write_batch[count] = c.take_owned();
            conn->write_iovs[count].iov_base = conn->write_batch[count].data();
            conn->write_iovs[count].iov_len  = conn->write_batch[count].size();
        }
        else
        {
            conn->write_iovs[count].iov_base = const_cast<char*>(c.data());
            conn->write_iovs[count].iov_len  = c.size();
            conn->write_batch_seg[count] = c.take_shared();
        }
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    bool queued;
    if (count == 1)
    {
        auto len = static_cast<uint32_t>(conn->write_iovs[0].iov_len);
        conn->write_req.type = op_write;
        if (conn->direct_fd)
            queued = m_loop->submit_write_fixed_file(conn->fixed_idx, static_cast<const char*>(conn->write_iovs[0].iov_base), len, &conn->write_req);
        else
            queued = m_loop->submit_write(conn->fd, static_cast<const char*>(conn->write_iovs[0].iov_base), len, &conn->write_req);
    }
    else
    {
        conn->write_msg.msg_iov = conn->write_iovs;
        conn->write_msg.msg_iovlen = count;
        conn->write_req.type = op_writev;
        if (conn->direct_fd)
            queued = m_loop->submit_sendmsg_fixed_file(conn->fixed_idx, &conn->write_msg, &conn->write_req);
        else
            queued = m_loop->submit_sendmsg(conn->fd, &conn->write_msg, &conn->write_req);
    }

    if (SOCKETLEY_UNLIKELY(!queued))
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            { conn->write_batch[i].clear(); conn->write_batch_seg[i].reset(); }
        conn->write_batch_count = 0;
        conn->write_pending = false;
        return false;
    }
    return true;
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

// The expiry check first, exactly as the wire's EXISTS does it: a key past its
// deadline is not there, and asking without sweeping would answer that it is.
bool cache_instance::lua_exists(std::string_view key)
{
    if (m_has_ttl_keys)
        m_store.check_expiry(key);
    return m_store.exists(key);
}

// Spell a script's write as the text command a client would have typed and
// hand it to replicate_command(), because the journal and the followers log
// that chokepoint and this API used to walk past both.
void cache_instance::log_lua_mutation(std::initializer_list<std::string_view> parts)
{
    if (!mutation_log_wanted())
        return;
    // Only the last part survives a space, because the reader splits the rest on it.
    for (auto it = parts.begin() + 1; it + 1 < parts.end(); ++it)
        if (it->find(' ') != std::string_view::npos)
        {
            repl_unfaithful(*it);
            return;
        }
    size_t n = 0;
    for (const auto p : parts)
        n += p.size() + 1;
    std::string line;
    line.reserve(n);
    for (const auto p : parts)
    {
        if (!line.empty())
            line += ' ';
        line.append(p.data(), p.size());
    }
    replicate_command(line);
}

bool cache_instance::lua_set(std::string_view key, std::string_view value)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    const bool did = m_store.set(key, value);
    if (did)
        log_lua_mutation({"set", key, value});
    return did;
}

bool cache_instance::lua_del(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return false;
    const bool did = m_store.del(key);
    if (did)
        log_lua_mutation({"del", key});
    return did;
}

bool cache_instance::lua_lpush(std::string_view key, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    const bool did = m_store.lpush(key, val);
    if (did)
        log_lua_mutation({"lpush", key, val});
    return did;
}

bool cache_instance::lua_rpush(std::string_view key, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    const bool did = m_store.rpush(key, val);
    if (did)
        log_lua_mutation({"rpush", key, val});
    return did;
}

std::string cache_instance::lua_lpop(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return "";
    m_store.check_expiry(key);
    std::string val;
    if (m_store.lpop(key, val))
    {
        log_lua_mutation({"lpop", key});
        return val;
    }
    return "";
}

std::string cache_instance::lua_rpop(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return "";
    m_store.check_expiry(key);
    std::string val;
    if (m_store.rpop(key, val))
    {
        log_lua_mutation({"rpop", key});
        return val;
    }
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
    if (start <= stop)
    {
        auto e = deq->iterator_at(static_cast<size_t>(start));
        for (int i = start; i <= stop; i++, ++e)
            result[lua_idx++] = std::string(*e);
    }

    return result;
}
#endif

int cache_instance::lua_sadd(std::string_view key, std::string_view member)
{
    if (m_mode == cache_mode_readonly)
        return -1;
    m_store.check_expiry(key);
    const int added = m_store.sadd(key, member);
    if (added == 1)
        log_lua_mutation({"sadd", key, member});
    return added;
}

bool cache_instance::lua_srem(std::string_view key, std::string_view member)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    const bool did = m_store.srem(key, member);
    if (did)
        log_lua_mutation({"srem", key, member});
    return did;
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
    const bool did = m_store.hset(key, field, val);
    if (did)
        log_lua_mutation({"hset", key, field, val});
    return did;
}

std::string cache_instance::lua_hget(std::string_view key, std::string_view field)
{
    m_store.check_expiry(key);
    const auto val = m_store.hget(key, field);
    return val ? std::string(*val) : std::string();
}

bool cache_instance::lua_hexists(std::string_view key, std::string_view field)
{
    m_store.check_expiry(key);
    return m_store.hget(key, field).has_value();
}

bool cache_instance::lua_hdel(std::string_view key, std::string_view field)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    const bool did = m_store.hdel(key, field);
    if (did)
        log_lua_mutation({"hdel", key, field});
    return did;
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
    // The third door to the same decision, so a script gets what the two
    // protocols get: zero or less deletes, and a key already past its deadline
    // is not there to be given a new one.  Both answers are true here, because
    // this returns "did it do something" and both did.
    const auto r = m_store.expire_in(key, seconds, false);
    if (r == cache_store::expire_result::no_such_key)
        return false;
    if (r == cache_store::expire_result::armed)
        mark_ttl_keys();
    log_lua_mutation({"expire", key, std::to_string(seconds)});
    return true;
}

int64_t cache_instance::lua_ttl(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.get_ttl(key);
}

bool cache_instance::lua_persist(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return false;
    const bool did = m_store.persist(key);
    if (did)
        log_lua_mutation({"persist", key});
    return did;
}

// ─── a script's publish ─────────────────────────────────────────────────────
// publish() is this process's subscribers and the cross-runtime half, and on N
// shards that is 1/N of the cache's socket subscribers: the daemon's publish
// frame does reach every sibling, but a sibling answers it in
// on_publish_dispatch(), which runs Lua and never looks at a socket.  Measured
// on four shards with forty subscribers spread over them: self.publish reached
// 17, the wire's PUBLISH 40.
//
// So the message takes the wire's own road for the half publish() cannot do --
// one batch a turn for each sibling that may hold a subscriber, exactly the
// set fan_publish() picks.  No reply is collected: the batches answer on a later
// turn and self.publish() answers on this one, which is the same wall the
// keyspace calls above run into.  That is why the count is this shard's
// subscribers and not the cache's, and it is the count this call has always
// returned.
void cache_instance::fan_publish_siblings(std::string_view channel,
                                          std::string_view message)
{
    // RESP and not the text form, because a message holding a newline is one message, and built only at the first
    // sibling the filter keeps.
    std::string_view args[3] = {"publish", channel, message};
    std::string      cmd;

    const auto&    tbl      = shard_stats_table();
    const bool     filtered = tbl.mapped() && tbl.count() == m_shard_n;
    const uint32_t bit      = shard_stats::channel_bit(channel);
    if (m_lua_pub.size() != m_shard_n)
    {
        m_lua_pub.assign(m_shard_n, {});
        m_lua_pub_count.assign(m_shard_n, 0);
    }

    for (uint32_t sh = 0; sh < m_shard_n; ++sh)
    {
        // This shard was served inline by publish(), above.
        if (sh == m_shard_i)
            continue;
        // A pattern subscriber has no bit of its own, so a shard holding one
        // is never filtered out -- the same rule fan_publish() states.
        if (filtered && !tbl.channel_may_have(sh, bit)
            && !tbl.channel_may_have(sh, shard_stats::pattern_bit))
            continue;

        // Gathered for the turn, because a crossing each for a script that
        // publishes in a loop filled the channel and the sibling's parked
        // requests, and three quarters of 2,000 publishes were lost.
        if (cmd.empty())
            rebuild_resp(cmd, args, 3);
        std::string& batch = m_lua_pub[sh];
        if (batch.empty())
            batch.assign(shard_batch_resp);
        shard_frame_append(batch, cmd);
        ++m_lua_pub_count[sh];
        if (batch.size() >= lua_pub_batch_bytes)
            flush_lua_publish(sh);
    }
}

void cache_instance::flush_lua_publishes()
{
    bool kept = false;
    for (uint32_t sh = 0; sh < m_lua_pub.size(); ++sh)
    {
        if (!m_lua_pub[sh].empty())
            flush_lua_publish(sh);
        kept |= !m_lua_pub[sh].empty();
    }
    // Emptied when nothing is kept, so a turn with nothing to send costs one test.
    if (!kept)
    {
        m_lua_pub.clear();
        m_lua_pub_count.clear();
    }
}

void cache_instance::flush_lua_publish(uint32_t sh)
{
    auto* mgr = get_runtime_manager();
    std::string& batch = m_lua_pub[sh];
    // A cookie m_posts does not hold, so on_request_reply() takes it here and
    // only says something when the sibling would not take the batch.
    const uint64_t cookie = m_next_cookie++;
    if (mgr && mgr->requests().post(this, cookie, shard_target(get_name(), sh),
                                    batch, request_class::client))
    {
        m_lua_pub_posts.emplace(cookie, m_lua_pub_count[sh]);
        batch.clear();
        m_lua_pub_count[sh] = 0;
        return;
    }
    // Refused here, so kept for the next turn, up to what a channel takes.
    if (batch.size() < lua_pub_keep_bytes)
        return;
    LOG_WARN(("cache: " + std::to_string(m_lua_pub_count[sh]) +
              " script publish(es) could not be posted to a sibling shard; "
              "its subscribers did not hear them").c_str());
    batch.clear();
    m_lua_pub_count[sh] = 0;
}

int cache_instance::lua_publish(std::string_view channel, std::string_view message)
{
    const int local = publish(channel, message);
    if (m_shard_n > 1)
        fan_publish_siblings(channel, message);
    return local;
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

bool cache_instance::process_resp(client_connection* conn)
{
    // Fixed-size string_view array — zero heap allocations per command, and
    // the parser's own RESP_MAX_ARRAY_SIZE rather than a second, smaller cap
    // that turned valid Redis commands into protocol errors.
    static constexpr int MAX_RESP_ARGS = resp::RESP_MAX_ARRAY_SIZE;
    resp::arg_slots  slots;
    std::string_view* args = slots.v;
    int argc = 0;
    size_t consumed = 0;
    size_t offset = 0;
    bool   cut = false;

    // Commands parsed ahead of the one running, so a keyspace past the
    // caches has its slot and entry lines on their way before each lookup
    // instead of every lookup waiting for its own.
    static constexpr int AHEAD = 8, AHEAD_ARGS = 8;
    struct ahead_cmd
    {
        std::string_view args[AHEAD_ARGS];
        int              argc;
        size_t           consumed;
        uint64_t         h;
    };
    // Built empty, like resp::arg_slots, so a read that never looks ahead zeroes no 1 KiB of views.
    union ahead_queue
    {
        ahead_cmd v[AHEAD];
        ahead_queue()  noexcept {}
        ~ahead_queue() noexcept {}
    } q_slots;
    ahead_cmd* const q = q_slots.v;
    int    qh = 0, qn = 0;
    size_t scan = 0;
    // Stalled until the first command has run the ordinary way, so a read
    // holding one command -- every read at depth 1 -- never copies it twice.
    bool   scan_stalled = true;
    const bool ahead = m_store.keyspace_outgrows_cache();

    while (offset < conn->partial.size())
    {
        // Same cut as parse_text_lines makes, for the same reason and in the
        // same place: the loop that consumes is the loop that decides how much.
        if (SOCKETLEY_UNLIKELY(m_collect
                               && m_collect->slots.size() >= MAX_ROUTED_PER_BATCH))
        {
            cut = true;
            break;
        }

        // A blocked BLPOP answers on a later turn, so everything behind it
        // waits in `partial` rather than being answered out of order.  Not
        // through `cut`: that path's caller loops straight back in, which for
        // a connection that is still blocked never ends.
        if (SOCKETLEY_UNLIKELY(conn->blocked))
            break;

        // And a connection already on its way out answers nothing more.
        //
        // Without this the rest of a pipelined batch was still parsed and still
        // answered into response_buf, while every flush it triggered was skipped
        // -- flush_responses() returns true for a closing connection, which the
        // callers read as success, so the 1 MiB cap below called a flush that did
        // nothing and then cleared nothing.  Measured before this, one connection
        // asking for a 256 KiB value 4,096 times and reading none of it: the
        // worker peaked at 1,063 MB, for a bound of 8 MiB it had already decided
        // to enforce.
        if (SOCKETLEY_UNLIKELY(conn->closing))
            break;

        // Anything the lookahead cannot hold -- a long command, an incomplete
        // or malformed one -- stops it there, and the parse below meets it.
        while (ahead && !scan_stalled && qn < AHEAD && scan < conn->partial.size())
        {
            ahead_cmd& c = q[(qh + qn) % AHEAD];
            std::string_view rest(conn->partial.data() + scan, conn->partial.size() - scan);
            if (resp::parse_message_views(rest, c.args, AHEAD_ARGS, c.argc, c.consumed,
                                          read_bulk_limit()) != resp::parse_result::ok
                || c.argc < 1)
            {
                scan_stalled = true;
                break;
            }
            c.h = 0;
            if (c.argc >= 2)
            {
                c.h = cache_store::key_hash(c.args[1]);
                m_store.prefetch_slot(c.h);
            }
            scan += c.consumed;
            ++qn;
        }

        std::string_view* cargs = args;
        resp::parse_result result;
        if (qn > 0)
        {
            ahead_cmd& c = q[qh];
            cargs    = c.args;
            argc     = c.argc;
            consumed = c.consumed;
            result   = resp::parse_result::ok;
            qh = (qh + 1) % AHEAD;
            --qn;
            // Three commands out the slot has had time to arrive.
            if (qn >= 3 && q[(qh + 2) % AHEAD].h)
                m_store.prefetch_entry(q[(qh + 2) % AHEAD].h);
        }
        else
        {
            std::string_view buf(conn->partial.data() + offset, conn->partial.size() - offset);
            result = resp::parse_message_views(buf, args, MAX_RESP_ARGS, argc, consumed, read_bulk_limit());
            if (result == resp::parse_result::ok)
            {
                scan = offset + consumed;
                scan_stalled = false;
            }
        }

        if (result == resp::parse_result::incomplete)
            break;

        if (result == resp::parse_result::too_many_args)
        {
            // Named, with the limit in it.  Redis accepts up to 1024*1024
            // elements; ours is 1024 because args[] is a stack array, and a
            // client that hits it deserves to be told which wall it met rather
            // than "protocol error".  The stream is still framed here -- the
            // header was read and the message length is known -- but the
            // arguments were never stored, so the connection cannot continue
            // from a message it did not take.
            conn->response_buf.append(
                "-ERR too many arguments in one command (limit ");
            conn->response_buf.append(std::to_string(MAX_RESP_ARGS));
            conn->response_buf.append(")\r\n");
            conn->partial.clear();
            if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
            {
                conn->closing = true;
                return false;
            }
            conn->closing = true;
            return false;
        }

        if (result == resp::parse_result::value_too_large)
        {
            // Named, with the limit in it, for the reason the branch above
            // gives: a client told "protocol error" for a value that was
            // merely large concludes its framing is broken and sends the same
            // value again.  Measured before this branch existed --
            // `SET b <600KB>` answered "-ERR protocol error" and the
            // connection closed, which is both the wrong cause and the loop
            // that comment warns about.
            //
            // Closed all the same, which is what Redis does for a bulk length
            // it will not take: the body was never read, so there is no
            // framed position to continue from.  What changes is that the
            // client is told which wall it met.
            conn->response_buf.append("-ERR value is larger than this cache accepts (limit ");
            conn->response_buf.append(std::to_string(read_bulk_limit()));
            conn->response_buf.append(" bytes)\r\n");
            conn->partial.clear();
            if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
            {
                conn->closing = true;
                return false;
            }
            conn->closing = true;
            return false;
        }

        if (result == resp::parse_result::error)
        {
            // Redis closes on a protocol error, and this path is the reason.
            // partial.clear() also threw away whatever the client had already
            // pipelined BEHIND the bad command, so it received fewer replies
            // than it sent commands and waited for ever on a connection that
            // stayed open.  Answering and then closing is the only outcome
            // that cannot strand it: the stream is no longer framed, and
            // nothing after this point can be read as anything.
            conn->response_buf.append("-ERR protocol error\r\n");
            conn->partial.clear();
            // Flushed BEFORE the flag and not after it.  flush_responses drops
            // a closing connection's buffer -- deliberately, and there is a
            // trace line for it -- so setting `closing` first threw away the
            // very reply this path exists to send.  Every protocol error, not
            // just this one, reached the client as a bare EOF, which a client
            // library cannot tell from a crash: it reconnects, sends the same
            // thing, and is cut off again with nothing to log.
            //
            // The write survives the flag: a closing connection with bytes in
            // flight is closed by the write-drain path, not here.
            if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
            {
                conn->closing = true;
                return false;
            }
            conn->closing = true;
            return false;
        }

        // Advance offset; args[] point into conn->partial which stays valid
        offset += consumed;

        if (argc > 0)
        {
            SKL_TRACE_ADD(conn, commands_parsed, 1);
            const size_t rb_before = conn->response_buf.size();
            process_resp_command(conn, cargs, argc);
            if (conn->response_buf.size() != rb_before)
                SKL_TRACE_ADD(conn, responses_made, 1);
        }

        // Cap response_buf at 1 MiB during large pipelines to prevent OOM
        if (conn->response_buf.size() > (1 << 20))
        {
            if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
            {
                // Nothing more can be delivered to this client, and marking it
                // is all this may do, because the caller still holds conn and
                // the read handler's tail tears it down.
                conn->closing = true;
                break;
            }
            conn->response_buf.reserve(4096);
        }
    }

    // Single erase for entire batch — O(remaining) not O(n * commands)
    if (offset > 0)
    {
        if (offset >= conn->partial.size())
            conn->partial.clear();
        else
            conn->partial.erase(0, offset);
    }
    return cut;
}

// The same question asked once for the other interpreter, which is two sites
// deciding routing against the sixty-odd handlers behind them.
// The index of the first key among every `step`th of args[from..from+n) that
// this shard does not own, or -1 when it owns them all.
int cache_instance::first_foreign_key(std::string_view* args, int from, int n, int step) const
{
    for (int i = from; i < from + n; i += step)
        if (!args[i].empty() && cache_shard_of(args[i], m_shard_n) != m_shard_i)
            return i;
    return -1;
}

// -1 when this shard can run the command by itself, the index of a key it does
// not own, or -2 for a command that reaches every shard and so none alone.
int cache_instance::resp_first_foreign_key(uint32_t h, std::string_view* args, int argc) const
{
    if (h == fnv1a("eval") || h == fnv1a("evalsha"))
    {
        int64_t nkeys = 0;
        if (argc >= 3 && parse_int_sv(args[2], nkeys) && nkeys > 0 && nkeys <= argc - 3)
            return first_foreign_key(args, 3, static_cast<int>(nkeys), 1);
        return -1;
    }
    if (h == fnv1a("xread") || h == fnv1a("xreadgroup"))
    {
        const stream_read_keys k = find_stream_read_keys(args, argc);
        return k.count > 0 ? first_foreign_key(args, k.first, k.count, 1) : -1;
    }
    if (cache_needs_one_shard(h) && argc >= 2)
    {
        const bool two = h == fnv1a("smove") || h == fnv1a("rename") ||
                         h == fnv1a("renamenx") || h == fnv1a("copy");
        return first_foreign_key(args, 1, two ? std::min(2, argc - 1) : argc - 1, 1);
    }
    switch (cache_classify_resp(h, argc))
    {
        case cache_cmd_class::connection:
        case cache_cmd_class::unknown:
            return -1;
        case cache_cmd_class::single_key:
            return argc > cache_key_arg(h) ? first_foreign_key(args, cache_key_arg(h), 1, 1) : -1;
        case cache_cmd_class::multi_key:
            if (h == fnv1a("mset") || h == fnv1a("msetnx"))
                return first_foreign_key(args, 1, argc - 1, 2);
            if (h == fnv1a("del") || h == fnv1a("unlink") || h == fnv1a("exists") ||
                h == fnv1a("touch") || h == fnv1a("mget"))
                return first_foreign_key(args, 1, argc - 1, 1);
            return -2;
        case cache_cmd_class::cursor_scan:
            return scan_cursor_owner(argc >= 2 ? args[1] : std::string_view{}) == m_shard_i
                ? -1 : -2;
        case cache_cmd_class::keyspace:
        case cache_cmd_class::fanout:
        case cache_cmd_class::stateful:
            return -2;
    }
    return -2;
}

void cache_instance::process_resp_command(client_connection* conn,
                                          std::string_view* args, int argc)
{
    if (SOCKETLEY_LIKELY(m_shard_n <= 1) || argc <= 0)
    {
        process_resp_command_local(conn, args, argc);
        return;
    }
    if (conn->fd >= 0 && !conn->cluster_port)
        ++m_stat_shared_cmds;

    const uint32_t h = fnv1a_lower(args[0]);

    // A transaction is queued and replayed by this shard alone, so inside one
    // -- and in the WATCH that guards it -- a command this shard cannot run by
    // itself is refused and the transaction with it, where routing it ran it
    // at once, outside the transaction, and answered it in the wrong place.
    const bool txn_verb = h == fnv1a("multi") || h == fnv1a("exec") ||
                          h == fnv1a("discard") || h == fnv1a("unwatch") ||
                          h == fnv1a("reset") || h == fnv1a("quit");
    if (SOCKETLEY_UNLIKELY((conn->in_multi && !txn_verb) || h == fnv1a("watch")))
    {
        const int away = (h == fnv1a("watch"))
            ? first_foreign_key(args, 1, argc - 1, 1)
            : resp_first_foreign_key(h, args, argc);
        if (away != -1)
        {
            if (conn->in_multi) conn->multi_broken = true;
            run_in_reply_order(conn, [&] {
                if (conn->cluster_port && away >= 0)
                    emit_moved(conn, args[away], cache_shard_of(args[away], m_shard_n), true);
                else
                    resp::encode_error_code_into(conn->response_buf,
                        "CROSSSLOT a transaction on a sharded cache may only "
                        "name keys of the shard it runs on");
            });
            return;
        }
        run_in_reply_order(conn, [&] { process_resp_command_local(conn, args, argc); });
        return;
    }

    // A client on the per-shard port is asking this node, so DBSIZE, KEYS,
    // SCAN and FLUSH answer for it alone, while a publish still fans out and a
    // single-key command is handled by -MOVED.
    if (SOCKETLEY_UNLIKELY(conn->cluster_port))
    {
        const cache_cmd_class cc = cache_classify_resp(h, argc);
        if (cc == cache_cmd_class::keyspace || cc == cache_cmd_class::cursor_scan)
        {
            run_in_reply_order(conn, [&] { process_resp_command_local(conn, args, argc); });
            return;
        }
    }

#ifndef SOCKETLEY_NO_LUA
    // EVAL is routed by the keys it DECLARES, because args[1] is the script.
    // Redis says a script may only touch keys it declared; here that is not a
    // convention but the routing itself, and a script reaching past its own
    // KEYS on a sharded cache would be reaching into another process's store.
    if (SOCKETLEY_UNLIKELY(h == fnv1a("eval") || h == fnv1a("evalsha")))
    {
        int64_t nkeys = 0;
        if (argc >= 3 && parse_int_sv(args[2], nkeys) && nkeys > 0 && nkeys <= argc - 3)
            if (route_all_keys_one_shard(conn, args, argc, 3, static_cast<int>(nkeys)))
                return;
    }

    // Set algebra reads several whole sets and answers one thing, so it cannot
    // be split into per-key parts the way MGET or DEL can: an intersection
    // computed on two shards separately is not an intersection.  Same rule as
    // EVAL therefore -- one shard owns all of it or the command is refused --
    // and Redis Cluster answers CROSSSLOT for exactly this reason.
    if (SOCKETLEY_UNLIKELY(cache_needs_one_shard(h)) && argc >= 2)
    {
        // SMOVE names two keys and then a member; RENAME and COPY name exactly
        // two and COPY may carry REPLACE after them; the set forms are all
        // keys, and for the STORE forms that includes the destination.
        const int nk = (h == fnv1a("smove") || h == fnv1a("rename")
                     || h == fnv1a("renamenx") || h == fnv1a("copy"))
                     ? 2 : argc - 1;
        if (route_all_keys_one_shard(conn, args, argc, 1, nk))
            return;
    }
#endif

    // XREAD answers several streams as one reply, so its streams have to be
    // one shard's, the rule EVAL and set algebra follow; a BLOCK waits where it
    // is served and a crossing is answered once, so it is served only at home.
    if (SOCKETLEY_UNLIKELY(h == fnv1a("xread") || h == fnv1a("xreadgroup")))
    {
        const stream_read_keys k = find_stream_read_keys(args, argc);
        if (k.count > 0)
        {
            if (!k.blocks)
            {
                if (route_all_keys_one_shard(conn, args, argc, k.first, k.count))
                    return;
            }
            else if (const int away = first_foreign_key(args, k.first, k.count, 1); away >= 0)
            {
                run_in_reply_order(conn, [&] {
                    if (conn->cluster_port)
                        emit_moved(conn, args[away], cache_shard_of(args[away], m_shard_n), true);
                    else
                        resp::encode_error_code_into(conn->response_buf,
                            "ERR a blocking read waits on the shard that owns its streams -- "
                            "connect to that shard's own cluster port to block on them");
                });
                return;
            }
        }
    }

    switch (cache_classify_resp(h, argc))
    {
        case cache_cmd_class::single_key:
        {
            const int ki = cache_key_arg(h);
            if (argc > ki && !args[ki].empty())
            {
                const uint32_t owner = cache_shard_of(args[ki], m_shard_n);
                note_key_owner(conn, owner);
                if (owner != m_shard_i)
                {
                    // The per-shard port's answer, because this client chose
                    // this shard out of the slot map and -MOVED corrects the
                    // map rather than hiding the mistake behind a crossing.
                    if (conn->cluster_port)
                    {
                        run_in_reply_order(conn, [&] {
                            emit_moved(conn, args[ki], owner, true);
                        });
                        return;
                    }

                    // The same gate the text router explains: a scratch
                    // connection has no later turn for a reply to arrive on.
                    if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
                    {
                        run_in_reply_order(conn, [&] {
                            emit_unrouted(conn, args[0], true,
                                          "names a key another shard owns, and "
                                          "this path cannot wait for it");
                        });
                        return;
                    }

                    // Rebuilt from the parsed arguments rather than forwarded
                    // as the bytes that arrived, because they are the same
                    // message and a length threaded down from the parse loop
                    // is a second fact to disagree about.  Into a kept string, since a foreign key's route_part()
                    // only appends it and nothing in between can reach here again.
                    rebuild_resp(m_cross_scratch, args, argc);
                    const uint32_t slot =
                        slot_open(conn, true, cache_merge::single, 1);
                    route_part(conn, owner, slot, 0, m_cross_scratch, true);
                    return;
                }
            }
            break;
        }

        case cache_cmd_class::multi_key:
        {
            // The crossing gate lives in explode_resp_multi, after the keys are known to be foreign.
            if (explode_resp_multi(conn, h, args, argc))
                return;
            break;
        }

        case cache_cmd_class::keyspace:
        {
            if (answer_from_table(conn, h, argc == 1, true))
                return;
            if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, args[0], true,
                                  "reads every shard's slice, and this path "
                                  "cannot wait for them");
                });
                return;
            }
            std::string raw;
            rebuild_resp(raw, args, argc);
            fan_all_shards(conn, h, raw, true);
            return;
        }

        case cache_cmd_class::cursor_scan:
        {
            const uint32_t owner =
                scan_cursor_owner(argc >= 2 ? args[1] : std::string_view{});
            if (owner == m_shard_i)
                break;
            if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, args[0], true,
                                  "resumes in another shard, and this path "
                                  "cannot wait for it");
                });
                return;
            }
            std::string raw;
            rebuild_resp(raw, args, argc);
            const uint32_t slot = slot_open(conn, true, cache_merge::single, 1);
            route_part(conn, owner, slot, 0, raw, true);
            return;
        }

        case cache_cmd_class::stateful:
            run_in_reply_order(conn, [&] {
                emit_unrouted(conn, args[0], true,
                              "is not routed across the shards of this cache");
            });
            return;

        case cache_cmd_class::fanout:
        {
            if (SOCKETLEY_UNLIKELY(!can_cross(conn)))
            {
                run_in_reply_order(conn, [&] {
                    emit_unrouted(conn, args[0], true,
                                  "has to reach every shard's subscribers, and "
                                  "this path cannot wait for them");
                });
                return;
            }
            std::string raw;
            rebuild_resp(raw, args, argc);
            if (argc < 2)
                fan_all_shards(conn, h, raw, true);
            else
                fan_publish(conn, h, raw, true, args[1]);
            return;
        }

        case cache_cmd_class::connection:
        case cache_cmd_class::unknown:
            break;
    }

    run_in_reply_order(conn, [&] { process_resp_command_local(conn, args, argc); });
}

#ifndef SOCKETLEY_NO_LUA
// What a script may not run, because each starts or ends a session the script
// cannot finish: EVAL inside EVAL recursed until the worker died, and MULTI or
// SUBSCRIBE left the caller's connection queueing or subscribed.
static bool refused_in_script(uint32_t h)
{
    switch (h)
    {
        case fnv1a("eval"):  case fnv1a("evalsha"): case fnv1a("script"):
        case fnv1a("multi"): case fnv1a("exec"):    case fnv1a("discard"):
        case fnv1a("watch"): case fnv1a("unwatch"):
        case fnv1a("subscribe"):  case fnv1a("unsubscribe"):
        case fnv1a("psubscribe"): case fnv1a("punsubscribe"):
        case fnv1a("quit"):  case fnv1a("reset"):   case fnv1a("hello"):
        case fnv1a("auth"):  case fnv1a("client"):
            return true;
        default:
            return false;
    }
}
#endif

void cache_instance::process_resp_command_local(client_connection* conn, std::string_view* args, int argc)
{
    if (SOCKETLEY_UNLIKELY(argc == 0))
        return;

    if (SOCKETLEY_UNLIKELY(m_fenced) && conn->fd >= 0)
    {
        refuse_fenced(conn, true);
        return;
    }

#ifndef SOCKETLEY_NO_LUA
    if (SOCKETLEY_UNLIKELY(m_script_depth > 0) && refused_in_script(fnv1a_lower(args[0])))
    {
        resp::encode_error_code_into(conn->response_buf,
            "ERR This Redis command is not allowed from script");
        return;
    }
#endif

    // Global rate limit check (across all connections)
    if (SOCKETLEY_UNLIKELY(!check_global_rate_limit()))
    {
        resp::encode_error_into(conn->response_buf, "rate limited");
        return;
    }

    // Rate limit check (usually disabled — rl_max == 0)
    if (SOCKETLEY_UNLIKELY(conn->rl_max > 0))
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
    stat_add(m_stat_total_messages, 1);

    // ─── WHAT A FOLLOWER CAN PUT BACK TOGETHER ──────────────────────────────
    // Both consumers of a replicated record -- a follower's link and this
    // cache's own journal replay -- hand the line to the text interpreter,
    // which splits on spaces and lets the LAST argument absorb whatever is
    // left.  So every argument but the last has to be free of spaces, or what
    // arrives is a different command with the same bytes.
    //
    // Measured, leader and follower side by side after `SET "a b" v`:
    //
    //     GET 'a b'   leader v        follower (nothing)
    //     GET 'a'     leader nothing  follower "b v"
    //     DBSIZE      4               4
    //
    // The follower did not lose a key: it INVENTED one, under a name no client
    // ever wrote, holding bytes no client ever stored there -- and the counts
    // match on both sides, so nothing looks wrong from outside.  A later read
    // of `a` against the follower answers "b v" and is believed.
    //
    // Not emitting it is the smaller wrong.  The leader keeps the key, the
    // follower does not have it, and the line below says so; a divergence you
    // can see beats one that answers.
    //
    // The complete repair is a record that carries its own field lengths, and
    // that is a wire format between a leader and a follower that may be
    // different builds -- not a thing to change quietly.  The text path does
    // not need it: there the client typed the line and the follower splits it
    // exactly as this leader did.
    auto repl_faithful = [](std::string_view* a, int n) {
        for (int i = 0; i + 1 < n; i++)
            if (a[i].find(' ') != std::string_view::npos) return false;
        return true;
    };
    auto repl_refuse = [&](std::string_view key) { repl_unfaithful(key); };

    // Helper: build text command from RESP args for replication
    auto repl = [&](std::string_view* a, int n) {
        if (!mutation_log_wanted()) return;
        if (SOCKETLEY_UNLIKELY(!repl_faithful(a, n)))
        { repl_refuse(n > 1 ? a[1] : std::string_view{}); return; }
        std::string cmd;
        for (int i = 0; i < n; i++) {
            if (i > 0) cmd += ' ';
            cmd.append(a[i].data(), a[i].size());
        }
        replicate_command(cmd);
    };

    // One record per unit, for the reason the comment below gives about SET:
    // the follower and the journal both read a text command, and its splitter
    // takes everything after the fixed fields as the last one.  So `LPUSH k a
    // b c` came back as the single element "a b c", and `ZREM z m1 m2` removed
    // nothing at all.  DEL and MSET have always emitted one record per unit
    // and so has dump_commands; these are the commands that had not caught up.
    //
    // `mid` is the field between the key and the last one -- a hash's field --
    // and is left empty by a command that has none; a caller that HAS one must
    // not pass it empty, because the reader would then take the last field for
    // it.
    auto repl_unit = [&](std::string_view verb, std::string_view key,
                         std::string_view mid, std::string_view last) {
        if (!mutation_log_wanted()) return;
        // Only the last field survives a space, because everything before it
        // is what the reader splits on -- repl_set_effect's rule, at a third
        // door.
        if (SOCKETLEY_UNLIKELY(key.find(' ') != std::string_view::npos ||
                               mid.find(' ') != std::string_view::npos))
        { repl_refuse(key); return; }
        std::string cmd;
        cmd.reserve(verb.size() + key.size() + mid.size() + last.size() + 3);
        cmd.append(verb);
        cmd.push_back(' ');
        cmd.append(key.data(), key.size());
        if (!mid.empty())
        {
            cmd.push_back(' ');
            cmd.append(mid.data(), mid.size());
        }
        cmd.push_back(' ');
        cmd.append(last.data(), last.size());
        replicate_command(cmd);
    };

    // SET replicates its effect rather than its command, because repl() joins
    // arguments with spaces and the text interpreter takes everything after
    // the key as the value -- so `SET rk rv EX 100` reached the follower as
    // the value "rv EX 100" with no expiry.
    auto repl_set_effect = [&](std::string_view key, std::string_view val,
                               int64_t ex_sec, int64_t px_ms) {
        if (!mutation_log_wanted()) return;
        // The key is not the last field here, so a space in it moves the
        // boundary the follower reads -- same rule, stated at the second door.
        if (SOCKETLEY_UNLIKELY(key.find(' ') != std::string_view::npos))
        { repl_refuse(key); return; }

        std::string cmd;
        cmd.reserve(5 + key.size() + val.size());
        cmd += "set ";
        cmd.append(key.data(), key.size());
        cmd += ' ';
        cmd.append(val.data(), val.size());
        replicate_command(cmd);

        // Saturating, because ex_sec is the client's int64 now that SET no
        // longer shields itself behind an `int` that could not hold one.
        constexpr int64_t far = std::numeric_limits<int64_t>::max();
        const int64_t ms = px_ms > 0 ? px_ms
                         : ex_sec > far / 1000 ? far
                         : ex_sec > 0 ? ex_sec * 1000 : 0;
        if (ms > 0)
        {
            std::string ttl_cmd = "pexpire ";
            ttl_cmd.append(key.data(), key.size());
            ttl_cmd += ' ';
            ttl_cmd += std::to_string(ms);
            replicate_command(ttl_cmd);
        }
    };

    // Dispatch via case-insensitive FNV-1a — no string allocation
    auto& rb = conn->response_buf;

    // EXPIRE's whole answer, for all four spellings: 0 when there was no key,
    // 1 when there was -- and the deletion is replicated exactly like the
    // arming, because a follower that skipped it keeps a key the leader
    // dropped.  Before, EXPIREAT and PEXPIREAT answered 1 for a key that had
    // never existed AND replicated that, so a follower was told about a
    // deadline for nothing.
    // The record carries no NX/XX/GT/LT, because the leader has decided and
    // the follower is only told the outcome.
    const auto answered_expire = [&](cache_store::expire_result r) {
        if (r == cache_store::expire_result::no_such_key)
        { resp::encode_integer_into(rb, 0); return; }
        if (r == cache_store::expire_result::armed) mark_ttl_keys();
        repl(args, argc < 3 ? argc : 3);
        resp::encode_integer_into(rb, 1);
    };

    // EXPIRE's NX, XX, GT and LT, which were read past and so always set:
    // `EXPIRE k 10 NX` replaced the TTL it was told to leave alone.  1 is go,
    // 0 is a refusal to answer 0 for, -1 an error already answered; a key with
    // no TTL is an infinite one, so GT never moves it and LT always does.
    const auto expire_condition = [&](int64_t new_rel_ms) -> int {
        bool nx = false, xx = false, gt = false, lt = false;
        for (int i = 3; i < argc; ++i)
        {
            const uint32_t o = fnv1a_lower(args[i]);
            if      (o == fnv1a("nx")) nx = true;
            else if (o == fnv1a("xx")) xx = true;
            else if (o == fnv1a("gt")) gt = true;
            else if (o == fnv1a("lt")) lt = true;
            else
            {
                resp::encode_error_into(rb, "Unsupported option " + std::string(args[i]));
                return -1;
            }
        }
        if ((nx && (xx || gt || lt)) || (gt && lt))
        {
            resp::encode_error_into(rb, "NX and XX, GT or LT options at the same time "
                                        "are not compatible");
            return -1;
        }
        if (!(nx || xx || gt || lt))
            return 1;
        if (m_has_ttl_keys) m_store.check_expiry(args[1]);
        const int64_t cur = m_store.get_pttl(args[1]);
        if (cur == -2) return 1;                    // expire_in answers the missing key
        if (nx && cur != -1) return 0;
        if (xx && cur == -1) return 0;
        if (gt && (cur == -1 || new_rel_ms <= cur)) return 0;
        if (lt && cur != -1 && new_rel_ms >= cur) return 0;
        return 1;
    };
    const auto ms_of = [](int64_t sec) {
        return sec > INT64_MAX / 1000 ? INT64_MAX : sec < INT64_MIN / 1000 ? INT64_MIN : sec * 1000;
    };
    const auto expire_gated = [&](int64_t new_rel_ms) {
        const int c = expire_condition(new_rel_ms);
        if (c == 0) resp::encode_integer_into(rb, 0);
        return c == 1;
    };

    // One place turns the store's three answers into a reply, because four
    // commands share them and INCR wording the overflow differently from
    // DECRBY is the split this file has paid for before.  True means the write
    // happened, and is the caller's cue to replicate it.
    //
    // Every caller names the store call on its own line first: see the text
    // twin for what folding it into the argument list cost.
    const auto answered_incr = [&rb](cache_store::incr_result st, int64_t result) {
        if (st == cache_store::incr_result::ok)
        { resp::encode_integer_into(rb, result); return true; }
        if (st == cache_store::incr_result::wrong_type)
            resp::encode_error_code_into(rb, wrongtype_msg);
        else if (st == cache_store::incr_result::out_of_memory)
            resp::encode_error_code_into(rb, oom_msg);
        else
            resp::encode_error_into(rb, st == cache_store::incr_result::would_overflow
                ? "increment or decrement would overflow"
                : "value is not an integer or out of range");
        return false;
    };

    // ── MULTI, over RESP ────────────────────────────────────────────────────
    // The same queue the text protocol fills, with the one difference RESP
    // forces: EXEC answers ONE array holding every reply, so the replies are
    // built into a scratch buffer and counted before the header can be
    // written.
    {
        const uint32_t mh = fnv1a_lower(args[0]);
        if (mh == fnv1a("multi"))
        {
            if (conn->in_multi) { resp::encode_error_into(rb, "MULTI calls can not be nested"); return; }
            conn->in_multi = true; conn->multi_broken = false;
            conn->multi_queue.clear(); conn->multi_bytes = 0;
            resp::encode_simple_into(rb, "OK");
            return;
        }
        if (mh == fnv1a("watch"))
        {
            // Redis refuses it inside MULTI, because a watch taken after the
            // queue started could not be checked against the reads that
            // decided what to queue.
            if (conn->in_multi) { resp::encode_error_into(rb, "WATCH inside MULTI is not allowed"); return; }
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            watch_keys(conn, args, argc);
            resp::encode_ok_into(rb);
            return;
        }
        if (mh == fnv1a("unwatch"))
        {
            unwatch_all(conn);
            resp::encode_ok_into(rb);
            return;
        }
        if (mh == fnv1a("discard"))
        {
            if (!conn->in_multi) { resp::encode_error_into(rb, "DISCARD without MULTI"); return; }
            unwatch_all(conn);
            conn->in_multi = false; conn->multi_broken = false;
            conn->multi_queue.clear(); conn->multi_bytes = 0;
            resp::encode_simple_into(rb, "OK");
            return;
        }
        // RESET and QUIT run even inside MULTI, where everything else is
        // queued.  RESET queued is RESET not happening: a pooling client sends
        // it precisely because it does not know what state a connection is in,
        // and if a stray MULTI is that state then the one command meant to
        // clear it would be filed behind the mess.  redis-server answers
        // +RESET at once and then "EXEC without MULTI" -- the transaction is
        // gone, not queued.  Both protocols, because both have the queue.
        if (conn->in_multi && mh != fnv1a("exec")
                           && mh != fnv1a("reset") && mh != fnv1a("quit"))
        {
            std::string framed;
            rebuild_resp(framed, args, argc);
            if (conn->multi_queue.size() >= client_connection::MULTI_MAX_CMDS
                || conn->multi_bytes + framed.size() > client_connection::MULTI_MAX_BYTES)
            {
                conn->multi_broken = true;
                resp::encode_error_into(rb, "transaction too large");
                return;
            }
            conn->multi_bytes += framed.size();
            conn->multi_queue.emplace_back(std::move(framed));
            resp::encode_simple_into(rb, "QUEUED");
            return;
        }
        if (mh == fnv1a("exec"))
        {
            if (!conn->in_multi) { resp::encode_error_into(rb, "EXEC without MULTI"); return; }
            std::vector<std::string> queued;
            queued.swap(conn->multi_queue);
            const bool broken = conn->multi_broken;
            const bool dirty  = conn->watch_dirty;
            conn->in_multi = false; conn->multi_broken = false; conn->multi_bytes = 0;
            // Either way the watch is over: EXEC ends it whether it ran or
            // not, so a retry loop starts from a fresh WATCH rather than an
            // old one that is already dirty.
            unwatch_all(conn);
            if (dirty)
            {
                // A nil ARRAY and not a nil string: a client tells "the
                // transaction did not run" from "it ran and returned nothing"
                // by the type.
                rb.append("*-1\r\n", 5);
                return;
            }
            if (broken)
            {
                resp::encode_error_code_into(rb, "EXECABORT Transaction discarded because of previous errors.");
                return;
            }

            // The bound the OTHER RESP parse sites use, which is what the
            // comment here used to claim and was not: it said 64 while
            // MAX_RESP_ARGS at both of them is resp::RESP_MAX_ARRAY_SIZE,
            // 1024.  13a6b475 raised them -- "A RESP command with more than 64
            // arguments was a protocol error, and took the pipeline with it"
            // -- and this replay was missed.
            //
            // Measured at the boundary: MSET with 31 pairs queued and ran,
            // MSET with 32 answered +QUEUED and then "unparseable queued
            // command" at EXEC, while the identical command outside a
            // transaction answered +OK.
            static constexpr int QUEUED_MAX_ARGS = resp::RESP_MAX_ARRAY_SIZE;

            // Parsed through before anything runs, because the loop below used
            // to answer the error in place and carry on: a transaction of
            // three where the middle one was too long ran the other two and
            // told the client so in an array of three.  Measured -- `before`
            // was set, `after` was set, the MSET between them was not.
            //
            // "Nothing ran, because running part of what was asked is worse
            // than running none of it" is this cache's own rule, stated at the
            // line protocol's EXEC, and EXECABORT is how RESP says it.
            //
            // With the bound above matching the queue-time parse this arm is a
            // net rather than a path: a command that would not re-parse cannot
            // have been queued.  It is here so that the next time the two
            // bounds drift the answer is a refused transaction and not a
            // half-applied one, which is how this was found.
            std::vector<std::string_view> parsed;
            parsed.reserve(queued.size() * 4);
            std::vector<int> counts;
            counts.reserve(queued.size());
            for (const auto& q : queued)
            {
                std::string_view qargs[QUEUED_MAX_ARGS];
                int              qargc = 0;
                size_t           qconsumed = 0;
                if (resp::parse_message_views(q, qargs, QUEUED_MAX_ARGS, qargc,
                                              qconsumed, read_bulk_limit()) != resp::parse_result::ok
                    || qargc <= 0)
                {
                    resp::encode_error_code_into(
                        rb, "EXECABORT Transaction discarded because of previous errors.");
                    return;
                }
                counts.push_back(qargc);
                parsed.insert(parsed.end(), qargs, qargs + qargc);
            }

            // The replies are produced into the connection's own buffer, taken
            // away between commands, because that is the only buffer the
            // dispatch below writes to.
            std::string body;
            size_t at = 0;
            conn->in_exec = true;
            for (size_t i = 0; i < queued.size(); ++i)
            {
                std::string held;
                held.swap(rb);
                process_resp_command_local(conn, parsed.data() + at, counts[i]);
                at += static_cast<size_t>(counts[i]);
                body.append(rb);
                rb.swap(held);
            }
            conn->in_exec = false;
            resp::encode_array_header_into(rb, static_cast<int>(queued.size()));
            rb.append(body);
            return;
        }
    }

    // A command added here must be classified in cache_shard_map.h, because an
    // unnamed hash reads `unknown` and is served where it was asked -- right
    // for a command that does not exist and wrong for a real one.
    const uint32_t cmd_hash = fnv1a_lower(args[0]);

    // Whoever is watching what this may touch cannot commit any more.  Before
    // the switch and not inside forty cases, because a write that forgot to
    // say so is a transaction committing over a change it never saw -- and
    // silent.  Costs one empty() test when nobody is watching, which is the
    // usual state.
    note_write_for_watch(cmd_hash, args, argc);

    switch (cmd_hash)
    {
        case fnv1a("set"):
        {
            if (SOCKETLEY_UNLIKELY(argc < 3)) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (SOCKETLEY_UNLIKELY(m_mode == cache_mode_readonly)) { resp::encode_error_into(rb, "readonly mode"); return; }

            // Fast-path: plain SET key value (argc == 3, no options)
            // This is the overwhelmingly common case in benchmarks
            if (SOCKETLEY_LIKELY(argc == 3))
            {
                if (SOCKETLEY_UNLIKELY(!m_store.set(args[1], args[2])))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.set(args[1], args[2]))
                    {
                        auto t = m_store.type(args[1]);
                        if (t == "none" || t == "string")
                            resp::encode_error_code_into(rb,
                                "OOM command not allowed when used memory > 'maxmemory'");
                        else
                            resp::encode_error_code_into(rb, wrongtype_msg);
                        break;
                    }
                }
                rb.append(resp::RESP_OK, 5);
                repl(args, argc);
#ifndef SOCKETLEY_NO_LUA
                if (SOCKETLEY_UNLIKELY(lua() && lua()->has_on_write()))
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(args[1], args[2], 0);
                        lua_diag::raised(r, get_name(), "on_write");
                    }
                }
#endif
                break;
            }

            // Slow path: SET with NX/XX/EX/PX/KEEPTTL/GET options
            bool nx = false, xx = false, keepttl = false, want_old = false;
            int64_t ex_sec = 0;
            int64_t px_ms = 0;
            // Judged where it is read and before anything is written, because
            // `EX 0` stored the key with no deadline at all and said +OK.
            // The argument gets its own word: a number that will not parse is
            // not a syntax error about the word after it.
            const auto expire_arg = [&](int i, int64_t& out) {
                if (i + 1 >= argc)
                { resp::encode_error_into(rb, "syntax error"); return false; }
                if (!parse_int_sv(args[i+1], out))
                { resp::encode_error_into(rb, "value is not an integer or out of range"); return false; }
                if (out <= 0)
                { resp::encode_error_into(rb, "invalid expire time in 'set' command"); return false; }
                return true;
            };
            for (int i = 3; i < argc; i++)
            {
                switch (fnv1a_lower(args[i]))
                {
                    case fnv1a("ex"):
                        if (!expire_arg(i, ex_sec)) return;
                        i++;
                        break;
                    case fnv1a("px"):
                        if (!expire_arg(i, px_ms)) return;
                        i++;
                        break;
                    case fnv1a("nx"): nx = true; break;
                    case fnv1a("xx"): xx = true; break;
                    // A write clears the deadline unless this says otherwise,
                    // which is the flag a session refresh needs: the value
                    // changes and the hour it has left does not.
                    case fnv1a("keepttl"): keepttl = true; break;
                    // Answers the value SET replaced rather than +OK, so a
                    // caller reads and writes in one round trip.
                    case fnv1a("get"): want_old = true; break;
                    default:
                        // Refused rather than ignored, because `SET k v FOO`
                        // matched no case, fell through and reported success
                        // -- so EXX instead of EX gave a key with no expiry
                        // and an "+OK".
                        resp::encode_error_into(rb, "syntax error");
                        return;
                }
            }
            // KEEPTTL means "leave the deadline alone", and EX/PX mean "set
            // this one" -- asking for both is a contradiction Redis refuses
            // rather than resolving in one of the two directions.
            if (keepttl && (ex_sec > 0 || px_ms > 0))
            { resp::encode_error_into(rb, "syntax error"); return; }

            if (m_has_ttl_keys) m_store.check_expiry(args[1]);

            // Read before the write, because SET is what destroys it.  GET
            // reports the type conflict itself: a caller asking for the old
            // value of a list wants to hear that, not a null.
            std::string old_val;
            bool had_old = false;
            if (want_old)
            {
                if (m_store.type(args[1]) != "string" && m_store.exists(args[1]))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                had_old = m_store.get(args[1], old_val);
            }

            bool key_exists = m_store.exists(args[1]);
            if (nx && key_exists)
            {
                if (want_old && had_old) resp::encode_bulk_into(rb, old_val);
                else                     resp::encode_null_into(rb);
                break;
            }
            if (xx && !key_exists)
            {
                resp::encode_null_into(rb);
                break;
            }

            // The deadline as it stands, captured before set() drops it.
            const int64_t kept = keepttl ? m_store.get_pttl(args[1]) : -1;

            if (!m_store.set(args[1], args[2]))
            {
                encode_refusal(rb, m_store.type(args[1]), "string");
                break;
            }
            if (ex_sec > 0) { m_store.set_expiry(args[1], ex_sec); mark_ttl_keys(); }
            else if (px_ms > 0) { m_store.set_expiry_ms(args[1], px_ms); mark_ttl_keys(); }
            else if (keepttl && kept > 0) { m_store.set_expiry_ms(args[1], kept); mark_ttl_keys(); }

            if (want_old)
            {
                if (had_old) resp::encode_bulk_into(rb, old_val);
                else         resp::encode_null_into(rb);
            }
            else
                resp::encode_ok_into(rb);
            // KEEPTTL replicates the deadline it kept, because the follower's set drops one.
            repl_set_effect(args[1], args[2], ex_sec,
                            (keepttl && kept > 0) ? kept : px_ms);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[2], ex_sec);
                    lua_diag::raised(r, get_name(), "on_write");
                }
            }
#endif
            break;
        }
        case fnv1a("get"):
        {
            if (SOCKETLEY_UNLIKELY(argc < 2)) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            // Combined expiry check + lookup — one hash probe instead of two
            const std::string* val = m_store.check_expiry_and_get_ptr(args[1]);
            if (SOCKETLEY_LIKELY(val != nullptr))
            {
                m_stat_get_hits++;
                resp::encode_bulk_into(rb, *val);
            }
            else
            {
#ifndef SOCKETLEY_NO_LUA
                if (SOCKETLEY_UNLIKELY(lua() && lua()->has_on_miss()))
                {
                    // Checked before the result is read, because on a failed
                    // call index 0 is the error object and reading it would
                    // store a Lua error message in the cache as the fetched
                    // value.
                    sol::protected_function_result res = lua()->on_miss()(args[1]);
                    if (!lua_diag::raised(res, get_name(), "on_miss"))
                    {
                        sol::optional<std::string> fetched = res.get<sol::optional<std::string>>(0);
                        if (fetched && !fetched->empty())
                        {
                            int ttl = 0;
                            sol::optional<int> ttl_opt = res.get<sol::optional<int>>(1);
                            if (ttl_opt) ttl = *ttl_opt;
                            m_store.set(args[1], *fetched);
                            if (ttl > 0) { m_store.set_expiry(args[1], ttl); mark_ttl_keys(); }
                            m_stat_get_hits++;
                            resp::encode_bulk_into(rb, *fetched);
                            break;
                        }
                    }
                }
#endif
                m_stat_get_misses++;
                // A miss and a key of another type are two different answers,
                // and until this was here every read gave the first for both:
                // GET on a list replied nil, which a caller reads as "not
                // cached" and acts on.
                if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 's')))
                    resp::encode_error_code_into(rb, wrongtype_msg);
                else
                    rb.append(resp::RESP_NULL, 5);
            }
            break;
        }
        // UNLINK frees in the background on Redis and there is no background
        // here, so it is del's other spelling rather than a second path.
        case fnv1a("del"):
        case fnv1a("unlink"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int deleted = 0;
            for (int i = 1; i < argc; i++)
            {
                // del() succeeds on an already-expired key, so without this the
                // reply would count keys that Redis reports as absent.
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
                if (m_store.del(args[i]))
                {
                    deleted++;
#ifndef SOCKETLEY_NO_LUA
                    if (lua() && lua()->has_on_delete())
                    {
                        {
                            sol::protected_function_result r = lua()->on_delete_cb()(args[i]);
                            lua_diag::raised(r, get_name(), "on_delete");
                        }
                    }
#endif
                }
            }
            // One key per replicated command, because the text interpreter's
            // `del` takes the whole remainder as one key, so `DEL p1 p2`
            // deleted a key literally named "p1 p2" on the follower and left
            // both where they were.
            if (deleted > 0)
                for (int i = 1; i < argc; ++i)
                {
                    std::string one;
                    one.reserve(4 + args[i].size());
                    one += "del ";
                    one.append(args[i]);
                    replicate_command(one);
                }
            resp::encode_integer_into(rb, deleted);
            break;
        }
        // Every key given, counted with repeats -- Redis answers 2 for the same
        // key named twice, and answering for args[1] alone read as 1 for any
        // number of them.
        case fnv1a("exists"):
        case fnv1a("touch"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            int64_t found = 0;
            for (int i = 1; i < argc; ++i)
            {
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
                if (m_store.exists(args[i])) ++found;
            }
            resp::encode_integer_into(rb, found);
            break;
        }
        case fnv1a("incr"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t result = 0;
            const auto st = m_store.incr(args[1], 1, result);
            if (answered_incr(st, result)) repl(args, argc);
            break;
        }
        case fnv1a("decr"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t result = 0;
            const auto st = m_store.incr(args[1], -1, result);
            if (answered_incr(st, result)) repl(args, argc);
            break;
        }
        case fnv1a("incrby"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t delta = 0;
            if (!parse_int_sv(args[2], delta)) { resp::encode_error_into(rb, "value is not an integer or out of range"); return; }
            int64_t result = 0;
            const auto st = m_store.incr(args[1], delta, result);
            if (answered_incr(st, result)) repl(args, argc);
            break;
        }
        case fnv1a("decrby"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t delta = 0;
            if (!parse_int_sv(args[2], delta)) { resp::encode_error_into(rb, "value is not an integer or out of range"); return; }
            // The one refusal the store cannot make: INT64_MIN has no negation
            // in int64, so `-delta` is undefined BEFORE the call and there is
            // nothing left for incr()'s own guard to inspect.
            if (SOCKETLEY_UNLIKELY(delta == std::numeric_limits<int64_t>::min()))
            { resp::encode_error_into(rb, "decrement would overflow"); break; }
            int64_t result = 0;
            const auto st = m_store.incr(args[1], -delta, result);
            if (answered_incr(st, result)) repl(args, argc);
            break;
        }
        case fnv1a("append"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            size_t newlen = m_store.append(args[1], args[2]);
            if (newlen == cache_store::append_wrong_type)
                resp::encode_error_code_into(rb, wrongtype_msg);
            else if (newlen == cache_store::append_denied)
                resp::encode_error_code_into(rb, "OOM command not allowed when used memory > 'maxmemory'");
            else
            { resp::encode_integer_into(rb, static_cast<int64_t>(newlen)); repl(args, argc); }
            break;
        }
        case fnv1a("strlen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            {
                const size_t n = m_store.strlen_key(args[1]);
                if (SOCKETLEY_UNLIKELY(n == 0 && m_store.holds_other_type(args[1], 's')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_integer_into(rb, static_cast<int64_t>(n));
            }
            break;
        }
        case fnv1a("getset"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            // GETSET must return nil for an expired key, not its stale value.
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            bool had_key = m_store.exists(args[1]);
            std::string oldval;
            if (!m_store.getset(args[1], args[2], oldval))
                encode_refusal(rb, m_store.type(args[1]), "string");
            else
            {
                if (!had_key) resp::encode_null_into(rb);
                else resp::encode_bulk_into(rb, oldval);
                repl(args, argc);
            }
            break;
        }
        case fnv1a("mget"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            resp::encode_array_header_into(rb, argc - 1);
            for (int i = 1; i < argc; i++)
            {
                if ((i - 1) % cache_store::PREFETCH_BATCH == 0)
                    m_store.prefetch_keys(args + i, static_cast<size_t>(argc - i), 1);
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
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
            // Pairs go in order up to the first the store refuses, and only those reach a follower.
            int applied = argc;
            for (int i = 1; i + 1 < argc; i += 2)
            {
                if ((i - 1) / 2 % cache_store::PREFETCH_BATCH == 0)
                    m_store.prefetch_keys(args + i, static_cast<size_t>(argc - i), 2);
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
                if (!m_store.set(args[i], args[i+1]))
                {
                    encode_refusal(rb, m_store.type(args[i]), "string");
                    applied = i;
                    break;
                }
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_write())
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(args[i], args[i+1], 0);
                        lua_diag::raised(r, get_name(), "on_write");
                    }
                }
#endif
            }
            if (applied == argc) resp::encode_ok_into(rb);
            // One key per replicated command, for the reason the text spelling
            // gives above.
            for (int i = 1; i + 1 < applied; i += 2)
                repl_set_effect(args[i], args[i + 1], 0, 0);
            break;
        }
        case fnv1a("type"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
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
            if (SOCKETLEY_LIKELY(argc <= 1))
                rb.append(resp::RESP_PONG, 7);
            else
                resp::encode_bulk_into(rb, args[1]);
            break;
        }
        // The map a cluster client bootstraps from, answered in the local
        // dispatch and therefore on every port and at every shard count,
        // because every field is derived from two numbers each shard already
        // holds.
        case fnv1a("cluster"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            emit_cluster(conn, args[1], argc >= 3 ? args[2] : std::string_view{}, true);
            break;
        }
        // A follower of a --resp cache asks here; what follows is the replication stream, lines and not RESP.
        case fnv1a("replicate"):
        {
            handle_replicate_request(conn, argc >= 3 ? args[1] : std::string_view{},
                                     argc >= 3 ? args[2] : std::string_view{});
            return;
        }
        case fnv1a("dbsize"):
        {
            // dbsize [type t] -- the count of one map, answered from its size
            // rather than by walking it.  Same vocabulary as scan's type filter,
            // and a name no type has counts nothing rather than everything.
            if (argc >= 3 && fnv1a_lower(args[1]) == fnv1a("type"))
            {
                const int m = cache_store::scan_map_of_type(args[2]);
                resp::encode_integer_into(rb, m < 0 ? 0u : m_store.size_of_type(m));
                break;
            }
            resp::encode_integer_into(rb, m_store.size());
            break;
        }
        case fnv1a("lpush"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            for (int i = 2; i < argc; i++)
            {
                if (!m_store.lpush(args[1], args[i]))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.lpush(args[1], args[i]))
                    {
                        // A refusal after the first element is the store out of
                        // room, and what has been logged stands rather than
                        // being taken back.
                        encode_refusal(rb, m_store.type(args[1]), "list");
                        // The elements that did go in are owed to whoever waits on the key.
                        if (i > 2) while (wake_one_waiter(args[1])) {}
                        return;
                    }
                }
                repl_unit("lpush", args[1], {}, args[i]);
            }
            // The length INCLUDING what was just pushed, and only then the
            // waiters: a client blocked on this key takes an element, and a
            // reply counted after that would report a queue shorter than the
            // one the caller filled.
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            // N elements can free N waiters, so this runs until nobody is left
            // for this key or the list is empty again.
            while (wake_one_waiter(args[1])) {}
            break;
        }
        case fnv1a("rpush"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            for (int i = 2; i < argc; i++)
            {
                if (!m_store.rpush(args[1], args[i]))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.rpush(args[1], args[i]))
                    {
                        // A refusal after the first element is the store out of
                        // room, and what has been logged stands rather than
                        // being taken back.
                        encode_refusal(rb, m_store.type(args[1]), "list");
                        // The elements that did go in are owed to whoever waits on the key.
                        if (i > 2) while (wake_one_waiter(args[1])) {}
                        return;
                    }
                }
                repl_unit("rpush", args[1], {}, args[i]);
            }
            // The length INCLUDING what was just pushed, and only then the
            // waiters: a client blocked on this key takes an element, and a
            // reply counted after that would report a queue shorter than the
            // one the caller filled.
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            // N elements can free N waiters, so this runs until nobody is left
            // for this key or the list is empty again.
            while (wake_one_waiter(args[1])) {}
            break;
        }
        case fnv1a("lpop"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            if (argc >= 3)
            {
                resp_pop_count(conn, args, argc, true, rb);
                break;
            }
            if (m_store.pop_with(args[1], true, [&](std::string_view v) { resp::encode_bulk_into(rb, v); }))
                repl(args, 2);
            else if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'l')))
                resp::encode_error_code_into(rb, wrongtype_msg);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("rpop"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            if (argc >= 3)
            {
                resp_pop_count(conn, args, argc, false, rb);
                break;
            }
            if (m_store.pop_with(args[1], false, [&](std::string_view v) { resp::encode_bulk_into(rb, v); }))
                repl(args, 2);
            else if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'l')))
                resp::encode_error_code_into(rb, wrongtype_msg);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("llen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            {
                const int n = m_store.llen(args[1]);
                if (SOCKETLEY_UNLIKELY(n == 0 && m_store.holds_other_type(args[1], 'l')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_integer_into(rb, n);
            }
            break;
        }
        case fnv1a("lrange"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int start = 0, stop = 0;
            if (!parse_int_sv(args[2], start) || !parse_int_sv(args[3], stop)) { resp::encode_error_into(rb, "value is not an integer or out of range"); return; }
            const auto* deq = m_store.list_ptr(args[1]);
            if (!deq || deq->empty())
            {
                if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'l')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_array_header_into(rb, 0); break;
            }
            int len = static_cast<int>(deq->size());
            if (start < 0) start += len;
            if (stop < 0) stop += len;
            if (start < 0) start = 0;
            if (stop >= len) stop = len - 1;
            int result_len = (start > stop) ? 0 : (stop - start + 1);
            resp::encode_array_header_into(rb, result_len);
            if (start <= stop)
            {
                auto e = deq->iterator_at(static_cast<size_t>(start));
                for (int i = start; i <= stop; i++, ++e)
                    resp::encode_bulk_into(rb, *e);
            }
            break;
        }
        case fnv1a("lindex"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int idx = 0;
            if (!parse_int_sv(args[2], idx)) { resp::encode_error_into(rb, "value is not an integer or out of range"); return; }
            const auto val = m_store.lindex(args[1], idx);
            if (val) resp::encode_bulk_into(rb, *val);
            else if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'l')))
                resp::encode_error_code_into(rb, wrongtype_msg);
            else resp::encode_null_into(rb);
            break;
        }
        // ─── Sorted sets, over RESP ─────────────────────────────────────
        // ZADD takes score/member pairs, which is why the arity is checked as
        // an even remainder rather than a minimum.
        case fnv1a("zadd"):
        {
            // NX, XX, GT, LT and CH ahead of the pairs, which were counted as
            // pairs: `ZADD z NX 1 a` answered wrong-number-of-arguments and
            // `ZADD z GT CH 1 a` "not a valid float".
            bool znx = false, zxx = false, zgt = false, zlt = false, zch = false;
            int zfirst = 2;
            for (; zfirst < argc; ++zfirst)
            {
                const uint32_t o = fnv1a_lower(args[zfirst]);
                if      (o == fnv1a("nx")) znx = true;
                else if (o == fnv1a("xx")) zxx = true;
                else if (o == fnv1a("gt")) zgt = true;
                else if (o == fnv1a("lt")) zlt = true;
                else if (o == fnv1a("ch")) zch = true;
                else if (o == fnv1a("incr"))
                { resp::encode_error_into(rb, "ZADD INCR is not supported by this cache; use ZINCRBY"); return; }
                else break;
            }
            if ((znx && zxx) || (zgt && zlt) || (znx && (zgt || zlt)))
            { resp::encode_error_into(rb, "GT, LT, and/or NX options at the same time are not compatible"); return; }
            if (argc - zfirst < 2 || ((argc - zfirst) % 2) != 0)
            { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly)
            { resp::encode_error_into(rb, "readonly mode"); return; }
            // Every score parsed before any pair is stored, the way zincrby
            // below does it and the way every other numeric mutator here does:
            // the refusal used to land after earlier pairs were already in and
            // jumped over the repl() nine lines down, so those members stayed
            // on this leader and no follower was ever told.
            std::vector<double> zscores;
            zscores.reserve(static_cast<size_t>((argc - zfirst) / 2));
            for (int i = zfirst; i + 1 < argc; i += 2)
            {
                double zsc = 0.0;
                if (!parse_double_sv(args[i], zsc))
                { resp::encode_error_into(rb, "value is not a valid float"); return; }
                zscores.push_back(zsc);
            }
            // The key is not the last field of a `zadd` record, so a space in
            // it moves the boundary the follower splits on -- the same rule
            // repl_set_effect states at the other door.
            bool zlog = mutation_log_wanted();
            if (SOCKETLEY_UNLIKELY(zlog &&
                                   args[1].find(' ') != std::string_view::npos))
            { repl_refuse(args[1]); zlog = false; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int zadded = 0;
            // The member's current score is only asked for by a flag.
            const bool zask = znx || zxx || zgt || zlt || zch;
            for (size_t zi = 0; zi < zscores.size(); ++zi)
            {
                const int i = zfirst + static_cast<int>(zi) * 2;
                double zcur = 0.0;
                const bool zhad = zask && m_store.zscore(args[1], args[i + 1], zcur);
                if ((znx && zhad) || (zxx && !zhad) ||
                    (zhad && zgt && !(zscores[zi] > zcur)) ||
                    (zhad && zlt && !(zscores[zi] < zcur)))
                    continue;
                const int zn = m_store.zadd(args[1], zscores[zi], args[i + 1]);
                // A refusal this late is the store out of room, and whatever
                // was logged below stands rather than diverging.
                if (zn < 0)
                { encode_refusal(rb, m_store.type(args[1]), "zset"); return; }
                zadded += (zch && zhad && zcur != zscores[zi]) ? 1 : zn;
                // One pair per record, like DEL and MSET and like
                // dump_commands, because the text interpreter takes the whole
                // remainder as the member: `ZADD z 1 a 2 b` reached a follower
                // as the single member "a 2 b" scored 1.
                if (zlog)
                {
                    std::string one;
                    one.reserve(8 + args[1].size() + args[i + 1].size());
                    one += "zadd ";
                    one.append(args[1].data(), args[1].size());
                    one += ' ';
                    one += score_text(zscores[zi]);
                    one += ' ';
                    one.append(args[i + 1].data(), args[i + 1].size());
                    replicate_command(one);
                }
            }
            resp::encode_integer_into(rb, zadded);
            break;
        }
        case fnv1a("zrem"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly)
            { resp::encode_error_into(rb, "readonly mode"); return; }
            m_store.check_expiry(args[1]);
            int zgone = 0;
            for (int i = 2; i < argc; i++)
                if (m_store.zrem(args[1], args[i]))
                {
                    zgone++;
                    repl_unit("zrem", args[1], {}, args[i]);
                }
            if (SOCKETLEY_UNLIKELY(zgone == 0 && m_store.holds_other_type(args[1], 'z')))
            { resp::encode_error_code_into(rb, wrongtype_msg); break; }
            resp::encode_integer_into(rb, zgone);
            break;
        }
        case fnv1a("zscore"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            double zsc = 0.0;
            if (!m_store.zscore(args[1], args[2], zsc))
            {
                if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'z')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_null_into(rb); break;
            }
            std::string zs;
            append_score_bare(zs, zsc);
            resp::encode_bulk_into(rb, zs);
            break;
        }
        case fnv1a("zcard"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            {
                const size_t n = m_store.zcard(args[1]);
                if (SOCKETLEY_UNLIKELY(n == 0 && m_store.holds_other_type(args[1], 'z')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_integer_into(rb, static_cast<int64_t>(n));
            }
            break;
        }
        case fnv1a("zrank"):
        case fnv1a("zrevrank"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            m_store.check_expiry(args[1]);
            size_t zr = 0;
            if (!m_store.zrank(args[1], args[2], zr, fnv1a_lower(args[0]) == fnv1a("zrevrank")))
            {
                if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'z')))
                    resp::encode_error_code_into(rb, wrongtype_msg);
                else
                    resp::encode_null_into(rb);
                break;
            }
            resp::encode_integer_into(rb, static_cast<int64_t>(zr));
            break;
        }
        case fnv1a("zrange"):
        case fnv1a("zrevrange"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            // Every option parsed or refused, because the ones this read past
            // -- REV, BYSCORE, LIMIT -- came back as an ascending rank range
            // with no error, which is wrong data a client cannot tell apart.
            const bool plain = fnv1a_lower(args[0]) == fnv1a("zrange");
            bool zwith = false, zrev = !plain, byscore = false, limited = false;
            int64_t off = 0, cnt = -1;
            for (int i = 4; i < argc; ++i)
            {
                const uint32_t o = fnv1a_lower(args[i]);
                if (o == fnv1a("withscores")) zwith = true;
                else if (plain && o == fnv1a("rev")) zrev = true;
                else if (plain && o == fnv1a("byscore")) byscore = true;
                else if (plain && o == fnv1a("limit") && i + 2 < argc &&
                         parse_int_sv(args[i + 1], off) && parse_int_sv(args[i + 2], cnt))
                { limited = true; i += 2; }
                else if (plain && o == fnv1a("bylex"))
                { resp::encode_error_into(rb, "BYLEX is not supported by this cache"); return; }
                else { resp::encode_error_into(rb, "syntax error"); return; }
            }
            if (limited && !byscore)
            {
                resp::encode_error_into(rb, "syntax error, LIMIT is only supported in "
                                            "combination with either BYSCORE or BYLEX");
                return;
            }
            m_store.check_expiry(args[1]);
            std::vector<std::pair<std::string_view, double>> zitems;
            if (byscore)
            {
                // REV names the range from its high end, as Redis spells it.
                double lo = 0, hi = 0; bool lo_in = true, hi_in = true;
                if (!parse_score_bound(zrev ? args[3] : args[2], lo, lo_in)
                 || !parse_score_bound(zrev ? args[2] : args[3], hi, hi_in))
                { resp::encode_error_code_into(rb, "ERR min or max is not a float"); break; }
                m_store.zrangebyscore(args[1], lo, hi, lo_in, hi_in, zrev, zitems);
                apply_zlimit(zitems, off, cnt);
            }
            else
            {
                int64_t zstart = 0, zstop = 0;
                if (!parse_int_sv(args[2], zstart) || !parse_int_sv(args[3], zstop))
                { resp::encode_error_into(rb, "value is not an integer or out of range"); return; }
                m_store.zrange(args[1], zstart, zstop, zitems, zrev);
            }
            resp::encode_array_header_into(rb, static_cast<int>(zitems.size())
                                             * (zwith ? 2 : 1));
            for (const auto& [zm, zsc] : zitems)
            {
                resp::encode_bulk_into(rb, zm);
                if (zwith)
                {
                    std::string zs;
                    append_score_bare(zs, zsc);
                    resp::encode_bulk_into(rb, zs);
                }
            }
            break;
        }
        case fnv1a("zincrby"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly)
            { resp::encode_error_into(rb, "readonly mode"); return; }
            double zd = 0.0;
            if (!parse_double_sv(args[2], zd))
            { resp::encode_error_into(rb, "value is not a valid float"); return; }
            m_store.check_expiry(args[1]);
            double zout = 0.0;
            switch (m_store.zincrby(args[1], zd, args[3], zout))
            {
                case cache_store::zincr_result::ok: break;
                case cache_store::zincr_result::not_a_number:
                    resp::encode_error_into(rb, "resulting score is not a number (NaN)");
                    return;
                case cache_store::zincr_result::type_conflict:
                    encode_refusal(rb, m_store.type(args[1]), "zset"); return;
            }
            repl(args, argc);
            std::string zs;
            append_score_bare(zs, zout);
            resp::encode_bulk_into(rb, zs);
            break;
        }
        case fnv1a("sadd"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int added = 0;
            for (int i = 2; i < argc; i++)
            {
                int r = m_store.sadd(args[1], args[i]);
                if (r < 0)
                {
                    m_store.check_expiry(args[1]);
                    r = m_store.sadd(args[1], args[i]);
                    // A refusal after the first member is the store out of
                    // room, and what has been logged stands.
                    if (r < 0) { encode_refusal(rb, m_store.type(args[1]), "set"); return; }
                }
                added += r;
                if (r > 0)
                    repl_unit("sadd", args[1], {}, args[i]);
            }
            resp::encode_integer_into(rb, added);
            break;
        }
        case fnv1a("srem"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int removed = 0;
            for (int i = 2; i < argc; i++)
                if (m_store.srem(args[1], args[i]))
                {
                    removed++;
                    repl_unit("srem", args[1], {}, args[i]);
                }
            if (SOCKETLEY_UNLIKELY(removed == 0 && m_store.holds_other_type(args[1], 't')))
            { resp::encode_error_code_into(rb, wrongtype_msg); break; }
            resp::encode_integer_into(rb, removed);
            break;
        }
        case fnv1a("sismember"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            if (SOCKETLEY_UNLIKELY(!m_store.sismember(args[1], args[2])
                                   && m_store.holds_other_type(args[1], 't')))
            { resp::encode_error_code_into(rb, wrongtype_msg); break; }
            resp::encode_integer_into(rb, m_store.sismember(args[1], args[2]) ? 1 : 0);
            break;
        }
        case fnv1a("scard"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            {
                const int n = m_store.scard(args[1]);
                if (SOCKETLEY_UNLIKELY(n == 0 && m_store.holds_other_type(args[1], 't')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_integer_into(rb, n);
            }
            break;
        }
        case fnv1a("smembers"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const auto* s = m_store.set_ptr(args[1]);
            if (!s)
            {
                if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 't')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_array_header_into(rb, 0); break;
            }
            resp::encode_array_header_into(rb, static_cast<int>(s->size()));
            for (const auto& member : *s)
                resp::encode_bulk_into(rb, member);
            break;
        }
        case fnv1a("flushall"):
        case fnv1a("flushdb"):
        {
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            // ASYNC and SYNC are accepted and both mean the same here: the
            // store is freed inline, and a client that asks for ASYNC gets the
            // answer it expects rather than an argument error.
            m_store.flush_all();
            m_has_ttl_keys = false;
            repl(args, argc);
            resp::encode_ok_into(rb);
            break;
        }

        // ─── Whole-key operations ───────────────────────────────────────
        case fnv1a("rename"):
        case fnv1a("renamenx"):
        {
            if (argc != 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) { m_store.check_expiry(args[1]); m_store.check_expiry(args[2]); }
            const bool nx = (cmd_hash == fnv1a("renamenx"));
            const int r = m_store.rename_key(args[1], args[2], nx);
            // Redis answers an error and not a zero for a missing source, and a
            // client distinguishes the two: "there was nothing to rename" is
            // not "the destination was in the way".
            if (r == -2) { resp::encode_error_into(rb, "no such key"); break; }
            repl(args, argc);
            if (nx) resp::encode_integer_into(rb, r);
            else    resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("copy"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            bool replace = false;
            for (int i = 3; i < argc; ++i)
                if (fnv1a_lower(args[i]) == fnv1a("replace")) replace = true;
            if (m_has_ttl_keys) { m_store.check_expiry(args[1]); m_store.check_expiry(args[2]); }
            const int r = m_store.copy_key(args[1], args[2], replace);
            // A missing source is 0 here and not an error: COPY answers whether
            // it copied, which is the shape a client tests.  Want of room is
            // the error Redis gives a denyoom command.
            if (r == -3)
            {
                resp::encode_error_code_into(rb, "OOM command not allowed when used memory > 'maxmemory'");
                break;
            }
            if (r > 0) repl(args, argc);
            resp::encode_integer_into(rb, r > 0 ? 1 : 0);
            break;
        }
        case fnv1a("randomkey"):
        {
            // Answered by whichever shard was asked, as Redis Cluster does: a
            // key drawn from the whole ring would need every shard to be asked
            // and one of them to be picked, and no client expects that.
            const std::string_view k = m_store.random_key();
            if (k.empty()) resp::encode_null_into(rb);
            else           resp::encode_bulk_into(rb, k);
            break;
        }
        case fnv1a("expiretime"):
        case fnv1a("pexpiretime"):
        {
            if (argc != 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb,
                m_store.expire_time(args[1], cmd_hash == fnv1a("pexpiretime")));
            break;
        }

        // ─── Set algebra ────────────────────────────────────────────────
        //
        // The reading forms and the STORE forms share their body, because the
        // only difference is where the answer goes -- and a second copy of the
        // union rules is a second place for them to disagree.
        case fnv1a("sinter"):      case fnv1a("sunion"):      case fnv1a("sdiff"):
        case fnv1a("sinterstore"): case fnv1a("sunionstore"): case fnv1a("sdiffstore"):
        {
            const bool store = (cmd_hash == fnv1a("sinterstore")
                             || cmd_hash == fnv1a("sunionstore")
                             || cmd_hash == fnv1a("sdiffstore"));
            const int first = store ? 2 : 1;
            if (argc < first + 1) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (store && m_mode == cache_mode_readonly)
            { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys)
                for (int i = first; i < argc; ++i) m_store.check_expiry(args[i]);

            std::vector<std::string> out;
            const size_t n = static_cast<size_t>(argc - first);
            int rc;
            if (cmd_hash == fnv1a("sinter") || cmd_hash == fnv1a("sinterstore"))
                rc = m_store.sinter(args + first, n, out);
            else if (cmd_hash == fnv1a("sunion") || cmd_hash == fnv1a("sunionstore"))
                rc = m_store.sunion(args + first, n, out);
            else
                rc = m_store.sdiff(args + first, n, out);
            if (rc < 0) { resp::encode_error_code_into(rb, wrongtype_msg); break; }

            if (!store)
            {
                resp::encode_array_header_into(rb, static_cast<int>(out.size()));
                for (const auto& m : out) resp::encode_bulk_into(rb, m);
                break;
            }
            const size_t card = m_store.sreplace(args[1], std::move(out));
            if (card == cache_store::sreplace_refused) { resp::encode_error_code_into(rb, oom_msg); break; }
            // Replicated as the command, not as the result: the follower holds
            // the same sets, so it computes the same answer -- and shipping the
            // members would be the whole result on the wire for every call.
            repl(args, argc);
            resp::encode_integer_into(rb, static_cast<int64_t>(card));
            break;
        }
        case fnv1a("smove"):
        {
            if (argc != 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) { m_store.check_expiry(args[1]); m_store.check_expiry(args[2]); }
            const int r = m_store.smove(args[1], args[2], args[3]);
            if (r < 0) { resp::encode_error_code_into(rb, wrongtype_msg); break; }
            if (r > 0) repl(args, argc);
            resp::encode_integer_into(rb, r);
            break;
        }
        // HMSET is HSET answered +OK, and the two names differ in length, so
        // one body serves both and its type check and replication with it.
        case fnv1a("hmset"):
        case fnv1a("hset"):
        {
            const bool answer_ok = args[0].size() == 5;
            if (argc < 4 || (argc - 2) % 2 != 0)
            {
                resp::encode_error_into(rb, "wrong number of arguments");
                return;
            }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int added = 0;
            for (int i = 2; i + 1 < argc; i += 2)
            {
                bool created = false;
                if (!m_store.hset(args[1], args[i], args[i+1], &created))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.hset(args[1], args[i], args[i+1], &created))
                    {
                        // Same as SET: a memory refusal is not a type conflict,
                        // and overwriting a field can now be refused for room.
                        auto t = m_store.type(args[1]);
                        if (t == "none" || t == "hash")
                            resp::encode_error_code_into(rb,
                                "OOM command not allowed when used memory > 'maxmemory'");
                        else
                            resp::encode_error_code_into(rb, wrongtype_msg);
                        return;
                    }
                }
                added += created;
                // An empty field would be read as the value by a reader that
                // splits on spaces, so it goes the way a key with a space in it
                // goes rather than as a record that means something else.
                if (SOCKETLEY_UNLIKELY(args[i].empty()))
                    { if (mutation_log_wanted()) repl_refuse(args[1]); continue; }
                repl_unit("hset", args[1], args[i], args[i + 1]);
            }
            if (answer_ok) resp::encode_ok_into(rb);
            else           resp::encode_integer_into(rb, added);
            break;
        }
        case fnv1a("hget"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const auto val = m_store.hget(args[1], args[2]);
            if (val) resp::encode_bulk_into(rb, *val);
            else if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'h')))
                resp::encode_error_code_into(rb, wrongtype_msg);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("hdel"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int removed = 0;
            for (int i = 2; i < argc; i++)
                if (m_store.hdel(args[1], args[i]))
                {
                    removed++;
                    repl_unit("hdel", args[1], {}, args[i]);
                }
            if (SOCKETLEY_UNLIKELY(removed == 0 && m_store.holds_other_type(args[1], 'h')))
            { resp::encode_error_code_into(rb, wrongtype_msg); break; }
            resp::encode_integer_into(rb, removed);
            break;
        }
        case fnv1a("hlen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            {
                const int n = m_store.hlen(args[1]);
                if (SOCKETLEY_UNLIKELY(n == 0 && m_store.holds_other_type(args[1], 'h')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_integer_into(rb, n);
            }
            break;
        }
        case fnv1a("hgetall"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const auto* h = m_store.hash_ptr(args[1]);
            if (!h)
            {
                if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'h')))
                { resp::encode_error_code_into(rb, wrongtype_msg); break; }
                resp::encode_array_header_into(rb, 0); break;
            }
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
            // Zero and negative are not refused: Redis deletes the key and
            // says 1, and a caller whose TTL arithmetic came out at zero means
            // "gone now", not "this call was a mistake".
            int64_t sec = 0;
            if (!parse_int_sv(args[2], sec)) { resp::encode_error_into(rb, "invalid seconds"); return; }
            if (!expire_gated(ms_of(sec))) break;
            answered_expire(m_store.expire_in(args[1], sec, false));
            break;
        }
        case fnv1a("ttl"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            const int64_t ms = m_store.expire_then_pttl(args[1]);
            resp::encode_integer_into(rb, ms < 0 ? ms : (ms + 500) / 1000);
            break;
        }
        case fnv1a("persist"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_store.persist(args[1]))
            { repl(args, argc); resp::encode_integer_into(rb, 1); }
            else
                resp::encode_integer_into(rb, 0);
            break;
        }
        case fnv1a("setnx"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            bool did_set = m_store.setnx(args[1], args[2]);
            if (did_set) repl(args, argc);
            resp::encode_integer_into(rb, did_set ? 1 : 0);
#ifndef SOCKETLEY_NO_LUA
            if (did_set && lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[2], 0);
                    lua_diag::raised(r, get_name(), "on_write");
                }
            }
#endif
            break;
        }
        case fnv1a("setex"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int sec = 0;
            if (!parse_int_sv(args[2], sec) || sec <= 0) { resp::encode_error_into(rb, "invalid expire time in SETEX"); return; }
            if (!m_store.set(args[1], args[3]))
            {
                m_store.check_expiry(args[1]);
                if (!m_store.set(args[1], args[3]))
                { encode_refusal(rb, m_store.type(args[1]), "string"); return; }
            }
            m_store.set_expiry(args[1], sec);
            mark_ttl_keys();
            resp::encode_ok_into(rb);
            repl(args, argc);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[3], sec);
                    lua_diag::raised(r, get_name(), "on_write");
                }
            }
#endif
            break;
        }
        case fnv1a("psetex"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t ms = 0;
            if (!parse_int_sv(args[2], ms) || ms <= 0) { resp::encode_error_into(rb, "invalid expire time in PSETEX"); return; }
            if (!m_store.set(args[1], args[3]))
            {
                m_store.check_expiry(args[1]);
                if (!m_store.set(args[1], args[3]))
                { encode_refusal(rb, m_store.type(args[1]), "string"); return; }
            }
            m_store.set_expiry_ms(args[1], ms);
            mark_ttl_keys();
            resp::encode_ok_into(rb);
            repl(args, argc);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[3], 0);
                    lua_diag::raised(r, get_name(), "on_write");
                }
            }
#endif
            break;
        }
        case fnv1a("pexpire"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t ms = 0;
            if (!parse_int_sv(args[2], ms)) { resp::encode_error_into(rb, "invalid expire time"); return; }
            if (!expire_gated(ms)) break;
            answered_expire(m_store.expire_in(args[1], ms, true));
            break;
        }
        case fnv1a("pttl"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            resp::encode_integer_into(rb, m_store.expire_then_pttl(args[1]));
            break;
        }
        case fnv1a("expireat"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t unix_s = 0;
            if (!parse_int_sv(args[2], unix_s)) { resp::encode_error_into(rb, "invalid timestamp"); return; }
            {
                const int64_t now_s = socketley::wall::now_sec();
                const int64_t rel_s = saturating_until(unix_s, now_s);
                if (!expire_gated(ms_of(rel_s))) break;
                answered_expire(m_store.expire_in(args[1], rel_s, false));
            }
            break;
        }
        case fnv1a("pexpireat"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t unix_ms = 0;
            if (!parse_int_sv(args[2], unix_ms)) { resp::encode_error_into(rb, "invalid timestamp"); return; }
            {
                const int64_t now_ms = socketley::wall::now_ms();
                const int64_t rel_ms = saturating_until(unix_ms, now_ms);
                if (!expire_gated(rel_ms)) break;
                answered_expire(m_store.expire_in(args[1], rel_ms, true));
            }
            break;
        }
        case fnv1a("scan"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            uint64_t scan_cursor = 0;
            {
                if (!parse_int_sv(args[1], scan_cursor)) { resp::encode_error_into(rb, "invalid cursor"); return; }
            }
            std::string_view scan_pattern = "*";
            scan_preds sp;
            bool scan_count_given = false, scan_has_type = false, scan_with_values = false;
            int scan_type = -1;
            size_t scan_count = 10;
            for (int i = 2; i < argc; i++)
            {
                if (fnv1a_lower(args[i]) == fnv1a("match") && i + 1 < argc)
                    scan_pattern = args[++i];
                else if (fnv1a_lower(args[i]) == fnv1a("valuematch") && i + 1 < argc)
                {
                    const size_t k = sp.slot(false);
                    sp.value[k] = args[++i]; sp.has_value[k] = true;
                }
                else if (fnv1a_lower(args[i]) == fnv1a("type") && i + 1 < argc)
                {
                    scan_type = cache_store::scan_map_of_type(args[++i]);
                    scan_has_type = true;
                }
                else if (fnv1a_lower(args[i]) == fnv1a("withvalues"))
                    scan_with_values = true;
                else if (fnv1a_lower(args[i]) == fnv1a("field") && i + 1 < argc)
                {
                    const size_t k = sp.slot(true);
                    sp.field[k] = args[++i]; sp.has_field[k] = true;
                }
                // The bounds a zset range already speaks: -inf, +inf, and a
                // leading ( for exclusive.  One numeric vocabulary, not two.
                else if (fnv1a_lower(args[i]) == fnv1a("valuerange") && i + 2 < argc)
                {
                    const size_t k = sp.slot(false);
                    if (!parse_score_bound(args[i + 1], sp.range[k].lo, sp.range[k].lo_inclusive)
                     || !parse_score_bound(args[i + 2], sp.range[k].hi, sp.range[k].hi_inclusive))
                    { resp::encode_error_into(rb, "min or max is not a float"); return; }
                    sp.has_range[k] = true;
                    i += 2;
                }
                else if (fnv1a_lower(args[i]) == fnv1a("count") && i + 1 < argc)
                {
                    size_t cnt = 10;
                    if (!parse_int_sv(args[i+1], cnt))
                    { resp::encode_error_into(rb, "value is not an integer or out of range"); return; }
                    scan_count = cnt; scan_count_given = true;
                    i++;
                }
            }
            if (sp.too_many)
            { resp::encode_error_into(rb, "too many field predicates"); return; }
            // COUNT means keys EXAMINED once there is a value predicate, and ten
            // of those returns almost nothing per page: a client that did not
            // say otherwise would be asked for sixty thousand round trips over a
            // keyspace one call could walk in 74 ms.
            if (sp.n != 0 && !scan_count_given)
                scan_count = 1000;
            const cache_store::scan_filter scan_filt = sp.build(
                scan_has_type ? scan_type : -1, scan_with_values);
            // Which map the options require, if they require one: a field names
            // hashes, and a predicate or WITHVALUES without one names strings.  A
            // type filter that disagrees with that, a type name no type has, or
            // predicates that disagree with EACH OTHER can match nothing -- and
            // the walk is skipped rather than run to find that out.
            const int scan_needs = scan_filt.wants_hashes() ? 3
                                 : (sp.n != 0 || scan_with_values) ? 0 : -1;
            if (sp.contradictory() ||
                (scan_has_type && (scan_type < 0 ||
                                   (scan_needs >= 0 && scan_type != scan_needs))))
            {
                rb.append("*2\r\n");
                resp::encode_bulk_into(rb, "0");
                resp::encode_array_header_into(rb, 0);
                break;
            }
            std::vector<std::string_view> scan_keys;
            uint64_t next_cursor = 0;
            if (!shard_scan(scan_cursor, scan_pattern, scan_count, scan_keys, next_cursor,
                            conn->cluster_port, scan_filt))
            {
                resp::encode_error_into(rb, "invalid cursor");
                return;
            }
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
        // Every client library sends QUIT before it drops a connection, and
        // was answered "unknown command" for it -- harmless in effect and a
        // line in somebody's error log every time a pool recycled a socket.
        case fnv1a("quit"):
        {
            rb.append("+OK\r\n", 5);
            conn->quit_after_flush = true;
            break;
        }
        // RESET returns a connection to the state it had on accept, which is
        // what a pooling client needs before handing it to the next caller: a
        // socket that is still inside a MULTI, still watching a key or still
        // subscribed is not a fresh one, and the caller cannot tell.
        case fnv1a("reset"):
        {
            reset_connection_state(conn);
            rb.append("+RESET\r\n", 8);
            break;
        }
        case fnv1a("subscribe"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            for (int i = 1; i < argc; i++)
            {
                if (m_store.subscribe(conn->fd, args[i])) ++conn->sub_count;
                // The confirmation Redis sends and a client library waits for:
                // it counts down from this number to know its own subscribe
                // batch is complete, and +OK gives it nothing to count.
                sub_confirm(rb, "subscribe", args[i], conn->sub_count);
            }
            break;
        }
        case fnv1a("psubscribe"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            const bool first = !m_store.has_patterns();
            for (int i = 1; i < argc; i++)
            {
                if (m_store.psubscribe(conn->fd, args[i])) ++conn->sub_count;
                sub_confirm(rb, "psubscribe", args[i], conn->sub_count);
            }
            // A shard that has gained its first pattern can no longer be
            // skipped by the channel filter, and this is how the publishing
            // shard finds that out.
            if (first && m_shard_n > 1) channel_presence_bit(shard_stats::pattern_bit, true);
            break;
        }
        case fnv1a("punsubscribe"):
        {
            resp_unsubscribe(conn, args, argc, true, rb);
            if (!m_store.has_patterns() && m_shard_n > 1)
                channel_presence_bit(shard_stats::pattern_bit, false);
            break;
        }
        case fnv1a("unsubscribe"):
        {
            resp_unsubscribe(conn, args, argc, false, rb);
            break;
        }
        case fnv1a("publish"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            // Refused as the text protocol refuses it, so readonly means the same on both wires.
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int count = publish(args[1], args[2]);
            resp::encode_integer_into(rb, count);
            break;
        }
        // ─── The handshake set: no key, and this process answers ───
        //
        // HELLO refuses RESP3 with -NOPROTO the way a Redis before 6 does, so
        // a client that asks falls back to RESP2 instead of failing.
        case fnv1a("hello"):
        {
            // Parsed and not compared: the argument is a number, so Redis
            // reads "02" as 2 and a string compare would refuse it.
            if (argc >= 2)
            {
                int64_t ver = 0;
                if (!parse_int_sv(args[1], ver) || ver != 2)
                {
                    resp::encode_error_code_into(rb,
                        "NOPROTO unsupported protocol version");
                    break;
                }
            }
            resp::encode_array_header_into(rb, 14);
            resp::encode_bulk_into(rb, "server");   resp::encode_bulk_into(rb, "socketley");
            resp::encode_bulk_into(rb, "version");  resp::encode_bulk_into(rb, SOCKETLEY_VERSION);
            resp::encode_bulk_into(rb, "proto");    resp::encode_integer_into(rb, 2);
            resp::encode_bulk_into(rb, "id");       resp::encode_integer_into(rb, conn->fd);
            resp::encode_bulk_into(rb, "mode");
            resp::encode_bulk_into(rb, m_shard_n > 1 && m_cluster_on ? "cluster" : "standalone");
            resp::encode_bulk_into(rb, "role");
            resp::encode_bulk_into(rb, m_mode == cache_mode_readonly ? "replica" : "master");
            resp::encode_bulk_into(rb, "modules");  resp::encode_array_header_into(rb, 0);
            break;
        }
        case fnv1a("echo"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            resp::encode_bulk_into(rb, args[1]);
            break;
        }
        // There is one keyspace here, so index zero is the only one that can
        // be selected and anything else is refused rather than ignored.
        case fnv1a("select"):
        {
            if (argc >= 2)
            {
                int64_t db = 0;
                if (!parse_int_sv(args[1], db) || db != 0)
                { resp::encode_error_code_into(rb, "ERR DB index is out of range"); break; }
            }
            resp::encode_ok_into(rb);
            break;
        }
        // What a cluster client sends on every connection it opens, answered
        // because every shard serves reads and has no redirect to pre-empt.
        case fnv1a("readonly"):
        case fnv1a("readwrite"):
        case fnv1a("asking"):
            resp::encode_ok_into(rb);
            break;
        // A cache with no password answers AUTH the way Redis does, which is
        // an error naming the reason rather than a silent success.
        case fnv1a("auth"):
        {
            resp::encode_error_code_into(rb,
                "ERR Client sent AUTH, but no password is set");
            break;
        }
        case fnv1a("client"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            switch (fnv1a_lower(args[1]))
            {
                case fnv1a("id"):      resp::encode_integer_into(rb, conn->fd); break;
                case fnv1a("getname"): resp::encode_null_into(rb);              break;
                // What a client library sends on connect; accepting them is
                // what lets the connection finish being made.
                case fnv1a("setname"):
                case fnv1a("setinfo"):
                case fnv1a("no-evict"):
                case fnv1a("reply"):   resp::encode_ok_into(rb);                break;
                default: resp::encode_error_into(rb, "unknown CLIENT subcommand"); break;
            }
            break;
        }
        case fnv1a("command"):
        {
            // The table is resp_command_table.h's; COUNT, LIST and INFO read it,
            // and DOCS answers an empty map, which says "no docs" in RESP2.
            auto entry = [&](const resp_command_info& c) {
                resp::encode_array_header_into(rb, 6);
                resp::encode_bulk_into(rb, c.name);
                resp::encode_integer_into(rb, c.arity);
                int nflags = 0;
                for (std::string_view f = c.flags; !f.empty(); )
                {
                    const size_t sp = f.find(' ');
                    ++nflags;
                    f = (sp == std::string_view::npos) ? std::string_view{} : f.substr(sp + 1);
                }
                resp::encode_array_header_into(rb, nflags);
                for (std::string_view f = c.flags; !f.empty(); )
                {
                    const size_t sp = f.find(' ');
                    rb.push_back('+');
                    rb.append(f.substr(0, sp));
                    rb.append("\r\n", 2);
                    f = (sp == std::string_view::npos) ? std::string_view{} : f.substr(sp + 1);
                }
                resp::encode_integer_into(rb, c.first_key);
                resp::encode_integer_into(rb, c.last_key);
                resp::encode_integer_into(rb, c.step);
            };
            const uint32_t sub = argc >= 2 ? fnv1a_lower(args[1]) : 0;
            if (argc < 2)
            {
                resp::encode_array_header_into(rb, static_cast<int>(std::size(resp_command_table)));
                for (const auto& c : resp_command_table) entry(c);
            }
            else if (sub == fnv1a("count"))
                resp::encode_integer_into(rb, static_cast<int64_t>(std::size(resp_command_table)));
            else if (sub == fnv1a("list"))
            {
                resp::encode_array_header_into(rb, static_cast<int>(std::size(resp_command_table)));
                for (const auto& c : resp_command_table) resp::encode_bulk_into(rb, c.name);
            }
            else if (sub == fnv1a("info"))
            {
                resp::encode_array_header_into(rb, argc - 2);
                for (int i = 2; i < argc; ++i)
                {
                    const resp_command_info* hit = nullptr;
                    for (const auto& c : resp_command_table)
                        if (fnv1a_lower(args[i]) == fnv1a(c.name)) { hit = &c; break; }
                    if (hit) entry(*hit);
                    else     rb.append("*-1\r\n", 5);
                }
            }
            else if (sub == fnv1a("docs"))
                resp::encode_array_header_into(rb, 0);
            else
                resp::encode_error_into(rb, "unknown subcommand for COMMAND");
            break;
        }
        // Only the two fields a client actually reads back are answered, and
        // an unknown parameter comes back empty rather than invented.
        case fnv1a("config"):
        {
            if (argc < 3 || fnv1a_lower(args[1]) != fnv1a("get"))
            { resp::encode_array_header_into(rb, 0); break; }
            switch (fnv1a_lower(args[2]))
            {
                case fnv1a("maxmemory"):
                    resp::encode_array_header_into(rb, 2);
                    resp::encode_bulk_into(rb, "maxmemory");
                    resp::encode_bulk_into(rb, std::to_string(get_max_memory()));
                    break;
                // Both are empty here, and empty is the true answer rather
                // than an absent one.
                case fnv1a("save"):
                case fnv1a("appendonly"):
                    resp::encode_array_header_into(rb, 2);
                    resp::encode_bulk_into(rb, args[2]);
                    resp::encode_bulk_into(rb, "");
                    break;
                default: resp::encode_array_header_into(rb, 0); break;
            }
            break;
        }
        case fnv1a("info"):
        {
            std::string info;
            build_info_reply(info, !conn->cluster_port);
            resp::encode_bulk_into(rb, info);
            break;
        }

        // ─── Strings, the range and float spellings ───
        case fnv1a("getrange"):
        case fnv1a("substr"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            int64_t s = 0, e = 0;
            if (!parse_int_sv(args[2], s) || !parse_int_sv(args[3], e))
            { resp::encode_error_code_into(rb, "ERR value is not an integer or out of range"); break; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            std::string out;
            if (!m_store.getrange(args[1], s, e, out)
                && SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 's')))
            { resp::encode_error_code_into(rb, wrongtype_msg); break; }
            resp::encode_bulk_into(rb, out);
            break;
        }
        case fnv1a("setrange"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t off = 0;
            if (!parse_int_sv(args[2], off) || off < 0)
            { resp::encode_error_code_into(rb, "ERR offset is out of range"); break; }
            const size_t n = m_store.setrange(args[1], static_cast<size_t>(off), args[3]);
            if (n == cache_store::append_wrong_type)   resp::encode_error_code_into(rb, "WRONGTYPE");
            else if (n == cache_store::append_too_long)
                resp::encode_error_code_into(rb, "ERR string exceeds maximum allowed size");
            else if (n == cache_store::append_denied)  resp::encode_error_into(rb, "out of memory");
            else { resp::encode_integer_into(rb, static_cast<int64_t>(n)); repl(args, argc); }
            break;
        }
        // Replicated as its result and not as itself, because two builds may
        // round the same addition differently and the follower would drift.
        case fnv1a("incrbyfloat"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            double d = 0;
            if (!parse_double_sv(args[2], d))
            { resp::encode_error_code_into(rb, "ERR value is not a valid float"); break; }
            double out = 0;
            if (!m_store.incrbyfloat(args[1], d, out))
            { resp::encode_error_code_into(rb, "ERR value is not a valid float"); break; }
            const std::string txt = cache_float_text(out);
            resp::encode_bulk_into(rb, txt);
            repl_set_effect(args[1], txt, 0, 0);
            break;
        }
        case fnv1a("getdel"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            std::string val;
            if (m_store.getdel(args[1], val))
            {
                resp::encode_bulk_into(rb, val);
                std::string cmd = "del "; cmd.append(args[1].data(), args[1].size());
                if (mutation_log_wanted()) replicate_command(cmd);
            }
            else resp::encode_null_into(rb);
            break;
        }

        // ─── Lists, the positional spellings ───
        case fnv1a("lset"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t idx = 0;
            if (!parse_int_sv(args[2], idx))
            { resp::encode_error_code_into(rb, "ERR value is not an integer or out of range"); break; }
            const int rc = m_store.lset(args[1], idx, args[3]);
            if (rc == 0)       { resp::encode_ok_into(rb); repl(args, argc); }
            else if (rc == -1) encode_refusal(rb, m_store.type(args[1]), "list", "ERR no such key");
            else if (rc == -3) encode_refusal(rb, "list", "list");
            else               resp::encode_error_code_into(rb, "ERR index out of range");
            break;
        }
        case fnv1a("lrem"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t cnt = 0;
            if (!parse_int_sv(args[2], cnt))
            { resp::encode_error_code_into(rb, "ERR value is not an integer or out of range"); break; }
            const int gone = m_store.lrem(args[1], cnt, args[3]);
            resp::encode_integer_into(rb, gone);
            if (gone > 0) repl(args, argc);
            break;
        }
        case fnv1a("ltrim"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t s = 0, e = 0;
            if (!parse_int_sv(args[2], s) || !parse_int_sv(args[3], e))
            { resp::encode_error_code_into(rb, "ERR value is not an integer or out of range"); break; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[1], 'l')))
            { resp::encode_error_code_into(rb, wrongtype_msg); break; }
            m_store.ltrim(args[1], s, e);
            resp::encode_ok_into(rb);
            repl(args, argc);
            break;
        }
        case fnv1a("linsert"):
        {
            if (argc < 5) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            const uint32_t where = fnv1a_lower(args[2]);
            if (where != fnv1a("before") && where != fnv1a("after"))
            { resp::encode_error_code_into(rb, "ERR syntax error"); break; }
            const int n = m_store.linsert(args[1], where == fnv1a("before"), args[3], args[4]);
            if (n == cache_store::linsert_refused) { resp::encode_error_code_into(rb, oom_msg); break; }
            resp::encode_integer_into(rb, n);
            if (n > 0) repl(args, argc);
            break;
        }

#ifndef SOCKETLEY_NO_LUA_UNUSED
#endif
        // ─── Lists, the blocking pops ───
        case fnv1a("blpop"):
        case fnv1a("brpop"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            // Every shard is a process of its own, so a key another shard owns
            // would have to wake this one across a boundary the crossing
            // protocol only carries answers over.  Refused by name, the way
            // `replicate` is on a sharded cache.
            if (SOCKETLEY_UNLIKELY(m_shard_n > 1))
            {
                resp::encode_error_code_into(rb,
                    "ERR BLPOP is not available on a sharded cache -- a waiting "
                    "client and the key it waits on can be in two processes");
                break;
            }
            // And the other thing a waiter needs: a connection.  See the line
            // protocol's copy of this for what an unguarded one answered.
            if (SOCKETLEY_UNLIKELY(conn == m_request_conn.get()))
            {
                resp::encode_error_code_into(rb,
                    "ERR BLPOP needs a connection to wait on, and a "
                    "cross-runtime request has none");
                break;
            }
            const bool from_head = (cmd_hash == fnv1a("blpop"));
            double secs = 0;
            if (!parse_double_sv(args[argc - 1], secs) || secs < 0)
            { resp::encode_error_code_into(rb, "ERR timeout is not a float or out of range"); break; }

            // Tried in the order given, and answered at once if any of them
            // has something -- a BLPOP on a queue that is not empty must not
            // pay for the machinery below.
            for (int i = 1; i < argc - 1; ++i)
            {
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
                if (SOCKETLEY_UNLIKELY(m_store.holds_other_type(args[i], 'l')))
                { resp::encode_error_code_into(rb, wrongtype_msg); goto blpop_done; }
                std::string val;
                const bool got = from_head ? m_store.lpop(args[i], val)
                                           : m_store.rpop(args[i], val);
                if (got)
                {
                    resp::encode_array_header_into(rb, 2);
                    resp::encode_bulk_into(rb, args[i]);
                    resp::encode_bulk_into(rb, val);
                    if (mutation_log_wanted())
                    {
                        std::string c = from_head ? "lpop " : "rpop ";
                        c.append(args[i].data(), args[i].size());
                        replicate_command(c);
                    }
                    goto blpop_done;
                }
            }
            // Inside EXEC it must not wait, for two reasons that are both
            // fatal on their own.  The reply array is counted before the
            // replies are produced, so a command that writes nothing leaves
            // the client reading N-1 elements under an N header; and the
            // waiter would be a second one on this descriptor, which
            // m_wait_fd holds one of and drop_blocked() looks up by fd alone.
            // Redis answers a blocking pop in a transaction as its
            // non-blocking twin, which on an empty list is a null array.
            if (SOCKETLEY_UNLIKELY(conn->in_exec))
            {
                rb.append("*-1\r\n", 5);
                break;
            }
            // Nothing to take, so the caller waits and this command answers on
            // a later turn -- the only one in this file that does.
            block_pop(conn, args, argc, from_head);
        blpop_done:
            break;
        }

        // ─── Lists, the reliable-queue move ───
        case fnv1a("rpoplpush"):
        case fnv1a("lmove"):
        {
            const bool three = (cmd_hash == fnv1a("rpoplpush"));
            if (argc < (three ? 3 : 5))
            { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }

            bool from_head = false, to_head = true;   // RPOPLPUSH's directions
            if (!three)
            {
                const uint32_t f = fnv1a_lower(args[3]), t = fnv1a_lower(args[4]);
                if ((f != fnv1a("left") && f != fnv1a("right"))
                 || (t != fnv1a("left") && t != fnv1a("right")))
                { resp::encode_error_into(rb, "syntax error"); return; }
                from_head = (f == fnv1a("left"));
                to_head   = (t == fnv1a("left"));
            }

            // The destination has to be this shard's, because the element
            // would otherwise leave one process and have to arrive in another
            // with nothing to undo the pop if it did not.
            if (SOCKETLEY_UNLIKELY(m_shard_n > 1)
                && cache_shard_of(args[2], m_shard_n) != m_shard_i)
            {
                resp::encode_error_code_into(rb,
                    "CROSSSLOT Keys in request don't hash to the same slot");
                break;
            }

            std::string moved;
            if (!m_store.lmove(args[1], args[2], from_head, to_head, moved))
            {
                // Absent source and wrong type are two different answers, and
                // the store says false to both.
                const std::string_view st = m_store.type(args[1]);
                const std::string_view dt = m_store.type(args[2]);
                if ((st != "none" && st != "list") || (dt != "none" && dt != "list"))
                    resp::encode_error_code_into(rb, wrongtype_msg);
                else if (st == "none")
                    resp::encode_null_into(rb);
                else
                    resp::encode_error_code_into(rb, oom_msg);   // a list to move from, and no room
                break;
            }
            resp::encode_bulk_into(rb, moved);
            repl(args, argc);
            // The destination gained an element, and a worker may be waiting
            // on it -- the reliable-queue shape is exactly this pair.
            while (wake_one_waiter(args[2])) {}
            break;
        }

        // ─── Sets, the sampling spellings ───
        // SPOP picks a member at random, so it replicates as the SREM it
        // turned out to be rather than as itself.
        case fnv1a("spop"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (argc >= 3)
            {
                resp_spop_count(args, argc, rb);
                break;
            }
            std::string member;
            if (m_store.spop(args[1], member))
            {
                resp::encode_bulk_into(rb, member);
                if (mutation_log_wanted())
                {
                    std::string cmd = "srem ";
                    cmd.append(args[1].data(), args[1].size());
                    cmd += ' '; cmd += member;
                    replicate_command(cmd);
                }
            }
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("srandmember"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (argc >= 3)
            {
                resp_srandmember_count(args, argc, rb);
                break;
            }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            std::string member;
            if (m_store.srandmember(args[1], member)) resp::encode_bulk_into(rb, member);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("smismember"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            resp::encode_array_header_into(rb, argc - 2);
            for (int i = 2; i < argc; ++i)
                resp::encode_integer_into(rb, m_store.sismember(args[1], args[i]) ? 1 : 0);
            break;
        }

        // ─── Hashes, the field spellings ───
        case fnv1a("hexists"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.hexists(args[1], args[2]) ? 1 : 0);
            break;
        }
        case fnv1a("hincrby"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t d = 0;
            if (!parse_int_sv(args[3], d))
            { resp::encode_error_code_into(rb, "ERR value is not an integer or out of range"); break; }
            int64_t out = 0;
            const auto hst = m_store.hincrby(args[1], args[2], d, out);
            if (hst == cache_store::incr_result::ok)
            { resp::encode_integer_into(rb, out); repl(args, argc); }
            else if (hst == cache_store::incr_result::would_overflow)
                resp::encode_error_into(rb, "increment or decrement would overflow");
            else if (hst == cache_store::incr_result::wrong_type)
                resp::encode_error_code_into(rb, wrongtype_msg);
            else if (hst == cache_store::incr_result::out_of_memory)
                resp::encode_error_code_into(rb, oom_msg);
            else resp::encode_error_code_into(rb, "ERR hash value is not an integer");
            break;
        }
        case fnv1a("hsetnx"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            const int rc = m_store.hsetnx(args[1], args[2], args[3]);
            if (rc < 0) { encode_refusal(rb, m_store.type(args[1]), "hash"); break; }
            resp::encode_integer_into(rb, rc);
            if (rc == 1) repl(args, argc);
            break;
        }
        case fnv1a("hmget"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_array_header_into(rb, argc - 2);
            for (int i = 2; i < argc; ++i)
            {
                const auto v = m_store.hget(args[1], args[i]);
                if (v) resp::encode_bulk_into(rb, *v);
                else   resp::encode_null_into(rb);
            }
            break;
        }
        case fnv1a("hkeys"):
        case fnv1a("hvals"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const hash_inner* h = m_store.hash_ptr(args[1]);
            const bool want_keys = (cmd_hash == fnv1a("hkeys"));
            resp::encode_array_header_into(rb, h ? static_cast<int>(h->size()) : 0);
            if (h) for (const auto& [f, v] : *h)
                resp::encode_bulk_into(rb, want_keys ? f : v);
            break;
        }
        case fnv1a("hstrlen"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const auto v = m_store.hget(args[1], args[2]);
            resp::encode_integer_into(rb, v ? static_cast<int64_t>(v->size()) : 0);
            break;
        }
#ifndef SOCKETLEY_NO_LUA
        // ─── Scripting ──────────────────────────────────────────────────────
        case fnv1a("eval"):
        case fnv1a("evalsha"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            int64_t nkeys = 0;
            if (!parse_int_sv(args[2], nkeys) || nkeys < 0 || nkeys > argc - 3)
            { resp::encode_error_code_into(rb,
                "ERR Number of keys can't be greater than number of args"); break; }

            std::string_view body;
            if (cmd_hash == fnv1a("evalsha"))
            {
                const std::string* found = m_scripts.body_of(args[1]);
                if (!found)
                { resp::encode_error_code_into(rb,
                    "NOSCRIPT No matching script. Please use EVAL."); break; }
                body = *found;
            }
            else
                body = args[1];

            const std::span<const std::string_view> keys(args + 3, static_cast<size_t>(nkeys));
            const std::span<const std::string_view> argv(args + 3 + nkeys, static_cast<size_t>(argc - 3 - nkeys));

            // Straight into rb, since eval appends its reply only once the script has succeeded.
            std::string err;
            const bool was_exec = conn->in_exec;
            conn->in_exec = true;
            ++m_script_depth;
            const bool okrun = m_scripts.eval(
                body, keys, argv,
                [this, conn](std::span<std::string_view> a, std::string& reply)
                { script_command(conn, a, reply); },
                rb, err);
            --m_script_depth;
            conn->in_exec = was_exec;
            if (!okrun)
            {
                // A redis.call that failed carries the cache's own error out
                // of the script, and its code is what a client switches on --
                // so WRONGTYPE stays WRONGTYPE rather than becoming the ERR
                // that wraps it.  Anything without a code gets one.
                static constexpr std::string_view codes[] = {
                    "ERR ", "WRONGTYPE ", "NOSCRIPT ", "CROSSSLOT ", "MOVED ",
                    "NOPROTO ", "OOM ", "BUSYGROUP ", "NOTBUSY ", "NOGROUP "
                };
                bool coded = false;
                for (const auto& c : codes)
                    if (err.compare(0, c.size(), c) == 0) { coded = true; break; }
                resp::encode_error_code_into(rb, coded ? err : "ERR " + err);
                break;
            }
            break;
        }
        case fnv1a("script"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            switch (fnv1a_lower(args[1]))
            {
                case fnv1a("load"):
                    if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
                {
                    std::string why;
                    const std::string sha = m_scripts.load(args[2], why);
                    if (sha.empty()) resp::encode_error_code_into(rb, "ERR " + why);
                    else resp::encode_bulk_into(rb, sha);
                    break;
                }
                case fnv1a("exists"):
                    resp::encode_array_header_into(rb, argc - 2);
                    for (int i = 2; i < argc; ++i)
                        resp::encode_integer_into(rb, m_scripts.known(args[i]) ? 1 : 0);
                    break;
                case fnv1a("flush"):
                    m_scripts.flush();
                    resp::encode_ok_into(rb);
                    break;
                default:
                    resp::encode_error_into(rb, "unknown SCRIPT subcommand");
                    break;
            }
            break;
        }
#endif
        // ─── One collection, scanned ───
        case fnv1a("hscan"):
        case fnv1a("sscan"):
        case fnv1a("zscan"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            uint64_t cur = 0;
            if (!parse_int_sv(args[2], cur))
            { resp::encode_error_into(rb, "invalid cursor"); break; }
            std::string_view pat = "*";   // absent MATCH is everything; see above
            size_t want = 10;                       // Redis's own default COUNT
            std::string_view vpat; bool has_v = false, count_given = false;
            for (int i = 3; i < argc; i += 2)
            {
                if (i + 1 >= argc) { resp::encode_error_into(rb, "syntax error"); return; }
                const uint32_t o = fnv1a_lower(args[i]);
                if (o == fnv1a("match")) pat = args[i + 1];
                else if (o == fnv1a("valuematch")) { vpat = args[i + 1]; has_v = true; }
                else if (o == fnv1a("count"))
                {
                    int64_t c = 0;
                    if (!parse_int_sv(args[i + 1], c) || c < 1)
                    { resp::encode_error_into(rb, "syntax error"); return; }
                    want = static_cast<size_t>(c); count_given = true;
                }
                else { resp::encode_error_into(rb, "syntax error"); return; }
            }
            // Only a hash has values to match, for the reason the text door
            // gives, and the same page-size rule as scan's.
            if (has_v && cmd_hash != fnv1a("hscan"))
            { resp::encode_error_into(rb, "syntax error"); return; }
            if (has_v && !count_given) want = 1000;
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);

            // Two elements: the cursor to come back with, then the flat list.
            // A hash and a zset emit two entries per element, a set one -- so
            // the body is built first and counted, because the array header
            // has to be written before it.
            std::string body;
            int n = 0;
            uint64_t next = 0;
            if (cmd_hash == fnv1a("hscan"))
            {
                std::vector<std::pair<std::string_view, std::string_view>> got;
                next = m_store.hscan(args[1], cur, pat, want, got, has_v ? &vpat : nullptr);
                for (const auto& [f, v] : got)
                { resp::encode_bulk_into(body, f); resp::encode_bulk_into(body, v); n += 2; }
            }
            else if (cmd_hash == fnv1a("sscan"))
            {
                std::vector<std::string_view> got;
                next = m_store.sscan(args[1], cur, pat, want, got);
                for (const auto& m : got) { resp::encode_bulk_into(body, m); ++n; }
            }
            else
            {
                std::vector<std::pair<std::string_view, double>> got;
                next = m_store.zscan(args[1], cur, pat, want, got);
                for (const auto& [m, sc] : got)
                { resp::encode_bulk_into(body, m);
                  resp::encode_bulk_into(body, score_text(sc)); n += 2; }
            }
            resp::encode_array_header_into(rb, 2);
            resp::encode_bulk_into(rb, std::to_string(next));
            resp::encode_array_header_into(rb, n);
            rb.append(body);
            break;
        }

        // ─── Sorted sets, by score rather than by rank ───
        case fnv1a("zrangebyscore"):
        case fnv1a("zrevrangebyscore"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            const bool rev = (cmd_hash == fnv1a("zrevrangebyscore"));
            // The reverse spelling takes max before min, which is the one place
            // the two differ apart from the direction of the walk.
            double lo = 0, hi = 0; bool lo_in = true, hi_in = true;
            if (!parse_score_bound(rev ? args[3] : args[2], lo, lo_in)
             || !parse_score_bound(rev ? args[2] : args[3], hi, hi_in))
            { resp::encode_error_code_into(rb, "ERR min or max is not a float"); break; }
            bool withscores = false;
            int64_t off = 0, cnt = -1;
            for (int i = 4; i < argc; ++i)
            {
                const uint32_t o = fnv1a_lower(args[i]);
                if (o == fnv1a("withscores")) withscores = true;
                else if (o == fnv1a("limit") && i + 2 < argc &&
                         parse_int_sv(args[i + 1], off) && parse_int_sv(args[i + 2], cnt))
                    i += 2;
                else { resp::encode_error_into(rb, "syntax error"); return; }
            }
            std::vector<std::pair<std::string_view, double>> out;
            m_store.check_expiry(args[1]);
            m_store.zrangebyscore(args[1], lo, hi, lo_in, hi_in, rev, out);
            apply_zlimit(out, off, cnt);
            resp::encode_array_header_into(rb,
                static_cast<int>(out.size()) * (withscores ? 2 : 1));
            for (const auto& [m, sc] : out)
            {
                resp::encode_bulk_into(rb, m);
                if (withscores) resp::encode_bulk_into(rb, score_text(sc));
            }
            break;
        }
        case fnv1a("zcount"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            double lo = 0, hi = 0; bool lo_in = true, hi_in = true;
            if (!parse_score_bound(args[2], lo, lo_in) || !parse_score_bound(args[3], hi, hi_in))
            { resp::encode_error_code_into(rb, "ERR min or max is not a float"); break; }
            m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb,
                static_cast<int64_t>(m_store.zcount(args[1], lo, hi, lo_in, hi_in)));
            break;
        }
        // Same rewrite SPOP needs, and for the same reason.
        case fnv1a("zpopmin"):
        case fnv1a("zpopmax"):
        {
            if (argc < 2 || argc > 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t zcount_want = 1;
            if (argc == 3 && (!parse_int_sv(args[2], zcount_want) || zcount_want < 0))
            { resp::encode_error_into(rb, "value is out of range, must be positive"); return; }
            std::string member; double score = 0;
            std::string zbody;
            int64_t zpopped = 0;
            while (zpopped < zcount_want
                   && m_store.zpop(args[1], cmd_hash == fnv1a("zpopmax"), member, score))
            {
                ++zpopped;
                resp::encode_bulk_into(zbody, member);
                resp::encode_bulk_into(zbody, score_text(score));
                if (mutation_log_wanted())
                {
                    std::string cmd = "zrem ";
                    cmd.append(args[1].data(), args[1].size());
                    cmd += ' '; cmd += member;
                    replicate_command(cmd);
                }
            }
            resp::encode_array_header_into(rb, static_cast<int>(zpopped * 2));
            rb.append(zbody);
            break;
        }
        case fnv1a("zremrangebyrank"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t s = 0, e = 0;
            if (!parse_int_sv(args[2], s) || !parse_int_sv(args[3], e))
            { resp::encode_error_code_into(rb, "ERR value is not an integer or out of range"); break; }
            const size_t gone = m_store.zremrangebyrank(args[1], s, e);
            resp::encode_integer_into(rb, static_cast<int64_t>(gone));
            if (gone > 0) repl(args, argc);
            break;
        }
        case fnv1a("zremrangebyscore"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            double lo = 0, hi = 0; bool lo_in = true, hi_in = true;
            if (!parse_score_bound(args[2], lo, lo_in) || !parse_score_bound(args[3], hi, hi_in))
            { resp::encode_error_code_into(rb, "ERR min or max is not a float"); break; }
            const size_t gone = m_store.zremrangebyscore(args[1], lo, hi, lo_in, hi_in);
            resp::encode_integer_into(rb, static_cast<int64_t>(gone));
            if (gone > 0) repl(args, argc);
            break;
        }
        case fnv1a("xadd"):      case fnv1a("xrange"):     case fnv1a("xrevrange"):
        case fnv1a("xlen"):      case fnv1a("xread"):      case fnv1a("xreadgroup"):
        case fnv1a("xdel"):      case fnv1a("xtrim"):      case fnv1a("xgroup"):
        case fnv1a("xsetid"):    case fnv1a("xack"):       case fnv1a("xpending"):
        case fnv1a("xclaim"):    case fnv1a("xautoclaim"): case fnv1a("xinfo"):
            stream_command(conn, cmd_hash, args, argc, rb);
            break;
        default:
        {
            rb.append("-ERR unknown command '", 22);
            resp::append_one_line(rb, args[0]);
            rb.append("'\r\n", 3);
            break;
        }
    }
}

#ifndef SOCKETLEY_NO_LUA
void cache_instance::repl_unfaithful(std::string_view key)
{
    ++m_repl_unfaithful;
    if (m_repl_unfaithful == 1 || (m_repl_unfaithful % 1000) == 0)
        LOG_ERROR(("cache \"" + std::string(get_name()) + "\": a key with a "
                   "space in it cannot be written to the replication log or "
                   "the journal, because both are re-split on spaces -- \""
                   + std::string(key) + "\" is on this cache and will not be "
                   "on a follower; " + std::to_string(m_repl_unfaithful)
                   + " command(s) have now been held back").c_str());
}

// ─── EVAL's way into the cache ──────────────────────────────────────────────
//
// One command, run through the same local dispatch every other command takes,
// with the reply captured instead of queued.  A script therefore sees exactly
// what a client would -- including the refusals -- and cannot reach past the
// dispatch into the store.
void cache_instance::script_command(client_connection* conn, std::span<std::string_view> args,
                                    std::string& reply)
{
    // The parser's two limits, which a command from a script no longer passes.
    std::string held;
    held.swap(conn->response_buf);
    reply.clear();
    conn->response_buf.swap(reply);
    const size_t limit = static_cast<size_t>(read_bulk_limit());
    const auto too_large = [limit](std::string_view a) { return a.size() > limit; };
    if (args.size() > static_cast<size_t>(resp::RESP_MAX_ARRAY_SIZE))
        resp::encode_error_into(conn->response_buf, "too many arguments in one command");
    else if (std::any_of(args.begin(), args.end(), too_large))
        resp::encode_error_into(conn->response_buf, "value is larger than this cache accepts");
    else
        process_resp_command_local(conn, args.data(), static_cast<int>(args.size()));
    reply.swap(conn->response_buf);
    conn->response_buf.swap(held);
}
#endif

// ─── WATCH ──────────────────────────────────────────────────────────────────
//
// The guarantee is one sentence: EXEC does nothing if a watched key was
// written between the WATCH and the EXEC.  That is what makes a
// compare-and-set loop possible, and it is the usual reason to reach for MULTI
// at all -- without it a transaction here is a batch.

// Everything a connection accumulated for its own session, dropped in one
// place.  Two protocols reach RESET, and a piece of state cleared in one of
// them and not the other is a connection that looks fresh and is not.
void cache_instance::reset_connection_state(client_connection* conn)
{
    unwatch_all(conn);
    drop_blocked(conn->fd);
    conn->blocked = false;
    m_store.unsubscribe_all(conn->fd);
    m_store.punsubscribe_all(conn->fd);
    conn->sub_count    = 0;
    conn->in_multi     = false;
    conn->multi_broken = false;
    conn->multi_queue.clear();
    conn->multi_bytes  = 0;
}

void cache_instance::watch_keys(client_connection* conn, std::string_view* args, int argc)
{
    for (int i = 1; i < argc; ++i)
    {
        // The set already knows whether this connection watches this key, so the
        // duplicate check is its insert result and not a scan of conn->watched.
        if (m_watchers[std::string(args[i])].insert(conn->fd).second)
            conn->watched.emplace_back(args[i]);
    }
    if (!conn->watched.empty()) m_watching.insert(conn->fd);
}

void cache_instance::unwatch_all(client_connection* conn)
{
    if (conn->watched.empty()) { conn->watch_dirty = false; return; }
    for (const auto& k : conn->watched)
    {
        auto it = m_watchers.find(k);
        if (it == m_watchers.end()) continue;
        it->second.erase(conn->fd);
        if (it->second.empty()) m_watchers.erase(it);
    }
    conn->watched.clear();
    conn->watch_dirty = false;
    m_watching.erase(conn->fd);
}

// The fallback for a close with no connection object to read the key list
// from; the close path itself calls unwatch_all, which touches only this
// client's keys.  Reached only by a descriptor that was actually watching, so
// a busy cache does not walk the map on every disconnect.
void cache_instance::drop_watches(int fd)
{
    if (SOCKETLEY_LIKELY(m_watching.erase(fd) == 0))
        return;
    for (auto it = m_watchers.begin(); it != m_watchers.end(); )
    {
        it->second.erase(fd);
        if (it->second.empty()) it = m_watchers.erase(it); else ++it;
    }
}

void cache_instance::note_write_for_watch(uint32_t h, std::string_view* args, int argc)
{
    // Nobody is watching, which is nearly always, and this is the whole cost
    // of carrying the feature for everybody who does not use it.
    if (SOCKETLEY_LIKELY(m_watching.empty()))
        return;
    if (cache_is_read_only(h))
        return;

    const auto dirty = [this](const std::unordered_set<int>& fds) {
        for (int fd : fds)
        {
            // A descriptor and not a pointer, so it is looked up rather than
            // trusted -- the same rule the subscriber set follows.
            if (fd < 0 || fd >= MAX_FDS) continue;
            if (auto* c = m_conn_idx[fd]) c->watch_dirty = true;
        }
    };

    // A single-key write names its key, which is the case worth being exact
    // about: two clients on two different keys must not abort each other.
    if (cache_classify(h) == cache_cmd_class::single_key)
    {
        const int ki = cache_key_arg(h);
        if (argc <= ki) return;             // a usage error changes nothing
        auto it = m_watchers.find(args[ki]);
        if (it != m_watchers.end()) dirty(it->second);
        return;
    }

    // Anything else -- MSET, DEL with several keys, FLUSH, EVAL -- may have
    // touched anything, so everyone watching is told.  Pessimistic, and for a
    // compare-and-set loop that is a retry rather than a wrong answer; the
    // other direction would be a transaction committing over a change it never
    // saw.
    dirty(m_watching);
}

// ─── BLPOP / BRPOP ──────────────────────────────────────────────────────────
//
// The half that looks hard is already here: publish() writes into another
// connection's buffer and flushes it, and the subscriber set has solved the
// lifetime question by holding descriptors rather than pointers.  What is new
// is only that the caller gets NO reply now -- every other command in this
// file answers on the turn it arrived on.

void cache_instance::arm_block_timer()
{
    if (m_block_timer_armed || m_ticking_waiters == 0 || !m_loop)
        return;
    if (!m_block_timer)
        m_block_timer = std::make_unique<timer_op>();
    // A tick and not a per-client deadline: one timer for the whole list, at a
    // resolution a human waiting on a job queue cannot tell from exact.
    m_block_timer->ts.tv_sec  = 0;
    m_block_timer->ts.tv_nsec = 100 * 1000 * 1000;
    m_block_timer->req = { this, nullptr, -1, 0, op_timeout };
    if (m_loop->submit_timeout(&m_block_timer->ts, &m_block_timer->req))
        m_block_timer_armed = true;
}

// The reply a blocked pop gets when it finally has one, written into the
// waiting connection rather than the caller's -- publish()'s path, with
// publish()'s guards.
static void deliver_pop(client_connection* c, std::string_view key,
                        const std::string* value)
{
    std::string out;
    if (c->resp_mode)
    {
        if (!value) { out.append("*-1\r\n", 5); }
        else
        {
            resp::encode_array_header_into(out, 2);
            resp::encode_bulk_into(out, key);
            resp::encode_bulk_into(out, *value);
        }
    }
    else
    {
        if (!value) out.append("nil\n", 4);
        else { out.append(key.data(), key.size()); out.push_back(' ');
               out.append(*value); out.push_back('\n'); }
    }
    c->write_queue.push_coalesced(out, client_connection::WRITE_COALESCE_LIMIT);
}

// Drops a waiter from the sequence map, from every key queue it sits in, and
// from the descriptor index.  One place, because a waiter left in one of the
// three and not the others is either a wake that never comes or a wake sent to
// a descriptor the kernel has reissued.
void cache_instance::forget_waiter(uint64_t seq)
{
    auto it = m_blocked.find(seq);
    if (it == m_blocked.end())
        return;
    const blocked_pop& w = it->second;
    auto& queues = w.stream ? m_stream_wait_key : m_wait_key;
    for (size_t i = 0; i < w.keys.size() && i < w.slots.size(); ++i)
    {
        auto ki = queues.find(w.keys[i]);
        if (ki == queues.end()) continue;
        ki->second.erase(w.slots[i]);
        if (ki->second.empty()) queues.erase(ki);
    }
    auto fi = m_wait_fd.find(w.fd);
    if (fi != m_wait_fd.end() && fi->second == seq) m_wait_fd.erase(fi);
    if (w.needs_tick())
        --m_ticking_waiters;
    m_blocked.erase(it);
}

bool cache_instance::wake_one_waiter(std::string_view key)
{
    if (SOCKETLEY_LIKELY(m_blocked.empty()))
        return false;

    // Longest-waiting first: a worker pool that served its newest member would
    // starve the one that has been idle longest.  The queue is appended in
    // sequence order, so that client is its front and no comparison is needed
    // to find it.
    auto ki = m_wait_key.find(key);
    if (ki == m_wait_key.end() || ki->second.empty())
        return false;

    const uint64_t seq = ki->second.front();
    auto bi = m_blocked.find(seq);
    if (bi == m_blocked.end())
    {
        // Cannot happen while forget_waiter is the only way out, and repaired
        // rather than trusted: a stale sequence here would wedge this key's
        // queue for good.
        ki->second.pop_front();
        return true;
    }
    const blocked_pop w = bi->second;

    // Revalidated rather than trusted: between the park and this push the
    // descriptor may have closed and been reissued to somebody else.
    client_connection* c = (w.fd >= 0 && w.fd < MAX_FDS) ? m_conn_idx[w.fd] : nullptr;
    if (!c || c->closing || c->is_follower)
    {
        // Its socket is gone, so it is dropped -- but the element stays, for
        // whoever is behind it.
        forget_waiter(seq);
        return true;
    }

    // Taken BEFORE the waiter is removed from the list.  The other order lost
    // a waiter every time: the caller loops while this returns true, the
    // second call picked the next waiter, erased it, found the list empty and
    // answered false -- and that waiter had already gone from the list without
    // ever being answered.  Measured as two of three clients served.
    std::string val;
    const bool got = w.from_head ? m_store.lpop(key, val) : m_store.rpop(key, val);
    if (!got)
        return false;
    forget_waiter(seq);

    deliver_pop(c, key, &val);
    c->blocked = false;
    if (!c->write_pending && SOCKETLEY_UNLIKELY(!flush_write_queue(c)))
    {
        c->closing = true;
        return true;                        // taken from the list either way
    }

    // The pop is what replicates, not the blocking: a follower running BLPOP
    // would wait for its own push and never see the leader's.
    if (mutation_log_wanted())
    {
        std::string cmd = w.from_head ? "lpop " : "rpop ";
        cmd.append(key.data(), key.size());
        replicate_command(cmd);
    }

    // Whatever the client pipelined behind its BLPOP has been sitting in
    // `partial` since, and nothing else will come to drive it.  pump() parses
    // and routes; putting the replies on the wire is flush_responses()'s job,
    // which the read path does immediately after it for the same reason.
    pump(c);
    if (SOCKETLEY_UNLIKELY(!flush_responses(c)))
        c->closing = true;
    return true;
}

void cache_instance::sweep_blocked()
{
    m_block_timer_armed = false;
    if (m_blocked.empty())
        return;

    const auto now = std::chrono::steady_clock::now();
    // Collected first: forget_waiter rehashes the map it is walking.
    std::vector<uint64_t> expired;
    std::vector<std::pair<uint64_t, std::string>> orphaned;
    for (const auto& [seq, w] : m_blocked)
    {
        // A group reader whose stream was deleted or replaced waits for a
        // group that cannot come back, and Redis unblocks it with an error.
        if (w.stream && !w.group.empty())
        {
            const auto gone = std::find_if(w.keys.begin(), w.keys.end(),
                [&](const std::string& k) { return !m_store.stream_find(k); });
            if (gone != w.keys.end()) { orphaned.emplace_back(seq, *gone); continue; }
        }
        if (w.deadline.time_since_epoch().count() != 0 && now >= w.deadline)
            expired.push_back(seq);
    }
    for (const auto& [seq, key] : orphaned)
        serve_stream_waiter(seq, key);

    for (const uint64_t seq : expired)
    {
        auto bi = m_blocked.find(seq);
        if (bi == m_blocked.end()) continue;
        const blocked_pop done = bi->second;
        forget_waiter(seq);

        client_connection* c =
            (done.fd >= 0 && done.fd < MAX_FDS) ? m_conn_idx[done.fd] : nullptr;
        if (!c || c->closing) continue;
        deliver_pop(c, {}, nullptr);
        c->blocked = false;
        if (!c->write_pending && SOCKETLEY_UNLIKELY(!flush_write_queue(c)))
        { c->closing = true; continue; }
        pump(c);
        if (SOCKETLEY_UNLIKELY(!flush_responses(c)))
        { c->closing = true; continue; }
    }
    arm_block_timer();
}

void cache_instance::drop_blocked(int fd)
{
    if (SOCKETLEY_LIKELY(m_blocked.empty()))
        return;
    // A blocked connection stops reading, so it holds at most one waiter and
    // the descriptor index is enough to find it.
    auto it = m_wait_fd.find(fd);
    if (it == m_wait_fd.end())
        return;
    forget_waiter(it->second);
}

bool cache_instance::block_pop(client_connection* conn, std::string_view* args,
                               int argc, bool from_head)
{
    // One waiter per descriptor, stated here because m_wait_fd holds one entry
    // per fd and drop_blocked() forgets exactly that one: a second parked here
    // would overwrite the index and orphan the first in m_blocked and
    // m_wait_key, where a zero deadline means sweep_blocked() never reaches it
    // either.  The callers make this impossible -- a blocked connection stops
    // being read, and EXEC answers rather than parking -- so this is the
    // invariant restated where it is relied upon, not a path.
    if (SOCKETLEY_UNLIKELY(conn->blocked))
        return false;

    // The last argument is the timeout, so there is at least one key before it.
    double secs = 0;
    if (!parse_double_sv(args[argc - 1], secs) || secs < 0)
        return false;

    blocked_pop w;
    w.fd        = conn->fd;
    w.from_head = from_head;
    w.resp      = conn->resp_mode;
    w.seq       = ++m_block_seq;
    for (int i = 1; i < argc - 1; ++i) w.keys.emplace_back(args[i]);
    // Past some thirty years the clock would overflow into the past, and a wait that long is a wait for good.
    if (secs > 0 && secs < 1e9)
        w.deadline = std::chrono::steady_clock::now()
                   + std::chrono::milliseconds(static_cast<int64_t>(secs * 1000.0));

    const uint64_t seq = w.seq;
    auto [it, fresh] = m_blocked.emplace(seq, std::move(w));
    (void)fresh;
    blocked_pop& parked = it->second;
    if (parked.needs_tick())
        ++m_ticking_waiters;
    parked.slots.reserve(parked.keys.size());
    for (const auto& k : parked.keys)
    {
        auto& q = m_wait_key[k];
        parked.slots.push_back(q.insert(q.end(), seq));
    }
    m_wait_fd[conn->fd] = seq;
    conn->blocked = true;
    arm_block_timer();
    return true;
}

// ─── INFO ───

void cache_instance::build_info_reply(std::string& out, bool whole) const
{
    // The runtime's figures on its shared port, from what every shard published, and this shard's on its own port,
    // where a cluster client is asking one node.
    const auto& tbl = shard_stats_table();
    whole = whole && m_shard_n > 1 && tbl.mapped() && tbl.count() == m_shard_n;
    uint64_t used = m_store.get_memory_used(), keys = m_store.size();
    if (whole)
        for (uint32_t sh = 0; sh < m_shard_n; ++sh)
            if (sh != m_shard_i)
            {
                keys += tbl.word_at(sh, 0);
                used += tbl.word_at(sh, 1);
            }
    out.reserve(512);
    out += "# Server\r\n";
    out += "redis_version:7.0.0\r\n";        // the dialect spoken, not our own
    out += "socketley_version:" SOCKETLEY_VERSION "\r\n";
    out += "tcp_port:" + std::to_string(get_port()) + "\r\n";
    out += "\r\n# Clients\r\n";
    out += "connected_clients:" + std::to_string(whole ? tbl.sum_active() : m_clients.size()) + "\r\n";
    out += "\r\n# Memory\r\n";
    out += "used_memory:" + std::to_string(used) + "\r\n";
    out += "maxmemory:" + std::to_string(whole ? get_max_memory() : m_store.get_max_memory()) + "\r\n";
    out += "\r\n# Stats\r\n";
    out += "total_commands_processed:" + std::to_string(m_stat_commands) + "\r\n";
    out += "\r\n# Replication\r\n";
    // The replication role, and not whether the cache is read-only: derived
    // from m_mode, a follower reported "master" unless it also happened to be
    // read-only, which is the one field a client asks this section for.
    const bool is_follower = (m_repl_role == repl_follower);
    out += std::string("role:") + (is_follower ? "slave" : "master") + "\r\n";
    if (is_follower)
    {
        // Whom it follows and whether the link is standing.  A follower that
        // never reached its master answers every read out of an empty dataset
        // and is otherwise indistinguishable from one in sync; m_master exists
        // only once the connect completed and a read was armed on it, so its
        // presence is the link.  A target that was never usable leaves the host
        // empty and the port 0, which is the honest answer to "where".
        std::string master_host;
        uint16_t master_port = 0;
        socketley::dial_addr::refusal(m_replicate_target, master_host, master_port);
        out += "master_host:" + master_host + "\r\n";
        out += "master_port:" + std::to_string(master_port) + "\r\n";
        // Connected is not synced, and a follower that reports "up" while the
        // dump is still arriving is answering out of a dataset it is in the
        // middle of replacing -- the same two fields the dialect uses, for the
        // same reason.
        const bool syncing = (m_master && !m_master->synced);
        out += std::string("master_link_status:") +
               ((m_master && m_master->synced) ? "up" : "down") + "\r\n";
        out += std::string("master_sync_in_progress:") + (syncing ? "1" : "0") + "\r\n";
    }
    else
    {
        size_t live = 0;
        for (const auto& f : m_followers)
            if (f && !f->dead && f->fd >= 0)
                ++live;
        out += "connected_slaves:" + std::to_string(live) + "\r\n";
    }
    out += "\r\n# Cluster\r\n";
    out += std::string("cluster_enabled:") + (m_cluster_on ? "1" : "0") + "\r\n";
    out += "\r\n# Keyspace\r\n";
    // This shard's slice on a per-shard port, which is what a cluster client means when it asks a node, and what
    // DBSIZE answers there for the same reason.
    if (keys > 0)
        out += "db0:keys=" + std::to_string(keys) + ",expires=0,avg_ttl=0\r\n";
}

// ─── Pub/Sub publish ───

int cache_instance::publish(std::string_view channel, std::string_view message)
{
    const auto* subs = m_store.get_subscribers(channel);
    int count = 0;

    if (subs && !subs->empty())
    {
        // Lazily built per-format messages (avoid building both if only one type exists)
        std::string text_msg;
        std::string resp_msg;
        // Placed once per format at its first subscriber, then only sliced.
        std::shared_ptr<const std::string> text_seg, resp_seg;
        uint32_t text_off = 0, resp_off = 0;

        for (int fd : *subs)
        {
            if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
                continue;

            auto* sub_conn = m_conn_idx[fd];
            // A promoted follower has had its subscriptions dropped and should
            // never appear here, and the check stays because delivering to it
            // would write into the middle of the replication stream.
            if (sub_conn->closing || sub_conn->is_follower)
                continue;

            // These two marks defer a teardown to an armed read, which
            // conn_reachability.h refuses, and it is sound because neither is
            // about the peer -- measured, 952 of 952 subscribers reached and
            // closed when left to the read against 0 when routed through
            // classify() -- while the defect that paragraph left open was
            // fixed in get_sqe_when_full().

            // The bound on a subscriber that has stopped reading is memory
            // rather than entries, and reaching it needs a write in flight, so
            // the chokepoint sees the connection on that completion
            // regardless.
            if (sub_conn->write_queue.bytes() >= write_buffer_bytes())
            {
                // Said out loud, on the house rule flush_responses() states for
                // the same drop on the reply path: "dropping the connection is
                // right but must not happen quietly".  Two doors here were the
                // quiet ones, and a subscriber that stops receiving without a
                // word is indistinguishable from a channel that went idle.
                //
                // Once per subscriber and not once per publish: `closing` is
                // set, and the test at the top of this loop skips it from here
                // on.
                std::cerr << "[cache] subscriber " << fd << " on channel '"
                          << channel << "' is not draining its socket ("
                          << sub_conn->write_queue.bytes()
                          << " bytes queued), dropping its subscription\n";
                sub_conn->closing = true;
                continue;
            }

            std::string& out = sub_conn->resp_mode ? resp_msg : text_msg;
            std::shared_ptr<const std::string>& seg = sub_conn->resp_mode ? resp_seg : text_seg;
            uint32_t& off = sub_conn->resp_mode ? resp_off : text_off;
            if (out.empty())
            {
                if (sub_conn->resp_mode)
                {
                    // RESP pub/sub: *3\r\n$7\r\nmessage\r\n$<chanlen>\r\n<chan>\r\n$<msglen>\r\n<msg>\r\n
                    out.reserve(32 + channel.size() + message.size());
                    out.append("*3\r\n$7\r\nmessage\r\n");
                    resp::encode_bulk_into(out, channel);
                    resp::encode_bulk_into(out, message);
                }
                else
                {
                    out.reserve(8 + channel.size() + 1 + message.size() + 1);
                    out.append("message ");
                    out.append(channel.data(), channel.size());
                    out.push_back(' ');
                    out.append(message.data(), message.size());
                    out.push_back('\n');
                }
            }

            if (!seg)
            {
                auto& place = sub_conn->resp_mode ? m_pub_seg_resp : m_pub_seg_text;
                off = socketley::place_in_segment(place, out);
                seg = place;
            }
            // A subscriber still queued behind the last message takes this one
            // by growing that slice: no copy and no new entry per message.
            sub_conn->write_queue.push_slice(seg, off, static_cast<uint32_t>(out.size()));

            if (!sub_conn->write_pending && SOCKETLEY_UNLIKELY(!flush_write_queue(sub_conn)))
            {
                // Marking is all that is allowed here, because close_client()
                // would call unsubscribe_all() on the set this loop is walking
                // -- and what is left of this branch is a ring that is closed
                // or a kernel that will not wait, both already logged.
                sub_conn->closing = true;
                continue;
            }
            count++;
        }
    }

    // And the pattern subscribers, which are matched rather than looked up --
    // the reason they are a second map and the reason a shard holding one has
    // to be woken by every publish.  Walked only when there are any, so a
    // cache nobody psubscribes to pays one empty() test.
    if (SOCKETLEY_UNLIKELY(m_store.has_patterns()))
    {
        for (const auto& [pat, fds] : m_store.patterns())
        {
            // Views on both sides: the channel was copied into a std::string
            // only so fnmatch could have a terminator, and every pattern then
            // cost two strlen calls on lengths both sides already knew.
            if (!socketley::glob_match(pat, channel))
                continue;
            // Built once a pattern for each protocol and placed once, as the channel path does, not once a psubscriber.
            std::string p_resp, p_text;
            std::shared_ptr<const std::string> p_resp_seg, p_text_seg;
            uint32_t p_resp_off = 0, p_text_off = 0;
            for (int fd : fds)
            {
                if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) continue;
                auto* pc = m_conn_idx[fd];
                if (pc->closing || pc->is_follower) continue;
                if (pc->write_queue.bytes() >= write_buffer_bytes())
                {
                    // The pattern is named as well as the channel, because a
                    // psubscriber dropped on one channel of a pattern is not
                    // findable from the channel alone.
                    std::cerr << "[cache] psubscriber " << fd << " on pattern '"
                              << pat << "' matching '" << channel
                              << "' is not draining its socket ("
                              << pc->write_queue.bytes()
                              << " bytes queued), dropping its subscription\n";
                    pc->closing = true;
                    continue;
                }

                // pmessage and not message: the pattern is part of the reply,
                // because a client subscribed to two patterns cannot otherwise
                // tell which one matched.
                std::string& out = pc->resp_mode ? p_resp : p_text;
                if (out.empty())
                {
                    if (pc->resp_mode)
                    {
                        resp::encode_array_header_into(out, 4);
                        resp::encode_bulk_into(out, "pmessage");
                        resp::encode_bulk_into(out, pat);
                        resp::encode_bulk_into(out, channel);
                        resp::encode_bulk_into(out, message);
                    }
                    else
                    {
                        out.append("pmessage ");
                        out.append(pat); out.push_back(' ');
                        out.append(channel.data(), channel.size()); out.push_back(' ');
                        out.append(message.data(), message.size()); out.push_back('\n');
                    }
                }
                std::shared_ptr<const std::string>& seg = pc->resp_mode ? p_resp_seg : p_text_seg;
                uint32_t& off = pc->resp_mode ? p_resp_off : p_text_off;
                if (!seg)
                {
                    auto& place = pc->resp_mode ? m_pub_seg_resp : m_pub_seg_text;
                    off = socketley::place_in_segment(place, out);
                    seg = place;
                }
                pc->write_queue.push_slice(seg, off, static_cast<uint32_t>(out.size()));
                if (!pc->write_pending && SOCKETLEY_UNLIKELY(!flush_write_queue(pc)))
                { pc->closing = true; continue; }
                count++;
            }
        }
    }

    // The cross-runtime half, done by one shard only, because each of N shards
    // runs this same publish() and without the guard every sibling's Lua
    // subscriber would fire once per shard.
    if (!m_serving_shard_batch)
    {
        if (auto* mgr = get_runtime_manager())
            mgr->dispatch_publish(get_name(), channel, message);
    }

    return count;
}

// ─── Maxmemory / Eviction ───

// --maxmemory is the runtime's, and a key lives on one shard, so each shard's store holds its share of it.
void cache_instance::set_max_memory(size_t bytes)
{
    m_max_memory = bytes;
    const uint32_t n = std::max<uint32_t>(1, get_shards());
    m_store.set_max_memory(bytes && n > 1 ? std::max<size_t>(1, bytes / n) : bytes);
}

size_t cache_instance::get_max_memory() const
{
    return m_max_memory;
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

// The two flags are one setting, so the later one typed wins.
void cache_instance::set_cluster(bool enabled)
{
    m_cluster_forced = enabled;
    if (enabled)
        m_no_cluster = false;
}

void cache_instance::set_no_cluster(bool enabled)
{
    m_no_cluster = enabled;
    if (enabled)
        m_cluster_forced = false;
}

bool cache_instance::get_no_cluster() const
{
    return m_no_cluster;
}

// get_shards() and get_listen_path() and not what setup() cached, because the
// daemon's placeholder asks this too, for listen_addresses().
bool cache_instance::cluster_mode() const
{
    if (m_no_cluster)
        return false;
    return m_cluster_forced || (get_shards() > 1 && get_listen_path().empty());
}

void cache_instance::set_public(bool enabled)
{
    m_public = enabled;
}

bool cache_instance::get_public() const
{
    return m_public;
}

bool cache_instance::get_cluster() const
{
    return m_cluster_forced;
}

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

    // ─── What an empty target means ────────────────────────────────────────
    // An empty target means follows nobody rather than follows something
    // unspecified, because assigning repl_follower unconditionally turned
    // every `edit` of a plain cache into a follower of nothing that could
    // never become a leader again.
    // ─── Why a leader is left alone ────────────────────────────────────────
    // repl_leader is established at runtime and owns live sockets, so a config
    // change may not revoke it: an edit that touched only the eviction policy
    // demoted a leader and every write after it stopped reaching a healthy
    // follower.
    if (m_repl_role == repl_leader)
        return;

    m_repl_role = m_replicate_target.empty() ? repl_none : repl_follower;
}

std::string_view cache_instance::get_replicate_target() const
{
    return m_replicate_target;
}

cache_instance::repl_role cache_instance::get_repl_role() const
{
    return m_repl_role;
}

// ─── A replica of a cluster cache ───

namespace {

// The same monotonic base every order's validity is counted from.
uint64_t role_clock_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

}   // namespace

void cache_instance::refuse_fenced(client_connection* conn, bool resp)
{
    static constexpr std::string_view why = "this replica holds no cluster lease: it answers nobody until the cluster tells it what it is";
    if (resp)
    {
        std::string text = "CLUSTERDOWN ";
        text.append(why);
        resp::encode_error_code_into(conn->response_buf, text);
        return;
    }
    conn->response_buf.append("error: ");
    conn->response_buf.append(why);
    conn->response_buf.push_back('\n');
}

void cache_instance::on_replica_order(std::string_view payload)
{
    if (!m_role)
        return;
    socketley::cluster::replica_order o;
    if (!socketley::cluster::decode(payload, o))
    {
        LOG_WARN("cache: a replica order this build cannot read was ignored");
        return;
    }
    const auto effect = m_role->order(o, role_clock_ms());
    apply_role(effect.mode, effect.retarget);
    arm_role_timer();
}

// What the replica does about the mode the order in force puts it in, where a repeated order changes nothing.
void cache_instance::apply_role(socketley::cluster::replica_mode mode, bool retarget)
{
    using socketley::cluster::replica_mode;
    if (mode != m_role_mode)
        LOG_INFO(("cache \"" + std::string(get_name()) + "\": " + socketley::cluster::mode_name(m_role_mode) + " -> "
                  + socketley::cluster::mode_name(mode)).c_str());
    m_role_mode     = mode;
    m_fenced        = mode == replica_mode::fenced;
    m_leads_cluster = mode == replica_mode::primary;

    switch (mode)
    {
    case replica_mode::fenced:
        // Nothing is torn down: a copy that keeps following stays current, and the lease may come back.
        m_mode = cache_mode_readonly;
        return;

    case replica_mode::primary:
        m_mode = m_mode_asked;
        if (m_repl_role == repl_follower)
        {
            // Promoted: it follows nobody now, and what it had copied is what it leads from.
            m_repl_role = repl_none;
            m_replicate_target.clear();
            drop_master();
        }
        return;

    case replica_mode::follower:
        m_mode = cache_mode_readonly;
        if (m_repl_role == repl_leader)
        {
            // Demoted: the followers it had were following the wrong one, and dial the right one when told.
            for (auto& f : m_followers)
                f->dead = true;
            reap_followers();
            m_repl_role = repl_none;
        }
        follow(std::string(m_role->target()), retarget);
        return;
    }
}

void cache_instance::follow(const std::string& target, bool retarget)
{
    if (target != m_replicate_target || m_repl_role != repl_follower)
    {
        set_replicate_target(target);
        retarget = true;
    }
    if (retarget)
    {
        m_master_attempt = 0;
        drop_master();
    }
    if (!m_master && !m_master_dial && !m_master_retry && m_loop)
        if (!connect_to_master())
            schedule_master_retry();
}

// Shut down and not torn down, for the reason the sync deadline gives: the read is still armed, and its completion with
// zero is what walks the one drop path that already knows how to release the link and dial again.
void cache_instance::drop_master()
{
    if (m_master && m_master->fd >= 0)
        ::shutdown(m_master->fd, SHUT_RDWR);
}

// One timer at a time, armed for what the order in force has left and re-armed from its own firing, so a stream of
// renewals costs a submission per lease and not one per order.
void cache_instance::arm_role_timer()
{
    if (!m_loop || !m_role || m_role_timer_armed)
        return;
    const uint64_t left = m_role->left_ms(role_clock_ms());
    if (left == 0)
        return;
    if (!m_role_timer)
    {
        m_role_timer = std::make_unique<timer_op>();
        m_role_timer->req = { this, nullptr, -1, 0, op_timeout };
    }
    m_role_timer->ts.tv_sec  = static_cast<long>(left / 1000);
    m_role_timer->ts.tv_nsec = static_cast<long>((left % 1000) * 1000000);
    m_role_timer_armed = m_loop->submit_timeout(&m_role_timer->ts, &m_role_timer->req);
}

void cache_instance::role_lapsed()
{
    m_role_timer_armed = false;
    if (!m_role)
        return;
    const auto mode = m_role->mode(role_clock_ms());
    if (mode == socketley::cluster::replica_mode::fenced && m_role_mode != mode)
    {
        LOG_WARN(("cache \"" + std::string(get_name()) + "\": no order from the daemon within the lease, so this replica is fenced").c_str());
        apply_role(mode, false);
    }
    arm_role_timer();
}

void cache_instance::follower_kick(follower_conn& f)
{
    // fd < 0 means the client this follower was promoted from has gone, and
    // submitting anyway is how the whole replication stream ended up in an
    // unrelated client's socket with every write reporting success.
    if (f.write_pending || f.dead || f.fd < 0 || !m_loop)
        return;

    // Safe to touch `out` only now that nothing is in flight.
    if (f.out_off == f.out.size())
    {
        f.out.clear();
        f.out_off = 0;
        if (!f.queued.empty())
            f.out.swap(f.queued);
    }
    if (f.out.empty())
        return;

    // Bounded per write, because the length field is 32 bits and a dump is not.
    constexpr size_t max_write = size_t{1} << 30;
    f.in_flight = std::min(f.out.size() - f.out_off, max_write);
    f.write_req = { this, nullptr, f.fd, static_cast<uint32_t>(f.in_flight), op_write };
    f.write_pending = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_write(f.fd, f.out.data() + f.out_off,
                                                 static_cast<uint32_t>(f.in_flight), &f.write_req)))
    {
        // Nothing restarts the stream after this, so the follower is dropped
        // rather than left silently frozen at an old snapshot -- a reconnect
        // and a fresh dump is recoverable.
        f.write_pending = false;
        f.in_flight = 0;
        f.dead = true;
        LOG_WARN("cache: replication write refused by the ring, dropping the follower");
    }
}

// The whole dataset of a full sync moves in when nothing is queued ahead of it, where an append held it twice at once.
bool cache_instance::follower_write_owned(follower_conn& f, std::string&& data)
{
    if (f.dead || f.fd < 0 || !f.queued.empty())
        return follower_write(f, std::string_view(data));
    f.queued = std::move(data);
    return follower_write(f, std::string_view{});
}

bool cache_instance::follower_write(follower_conn& f, std::string_view data)
{
    if (f.dead || f.fd < 0)
        return false;

    f.queued.append(data.data(), data.size());

    if (f.backlog() > MAX_FOLLOWER_PENDING + f.sync_left)
    {
        std::cerr << "[cache] follower too far behind ("
                  << f.backlog() << " bytes queued), dropping\n";
        return false;
    }

    // follower_kick() gives up on the follower when its write cannot be handed
    // to the ring; report that here rather than letting the caller believe the
    // data is on its way.
    follower_kick(f);
    return !f.dead;
}

void cache_instance::handle_follower_write(struct io_uring_cqe* cqe, follower_conn& f)
{
    f.write_pending = false;

    if (cqe->res <= 0)
    {
        f.dead = true;
        return;
    }

    // Replication bytes are this runtime's wire traffic too, counted in each
    // handler for the reason the bytes_in note in handle_read() gives.
    stat_add(m_stat_bytes_out, static_cast<uint64_t>(cqe->res));

    // A short write is normal; only the acknowledged prefix may be dropped.
    size_t written = std::min(static_cast<size_t>(cqe->res), f.in_flight);
    f.out_off += written;
    f.sync_left -= std::min(f.sync_left, written);
    f.in_flight = 0;

    follower_kick(f);
}

void cache_instance::reap_followers()
{
    for (auto it = m_followers.begin(); it != m_followers.end(); )
    {
        // A follower with a write still in flight has to stay alive until its
        // completion arrives — the kernel still points at its buffer.
        if (!(*it)->dead || (*it)->write_pending)
        {
            ++it;
            continue;
        }

        // The socket belongs to the client_connection this follower was
        // promoted from, so the connection is asked to go rather than the
        // descriptor taken -- and marked rather than closed, because this runs
        // from inside command handling.
        const int fd = (*it)->fd;
        if (fd >= 0 && fd < MAX_FDS && m_conn_idx[fd])
        {
            m_conn_idx[fd]->closing = true;
            shutdown(fd, SHUT_RDWR);
        }
        it = m_followers.erase(it);
    }
}

void cache_instance::detach_follower(int fd)
{
    if (m_followers.empty() || fd < 0)
        return;

    for (auto& f : m_followers)
    {
        if (f->fd != fd)
            continue;
        // The descriptor goes back with the client and only buffers remain, so
        // an in-flight write keeps going to the socket it was submitted
        // against and only new submissions have to be stopped.
        f->fd = -1;
        f->dead = true;
    }
    reap_followers();
}

cache_instance::follower_conn* cache_instance::follower_for_fd(int fd)
{
    if (fd < 0)
        return nullptr;
    for (auto& f : m_followers)
        if (f->fd == fd)
            return f.get();
    return nullptr;
}

void cache_instance::refuse_follower_input(client_connection* conn)
{
    // The bytes are dropped and not parsed, because executing them would
    // produce a response and the follower buffer owns this socket now.
    conn->partial.clear();

    if (conn->follower_refused)
        return;
    conn->follower_refused = true;

    LOG_WARN("cache: command received on a replication follower connection, ignoring");

    // Said through the replication stream itself so the socket keeps exactly
    // one writer, once per connection, or a client could push the follower
    // past its cap with error lines alone.
    follower_conn* f = follower_for_fd(conn->fd);
    if (!f)
        return;
    if (!follower_write(*f, "error: replication follower, commands are not accepted\n"))
    {
        f->dead = true;
        reap_followers();
    }
}

// A replicated command names at most one key, because the follower's text
// interpreter takes the whole remainder as one and a sharded follower's slices
// own separate keys -- an obligation this function cannot check and each
// emitter names.
void cache_instance::replicate_command(std::string_view cmd)
{
    // Every mutation the followers would be told about is a mutation the
    // journal has to hold, in one chokepoint, so a write path added later
    // cannot reach one and miss the other.
    if (SOCKETLEY_UNLIKELY(m_journal.is_open() && !m_journal_replaying))
        journal_mutation(cmd);

    // The position in the stream, counted whether or not anybody is listening, so that two followers that joined at
    // different moments can be told apart by how far into it each has come.
    if (SOCKETLEY_UNLIKELY(m_leads_cluster))
        m_role->record();

    if (m_repl_role != repl_leader || m_followers.empty())
        return;

    // ─── A VALUE WITH A NEWLINE IN IT ───────────────────────────────────────
    // Framed by the same rule ipc_framing.h uses, only when a line cannot
    // carry the command, so every value without a newline is byte-identical on
    // the wire and an old follower stores nothing rather than a truncated
    // value plus a command nobody sent.
    std::string& line = m_repl_line;
    if (ipc_frame::needs_frame(cmd))
    {
        line = ipc_frame::encode(cmd);
    }
    else
    {
        line.assign(cmd.data(), cmd.size());
        line.push_back('\n');
    }

    // A follower shard that named its slice gets the records of its own keys and every keyless one, so a sharded
    // follower costs one stream and not one per shard; the key is read once, and its owner once per shard count.
    std::string_view key;
    int      keyed   = -1;
    uint32_t owner_n = 0, owner = 0;
    for (auto& f : m_followers)
    {
        if (f->shard_n > 1)
        {
            if (keyed < 0)
                keyed = cache_record_key(cmd, key) ? 1 : 0;
            if (keyed)
            {
                if (owner_n != f->shard_n)
                {
                    owner_n = f->shard_n;
                    owner   = cache_shard_of(key, owner_n);
                }
                if (owner != f->shard_i)
                    continue;
            }
        }
        if (!follower_write(*f, line))
            f->dead = true;
    }
    // One large value does not keep its size here for the life of the leader.
    if (line.capacity() > 64 * 1024)
        std::string().swap(line);
    reap_followers();
}

void cache_instance::handle_replicate_request(client_connection* conn, std::string_view shard, std::string_view of)
{
    // A TLS cache is not a replication leader, which no configuration gate can
    // decide because promotion happens when a client asks -- and follower_conn
    // writes raw bytes around the record layer, which would put the whole
    // dataset in the clear.
    if (m_tls)
    {
        conn->response_buf.append(
            "error: this cache terminates TLS on its listener and replication is "
            "not encrypted -- the dump and the command stream would go out in "
            "cleartext\n", 143);
        return;
    }

    // A replica of a cluster cache is a source only while it is the primary and holds its lease, so a follower that
    // dialled it a moment too early, or a fenced primary, is told so and dials again.
    if (m_role && (m_fenced || m_role_mode != socketley::cluster::replica_mode::primary))
    {
        conn->response_buf.append("error: this replica is not the primary\n");
        return;
    }

    // Client sent "REPLICATE\n" — promote self to leader, send full dump
    if (m_repl_role == repl_follower)
    {
        conn->response_buf.append("error: this node is a follower\n", 31);
        return;
    }

    // A follower is a socket and interactive execute() has none, so
    // registering one put a follower in the list that could never be written
    // to.
    if (conn->fd < 0)
    {
        conn->response_buf.append("error: replicate needs a connection\n", 36);
        return;
    }

    // ─── What REPLICATE promises ───────────────────────────────────────────
    // Promotion makes this runtime the sole writer on the descriptor, because
    // two writes in flight are ordered by nothing and a reply landing inside a
    // replicated command cannot be resynced from -- which is also why
    // promotion is refused while the ordinary path still owes this client
    // bytes.
    if (!conn->response_buf.empty() || !conn->write_queue.empty() ||
        conn->write_pending)
    {
        conn->response_buf.append("error: replicate needs an idle connection\n", 42);
        return;
    }

    // `replicate <i> <n>` is shard i of a follower of n shards, which takes only its slice; plain `replicate`, and
    // what an older follower sends, takes everything.
    uint32_t shard_i = 0, shard_n = 1;
    if (!shard.empty() || !of.empty())
    {
        if (!parse_int_sv(shard, shard_i) || !parse_int_sv(of, shard_n) || shard_n < 1 ||
            shard_n > max_shards || shard_i >= shard_n)
        {
            conn->response_buf.append("error: usage: replicate [<shard> <shards>]\n");
            return;
        }
    }

    m_repl_role = repl_leader;
    // Ordinary command service on this connection ends here, not when the dump
    // finishes: the refusal in handle_read() has to cover anything the client
    // pipelined behind the REPLICATE line as well.
    conn->is_follower = true;

    // Any channel this connection subscribed to goes with the promotion,
    // because publish() writes straight into the write queue and the
    // subscriber can no longer unsubscribe itself.
    m_store.unsubscribe_all(conn->fd);
    m_store.punsubscribe_all(conn->fd);

    // Register first, then queue the dump: both the dump and every command that
    // follows travel through the same buffer, which is what keeps them ordered.
    auto f = std::make_unique<follower_conn>();
    f->fd = conn->fd;
    f->shard_i = shard_i;
    f->shard_n = shard_n;
    follower_conn& fc = *f;
    m_followers.push_back(std::move(f));

    // The acknowledgement travels through the follower buffer ahead of the
    // dump, because response_buf would be a second independent writer on the
    // same socket.
    bool ok = follower_write(fc, "ok\n") && send_full_dump(fc);
    if (!ok)
    {
        std::cerr << "[cache] full sync to follower failed, dropping it\n";
        fc.dead = true;
        reap_followers();
    }
}

// The end of a full dump, which the stream has no other way to mark.  Read by
// the link rather than handed to the interpreter, so it never becomes a command
// a client could send, and it cannot collide with a framed line because those
// begin with ipc_frame::marker and this begins with a letter.
static constexpr std::string_view repl_sync_done = "replicate-sync-done";

bool cache_instance::send_full_dump(follower_conn& f)
{
    // A full sync replaces the follower's dataset rather than merging into it.
    // The dump is a list of `set` and `rpush` lines with nothing in front of
    // them, so a follower that reconnects still holding data keeps every key
    // the leader dropped meanwhile and appends a second time to every list it
    // already had -- measured, a list of two came back as four.
    std::string buf = "flushall\n";
    buf.reserve(65536);
    m_store.dump_commands(buf, f.shard_i, f.shard_n);

    buf.append(repl_sync_done);
    // Where in the primary's stream this dump was taken, which is what tells two followers' copies apart.
    if (m_role)
    {
        buf.push_back(' ');
        buf.append(std::to_string(m_role->offset()));
    }
    buf.push_back('\n');

    // Sent even when the dump adds nothing, because a leader flushed while the
    // link was down is exactly the case that leaves the follower full.
    // Queued rather than written synchronously, because a dataset exceeds the
    // socket buffer and the follower may be a runtime inside this very daemon.
    f.sync_left = f.backlog() + buf.size();
    return follower_write_owned(f, std::move(buf));
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
    if (!parse_int_sv(port_sv, port))
        return false;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;
    // A replica only reads, and a leader gone without a FIN would otherwise leave it waiting on the link for ever.
    socket_tuning::keepalive_dead_peer(fd);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
    {
        // A name, which is what the manual offers -- "--replicate host:port",
        // "replicate_target: Leader host:port" -- and what inet_pton alone
        // refused, so `--replicate localhost:6379` could never connect.
        // Resolved off the loop, since a replica re-dials every fifth of a second and a resolver that hangs held the
        // whole cache each time; the dial is asked again shortly while the answer is out.
        std::vector<socketley::async_resolver::address> found;
        const auto st = m_resolver.lookup(host, AF_INET, found);
        if (st != socketley::async_resolver::state::ready || found.empty() ||
            found.front().len < sizeof(struct sockaddr_in))
        {
            close_tracked(fd);
            if (st == socketley::async_resolver::state::pending && !m_master_retry)
            {
                auto t = std::make_unique<timer_op>();
                t->ts.tv_sec = 0;
                t->ts.tv_nsec = 100 * 1000000L;
                t->req = { this, nullptr, -1, 0, op_timeout };
                if (m_loop && m_loop->submit_timeout(&t->ts, &t->req))
                    m_master_retry = std::move(t);
            }
            return false;
        }
        addr.sin_addr = reinterpret_cast<const struct sockaddr_in*>(&found.front().addr)->sin_addr;
    }

    // Read-only from the moment this cache intends to follow, and not once the
    // link stands: the dial is asynchronous now, and a follower that took
    // writes in the window before its leader answered would have them erased
    // without a word by the dump that follows.  A leader that is down does not
    // make a follower writable either, which is what a replica is.
    m_mode = cache_mode_readonly;

    // Asked of the ring rather than waited for, because the retry below cannot
    // block the loop for five seconds every time a leader is slow to answer.
    // One dial at a time: the struct holds the address for as long as the
    // kernel is reading it.
    auto dial = std::make_unique<master_dial>();
    dial->fd = fd;
    dial->addr = addr;
    dial->target = m_replicate_target;
    dial->req = { this, nullptr, fd, 0, op_connect };

    if (!m_loop ||
        SOCKETLEY_UNLIKELY(!m_loop->submit_connect(fd,
                reinterpret_cast<const struct sockaddr*>(&dial->addr),
                sizeof(dial->addr), &dial->req)))
    {
        close_tracked(fd);
        return false;
    }

    m_master_dial = std::move(dial);
    return true;
}

// The dial landing.  Everything that used to follow the blocking connect is
// here, because this is where the socket first exists as a connected one.
void cache_instance::handle_master_connect(struct io_uring_cqe* cqe, io_request* req)
{
    // A completion for a dial nobody is waiting for any more -- the target
    // changed, or the runtime stopped -- owns nothing and must touch nothing.
    if (!m_master_dial || req != &m_master_dial->req)
        return;

    auto dial = std::move(m_master_dial);
    const int fd = dial->fd;

    // The daemon named another primary while this dial was out, or none at all: what connected is not who is wanted.
    if (dial->target != m_replicate_target || m_repl_role != repl_follower)
    {
        close_tracked(fd);
        schedule_master_retry();
        return;
    }

    if (cqe->res < 0)
    {
        close_tracked(fd);
        LOG_ERROR(("cache \"" + std::string(get_name()) + "\": could not dial master \"" +
                   m_replicate_target + "\": " + std::strerror(-cqe->res)).c_str());
        schedule_master_retry();
        return;
    }

    // Eleven bytes into the send buffer of a socket that has just connected, so
    // the short write this cannot handle is not one that happens; ended by CRLF
    // so a --resp leader's inline reader takes it as the line reader does.
    // A shard of a sharded follower names its slice, and the leader sends it only that.
    const std::string cmd = m_shard_n > 1
        ? "replicate " + std::to_string(m_shard_i) + " " + std::to_string(m_shard_n) + "\r\n"
        : std::string("replicate\r\n");
    if (::write(fd, cmd.data(), cmd.size()) < static_cast<ssize_t>(cmd.size()))
    {
        close_tracked(fd);
        LOG_ERROR("cache: the master link connected and would not take `replicate`");
        schedule_master_retry();
        return;
    }

    // A link of its own and never the previous one reused, because the read
    // armed on the old link survives its socket and a reconnect usually lands
    // on the same fd number.
    auto link = std::make_unique<master_link>();
    link->fd = fd;
    link->read_req = { this, link->buf, fd, sizeof(link->buf), op_read };
    link->read_pending = true;

    if (SOCKETLEY_UNLIKELY(!m_loop || !m_loop->submit_read(fd, link->buf,
                                                           sizeof(link->buf), &link->read_req)))
    {
        // Without this read the node is connected and deaf, so failing the
        // connect outright keeps the follower visibly unsynced rather than
        // silently frozen at an empty dataset.
        LOG_ERROR("cache: read from master could not be armed — replication link not established");
        close_tracked(fd);
        schedule_master_retry();
        return;
    }

    m_master = std::move(link);

    // The backoff is reset by a sync and not by a connect, because a leader
    // that accepts and then says nothing would otherwise get a fresh 1-second
    // retry every time the deadline below dropped it.
    arm_master_sync_deadline();
}

// One deadline at a time, re-armed from its own firing rather than from every
// read: a busy live link would otherwise pay two submissions per read for a
// timer it never needs.
void cache_instance::arm_master_sync_deadline()
{
    if (!m_loop || !m_master || m_master_sync_deadline)
        return;

    auto t = std::make_unique<timer_op>();
    t->ts.tv_sec = 30;
    t->ts.tv_nsec = 0;
    t->req = { this, nullptr, -1, 0, op_timeout };
    m_master->bytes_at_deadline = m_master->bytes_seen;
    if (m_loop->submit_timeout(&t->ts, &t->req))
        m_master_sync_deadline = std::move(t);
}

// The same backoff the server uses for an upstream -- 1, 2, 4, 8, 16 seconds
// capped at 30, with jitter so a shard fleet that lost one leader does not
// dial it back in lockstep.
void cache_instance::schedule_master_retry()
{
    // Not a follower any more, or on the way out: both are answers, and
    // neither is "try again".
    if (!m_loop || m_repl_role != repl_follower || m_replicate_target.empty())
        return;
    if (m_master || m_master_dial || m_master_retry)
        return;

    const uint32_t step = m_master_attempt < 4 ? m_master_attempt : 4;
    int delay_sec = 1 << step;              // 1, 2, 4, 8, 16
    if (delay_sec > 30) delay_sec = 30;
    long jitter_ms = (m_master_attempt * 137L) % 500;
    ++m_master_attempt;

    // A cluster replica is dialled again in a fifth of a second however many times it has failed, because it fails
    // for the ordinary reason that the primary it was given has not been told it is one yet, and waiting a doubling
    // interval for that would be most of a failover.
    if (m_role)
    {
        delay_sec = 0;
        jitter_ms = 200;
    }

    auto t = std::make_unique<timer_op>();
    t->ts.tv_sec = delay_sec;
    t->ts.tv_nsec = jitter_ms * 1000000L;
    t->req = { this, nullptr, -1, 0, op_timeout };
    if (m_loop->submit_timeout(&t->ts, &t->req))
        m_master_retry = std::move(t);
}

void cache_instance::handle_master_read(struct io_uring_cqe* cqe)
{
    if (!m_master)
        return;

    auto& link = *m_master;
    link.read_pending = false;

    if (cqe->res <= 0)
    {
        // Master disconnected, and the link goes with it rather than being
        // kept, because nothing is in flight on it and connect_to_master()
        // hands back a fresh one.
        if (link.fd >= 0)
            close_tracked(link.fd);
        m_master.reset();
        // And connect_to_master() does hand back a fresh one now, on a backoff,
        // which is what this comment used to only promise.
        schedule_master_retry();
        return;
    }

    // The replication stream from the leader is wire traffic in, counted here
    // for the reason the bytes_in note gives.
    stat_add(m_stat_bytes_in, static_cast<uint64_t>(cqe->res));

    link.bytes_seen += static_cast<uint64_t>(cqe->res);
    link.partial.append(link.buf, cqe->res);

    // Framed or line, decided by a first byte no line command can begin with,
    // and scanned by offset with one erase at the end because erasing per
    // command would make a busy leader's batch quadratic.
    size_t scan_from = 0;
    bool   framing_broken = false;
    bool   link_refused   = false;
    while (scan_from < link.partial.size())
    {
        std::string_view line;

        if (link.partial[scan_from] == ipc_frame::marker)
        {
            link.searched = 0;
            size_t next = 0;
            const auto r = ipc_frame::peek_frame(link.partial, scan_from, line, next);
            if (r == ipc_frame::take::need_more)
                break;
            if (r == ipc_frame::take::fatal)
            {
                framing_broken = true;
                break;
            }
            scan_from = next;
        }
        else
        {
            const size_t pos = link.partial.find('\n', scan_from + (scan_from == 0 ? link.searched : 0));
            if (pos == std::string::npos)
            {
                link.searched = link.partial.size() - scan_from;
                // A line is bounded too, as a frame is, or a leader that never ends one fills this process.
                if (link.searched > std::max<size_t>(read_buffer_bytes(), size_t{512} << 20))
                    framing_broken = true;
                break;
            }
            link.searched = 0;
            line = std::string_view(link.partial.data() + scan_from, pos - scan_from);
            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);
            scan_from = pos + 1;
        }

        // The marker, with the primary's position in its stream after it when it is a cluster cache's.
        if (line == repl_sync_done || (line.starts_with(repl_sync_done) && line.size() > repl_sync_done.size()
                                       && line[repl_sync_done.size()] == ' '))
        {
            link.synced = true;
            // A sync is what resets the backoff, not a connect: a leader that
            // accepts and then says nothing would otherwise be re-dialled one
            // second after every deadline, forever, at full rate.
            m_master_attempt = 0;
            if (m_role)
            {
                uint64_t at = 0;
                const std::string_view digits = line.size() > repl_sync_done.size() ? line.substr(repl_sync_done.size() + 1)
                                                                                   : std::string_view{};
                if (!parse_int_sv(digits, at))
                    at = 0;
                m_role->sync_done(at);
            }
            continue;
        }

        // A source that is not a primary answers `replicate` with an error and nothing else, so this link is for a
        // replica that is not, or not yet, the one to follow.
        if (m_role && !link.synced && line.starts_with("error:"))
        {
            link_refused = true;
            break;
        }

        // The copy is nothing from the first line of a dump to its end, and a position in the primary's stream after.
        if (m_role && !line.empty())
        {
            if (link.synced)
                m_role->record();
            else if (!m_role->syncing() && line != "ok")
                m_role->sync_started();
        }

        if (!line.empty())
        {
            // The same interpreter the leader ran, because the hand-picked
            // switch over six commands dropped every incr, append, lpop,
            // expire and mset on the floor with both sides believing they were
            // in sync.
            cache_mode saved = m_mode;
            m_mode = cache_mode_readwrite;

            apply_replicated(line);

            m_mode = saved;
        }
    }

    // The other end said it is not the primary; it is dialled again shortly, when the daemon has told it what it is.
    if (link_refused)
    {
        if (link.fd >= 0)
            close_tracked(link.fd);
        m_master.reset();
        schedule_master_retry();
        return;
    }

    // A length past max_payload means the framing is wrong and no point says
    // where the next command starts, so the link goes rather than the bytes
    // being applied.
    if (framing_broken)
    {
        LOG_ERROR("cache: replication frame or line longer than the protocol allows — "
                  "the link is dropped rather than resynchronised");
        if (link.fd >= 0)
            close_tracked(link.fd);
        m_master.reset();
        schedule_master_retry();
        return;
    }

    if (scan_from > 0)
    {
        if (scan_from >= link.partial.size())
            link.partial.clear();
        else
            link.partial.erase(0, scan_from);
    }

    // Re-submit read
    if (m_loop && link.fd >= 0)
    {
        link.read_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(link.fd, link.buf,
                                                    sizeof(link.buf), &link.read_req)))
        {
            // This read is the only thing that re-arms itself, so a refusal
            // ends replication for good and dropping the socket at least
            // surfaces as a master disconnect.
            LOG_ERROR("cache: read from master refused — the replication link is dropped");
            link.read_pending = false;
            close_tracked(link.fd);
            m_master.reset();
            schedule_master_retry();
        }
    }
}

// ─── Handoff (on with more than one shard; SOCKETLEY_CACHE_HANDOFF=0 turns it off) ───

// A connection whose window chose another shard is handed there once nothing is owed on it and nothing ties it to
// this process; what ties it for good clears the wish, what only has to finish leaves it for the next quiet moment.
void cache_instance::try_handoff(client_connection* conn, int fd)
{
    if (conn->ho_state != client_connection::handoff::none || !m_handoff_on)
        return;
    if (conn->in_multi || conn->in_exec || !conn->watched.empty() || conn->sub_count != 0 || conn->blocked ||
        conn->is_follower || conn->ssl != nullptr || conn->cluster_port || conn->unix_peer || conn->closing ||
        conn->peer_gone || conn->quit_after_flush || conn->wr_shutdown || conn->ho_target >= m_shard_n ||
        conn->ho_target == m_shard_i)
    {
        conn->ho_want = false;
        return;
    }
    if (!conn->batches.empty() || conn->crossing_bytes != 0 || conn->write_pending || conn_has_output(conn) ||
        !conn->response_buf.empty() || conn->read_paused || conn->partial.size() > HO_MAX_BACKLOG)
        return;
    if (socketley::turn_clock::now_ns() < conn->ho_not_before_ns)
        return;

    conn->ho_want  = false;
    conn->ho_tries = 0;
    conn->ho_id    = m_ho_next_id++;
    if (!conn->read_pending)
    {
        handoff_send_now(conn, fd);
        return;
    }
    // The standing read goes first, since a byte it took after the descriptor left would be lost to both shards.
    if (!m_loop || !m_loop->submit_cancel_request(&conn->read_req))
    {
        conn->ho_want = true;
        return;
    }
    conn->ho_state = client_connection::handoff::withdrawing;
}

// One completion of the read being withdrawn: its bytes join what travels, its end sends the connection, and a peer
// that went meanwhile ends the handoff and is served what it sent before the ordinary end of a read takes over.
void cache_instance::handoff_read(client_connection* conn, int fd, struct io_uring_cqe* cqe, io_request* req)
{
    const bool provided = req->type == op_read_provided || is_multishot_recv_op(req->type);
    const int  res      = cqe->res;
    if (res > 0)
    {
        stat_add(m_stat_bytes_in, static_cast<uint64_t>(res));
        if (provided)
            m_loop->for_each_cqe_buf(BUF_GROUP_ID, cqe, [&](char* p, uint32_t n) { conn->partial.append(p, n); });
        else
            conn->partial.append(conn->read_buf.get(), static_cast<size_t>(res));
    }
    else if (res != -ECANCELED && res != -ENOBUFS)
    {
        conn->ho_state = client_connection::handoff::none;
        ++m_stat_ho_aborted;
        serve_buffered(conn, fd);
        handle_read(cqe, req);
        return;
    }
    else if (provided && (cqe->flags & IORING_CQE_F_BUFFER))
        m_loop->return_cqe_buf(cqe, req);

    if (conn->read_pending)
        return;
    if (conn->partial.size() > HO_MAX_BACKLOG)
    {
        handoff_abort(conn, fd);
        return;
    }
    handoff_send_now(conn, fd);
}

// [u64 id][u8 resp_mode | resp_detected << 1][u8 hops][u64 rate-limit tokens][u32 n][n bytes read and not run].
void cache_instance::handoff_send_now(client_connection* conn, int fd)
{
    std::string payload;
    payload.reserve(26 + conn->partial.size());
    socketley::bytes::append64(payload, conn->ho_id);
    payload.push_back(static_cast<char>((conn->resp_mode ? 1 : 0) | (conn->resp_detected ? 2 : 0)));
    payload.push_back(static_cast<char>(conn->ho_hops));
    socketley::bytes::append64(payload, std::bit_cast<uint64_t>(conn->rl_tokens));
    socketley::bytes::append32(payload, static_cast<uint32_t>(conn->partial.size()));
    payload.append(conn->partial);

    switch (hand_off(conn->ho_target, payload, fd))
    {
        case runtime_instance::handoff_send::sent:
            conn->ho_state = client_connection::handoff::sent;
            m_ho_sent.push_back({ fd, conn->ho_id, conn->ho_target });
            return;
        case runtime_instance::handoff_send::busy:
            ++m_stat_ho_busy;
            if (++conn->ho_tries > HO_MAX_TRIES)
            {
                handoff_abort(conn, fd);
                return;
            }
            conn->ho_state = client_connection::handoff::waiting;
            m_ho_waiting.push_back({ fd, conn->ho_id, conn->ho_target });
            return;
        case runtime_instance::handoff_send::gone:
            handoff_abort(conn, fd);
            return;
    }
}

// The connection stays: what was read for the sibling is served here, the read comes back, and the next attempt
// waits a second.
void cache_instance::handoff_abort(client_connection* conn, int fd)
{
    conn->ho_state = client_connection::handoff::none;
    conn->ho_want  = false;
    conn->ho_not_before_ns = socketley::turn_clock::now_ns() + HO_SECOND_NS;
    ++m_stat_ho_aborted;
    serve_buffered(conn, fd);
    conn = m_conn_idx[fd];
    if (!conn || conn->closing || conn->read_pending || conn->read_paused)
        return;
    if (SOCKETLEY_UNLIKELY(!submit_client_read(conn, fd)))
    {
        conn->closing = true;
        if (!conn->write_pending)
            close_client(conn, fd, "read-submit-failed");
    }
}

// What sits in `partial` run as a read would have run it, without arming one.
void cache_instance::serve_buffered(client_connection* conn, int fd)
{
    if (!conn->partial.empty())
    {
        if (!conn->resp_detected)
        {
            conn->resp_detected = true;
            if (conn->partial[0] == '*' || m_resp_forced)
                conn->resp_mode = true;
        }
        pump(conn);
    }
    if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
        conn->closing = true;
    if (SOCKETLEY_UNLIKELY(conn->quit_after_flush))
        conn->closing = true;
    if (conn->closing && !conn->read_pending && !conn->write_pending && conn->batches.empty())
    {
        if (conn_has_output(conn) && flush_write_queue(conn) && conn->write_pending)
            return;
        close_client(conn, fd, "closing-after-handoff");
    }
}

// Retries for links that were busy, and answers that will not come because the link went: the descriptor may have
// reached the sibling, so this shard's copy is closed rather than served beside it.
void cache_instance::handoff_turn()
{
    if (!m_ho_waiting.empty())
    {
        std::vector<ho_ref> waiting;
        waiting.swap(m_ho_waiting);
        for (const ho_ref& w : waiting)
        {
            auto* c = (w.fd >= 0 && w.fd < MAX_FDS) ? m_conn_idx[w.fd] : nullptr;
            if (c && c->ho_id == w.id && c->ho_state == client_connection::handoff::waiting)
                handoff_send_now(c, w.fd);
        }
    }
    for (size_t i = 0; i < m_ho_sent.size();)
    {
        const ho_ref w = m_ho_sent[i];
        auto* c = (w.fd >= 0 && w.fd < MAX_FDS) ? m_conn_idx[w.fd] : nullptr;
        const bool live = c && c->ho_id == w.id && c->ho_state == client_connection::handoff::sent;
        if (live && handoff_link_alive(w.shard))
        {
            ++i;
            continue;
        }
        m_ho_sent[i] = m_ho_sent.back();
        m_ho_sent.pop_back();
        if (live)
            close_client(c, w.fd, "handoff-unanswered");
    }
}

// The sibling's answer: taken, and this shard's copy of the descriptor is closed with nothing said on it; refused,
// and the connection carries on here.
void cache_instance::on_handoff_answer(uint32_t /*shard*/, uint64_t id, bool taken)
{
    for (size_t i = 0; i < m_ho_sent.size(); ++i)
    {
        if (m_ho_sent[i].id != id)
            continue;
        const int fd = m_ho_sent[i].fd;
        m_ho_sent[i] = m_ho_sent.back();
        m_ho_sent.pop_back();
        auto* c = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
        if (!c || c->ho_id != id || c->ho_state != client_connection::handoff::sent)
            return;
        if (taken)
        {
            ++m_stat_ho_out;
            close_client(c, fd, "handed-off");
        }
        else
            handoff_abort(c, fd);
        return;
    }
}

// A sibling's connection becoming this shard's own, with what it had read and not run served before anything new.
bool cache_instance::adopt_handoff(uint32_t /*from*/, std::string_view payload, int fd)
{
    worker_proto::reader r(payload.data(), payload.size());
    r.u64();
    const uint8_t  flags  = r.u8();
    const uint8_t  hops   = r.u8();
    const uint64_t tokens = r.u64();
    const uint32_t n      = r.u32();
    if (fd < 0)
        return false;
    if (!r.ok || static_cast<size_t>(r.end - r.p) != n || !m_handoff_on || !m_loop || fd >= MAX_FDS ||
        connections_full(m_clients.size(), m_max_conns_cached))
    {
        close_tracked(fd);
        return false;
    }
    if (!adopt_client(fd, false, false, true))
        return false;
    auto* conn = m_conn_idx[fd];
    if (!conn)
        return false;

    ++m_stat_ho_in;
    conn->resp_mode     = (flags & 1) != 0;
    conn->resp_detected = (flags & 2) != 0;
    if (conn->rl_max > 0)
        conn->rl_tokens = std::min(conn->rl_max, std::bit_cast<double>(tokens));
    conn->ho_hops = static_cast<uint8_t>(std::min<int>(hops + 1, 30));
    conn->ho_not_before_ns = socketley::turn_clock::now_ns() + (HO_SECOND_NS << std::min<int>(conn->ho_hops - 1, 6));
    conn->partial.assign(r.p, n);
    if (!conn->partial.empty())
    {
        conn->partial_since = std::chrono::steady_clock::now();
        serve_buffered(conn, fd);
    }
    return true;
}

// ─── Stats ───

// The cache-specific half of `stats`, which is the part a worker still pushes,
// because rebuilding it in the daemon reads the placeholder's empty store and
// prints keys:0 for a cache that had just served five SETs.
std::string cache_instance::stats_lines() const
{
    std::ostringstream out;
    out << "keys:" << m_store.size() << "\n"
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
        // The one thing repl_role cannot say: a follower with no link is a
        // follower all the same, and reads as one here until this line.
        << "master_link:" << (m_master ? 1 : 0) << "\n"
        // Beside it rather than folded into it: master_link still answers
        // "is there a socket", which is the question that tells a dial apart
        // from a leader that accepts and then says nothing.
        << "master_sync_in_progress:" << ((m_master && !m_master->synced) ? 1 : 0) << "\n"
        << "followers:" << m_followers.size() << "\n";
    if (m_shard_n > 1)
        out << "shared_port_commands:" << m_stat_shared_cmds << "\n"
            << "relayed_commands:" << m_stat_relayed_cmds << "\n";
    if (m_journal.is_open())
        out << "journal_bytes:" << m_journal.bytes() << "\n"
            << "journal_snapshots:" << m_stat_snapshots << "\n"
            << "journal_snapshot_failures:" << m_stat_snapshot_failures << "\n";
    if (m_handoff_on)
        out << "handoff_out:" << m_stat_ho_out << "\n"
            << "handoff_in:" << m_stat_ho_in << "\n"
            << "handoff_aborted:" << m_stat_ho_aborted << "\n"
            << "handoff_busy:" << m_stat_ho_busy << "\n";
    {
        std::string line;
        m_lat_batch.put(line, "batch_latency");
        out << line;
    }
    if (m_role)
        out << socketley::cluster::report_lines(*m_role, role_clock_ms());
    return out.str();
}
