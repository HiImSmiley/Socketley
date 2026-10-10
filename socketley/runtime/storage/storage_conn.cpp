// The wire side of a storage run: accepting, reading, writing, HTTP framing,
// the streaming of a body into an object and of an object out to a socket.
#include "storage_run.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "lifecycle.h"
#include "s3_names.h"
#include "s3_vhost.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"
#include "../../shared/random_id.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/unix_listener.h"

namespace socketley::storage
{

namespace
{

constexpr size_t   max_head_bytes      = 32 * 1024;
constexpr size_t   pipe_bytes          = 1u << 20;
constexpr size_t   stream_chunk        = 256 * 1024;
// What one recv brings a heavy hook, so the hop to its thread is paid per quarter megabyte.
constexpr size_t   hook_read_bytes     = 256 * 1024;
constexpr size_t   hook_buffers_kept   = 32;
// What a heavy hook is given at least, unless the body ends first.
constexpr size_t   recv_batch_bytes    = 64 * 1024;
// A body arriving slower than 4 MB/s is trickling in, and its next recv waits for the pace tick.
constexpr uint64_t trickle_ns_per_byte = 250;
// How long a trickling body is left to gather in the socket, where what it holds is bounded by the rate above.
constexpr long     pace_ns             = 10'000'000;
// What a trickling body must still owe for its next recv to wait, so the end of a body is never held.
constexpr uint64_t pace_tail_bytes     = 64 * 1024;
// What a body already refused is read and thrown away up to, so the client that
// sent it hears the answer instead of a reset; beyond it the connection closes.
constexpr uint64_t discard_limit       = 64ull << 20;
constexpr int      body_stall_secs     = 60;
// The group of the buffer ring a recv is lent its bytes from, and its geometry: a head is a few hundred
// bytes, so what one buffer holds is what a small body can arrive in.
constexpr uint16_t ring_group          = 5;
constexpr uint32_t ring_buf_bytes      = 16 * 1024;
constexpr uint32_t ring_buf_count      = 64;
// What a recv brings when the ring has none to lend.
constexpr uint32_t fallback_bytes      = 16 * 1024;
// A body this small is taken out of the ring's buffers, and a larger one is read where it will be written.
constexpr uint64_t direct_min          = 32 * 1024;
// What may pile up unread by the phase before the recv that delivers it is stopped.
constexpr size_t   backlog_cap         = 256 * 1024;
constexpr size_t   tls_plain_bytes     = 16 * 1024;
// What one turn of the encryptor puts in front of the kernel.
constexpr size_t   tls_write_slice     = 64 * 1024;
constexpr size_t   tls_write_cap       = 512 * 1024;
constexpr int      write_stall_secs    = 120;

}   // namespace

namespace
{

// Threads that hash large bodies: three a shard, fewer when the shards would together hold more than the machine has
// cores; none to hash on the loop.
unsigned hash_threads(uint32_t shards)
{
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_HASH_THREADS"))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && v >= 0 && v <= 16)
            return static_cast<unsigned>(v);
    }
    const unsigned cpus = std::max(1u, std::thread::hardware_concurrency());
    return std::clamp(cpus / std::max<uint32_t>(shards, 1), 1u, 3u);
}

}   // namespace

storage_run::storage_run(storage_instance& owner, event_loop& loop, store_options opts, authenticator* auth)
    : m_owner(owner), m_loop(loop), m_io(loop, this), m_hash(hash_threads(opts.nshards)),
      m_store(loop, m_io, std::move(opts)),
      m_mpu(loop, m_io, m_store),
      m_notify(loop, m_io, this),
      m_repl(loop, m_io, this, m_store, m_hash,
             [this](const object_meta& m, sse_key& out)
             {
                 s3_error ignored;
                 return sse_data_key(m, std::nullopt, out, ignored);
             }),
      m_scrub(loop, m_io, m_store, m_hash,
              [this](const object_meta& m, sse_key& out)
              {
                  s3_error ignored;
                  return sse_data_key(m, std::nullopt, out, ignored);
              },
              [this](scrubber::finding f) { scrub_found(std::move(f)); }),
      m_compact(loop, m_io, m_store, m_hash),
      m_tier(loop, m_io, m_store, m_hash),
      m_transport(owner.get_runtime_manager() ? &owner.get_runtime_manager()->requests() : nullptr,
                  std::string(owner.get_name())),
      m_node(m_store, m_transport), m_auth(auth)
{
    // Uploads are each on the shard that owns their key; a bucket is dropped only
    // when no shard is at work on one, and the idle ones are aborted with it, as in S3.
    m_node.set_multipart(&m_mpu);
    // --fsync interval and never answer a write without the syncs only a crash of the machine needs.
    m_io.set_relaxed(m_store.options().sync != sync_mode::always);
    m_store.set_drop_guard([this](std::string_view bucket) { return m_mpu.bucket_uploads_busy(bucket); });
    m_store.set_forget_listener([this](const std::string& bucket) { m_mpu.drop_bucket(bucket); });
    m_store.set_lifecycle_listener([this]() { lifecycle_changed(); });
    m_store.set_change_sink(this);
    m_store.set_owner_quota([this](std::string_view owner) { return m_auth ? m_auth->max_bytes_of(owner) : 0; });
    m_lc_day_ms = lifecycle_day_ms;
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS"))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && v > 0 && v <= 86400)
            m_lc_day_ms = static_cast<int64_t>(v) * 1000;
    }
    m_tier.set_day_ms(m_lc_day_ms);
    m_rid_seq = random_u64();
    m_store.set_hash_pool(&m_hash);
    if (!m_hash.attach(m_io))
    {
        LOG_WARN("storage: the digest threads cannot be waited for, so bodies are hashed on the loop");
        m_hash.stop();
    }
    m_max_conns = m_owner.get_max_connections();
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_HTTP2"))
        m_h2 = std::string_view(e) != "0";
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_SPLICE_MIN"))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && v >= 0)
            m_zero_copy_min = static_cast<size_t>(v);
    }
    // A count the tests shrink to make the ring run dry; zero takes it away.
    uint32_t ring_bufs = ring_buf_count;
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_RECV_BUFS"))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && v >= 0 && v <= 4096 && (v & (v - 1)) == 0)
            ring_bufs = static_cast<uint32_t>(v);
    }
    m_ring      = ring_bufs != 0 && m_loop.setup_buf_ring(ring_group, ring_bufs, ring_buf_bytes);
    m_multishot = m_ring && m_loop.recv_multishot_enabled();
}

storage_run::~storage_run()
{
    for (const pooled_pipe& p : m_pipes)
    {
        ::close(p.rd);
        ::close(p.wr);
    }
}

bool storage_run::open(std::string& err)
{
    recovery_report rep;
    if (!m_store.open(err, &rep))
        return false;
    if (m_store.mirror() && !m_store.open_removed(err))
        return false;
    if (!m_mpu.open(err))
        return false;
    const auto made = [this](std::string_view check)
    {
        change_note n;
        return decode_change_check(check, n) && m_store.change_on_disk(n);
    };
    if (!m_notify.open(m_store.options().dir, m_store.shard(), made, err))
        return false;
    if (!m_repl.open(m_store.options().dir, m_store.shard(), made, err))
        return false;
    if (!m_cluster_self.empty() && !load_cluster_id(err))
        return false;
    m_scrub.open(m_store.options().dir, m_store.shard());
    m_compact.open(m_store.options().dir, m_store.shard());
    {
        // Where `git-sync` reaches this runtime: its own address, loopback for a wildcard.
        std::string endpoint, why;
        const std::string bind(m_owner.get_bind_address());
        if (!m_owner.get_listen_path().empty())
            why = "git needs the runtime on a TCP port; it listens on a unix socket";
        else
            endpoint = (bind.empty() || bind == "0.0.0.0" ? std::string("127.0.0.1")
                        : bind == "::" ? std::string("[::1]")
                        : bind.find(':') != std::string::npos ? "[" + bind + "]" : bind) +
                       ":" + std::to_string(m_owner.effective_port());
        m_git.open(m_store.options().dir, m_store.shard(), endpoint, m_tls != nullptr, why,
                   std::string(m_owner.get_cert_path()));
    }
    reap_uploads();
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
    tell_started();
    arm_sweep();
    return m_accept_pending;
}

void storage_run::tell_started()
{
    if (m_start_note != start_note::untold || m_store.shards() <= 1)
        return;
    // A sibling silent for this long is gone, and one that comes back holds no copies.
    if (++m_start_tries > 30)
    {
        m_start_note = start_note::told;
        m_node.trust_holders();
        return;
    }
    m_start_note = start_note::telling;
    m_node.announce_start([this](bool all) { m_start_note = all ? start_note::told : start_note::untold; });
}

bool storage_run::drained() const
{
    return m_loop.owner_inflight(this) == 0 && !m_loop.owner_table_full();
}

void s3_request::reset()
{
    head.clear();
    method = version = raw_path = raw_query = host = payload_hash = {};
    bucket.clear();
    key.clear();
    vhost = false;
    website = false;
    head_request = false;
    app = 0;
    headers.clear();
    query.clear();
    request_id.clear();
    has_content_length = false;
    content_length     = 0;
    chunked            = false;
    keep_alive         = true;
    expect_continue    = false;
    form.reset();
}

void storage_run::new_request_id(std::string& id)
{
    // Sixteen hex digits, the shape S3's own have, from a counter the loop
    // steps: a syscall per request would be the most expensive thing in a HEAD.
    uint64_t x = m_rid_seq += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    x ^= x >> 31;
    static constexpr char digits[] = "0123456789ABCDEF";
    id.assign(16, '0');
    for (int i = 15; i >= 0; --i, x >>= 4)
        id[static_cast<size_t>(i)] = digits[x & 15];
}

std::shared_ptr<conn> storage_run::find(uint64_t id)
{
    auto it = m_conns.find(id);
    if (it != m_conns.end())
        return it->second;
    auto st = m_streams.find(id);
    return st == m_streams.end() ? nullptr : st->second;
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
    if (h3_owns(req))
    {
        h3_cqe(req, cqe->res);
        return;
    }
    if (req == &m_sweep_timer.req)
    {
        m_sweep_timer.armed = false;
        if (!m_stopped)
            sweep();
        return;
    }
    if (req == &m_lc_timer.req)
    {
        m_lc_timer.armed = false;
        if (!m_stopped && m_lc)
        {
            m_lc->scanned = 0;
            lifecycle_pump();
        }
        return;
    }
    if (req == &m_media_timer.req)
    {
        m_media_timer.armed = false;
        if (!m_stopped)
            media_tick();
        return;
    }
    if (req->type == op_poll && req->owner == this && media_exit_done(req))
        return;
    if (req == &m_pace_timer.req)
    {
        m_pace_timer.armed = false;
        if (!m_stopped)
            pace_tick();
        return;
    }
    if (req == &m_accept_backoff.req)
    {
        m_accept_backoff.armed = false;
        if (!m_stopped)
            arm_accept();
        return;
    }
    if (m_notify.owns(req))
    {
        m_notify.on_timer();
        return;
    }
    if (m_repl.owns(req))
    {
        m_repl.on_timer();
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
    {
        // A buffer the ring lent to a completion nobody can take is still the ring's.
        m_loop.return_cqe_buf(cqe, req);
        return;
    }

    switch (req->type)
    {
        case op_read:
        case op_read_provided:
        case op_recv_multishot:
            read_done(c, cqe);
            break;
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

bool storage_run::adopt_external(int fd)
{
    if (m_stopped)
    {
        m_loop.close_fd(fd);
        return false;
    }
    // The companion node is a unix socket, so it is tuned as one.
    socketley::unix_sock::tune_stream(fd);
    adopt(fd);
    return true;
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
    c->accepted      = c->last_progress;
    // A session before the first byte is read, so a plaintext client meets the
    // handshake and is refused, and is never served in the clear.
    if (m_tls)
    {
        c->ssl = m_tls->create_ssl_server();
        if (!c->ssl)
        {
            m_loop.close_fd(fd);
            return;
        }
        c->tls_state = tls_conn_handshake;
    }
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
    std::vector<std::shared_ptr<conn>> sessions;
    auto judge = [&](const std::shared_ptr<conn>& c)
    {
        const auto quiet = std::chrono::duration_cast<std::chrono::seconds>(now - c->last_progress).count();
        bool kill = false;
        // A peer that has not become a client is not counted as one.
        if (c->ssl && c->tls_state == tls_conn_handshake)
        {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - c->accepted).count() >
                static_cast<long>(tls_handshake_deadline_secs))
            {
                ++m_c.tls_failures;
                victims.push_back(c);
            }
            return;
        }
        switch (c->ph)
        {
            case phase::h2:
                // Its streams are judged one by one; the connection only for a preface or an idle session.
                sessions.push_back(c);
                break;
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
            case phase::form_head:
                kill = quiet > body_stall_secs;
                break;
            case phase::respond:
                kill = quiet > write_stall_secs;
                break;
            case phase::hook_wait:
                kill = quiet > body_stall_secs;
                break;
        }
        if (kill)
            victims.push_back(c);
    };
    for (auto& [id, c] : m_conns)
        judge(c);
    for (auto& [id, c] : m_streams)
        judge(c);
    for (auto& c : victims)
    {
        ++m_c.timeouts;
        close_conn(c);
    }
    for (auto& c : sessions)
        if (!c->dead)
            h2_sweep(c, now);
    // An upload sealed for an assembler on another shard that never said how it
    // ended is opened again after six hours.
    m_mpu.unseal_stale(static_cast<int64_t>(m_store.now_ms()) - 6ll * 3600 * 1000);
    // Expired uploads are looked for a few times within the expiry, at most
    // every half minute, and only when any expire.
    if (m_mpu_expire_secs != 0)
    {
        const auto every = std::chrono::seconds(std::clamp<uint32_t>(m_mpu_expire_secs / 4, 1, 30));
        if (now - m_last_reap >= every)
        {
            m_last_reap = now;
            reap_uploads();
        }
    }
    lifecycle_tick();
    share_burn_tick();
    m_scrub.tick();
    m_compact.tick();
    m_tier.tick();
    if (m_auth)
        m_git.tick(*m_auth);
    tell_started();
    flush_access_logs(false);
    if (!m_conns.empty() || m_mpu_expire_secs != 0 || m_start_note != start_note::told || m_lc ||
        m_store.lifecycle_buckets() != 0 || m_store.any_doubt() || !m_access_logs.empty() || m_scrub.enabled() ||
        m_compact.enabled() || m_tier.enabled() || m_git.enabled() || m_burns != 0 || !m_burning.empty() || !m_hooks.empty())
        arm_sweep();
}

void storage_run::on_turn()
{
    if (!m_h2_due.empty())
        h2_turn();
    // What the turn gave QUIC connections to send leaves in one write each; a stream whose bytes that write took
    // goes on now, and what it writes in turn is sent before the loop sleeps.
    for (int round = 0; m_h3 && round < 8; ++round)
    {
        h3_flush_dirty();
        if (m_h2_due.empty())
            break;
        h2_turn();
    }
    m_max_conns = m_owner.get_max_connections();
    m_node.flush_holds();
}

void storage_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    stop_rpc();
    m_git.stop();
    for (auto& [url, h] : m_hooks)
        h->peer->stop();
    // Access log lines not yet delivered are dropped with the deliveries in flight.
    for (auto& d : m_log_deliveries)
        d->abort();
    m_log_deliveries.clear();

    h3_stop();
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
    if (m_lc_timer.armed)
        m_loop.submit_timeout_remove(&m_lc_timer.req);
    m_lc.reset();
    if (m_pace_timer.armed)
        m_loop.submit_timeout_remove(&m_pace_timer.req);
    m_paced.clear();
    media_stop();

    std::vector<std::shared_ptr<conn>> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c);
    // An HTTP/2 client is told the connection ends, and which of its streams were taken, before it does.
    for (auto& c : all)
        if (c->h2)
            h2_goaway(c, 0, true);
    for (auto& c : all)
        close_conn(c);

    // No crossing is answered from here on, and every one still out is answered as failed while the node can still hear it, so the work waiting on a sibling finishes in the drain below.
    m_transport.stop();
    m_node.stop();
    m_notify.stop();
    m_repl.stop();
    m_scrub.stop();
    m_compact.stop();
    m_tier.stop();

    // Nothing new can arrive, so the journal writes, syncs and compaction already begun are let finish, which is what lets close() mark the stop clean.
    const auto give_up = std::chrono::steady_clock::now() + stop_drain_bound;
    while (m_store.busy() && std::chrono::steady_clock::now() < give_up)
        m_loop.poll_completions(10);
    // A test's stop held past its drain, longer the higher the shard, so a start beside it meets shards that let go one by one.
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_STOP_HOLD_MS"))
        std::this_thread::sleep_for(std::chrono::milliseconds(std::clamp(std::strtol(e, nullptr, 10), 0L, 3000L) *
                                                              (m_store.options().shard + 1)));

    // The digest threads end first, so none of them writes to a descriptor the
    // loop is about to close, and the read waiting on it is cancelled with it.
    m_hash.stop();
    if (const int fd = m_hash.release_wake_fd(); fd >= 0)
        m_loop.close_fd(fd);
    // A bind in progress is waited out here, which its own deadline bounds.
    m_ldap_pool.stop();
    if (const int fd = m_ldap_pool.release_wake_fd(); fd >= 0)
        m_loop.close_fd(fd);

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
    // A stream has no socket: what it held is let go and the session told, which resets it unless it ended.
    if (c->stream())
    {
        if (c->put)
            c->put->abort();
        c->dec.reset();
        c->sel.reset();
        zip_end(*c);
        if (c->file_fd >= 0)
        {
            m_loop.close_fd(c->file_fd);
            c->file_fd = -1;
        }
        c->after_write = conn::after_kind::none;
        c->on_body     = false;
        if (c->h3s)
            h3_stream_gone(c);
        else
            h2_stream_gone(c);
        m_streams.erase(c->id);
        // A read of its file may still be landing in sbuf.
        if (c->file_rd_pending)
            m_closing.push_back(c);
        return;
    }
    if (c->h2)
        h2_parent_gone(c);

    // Aborted but not dropped: a receive may still be landing in its buffer.
    if (c->put)
        c->put->abort();
    c->dec.reset();
    c->sel.reset();
    zip_end(*c);
    if (c->file_fd >= 0)
    {
        m_loop.close_fd(c->file_fd);
        c->file_fd = -1;
    }
    pipe_release(*c);
    if (c->ssl)
    {
        tls_context::free_ssl(c->ssl);
        c->ssl = nullptr;
    }
    if (c->fd >= 0)
    {
        ::shutdown(c->fd, SHUT_RDWR);
        m_loop.close_fd(c->fd);
        c->fd = -1;
    }
    c->after_write = conn::after_kind::none;
    c->on_body     = false;

    m_conns.erase(c->id);
    if (c->rd_pending || c->wr_pending || c->sp_in_pending || c->sp_out_pending || c->file_rd_pending)
        m_closing.push_back(c);
}

void storage_run::maybe_release(const std::shared_ptr<conn>& c)
{
    if (!c->dead || c->rd_pending || c->wr_pending || c->sp_in_pending || c->sp_out_pending || c->file_rd_pending)
        return;
    auto it = std::find(m_closing.begin(), m_closing.end(), c);
    if (it != m_closing.end())
    {
        *it = std::move(m_closing.back());
        m_closing.pop_back();
    }
}

// What the next recv of a connection should be, decided in one place because arm_read() asks it both to
// arm one and to learn whether the one already armed is the wrong kind.
storage_run::read_plan storage_run::plan_read(const conn& c) const
{
    read_plan p;
    p.k = read_plan::kind::ring;
    switch (c.ph)
    {
        case phase::respond:
        case phase::hook_wait:
            p.k = read_plan::kind::none;
            return p;
        case phase::body_put:
            if (c.ssl)
            {
                // Ciphertext cannot land in the staging buffer: what the put
                // takes is what the session decrypted.
                if (c.park_off < c.park.size())
                    p.k = read_plan::kind::none;   // waiting for the put to take what is parked
            }
            else if (!c.hook && !c.req.chunked && c.put && !c.put->failed() && c.put_failed == st::ok &&
                     c.body_left >= direct_min)
            {
                // Straight into the staging buffer: the bytes are hashed where
                // they land and written from there.
                const size_t room = c.put->stage_room();
                char* buf = room ? c.put->stage_ptr() : nullptr;
                const uint32_t len = static_cast<uint32_t>(std::min<uint64_t>({room, c.body_left, 1u << 20}));
                if (!buf || len == 0)
                    p.k = read_plan::kind::none;   // the put's ready callback arms this again
                else
                {
                    p.k      = read_plan::kind::own;
                    p.buf    = buf;
                    p.len    = len;
                    p.direct = true;
                }
            }
            else if (c.hook && c.hook->heavy() && !c.req.chunked && m_hash.enabled() && c.put &&
                     !c.put->failed() && c.put_failed == st::ok && (c.body_left >= direct_min || c.hfill > 0))
            {
                // A signed body is verified on a helper thread, up to a quarter megabyte at a time.
                if (c.park_off < c.park.size() || c.hook_busy)
                    p.k = read_plan::kind::none;   // resumed when the hook has reported and the put has taken its bytes
                else
                {
                    p.k    = read_plan::kind::own;
                    p.len  = static_cast<uint32_t>(std::min<uint64_t>(hook_read_bytes - c.hfill, c.body_left));
                    p.hook = true;
                }
            }
            else if (c.park_off < c.park.size())
                p.k = read_plan::kind::none;   // waiting for the put to take what is parked
            break;
        default:
            break;
    }
    return p;
}

void storage_run::pace_tick()
{
    std::vector<uint64_t> due;
    due.swap(m_paced);
    for (const uint64_t id : due)
    {
        auto c = find(id);
        if (!c || c->dead || !c->paced)
            continue;
        c->paced    = false;
        // Whatever gathered while it waited is taken now, however little it is.
        c->pace_due = true;
        arm_read(c);
    }
}

void storage_run::cancel_read(const std::shared_ptr<conn>& c)
{
    if (c->rd_cancel)
        return;
    if (!m_loop.submit_cancel_request(&c->rd_req))
    {
        close_conn(c);
        return;
    }
    c->rd_cancel = true;
    ++m_c.recv_cancels;
}

void storage_run::arm_read(const std::shared_ptr<conn>& c)
{
    // A stream reads what its DATA frames brought, and the window it gives back is what lets more come.
    if (c->h2s)
    {
        if (!c->dead)
            h2_pull(c);
        return;
    }
    if (c->h3s)
    {
        if (!c->dead)
            h3_pull(c);
        return;
    }
    if (c->dead || c->fd < 0 || c->paced)
        return;
    // A body that trickles in is left to gather in the socket until the next tick, so a recv and a wakeup are not paid per segment.
    const bool pace = c->ph == phase::body_put && c->trickle && c->body_left > pace_tail_bytes && !m_stopped;
    if (c->rd_pending)
    {
        // A recv that keeps delivering is left standing, unless the phase now wants a buffer of its own or a pace.
        if (c->rd_multi && !c->rd_cancel && (pace || plan_read(*c).k == read_plan::kind::own))
            cancel_read(c);
        return;
    }

    // What the record layer already holds is delivered before another recv is
    // asked for, because nothing would ever complete for bytes that are here.
    if (c->ssl && !c->pulling && c->tls_state == tls_conn_ready && c->ph != phase::respond &&
        c->ph != phase::hook_wait)
    {
        tls_pull(c);
        if (c->dead || c->rd_pending)
            return;
    }

    read_plan plan = plan_read(*c);
    if (plan.k == read_plan::kind::none)
        return;
    // A peer that has said all it will say is answered, and gone when there is nothing left to read.
    if (c->peer_eof)
    {
        close_conn(c);
        return;
    }
    if (pace && !c->pace_due)
    {
        if (!m_pace_timer.armed)
        {
            m_pace_timer.ts  = {0, pace_ns};
            m_pace_timer.req = io_request{};
            m_pace_timer.req.owner = this;
            m_pace_timer.req.type  = op_timeout;
            m_pace_timer.armed     = m_loop.submit_timeout(&m_pace_timer.ts, &m_pace_timer.req);
        }
        if (m_pace_timer.armed)
        {
            c->paced = true;
            m_paced.push_back(c->id);
            return;
        }
    }
    c->pace_due  = false;
    c->rd_direct = plan.direct;
    c->rd_hook   = plan.hook;
    c->rd_multi  = false;
    c->rd_cancel = false;
    if (plan.hook)
    {
        if (!c->hbuf)
            c->hbuf = take_hook_buffer();
        plan.buf = c->hbuf.get() + c->hfill;
    }

    c->rd_req = io_request{};
    c->rd_req.owner  = this;
    c->rd_req.buffer = reinterpret_cast<char*>(c.get());
    bool queued = false;
    if (plan.k == read_plan::kind::ring && m_ring && !c->rd_fallback)
    {
        // Nothing is held for an idle connection: the kernel picks a buffer when bytes arrive.
        if (m_multishot && !c->ssl && !pace)
            queued = c->rd_multi = m_loop.submit_recv_multishot(c->fd, ring_group, &c->rd_req);
        if (!queued)
            queued = m_loop.submit_read_provided(c->fd, ring_group, &c->rd_req, c->rd_drained);
    }
    else
    {
        if (plan.k == read_plan::kind::ring)
        {
            // The ring could not lend one, so this receive brings its own.
            c->fbuf = std::make_unique_for_overwrite<char[]>(fallback_bytes);
            plan.buf = c->fbuf.get();
            plan.len = fallback_bytes;
        }
        c->rd_req.type = op_read;
        queued = m_loop.submit_read(c->fd, plan.buf, plan.len, &c->rd_req);
    }
    c->rd_fallback = false;
    if (!queued)
    {
        c->rd_multi = false;
        close_conn(c);
        return;
    }
    c->rd_pending = true;
}

void storage_run::read_done(const std::shared_ptr<conn>& c, struct io_uring_cqe* cqe)
{
    const bool multi = is_multishot_recv_op(c->rd_req.type);
    const bool more  = multi && (cqe->flags & IORING_CQE_F_MORE) != 0;
    // Whatever the ring lent goes back on every way out, and a fallback buffer is freed with it.
    struct lent
    {
        event_loop&              loop;
        bool                     held;
        uint16_t                 id;
        std::unique_ptr<char[]>  own;
        ~lent()
        {
            if (held)
                loop.return_buf(ring_group, id);
        }
    } lend{m_loop, (cqe->flags & IORING_CQE_F_BUFFER) != 0,
           static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT), std::move(c->fbuf)};
    if (!more)
    {
        c->rd_pending = false;
        c->rd_multi   = false;
        c->rd_cancel  = false;
    }
    if (c->dead)
    {
        maybe_release(c);
        return;
    }
    const int res = cqe->res;
    if (res == -ENOBUFS)
    {
        // The ring had nothing to lend: this receive is taken by a buffer of the connection's own.
        ++m_c.recv_fallbacks;
        c->rd_fallback = true;
        arm_read(c);
        return;
    }
    if (res == -ECANCELED && !more)
    {
        // Asked for, because the phase wanted a buffer of its own or the backlog was full.
        arm_read(c);
        return;
    }
    if (res == 0 && (c->ph == phase::respond || c->ph == phase::hook_wait))
    {
        c->peer_eof = true;
        return;
    }
    if (res <= 0)
    {
        // The peer went, or the socket failed: whatever it was owed is moot.
        close_conn(c);
        return;
    }
    const size_t n = static_cast<size_t>(res);
    c->rd_drained = event_loop::recv_drained(cqe);
    // A request being answered is not progress by the client, or a stalled write would never be reaped.
    if (c->ph != phase::respond && c->ph != phase::hook_wait)
    {
        const auto now = std::chrono::steady_clock::now();
        if (c->ph == phase::body_put)
        {
            // The rate is judged over a pace interval at the least, so a burst of a few segments is not taken for speed.
            c->rate_bytes += n;
            const auto ns = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(now - c->rate_since).count());
            // What gathered during a tick is all taken before the next wait: a TLS recv brings one 16 KiB ring buffer,
            // under the rate above, so taking one a tick held a body once judged trickling at 1.6 MB/s to its end.
            if (c->trickle && !c->rd_drained)
                c->pace_due = true;
            if (ns >= static_cast<uint64_t>(pace_ns))
            {
                c->trickle    = c->rate_bytes * trickle_ns_per_byte < ns;
                c->rate_since = now;
                c->rate_bytes = 0;
            }
        }
        c->last_progress = now;
    }
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, n);
    m_c.bytes_in += n;
    if (c->ph == phase::body_put)
        ++m_c.body_recvs;

    const char* data = nullptr;
    if (lend.held)
        data = m_loop.get_buf_ptr(ring_group, lend.id);
    else if (lend.own)
        data = lend.own.get();

    if (c->rd_direct || c->rd_hook)
    {
        const bool direct = c->rd_direct;
        c->rd_direct = false;
        c->rd_hook   = false;
        if (c->ph == phase::body_put && direct)
        {
            m_c.recv_direct_bytes += n;
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
        if (c->ph == phase::body_put)
        {
            c->body_left -= n;
            c->hfill     += n;
            if (c->hfill >= recv_batch_bytes || c->body_left == 0 || c->hfill == hook_read_bytes)
                hook_async(c, std::exchange(c->hfill, 0));
            else
                arm_read(c);
            return;
        }
        // The answer was decided while this was in flight, so what it brought is counted and dropped.
        c->hfill = 0;
        if (c->ph == phase::body_discard)
        {
            // Such a recv asks for no more than the body's rest, so none of what it brought can be the next request.
            if (n > c->body_left)
            {
                give_hook_buffer(std::move(c->hbuf));
                close_conn(c);
                return;
            }
            static const char sink[1] = {0};
            plain_in(c, sink, n);
        }
        give_hook_buffer(std::move(c->hbuf));
        return;
    }
    if (!data)
    {
        close_conn(c);
        return;
    }
    if (c->ssl)
        tls_in(c, data, n);
    else
        plain_in(c, data, n);
    if (c->dead)
        return;
    // A recv that keeps delivering is stopped when what it brought has piled up faster than it is taken.
    if (more && !c->rd_cancel &&
        (c->in.size() > backlog_cap || c->park.size() - c->park_off > backlog_cap))
        cancel_read(c);
    else if (!more && multi)
        arm_read(c);
}

// What a heavy hook did with one recv: run on a helper thread, reported on the loop.
struct storage_run::hook_job
{
    std::shared_ptr<body_hook> hook;
    std::shared_ptr<char[]>    buf;
    size_t                     n{0};
    std::string                out;
    s3_error                   err;
    bool                       ok{true};
};

std::shared_ptr<char[]> storage_run::take_hook_buffer()
{
    if (!m_hook_buffers.empty())
    {
        auto b = std::move(m_hook_buffers.back());
        m_hook_buffers.pop_back();
        return b;
    }
    return std::make_shared_for_overwrite<char[]>(hook_read_bytes);
}

void storage_run::give_hook_buffer(std::shared_ptr<char[]> b)
{
    if (b && m_hook_buffers.size() < hook_buffers_kept)
        m_hook_buffers.push_back(std::move(b));
}

void storage_run::hook_async(const std::shared_ptr<conn>& c, size_t n)
{
    auto job  = std::make_shared<hook_job>();
    job->hook = c->hook;
    job->buf  = std::move(c->hbuf);
    job->n    = n;
    c->hook_busy = true;
    if (!c->has_lane)
    {
        c->hash_lane = m_hash.next_lane();
        c->has_lane  = true;
    }
    // In order on this connection's lane, so the hook is never fed by two threads at once.
    m_hash.submit(c->hash_lane,
        [job]
        {
            job->ok = job->hook->feed(std::string_view(job->buf.get(), job->n), job->out, job->err);
        },
        [this, id = c->id, job] { hook_async_done(id, job); });
}

void storage_run::hook_async_done(uint64_t id, const std::shared_ptr<hook_job>& job)
{
    give_hook_buffer(std::move(job->buf));
    auto c = find(id);
    if (!c || c->dead)
        return;
    c->hook_busy = false;
    if (!job->ok)
    {
        put_refused(c, job->err);
        return;
    }
    if (c->park.empty())
        c->park = std::move(job->out);
    else
        c->park += job->out;
    c->put_fin_called = c->body_left == 0;
    put_drain_park(c);
}

// What a connection's plaintext does, whether it came off the wire or out of a
// session: the phase decides what it is.
void storage_run::plain_in(const std::shared_ptr<conn>& c, const char* p, size_t n)
{
    switch (c->ph)
    {
        case phase::h2:
            h2_in(c, p, n);
            return;
        case phase::head:
            // A cleartext connection whose first bytes are HTTP/2's preface speaks it from there on.
            if (m_h2 && !c->ssl && !c->any_request && h2_preface_in(c, p, n))
                return;
            if (c->in.empty())
            {
                c->request_began = c->last_progress;
                // A head that lies whole in what arrived is parsed there, and only what follows it is kept.
                const size_t end = std::string_view(p, n).find("\r\n\r\n");
                if (end != std::string_view::npos && end + 4 <= max_head_bytes)
                {
                    if (!parse_head(c, std::string_view(p, end + 4)))
                        return;
                    c->in.assign(p + end + 4, n - end - 4);
                    ++m_c.requests;
                    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
                    dispatch(c);
                    return;
                }
            }
            c->in.append(p, n);
            process_in(c);
            return;
        case phase::body_small:
            feed_small_body(c, p, n);
            if (!c->dead && c->ph == phase::body_small)
                arm_read(c);
            return;
        case phase::body_put:
            put_body_bytes(c, p, n);
            return;
        case phase::body_discard:
            if (n >= c->body_left)
            {
                // What follows the body is the next request.
                const size_t extra = n - static_cast<size_t>(c->body_left);
                c->body_left = 0;
                if (extra)
                    c->in.append(p + (n - extra), extra);
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
        case phase::hook_wait:
            // The next request, sent ahead of the answer to this one.
            c->in.append(p, n);
            return;
        case phase::form_head:
            c->in.append(p, n);
            post_form_more(c);
            return;
    }
}

// ─── TLS ────────────────────────────────────────────────────────────────────

// Ciphertext in: into the session, the handshake advanced, and whatever the
// records carry delivered.  Its own records go out before it returns.
void storage_run::tls_in(const std::shared_ptr<conn>& c, const char* data, size_t n)
{
    size_t off = 0;
    while (off < n)
    {
        const int k = tls_context::bio_write_in(c->ssl, data + off, static_cast<int>(n - off));
        if (k <= 0)
        {
            if (c->tls_state == tls_conn_handshake)
                ++m_c.tls_failures;
            close_conn(c);
            return;
        }
        off += static_cast<size_t>(k);
    }

    if (c->tls_state == tls_conn_handshake)
    {
        const int r = tls_context::do_handshake(c->ssl);
        if (r < 0)
        {
            // The alert is the only diagnosis the peer gets, and a plaintext
            // client arrives here too and is refused rather than downgraded.
            ++m_c.tls_failures;
            if (!c->wr_pending && tls_encrypt(c) && c->fd >= 0 && c->wbuf.size() > c->woff)
            {
                // One try, without waiting: the connection is going either way.
                const ssize_t sent = ::send(c->fd, c->wbuf.data() + c->woff, c->wbuf.size() - c->woff,
                                            MSG_NOSIGNAL | MSG_DONTWAIT);
                if (sent < 0) {}
            }
            close_conn(c);
            return;
        }
        if (r == 0)
        {
            pump_write(c);
            arm_read(c);
            return;
        }
        c->tls_state = tls_conn_ready;
        ++m_c.tls_handshakes;
        if (m_h2 && tls_context::negotiated_h2(c->ssl))
            h2_start(c);
        // The tickets a finished handshake owes go out now, and the first
        // request may already be in the same packet.
        pump_write(c);
    }

    tls_pull(c);
    if (c->dead)
        return;
    // A session that had nothing complete to give still owes the socket a read.
    arm_read(c);
}

// Plaintext the session holds, handed to the phase one piece at a time until
// the phase stops taking it -- a request being answered leaves the rest where
// it is, and arm_read() comes back for it.
void storage_run::tls_pull(const std::shared_ptr<conn>& c)
{
    if (c->pulling || c->dead || c->tls_state != tls_conn_ready)
        return;
    c->pulling = true;
    char plain[tls_plain_bytes];
    while (!c->dead && c->ph != phase::respond && c->ph != phase::hook_wait &&
           c->park_off >= c->park.size())
    {
        const int k = tls_context::ssl_read(c->ssl, plain, static_cast<int>(sizeof(plain)));
        if (k > 0)
        {
            c->last_progress = std::chrono::steady_clock::now();
            plain_in(c, plain, static_cast<size_t>(k));
            continue;
        }
        // The peer's close_notify or an unusable record ends the connection
        // the way an EOF does.
        if (k < 0)
        {
            c->pulling = false;
            close_conn(c);
            return;
        }
        break;
    }
    c->pulling = false;
}

// Everything the session owes the wire, gathered into `wbuf`: handshake
// records and alerts, and the record-layer form of what waits in `wq`.
bool storage_run::tls_encrypt(const std::shared_ptr<conn>& c)
{
    if (c->dead || !c->ssl)
        return false;
    if (c->tls_state == tls_conn_ready)
    {
        size_t encrypted = 0;
        while (c->wq_off < c->wq.size() && encrypted < tls_write_cap)
        {
            const size_t take = std::min(c->wq.size() - c->wq_off, tls_write_slice);
            const int k = tls_context::ssl_write(c->ssl, c->wq.data() + c->wq_off, static_cast<int>(take));
            if (k < 0)
            {
                close_conn(c);
                return false;
            }
            if (k == 0)
                break;
            c->wq_off += static_cast<size_t>(k);
            encrypted += static_cast<size_t>(k);
        }
        if (c->wq_off >= c->wq.size())
        {
            c->wq.clear();
            c->wq_off = 0;
        }
    }
    char out[16384];
    while (c->wbuf.size() - c->woff < tls_write_cap)
    {
        const int k = tls_context::bio_read_out(c->ssl, out, sizeof(out));
        if (k < 0)
        {
            close_conn(c);
            return false;
        }
        if (k == 0)
            break;
        c->wbuf.append(out, static_cast<size_t>(k));
    }
    return true;
}

// ─── Writing ────────────────────────────────────────────────────────────────

void storage_run::queue_write(const std::shared_ptr<conn>& c, std::string data)
{
    if (c->dead || data.empty())
        return;
    if (c->h2s)
    {
        h2_stream_out(c, std::move(data));
        return;
    }
    if (c->h3s)
    {
        h3_stream_out(c, std::move(data));
        return;
    }
    if (c->ssl)
        c->wq += data;
    else if (c->wbuf.empty() && c->wq.empty())
        c->wbuf = std::move(data);
    else
        c->wq += data;
    pump_write(c);
}

void storage_run::pump_write(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->wr_pending || c->stream())
        return;
    if (c->woff >= c->wbuf.size())
    {
        c->wbuf.clear();
        c->woff = 0;
        if (c->ssl)
        {
            if (!tls_encrypt(c))
                return;
            if (c->wbuf.empty())
                return;
        }
        else
        {
            if (c->wq.empty())
                return;
            c->wbuf.swap(c->wq);
            c->wq.clear();
        }
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
    if (c->h2)
    {
        h2_written(c);
        return;
    }

    if (c->woff < c->wbuf.size() || c->wq_off < c->wq.size() ||
        (c->ssl && tls_context::has_pending_out(c->ssl)))
    {
        pump_write(c);
        // What that submitted, or nothing when the session had no record left
        // to give: only then is the queue empty for the purposes of the caller.
        if (c->dead || c->wr_pending)
            return;
        if (c->woff < c->wbuf.size() || c->wq_off < c->wq.size())
            return;
    }
    c->wbuf.clear();
    c->woff = 0;
    const conn::after_kind next = c->after_write;
    c->after_write = conn::after_kind::none;
    if (next == conn::after_kind::finish)
        finish_request(c);
    else if (next == conn::after_kind::pump)
        file_pump(c);
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

std::string storage_run::response_head(const conn& c, const response& r, size_t room) const
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

    const std::string_view reason = r.reason.empty() ? std::string_view(reason_phrase(r.status)) : r.reason;
    size_t need = 200 + reason.size() + cached_date.size() + 2 * c.req.request_id.size();
    for (const auto& [k, v] : r.headers)
        need += k.size() + v.size() + 4;
    need += r.headers_raw.size() + c.cors_head.size() + m_alt_svc.size();
    std::string h;
    h.reserve(need + room);
    auto number = [&h](uint64_t n)
    {
        char buf[24];
        h.append(buf, static_cast<size_t>(std::to_chars(buf, buf + sizeof buf, n).ptr - buf));
    };
    h += "HTTP/1.1 ";
    number(static_cast<uint64_t>(r.status));
    h += ' ';
    h += reason;
    h += "\r\nServer: Socketley\r\nDate: ";
    h += cached_date;
    h += "\r\nx-amz-request-id: ";
    h += c.req.request_id;
    h += "\r\nx-amz-id-2: ";
    h += c.req.request_id;
    h += "\r\n";
    for (const auto& [k, v] : r.headers)
    {
        // A value a client put in a query (response-content-disposition) is dropped rather than allowed to write
        // headers of its own into the answer.
        if (!http_field_value_ok(k) || !http_field_value_ok(v))
            continue;
        h += k;
        h += ": ";
        h += v;
        h += "\r\n";
    }
    h += r.headers_raw;
    h += c.cors_head;
    // A client over TCP learns HTTP/3 is offered on the same port.
    if (!m_alt_svc.empty() && !c.h3s)
    {
        h += "Alt-Svc: ";
        h += m_alt_svc;
        h += "\r\n";
    }
    if (r.chunked)
        h += "Transfer-Encoding: chunked\r\n";
    else if (r.status != 204 && r.status != 304 && r.status != 100)
    {
        h += "Content-Length: ";
        number(r.has_length_override ? r.length_override
                                      : (r.body_view.data() ? r.body_view.size() : r.body.size()));
        h += "\r\n";
    }
    h += r.close ? "Connection: close\r\n\r\n" : "Connection: keep-alive\r\n\r\n";
    return h;
}

const char* reason_phrase(int status)
{
    switch (status)
    {
        case 100: return "Continue";
        case 200: return "OK";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
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

void storage_run::send_response(const std::shared_ptr<conn>& c, response r)
{
    if (c->dead)
        return;
    // An application that sent its request down the S3 path answers in its own terms.
    if (c->on_answer)
    {
        auto f = std::move(c->on_answer);
        c->on_answer = nullptr;
        f(c, r);
        return;
    }
    if (r.status >= 500)
        ++m_c.server_errors;
    else if (r.status >= 400)
        ++m_c.client_errors;
    r.close = r.close || !c->req.keep_alive;
    // A HEAD's answer keeps the length its body would have had and leaves the body out, whoever built it.
    if (c->req.head_request && !r.head_only)
    {
        if (!r.has_length_override)
        {
            r.has_length_override = true;
            r.length_override = r.body_view.data() ? r.body_view.size() : r.body.size();
        }
        r.head_only = true;
    }

    c->ph = phase::respond;
    const std::string_view body = r.head_only ? std::string_view{}
                                : r.body_view.data() ? r.body_view : std::string_view(r.body);
    access_log(c, r.status, body.size());
    std::string out = response_head(*c, r, body.size());
    out += body;
    c->close_after_write = r.close;
    c->after_write = conn::after_kind::finish;
    queue_write(c, std::move(out));
}

void storage_run::send_error(const std::shared_ptr<conn>& c, const s3_error& e, bool close,
                             std::string_view extra_name, std::string_view extra_value)
{
    if (c->hide_missing && e.code == "NoSuchKey")
    {
        send_error(c, make_error("AccessDenied"), close, extra_name, extra_value);
        return;
    }
    // A website answers its failures in HTML, or as its configuration says.
    if (c->req.website)
    {
        c->req.keep_alive = c->req.keep_alive && !close;
        website_failure(c, e);
        return;
    }
    count_error(*c, e.code);
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

void storage_run::count_error(conn& c, std::string_view code)
{
    if (code.empty())
        return;
    c.error_code = code;
    // The set of codes is the runtime's own and small; the bound is for a
    // future code that carries something a client chose.
    auto it = m_c.errors.find(code);
    if (it != m_c.errors.end())
        ++it->second;
    else if (m_c.errors.size() < 64)
        m_c.errors.emplace(std::string(code), 1);
}

void storage_run::send_error_st(const std::shared_ptr<conn>& c, st s)
{
    send_error(c, error_for(s));
}

void storage_run::store_doc(const std::shared_ptr<conn>& c, bucket_doc kind, std::string bucket, std::string xml,
                            int status)
{
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(kind, std::move(bucket), std::move(xml), [this, weak, status](st s)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        response r;
        r.status = status;
        send_response(cc, std::move(r));
    });
}

void storage_run::reset_request(const std::shared_ptr<conn>& c)
{
    c->req.reset();
    c->body.clear();
    c->body.shrink_to_fit();
    c->body_left = 0;
    c->chunk = http_chunked_decoder{};
    c->chunk_in.clear();
    c->on_body = false;
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
    c->ck_trailer.clear();
    c->sent_body = 0;
    c->dec.reset();
    c->sel.reset();
    zip_end(*c);
    c->rd_direct = false;
    c->hfill = 0;
    c->trickle  = false;
    c->pace_due = false;
    c->principal.clear();
    if (c->ip_forwarded)
    {
        c->ip_known     = false;
        c->ip_forwarded = false;
    }
    c->user.reset();
    c->anonymous       = false;
    c->cluster         = false;
    c->policy_admitted = false;
    c->cors_head.clear();
    c->hide_missing = false;
    c->acl_need = 0;
    c->by_acl   = false;
    c->website_key.clear();
    c->website_error = {};
    c->website_status = 0;
    c->error_code.clear();
    c->on_answer = nullptr;
    c->app_header.clear();
    c->share_id.clear();
    // A large GET's or a signed PUT's buffers are not kept for the rest of a keep-alive connection's life.
    if (c->sbuf.capacity() > 64 * 1024)
        std::string().swap(c->sbuf);
    if (c->park.capacity() > 64 * 1024)
        std::string().swap(c->park);
}

void storage_run::finish_request(const std::shared_ptr<conn>& c)
{
    if (c->dead)
        return;
    // A stream is not reused: its answer ends it.
    if (c->h2s)
    {
        h2_stream_end(c);
        return;
    }
    if (c->h3s)
    {
        h3_stream_end(c);
        return;
    }
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
    if (end == std::string::npos || end + 4 > max_head_bytes)
    {
        if (c->in.size() > max_head_bytes)
        {
            new_request_id(c->req.request_id);
            c->req.keep_alive = false;
            send_error(c, make_error("InvalidRequest"), true);
            return;
        }
        arm_read(c);
        return;
    }
    if (!parse_head(c, std::string_view(c->in).substr(0, end + 4)))
        return;
    c->in.erase(0, end + 4);
    ++m_c.requests;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    dispatch(c);
}

bool storage_run::parse_head(const std::shared_ptr<conn>& c, std::string_view head)
{
    s3_request& r = c->req;
    r.reset();
    c->any_request = true;
    new_request_id(r.request_id);
    r.head.assign(head);

    const std::string_view all(r.head);
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
    r.method  = line.substr(0, sp1);
    r.head_request = r.method == "HEAD";
    const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    r.version = line.substr(sp2 + 1);
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
        char* name = r.head.data() + (hl.data() - all.data());
        for (size_t i = 0; i < colon; ++i)
            name[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(name[i])));
        r.headers.push_back({hl.substr(0, colon), http_trim_ows(hl.substr(colon + 1))});
    }

    r.host         = r.header("host");
    r.payload_hash = r.header("x-amz-content-sha256");
    const std::string_view conn_hdr = r.header("connection");
    if (r.version == "HTTP/1.0")
        r.keep_alive = http_list_has_token(conn_hdr, "keep-alive", 10);
    else
        r.keep_alive = !http_list_has_token(conn_hdr, "close", 5);
    r.expect_continue = http_list_has_token(r.header("expect"), "100-continue", 12);

    const size_t q = target.find('?');
    r.raw_path  = target.substr(0, q);
    r.raw_query = q == std::string_view::npos ? std::string_view{} : target.substr(q + 1);

    std::string& path = m_path_scratch;
    if (!percent_decode(r.raw_path, path, false))
        return bad("InvalidRequest");
    const std::string_view rest_path = std::string_view(path).substr(1);
    r.website = !m_website_domains.empty() && vhost_bucket(r.host, m_website_domains, r.bucket);
    r.vhost = !r.website && !m_domains.empty() && vhost_bucket(r.host, m_domains, r.bucket);
    if (r.vhost || r.website)
        r.key.assign(rest_path);
    else
    {
        const size_t slash = rest_path.find('/');
        r.bucket.assign(rest_path.substr(0, slash));
        if (slash != std::string_view::npos)
            r.key.assign(rest_path.substr(slash + 1));
    }

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

void storage_run::collect_body(const std::shared_ptr<conn>& c, uint64_t limit)
{
    c->ph         = phase::body_small;
    c->body.clear();
    c->body_limit = limit;
    c->on_body    = true;
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
        c->on_body = false;
        route_small(c);
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
    const bool armed = c->on_body;
    c->on_body = false;
    if (armed)
        route_small(c);
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
    c->rate_since = std::chrono::steady_clock::now();
    c->rate_bytes = 0;
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
    if (!c->req.chunked && c->body_left == 0 && pre.empty())
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
    // A checksum that followed the body in a trailer is known only now.
    if (c->hook && !c->ck_trailer.empty())
    {
        const std::string v = c->hook->trailer_value(c->ck_trailer);
        std::string raw;
        const checksum_algo a = checksum_from_header(c->ck_trailer);
        if (!v.empty() && (!base64_decode(v, raw) || raw.size() != checksum_raw_len(a)))
        {
            s3_error e = make_error("InvalidRequest");
            e.message = "Value for " + c->ck_trailer + " header is invalid.";
            put_refused(c, e);
            return;
        }
        if (!v.empty())
            c->put->expect_checksum(v);
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
        if (cc->req.form)
        {
            const std::string bucket = cc->req.bucket;
            const std::string key    = cc->req.key;
            send_post_result(cc, r.meta);
            notify_put(bucket, key, r.meta);
            return;
        }
        // A part is not an object: the completed upload is the put the script is told of.
        const bool is_part = cc->req.has_query("uploadId");
        response resp;
        resp.status = 200;
        resp.headers.emplace_back("ETag", "\"" + r.meta.etag() + "\"");
        if (r.meta.checksum)
        {
            resp.headers.emplace_back(checksum_header(r.meta.checksum.algo), r.meta.checksum.b64());
            if (!is_part)
                resp.headers.emplace_back("x-amz-checksum-type", "FULL_OBJECT");
        }
        for (const auto& [n, v] : r.meta.extra)
            if (n == version_extra)
                resp.headers.emplace_back("x-amz-version-id", version_of(r.meta).id);
            else if (n == sse_extra)
                sse_headers(cc->req, r.meta, resp.headers);
        if (!is_part)
            expiration_header(cc->req.bucket, cc->req.key, r.meta, resp.headers);
        const std::string bucket = cc->req.bucket;
        const std::string key    = cc->req.key;
        send_response(cc, std::move(resp));
        // After the answer is on its way, so a script that is slow to notice does
        // not hold the client.
        if (!is_part)
            notify_put(bucket, key, r.meta);
    });
}

void storage_run::deny_request(const std::shared_ptr<conn>& c, const s3_error& e)
{
    s3_request& r = c->req;
    // A client that waits for 100 Continue has sent nothing, and a chunked
    // body has no length to read to.
    if (r.has_content_length && !r.chunked && !r.expect_continue && r.content_length > 0 &&
        r.content_length <= discard_limit)
    {
        c->body_error = e;
        c->body_left  = r.content_length;
        c->ph         = phase::body_discard;
        // Some of it came with the head.
        const size_t have = static_cast<size_t>(std::min<uint64_t>(c->in.size(), c->body_left));
        c->body_left -= have;
        c->in.erase(0, have);
        if (c->body_left == 0)
        {
            send_error(c, e, false);
            return;
        }
        arm_read(c);
        return;
    }
    r.keep_alive = false;
    send_error(c, e, true);
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
        c.pipe_rd   = m_pipes.back().rd;
        c.pipe_wr   = m_pipes.back().wr;
        c.pipe_size = m_pipes.back().size;
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
    if (c.pipe_held == 0 && !c.sp_in_pending && !c.sp_out_pending && m_pipes.size() < 64)
        m_pipes.push_back({c.pipe_rd, c.pipe_wr, c.pipe_size});
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
    // A large body is read ahead in big steps, as a player's or a download's reading of it goes on in order.
    if (len >= (1u << 20) && ::posix_fadvise(fd, static_cast<off_t>(off), static_cast<off_t>(len), POSIX_FADV_SEQUENTIAL) != 0) {}

    c->file_fd   = fd;
    c->file_off  = off;
    c->file_left = len;
    c->ph        = phase::respond;
    c->close_after_write = head.close;
    // A body worth the pipe goes file to socket in the kernel, and the rest is
    // read here and written from memory.
    // Not on a session: a splice moves bytes the record layer never sees.
    c->spliced = !c->ssl && !c->stream() && len >= m_zero_copy_min && pipe_acquire(*c);
    if (c->spliced)
        ++m_c.zero_copy_gets;
    else
        ++m_c.copied_gets;

    c->after_write = conn::after_kind::pump;
    access_log(c, head.status, len);
    queue_write(c, response_head(*c, head));
}

void storage_run::file_pump(const std::shared_ptr<conn>& c)
{
    if (c->dead)
        return;
    if (c->sel)
    {
        select_pump(c);
        return;
    }
    if (c->zip)
    {
        zip_pump(c);
        return;
    }
    if (c->file_left == 0)
    {
        file_done(c);
        return;
    }
    if (c->dec)
    {
        sealed_pump(c);
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
    // Sized without being cleared: the read writes every byte the answer takes.
    c->sbuf.resize_and_overwrite(n, [](char*, size_t len) { return len; });
    std::weak_ptr<conn> weak = c;
    if (!m_io.pread(c->file_fd, c->sbuf.data(), n, c->file_off,
            [this, weak](int64_t res)
            {
                auto cc = weak.lock();
                if (!cc)
                    return;
                cc->file_rd_pending = false;
                if (cc->dead)
                {
                    maybe_release(cc);
                    return;
                }
                stream_read_done(cc, res);
            }))
    {
        close_conn(c);
        return;
    }
    c->file_rd_pending = true;
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
    c->after_write = conn::after_kind::pump;
    // A stream keeps what it is handed until it is sent (HTTP/2) or acknowledged (HTTP/3), so it is given the buffer
    // itself, and the next read gets a new one, rather than a copy of it.
    if (c->stream())
    {
        std::string piece;
        piece.swap(c->sbuf);
        piece.resize(static_cast<size_t>(res));
        queue_write(c, std::move(piece));
        return;
    }
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
