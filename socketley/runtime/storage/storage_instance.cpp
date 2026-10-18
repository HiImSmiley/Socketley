#include "storage_instance.h"
#include "sync_runners.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cluster.h"
#include "s3_sigv4_auth.h"
#include "s3_vhost.h"
#include "sse.h"
#include "shard_wire.h"
#include "storage_run.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/util/logging.h"
#include "../../shared/net/socket_tuning.h"
#include "../../shared/net/unix_listener.h"
#include "../../shared/util/settings.h"

using socketley::storage::storage_run;

storage_instance::storage_instance(std::string_view name)
    : runtime_instance(runtime_storage, name)
{
}

storage_instance::~storage_instance()
{
    if (auto* mgr = get_runtime_manager())
        mgr->requests().drop_sink(this);
    // A runtime destroyed while running has its run freed by the graveyard's
    // destructor, which is only safe because the loop is gone first in every
    // process that builds one.
}

void storage_instance::set_authenticator(std::unique_ptr<socketley::storage::authenticator> a)
{
    m_auth = std::move(a);
}

size_t storage_instance::get_connection_count() const
{
    return m_run ? m_run->connection_count() : 0;
}

uint16_t storage_instance::effective_port() const
{
    if (!get_listen_path().empty())
        return 0;
    return get_port() ? get_port() : storage_default_port;
}

void storage_instance::listen_addresses(std::vector<std::string>& out) const
{
    const std::string listen_path(get_listen_path());
    if (!listen_path.empty())
    {
        out.push_back("unix:" + listen_path);
        return;
    }
    out.push_back("tcp:" + std::to_string(effective_port()));
}

std::string storage_instance::config_refusal() const
{
    if (m_dir.empty())
        return "storage: --dir <path> is required, because that is where the buckets live\n";
    // Refused rather than defaulted: an endpoint that answers anybody must have
    // been asked to.
    if (!m_anonymous && !m_auth && !has_credentials())
        return "storage: a runtime with no credentials serves nobody; pass --access-key and "
               "--secret-key or --credentials to require signed requests, or --anonymous to "
               "accept every request without authentication\n";
    if (!m_cluster_file.empty())
    {
        socketley::storage::cluster_config cluster;
        if (std::string why; !socketley::storage::load_cluster(m_cluster_file, cluster, why))
            return "storage: " + why + "\n";
        if (m_auth)
            return "storage: a node of a cluster checks signatures itself, so it takes no authenticator of its own\n";
    }
    if (has_credentials())
        if (const std::string why = socketley::storage::sigv4_config_error(
                {m_access_key, m_secret_key, m_credentials_file, m_anonymous, {}, {}, {}}); !why.empty())
            return "storage: " + why + "\n";
    if (!m_sse_key_file.empty())
    {
        socketley::storage::sse_key key{};
        if (std::string why; !socketley::storage::load_sse_master(m_sse_key_file, key, why))
            return "storage: " + why + "\n";
    }
    if (std::vector<std::string> d; !m_domain.empty())
        if (std::string why; !socketley::storage::parse_domains(m_domain, d, why))
            return "storage: " + why + "\n";
    if (std::vector<std::string> d; !m_website_domain.empty())
        if (std::string why; !socketley::storage::parse_domains(m_website_domain, d, why))
            return "storage: --website-domain: " + why + "\n";
    if (socketley::storage::sync_mode m; !m_fsync.empty() && !socketley::storage::parse_sync_mode(m_fsync, m))
        return "storage: --fsync is always, interval or never, not " + m_fsync + "\n";
    if (!m_notify_targets.empty())
    {
        std::vector<socketley::storage::notify_target> targets;
        if (std::string why; !socketley::storage::load_notify_targets(m_notify_targets, targets, why))
            return "storage: " + why + "\n";
    }
    if (!m_replication_targets.empty())
    {
        std::vector<socketley::storage::replication_target> targets;
        if (std::string why; !socketley::storage::load_replication_targets(m_replication_targets, targets, why))
            return "storage: " + why + "\n";
    }
    if (!m_tiers_file.empty())
    {
        std::vector<socketley::storage::replication_target> tiers;
        if (std::string why; !socketley::storage::load_replication_targets(m_tiers_file, tiers, why))
            return "storage: " + why + "\n";
    }
    if (!m_federation_file.empty())
    {
        socketley::storage::federation_config fed;
        if (std::string why; !socketley::storage::load_federation(m_federation_file, fed, why))
            return "storage: " + why + "\n";
    }
    if (std::vector<socketley::storage::bucket_policy::cidr> from; !tls_offloaded_blocks(from))
        return "storage: --tls-offloaded takes addresses or blocks such as 10.0.0.5 or 10.0.0.0/24, comma-separated\n";
    return {};
}

bool storage_instance::tls_offloaded_blocks(std::vector<socketley::storage::bucket_policy::cidr>& out) const
{
    std::string_view rest = m_tls_offloaded;
    while (!rest.empty())
    {
        const size_t comma = rest.find(',');
        const std::string_view one = rest.substr(0, comma);
        rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
        socketley::storage::bucket_policy::cidr c;
        if (!socketley::storage::parse_cidr_text(one, c))
            return false;
        out.push_back(c);
    }
    return true;
}

void storage_instance::serve_request(std::string_view, std::string& out)
{
    // Unreachable because serves_inline() is false.
    out.clear();
}

bool storage_instance::serve_deferred(uint64_t ticket, std::string_view, std::string_view payload)
{
    // A sibling shard's request opens with the magic of the shard protocol, and
    // a script's with the version byte of storage_rpc, so one payload is never both.
    socketley::storage::wire::op sibling{};
    if (!socketley::storage::wire::request_op(payload, sibling))
        return m_run && m_run->serve_rpc(ticket, payload);

    if (!m_run || get_shards() <= 1)
        return false;
    auto* mgr = get_runtime_manager();
    if (!mgr)
        return false;
    request_channel* ch = &mgr->requests();
    // The channel outlives the run, so an answer that comes after the run is
    // gone still lands on a ticket the channel knows or ignores.
    m_run->node().serve(payload, [ch, ticket](bool ok, std::string reply)
    {
        ch->complete_deferred(ticket, ok ? request_status::ok : request_status::no_target, reply);
    });
    return true;
}

namespace
{

// The setting a stored name gives; one that is not a setting at all -- a hand-edited state file -- is never, which
// makes nothing rather than guessing.
socketley::storage::sync_runners sync_runners_of(std::string_view name)
{
    socketley::storage::sync_runners r{socketley::storage::sync_runners::never};
    socketley::storage::parse_sync_runners(name, r);
    return r;
}

}   // namespace

void storage_instance::refresh_cached_limits()
{
    m_max_conns_cached = get_max_connections();
    if (m_run)
    {
        m_run->store().set_max_bytes(m_max_bytes);
        m_run->set_mpu_expire_secs(m_mpu_expire_secs);
        m_run->set_scrub_secs(m_scrub_secs);
        m_run->set_compress_secs(m_compress_secs);
        m_run->set_sync_runners(sync_runners_of(m_sync));
    }
}

void storage_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion of a storage runtime belongs to a run, which registers
    // itself; anything landing here is the instance's own registration and
    // owes nothing.
}

bool storage_instance::open_listener(uint16_t port, bool reuseport, int& out_fd)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (reuseport)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    // The buffers are left to the kernel: a body of gigabytes is what autotuning
    // is for, and the sizes a small-message runtime pins would cap it.
    socket_tuning::tcp_listener_defaults(fd, 0, 0);

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = bind_in_addr();
    addr.sin_port        = htons(port);
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        LOG_ERROR(("storage: port " + std::to_string(port) + " could not be bound: " +
                   std::string(std::strerror(errno))).c_str());
        ::close(fd);
        return false;
    }
    if (::listen(fd, 4096) < 0)
    {
        ::close(fd);
        return false;
    }
    out_fd = fd;
    return true;
}

bool storage_instance::setup(event_loop& loop)
{
    m_graveyard.reap();

    m_loop = &loop;
    // Storage waits on the disk rather than on the next packet, so a spin finds nothing and only spends CPU.
    loop.set_busy_spin(false);
    refresh_cached_limits();

    // Read here, at every start, so a `reload` installs a replaced certificate.
    std::unique_ptr<tls_context> tls;
    if (get_tls())
    {
        tls = std::make_unique<tls_context>();
        if (!tls->init_server(get_cert_path(), get_key_path(), get_ca_path()))
        {
            LOG_ERROR("storage: TLS listener not started -- the certificate, key or "
                      "client CA could not be loaded");
            return false;
        }
        // A browser that asks for HTTP/2 by ALPN is given it, unless SOCKETLEY_STORAGE_HTTP2=0.
        tls->enable_h2(socketley::settings::flag("SOCKETLEY_STORAGE_HTTP2", true));
    }

    // Read here, at every start, so an edited cluster file is the one a restart takes.
    socketley::storage::cluster_config cluster;
    if (!m_cluster_file.empty())
        if (std::string why; !socketley::storage::load_cluster(m_cluster_file, cluster, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            return false;
        }

    socketley::storage::authenticator* auth = m_auth.get();
    std::unique_ptr<socketley::storage::authenticator> signed_auth;
    if (!auth && (has_credentials() || !m_cluster_file.empty()))
    {
        // Made at every start, so a reload picks up a changed file and key.
        // The IAM API's users, groups and roles are kept beside the buckets, where every shard reads them.
        auto a = std::make_unique<socketley::storage::sigv4_authenticator>(socketley::storage::sigv4_config{
            m_access_key, m_secret_key, m_credentials_file, m_anonymous, m_dir + "/.iam.json", cluster.access_key,
            cluster.secret});
        std::string why;
        if (!a->load(why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            return false;
        }
        auth        = a.get();
        signed_auth = std::move(a);
    }
    else if (!auth)
    {
        m_anon = std::make_unique<socketley::storage::anonymous_authenticator>();
        auth   = m_anon.get();
    }

    socketley::storage::store_options opts;
    opts.dir       = m_dir;
    opts.shard     = get_shard_index();
    opts.nshards   = std::max<uint32_t>(get_shards(), 1);
    opts.max_bytes = m_max_bytes;
    if (!m_fsync.empty() && !socketley::storage::parse_sync_mode(m_fsync, opts.sync))
    {
        LOG_ERROR(("storage: --fsync is always, interval or never, not " + m_fsync).c_str());
        return false;
    }
    opts.sync_interval_ms = (m_fsync_interval_secs ? m_fsync_interval_secs : 1) * 1000;

    auto run = std::make_unique<storage_run>(*this, loop, opts, auth);
    if (signed_auth)
        run->adopt_authenticator(std::move(signed_auth));
    run->set_mpu_expire_secs(m_mpu_expire_secs);
    run->set_scrub_secs(m_scrub_secs);
    run->set_compress_secs(m_compress_secs);
    run->set_sync_runners(sync_runners_of(m_sync));
    run->set_acls_default(m_acls);
    run->set_tls(std::move(tls));
    if (std::vector<std::string> d; !m_domain.empty())
    {
        std::string why;
        if (!socketley::storage::parse_domains(m_domain, d, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        run->set_domains(std::move(d));
    }
    if (std::vector<std::string> d; !m_website_domain.empty())
    {
        std::string why;
        if (!socketley::storage::parse_domains(m_website_domain, d, why))
        {
            LOG_ERROR(("storage: --website-domain: " + why).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        run->set_website_domains(std::move(d));
    }
    // Read here, at every start, so a replaced key file is the one a restart serves with.
    if (!m_sse_key_file.empty())
    {
        socketley::storage::sse_key key{};
        std::string why;
        if (!socketley::storage::load_sse_master(m_sse_key_file, key, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        run->set_sse_master(key);
    }
    // Read here, at every start, so an edited targets file is the one a restart delivers to.
    if (!m_notify_targets.empty())
    {
        std::vector<socketley::storage::notify_target> targets;
        std::string why;
        if (!socketley::storage::load_notify_targets(m_notify_targets, targets, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        run->notifications().set_targets(std::move(targets));
        run->notifications().set_runtimes(get_runtime_manager(), std::string(get_name()));
    }
    if (!m_replication_targets.empty())
    {
        std::vector<socketley::storage::replication_target> targets;
        std::string why;
        if (!socketley::storage::load_replication_targets(m_replication_targets, targets, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        run->replication().set_targets(std::move(targets));
    }
    if (!m_tiers_file.empty())
    {
        std::vector<socketley::storage::replication_target> tiers;
        std::string why;
        if (!socketley::storage::load_replication_targets(m_tiers_file, tiers, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        run->set_tiers(std::move(tiers));
    }
    if (!m_federation_file.empty())
    {
        socketley::storage::federation_config fed;
        std::string why;
        if (!socketley::storage::load_federation(m_federation_file, fed, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        run->set_federation(std::move(fed));
    }
    if (std::vector<socketley::storage::bucket_policy::cidr> from; tls_offloaded_blocks(from))
        run->set_tls_offloaded(std::move(from));
    if (!m_cluster_file.empty())
        run->set_cluster(std::move(cluster));

    // The one blocking step: reading the directory and reconciling the journals
    // happens here, before the listener exists, so no connection waits behind it.
    std::string err;
    if (!run->open(err))
    {
        LOG_ERROR(("storage: " + err).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }

    const std::string listen_path(get_listen_path());
    int fd = -1;
    if (!listen_path.empty())
    {
        if (const std::string msg = socketley::unix_sock::listen_config_refusal(
                listen_path, get_port(), get_tls()); !msg.empty())
        {
            LOG_ERROR(("storage: " + msg).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        // One node per shard, because a path is one listener and the second
        // process to bind it would unlink the first.
        if (const std::string msg = socketley::unix_sock::shard_listen_path_refusal(
                listen_path, get_shards()); !msg.empty())
        {
            LOG_ERROR(("storage: " + msg).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        const std::string mine = socketley::unix_sock::shard_listen_path(
            listen_path, get_shard_index(), get_shards());
        auto r = socketley::unix_sock::bind_listener(mine);
        if (r.fd < 0)
        {
            LOG_ERROR(("storage: " + r.error).c_str());
            m_graveyard.retire(std::move(run));
            return false;
        }
        fd = r.fd;
        m_bound_listen_path = mine;
    }
    else if (!open_listener(effective_port(), /*reuseport=*/get_shards() > 1, fd))
    {
        m_graveyard.retire(std::move(run));
        return false;
    }

    // The run holds the descriptor from listen_on() on, and its stop() closes it: closed here too it was closed
    // twice, the second time whatever had been given its number since.
    if (!run->listen_on(fd))
    {
        m_graveyard.retire(std::move(run));
        // The socket node this start bound goes with it, so the next start does not meet a stale path.
        if (!m_bound_listen_path.empty())
        {
            if (::unlink(m_bound_listen_path.c_str()) < 0) {}
            m_bound_listen_path.clear();
        }
        return false;
    }
#if SOCKETLEY_HTTP3
    // HTTP/3 on the same port over UDP, unless SOCKETLEY_STORAGE_HTTP3=0; a port it cannot have only leaves it out.
    if (listen_path.empty() && get_tls())
    {
        // The port the Alt-Svc header names is this one unless SOCKETLEY_STORAGE_HTTP3_ADVERTISE says another --
        // the one a proxy in front forwards UDP from -- or 0, for none.
        const uint16_t advertise =
            socketley::settings::number<uint16_t>("SOCKETLEY_STORAGE_HTTP3_ADVERTISE").value_or(effective_port());
        if (socketley::settings::flag("SOCKETLEY_STORAGE_HTTP3", true))
            run->h3_open(effective_port(), advertise, get_shard_index(), std::max<uint32_t>(get_shards(), 1),
                         std::string(get_cert_path()), std::string(get_key_path()), std::string(get_ca_path()));
    }
#endif
    m_run = std::move(run);

    // And a node beside the port for callers already on this box.  Its failure
    // is not this runtime's failure: the port is up either way.
    if (socketley::unix_sock::wants_companion(get_type(), get_port(), listen_path, get_tls(),
                                              /*udp=*/false, get_shards()) &&
        !get_companion_path().empty())
    {
        if (!m_companion)
            m_companion = std::make_unique<socketley::unix_companion>(
                std::string(get_companion_path()),
                [this](int fd)
                {
                    if (m_run)
                        return m_run->adopt_external(fd);
                    if (m_loop)
                        m_loop->close_fd(fd);
                    return false;
                });
        m_companion->start(loop);
    }
    return true;
}

void storage_instance::teardown(event_loop&)
{
    if (m_companion)
        m_companion->stop();
    m_graveyard.retire(std::move(m_run));
    if (!m_bound_listen_path.empty())
    {
        if (::unlink(m_bound_listen_path.c_str()) < 0) {}
        m_bound_listen_path.clear();
    }
    m_loop = nullptr;
}

void storage_instance::on_loop_turn()
{
    m_graveyard.reap();
    if (m_companion)
        m_companion->pump();
    if (m_run)
        m_run->on_turn();
}

std::string storage_instance::stats_lines() const
{
    std::ostringstream out;
    if (!m_run)
        return {};
    const auto& c = m_run->counters();
    const auto  t = m_run->store().totals();
    const auto  mp = m_run->multipart().totals();
    out << "buckets:" << t.buckets << "\n"
        << "objects:" << t.objects << "\n"
        << "bytes:" << t.bytes << "\n"
        << "max_bytes:" << m_max_bytes << "\n"
        << "requests:" << c.requests << "\n"
        << "gets:" << c.gets << "\n"
        << "heads:" << c.heads << "\n"
        << "puts:" << c.puts << "\n"
        << "deletes:" << c.deletes << "\n"
        << "copies:" << c.copies << "\n"
        << "selects:" << c.selects << "\n"
        << "select_scanned:" << c.select_scanned << "\n"
        << "lists:" << c.lists << "\n"
        << "client_errors:" << c.client_errors << "\n"
        << "server_errors:" << c.server_errors << "\n"
        << "zero_copy_gets:" << c.zero_copy_gets << "\n"
        << "copied_gets:" << c.copied_gets << "\n"
        << "hot_gets:" << c.hot_gets << "\n"
        << "hot_bytes:" << m_run->hot_bytes() << "\n"
        << "zero_copy_bytes:" << c.zero_copy_bytes << "\n"
        << "journal_records:" << t.journal_records << "\n"
        << "journal_compactions:" << t.compactions << "\n"
        << "tag_writes:" << t.tag_writes << "\n"
        << "tag_rewrites:" << t.tag_rewrites << "\n"
        << "fsyncs:" << m_run->io().syncs() << "\n"
        << "fsyncs_skipped:" << m_run->io().skipped_syncs() << "\n"
        << "syncfs_rounds:" << m_run->store().syncfs_rounds() << "\n"
        << "syncfs_failed:" << m_run->store().syncfs_failed() << "\n"
        << "start_files_read:" << t.start_files_read << "\n"
        << "pool_ready:" << t.pool_ready << "\n"
        << "timeouts:" << c.timeouts << "\n"
        << "multipart_uploads:" << mp.uploads << "\n"
        << "multipart_parts:" << mp.parts << "\n"
        << "multipart_bytes:" << mp.bytes << "\n"
        << "multipart_created:" << c.mpu_created << "\n"
        << "multipart_completed:" << c.mpu_completed << "\n"
        << "multipart_aborted:" << c.mpu_aborted << "\n"
        << "multipart_list_trailers:" << m_run->multipart().trailers() << "\n"
        << "lifecycle_expired:" << c.lifecycle_expired << "\n"
        << "lifecycle_aborted:" << c.lifecycle_aborted << "\n"
        << "tls:" << (m_run->tls_enabled() ? 1 : 0) << "\n"
        << "tls_handshakes:" << c.tls_handshakes << "\n"
        << "tls_failures:" << c.tls_failures << "\n"
        << "h2_conns:" << c.h2_conns << "\n"
        << "h2_streams:" << c.h2_streams << "\n"
        << "h2_refused:" << c.h2_refused << "\n"
        << "h2_resets_in:" << c.h2_resets_in << "\n"
        << "h2_resets_out:" << c.h2_resets_out << "\n"
        << "h2_goaways:" << c.h2_goaways << "\n"
        << "h3:" << (m_run->h3_enabled() ? 1 : 0) << "\n"
        << "h3_conns:" << c.h3_conns << "\n"
        << "h3_open:" << m_run->h3_open_conns() << "\n"
        << "h3_streams:" << c.h3_streams << "\n"
        << "h3_retries:" << c.h3_retries << "\n"
        << "h3_forwarded:" << c.h3_forwarded << "\n"
        << "recv_fallbacks:" << c.recv_fallbacks << "\n"
        << "recv_cancels:" << c.recv_cancels << "\n"
        << "recv_direct_bytes:" << c.recv_direct_bytes << "\n"
        << "body_recvs:" << c.body_recvs << "\n"
        << "hash_handoffs:" << m_run->hash_handoffs() << "\n"
        << "sse:" << (m_run->has_sse_master() ? 1 : 0) << "\n"
        << "sse_puts:" << c.sse_puts << "\n"
        << "sse_gets:" << c.sse_gets << "\n"
        << "compressed_gets:" << c.compressed_gets << "\n"
        << "media_made:" << c.media_made << "\n"
        << "media_failed:" << c.media_failed << "\n"
        << "media_served:" << c.media_served << "\n"
        << "media_direct:" << c.media_direct << "\n"
        << "media_hw:" << c.media_hw << "\n"
        << "notify_sent:" << m_run->notifications().counters().sent << "\n"
        << "notify_failed:" << m_run->notifications().counters().failed << "\n"
        << "notify_queued:" << m_run->notifications().queued() << "\n"
        << "notify_dropped:" << m_run->notifications().counters().dropped << "\n"
        << "notify_resolves:" << m_run->notifications().resolves() << "\n"
        << "notify_connects:" << m_run->notifications().connects() << "\n"
        << "notify_reuses:" << m_run->notifications().reuses() << "\n"
        << "replication_pending:" << m_run->replication().pending() << "\n"
        << "replication_completed:" << m_run->replication().counters().completed << "\n"
        << "replication_failed:" << m_run->replication().counters().failed << "\n"
        << "replication_retries:" << m_run->replication().counters().retries << "\n"
        << "replication_connects:" << m_run->replication().connects() << "\n"
        << "replication_reuses:" << m_run->replication().reuses() << "\n"
        << "cluster_pending:" << m_run->replication().node_pending() << "\n"
        << "cluster_sent:" << m_run->replication().counters().node_sent << "\n"
        << "cluster_failed:" << m_run->replication().counters().node_failed << "\n"
        << "cluster_in:" << m_run->counters().cluster_in << "\n"
        << "cluster_seeds:" << m_run->replication().counters().node_seeds << "\n"
        << "cluster_seeded:" << m_run->replication().counters().node_seeded << "\n"
        << "cluster_seeding:" << m_run->replication().node_seeding() << "\n"
        << "cluster_overflows:" << m_run->replication().counters().node_overflows << "\n"
        << "cluster_synced:" << m_run->replication().counters().node_synced << "\n"
        << "cluster_sync_timeouts:" << m_run->replication().counters().node_sync_timeouts << "\n"
        << "scrub_objects:" << m_run->scrub().counters().objects << "\n"
        << "scrub_bytes:" << m_run->scrub().counters().bytes << "\n"
        << "scrub_corrupt:" << m_run->scrub().counters().corrupt << "\n"
        << "scrub_skipped:" << m_run->scrub().counters().skipped << "\n"
        << "scrub_passes:" << m_run->scrub().counters().passes << "\n"
        << "scrub_last_pass_ms:" << m_run->scrub().counters().last_pass_ms << "\n"
        << "scrub_heals:" << m_run->counters().scrub_heals << "\n"
        << "scrub_unhealed:" << m_run->counters().scrub_unhealed << "\n"
        << "compressed_objects:" << m_run->compaction().counters().objects << "\n"
        << "compressed_skipped:" << m_run->compaction().counters().skipped << "\n"
        << "compressed_failed:" << m_run->compaction().counters().failed << "\n"
        << "compressed_bytes_in:" << m_run->compaction().counters().bytes_in << "\n"
        << "compressed_bytes_out:" << m_run->compaction().counters().bytes_out << "\n"
        << "compressed_passes:" << m_run->compaction().counters().passes << "\n"
        << "tier_moved:" << m_run->tiers().counters().moved << "\n"
        << "tier_moved_bytes:" << m_run->tiers().counters().bytes << "\n"
        << "tier_failed:" << m_run->tiers().counters().failed << "\n"
        << "tier_moving:" << m_run->tiers().moving() << "\n"
        << "tier_reads:" << m_run->tiers().counters().reads << "\n"
        << "tier_read_failures:" << m_run->tiers().counters().read_failures << "\n"
        << "tier_swept:" << m_run->tiers().counters().swept << "\n"
        << "tier_gets:" << c.tier_gets << "\n"
        << "replication_bytes:" << m_run->replication().counters().bytes << "\n";
    // One line per code answered, so a client's mistakes and the runtime's own
    // are told apart without reading a log.
    for (const auto& [code, n] : c.errors)
        out << "error_" << code << ":" << n << "\n";
    {
        // What the shards say to one another, per shard because how the work
        // is spread is a question a sum cannot answer, and all zero at one shard.
        const auto& n = m_run->node().counters();
        out << "shard_index:" << get_shard_index() << "\n"
            << "shard_commits_sent:" << n.commits_out << "\n"
            << "shard_commits_served:" << n.commits_in << "\n"
            << "shard_deletes_sent:" << n.removes_out << "\n"
            << "shard_deletes_served:" << n.removes_in << "\n"
            << "shard_tags_sent:" << n.tags_out << "\n"
            << "shard_tags_served:" << n.tags_in << "\n"
            << "shard_list_fanouts:" << n.list_fanouts << "\n"
            << "shard_list_pages_served:" << n.list_pages_served << "\n"
            << "shard_bucket_ops:" << n.bucket_ops << "\n"
            << "shard_mpu_sent:" << n.mpu_out << "\n"
            << "shard_mpu_served:" << n.mpu_in << "\n"
            << "shard_hot_drops_sent:" << n.hot_drops_out << "\n"
            << "shard_hot_drops_served:" << n.hot_drops_in << "\n"
            << "shard_hot_holds_sent:" << n.hot_holds_out << "\n"
            << "shard_hot_holds_served:" << n.hot_holds_in << "\n"
            << "shard_peer_failures:" << n.peer_failures << "\n";
    }
    return out.str();
}
