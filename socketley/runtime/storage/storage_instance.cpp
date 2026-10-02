#include "storage_instance.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sstream>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "s3_sigv4_auth.h"
#include "s3_vhost.h"
#include "sse.h"
#include "shard_wire.h"
#include "storage_run.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/event_loop.h"
#include "../../shared/logging.h"
#include "../../shared/socket_tuning.h"
#include "../../shared/unix_listener.h"

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
    if (has_credentials())
        if (const std::string why = socketley::storage::sigv4_config_error(
                {m_access_key, m_secret_key, m_credentials_file, m_anonymous}); !why.empty())
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
    return {};
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

void storage_instance::refresh_cached_limits()
{
    m_max_conns_cached = get_max_connections();
    if (m_run)
    {
        m_run->store().set_max_bytes(m_max_bytes);
        m_run->set_mpu_expire_secs(m_mpu_expire_secs);
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
    addr.sin_addr.s_addr = INADDR_ANY;
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
    // A run the ring has finished with is freed here, and the ones it still
    // owes completions stay where they are.
    std::erase_if(m_graveyard, [](const auto& r) { return r->drained(); });

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
    }

    socketley::storage::authenticator* auth = m_auth.get();
    std::unique_ptr<socketley::storage::authenticator> signed_auth;
    if (!auth && has_credentials())
    {
        // Made at every start, so a reload picks up a changed file and key.
        auto a = std::make_unique<socketley::storage::sigv4_authenticator>(
            socketley::storage::sigv4_config{m_access_key, m_secret_key, m_credentials_file, m_anonymous});
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

    auto run = std::make_unique<storage_run>(*this, loop, opts, auth);
    if (signed_auth)
        run->adopt_authenticator(std::move(signed_auth));
    run->set_mpu_expire_secs(m_mpu_expire_secs);
    run->set_tls(std::move(tls));
    if (std::vector<std::string> d; !m_domain.empty())
    {
        std::string why;
        if (!socketley::storage::parse_domains(m_domain, d, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            run->stop();
            m_graveyard.push_back(std::move(run));
            return false;
        }
        run->set_domains(std::move(d));
    }
    // Read here, at every start, so a replaced key file is the one a restart serves with.
    if (!m_sse_key_file.empty())
    {
        socketley::storage::sse_key key{};
        std::string why;
        if (!socketley::storage::load_sse_master(m_sse_key_file, key, why))
        {
            LOG_ERROR(("storage: " + why).c_str());
            run->stop();
            m_graveyard.push_back(std::move(run));
            return false;
        }
        run->set_sse_master(key);
    }

    // The one blocking step: reading the directory and reconciling the journals
    // happens here, before the listener exists, so no connection waits behind it.
    std::string err;
    if (!run->open(err))
    {
        LOG_ERROR(("storage: " + err).c_str());
        run->stop();
        m_graveyard.push_back(std::move(run));
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
            run->stop();
            m_graveyard.push_back(std::move(run));
            return false;
        }
        // One node per shard, because a path is one listener and the second
        // process to bind it would unlink the first.
        if (const std::string msg = socketley::unix_sock::shard_listen_path_refusal(
                listen_path, get_shards()); !msg.empty())
        {
            LOG_ERROR(("storage: " + msg).c_str());
            run->stop();
            m_graveyard.push_back(std::move(run));
            return false;
        }
        const std::string mine = socketley::unix_sock::shard_listen_path(
            listen_path, get_shard_index(), get_shards());
        auto r = socketley::unix_sock::bind_listener(mine);
        if (r.fd < 0)
        {
            LOG_ERROR(("storage: " + r.error).c_str());
            run->stop();
            m_graveyard.push_back(std::move(run));
            return false;
        }
        fd = r.fd;
        m_bound_listen_path = mine;
    }
    else if (!open_listener(effective_port(), /*reuseport=*/get_shards() > 1, fd))
    {
        run->stop();
        m_graveyard.push_back(std::move(run));
        return false;
    }

    if (!run->listen_on(fd))
    {
        loop.close_fd(fd);
        run->stop();
        m_graveyard.push_back(std::move(run));
        return false;
    }
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
    if (m_run)
    {
        m_run->stop();
        m_graveyard.push_back(std::move(m_run));
    }
    if (!m_bound_listen_path.empty())
    {
        if (::unlink(m_bound_listen_path.c_str()) < 0) {}
        m_bound_listen_path.clear();
    }
    m_loop = nullptr;
}

void storage_instance::on_loop_turn()
{
    if (!m_graveyard.empty())
        std::erase_if(m_graveyard, [](const auto& r) { return r->drained(); });
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
        << "fsyncs:" << t.fsyncs << "\n"
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
        << "recv_fallbacks:" << c.recv_fallbacks << "\n"
        << "recv_cancels:" << c.recv_cancels << "\n"
        << "recv_direct_bytes:" << c.recv_direct_bytes << "\n"
        << "body_recvs:" << c.body_recvs << "\n"
        << "hash_handoffs:" << m_run->hash_handoffs() << "\n"
        << "sse:" << (m_run->has_sse_master() ? 1 : 0) << "\n"
        << "sse_puts:" << c.sse_puts << "\n"
        << "sse_gets:" << c.sse_gets << "\n";
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
