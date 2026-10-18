#pragma once
// The storage runtime: an S3 endpoint over one directory.
//
// This object is the configuration and the lifecycle.  Everything that serves
// lives in a storage_run, which setup() makes and teardown() lets go of, so a
// stop and a start in one process never share a connection or a descriptor.
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "bucket_policy.h"
#include "s3_auth.h"
#include "../../shared/ipc/request_channel.h"
#include "../../shared/runtime/runtime_instance.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/net/unix_companion.h"
#include "shared/runtime/retired_runs.h"

namespace socketley::storage
{
class storage_run;
}

// The port a storage runtime listens on when none was configured.  Named once
// because setup() and listen_addresses() have to answer with the same number.
inline constexpr uint16_t storage_default_port = 9000;

class storage_instance : public runtime_instance, public deferred_request_sink
{
public:
    explicit storage_instance(std::string_view name);
    ~storage_instance() override;

    // Where the buckets live.
    void set_dir(std::string_view dir) { m_dir = std::string(dir); }
    std::string_view get_dir() const { return m_dir; }

    // Requests are accepted without credentials.  Off unless asked for, and
    // the runtime refuses to start with neither this nor a way to
    // authenticate.
    void set_anonymous(bool on) { m_anonymous = on; }
    bool get_anonymous() const { return m_anonymous; }

    // The idp runtime of this daemon whose sign-in the web interface takes (--idp), a user signed in there being the
    // user of the same name here.
    void set_idp(std::string_view name) { m_idp = std::string(name); }
    std::string_view get_idp() const { return m_idp; }
    // Buckets given no ownership controls take ACLs (--acls), as S3 did before it disabled them by default.
    void set_acls(bool on) { m_acls = on; }
    bool get_acls() const { return m_acls; }

    // The credentials requests are signed with, as a pair given here and as
    // a file of `access:secret` lines that is re-read when it changes.
    void set_access_key(std::string_view k) { m_access_key = std::string(k); }
    void set_secret_key(std::string_view k) { m_secret_key = std::string(k); }
    void set_credentials_file(std::string_view f) { m_credentials_file = std::string(f); }
    std::string_view get_access_key() const { return m_access_key; }
    std::string_view get_secret_key() const { return m_secret_key; }
    std::string_view get_credentials_file() const { return m_credentials_file; }
    bool has_credentials() const
    {
        return !m_access_key.empty() || !m_secret_key.empty() || !m_credentials_file.empty();
    }

    // Uploads left open this many seconds are aborted; 0 keeps them until they
    // are completed or aborted.
    void set_mpu_expire_secs(uint32_t s) { m_mpu_expire_secs = s; }
    uint32_t get_mpu_expire_secs() const { return m_mpu_expire_secs; }
    // A whole scrub of every object in this long (--scrub), 0 for none.
    void set_scrub_secs(uint32_t s) { m_scrub_secs = s; }
    uint32_t get_scrub_secs() const { return m_scrub_secs; }
    // Versions unwritten for this long are compressed (--compress), 0 for none.
    void set_compress_secs(uint32_t s) { m_compress_secs = s; }
    uint32_t get_compress_secs() const { return m_compress_secs; }

    // A quota on the bytes held, 0 for none.
    void set_max_bytes(uint64_t bytes) { m_max_bytes = bytes; }
    uint64_t get_max_bytes() const { return m_max_bytes; }

    // The file of the master key SSE-S3 data keys are wrapped with, read at every start; none refuses SSE-S3.
    void set_sse_key_file(std::string_view f) { m_sse_key_file = std::string(f); }
    std::string_view get_sse_key_file() const { return m_sse_key_file; }

    // The comma-separated domains under which a Host of `<bucket>.<domain>` addresses a bucket; empty is path style only.
    void set_domain(std::string_view d) { m_domain = std::string(d); }
    std::string_view get_domain() const { return m_domain; }
    // The comma-separated domains under which a Host of `<bucket>.<domain>` is that bucket's website.
    void set_website_domain(std::string_view d) { m_website_domain = std::string(d); }
    std::string_view get_website_domain() const { return m_website_domain; }

    // The file of `name url` lines naming the webhooks event notifications go to, read at every start; none refuses
    // every destination.
    void set_notify_targets(std::string_view f) { m_notify_targets = std::string(f); }
    std::string_view get_notify_targets() const { return m_notify_targets; }

    // The file of `name url region access_key secret` lines naming the endpoints buckets replicate to, read at every
    // start; none refuses every replication configuration.
    void set_replication_targets(std::string_view f) { m_replication_targets = std::string(f); }
    std::string_view get_replication_targets() const { return m_replication_targets; }
    // The tiers a lifecycle moves versions to (--tiers), a file of `name url region access_key secret` lines.
    void set_tiers_file(std::string_view f) { m_tiers_file = std::string(f); }
    std::string_view get_tiers_file() const { return m_tiers_file; }
    // The OIDC provider and LDAP directory STS takes identities from (--federation), a file of lines read at start.
    void set_federation_file(std::string_view f) { m_federation_file = std::string(f); }
    std::string_view get_federation_file() const { return m_federation_file; }
    // The proxies that terminate TLS before the runtime (--tls-offloaded), comma-separated addresses or blocks.
    void set_tls_offloaded(std::string_view v) { m_tls_offloaded = std::string(v); }
    std::string_view get_tls_offloaded() const { return m_tls_offloaded; }
    // The blocks --tls-offloaded names, false for one that is none.
    bool tls_offloaded_blocks(std::vector<socketley::storage::bucket_policy::cidr>& out) const;

    // The nodes file (--nodes) that names this runtime's node of a cluster, the others, and the key they sign with.
    void set_nodes_file(std::string_view f) { m_cluster_file = std::string(f); }
    std::string_view get_nodes_file() const { return m_cluster_file; }

    // When an answered write is synced: always before its answer (empty), within --fsync-interval after it, or never
    // before a stop.
    void set_fsync(std::string_view m) { m_fsync = std::string(m); }
    std::string_view get_fsync() const { return m_fsync; }
    // Which sync runtimes it makes for its users' git repositories: never, active or per-user.
    void set_sync(std::string_view m) { m_sync = std::string(m); }
    std::string_view get_sync() const { return m_sync; }
    // The interval of --fsync interval, 0 for its default of a second.
    void set_fsync_interval_secs(uint32_t s) { m_fsync_interval_secs = s; }
    uint32_t get_fsync_interval_secs() const { return m_fsync_interval_secs; }

    // What decides whether a request may go on.  Given, it is used instead of
    // the anonymous default; the SigV4 authenticator arrives here.
    void set_authenticator(std::unique_ptr<socketley::storage::authenticator> a);
    bool has_authenticator() const { return m_auth != nullptr; }

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;

    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    std::string config_refusal() const override;
    void refresh_cached_limits() override;

    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    // ── request_sink ────────────────────────────────────────────────────────
    // Two kinds of caller send this runtime a request by name: a sibling shard (a
    // commit, a delete, a page of a listing, a bucket or upload step, told by the
    // magic that opens the payload) and another runtime's script calling
    // socketley.storage.*.  Both are answered on a later turn, because each of
    // them waits on the disk, so a slow disk is latency and never a stopped loop.
    bool serve_deferred(uint64_t ticket, std::string_view target, std::string_view payload) override;
    // Itself in the worker, and the daemon's override where the runtime is a
    // placeholder for a worker, whose run is empty.
    request_sink* as_request_sink() override { return sink_or(this); }

    // What was counted, for the tests that read it through `stats`.
    socketley::storage::storage_run* run() const { return m_run.get(); }

private:
    bool open_listener(uint16_t port, bool reuseport, int& out_fd);

    std::string m_dir;
    bool        m_anonymous{false};
    std::string m_idp;
    bool        m_acls{false};
    uint64_t    m_max_bytes{0};
    std::string m_access_key;
    std::string m_secret_key;
    std::string m_credentials_file;
    std::string m_sse_key_file;
    std::string m_domain;
    std::string m_website_domain;
    std::string m_notify_targets;
    std::string m_replication_targets;
    std::string m_tiers_file;
    std::string m_federation_file;
    std::string m_tls_offloaded;
    std::string m_cluster_file;
    std::string m_fsync;
    std::string m_sync{"never"};
    uint32_t    m_fsync_interval_secs{0};
    uint32_t    m_mpu_expire_secs{0};
    uint32_t    m_scrub_secs{0};
    uint32_t    m_compress_secs{0};
    std::unique_ptr<socketley::storage::authenticator> m_auth;
    std::unique_ptr<socketley::storage::anonymous_authenticator> m_anon;

    std::unique_ptr<socketley::storage::storage_run> m_run;
    // Runs the ring still owes completions to, freed once it owes them none.
    socketley::retired_runs<socketley::storage::storage_run> m_graveyard;
    event_loop* m_loop{nullptr};
    std::string m_bound_listen_path;
    // The node beside the port, made once and kept: it owns an io_request the
    // ring may still be holding after a stop.
    std::unique_ptr<socketley::unix_companion> m_companion;
    uint32_t    m_max_conns_cached{0};
};
