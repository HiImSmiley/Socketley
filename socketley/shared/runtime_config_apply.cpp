#include "runtime_config_apply.h"

#include "logging.h"
#include "state_persistence.h"
#include "runtime_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../runtime/storage/storage_instance.h"

void apply_proxy_config(proxy_instance& prx, const runtime_config& cfg,
                        bool by_presence)
{
    // See the header for why there are two questions and only one list.  The
    // "!= default" arms are kept exactly as the restore path had them, which
    // matters for backend_timeout, where 0 means no deadline rather than not
    // configured.
    const auto want = [&](const char* key, bool differs) {
        return by_presence ? cfg.has(key) : differs;
    };

    if (want("protocol", true))
        prx.set_protocol(static_cast<proxy_protocol>(cfg.protocol));
    if (want("strategy", true))
        prx.set_strategy(static_cast<proxy_strategy>(cfg.strategy));
    if (want("backends", true))
    {
        // Replaced and not added to, but only on the document door: the
        // restore builds a fresh instance with an empty list, and clearing on
        // a document that never mentioned backends is a proxy with nowhere to
        // forward.
        if (by_presence)
            prx.clear_backends();
        for (const auto& b : cfg.backends)
            prx.add_backend(b);
    }

    if (want("health_check", cfg.health_check > 0))
        prx.set_health_check(static_cast<mesh_config::health_type>(cfg.health_check));
    if (want("health_interval", cfg.health_interval != 5))
        prx.set_health_interval(cfg.health_interval);
    if (want("health_path", !cfg.health_path.empty()))
        prx.set_health_path(cfg.health_path);
    if (want("health_threshold", cfg.health_threshold != 3))
        prx.set_health_threshold(cfg.health_threshold);
    if (want("circuit_threshold", cfg.circuit_threshold != 5))
        prx.set_circuit_threshold(cfg.circuit_threshold);
    if (want("circuit_timeout", cfg.circuit_timeout != 30))
        prx.set_circuit_timeout(cfg.circuit_timeout);
    if (want("backend_timeout", cfg.backend_timeout != 2))
        prx.set_backend_timeout(cfg.backend_timeout);
    if (want("retry_count", cfg.retry_count > 0))
        prx.set_retry_count(cfg.retry_count);
    if (want("retry_all", cfg.retry_all))
        prx.set_retry_all(cfg.retry_all);
    if (want("mesh_client_ca", !cfg.mesh_client_ca.empty()))
        prx.set_mesh_client_ca(cfg.mesh_client_ca);
    if (want("mesh_client_cert", !cfg.mesh_client_cert.empty()))
        prx.set_mesh_client_cert(cfg.mesh_client_cert);
    if (want("mesh_client_key", !cfg.mesh_client_key.empty()))
        prx.set_mesh_client_key(cfg.mesh_client_key);
}

void apply_cache_config(cache_instance& cache, const runtime_config& cfg, bool by_presence)
{
    // By value a zero or an empty field is the default, which a fresh object
    // already holds; by presence the document's own key set decides.
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    if (asked("persistent_path", !cfg.persistent_path.empty()))
        cache.set_persistent(cfg.persistent_path);
    if (asked("persistent_interval", cfg.persistent_interval > 0))
        cache.set_persist_interval(cfg.persistent_interval);
    if (asked("cache_mode", true))
        cache.set_mode(static_cast<cache_mode>(cfg.cache_mode));
    if (asked("resp_forced", cfg.resp_forced))
        cache.set_resp_forced(cfg.resp_forced);
    if (asked("cluster", cfg.cluster))
        cache.set_cluster(cfg.cluster);
    if (asked("replicate_target", !cfg.replicate_target.empty()))
        cache.set_replicate_target(cfg.replicate_target);
    if (asked("cluster_replica", cfg.cluster_replica != 0))
        cache.set_cluster_replica(cfg.cluster_replica);
    if (asked("max_memory", cfg.max_memory > 0))
        cache.set_max_memory(cfg.max_memory);
    if (asked("eviction", true))
        cache.set_eviction(static_cast<eviction_policy>(cfg.eviction));
    if (asked("public", cfg.cache_public))
        cache.set_public(cfg.cache_public);
}

void apply_storage_config(storage_instance& stg, const runtime_config& cfg, bool by_presence)
{
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    if (asked("dir", !cfg.storage_dir.empty()))
        stg.set_dir(cfg.storage_dir);
    if (asked("anonymous", cfg.storage_anonymous))
        stg.set_anonymous(cfg.storage_anonymous);
    if (asked("max_bytes", cfg.storage_max_bytes > 0))
        stg.set_max_bytes(cfg.storage_max_bytes);
    if (asked("access_key", !cfg.storage_access_key.empty()))
        stg.set_access_key(cfg.storage_access_key);
    if (asked("secret_key", !cfg.storage_secret_key.empty()))
        stg.set_secret_key(cfg.storage_secret_key);
    if (asked("credentials", !cfg.storage_credentials.empty()))
        stg.set_credentials_file(cfg.storage_credentials);
    if (asked("sse_key_file", !cfg.storage_sse_key_file.empty()))
        stg.set_sse_key_file(cfg.storage_sse_key_file);
    if (asked("domain", !cfg.storage_domain.empty()))
        stg.set_domain(cfg.storage_domain);
    if (asked("notify_targets", !cfg.storage_notify_targets.empty()))
        stg.set_notify_targets(cfg.storage_notify_targets);
    if (asked("replication_targets", !cfg.storage_replication_targets.empty()))
        stg.set_replication_targets(cfg.storage_replication_targets);
    if (asked("fsync", !cfg.storage_fsync.empty()))
        stg.set_fsync(cfg.storage_fsync);
    if (asked("fsync_interval", cfg.storage_fsync_interval_secs > 0))
        stg.set_fsync_interval_secs(cfg.storage_fsync_interval_secs);
    if (asked("mpu_expire", cfg.storage_mpu_expire_secs > 0))
        stg.set_mpu_expire_secs(cfg.storage_mpu_expire_secs);
}

void apply_common_config(runtime_instance& rt, const runtime_config& cfg)
{
    // Guarded the way the worker's own list was, because a setter called with
    // an empty value would overwrite a default that means something.
    if (cfg.port > 0)                rt.set_port(cfg.port);
    if (!cfg.listen_path.empty())    rt.set_listen_path(cfg.listen_path);
    if (!cfg.companion_path.empty()) rt.set_companion_path(cfg.companion_path);
    if (!cfg.group.empty())          rt.set_group(cfg.group);
    if (!cfg.log_file.empty())       rt.set_log_file(cfg.log_file);
    if (!cfg.write_file.empty())     rt.set_write_file(cfg.write_file);
    if (cfg.bash_output)             rt.set_bash_output(true);
    if (cfg.bash_prefix)             rt.set_bash_prefix(true);
    if (cfg.bash_timestamp)          rt.set_bash_timestamp(true);
    if (cfg.max_connections > 0)     rt.set_max_connections(cfg.max_connections);
    if (cfg.rate_limit > 0.0)        rt.set_rate_limit(cfg.rate_limit);
    if (cfg.global_rate_limit > 0.0) rt.set_global_rate_limit(cfg.global_rate_limit);
    if (cfg.idle_timeout > 0)        rt.set_idle_timeout(cfg.idle_timeout);
    if (cfg.write_buffer > 0)        rt.set_write_buffer(cfg.write_buffer);
    if (cfg.read_buffer > 0)         rt.set_read_buffer(cfg.read_buffer);
    if (cfg.drain)                   rt.set_drain(true);
    if (cfg.tls)                     rt.set_tls(true);
    if (!cfg.cert_path.empty())      rt.set_cert_path(cfg.cert_path);
    if (!cfg.key_path.empty())       rt.set_key_path(cfg.key_path);
    if (!cfg.ca_path.empty())        rt.set_ca_path(cfg.ca_path);
    if (!cfg.target.empty())         rt.set_target(cfg.target);
    if (!cfg.cache_name.empty())     rt.set_cache_name(cfg.cache_name);
    // Read by the daemon, which forks this many workers, and carried into the
    // worker so `inspect` describes the same runtime whichever side is asked.
    if (cfg.shards > 1)              rt.set_shards(cfg.shards);
    // Unconditional, unlike every other line here, because zero is shard 0 and
    // the guarded form would leave a restarted shard 0 holding whichever index
    // this object last had.
    rt.set_shard_index(cfg.shard_index);

    // The ring request, recorded on the runtime so `stats` answers about what
    // was asked for, with applying it to an actual ring left to the caller.
    if (!cfg.cpus.empty())
    {
        cpu_set_spec spec;
        std::string  err;
        if (parse_cpu_set(cfg.cpus, spec, err))
            rt.set_cpus(spec);
    }
}

void apply_live_config(runtime_instance& rt, const runtime_config& cfg)
{
    if (cfg.max_connections > 0)     rt.set_max_connections(cfg.max_connections);
    if (cfg.rate_limit > 0.0)        rt.set_rate_limit(cfg.rate_limit);
    if (cfg.global_rate_limit > 0.0) rt.set_global_rate_limit(cfg.global_rate_limit);
    if (cfg.idle_timeout > 0)        rt.set_idle_timeout(cfg.idle_timeout);
    if (cfg.write_buffer > 0)        rt.set_write_buffer(cfg.write_buffer);
    if (cfg.read_buffer > 0)         rt.set_read_buffer(cfg.read_buffer);

    // Unconditional, like backend_timeout below and for the same reason: the
    // only caller parses a whole document, so an absent write_file means the
    // operator cleared it, and a guarded form would make -w the one setting
    // that could be turned on and never off.  set_write_file() drops the old
    // descriptor when the path moves, so a live runtime follows the flag.
    rt.set_write_file(cfg.write_file);

    // A proxy's routing and mesh POLICY, which is every mesh field this worker
    // reads at the moment it uses it rather than at setup: a strategy is read
    // when a backend is picked, a deadline when a request is armed, a circuit
    // threshold when a failure is counted.  Those can move under a serving
    // proxy because nothing is built from them.
    //
    // What is NOT here is the other four, and each for the same reason in a
    // different place: --health-check arms a timer at setup and turning it on
    // has none to arm, and --client-ca/--client-cert/--client-key are the mTLS
    // context init_server() built before the first handshake.  `edit` refuses
    // those while the runtime is running rather than storing them quietly.
    if (rt.get_type() == runtime_proxy)
    {
        auto& prx = static_cast<proxy_instance&>(rt);
        prx.set_strategy(static_cast<proxy_strategy>(cfg.strategy));
        if (cfg.health_interval > 0)   prx.set_health_interval(cfg.health_interval);
        if (!cfg.health_path.empty())  prx.set_health_path(cfg.health_path);
        if (cfg.health_threshold > 0)  prx.set_health_threshold(cfg.health_threshold);
        if (cfg.circuit_threshold >= 0) prx.set_circuit_threshold(cfg.circuit_threshold);
        if (cfg.circuit_timeout > 0)   prx.set_circuit_timeout(cfg.circuit_timeout);
        // Unconditional, unlike the rest: zero is "no deadline" and is a
        // setting an operator can ask for, so the guarded form would make
        // `--backend-timeout 0` the one value that could not be edited.
        prx.set_backend_timeout(cfg.backend_timeout);
        if (cfg.retry_count >= 0)      prx.set_retry_count(cfg.retry_count);
        prx.set_retry_all(cfg.retry_all);
    }

    // A storage quota is read at each put, so it moves under a serving runtime.
    if (rt.get_type() == runtime_storage)
        static_cast<storage_instance&>(rt).set_max_bytes(cfg.storage_max_bytes);

    // The setters above write fields the hot paths do not read; this is what
    // makes them true for a runtime that is already serving.
    rt.refresh_cached_limits();
}

void apply_typed_config(runtime_instance& rt, const runtime_config& cfg)
{
    switch (rt.get_type())
    {
        case runtime_server:
        {
            auto& srv = static_cast<server_instance&>(rt);
            srv.set_mode(static_cast<server_mode>(cfg.mode));
            srv.set_send_to(cfg.send_to);
            srv.set_udp(cfg.udp);
            if (!cfg.master_pw.empty())  srv.set_master_pw(cfg.master_pw);
            if (!cfg.http_dir.empty())   srv.set_http_dir(cfg.http_dir);
            if (cfg.http_cache)          srv.set_http_cache(true);
            srv.clear_upstream_targets();
            for (const auto& u : cfg.upstreams)
            {
                // Log and skip, as the boot restore does, because there is no
                // command in flight to refuse to and dropping the runtime over
                // one unreadable entry takes down a listener the rest of the
                // configuration can serve.
                if (!srv.add_upstream_target(u))
                    LOG_WARN(("dropping upstream \"" + u +
                              "\": the port is not a number between 1 and 65535").c_str());
            }
            break;
        }
        case runtime_client:
        {
            auto& cli = static_cast<client_instance&>(rt);
            cli.set_mode(static_cast<client_mode>(cfg.mode));
            cli.set_udp(cfg.udp);
            // `>= 0`, not `!= 0`, because -1 is disabled and 0 is infinite
            // attempts -- the spelling `--reconnect` produces without a
            // number, which state_persistence.cpp already writes under the
            // same test.
            if (cfg.reconnect >= 0) cli.set_reconnect(cfg.reconnect);
            break;
        }
        case runtime_proxy:
            apply_proxy_config(static_cast<proxy_instance&>(rt), cfg);
            break;

        case runtime_cache:
            apply_cache_config(static_cast<cache_instance&>(rt), cfg);
            break;

        case runtime_storage:
            apply_storage_config(static_cast<storage_instance&>(rt), cfg);
            break;
    }

    // Unconditional because it is a no-op for the built-ins, and a registered
    // type's fields must arrive however the config did.
    rt.apply_config(cfg.extra);
}
