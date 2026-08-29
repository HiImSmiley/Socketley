#include "runtime_config_apply.h"

#include "logging.h"
#include "state_persistence.h"
#include "runtime_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"

void apply_proxy_config(proxy_instance& prx, const runtime_config& cfg)
{
    prx.set_protocol(static_cast<proxy_protocol>(cfg.protocol));
    prx.set_strategy(static_cast<proxy_strategy>(cfg.strategy));
    for (const auto& b : cfg.backends)
        prx.add_backend(b);

    // The "!= default" tests are kept exactly as the restore path had them,
    // which matters for backend_timeout, where 0 means no deadline rather than
    // not configured.
    if (cfg.health_check > 0)
        prx.set_health_check(static_cast<mesh_config::health_type>(cfg.health_check));
    if (cfg.health_interval != 5)
        prx.set_health_interval(cfg.health_interval);
    if (!cfg.health_path.empty())
        prx.set_health_path(cfg.health_path);
    if (cfg.health_threshold != 3)
        prx.set_health_threshold(cfg.health_threshold);
    if (cfg.circuit_threshold != 5)
        prx.set_circuit_threshold(cfg.circuit_threshold);
    if (cfg.circuit_timeout != 30)
        prx.set_circuit_timeout(cfg.circuit_timeout);
    if (cfg.backend_timeout != 2)
        prx.set_backend_timeout(cfg.backend_timeout);
    if (cfg.retry_count > 0)
        prx.set_retry_count(cfg.retry_count);
    if (cfg.retry_all)
        prx.set_retry_all(true);
    if (!cfg.mesh_client_ca.empty())
        prx.set_mesh_client_ca(cfg.mesh_client_ca);
    if (!cfg.mesh_client_cert.empty())
        prx.set_mesh_client_cert(cfg.mesh_client_cert);
    if (!cfg.mesh_client_key.empty())
        prx.set_mesh_client_key(cfg.mesh_client_key);
}

void apply_common_config(runtime_instance& rt, const runtime_config& cfg)
{
    // Guarded the way the worker's own list was, because a setter called with
    // an empty value would overwrite a default that means something.
    if (cfg.port > 0)                rt.set_port(cfg.port);
    if (!cfg.listen_path.empty())    rt.set_listen_path(cfg.listen_path);
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
    if (cfg.sqpoll_set)
        rt.set_sqpoll(cfg.sqpoll);
}

void apply_typed_config(runtime_instance& rt, const runtime_config& cfg)
{
    switch (rt.get_type())
    {
        case runtime_server:
        {
            auto& srv = static_cast<server_instance&>(rt);
            srv.set_mode(static_cast<server_mode>(cfg.mode));
            srv.set_udp(cfg.udp);
            if (!cfg.master_pw.empty())  srv.set_master_pw(cfg.master_pw);
            if (cfg.master_forward)      srv.set_master_forward(true);
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
        {
            auto& cache = static_cast<cache_instance&>(rt);
            if (!cfg.persistent_path.empty())
                cache.set_persistent(cfg.persistent_path);
            cache.set_mode(static_cast<cache_mode>(cfg.cache_mode));
            cache.set_resp_forced(cfg.resp_forced);
            cache.set_cluster(cfg.cluster);
            if (!cfg.replicate_target.empty())
                cache.set_replicate_target(cfg.replicate_target);
            if (cfg.max_memory > 0) cache.set_max_memory(cfg.max_memory);
            cache.set_eviction(static_cast<eviction_policy>(cfg.eviction));
            break;
        }
    }

    // Unconditional because it is a no-op for the built-ins, and a registered
    // type's fields must arrive however the config did.
    rt.apply_extra(cfg.extra);
}
