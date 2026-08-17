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

    // The "!= default" tests are kept exactly as the restore path had them.
    // They matter for backend_timeout in particular, where 0 means "no
    // deadline" and is not the same answer as "not configured" — see the note
    // on runtime_config::backend_timeout.
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
    // Guarded the way the worker's own list was: a setter called with an empty
    // or zero value would overwrite a default that means something, and this
    // function is used on a runtime that is already configured as well as on a
    // fresh one.
    if (cfg.port > 0)                rt.set_port(cfg.port);
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
    // Read by the daemon, which forks this many workers.  Carried into the
    // worker too, so `inspect` describes the same runtime whichever side is
    // asked — a shard itself does nothing with the number: it is one process
    // serving one listening socket, and which of N it happens to be changes
    // nothing about what it does.
    if (cfg.shards > 1)              rt.set_shards(cfg.shards);

    // The ring request, recorded on the runtime so `stats` answers about what
    // was asked for and not only about what the ring happens to be.  Applying
    // it to an actual ring is the caller's: in the daemon every runtime shares
    // one, built before any config was read, and in a worker there is one ring
    // per runtime and it is built from exactly this — see proxy_worker's
    // on_config, which has to do it before init() because io_uring fixes a
    // ring's flags at creation.
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
                // The worker's config frame carries what the daemon's state
                // file holds, so this is the same situation as the boot restore
                // in daemon.cpp and takes the same answer: log and skip.  There
                // is no command in flight to refuse to, and dropping the whole
                // runtime over one unreadable entry would take down a listener
                // that the rest of the configuration can still serve.
                //
                // A configuration typed today cannot reach here — `create`,
                // `edit` and `import` all refuse an unusable upstream before it
                // is ever written down.  What reaches here is a file an older
                // daemon wrote.
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
            // `>= 0`, not `!= 0`.  The field has three states — -1 disabled,
            // 0 infinite attempts, N a limit — so 0 is a value, not an absence,
            // and it is the one `--reconnect` produces when written without a
            // number, which the man page gives as the default form.  Guarding
            // on `!= 0` skipped exactly the spelling the flag is usually typed
            // as, leaving m_reconnect at its -1 default: accepted by the CLI,
            // stored, reported by `show`, and inert.
            //
            // state_persistence.cpp writes the field under `if (cfg.reconnect
            // >= 0)`.  Writer and reader disagreed about what 0 meant, and only
            // the worker path reads it back — which is why an in-daemon client
            // reconnected in about a second and a worker one, the default since
            // 2313c26, never did.
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
            if (!cfg.replicate_target.empty())
                cache.set_replicate_target(cfg.replicate_target);
            if (cfg.max_memory > 0) cache.set_max_memory(cfg.max_memory);
            cache.set_eviction(static_cast<eviction_policy>(cfg.eviction));
            break;
        }
    }
}
