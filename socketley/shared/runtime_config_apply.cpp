#include "runtime_config_apply.h"

#include "state_persistence.h"
#include "../runtime/proxy/proxy_instance.h"

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
