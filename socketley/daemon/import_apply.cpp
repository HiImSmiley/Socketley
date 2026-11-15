#include "import_apply.h"

#include <tuple>

#include "flag_handlers.h"
#include "../shared/persist/state_persistence.h"
#include "../shared/runtime/runtime_config_apply.h"
#include "../shared/runtime/runtime_instance.h"

bool import_apply(runtime_instance& rt, const runtime_config& cfg, std::string& why, bool restore)
{
    const auto has = [&cfg](const char* key) { return cfg.has(key); };
    runtime_instance* instance = &rt;

    if (has("port"))              instance->set_port(cfg.port);
    if (has("listen"))            instance->set_listen_path(cfg.listen_path);
    if (has("bind"))              instance->set_bind_address(cfg.bind_address);
    if (has("domain") && rt.get_type() != runtime_storage) instance->set_domains(cfg.domains);
    if (has("log_file"))          instance->set_log_file(cfg.log_file);
    if (has("write_file"))        instance->set_write_file(cfg.write_file);
    if (has("bash_output"))       instance->set_bash_output(cfg.bash_output);
    if (has("bash_prefix"))       instance->set_bash_prefix(cfg.bash_prefix);
    if (has("bash_timestamp"))    instance->set_bash_timestamp(cfg.bash_timestamp);
    if (has("max_connections"))   instance->set_max_connections(cfg.max_connections);
    if (has("rate_limit"))        instance->set_rate_limit(cfg.rate_limit);
    if (has("global_rate_limit")) instance->set_global_rate_limit(cfg.global_rate_limit);
    if (has("idle_timeout"))      instance->set_idle_timeout(cfg.idle_timeout);
    // Read, written by `show` and taken by --congestion, and applied by no import: the document said it, 0 came back.
    if (has("congestion"))        instance->set_congestion(cfg.congestion);
    if (has("write_buffer"))      instance->set_write_buffer(cfg.write_buffer);
    if (has("read_buffer"))       instance->set_read_buffer(cfg.read_buffer);
    if (has("drain"))             instance->set_drain(cfg.drain);
    if (has("lua_ffi"))           instance->set_lua_ffi(cfg.lua_ffi);
    if (has("reconnect"))         instance->set_reconnect(cfg.reconnect);
    if (has("tls"))               instance->set_tls(cfg.tls);
    if (has("cert_path"))         instance->set_cert_path(cfg.cert_path);
    if (has("key_path"))          instance->set_key_path(cfg.key_path);
    // As the flags take them, which also points TLS at the files the names' certificate is kept in; empty clears them.
    for (const auto& [key, value, email] : {std::tuple{"acme_domains", &cfg.acme_domains, false},
                                            std::tuple{"acme_email", &cfg.acme_email, true}})
    {
        if (!has(key))
            continue;
        if (value->empty() || restore)
        {
            if (email)
                instance->set_acme_email(*value);
            else
                instance->set_acme_domains(*value);
            continue;
        }
        if (std::string refused = apply_acme(instance, *value, email); !refused.empty())
        {
            why = refused + "\n";
            return false;
        }
    }
    if (has("ca_path"))           instance->set_ca_path(cfg.ca_path);
    if (has("target"))            instance->set_target(cfg.target);
    if (has("cache_name"))        instance->set_cache_name(cfg.cache_name);
    if (has("group"))             instance->set_group(cfg.group);
    // Carried into this form from the block it replaced, because `show` emits
    // shards and a round trip that dropped it would return a sharded proxy
    // with one worker.
    if (has("shards"))            instance->set_shards(cfg.shards);

    // Its type's own fields by the document's keys, refused whole on an upstream that cannot be.
    return apply_typed_config(rt, cfg, /*by_presence=*/true, &why);
}
