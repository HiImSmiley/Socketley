#include "runtime_config_apply.h"

#include "../util/logging.h"
#include "../persist/state_persistence.h"
#include "runtime_instance.h"
#include "../../runtime/server/server_instance.h"
#include "../../runtime/client/client_instance.h"
#include "../../runtime/proxy/proxy_instance.h"
#include "../../runtime/cache/cache_instance.h"
#include "../../runtime/storage/storage_instance.h"
#include "../../runtime/dns/dns_instance.h"
#include "../../runtime/sync/sync_instance.h"
#include "../../runtime/idp/idp_instance.h"
#include "../../runtime/db/db_instance.h"
#include "../../runtime/mqtt/mqtt_instance.h"
#include "../../runtime/mail/mail_instance.h"

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
    static const runtime_config defaults;

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
    if (want("health_interval", cfg.health_interval != defaults.health_interval))
        prx.set_health_interval(cfg.health_interval);
    if (want("health_path", !cfg.health_path.empty()))
        prx.set_health_path(cfg.health_path);
    if (want("health_threshold", cfg.health_threshold != defaults.health_threshold))
        prx.set_health_threshold(cfg.health_threshold);
    if (want("circuit_threshold", cfg.circuit_threshold != defaults.circuit_threshold))
        prx.set_circuit_threshold(cfg.circuit_threshold);
    if (want("circuit_timeout", cfg.circuit_timeout != defaults.circuit_timeout))
        prx.set_circuit_timeout(cfg.circuit_timeout);
    if (want("backend_timeout", cfg.backend_timeout != defaults.backend_timeout))
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
    if (want("auth", !cfg.proxy_auth.empty()))
        prx.set_auth(cfg.proxy_auth);
    if (want("redirect_https", cfg.https_redirect != 0))
        prx.set_https_redirect(cfg.https_redirect);
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

void apply_dns_config(dns_instance& dns, const runtime_config& cfg, bool by_presence)
{
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    if (asked("zones", !cfg.dns_zones.empty()))
        dns.set_zones(cfg.dns_zones);
    if (asked("transfer", !cfg.dns_transfer.empty()))
        dns.set_transfer(cfg.dns_transfer);
    if (asked("notify", !cfg.dns_notify.empty()))
        dns.set_notify(cfg.dns_notify);
    if (asked("publish", !cfg.dns_publish.empty()))
        dns.set_publish(cfg.dns_publish);
    if (asked("proxy", !cfg.dns_proxy.empty()))
        dns.set_proxy(cfg.dns_proxy);
    if (asked("rrl", true))
        dns.set_rrl(cfg.dns_rrl);
}

void apply_sync_config(sync_instance& sy, const runtime_config& cfg, bool by_presence)
{
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    if (asked("dir", !cfg.sync_dir.empty()))
        sy.set_dir(cfg.sync_dir);
    if (asked("storage", !cfg.sync_storage.empty()))
        sy.set_storage(cfg.sync_storage);
    if (asked("prefix", !cfg.sync_prefix.empty()))
        sy.set_prefix(cfg.sync_prefix);
    if (asked("credentials", !cfg.sync_credentials.empty()))
        sy.set_credentials(cfg.sync_credentials);
    if (asked("exclude", !cfg.sync_exclude.empty()))
        sy.set_exclude(cfg.sync_exclude);
    if (asked("repositories", !cfg.sync_repositories.empty()))
        sy.set_repositories(cfg.sync_repositories);
    if (asked("mode", cfg.mode != 0))
        sy.set_mode(static_cast<sync_mode>(cfg.mode));
    if (asked("every", true))
        sy.set_every(cfg.sync_every);
}

void apply_idp_config(idp_instance& ip, const runtime_config& cfg, bool by_presence)
{
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    if (asked("clients", !cfg.idp_clients.empty()))
        ip.set_clients(cfg.idp_clients);
    if (asked("issuer", !cfg.idp_issuer.empty()))
        ip.set_issuer(cfg.idp_issuer);
    if (asked("cookie_domain", !cfg.idp_cookie_domain.empty()))
        ip.set_cookie_domain(cfg.idp_cookie_domain);
}

void apply_db_config(db_instance& db, const runtime_config& cfg, bool by_presence)
{
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    if (asked("schema", !cfg.db_schema.empty()))
        db.set_schema_path(cfg.db_schema);
    if (asked("keys", !cfg.db_keys.empty()))
        db.set_keys_path(cfg.db_keys);
    if (asked("idp", !cfg.db_idp.empty()))
        db.set_idp(cfg.db_idp);
    if (asked("origins", !cfg.db_origins.empty()))
        db.set_origins(cfg.db_origins);
    if (asked("max_bytes", cfg.db_max_bytes > 0))
        db.set_max_bytes(cfg.db_max_bytes);
    if (asked("cache", true))
        db.set_cache_bytes(cfg.db_cache);
    if (asked("replicate", !cfg.db_replicate.empty()))
        db.set_replicate(cfg.db_replicate);
    if (asked("replicate_key", !cfg.db_replicate_key.empty()))
        db.set_replicate_key(cfg.db_replicate_key);
    if (asked("backup_dir", !cfg.db_backup_dir.empty()))
        db.set_backup_dir(cfg.db_backup_dir);
    if (asked("backup_every", true))
        db.set_backup_every(cfg.db_backup_every);
    if (asked("backup_keep", true))
        db.set_backup_keep(cfg.db_backup_keep);
}

void apply_mail_config(mail_instance& ml, const runtime_config& cfg, bool by_presence)
{
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    static const runtime_config defaults;
    if (asked("submission", cfg.mail_submission != defaults.mail_submission))
        ml.set_submission_port(cfg.mail_submission);
    if (asked("submissions", cfg.mail_submissions != defaults.mail_submissions))
        ml.set_submissions_port(cfg.mail_submissions);
    if (asked("imap", cfg.mail_imap != defaults.mail_imap))
        ml.set_imap_port(cfg.mail_imap);
    if (asked("imaps", cfg.mail_imaps != defaults.mail_imaps))
        ml.set_imaps_port(cfg.mail_imaps);
    if (asked("sieve", cfg.mail_sieve != defaults.mail_sieve))
        ml.set_sieve_port(cfg.mail_sieve);
    if (asked("dnsbl", !cfg.mail_dnsbl.empty()))
        ml.set_dnsbl(cfg.mail_dnsbl);
    if (asked("dns", !cfg.mail_dns.empty()))
        ml.set_dns(cfg.mail_dns);
    if (asked("mail_domain", !cfg.mail_domains.empty()))
        ml.set_mail_domains(cfg.mail_domains);
    if (asked("hostname", !cfg.mail_hostname.empty()))
        ml.set_hostname(cfg.mail_hostname);
    if (asked("no_reply", cfg.mail_no_reply))
        ml.set_no_reply(cfg.mail_no_reply);
    if (asked("idp", !cfg.mail_idp.empty()))
        ml.set_idp(cfg.mail_idp);
    if (asked("storage", !cfg.mail_storage.empty()))
        ml.set_storage(cfg.mail_storage);
    if (asked("users", !cfg.mail_users.empty()))
        ml.set_users(cfg.mail_users);
    if (asked("relay", !cfg.mail_relay.empty()))
        ml.set_relay(cfg.mail_relay);
    if (asked("aliases", !cfg.mail_aliases.empty()))
        ml.set_aliases(cfg.mail_aliases);
    if (asked("notify_targets", !cfg.mail_notify.empty()))
        ml.set_notify_targets(cfg.mail_notify);
    if (asked("max_size", cfg.mail_max_size != defaults.mail_max_size))
        ml.set_max_size(cfg.mail_max_size);
    if (asked("max_recipients", cfg.mail_max_rcpt != defaults.mail_max_rcpt))
        ml.set_max_recipients(cfg.mail_max_rcpt);
    if (asked("queue_lifetime", cfg.mail_lifetime != defaults.mail_lifetime))
        ml.set_queue_lifetime(cfg.mail_lifetime);
    if (asked("dkim_selector", cfg.mail_selector != defaults.mail_selector))
        ml.set_dkim_selector(cfg.mail_selector);
}

void apply_mqtt_config(mqtt_instance& mq, const runtime_config& cfg, bool by_presence)
{
    auto asked = [&](std::string_view key, bool nondefault) {
        return by_presence ? cfg.has(key) : nondefault;
    };
    static const runtime_config defaults;
    if (asked("users", !cfg.mqtt_users.empty()))
        mq.set_users(cfg.mqtt_users);
    if (asked("idp", !cfg.mqtt_idp.empty()))
        mq.set_idp(cfg.mqtt_idp);
    if (asked("acl", !cfg.mqtt_acl.empty()))
        mq.set_acl(cfg.mqtt_acl);
    if (asked("routes", !cfg.mqtt_routes.empty()))
        mq.set_routes(cfg.mqtt_routes);
    if (asked("anonymous", cfg.mqtt_anonymous))
        mq.set_anonymous(cfg.mqtt_anonymous);
    if (asked("ws_port", cfg.mqtt_ws_port != 0))
        mq.set_ws_port(cfg.mqtt_ws_port);
    if (asked("max_packet", cfg.mqtt_max_packet != defaults.mqtt_max_packet))
        mq.set_max_packet(cfg.mqtt_max_packet);
    if (asked("session_expiry", cfg.mqtt_session_expiry != defaults.mqtt_session_expiry))
        mq.set_session_expiry(cfg.mqtt_session_expiry);
    if (asked("session_queue", cfg.mqtt_session_queue != defaults.mqtt_session_queue))
        mq.set_session_queue(cfg.mqtt_session_queue);
    if (asked("retained_max", cfg.mqtt_retained_max != defaults.mqtt_retained_max))
        mq.set_retained_max(cfg.mqtt_retained_max);
    if (asked("max_sessions", cfg.mqtt_max_sessions != defaults.mqtt_max_sessions))
        mq.set_max_sessions(cfg.mqtt_max_sessions);
    if (asked("keepalive_max", cfg.mqtt_keepalive_max != defaults.mqtt_keepalive_max))
        mq.set_keepalive_max(cfg.mqtt_keepalive_max);
    if (asked("persistent_path", !cfg.persistent_path.empty()))
        mq.set_persistent(cfg.persistent_path);
    if (asked("persistent_interval", cfg.persistent_interval > 0))
        mq.set_persist_interval(cfg.persistent_interval);
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
    if (asked("idp", !cfg.storage_idp.empty()))
        stg.set_idp(cfg.storage_idp);
    if (asked("acls", cfg.storage_acls))
        stg.set_acls(cfg.storage_acls);
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
    if (asked("website_domain", !cfg.storage_website_domain.empty()))
        stg.set_website_domain(cfg.storage_website_domain);
    if (asked("notify_targets", !cfg.storage_notify_targets.empty()))
        stg.set_notify_targets(cfg.storage_notify_targets);
    if (asked("replication_targets", !cfg.storage_replication_targets.empty()))
        stg.set_replication_targets(cfg.storage_replication_targets);
    if (asked("tiers", !cfg.storage_tiers.empty()))
        stg.set_tiers_file(cfg.storage_tiers);
    if (asked("federation", !cfg.storage_federation.empty()))
        stg.set_federation_file(cfg.storage_federation);
    if (asked("tls_offloaded", !cfg.storage_tls_offloaded.empty()))
        stg.set_tls_offloaded(cfg.storage_tls_offloaded);
    if (asked("nodes", !cfg.storage_nodes.empty()))
        stg.set_nodes_file(cfg.storage_nodes);
    if (asked("fsync", !cfg.storage_fsync.empty()))
        stg.set_fsync(cfg.storage_fsync);
    if (asked("sync", !cfg.storage_sync.empty()))
        stg.set_sync(cfg.storage_sync);
    if (asked("fsync_interval", cfg.storage_fsync_interval_secs > 0))
        stg.set_fsync_interval_secs(cfg.storage_fsync_interval_secs);
    if (asked("mpu_expire", cfg.storage_mpu_expire_secs > 0))
        stg.set_mpu_expire_secs(cfg.storage_mpu_expire_secs);
    if (asked("scrub", cfg.storage_scrub_secs > 0))
        stg.set_scrub_secs(cfg.storage_scrub_secs);
    if (asked("compress", cfg.storage_compress_secs > 0))
        stg.set_compress_secs(cfg.storage_compress_secs);
}

void apply_common_config(runtime_instance& rt, const runtime_config& cfg)
{
    // Guarded the way the worker's own list was, because a setter called with
    // an empty value would overwrite a default that means something.
    if (cfg.port > 0)                rt.set_port(cfg.port);
    if (!cfg.listen_path.empty())    rt.set_listen_path(cfg.listen_path);
    if (!cfg.bind_address.empty())   rt.set_bind_address(cfg.bind_address);
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
    if (!cfg.acme_domains.empty())   rt.set_acme_domains(cfg.acme_domains);
    if (!cfg.acme_email.empty())     rt.set_acme_email(cfg.acme_email);
    if (!cfg.domains.empty())        rt.set_domains(cfg.domains);
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

bool apply_server_config(server_instance& srv, const runtime_config& cfg, bool by_presence, std::string* refusal)
{
    const auto asked = [&](const char* key, bool otherwise) { return by_presence ? cfg.has(key) : otherwise; };
    if (asked("mode", true))
        srv.set_mode(static_cast<server_mode>(cfg.mode));
    if (asked("send_to", true) || (by_presence && cfg.has("master_forward")))
        srv.set_send_to(cfg.send_to);
    if (asked("udp", true))
        srv.set_udp(cfg.udp);
    if (asked("http_dir", !cfg.http_dir.empty()))
        srv.set_http_dir(cfg.http_dir);
    if (asked("http_cache", cfg.http_cache))
        srv.set_http_cache(cfg.http_cache);
    if (!cfg.master_pw.empty())
        srv.set_master_pw(cfg.master_pw);
    // A document that never names the list leaves it, since clearing it would end the server's upstream leg.
    if (!asked("upstreams", true))
        return true;
    srv.clear_upstream_targets();
    for (const auto& u : cfg.upstreams)
    {
        if (srv.add_upstream_target(u))
            continue;
        if (refusal)
        {
            *refusal = server_instance::upstream_refusal(u);
            return false;
        }
        LOG_WARN(("dropping upstream \"" + u + "\" of " + std::string(srv.get_name()) +
                  ": the port is not a number between 1 and 65535").c_str());
    }
    return true;
}

void apply_client_config(client_instance& cli, const runtime_config& cfg, bool by_presence)
{
    if (!by_presence || cfg.has("mode"))
        cli.set_mode(static_cast<client_mode>(cfg.mode));
    if (!by_presence || cfg.has("udp"))
        cli.set_udp(cfg.udp);
    // `>= 0`, not `!= 0`, because -1 is disabled and 0 is infinite attempts, the spelling `--reconnect` produces
    // without a number.
    if (by_presence ? cfg.has("reconnect") : cfg.reconnect >= 0)
        cli.set_reconnect(cfg.reconnect);
}

bool apply_typed_config(runtime_instance& rt, const runtime_config& cfg, bool by_presence, std::string* refusal)
{
    switch (rt.get_type())
    {
        case runtime_server:
            if (!apply_server_config(static_cast<server_instance&>(rt), cfg, by_presence, refusal))
                return false;
            break;
        case runtime_client:
            apply_client_config(static_cast<client_instance&>(rt), cfg, by_presence);
            break;
        case runtime_proxy:
            apply_proxy_config(static_cast<proxy_instance&>(rt), cfg, by_presence);
            break;

        case runtime_cache:
            apply_cache_config(static_cast<cache_instance&>(rt), cfg, by_presence);
            break;

        case runtime_storage:
            apply_storage_config(static_cast<storage_instance&>(rt), cfg, by_presence);
            break;

        case runtime_dns:
            apply_dns_config(static_cast<dns_instance&>(rt), cfg, by_presence);
            break;
        case runtime_sync:
            apply_sync_config(static_cast<sync_instance&>(rt), cfg, by_presence);
            break;
        case runtime_idp:
            apply_idp_config(static_cast<idp_instance&>(rt), cfg, by_presence);
            break;
        case runtime_db:
            apply_db_config(static_cast<db_instance&>(rt), cfg, by_presence);
            break;
        case runtime_mqtt:
            apply_mqtt_config(static_cast<mqtt_instance&>(rt), cfg, by_presence);
            break;
        case runtime_mail:
            apply_mail_config(static_cast<mail_instance&>(rt), cfg, by_presence);
            break;
    }

    // A no-op for the built-ins, and a registered type's fields must arrive however the config did; a document
    // that never names the object leaves it.
    if (!by_presence || cfg.has("extra"))
        rt.apply_config(cfg.extra);
    return true;
}
