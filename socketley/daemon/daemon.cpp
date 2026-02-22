#include "daemon.h"
#include "daemon_handler.h"
#include "metrics_endpoint.h"
#include "../shared/event_loop.h"
#include "../shared/runtime_manager.h"
#include "../shared/cluster_discovery.h"
#include "../shared/logging.h"
#include "../shared/paths.h"
#include "../shared/state_persistence.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../cli/command_hashing.h"

#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <sol/sol.hpp>

static int g_signal_write_fd = -1;

static void signal_handler(int)
{
    if (g_signal_write_fd >= 0)
    {
        char c = 1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
        write(g_signal_write_fd, &c, 1);
#pragma GCC diagnostic pop
    }
}

static bool parse_log_level(std::string_view str, log_level& level)
{
    switch (fnv1a(str))
    {
        case fnv1a("debug"): level = log_debug; return true;
        case fnv1a("info"):  level = log_info;  return true;
        case fnv1a("warn"):  level = log_warn;  return true;
        case fnv1a("error"): level = log_error; return true;
        default: return false;
    }
}

static uint16_t load_daemon_config(const std::string& config_path)
{
    uint16_t metrics_port = 0;
    std::string path = config_path;

    // Check SOCKETLEY_CONFIG env var first
    const char* env = std::getenv("SOCKETLEY_CONFIG");
    if (env && env[0])
        path = env;

    if (path.empty())
        return 0;

    // Check if file exists
    std::ifstream check(path);
    if (!check.good())
        return 0;
    check.close();

    sol::state lua;
    lua.open_libraries(sol::lib::base, sol::lib::string);

    auto result = lua.safe_script_file(path, sol::script_pass_on_error);
    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "[config] error loading " << path << ": " << err.what() << "\n";
        return 0;
    }

    // Parse config table
    sol::optional<sol::table> config = lua["config"];
    if (!config)
        return 0;

    // log_level
    sol::optional<std::string> ll = (*config)["log_level"];
    if (ll)
    {
        log_level level;
        if (parse_log_level(*ll, level))
            logger::g_level = level;
    }

    // metrics_port
    sol::optional<int> mp = (*config)["metrics_port"];
    if (mp && *mp > 0 && *mp <= 65535)
        metrics_port = static_cast<uint16_t>(*mp);

    return metrics_port;
}

static void restore_runtimes(state_persistence& persistence,
                              runtime_manager& manager, event_loop& loop)
{
    auto configs = persistence.load_all();
    if (configs.empty())
        return;

    LOG_INFO("restoring runtimes from state");

    // Pass 1: Create all runtimes and apply configs
    for (const auto& cfg : configs)
    {
        if (!manager.create(cfg.type, cfg.name))
        {
            LOG_WARN("restore: could not create runtime (already exists?)");
            continue;
        }

        auto* instance = manager.get(cfg.name);
        if (!instance)
            continue;

        // Restore persisted ID
        instance->set_id(cfg.id);

        // Always set runtime manager and event loop
        instance->set_runtime_manager(&manager);
        instance->set_event_loop(&loop);

        // Restore group
        if (!cfg.group.empty())
            instance->set_group(cfg.group);

        // Restore ownership
        if (!cfg.owner.empty())
            instance->set_owner(cfg.owner);
        instance->set_child_policy(
            cfg.child_policy == 1 ? runtime_instance::child_policy::remove
                                  : runtime_instance::child_policy::stop);

        // External (attached) runtimes: mark as external so start() skips io_uring setup
        if (cfg.external_runtime)
        {
            instance->mark_external();
            if (cfg.pid > 0)
                instance->set_pid(static_cast<pid_t>(cfg.pid));
        }

        // Common fields
        if (cfg.port > 0) instance->set_port(cfg.port);
        if (!cfg.log_file.empty()) instance->set_log_file(cfg.log_file);
        if (!cfg.write_file.empty()) instance->set_write_file(cfg.write_file);
        if (cfg.bash_output) instance->set_bash_output(true);
        if (cfg.bash_prefix) instance->set_bash_prefix(true);
        if (cfg.bash_timestamp) instance->set_bash_timestamp(true);
        if (cfg.max_connections > 0) instance->set_max_connections(cfg.max_connections);
        if (cfg.rate_limit > 0.0) instance->set_rate_limit(cfg.rate_limit);
        if (cfg.drain) instance->set_drain(true);
        if (cfg.reconnect >= 0) instance->set_reconnect(cfg.reconnect);
        if (cfg.tls) instance->set_tls(true);
        if (!cfg.cert_path.empty()) instance->set_cert_path(cfg.cert_path);
        if (!cfg.key_path.empty()) instance->set_key_path(cfg.key_path);
        if (!cfg.ca_path.empty()) instance->set_ca_path(cfg.ca_path);
        if (!cfg.target.empty()) instance->set_target(cfg.target);
        if (!cfg.cache_name.empty()) instance->set_cache_name(cfg.cache_name);

        if (!cfg.lua_script.empty())
        {
            if (!instance->load_lua_script(cfg.lua_script))
                LOG_WARN("restore: could not load lua script");
        }

        // Type-specific
        switch (cfg.type)
        {
            case runtime_server:
            {
                auto* srv = static_cast<server_instance*>(instance);
                srv->set_mode(static_cast<server_mode>(cfg.mode));
                if (cfg.udp) srv->set_udp(true);
                if (!cfg.cache_name.empty())
                    srv->set_runtime_manager(&manager);
                if (!cfg.master_pw.empty())
                    srv->set_master_pw(cfg.master_pw);
                if (cfg.master_forward)
                    srv->set_master_forward(true);
                if (!cfg.http_dir.empty())
                    srv->set_http_dir(cfg.http_dir);
                if (cfg.http_cache)
                    srv->set_http_cache(true);
                break;
            }
            case runtime_client:
            {
                auto* cli = static_cast<client_instance*>(instance);
                cli->set_mode(static_cast<client_mode>(cfg.mode));
                if (cfg.udp) cli->set_udp(true);
                break;
            }
            case runtime_proxy:
            {
                auto* prx = static_cast<proxy_instance*>(instance);
                prx->set_runtime_manager(&manager);
                prx->set_protocol(static_cast<proxy_protocol>(cfg.protocol));
                prx->set_strategy(static_cast<proxy_strategy>(cfg.strategy));
                for (const auto& b : cfg.backends)
                    prx->add_backend(b);
                break;
            }
            case runtime_cache:
            {
                auto* cache = static_cast<cache_instance*>(instance);
                if (!cfg.persistent_path.empty()) cache->set_persistent(cfg.persistent_path);
                cache->set_mode(static_cast<cache_mode>(cfg.cache_mode));
                if (cfg.resp_forced) cache->set_resp_forced(true);
                if (!cfg.replicate_target.empty()) cache->set_replicate_target(cfg.replicate_target);
                if (cfg.max_memory > 0) cache->set_max_memory(cfg.max_memory);
                cache->set_eviction(static_cast<eviction_policy>(cfg.eviction));
                break;
            }
        }
    }

    // Pass 2: Start runtimes that were running
    for (const auto& cfg : configs)
    {
        if (!cfg.was_running)
            continue;

        if (!manager.run(cfg.name, loop))
            LOG_WARN("restore: could not start runtime");
        else
            LOG_DEBUG("restored runtime");
    }
}

int daemon_start(runtime_manager& manager, event_loop& loop,
                 int argc, char** argv)
{
    // Resolve paths (system vs dev mode)
    auto paths = socketley_paths::resolve();

    // Set socket path for daemon_handler and ipc_client
    daemon_handler::socket_path = paths.socket_path.string();

    // Parse daemon-specific flags: --name, --cluster, --cluster-addr
    std::string daemon_name;
    std::string cluster_dir;
    std::string cluster_addr;

    for (int i = 2; i < argc; ++i)
    {
        std::string_view arg = argv[i];
        if ((arg == "--name" || arg == "-n") && i + 1 < argc)
            daemon_name = argv[++i];
        else if (arg == "--cluster" && i + 1 < argc)
            cluster_dir = argv[++i];
        else if (arg == "--cluster-addr" && i + 1 < argc)
            cluster_addr = argv[++i];
    }

    // Load config file (sets log level, metrics port, etc.) before anything else
    uint16_t metrics_port = load_daemon_config(paths.config_path.string());

    // If another daemon is already running on this socket, exit gracefully
    if (daemon_handler::is_running())
        return 0;

    if (!loop.init())
    {
        LOG_ERROR("failed to init event loop");
        return 1;
    }

    // Create state persistence
    state_persistence persistence(paths.state_dir.string());

    daemon_handler handler(manager, loop);
    handler.set_state_persistence(&persistence);

    if (!handler.setup())
    {
        LOG_ERROR("failed to setup ipc socket");
        return 1;
    }

    // Create cluster discovery if --cluster is specified
    std::unique_ptr<cluster_discovery> cluster;
    if (!cluster_dir.empty())
    {
        if (daemon_name.empty())
        {
            LOG_ERROR("--cluster requires --name");
            handler.teardown();
            return 1;
        }

        cluster = std::make_unique<cluster_discovery>(
            daemon_name, cluster_dir, cluster_addr, manager);
        manager.set_cluster_discovery(cluster.get());
        handler.set_cluster_discovery(cluster.get());
    }

    // Start metrics endpoint if configured
    metrics_endpoint metrics(manager);
    if (metrics_port > 0)
    {
        if (metrics.start(metrics_port))
            LOG_INFO("metrics endpoint started");
        else
            LOG_WARN("failed to start metrics endpoint");
    }

    // Restore persisted runtimes before entering the event loop
    restore_runtimes(persistence, manager, loop);

    // Start cluster discovery timer AFTER restoring runtimes so the first
    // publish includes all restored runtimes
    if (cluster)
    {
        cluster->set_event_callback([&manager](const std::vector<cluster_event>& events) {
            manager.dispatch_cluster_events(events);
        });

        if (!cluster->start(loop))
        {
            handler.teardown();
            return 1;
        }
        LOG_INFO("cluster discovery started");
    }

    g_signal_write_fd = loop.get_signal_write_fd();

    // Ignore SIGPIPE — broken pipe errors are handled via io_uring CQE results (-EPIPE)
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);

    LOG_INFO("daemon started");

    loop.run();

    // Shutdown cluster discovery before stopping runtimes
    if (cluster)
        cluster->stop();

    manager.stop_all(loop);
    handler.teardown();

    g_signal_write_fd = -1;

    LOG_INFO("daemon stopped");

    return 0;
}
