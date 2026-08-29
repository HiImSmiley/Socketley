#include "daemon.h"
#include "daemon_handler.h"
#include "metrics_endpoint.h"
#include "type_manifest.h"
#include "../shared/event_loop.h"
#include "../shared/runtime_manager.h"
#include "../shared/logging.h"
#include "../shared/paths.h"
#include "../shared/daemon_client.h"
#include "../shared/state_persistence.h"
#include "../shared/runtime_config_apply.h"
#include "../shared/lua_context.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../cli/command_hashing.h"
#include "../runtime/worker/worker_main.h"

#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#ifndef SOCKETLEY_NO_LUA
#include <sol/sol.hpp>
#endif

static int g_signal_write_fd = -1;

static void signal_handler(int)
{
    if (g_signal_write_fd >= 0)
    {
        uint64_t val = 1;
        if (write(g_signal_write_fd, &val, sizeof(val)) < 0) {}
    }
}

// Everything a daemon configuration file can say, read in one pass and
// applied in three places, because the ring settings have to reach the loop
// before init() while the identity needs a handler that is already serving.
struct daemon_config
{
    uint16_t    metrics_port = 0;
    std::string name;
    std::string cluster;
    std::string cpus;
};

static daemon_config load_daemon_config(const std::string& config_path)
{
    daemon_config out;
    std::string path = config_path;

    // Check SOCKETLEY_CONFIG env var first
    const char* env = std::getenv("SOCKETLEY_CONFIG");
    if (env && env[0])
        path = env;

    if (path.empty())
        return out;

    // Check if file exists
    std::ifstream check(path);
    if (!check.good())
        return out;
    check.close();

#ifdef SOCKETLEY_NO_LUA
    // A build without an interpreter has nothing to run config.lua with, said
    // once rather than failing on each key.
    std::cerr << "[config] " << path << " ignored: built without Lua\n";
    return out;
#else
    sol::state lua;

    // The same set `socketley --lua` opens, so one file can be read by either
    // and os and io stay shut in both.
    lua.open_libraries(sol::lib::base, sol::lib::package, sol::lib::table,
                       sol::lib::string, sol::lib::math);

    // Bounded like every other chunk in this process, against the process
    // default rather than a `callback_timeout_ms` of the config's own, because
    // this file configures the daemon and not a runtime.
    auto result = [&] {
        lua_deadline::install(lua.lua_state(), lua_deadline::default_ms());
        lua_deadline::scope guard("the daemon configuration file",
                                  lua_deadline::default_ms());
        return lua.safe_script_file(path, sol::script_pass_on_error);
    }();
    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "[config] error loading " << path << ": " << err.what() << "\n";
        return out;
    }

    // `daemon` is the table `socketley --lua` already reads and the one this
    // file is documented under; `config` is the spelling that shipped first
    // and still works, with both at once refused rather than merged because
    // two tables setting one field is a file nobody can read.
    sol::optional<sol::table> daemon = lua["daemon"].get<sol::optional<sol::table>>();
    sol::optional<sol::table> config = lua["config"].get<sol::optional<sol::table>>();

    if (daemon && config)
    {
        std::cerr << "[config] " << path << " has both a `daemon` and a `config` "
                     "table: they are two spellings of one thing, so name it once\n";
        return out;
    }

    sol::optional<sol::table>& table = daemon ? daemon : config;
    if (!table)
        return out;

    sol::optional<std::string> ll = (*table)["log_level"].get<sol::optional<std::string>>();
    if (ll)
    {
        log_level level;
        if (log_level_from_string(ll->c_str(), level))
            logger::g_level = level;
    }

    sol::optional<int> mp = (*table)["metrics_port"].get<sol::optional<int>>();
    if (mp && *mp > 0 && *mp <= 65535)
        out.metrics_port = static_cast<uint16_t>(*mp);

    sol::optional<std::string> name = (*table)["name"].get<sol::optional<std::string>>();
    if (name && !name->empty())
        out.name = *name;

    sol::optional<std::string> cluster = (*table)["cluster"].get<sol::optional<std::string>>();
    if (cluster && !cluster->empty())
        out.cluster = *cluster;

    sol::optional<std::string> cpus = (*table)["cpus"].get<sol::optional<std::string>>();
    if (cpus && !cpus->empty())
        out.cpus = *cpus;

    return out;
#endif
}

// The first time a keyed state directory is used, whatever was in the
// directory it used to share is copied into it once -- marked on disk rather
// than inferred, and only when nobody is serving the default socket, because
// "keyed empty, legacy populated" equally describes a second daemon started
// beside a live one.
static void adopt_legacy_state(const socketley_paths& paths)
{
    namespace fs = std::filesystem;

    if (paths.legacy_state_dir.empty() || paths.state_dir.empty())
        return;   // this daemon is on the default path; nothing ever moved

    const fs::path marker = paths.state_dir / ".adopted";

    std::error_code ec;
    if (fs::exists(marker, ec))
        return;

    auto count_json = [](const fs::path& dir) {
        size_t n = 0;
        std::error_code lec;
        for (const auto& e : fs::directory_iterator(dir, lec))
        {
            if (e.is_regular_file() && e.path().extension() == ".json")
                ++n;
        }
        return n;   // a directory that does not exist iterates zero times
    };

    auto write_marker = [&](const std::string& body) {
        std::ofstream f(marker, std::ios::trunc);
        if (!f.is_open())
            return;
        f << "# socketley state directory for the daemon on socket\n"
          << "#   " << paths.socket_path.string() << "\n"
          << "#\n"
          << body
          << "#\n"
          << "# This file is what makes that a one-time event.  Delete it and the\n"
          << "# next restart will ask again, which is rarely what you want.\n";
    };

    // Never adopt into a directory that already holds runtimes: those are this
    // daemon's own, and a copy over the top of them would be resurrecting
    // something under a name that is already in use.
    const size_t existing = count_json(paths.state_dir);
    if (existing > 0)
    {
        write_marker("# Nothing was adopted: this directory already held " +
                     std::to_string(existing) + " runtime(s).\n");
        return;
    }

    // An empty legacy directory is nothing to adopt, full stop, which is also
    // the ordinary state of a box that has only ever run keyed daemons.
    const size_t available = count_json(paths.legacy_state_dir);
    if (available == 0)
    {
        write_marker("# Nothing was adopted: " + paths.legacy_state_dir.string() +
                     "\n# held no runtimes at this daemon's first start.\n");
        return;
    }

    const std::string dsock = paths.default_socket_path.string();
    const socketley::daemon_identity owner =
        socketley::daemon_probe(dsock.c_str(), nullptr, 1000);

    if (owner != socketley::daemon_identity::absent)
    {
        // Loud and naming both directories, because to the operator this looks
        // exactly like the runtimes vanishing, and no marker is written.
        LOG_WARN(("state: NOT adopting " + std::to_string(available) +
                  " runtime(s) from " + paths.legacy_state_dir.string() +
                  " into " + paths.state_dir.string() +
                  " — a daemon is serving " + dsock +
                  " and those runtimes belong to it").c_str());
        LOG_WARN(("state: this daemon starts with no runtimes.  They are not lost: "
                  "stop the daemon on " + dsock +
                  " and restart this one to adopt them, or copy the .json files "
                  "across by hand.  Adopting them now would bind ports that "
                  "daemon is already serving.").c_str());
        return;
    }

    size_t copied = 0, failed = 0;
    for (const auto& e : fs::directory_iterator(paths.legacy_state_dir, ec))
    {
        if (!e.is_regular_file() || e.path().extension() != ".json")
            continue;
        std::error_code cec;
        if (fs::copy_file(e.path(), paths.state_dir / e.path().filename(),
                          fs::copy_options::skip_existing, cec))
            ++copied;
        else
            ++failed;
    }

    write_marker("# " + std::to_string(copied) +
                 " runtime(s) were copied here at first start from\n#   " +
                 paths.legacy_state_dir.string() +
                 "\n# which is the directory a daemon on the default socket path uses,\n"
                 "# and which this daemon shared with it before its state directory\n"
                 "# was keyed to its socket.  Nothing was serving " + dsock +
                 " at the\n# time, so those runtimes were unowned.  The originals were left"
                 " in place.\n");

    if (copied > 0)
    {
        LOG_INFO(("state: adopted " + std::to_string(copied) +
                  " runtime(s) from " + paths.legacy_state_dir.string() +
                  " into " + paths.state_dir.string() +
                  " (nothing was serving " + dsock + ")").c_str());
    }
    if (failed > 0)
    {
        LOG_WARN(("state: " + std::to_string(failed) + " runtime(s) in " +
                  paths.legacy_state_dir.string() +
                  " could not be copied and will not be restored").c_str());
    }
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
        // Skipped rather than repaired, because str_to_type falls back to
        // runtime_server and restoring a registered type whose manifest is
        // gone would bind a server on its port.
        if (!cfg.type_name.empty() && cfg.type_name != type_to_string(cfg.type))
        {
            LOG_WARN(("restore: " + cfg.name + " has type \"" + cfg.type_name +
                      "\", which no manifest declares; not restored").c_str());
            continue;
        }

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

        // Every runtime this daemon supervises comes back behind a worker
        // whatever the state file says, because honouring `"out_of_process":
        // false` would restore an arrangement this build cannot create or
        // test.
        // An external runtime is the exception, and the mark declines rather
        // than this line testing for it, because the file is read here in no
        // particular order.
        instance->mark_out_of_process();

        // What this runtime asked its I/O to run as, restored before start(),
        // with a set this machine no longer has dropped with a warning rather
        // than refused.
        if (!cfg.cpus.empty())
        {
            cpu_set_spec spec;
            std::string err;
            if (parse_cpu_set(cfg.cpus, spec, err))
                instance->set_cpus(spec);
            else
                LOG_WARN("restore: this machine cannot satisfy a persisted --cpus set");
        }

        // External (attached) runtimes: mark as external so start() skips io_uring setup
        if (cfg.external_runtime)
        {
            if (cfg.managed && !cfg.exec_path.empty())
                instance->mark_managed(cfg.exec_path);
            else
                instance->mark_external();
            if (cfg.pid > 0)
                instance->set_pid(static_cast<pid_t>(cfg.pid));
        }

        // The common fields from the one list, because the second copy that
        // stood here had drifted -- `shards` was missing, so a four-shard
        // proxy came back with one worker and `show` stopped reporting the
        // field.
        apply_common_config(*instance, cfg);

        // Not part of the common list because it belongs to a client, and this
        // restore still has its own typed switch below.
        if (cfg.reconnect >= 0) instance->set_reconnect(cfg.reconnect);

        if (!cfg.lua_script.empty())
        {
            if (!instance->load_lua_script(cfg.lua_script))
                LOG_WARN("restore: could not load lua script");
        }

        // Type-specific, and still a second copy knowingly, because
        // apply_typed_config touches nothing that needs a runtime_manager and
        // three of these four cases wire exactly that.
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
                for (const auto& u : cfg.upstreams)
                {
                    // The boot restore has nobody to refuse to, so a bad entry
                    // is logged and skipped rather than taking a serving
                    // listener down.
                    if (!srv->add_upstream_target(u))
                        LOG_WARN(("restore: dropping upstream \"" + u +
                                  "\" of " + cfg.name +
                                  ": the port is not a number between 1 and 65535").c_str());
                }
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
                // Shared with the proxy worker, which rebuilds a proxy from
                // the same runtime_config, so the two cannot drift.
                apply_proxy_config(*prx, cfg);
                break;
            }
            case runtime_cache:
            {
                auto* cache = static_cast<cache_instance*>(instance);
                if (!cfg.persistent_path.empty()) cache->set_persistent(cfg.persistent_path);
                cache->set_mode(static_cast<cache_mode>(cfg.cache_mode));
                if (cfg.resp_forced) cache->set_resp_forced(true);
                if (cfg.cluster) cache->set_cluster(true);
                if (!cfg.replicate_target.empty()) cache->set_replicate_target(cfg.replicate_target);
                if (cfg.max_memory > 0) cache->set_max_memory(cfg.max_memory);
                cache->set_eviction(static_cast<eviction_policy>(cfg.eviction));
                break;
            }
        }

        // A registered type's fields, applied through the placeholder's bag.
        instance->apply_extra(cfg.extra);
    }

    // Pass 2: Start runtimes that were running
    for (const auto& cfg : configs)
    {
        if (!cfg.was_running)
            continue;

        // Named, because a daemon restoring several runtimes would otherwise
        // report a refusal with nothing to attach it to, and the runtime is
        // left `failed` where `ls` shows it.
        if (!manager.start(cfg.name, loop))
            LOG_WARN(("restore: could not start runtime " + cfg.name).c_str());
        else
            LOG_DEBUG("restored runtime");
    }
}

// The daemon's own command line, which is the ring policy and nothing else
// yet, because a ring is fixed at creation and only the environment could
// reach init() in time -- and unknown arguments are refused rather than
// ignored.
static bool parse_daemon_flags(int argc, char** argv, event_loop& loop,
                               bool& saw_cpus)
{
    // argv[0] is the binary and argv[1] is "daemon", so a daemon started with
    // no arguments decides nothing and leaves the environment in charge.
    for (int i = 2; i < argc; ++i)
    {
        const std::string_view arg = argv[i];

        switch (fnv1a(arg))
        {
            case fnv1a("--cpus"):
            {
                if (i + 1 >= argc)
                {
                    std::cout << "--cpus requires a CPU set: max | 0-3 | 0,1,2,3\n";
                    return false;
                }
                cpu_set_spec cpus;
                std::string err;
                if (!parse_cpu_set(argv[++i], cpus, err))
                {
                    // The same refusal `create --cpus` gives, because a daemon
                    // running nowhere near where its operator believes makes
                    // every later measurement a measurement of something else.
                    std::cout << "invalid --cpus value: " << err << "\n";
                    return false;
                }
                loop.set_cpus(cpus);
                saw_cpus = true;
                break;
            }

            default:
                std::cout << "unknown daemon flag: " << arg << "\n"
                          << "  socketley daemon takes --cpus <set>.\n"
                          << "  Runtime flags belong on `create`; this command "
                             "configures the process's ring.\n";
                return false;
        }
    }

    return true;
}

int daemon_start(runtime_manager& manager, event_loop& loop,
                 int argc, char** argv)
{
    // The supervisor forks and execs this binary with `proxy-worker` to serve
    // each runtime, so dispatching it here rather than at each caller is what
    // lets an SDK daemon start a runtime at all.
    if (argc > 1 && argv[1] && std::string_view(argv[1]) == "proxy-worker")
        return worker_main(3);

    // Before anything else, including the "is one already running" check: a
    // command line the daemon cannot honour is worth an exit code whether or
    // not this process was going to be the one serving the socket.
    bool saw_cpus = false;
    if (!parse_daemon_flags(argc, argv, loop, saw_cpus))
        return 1;

    // Resolve paths (system vs dev mode)
    auto paths = socketley_paths::resolve();

    // Set socket path for daemon_handler and ipc_client
    daemon_handler::socket_path = paths.socket_path.string();

    // Whether this daemon is the packaged one, decided from system_mode and
    // the default socket path together, because system_mode alone is settled
    // before SOCKETLEY_SOCKET moves the socket and would open a temp-path
    // daemon to the `socketley` group.
    daemon_handler::system_socket =
        paths.system_mode && paths.socket_path == paths.default_socket_path;

    // Load config file (sets log level, metrics port, etc.) before anything else
    const daemon_config config = load_daemon_config(paths.config_path.string());
    const uint16_t metrics_port = config.metrics_port;

    // The ring setting reaches the loop here because init() is a few lines
    // down, and only where the command line said nothing: a flag typed at the
    // daemon outranks a file it did not read.
    if (!config.cpus.empty() && !saw_cpus)
    {
        cpu_set_spec cpus;
        std::string err;
        if (parse_cpu_set(config.cpus, cpus, err))
            loop.set_cpus(cpus);
        else
            std::cerr << "[config] invalid cpus value: " << err << "\n";
    }

    // And on to whatever this daemon forks, exported unconditionally in the
    // parent at startup, because a worker reads no configuration file and a
    // setenv between the fork and the exec would allocate in a child that must
    // not.
    export_log_level(logger::g_level);

    // If another daemon is already running on this socket, exit gracefully
    if (daemon_handler::is_running())
        return 0;

    if (!loop.init())
    {
        LOG_ERROR("failed to init event loop");
        return 1;
    }

    // Give the cross-runtime request channel its ring before any runtime is
    // restored, because a server with --cache posts on its first message and
    // that message can arrive inside restore.
    manager.requests().attach(loop);

    // Which directory this daemon's runtimes live in, said once at startup,
    // because the answer now depends on the socket path and cannot be a
    // constant in the man page.
    LOG_INFO(("state directory: " + paths.state_dir.string()).c_str());

    // Registered types before the state files that may name them, because
    // restore refuses a type name nothing has declared.
    if (const size_t n = type_manifest::load_dir(paths.types_dir); n > 0)
        LOG_INFO(("registered " + std::to_string(n) + " runtime type(s) from " +
                  paths.types_dir.string()).c_str());

    // Before load_all(): an upgrade that keys this daemon's state directory to
    // its socket for the first time takes what it used to share with the
    // default-path daemon along with it.
    adopt_legacy_state(paths);

    // Create state persistence
    state_persistence persistence(paths.state_dir.string());

    daemon_handler handler(manager, loop);
    handler.set_state_persistence(&persistence);

    if (!handler.setup())
    {
        LOG_ERROR("failed to setup ipc socket");
        return 1;
    }

    // After setup and before any runtime is restored, because a restored
    // runtime publishes into the cluster this names -- and reported rather
    // than fatal, since a daemon that cannot join is still a daemon that
    // serves its own socket.
    if (!config.name.empty() || !config.cluster.empty())
    {
        if (const std::string why =
                handler.apply_startup_identity(config.name, config.cluster);
            !why.empty())
            std::cerr << "[config] " << why;
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
    handler.set_metrics_port(metrics_port);

    // Restore persisted runtimes before entering the event loop
    restore_runtimes(persistence, manager, loop);

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

    // Still with a live ring, because every teardown submits, and run() ending
    // the ring on its way out was a segfault on every SIGTERM that found a
    // runtime running.
    manager.stop_all(loop);

    // Still with a live ring and after stop_all so nothing can post again,
    // because a request left queued is an origin waiting on a wakeup the
    // unmapped ring can no longer produce.
    manager.requests().detach();

    // Nothing more will be submitted, so the ring goes before anything is
    // freed, which is the one point we can prove is safe to release the
    // instances removal kept alive.
    loop.shutdown_ring();

    manager.free_retired();

    handler.teardown();

    g_signal_write_fd = -1;

    LOG_INFO("daemon stopped");

    return 0;
}
