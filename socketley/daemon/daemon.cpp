#include "daemon.h"
#include "daemon_handler.h"
#include "metrics_endpoint.h"
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
        uint64_t val = 1;
        if (write(g_signal_write_fd, &val, sizeof(val)) < 0) {}
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

    // Bounded like every other chunk in this process — see lua_deadline in
    // lua_context.h.  This one runs before the socket is bound and before a
    // single runtime exists, so a config file that does not return does not
    // freeze a serving daemon; it stops one from ever starting, and under a
    // service manager that is a start timeout and a restart loop with the log
    // line missing.  With the bound it is a named error and a daemon that comes
    // up on its defaults.
    //
    // The process default rather than a `callback_timeout_ms` of the config's
    // own: this file configures the daemon, not a runtime, and the variable
    // that would set it is read out of the same environment this is.
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
        return 0;
    }

    // Parse config table
    sol::optional<sol::table> config = lua["config"].get<sol::optional<sol::table>>();
    if (!config)
        return 0;

    // log_level
    sol::optional<std::string> ll = (*config)["log_level"].get<sol::optional<std::string>>();
    if (ll)
    {
        log_level level;
        if (parse_log_level(*ll, level))
            logger::g_level = level;
    }

    // metrics_port
    sol::optional<int> mp = (*config)["metrics_port"].get<sol::optional<int>>();
    if (mp && *mp > 0 && *mp <= 65535)
        metrics_port = static_cast<uint16_t>(*mp);

    return metrics_port;
}

// ─── ADOPTING WHAT AN UPGRADE WOULD OTHERWISE HAVE ORPHANED ─────────────────
//
// paths.cpp now keys the state directory to the socket path whenever that path
// is not the default one.  For every deployed daemon that changes nothing —
// they run on the default path and their directory is where it always was — but
// a daemon that has been running for months behind a fixed SOCKETLEY_SOCKET,
// with real runtimes behind it, would come up after the upgrade looking at a
// directory that has never existed.  Every runtime gone, no error, nothing to
// go and read.  That is not an acceptable way to ship a path change.
//
// So the first time a keyed directory is used, whatever was in the directory it
// used to share is copied into it.  Once.
//
// WHY COPY RATHER THAN READ THROUGH.  Reading the old directory whenever the
// new one is empty is the smaller change and it is worse in two ways.  It never
// ends: the daemon keeps reading the old directory every boot, so the two
// daemons sharing it keep seeing each other's runtimes for ever, which is the
// defect this is supposed to close.  And it ends abruptly when it does end —
// the first runtime created in the new directory makes it non-empty, and every
// legacy runtime disappears in that instant, triggered by an unrelated action.
// A copy has no cliff and leaves one directory to look at afterwards instead of
// two.  The originals are not touched, so an older binary rolled back onto this
// machine finds exactly what it has always found.
//
// EXACTLY ONCE, and marked on disk rather than inferred.  "The new directory is
// empty" is not a safe trigger on its own: an operator who removes every
// runtime empties it again, and the next restart would resurrect the very
// runtimes they had just deleted.  The marker also cannot be inferred from the
// directory not existing yet, because every CLI command resolves paths too and
// creates it — `SOCKETLEY_SOCKET=... socketley ps` would have consumed the one
// chance before the daemon it auto-starts ever looked.
//
// ─── AND ONLY WHEN NOBODY IS STILL USING THEM ───────────────────────────────
//
// Disk state cannot tell the upgrade apart from the disaster.  "Keyed directory
// empty, legacy directory populated" describes the daemon that has been running
// for months behind a fixed SOCKETLEY_SOCKET — adopt, that is the whole point —
// and it equally describes a brand new second daemon started beside a live one,
// where adopting means binding the running daemon's ports.
//
// Which is the arrangement an operator debugging next to production actually
// has, and it took one command to reach.  Measured, before this check, on a box
// whose default-path daemon was serving collide_a on :19781:
//
//     SOCKETLEY_SOCKET=$HOME/b.sock socketley ls
//
//     LISTEN 0 4096 0.0.0.0:19781 users:(("socketley",pid=458701,fd=6))
//     LISTEN 0 4096 0.0.0.0:19781 users:(("socketley",pid=458349,fd=6))
//
// Two daemons on one port, and the second holding a copy of the first's state
// file that `remove` would delete — which is the transcript this whole change
// exists to prevent, produced by the repair for it.
//
// The discriminator is not on disk, it is on the socket: whoever is serving the
// default path owns the legacy directory.  Anything other than `absent` there
// means those runtimes are in use, and nothing is adopted.  A short deadline is
// deliberate and safe in one direction only — a slow daemon degrades to `mute`,
// never to `absent`, because `absent` means connect() was refused — so the
// worst a busy box can do is decline an adoption it would have declined anyway.
//
// A DECLINE IS NOT A DECISION, so it does not write the marker.  A successful
// adoption is permanent because the question has been answered; "somebody else
// is using them right now" is a fact about this minute, and a daemon whose
// upgrade happened to coincide with a stray default-path daemon deserves to
// adopt on the next boot once that daemon is gone.  It says so, loudly, with
// both directories named, because the operator reading it is the one whose
// runtimes appear to have vanished.
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

    // Asked before the socket is, and answered permanently.  An empty legacy
    // directory is "nothing to adopt", full stop — not an error and not a
    // reason to come back later.  It is also the ordinary state of a box that
    // has only ever run keyed daemons, because resolve() creates the base
    // directory whether or not anything will use it, so an empty one it made
    // itself and an empty one a daemon emptied read the same and mean the same.
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
        // Loud, and naming both directories: to the operator this looks exactly
        // like the runtimes vanishing, and the log is the only place that can
        // say otherwise.  No marker — see the note above.
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

        // A proxy that was created out-of-process comes back out-of-process.
        // Before start(), which reads it to decide whether to arm anything.
        if (cfg.out_of_process)
            instance->mark_out_of_process();

        // What this runtime asked its I/O to run as.  Restored before start(),
        // which is where the request meets the ring: this daemon's ring was
        // created from the environment it was launched with, and there is no
        // reason that has to be the environment the request was accepted under.
        //
        // A set this machine no longer has is dropped with a warning rather
        // than refused: the alternative is a daemon that will not restore a
        // runtime because the box it was moved to has fewer cores, and the
        // request is a requirement about the ring, not about this runtime's
        // ability to exist.  Dropping it means start() checks nothing, which is
        // the same position a runtime that never asked is in.
        if (!cfg.cpus.empty())
        {
            cpu_set_spec spec;
            std::string err;
            if (parse_cpu_set(cfg.cpus, spec, err))
                instance->set_cpus(spec);
            else
                LOG_WARN("restore: this machine cannot satisfy a persisted --cpus set");
        }
        if (cfg.sqpoll_set)
            instance->set_sqpoll(cfg.sqpoll);

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

        // Common fields
        if (cfg.port > 0) instance->set_port(cfg.port);
        if (!cfg.log_file.empty()) instance->set_log_file(cfg.log_file);
        if (!cfg.write_file.empty()) instance->set_write_file(cfg.write_file);
        if (cfg.bash_output) instance->set_bash_output(true);
        if (cfg.bash_prefix) instance->set_bash_prefix(true);
        if (cfg.bash_timestamp) instance->set_bash_timestamp(true);
        if (cfg.max_connections > 0) instance->set_max_connections(cfg.max_connections);
        if (cfg.rate_limit > 0.0) instance->set_rate_limit(cfg.rate_limit);
        if (cfg.global_rate_limit > 0.0) instance->set_global_rate_limit(cfg.global_rate_limit);
        if (cfg.idle_timeout > 0) instance->set_idle_timeout(cfg.idle_timeout);
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
                for (const auto& u : cfg.upstreams)
                {
                    // The boot restore has nobody to refuse to — there is no
                    // command in flight and refusing the runtime outright would
                    // take a serving listener down over one bad entry in a file
                    // an older daemon wrote.  So it is logged and skipped, which
                    // is the same thing that used to happen without the log.
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
                // Shared with the proxy worker, which rebuilds a proxy from the
                // same runtime_config arriving over its control socket.  One
                // list, so the two cannot drift.
                apply_proxy_config(*prx, cfg);
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

        // Named, because the reason start() gives is printed by start() and a
        // daemon restoring several runtimes would otherwise report a refusal
        // with nothing to attach it to.  The runtime is left in `failed`, where
        // `ls` and `stats` show it — a restore that could not honour what a
        // runtime asked for must not read as a restore that worked.
        if (!manager.start(cfg.name, loop))
            LOG_WARN(("restore: could not start runtime " + cfg.name).c_str());
        else
            LOG_DEBUG("restored runtime");
    }
}

// The daemon's own command line: the ring policy, and nothing else yet.
//
// These are the process's settings rather than a runtime's, because a ring is
// fixed when it is created and the process creates one before it has read a
// single runtime's configuration.  Until now the only thing that could reach
// init() in time was the environment, so SOCKETLEY_SQPOLL and SOCKETLEY_CPUS
// were the whole interface — and `socketley daemon` dropped every argument it
// was handed without a word.  `socketley daemon --sqpoll` started a daemon
// with no poller and exited 0, which is the shape of trap this flag exists to
// avoid one level down: a setting accepted and not applied.
//
// The environment still works and still means the same thing; the supervisor
// forks workers with it and a worker has no command line of its own to carry
// it.  A flag beats it when both are given, because a flag is typed for this
// one run and an exported variable is usually not typed at all.
//
// Returns false when the command line cannot be honoured, having said why.
// Unknown arguments are refused rather than ignored: an argument the daemon
// does not understand is either a typo or a setting the operator believes is
// in effect, and both are worth an exit code.
static bool parse_daemon_flags(int argc, char** argv, event_loop& loop)
{
    // argv[0] is the binary and argv[1] is "daemon"; both are ours, not the
    // operator's.  A daemon started with no arguments at all takes this loop
    // once and decides nothing, which is what leaves the environment in charge.
    for (int i = 2; i < argc; ++i)
    {
        const std::string_view arg = argv[i];

        switch (fnv1a(arg))
        {
            case fnv1a("--sqpoll"):
                loop.set_sqpoll(true);
                break;

            case fnv1a("--no-sqpoll"):
                loop.set_sqpoll(false);
                break;

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
                    // The same refusal `create --cpus` gives, for the same
                    // reason: a set this machine cannot satisfy is never
                    // rounded up to "all", because a daemon running nowhere
                    // near where its operator believes makes every measurement
                    // taken afterwards a measurement of something else.
                    std::cout << "invalid --cpus value: " << err << "\n";
                    return false;
                }
                loop.set_cpus(cpus);
                break;
            }

            default:
                std::cout << "unknown daemon flag: " << arg << "\n"
                          << "  socketley daemon takes --sqpoll, --no-sqpoll and "
                             "--cpus <set>.\n"
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
    // Before anything else, including the "is one already running" check: a
    // command line the daemon cannot honour is worth an exit code whether or
    // not this process was going to be the one serving the socket.
    if (!parse_daemon_flags(argc, argv, loop))
        return 1;

    // Resolve paths (system vs dev mode)
    auto paths = socketley_paths::resolve();

    // Set socket path for daemon_handler and ipc_client
    daemon_handler::socket_path = paths.socket_path.string();

    // ...and whether that path is the packaged deployment's, which is what
    // decides who may open the socket.  Only here: the CLI resolves paths too,
    // but the CLI never calls setup() and a value it set would be read by
    // nothing.  See the block in daemon_handler::setup().
    //
    // system_mode ALONE is not the question, though it is the obvious spelling
    // of this line.  It is decided in paths.cpp from the uid and from whether
    // socketley is installed, and it is decided BEFORE SOCKETLEY_SOCKET moves
    // the socket —
    // so root on a machine with the package installed carries system_mode into
    // a daemon whose socket is a mktemp path in /tmp, and that socket would
    // then be handed to the `socketley` group.  A test daemon, or any second
    // daemon, opened to a group nobody meant to invite.
    //
    // default_socket_path is the path this namespace resolves to with the
    // variable out of the picture — the one the deployed daemon binds — so the
    // two together say "this daemon is the packaged daemon" and nothing less.
    // Compared as written rather than canonicalised: a deployment that spells
    // the default path unusually falls to the owner-only side, which is the
    // safe direction, and no deployment sets the variable at all.
    daemon_handler::system_socket =
        paths.system_mode && paths.socket_path == paths.default_socket_path;

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

    // Give the cross-runtime request channel its ring.  Until this happens it
    // refuses every request, so it has to come before any runtime is restored
    // — a server with --cache posts on its first message, and the first message
    // can arrive inside restore.  See shared/request_channel.h.
    manager.requests().attach(loop);

    // Which directory this daemon's runtimes live in, said out loud, once, at
    // startup.  "Where does my state live" is a question an operator asks
    // exactly once and at the worst possible moment, and the daemon log is
    // where they are already looking when they ask it.  Under the rule in
    // paths.cpp the answer depends on the socket path, so it cannot be a
    // constant in the man page any more — it has to come from the process.
    LOG_INFO(("state directory: " + paths.state_dir.string()).c_str());

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

    // Still with a live ring: every teardown cancels the operations hanging off
    // its descriptors and withdraws its own timers, and all of that is
    // submitted.  run() used to end the ring on its way out, so the first
    // runtime this stopped submitted into an unmapped submission queue — a
    // segfault on every SIGTERM that found a runtime still running.
    manager.stop_all(loop);

    // Still with a live ring, and after stop_all so that nothing can post
    // again: every request the channel is still carrying is answered `dropped`
    // and its owner registration goes back.  A request left queued here is an
    // origin waiting on a reply that the ring, about to be unmapped, can no
    // longer produce a wakeup for.
    manager.requests().detach();

    // Nothing more will be submitted, so the ring can go — and it has to go
    // before anything is freed, because until it does the kernel may still be
    // writing into the read buffers of connections a retired instance is
    // holding on to.  With it gone, no completion can reference a retired
    // runtime's storage, which makes this the one point we can prove is safe to
    // free the instances that removal deliberately kept alive.
    loop.shutdown_ring();

    manager.free_retired();

    handler.teardown();

    g_signal_write_fd = -1;

    LOG_INFO("daemon stopped");

    return 0;
}
