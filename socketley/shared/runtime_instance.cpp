#include "runtime_instance.h"
#include "logging.h"
#include "tls_context.h"
#include "blocking_write.h"
#include "event_loop.h"
#include "lua_context.h"
#include "id_generator.h"
#include "runtime_manager.h"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <sys/uio.h>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sys/wait.h>

runtime_instance::runtime_instance(runtime_type type, std::string_view name)
    : m_name(name), m_id(generate_runtime_id()), m_type(type), m_state(runtime_created),
      m_created_time(std::chrono::system_clock::now())
{
    // So an unwritable path is reported as the flag the operator typed rather
    // than as a path with no provenance.
    m_write_out.set_label("-w");
    m_state_log.set_label("--log");
}

runtime_instance::~runtime_instance() = default;

void runtime_instance::tick_handler::on_cqe(struct io_uring_cqe* cqe)
{
    if (!rt)
    {
        if (loop) loop->deregister_owner(this);
        delete this;
        return;
    }
    rt->fire_tick(cqe->res);
}

// Nothing re-arms this chain but its own completion, so a refused submission
// ends on_tick for this runtime for good and leaks the handler, and both are
// now said out loud.
void runtime_instance::start_tick_timer()
{
    uint32_t ms = m_cb_tick_ms > 0 ? m_cb_tick_ms
                : (m_lua ? m_lua->get_tick_ms() : lua_tick::default_ms);
    if (ms < lua_tick::floor_ms) ms = lua_tick::floor_ms;
    m_tick = new tick_handler();
    m_tick->rt = this;
    m_tick->loop = m_event_loop;
    m_tick->req = { m_tick, nullptr, -1, 0, op_timeout };
    m_tick->ts = { static_cast<long long>(ms / 1000),
                   static_cast<long long>((ms % 1000) * 1000000LL) };
    m_tick->last = std::chrono::steady_clock::now();
    if (!m_event_loop->submit_timeout(&m_tick->ts, &m_tick->req))
    {
        LOG_ERROR("runtime tick timer refused: on_tick will not run again for "
                  "this runtime");
        // Nothing will complete for it, so this is the only place that can
        // free it, deregistering exactly as on_cqe's own teardown does because
        // arm() claims the slot before it prepares the SQE.
        tick_handler* dead = m_tick;
        m_tick = nullptr;
        m_event_loop->deregister_owner(dead);
        delete dead;
    }
}

void runtime_instance::fire_tick(int res)
{
    if (res == -ECANCELED || !m_tick) return;
    auto now = std::chrono::steady_clock::now();
    double dt = std::chrono::duration<double, std::milli>(now - m_tick->last).count();
    m_tick->last = now;
    if (m_cb_on_tick) {
        m_cb_on_tick(dt);
    } else if (m_lua && m_lua->has_on_tick()) {
#ifndef SOCKETLEY_NO_LUA
        sol::protected_function_result r = m_lua->on_tick()(dt);
        if (SOCKETLEY_UNLIKELY(!r.valid()))
        {
            sol::error e = r;
            std::cerr << lua_diag::tag(get_name()) << " on_tick error: " << e.what() << "\n";
        }
#endif
    }
    if (!m_tick || !m_event_loop) return;
    uint32_t ms = m_cb_tick_ms > 0 ? m_cb_tick_ms
                : (m_lua ? m_lua->get_tick_ms() : lua_tick::default_ms);
    if (ms < lua_tick::floor_ms) ms = lua_tick::floor_ms;
    m_tick->ts = { static_cast<long long>(ms / 1000),
                   static_cast<long long>((ms % 1000) * 1000000LL) };

    // The re-arm, on the same reasoning as the first: this completion is the
    // last thing that will name this handler unless the submission takes.
    if (!m_event_loop->submit_timeout(&m_tick->ts, &m_tick->req))
    {
        LOG_ERROR("runtime tick timer could not be re-armed: on_tick will not "
                  "run again for this runtime");
        tick_handler* dead = m_tick;
        m_tick = nullptr;
        delete dead;
    }
}

bool runtime_instance::start(event_loop& loop)
{
    runtime_state current = m_state.load(std::memory_order_acquire);

    // `failed` is an entry state and not a grave: a worker that could not bind
    // leaves the runtime here, and refusing to start it again made every such
    // runtime dead until remove + create -- with `start` answering "failed to
    // start" and no line anywhere saying why.  The daemon retires the dead
    // workers of a runtime it is starting out of `failed`, in
    // reconcile_proxy_workers(), or this would come up `running` with no child.
    if (current != runtime_created && current != runtime_stopped &&
        current != runtime_failed)
        return false;

    // Before every early return below, because the ring was created before the
    // state file was read, so a daemon restarted without the setting a
    // runtime's --cpus needed must refuse rather than come up silently on a
    // ring that does not meet it.
    if (const std::string msg = ring_policy_refusal(loop); !msg.empty())
    {
        LOG_ERROR(msg.c_str());
        store_state(runtime_failed);
        return false;
    }

    // The shard count on the same terms and before the out-of-process return,
    // because the daemon forks this many children and a state file carrying
    // `"shards": 4` on a cache passes no parser on the restore path.
    if (const std::string msg = shards_config_refusal(
            get_type(), m_shards);
        !msg.empty())
    {
        LOG_ERROR(msg.c_str());
        store_state(runtime_failed);
        return false;
    }

    // And whatever else this runtime type judges as a set, on the same terms
    // and here rather than in the four callers that reach a live runtime,
    // because a state file is not parsed by any of their parsers.
    if (const std::string msg = config_refusal(); !msg.empty())
    {
        LOG_ERROR(msg.c_str());
        store_state(runtime_failed);
        return false;
    }

    // A placeholder arms nothing and binds nothing, and returning before
    // register_owner() keeps has_armed_io() false so removal can free it on
    // the spot.
    if (m_out_of_process)
    {
        // Set before the state and not after, because `running` is the
        // daemon's record of what was asked for while nothing is listening
        // yet, and publish_endpoints() adds a member to its group on it.
        m_endpoint_live = false;

        store_state(runtime_running);
        m_start_time = std::chrono::system_clock::now();
        return true;
    }

    if (m_external)
    {
        if (m_managed && !m_exec_path.empty())
        {
            // Reap any zombie from a previous stop() before forking a new child
            if (m_pid > 0)
                waitpid(m_pid, nullptr, WNOHANG);

            pid_t child = fork();
            if (child < 0)
                return false;
            if (child == 0)
            {
                setsid();
                setenv("SOCKETLEY_MANAGED", "1", 1);
                setenv("SOCKETLEY_NAME", m_name.c_str(), 1);
                int devnull = open("/dev/null", O_RDWR);
                if (devnull >= 0)
                {
                    dup2(devnull, STDIN_FILENO);
                    dup2(devnull, STDOUT_FILENO);
                    dup2(devnull, STDERR_FILENO);
                    if (devnull > 2) close(devnull);
                }
                const char* path = m_exec_path.c_str();
                execl(path, path, nullptr);
                _exit(127);
            }
            m_pid = child;
        }
        store_state(runtime_running);
        m_start_time = std::chrono::system_clock::now();
        return true;  // skip setup(), on_start, tick timer
    }

    // From here the kernel may hold addresses inside this object, so it can no
    // longer be freed on demand, and a failed setup() counts because it cannot
    // say what it armed before giving up.
    std::string_view mesh_ca, mesh_cert, mesh_key;
    get_mesh_tls_paths(mesh_ca, mesh_cert, mesh_key);
    if (const std::string msg = tls_config_refusal(get_type(),
                                                   get_tls(), is_udp(), get_cert_path(),
                                                   get_key_path(), get_ca_path(),
                                                   mesh_ca, mesh_cert, mesh_key,
                                                   get_replication_target());
        !msg.empty())
    {
        LOG_ERROR(msg.c_str());
        store_state(runtime_failed);
        return false;
    }

    m_armed_io = true;
    // The loop keeps a token per owner so a completion arriving after this
    // runtime is gone can be recognised and dropped rather than dispatched
    // into it.
    loop.register_owner(this);

    if (!setup(loop))
    {
        store_state(runtime_failed);
        return false;
    }

    store_state(runtime_running);
    m_start_time = std::chrono::system_clock::now();

    // The latch stop() raised comes down here, before on_start arms its timers
    // and after the state store, so `stop; start` cannot produce a runtime
    // that serves and can schedule nothing.
#ifndef SOCKETLEY_NO_LUA
    if (m_lua)
        m_lua->allow_registrations();
#endif

    // Deliberately not acted on, because the runtime is already listening by
    // this line and reload_lua_script() is the one caller with a command in
    // flight that asked for it.
    if (!invoke_on_start()) {}
    if ((m_cb_on_tick || (m_lua && m_lua->has_on_tick())) && m_event_loop)
        start_tick_timer();
    return true;
}

bool runtime_instance::stop(event_loop& loop)
{
    // A failed runtime has nothing armed and no child left -- start() marks it
    // before arming anything, and check_liveness() reaps before it marks -- so
    // stopping one is bookkeeping.  Answering false here made `stop` a silent
    // no-op that still returned 0, which is how a runtime the operator had
    // stopped came back `Failed` in `ls`.
    if (m_state.load(std::memory_order_acquire) == runtime_failed)
    {
        store_state(runtime_stopped);
        return true;
    }

    if (m_state.load(std::memory_order_acquire) != runtime_running)
        return false;

    // The child is not signalled here, because the supervisor takes it down
    // through the control socket while it still has a ring to cancel into.
    if (m_out_of_process)
    {
        store_state(runtime_stopped);
        return true;
    }

    if (m_external)
    {
        if (m_pid > 0)
        {
            kill(m_pid, SIGTERM);   // ask the external process to shut down
            if (m_managed)
                waitpid(m_pid, nullptr, WNOHANG);  // reap immediately if already dead
        }
        store_state(runtime_stopped);
        return true;  // skip teardown(), on_stop
    }

    if (m_tick) { m_tick->rt = nullptr; m_tick = nullptr; }
    invoke_on_stop();

    // The script's own timers and subscriptions, severed after on_stop so one
    // armed inside on_stop goes too, and not replayed by a later start() for
    // the timers, which are armed at the script's top level, unlike the
    // subscriptions on_start makes.
#ifndef SOCKETLEY_NO_LUA
    if (m_lua)
    {
        m_lua->cancel_timers();
        m_lua->cancel_subscriptions();
    }
#endif

    teardown(loop);
    loop.deregister_owner(this);
    store_state(runtime_stopped);

    // ─── Not from a worker ──────────────────────────────────────────────────
    // This byte means "the runtime you are attached to has stopped", and a
    // worker cannot tell that from a restart or from its own shard being
    // replaced: it stops in all three, and in two of them the runtime is still
    // there a second later.  Only the daemon knows which happened.
    //
    // It had never fired for anyone.  The daemon's placeholder returns at the
    // m_out_of_process branch above and never arrives here, and until an
    // interactive session's descriptor was handed to the worker there was
    // nothing in this list on the only path that reaches it.  Measured the
    // moment there was: `restart` ended the session cleanly and gave the
    // operator their shell back.
    //
    // Left rather than deleted, because the signal is right and only its
    // sender is missing -- an operator attached to a runtime somebody stops
    // deserves to be told.  Whoever adds it should add it in the daemon, where
    // a stop can be told from a restart.
    if (!in_worker_process())
    {
        for (int ifd : m_interactive_fds)
            if (::write(ifd, "\0", 1) < 0) {}
    }
    m_interactive_fds.clear();

    return true;
}

runtime_state runtime_instance::get_state() const
{
    return m_state.load(std::memory_order_relaxed);
}

runtime_type runtime_instance::get_type() const
{
    return m_type;
}

bool runtime_instance::has_armed_io() const
{
    return m_armed_io;
}

const std::string& runtime_instance::last_on_start_error() const
{
    return m_on_start_error;
}

std::string_view runtime_instance::get_name() const
{
    return m_name;
}

void runtime_instance::set_name(std::string_view name)
{
    m_name = std::string(name);
}

std::string_view runtime_instance::get_id() const
{
    return m_id;
}

void runtime_instance::set_id(std::string_view id)
{
    m_id = id;
}

std::chrono::system_clock::time_point runtime_instance::get_created_time() const
{
    return m_created_time;
}

std::chrono::system_clock::time_point runtime_instance::get_start_time() const
{
    return m_start_time;
}

void runtime_instance::note_restart()
{
    ++m_restarts;
    m_start_time = std::chrono::system_clock::now();
}

void runtime_instance::set_port(uint16_t port)
{
    m_port = port;
}

uint16_t runtime_instance::get_port() const
{
    return m_port;
}

void runtime_instance::set_listen_path(std::string_view path)
{
    m_listen_path = path;
}

std::string_view runtime_instance::get_listen_path() const
{
    return m_listen_path;
}

void runtime_instance::set_companion_path(std::string_view path)
{
    m_companion_path = path;
}

std::string_view runtime_instance::get_companion_path() const
{
    return m_companion_path;
}

void runtime_instance::set_companion_paths(std::vector<std::string> paths)
{
    m_companion_paths = std::move(paths);
}

const std::vector<std::string>& runtime_instance::get_companion_paths() const
{
    return m_companion_paths;
}

void runtime_instance::set_log_file(std::string_view path)
{
    const bool moved = (path != m_log_file);
    m_log_file = path;
    m_state_log.set_path(path);

    // The file opens with where the runtime stands, which is the only way the
    // `created` the man page promises can appear at all: the initial state is
    // set in the constructor, long before any flag has been parsed.  Guarded
    // on the path having moved, or an `edit` that re-sent the same --log would
    // add a line for a transition nobody made.
    if (moved && !path.empty())
        append_state_line(m_state.load(std::memory_order_acquire));
}

std::string_view runtime_instance::get_log_file() const
{
    return m_log_file;
}

void runtime_instance::set_write_file(std::string_view path)
{
    m_write_file = path;
    m_write_out.set_path(path);
}

std::string_view runtime_instance::get_write_file() const
{
    return m_write_file;
}

void runtime_instance::set_test_mode(bool enabled)
{
    m_test_mode = enabled;
}

bool runtime_instance::get_test_mode() const
{
    return m_test_mode;
}

void runtime_instance::set_target(std::string_view target)
{
    m_target = target;
}

std::string_view runtime_instance::get_target() const
{
    return m_target;
}

void runtime_instance::set_cache_name(std::string_view name)
{
    m_cache_name = name;
}

std::string_view runtime_instance::get_cache_name() const
{
    return m_cache_name;
}

void runtime_instance::set_bash_output(bool enabled)
{
    m_bash_output = enabled;
}

void runtime_instance::set_bash_prefix(bool enabled)
{
    m_bash_prefix = enabled;
}

void runtime_instance::set_bash_timestamp(bool enabled)
{
    m_bash_timestamp = enabled;
}

bool runtime_instance::get_bash_output() const
{
    return m_bash_output;
}

bool runtime_instance::get_bash_prefix() const
{
    return m_bash_prefix;
}

bool runtime_instance::get_bash_timestamp() const
{
    return m_bash_timestamp;
}

void runtime_instance::print_bash_message(std::string_view msg) const
{
    if (!m_bash_output)
        return;

    if (m_bash_timestamp)
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_r(&time, &tm);
        std::cout << "[" << std::put_time(&tm, "%H:%M:%S") << "] ";
    }

    if (m_bash_prefix)
        std::cout << "[" << m_name << "] ";

    // Sanitize control characters (terminal escape injection prevention)
    for (char c : msg)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if ((uc < 0x20 && uc != '\t') || uc == 0x7F)
            std::cout << '?';
        else
            std::cout << c;
    }
    std::cout << std::endl;
}

// ─── -w file ────────────────────────────────────────────────────────────────
// The file half of print_bash_message, called from the same two places: the
// point in server_instance::process_message and client_instance::process_message
// where total_messages is counted, which is what "every received message"
// means.  Everything about the file itself -- open on first use, append, one
// write per line, latch a bad path -- is appending_file's, because --log wants
// the identical three things.
void runtime_instance::write_received_message(std::string_view msg)
{
    m_write_out.append(msg);
}

// ─── --log file ─────────────────────────────────────────────────────────────
// Every transition, from the one place that makes them, so that a state added
// later cannot be the one nobody logged.
void runtime_instance::store_state(runtime_state s)
{
    const runtime_state was = m_state.exchange(s, std::memory_order_acq_rel);
    if (was == s)
        return;   // "transitions", so a stop of a stopped runtime is not one
    append_state_line(s);
}

void runtime_instance::append_state_line(runtime_state s)
{
    if (m_log_file.empty())
        return;

    // The daemon's record and not the worker's copy of the same runtime: both
    // carry the path, and both writing would double every line.  The daemon's
    // is the right one because it is the state `ls` reports, which is what an
    // operator watching this file is watching for.
    if (in_worker_process())
        return;

    // Dated, not just clocked, because this file outlives a day -- the
    // daemon's own log uses [HH:MM:SS] and is read while it is happening.
    char stamp[32] = {0};
    const auto now = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    std::tm tm{};
    localtime_r(&now, &tm);
    std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm);

    m_state_log.append(std::string(stamp) + " " + m_name + " " +
                       state_to_string(s));
}

// The script belongs to the worker, so the placeholder compiles the file and
// discards it -- which keeps a parse error a `create` refusal rather than a
// failed runtime -- at the cost of an out-of-process runtime publishing no
// routes declaration.
bool runtime_instance::load_lua_script(std::string_view path)
{
    // Remembered whether or not it loads.  The path is the CONFIGURATION and
    // the compile is an attempt at it: a runtime whose script does not parse
    // is still a runtime configured with that script, and forgetting the path
    // on failure meant nothing could ever try it again.
    //
    // What that cost, measured: a boot restore whose script had been broken
    // between reboots dropped the path, so every later `start` forked a worker
    // with no lua_script in its config -- the file could be fixed and `start`,
    // `reload-lua` and `reload` all left the runtime scriptless, answering 404
    // where a callback used to be.  Only another daemon restart, which re-reads
    // the state file, brought it back.
    m_lua_script_path = path;

    if (m_out_of_process)
    {
        std::string err;
        if (!lua_context::script_compiles(path, err))
        {
            std::cerr << lua_diag::tag(get_name()) << " script error: "
                      << err << std::endl;
            return false;
        }
        return true;
    }

    m_lua = std::make_unique<lua_context>();

    if (!m_lua->load_script(path, this))
    {
        // The context goes and the path stays: every reader of m_lua tests it
        // first, and the path is what a retry needs.
        m_lua.reset();
        return false;
    }

    return true;
}

bool runtime_instance::reload_lua_script()
{
    if (m_lua_script_path.empty())
        return false;

    if (m_state.load(std::memory_order_acquire) != runtime_running)
        return false;

    // Same rule as load_lua_script: the placeholder has nothing to reload,
    // though re-checking that the file parses is still worth doing here.
    if (m_out_of_process)
    {
        std::string err;
        if (!lua_context::script_compiles(m_lua_script_path, err))
        {
            std::cerr << lua_diag::tag(get_name()) << " script error: "
                      << err << std::endl;
            return false;
        }
        return true;
    }

    // The replacement is built before the old one is given up, so a script
    // that no longer compiles leaves the runtime with the interpreter it had
    // rather than with none.
    auto next = std::make_unique<lua_context>();

    if (!next->load_script(m_lua_script_path, this))
        return false;

    m_lua = std::move(next);

    bool should_tick = m_lua->has_on_tick();
    if (!m_tick && should_tick)
        start_tick_timer();
    else if (m_tick && !should_tick) {
        m_tick->rt = nullptr;
        m_tick = nullptr;
    }

    // The new script's set-up runs, because the assignment above destroyed
    // every subscription and timer the outgoing context held; on_stop is
    // deliberately not run, since the runtime keeps its listener and clients
    // throughout, and a raise here is reported to whoever asked for the
    // reload.
    if (!invoke_on_start())
        return false;

    return true;
}

std::string_view runtime_instance::get_lua_script_path() const
{
    return m_lua_script_path;
}

bool runtime_instance::invoke_on_start()
{
    // Every attempt starts with nothing to report, including the ones that
    // return early.
    m_on_start_error.clear();

#ifndef SOCKETLEY_NO_LUA
    // Ahead of every early return below, because `self.state` is the RUNTIME's
    // state and not the callback's.  It stood after the has_on_start() test, so
    // a script that defined no on_start never had it written: measured, a
    // handler with only on_client_message answered a message and reported
    // `self.state == "created"` while doing it.  The store to runtime_running
    // happens in start() before this is called, so the literal is the truth.
    if (m_lua)
        m_lua->update_self_state("running");
#endif

    if (m_cb_on_start) { m_cb_on_start(); return true; }
    if (!m_lua || !m_lua->has_on_start())
        return true;

#ifndef SOCKETLEY_NO_LUA
    sol::protected_function_result r = m_lua->on_start()();
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_start error: " << e.what() << std::endl;

        // Recorded on the instance as well as printed, because `start srv1
        // srv2 srv3` runs three on_starts before it reports and each script's
        // own loads clear the thread-local buffer.
        m_on_start_error = std::string("on_start error: ") + e.what();
        lua_diag::record(m_on_start_error);
        return false;
    }
#endif
    return true;
}

void runtime_instance::invoke_on_stop()
{
#ifndef SOCKETLEY_NO_LUA
    // The same move for the same reason.  stop() stores runtime_stopped after
    // this returns, so this says what the runtime is about to be -- which is
    // what a script reading it from inside on_stop has always been told.
    if (m_lua)
        m_lua->update_self_state("stopped");
#endif

    if (m_cb_on_stop) { m_cb_on_stop(); return; }
    if (!m_lua || !m_lua->has_on_stop())
        return;

#ifndef SOCKETLEY_NO_LUA
    sol::protected_function_result r = m_lua->on_stop()();
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_stop error: " << e.what() << std::endl;
    }
#endif
}

void runtime_instance::invoke_on_message(std::string_view msg)
{
    if (m_cb_on_message) { m_cb_on_message(msg); return; }
    if (!m_lua || !m_lua->has_on_message())
        return;

#ifndef SOCKETLEY_NO_LUA
    sol::protected_function_result r = m_lua->on_message()(msg);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_message error: " << e.what() << std::endl;
    }
#endif
}

void runtime_instance::invoke_on_connect(int client_id)
{
    if (m_cb_on_connect) { m_cb_on_connect(client_id); return; }
    if (!m_lua || !m_lua->has_on_connect())
        return;

#ifndef SOCKETLEY_NO_LUA
    sol::protected_function_result r = m_lua->on_connect()(client_id);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_connect error: " << e.what() << std::endl;
    }
#endif
}

void runtime_instance::invoke_on_disconnect(int client_id)
{
    if (m_cb_on_disconnect) { m_cb_on_disconnect(client_id); return; }
    if (!m_lua || !m_lua->has_on_disconnect())
        return;

#ifndef SOCKETLEY_NO_LUA
    sol::protected_function_result r = m_lua->on_disconnect()(client_id);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_disconnect error: " << e.what() << std::endl;
    }
#endif
}

bool runtime_instance::invoke_on_auth(int client_id)
{
    if (m_cb_on_auth) return m_cb_on_auth(client_id);
#ifndef SOCKETLEY_NO_LUA
    if (!m_lua || !m_lua->has_on_auth()) return true;  // no hook = allow

    // A protected call, because a try/catch on sol::error depends on the panic
    // handler throwing and unwinding out of the interpreter, which in the
    // Sanitize build it does not.
    sol::protected_function_result r = m_lua->on_auth()(client_id);

    if (!r.valid()) {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_auth error: " << e.what() << "\n";
        return false;  // Lua error → reject (fail-closed)
    }
    // nil, a non-bool, or no return at all → reject (fail-closed)
    sol::optional<bool> res = r.return_count() > 0 ? r.get<sol::optional<bool>>()
                                                   : sol::optional<bool>{};
    return res.value_or(false);
#else
    return true;
#endif
}

void runtime_instance::invoke_on_send([[maybe_unused]] std::string_view msg)
{
    if (!m_lua || !m_lua->has_on_send())
        return;

#ifndef SOCKETLEY_NO_LUA
    sol::protected_function_result r = m_lua->on_send()(msg);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_send error: " << e.what() << std::endl;
    }
#endif
}

// ─── C++ callbacks ───

void runtime_instance::set_on_start(std::function<void()> cb)                            { m_cb_on_start = std::move(cb); }
void runtime_instance::set_on_stop(std::function<void()> cb)                             { m_cb_on_stop = std::move(cb); }
void runtime_instance::set_on_connect(std::function<void(int)> cb)                       { m_cb_on_connect = std::move(cb); }
void runtime_instance::set_on_disconnect(std::function<void(int)> cb)                    { m_cb_on_disconnect = std::move(cb); }
void runtime_instance::set_on_client_message(std::function<void(int, std::string_view)> cb) { m_cb_on_client_message = std::move(cb); }
void runtime_instance::set_on_message(std::function<void(std::string_view)> cb)          { m_cb_on_message = std::move(cb); }
void runtime_instance::set_on_tick(std::function<void(double)> cb)                       { m_cb_on_tick = std::move(cb); }
void runtime_instance::set_on_auth(std::function<bool(int)> cb)                          { m_cb_on_auth = std::move(cb); }
void runtime_instance::set_tick_interval(uint32_t ms)                                    { m_cb_tick_ms = ms; }

// ─── Group ───

void runtime_instance::set_group(std::string_view group) { m_group = std::string(group); }
std::string_view runtime_instance::get_group() const { return m_group; }

// ─── Ownership ───

// An owner is another runtime's name, and one row of `ls` is one line: an
// unchecked --owner of 3000 characters was stored verbatim and printed a table
// no field-splitter could read.
bool runtime_instance::set_owner(std::string_view owner_name)
{
    if (!owner_name.empty() && !runtime_manager::valid_name(owner_name))
        return false;
    m_owner = std::string(owner_name);
    return true;
}
std::string_view runtime_instance::get_owner() const { return m_owner; }
void runtime_instance::set_lua_created(bool v) { m_lua_created = v; }
bool runtime_instance::is_lua_created() const { return m_lua_created; }
// The two roles are exclusive here rather than at each caller, because start()
// dispatches on whichever flag it reads first and the marks arrive in no fixed
// order.
void runtime_instance::mark_external() { m_external = true; m_out_of_process = false; }
bool runtime_instance::is_external() const { return m_external; }
void runtime_instance::set_pid(pid_t pid) { m_pid = pid; }
pid_t runtime_instance::get_pid() const { return m_pid; }
void runtime_instance::mark_managed(std::string exec_path) { m_managed = true; mark_external(); m_exec_path = std::move(exec_path); }
bool runtime_instance::is_managed() const { return m_managed; }
std::string_view runtime_instance::get_exec_path() const { return m_exec_path; }
// Refused for an external runtime, whose exec_path and pid a placeholder would
// ignore.
void runtime_instance::mark_out_of_process() { if (!m_external) m_out_of_process = true; }
bool runtime_instance::is_out_of_process() const { return m_out_of_process; }

// Clamped here rather than trusted, because the state file is read at startup
// from a document another build may have written, and a zero would mean a
// runtime that is running with no process serving it.
void runtime_instance::set_shards(uint32_t n)
{
    m_shards = n < 1 ? 1 : (n > max_shards ? max_shards : n);
}
uint32_t runtime_instance::get_shards() const { return m_shards; }
void runtime_instance::set_shard_index(uint32_t i)
{
    // Clamped rather than refused, because a frame naming a slot outside the
    // table would be a write past the end of the shared mapping.
    m_shard_index = i < max_shards ? i : 0;
}
uint32_t runtime_instance::get_shard_index() const { return m_shard_index; }
void runtime_instance::set_child_policy(child_policy p) { m_child_policy = p; }
runtime_instance::child_policy runtime_instance::get_child_policy() const { return m_child_policy; }
void runtime_instance::set_cpus(const cpu_set_spec& cpus) { m_cpus = cpus; m_cpus_set = true; }
const cpu_set_spec& runtime_instance::get_cpus() const { return m_cpus; }
bool runtime_instance::has_cpus_request() const { return m_cpus_set; }

// io_uring fixes a ring's flags at creation and the ring belongs to the
// process, not the runtime, so a request the existing ring does not satisfy is
// refused rather than accepted and quietly ignored.
std::string runtime_instance::ring_policy_refusal(const event_loop& loop) const
{
    std::string msg;

    // Only what was actually asked for is checked, because a runtime created
    // without the flag has no request to disappoint.
    const cpu_set_spec& want = get_cpus();
    const cpu_set_spec& have = loop.cpus();
    if (has_cpus_request() &&
        (want.all != have.all || (!want.all && want.mask != have.mask)))
    {
        msg += "--cpus " + want.to_string() + ": this runtime's I/O thread is "
               "already pinned to " + have.to_string() + ".\n"
               "  One thread cannot be in two places, and every runtime in this "
               "daemon shares it.\n"
               "  Start the daemon with --cpus " + want.to_string()
             + " (or SOCKETLEY_CPUS=" + want.to_string() + ") to move all of them.\n";
    }

    return msg;
}

void runtime_instance::set_worker_routes(std::shared_ptr<const route_table> rt)
{
    m_worker_routes = std::move(rt);
}

const std::shared_ptr<const route_table>& runtime_instance::worker_routes() const
{
    return m_worker_routes;
}

void runtime_instance::set_runtime_manager(runtime_manager* mgr) { m_runtime_manager = mgr; }
void runtime_instance::set_event_loop(event_loop* loop) { m_event_loop = loop; }
runtime_manager* runtime_instance::get_runtime_manager() const { return m_runtime_manager; }
event_loop* runtime_instance::get_event_loop() const { return m_event_loop; }

void runtime_instance::invoke_on_client_message(int client_id, std::string_view msg)
{
    if (m_cb_on_client_message) { m_cb_on_client_message(client_id, msg); return; }
    if (!m_lua || !m_lua->has_on_client_message())
        return;

#ifndef SOCKETLEY_NO_LUA
    sol::protected_function_result r = m_lua->on_client_message()(client_id, msg);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        std::cerr << lua_diag::tag(get_name()) << " on_client_message error: " << e.what() << std::endl;
    }
#endif
}

// ─── Resource limits ───

void runtime_instance::set_max_connections(uint32_t max) { m_max_connections = max; }
uint32_t runtime_instance::get_max_connections() const { return m_max_connections; }

void runtime_instance::set_rate_limit(double rate) { m_rate_limit = rate; }
double runtime_instance::get_rate_limit() const { return m_rate_limit; }

void runtime_instance::set_global_rate_limit(double rate) { m_global_rate_limit = rate; m_global_tokens = rate; m_global_last = std::chrono::steady_clock::now(); }
double runtime_instance::get_global_rate_limit() const { return m_global_rate_limit; }

bool runtime_instance::check_global_rate_limit()
{
    if (m_global_rate_limit <= 0.0) return true;
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - m_global_last).count();
    m_global_last = now;
    m_global_tokens = std::min(m_global_rate_limit, m_global_tokens + elapsed * m_global_rate_limit);
    if (m_global_tokens < 1.0) return false;
    m_global_tokens -= 1.0;
    return true;
}

void runtime_instance::set_idle_timeout(uint32_t seconds) { m_idle_timeout = seconds; }
uint32_t runtime_instance::get_idle_timeout() const { return m_idle_timeout; }

void runtime_instance::set_drain(bool enabled) { m_drain = enabled; }
bool runtime_instance::get_drain() const { return m_drain; }

void runtime_instance::set_reconnect(int max_attempts) { m_reconnect = max_attempts; }
int runtime_instance::get_reconnect() const { return m_reconnect; }

// ─── TLS ───

void runtime_instance::set_tls(bool enabled) { m_tls = enabled; }
bool runtime_instance::get_tls() const { return m_tls; }
void runtime_instance::set_cert_path(std::string_view path) { m_cert_path = path; }
std::string_view runtime_instance::get_cert_path() const { return m_cert_path; }
void runtime_instance::set_key_path(std::string_view path) { m_key_path = path; }
std::string_view runtime_instance::get_key_path() const { return m_key_path; }
void runtime_instance::set_ca_path(std::string_view path) { m_ca_path = path; }
std::string_view runtime_instance::get_ca_path() const { return m_ca_path; }

// ─── Stats ───

// What `stats` prints, in the order it has always printed, each piece
// appending and none knowing what comes after it.

std::string runtime_instance::get_stats() const
{
    // Out of process the two halves come from two processes, and rebuilding
    // the second here reads this placeholder's empty containers, which printed
    // keys:0 for a cache that had just served five SETs.
    if (worker_backed())
        return stats_prefix() + stat_detail_snapshot();

    // Out of process, running, and no report has ever landed, so say what is
    // known rather than print this instance's zeros as though the worker had
    // answered.
    if (is_out_of_process() && !in_worker_process()
        && get_state() == runtime_running)
        return stats_prefix() + "worker_report:none\n";

    return stats_prefix() + stats_ring() + stats_lines();
}

// The counters, and nothing that needs a connection table walked, which is
// what lets the daemon print them for a runtime living somewhere else.
std::string runtime_instance::stats_prefix() const
{
    std::string out;
    out.reserve(256);

    char buf[32];
    auto append_u64 = [&](uint64_t v) {
        auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
        out.append(buf, static_cast<size_t>(ptr - buf));
    };

    const shard_stats::figures f = worker_figures();

    out += "name:";
    out += m_name;
    out += "\ntype:";
    out += type_to_string(m_type);
    out += "\nport:";
    // The bound port and not the configured one, for `ps`'s reason: a runtime
    // with no -p reported 0 while it was serving on its type's default.
    append_u64(effective_port());
    out += "\nconnections:";
    // Not get_connection_count(): see reported_connection_count(), which is the
    // same question asked in a way that survives the runtime living in a worker.
    append_u64(reported_connection_count());
    out += "\ntotal_connections:";
    append_u64(f.total_connections);
    out += "\ntotal_messages:";
    append_u64(f.total_messages);
    out += "\nbytes_in:";
    append_u64(f.bytes_in);
    out += "\nbytes_out:";
    append_u64(f.bytes_out);
    out += '\n';

    return out;
}

// ── How this runtime's I/O is running ───────────────────────────────────────
// Read from the loop and not from what was asked for, because the kernel can
// refuse a pinning, and this field is the ring's -- which is why a worker
// pushes it rather than the daemon writing it.
std::string runtime_instance::stats_ring() const
{
    std::string out;
    out += "cpus:";
    if (m_event_loop)
    {
        out += m_event_loop->cpus().to_string();
        if (!m_event_loop->cpus().all && !m_event_loop->affinity_applied())
            out += "(not applied)";
    }
    else
    {
        // No loop yet, which beats printing the default as if it had been
        // chosen.
        out += "unknown";
    }
    out += '\n';
    return out;
}

// ─── Interactive mode ───

void runtime_instance::add_interactive_fd(int fd)
{
    m_interactive_fds.push_back(fd);
}

void runtime_instance::remove_interactive_fd(int fd)
{
    m_interactive_fds.erase(
        std::remove(m_interactive_fds.begin(), m_interactive_fds.end(), fd),
        m_interactive_fds.end());
}

namespace
{

enum class notify_result { sent, skipped, broken };

// Nothing written means the message can be dropped and the stream stays
// intact, while a partial write has already put a fragment on the wire and
// finishes that connection.
notify_result notify_write(int fd, const char* data, size_t len)
{
    size_t written = 0;
    if (socketley::write_all(fd, data, len, &written))
        return notify_result::sent;
    return (written == 0) ? notify_result::skipped : notify_result::broken;
}

}  // namespace

void runtime_instance::notify_interactive(std::string_view msg) const
{
    if (m_interactive_fds.empty()) return;

    const bool has_newline = !msg.empty() && msg.back() == '\n';

    for (size_t i = 0; i < m_interactive_fds.size(); )
    {
        const int fd = m_interactive_fds[i];

        notify_result r = notify_write(fd, msg.data(), msg.size());
        if (r == notify_result::sent && !has_newline)
        {
            // The body is already out, so a terminator that does not follow it
            // leaves the same broken stream a partial write would have.
            r = (notify_write(fd, "\n", 1) == notify_result::sent)
                    ? notify_result::sent
                    : notify_result::broken;
        }

        if (r == notify_result::broken)
        {
            auto& fds = const_cast<std::vector<int>&>(m_interactive_fds);
            fds[i] = fds.back();
            fds.pop_back();
        }
        else
        {
            ++i;
        }
    }
}

void runtime_instance::on_publish_dispatch([[maybe_unused]] std::string_view cache_name,
                                          [[maybe_unused]] std::string_view channel,
                                          [[maybe_unused]] std::string_view message)
{
#ifndef SOCKETLEY_NO_LUA
    if (m_lua) m_lua->dispatch_publish(cache_name, channel, message);
#endif
}
