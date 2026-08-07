#include "runtime_instance.h"
#include "logging.h"
#include "tls_context.h"
#include "blocking_write.h"
#include "event_loop.h"
#include "lua_context.h"
#include "id_generator.h"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <unistd.h>
#include <cerrno>
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

void runtime_instance::start_tick_timer()
{
    uint32_t ms = m_cb_tick_ms > 0 ? m_cb_tick_ms
                : (m_lua ? m_lua->get_tick_ms() : 100);
    if (ms < 10) ms = 10;
    m_tick = new tick_handler();
    m_tick->rt = this;
    m_tick->loop = m_event_loop;
    m_tick->req = { m_tick, nullptr, -1, 0, op_timeout };
    m_tick->ts = { static_cast<long long>(ms / 1000),
                   static_cast<long long>((ms % 1000) * 1000000LL) };
    m_tick->last = std::chrono::steady_clock::now();
    m_event_loop->submit_timeout(&m_tick->ts, &m_tick->req);
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
        try { m_lua->on_tick()(dt); }
        catch (const sol::error& e) { std::cerr << "[lua] on_tick error: " << e.what() << "\n"; }
#endif
    }
    if (!m_tick || !m_event_loop) return;
    uint32_t ms = m_cb_tick_ms > 0 ? m_cb_tick_ms
                : (m_lua ? m_lua->get_tick_ms() : 100);
    if (ms < 10) ms = 10;
    m_tick->ts = { static_cast<long long>(ms / 1000),
                   static_cast<long long>((ms % 1000) * 1000000LL) };
    m_event_loop->submit_timeout(&m_tick->ts, &m_tick->req);
}

bool runtime_instance::start(event_loop& loop)
{
    runtime_state current = m_state.load(std::memory_order_acquire);

    if (current != runtime_created && current != runtime_stopped)
        return false;

    // Before every early return below, and deliberately so.  `create` checks
    // this for every runtime whatever process it will end up in, and this is the
    // same check on the path `create` does not cover: the daemon's own restore.
    //
    // The state file carries the request; the ring was created before the file
    // was read, from the environment the daemon was launched with.  So a daemon
    // restarted without the setting that satisfied a runtime's --cpus brings
    // that runtime up on a ring that does not meet it, and until this gate
    // existed it did so in silence — `stats` reported the ring it actually got
    // and nothing reported that it was not the one asked for.  Refusing to start
    // is the same answer `create` gives, arrived at one restart later.
    //
    // An out-of-process runtime is checked against the daemon's ring too, which
    // is not its own: its worker builds one from the environment it inherited
    // from this daemon, so this ring is what that one will look like.  Comparing
    // against it is closer than not comparing at all, and it keeps `create` and
    // restore giving the same answer to the same configuration.
    if (const std::string msg = ring_policy_refusal(loop); !msg.empty())
    {
        LOG_ERROR(msg.c_str());
        m_state.store(runtime_failed, std::memory_order_release);
        return false;
    }

    // A placeholder for a worker process arms nothing and binds nothing: the
    // supervisor forks the child that does both.  Returning before
    // register_owner() is what keeps has_armed_io() false for it, so removal
    // can free it on the spot instead of retiring it to the graveyard — there
    // is no completion the kernel could still deliver into this object.
    if (m_out_of_process)
    {
        // "Binds nothing" is the whole sentence above, and it is what this flag
        // has to say out loud.  The line below stores `running` because that is
        // the daemon's record of what was asked for — but nothing is listening
        // on this port yet and, at this point, no child has even been forked to
        // do it.  publish_endpoints() adds a member to its group on `running`,
        // so without this the address is announced to every gateway here, in
        // runtime_manager::start()'s publish, before the supervisor exists.
        //
        // Set before the state and not after: the two are read by another call
        // in the same statement sequence, and a reader that saw `running` with
        // the old flag would be reading exactly the state this prevents.
        m_endpoint_live = false;

        m_state.store(runtime_running, std::memory_order_release);
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
        m_state.store(runtime_running, std::memory_order_release);
        m_start_time = std::chrono::system_clock::now();
        return true;  // skip setup(), on_start, tick timer
    }

    // From here on the kernel may be holding addresses that point inside this
    // object, so it can no longer be freed on demand — see runtime_manager's
    // graveyard.  A setup() that fails counts too: it can have armed an accept
    // or a timer before it gave up on a later step, and it has no way to tell
    // us which.  Erring towards "armed" costs a retired object; erring the
    // other way costs the daemon.
    // Last gate before anything is armed, and the only one the daemon's own
    // restore path also passes through: the flag handlers refuse the TLS
    // options they cannot honour at create time, but a state file written
    // before that gate existed carries was_running and is auto-started at boot
    // without going near them.  Serving cleartext on a port the operator asked
    // to encrypt — and which inspect still reports as encrypted — is worse than
    // refusing to come up.
    //
    // Every runtime type performs a handshake somewhere now — a server's and a
    // cache's own listener, a client's outbound socket, a proxy's two legs —
    // so a complete configuration for any of them passes here and is honoured
    // by that runtime's setup().  What is still refused is a configuration
    // that would leave part of the traffic in the clear; see tls_context.h.
    //
    // "Complete" is all this gate can judge.  Refusals it cannot reach are
    // made by the runtime itself, because they depend on configuration this
    // signature does not carry or on something that happens later: --tls on a
    // UDP socket would need DTLS, a server's upstream leg has no handshake
    // behind it, and a TLS cache is only asked to become a replication leader
    // once a client sends REPLICATE.  The first two return false from setup()
    // and land in the same `failed` state as a refusal here; the third is
    // answered at the command.
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
        m_state.store(runtime_failed, std::memory_order_release);
        return false;
    }

    m_armed_io = true;
    // The loop keeps a token per owner so a completion arriving after this
    // runtime is gone can be recognised and dropped rather than dispatched
    // into it.
    loop.register_owner(this);

    if (!setup(loop))
    {
        m_state.store(runtime_failed, std::memory_order_release);
        return false;
    }

    m_state.store(runtime_running, std::memory_order_release);
    m_start_time = std::chrono::system_clock::now();
    invoke_on_start();
    if ((m_cb_on_tick || (m_lua && m_lua->has_on_tick())) && m_event_loop)
        start_tick_timer();
    return true;
}

bool runtime_instance::stop(event_loop& loop)
{
    if (m_state.load(std::memory_order_acquire) != runtime_running)
        return false;

    // The child is not signalled here.  The supervisor owns it and takes it
    // down through the control socket first, so that the worker stops its proxy
    // while it still has a ring to cancel into; a SIGTERM from this side would
    // race that and cost the connections a clean close.
    if (m_out_of_process)
    {
        m_state.store(runtime_stopped, std::memory_order_release);
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
        m_state.store(runtime_stopped, std::memory_order_release);
        return true;  // skip teardown(), on_stop
    }

    if (m_tick) { m_tick->rt = nullptr; m_tick = nullptr; }
    invoke_on_stop();
    teardown(loop);
    loop.deregister_owner(this);
    m_state.store(runtime_stopped, std::memory_order_release);

    // Signal all interactive sessions that runtime has stopped
    for (int ifd : m_interactive_fds)
        if (::write(ifd, "\0", 1) < 0) {}
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

void runtime_instance::set_port(uint16_t port)
{
    m_port = port;
}

uint16_t runtime_instance::get_port() const
{
    return m_port;
}

void runtime_instance::set_log_file(std::string_view path)
{
    m_log_file = path;
}

std::string_view runtime_instance::get_log_file() const
{
    return m_log_file;
}

void runtime_instance::set_write_file(std::string_view path)
{
    m_write_file = path;
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

// ─── Whose process does a script belong to? ─────────────────────────────────
//
// An out-of-process runtime exists twice: the worker that owns the listening
// socket and serves every byte, and a placeholder in the daemon that holds its
// name, port, group and state so `ls`, `stats` and the endpoint table have
// something to answer with.  The script belongs to the worker.
//
// The placeholder used to load it too, so every top-level line ran twice -- and
// the two copies did not even do the same thing, because the daemon's holds the
// runtime manager and the worker's does not.  A top-level socketley.create()
// therefore created a runtime FROM THE PLACEHOLDER while the identical line in
// the worker was refused, which is the inverse of the asymmetry that was
// intended: the refusal is there because a worker is not where the inventory
// is, and the daemon quietly obliging is the same mistake read backwards.
//
// The placeholder now compiles the file and discards it.  That keeps the one
// report `create` could always make -- a script that does not parse is refused
// on the spot rather than becoming "the worker exited and the runtime is
// failed" -- without executing a line of it.
//
// What the daemon gives up by not running it: a script's `routes` declaration
// is read from the placeholder's context by publish_endpoints, so an
// out-of-process runtime no longer publishes one.  Stated in LIMITATIONS.  The
// feature is a handler's, not a proxy's -- the example says so in its own first
// paragraph -- and only a proxy can be out-of-process today, so nothing in the
// tree declared routes from a process that this affects.  The two other
// readers of the placeholder's context already skipped out-of-process
// runtimes before this change.
bool runtime_instance::load_lua_script(std::string_view path)
{
    if (m_out_of_process)
    {
        std::string err;
        if (!lua_context::script_compiles(path, err))
        {
            std::cerr << "[lua] script error: " << err << std::endl;
            return false;
        }
        m_lua_script_path = path;
        return true;
    }

    m_lua = std::make_unique<lua_context>();

    if (!m_lua->load_script(path, this))
    {
        m_lua.reset();
        return false;
    }

    m_lua_script_path = path;
    return true;
}

bool runtime_instance::reload_lua_script()
{
    if (m_lua_script_path.empty())
        return false;

    if (m_state.load(std::memory_order_acquire) != runtime_running)
        return false;

    // Same rule as load_lua_script: the placeholder does not run the script, so
    // it has nothing to reload.  Re-checking that the file still parses is
    // worth doing anyway -- `reload-lua` on a broken file should say so here
    // rather than in the worker's exit status -- but the reload that matters
    // is the worker's, and this daemon-side object has no callbacks to replace.
    if (m_out_of_process)
    {
        std::string err;
        if (!lua_context::script_compiles(m_lua_script_path, err))
        {
            std::cerr << "[lua] script error: " << err << std::endl;
            return false;
        }
        return true;
    }

    // ─── The replacement is built before the old one is given up ────────────
    //
    // This used to reset m_lua and then load into the empty slot, so a script
    // that no longer compiled left the runtime with NO interpreter: every
    // callback stopped firing and nothing said so.  Both halves of the tree
    // claim otherwise -- proxy_worker's reload warns that "the previous one is
    // still in force", and cmd_reload_lua relies on the same promise when it
    // reads the declaration back afterwards -- so the contract was written down
    // twice and kept nowhere.
    //
    // Measured before this change, on a server whose script logs every message:
    // one edit that dropped a closing paren, one reload-lua reporting success,
    // and then total_messages 1 -> 3 with no further callback line.  The traffic
    // arrived; the script it was supposed to reach was gone.
    //
    // Swapping on success is the whole fix.  The two contexts overlap only for
    // the duration of the load: bindings are per-state, and the C++ callbacks
    // this instance holds are not the Lua ones.
    auto next = std::make_unique<lua_context>();

    if (!next->load_script(m_lua_script_path, this))
        return false;

    m_lua = std::move(next);

#ifndef SOCKETLEY_NO_LUA
    m_lua->update_self_state("running");
#endif

    bool should_tick = m_lua->has_on_tick();
    if (!m_tick && should_tick)
        start_tick_timer();
    else if (m_tick && !should_tick) {
        m_tick->rt = nullptr;
        m_tick = nullptr;
    }

    return true;
}

std::string_view runtime_instance::get_lua_script_path() const
{
    return m_lua_script_path;
}

void runtime_instance::invoke_on_start()
{
    if (m_cb_on_start) { m_cb_on_start(); return; }
    if (!m_lua || !m_lua->has_on_start())
        return;

#ifndef SOCKETLEY_NO_LUA
    m_lua->update_self_state("running");

    try {
        m_lua->on_start()();
    } catch (const sol::error& e) {
        std::cerr << "[lua] on_start error: " << e.what() << std::endl;
    }
#endif
}

void runtime_instance::invoke_on_stop()
{
    if (m_cb_on_stop) { m_cb_on_stop(); return; }
    if (!m_lua || !m_lua->has_on_stop())
        return;

#ifndef SOCKETLEY_NO_LUA
    m_lua->update_self_state("stopped");

    try {
        m_lua->on_stop()();
    } catch (const sol::error& e) {
        std::cerr << "[lua] on_stop error: " << e.what() << std::endl;
    }
#endif
}

void runtime_instance::invoke_on_message(std::string_view msg)
{
    if (m_cb_on_message) { m_cb_on_message(msg); return; }
    if (!m_lua || !m_lua->has_on_message())
        return;

#ifndef SOCKETLEY_NO_LUA
    try {
        m_lua->on_message()(msg);
    } catch (const sol::error& e) {
        std::cerr << "[lua] on_message error: " << e.what() << std::endl;
    }
#endif
}

void runtime_instance::invoke_on_connect(int client_id)
{
    if (m_cb_on_connect) { m_cb_on_connect(client_id); return; }
    if (!m_lua || !m_lua->has_on_connect())
        return;

#ifndef SOCKETLEY_NO_LUA
    try {
        m_lua->on_connect()(client_id);
    } catch (const sol::error& e) {
        std::cerr << "[lua] on_connect error: " << e.what() << std::endl;
    }
#endif
}

void runtime_instance::invoke_on_disconnect(int client_id)
{
    if (m_cb_on_disconnect) { m_cb_on_disconnect(client_id); return; }
    if (!m_lua || !m_lua->has_on_disconnect())
        return;

#ifndef SOCKETLEY_NO_LUA
    try {
        m_lua->on_disconnect()(client_id);
    } catch (const sol::error& e) {
        std::cerr << "[lua] on_disconnect error: " << e.what() << std::endl;
    }
#endif
}

bool runtime_instance::invoke_on_auth(int client_id)
{
    if (m_cb_on_auth) return m_cb_on_auth(client_id);
#ifndef SOCKETLEY_NO_LUA
    if (!m_lua || !m_lua->has_on_auth()) return true;  // no hook = allow

    // A PROTECTED call.  Written as a try/catch on sol::error — which is what
    // stood here, and what every other callback in this file still does — the
    // rejection happened and the message did not: the catch depends on sol2's
    // panic handler throwing and on that throw unwinding out of the
    // interpreter, and in this repository's Sanitize build it does neither.
    // Measured with a script that logs a marker and then raises: the marker
    // reached the daemon log, the client was rejected, and no `on_auth error`
    // line was ever written.
    //
    // This is the callback that decides whether a client is served at all, so
    // "it rejected everyone and would not say why" is the shape of outage an
    // operator has to be able to diagnose from the log.  The error comes back
    // as a value now, the way on_master_auth's and the filter chain's do.
    sol::protected_function_result r = m_lua->on_auth()(client_id);

    if (!r.valid()) {
        sol::error e = r;
        std::cerr << "[lua] on_auth error: " << e.what() << "\n";
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
    try {
        m_lua->on_send()(msg);
    } catch (const sol::error& e) {
        std::cerr << "[lua] on_send error: " << e.what() << std::endl;
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

void runtime_instance::set_owner(std::string_view owner_name) { m_owner = std::string(owner_name); }
std::string_view runtime_instance::get_owner() const { return m_owner; }
void runtime_instance::set_lua_created(bool v) { m_lua_created = v; }
bool runtime_instance::is_lua_created() const { return m_lua_created; }
void runtime_instance::mark_external() { m_external = true; }
bool runtime_instance::is_external() const { return m_external; }
void runtime_instance::set_pid(pid_t pid) { m_pid = pid; }
pid_t runtime_instance::get_pid() const { return m_pid; }
void runtime_instance::mark_managed(std::string exec_path) { m_managed = true; m_external = true; m_exec_path = std::move(exec_path); }
bool runtime_instance::is_managed() const { return m_managed; }
std::string_view runtime_instance::get_exec_path() const { return m_exec_path; }
void runtime_instance::mark_out_of_process() { m_out_of_process = true; }
bool runtime_instance::is_out_of_process() const { return m_out_of_process; }
void runtime_instance::set_child_policy(child_policy p) { m_child_policy = p; }
runtime_instance::child_policy runtime_instance::get_child_policy() const { return m_child_policy; }
void runtime_instance::set_cpus(const cpu_set_spec& cpus) { m_cpus = cpus; m_cpus_set = true; }
const cpu_set_spec& runtime_instance::get_cpus() const { return m_cpus; }
bool runtime_instance::has_cpus_request() const { return m_cpus_set; }
void runtime_instance::set_sqpoll(bool on) { m_sqpoll = on; m_sqpoll_set = true; }
bool runtime_instance::get_sqpoll() const { return m_sqpoll; }
bool runtime_instance::has_sqpoll_request() const { return m_sqpoll_set; }

// A ring is a queue between one thread and the kernel, and io_uring fixes its
// flags — SQPOLL among them — when the ring is created.  The ring a runtime uses
// is created by the *process* it lives in, before that process has read any
// runtime configuration at all: the daemon's in daemon_start(), a worker's
// before its config frame arrives.  So neither `create` nor `start` can make a
// ring; either can only be told to run a runtime on one that already exists.
//
// That leaves two honest answers to a request the existing ring does not
// satisfy, and this is the one that is not a lie.  Accepting it and doing
// nothing would put a figure in the state file that `stats` contradicts, and
// leave an operator measuring a poller that was never started.
//
// Nothing changes here when the split lands: a runtime that owns its process
// owns its ring, the request becomes that ring's parameters, and this check has
// nothing left to refuse.
std::string runtime_instance::ring_policy_refusal(const event_loop& loop) const
{
    std::string msg;

    // Only what was actually asked for is checked.  A runtime created without
    // either flag takes the ring it is given and is told nothing about it —
    // there is no request to disappoint.
    const bool want_sqpoll = get_sqpoll();
    if (has_sqpoll_request() && want_sqpoll != loop.sqpoll_enabled())
    {
        msg += want_sqpoll
             ? "--sqpoll: this runtime shares a ring that was created without a "
               "submission poller.\n"
               "  A ring's polling mode is fixed when the ring is created, and this "
               "one exists already.\n"
               "  Start the daemon with --sqpoll (or SOCKETLEY_SQPOLL=1) to give "
               "every runtime in it a poller.\n"
             : "--no-sqpoll: this runtime shares a ring that was created with a "
               "submission poller.\n"
               "  A ring's polling mode is fixed when the ring is created, and this "
               "one exists already.\n"
               "  Start the daemon with --no-sqpoll (and without SOCKETLEY_SQPOLL) "
               "to drop the poller.\n";
    }

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
    try {
        m_lua->on_client_message()(client_id, msg);
    } catch (const sol::error& e) {
        std::cerr << "[lua] on_client_message error: " << e.what() << std::endl;
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

std::string runtime_instance::get_stats() const
{
    std::string out;
    out.reserve(256);

    char buf[32];
    auto append_u64 = [&](uint64_t v) {
        auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
        out.append(buf, static_cast<size_t>(ptr - buf));
    };

    out += "name:";
    out += m_name;
    out += "\ntype:";
    out += (m_type == runtime_server ? "server" :
            m_type == runtime_client ? "client" :
            m_type == runtime_proxy  ? "proxy"  :
            m_type == runtime_cache  ? "cache"  : "unknown");
    out += "\nport:";
    append_u64(m_port);
    out += "\nconnections:";
    // Not get_connection_count(): see reported_connection_count(), which is the
    // same question asked in a way that survives the runtime living in a worker.
    // A type that overrides get_stats() hands back the worker's whole text
    // before reaching here; this covers the ones that do not, and any added
    // later.
    append_u64(reported_connection_count());
    out += "\ntotal_connections:";
    append_u64(m_stat_total_connections.load(std::memory_order_relaxed));
    out += "\ntotal_messages:";
    append_u64(m_stat_total_messages.load(std::memory_order_relaxed));
    out += "\nbytes_in:";
    append_u64(m_stat_bytes_in.load(std::memory_order_relaxed));
    out += "\nbytes_out:";
    append_u64(m_stat_bytes_out.load(std::memory_order_relaxed));

    // ── How this runtime's I/O is running ───────────────────────────────────
    // Read from the loop, not from what was asked for.  A runtime whose polling
    // mode or CPU set can only be inferred from the command line that created it
    // is one nobody can debug: the kernel refuses an SQPOLL ring on some
    // configurations and a cpuset can refuse the pinning, and in both cases the
    // request and the result differ with nothing on screen to say so.
    //
    // The three fields are the ring's, so an out-of-process runtime reports its
    // worker's ring here — this string is built inside the worker and pushed —
    // which is exactly the figure that is wanted once every runtime has one.
    out += "\nsqpoll:";
    if (m_event_loop)
    {
        out += m_event_loop->sqpoll_enabled() ? "on"
             : m_event_loop->sqpoll_requested() ? "off(refused)" : "off";
        out += "\ncpus:";
        out += m_event_loop->cpus().to_string();
        if (!m_event_loop->cpus().all && !m_event_loop->affinity_applied())
            out += "(not applied)";
        out += "\nsq_thread_cpu:";
        const int sq_cpu = m_event_loop->sq_thread_cpu();
        if (sq_cpu >= 0) out += std::to_string(sq_cpu);
        else             out += "-";
    }
    else
    {
        // No loop yet — a runtime created and not started.  Saying so beats
        // printing the defaults as if they had been chosen.
        out += "unknown\ncpus:unknown\nsq_thread_cpu:-";
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

// Which of the two ways a write failed decides what to do about it.
//
// Nothing written means the message can be dropped and the stream stays intact.
// A partial write has already put a fragment on the wire, and the reader will
// splice it onto whatever comes next — that connection is finished.
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
