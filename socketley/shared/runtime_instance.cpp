#include "runtime_instance.h"
#include "event_loop.h"
#include "lua_context.h"
#include "id_generator.h"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <unistd.h>
#include <cerrno>
#include <csignal>

runtime_instance::runtime_instance(runtime_type type, std::string_view name)
    : m_name(name), m_id(generate_runtime_id()), m_type(type), m_state(runtime_created),
      m_created_time(std::chrono::system_clock::now())
{
}

runtime_instance::~runtime_instance() = default;

void runtime_instance::tick_handler::on_cqe(struct io_uring_cqe* cqe)
{
    if (!rt) { delete this; return; }
    rt->fire_tick(cqe->res);
}

void runtime_instance::start_tick_timer()
{
    uint32_t ms = m_cb_tick_ms > 0 ? m_cb_tick_ms
                : (m_lua ? m_lua->get_tick_ms() : 100);
    if (ms < 10) ms = 10;
    m_tick = new tick_handler();
    m_tick->rt = this;
    m_tick->req = { op_timeout, -1, nullptr, 0, m_tick };
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

    if (m_external)
    {
        m_state.store(runtime_running, std::memory_order_release);
        m_start_time = std::chrono::system_clock::now();
        return true;  // skip setup(), on_start, tick timer
    }

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

    if (m_external)
    {
        if (m_pid > 0)
            kill(m_pid, SIGTERM);   // ask the external process to shut down
        m_state.store(runtime_stopped, std::memory_order_release);
        return true;  // skip teardown(), on_stop
    }

    if (m_tick) { m_tick->rt = nullptr; m_tick = nullptr; }
    invoke_on_stop();
    teardown(loop);
    m_state.store(runtime_stopped, std::memory_order_release);

    // Signal all interactive sessions that runtime has stopped
    for (int ifd : m_interactive_fds)
        (void)::write(ifd, "\0", 1);
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
        std::tm tm = *std::localtime(&time);
        std::cout << "[" << std::put_time(&tm, "%H:%M:%S") << "] ";
    }

    if (m_bash_prefix)
        std::cout << "[" << m_name << "] ";

    std::cout << msg << std::endl;
}

bool runtime_instance::load_lua_script(std::string_view path)
{
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

    m_lua.reset();
    m_lua = std::make_unique<lua_context>();

    if (!m_lua->load_script(m_lua_script_path, this))
    {
        m_lua.reset();
        return false;
    }

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
        m_lua->on_message()(std::string(msg));
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

void runtime_instance::invoke_on_send(std::string_view msg)
{
    if (!m_lua || !m_lua->has_on_send())
        return;

#ifndef SOCKETLEY_NO_LUA
    try {
        m_lua->on_send()(std::string(msg));
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
void runtime_instance::set_tick_interval(uint32_t ms)                                    { m_cb_tick_ms = ms; }

// ─── Ownership ───

void runtime_instance::set_owner(std::string_view owner_name) { m_owner = std::string(owner_name); }
std::string_view runtime_instance::get_owner() const { return m_owner; }
void runtime_instance::set_lua_created(bool v) { m_lua_created = v; }
bool runtime_instance::is_lua_created() const { return m_lua_created; }
void runtime_instance::mark_external() { m_external = true; }
bool runtime_instance::is_external() const { return m_external; }
void runtime_instance::set_pid(pid_t pid) { m_pid = pid; }
pid_t runtime_instance::get_pid() const { return m_pid; }
void runtime_instance::set_child_policy(child_policy p) { m_child_policy = p; }
runtime_instance::child_policy runtime_instance::get_child_policy() const { return m_child_policy; }

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
        m_lua->on_client_message()(client_id, std::string(msg));
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
    std::ostringstream out;
    out << "name:" << m_name << "\n"
        << "type:" << (m_type == runtime_server ? "server" :
                      m_type == runtime_client ? "client" :
                      m_type == runtime_proxy  ? "proxy"  :
                      m_type == runtime_cache  ? "cache"  : "unknown") << "\n"
        << "port:" << m_port << "\n"
        << "connections:" << get_connection_count() << "\n"
        << "total_connections:" << m_stat_total_connections.load(std::memory_order_relaxed) << "\n"
        << "total_messages:" << m_stat_total_messages.load(std::memory_order_relaxed) << "\n"
        << "bytes_in:" << m_stat_bytes_in.load(std::memory_order_relaxed) << "\n"
        << "bytes_out:" << m_stat_bytes_out.load(std::memory_order_relaxed) << "\n";
    return out.str();
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

void runtime_instance::notify_interactive(std::string_view msg) const
{
    if (m_interactive_fds.empty())
        return;

    std::string line;
    line.reserve(msg.size() + 1);
    line.append(msg.data(), msg.size());
    if (line.empty() || line.back() != '\n')
        line += '\n';

    for (size_t i = 0; i < m_interactive_fds.size(); )
    {
        ssize_t n = ::write(m_interactive_fds[i], line.data(), line.size());
        if (n < 0 && errno == EPIPE)
        {
            // Remove dead fd (const_cast is safe since we own the vector)
            auto& fds = const_cast<std::vector<int>&>(m_interactive_fds);
            fds.erase(fds.begin() + i);
        }
        else
            ++i;
    }
}
