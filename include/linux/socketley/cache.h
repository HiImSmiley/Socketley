// socketley/cache.h — Cache runtime (Tier 2, requires libsocketley_sdk.a)
#pragma once
#include "core.h"
#include "socketley/runtime/cache/cache_instance.h"

namespace socketley {

// ─── High-level cache wrapper ───────────────────────────────────────────────
// Usage:
//   socketley::cache c(6379);
//   c.persistent("/tmp/cache.dat").resp();
//   c.start();
class cache {
public:
    explicit cache(uint16_t port) : m_name("_sdk_cache") {
        m_mgr.create(runtime_cache, m_name);
        auto* inst = raw();
        inst->set_port(port);
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // ── Chainable config ────────────────────────────────────────────────
    cache& persistent(std::string_view path) { cch()->set_persistent(path); return *this; }
    cache& max_memory(size_t bytes)          { cch()->set_max_memory(bytes); return *this; }
    cache& eviction(eviction_policy p)       { cch()->set_eviction(p); return *this; }
    cache& resp()                            { cch()->set_resp_forced(true); return *this; }
    cache& mode(cache_mode m)                { cch()->set_mode(m); return *this; }
    cache& tls(std::string_view cert, std::string_view key) {
        auto* i = raw(); i->set_tls(true); i->set_cert_path(cert); i->set_key_path(key); return *this;
    }
    cache& max_connections(uint32_t n)       { raw()->set_max_connections(n); return *this; }
    cache& rate_limit(double r)              { raw()->set_rate_limit(r); return *this; }
    cache& global_rate_limit(double r)       { raw()->set_global_rate_limit(r); return *this; }
    cache& idle_timeout(uint32_t s)          { raw()->set_idle_timeout(s); return *this; }
    cache& replicate(std::string_view target){ cch()->set_replicate_target(target); return *this; }
    cache& lua(std::string_view path)        { raw()->load_lua_script(path); return *this; }
    cache& group(std::string_view g)         { raw()->set_group(g); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    cache& on_start(std::function<void()> cb)      { raw()->set_on_start(std::move(cb)); return *this; }
    cache& on_stop(std::function<void()> cb)       { raw()->set_on_stop(std::move(cb)); return *this; }
    cache& on_tick(std::function<void(double)> cb) { raw()->set_on_tick(std::move(cb)); return *this; }
    cache& tick_interval(uint32_t ms)              { raw()->set_tick_interval(ms); return *this; }

    // ── In-process cache access ──────────────────────────────────────────
    // These bypass the network and operate directly on the store.
    std::string get(std::string_view key)                                         { return cch()->lua_get(key); }
    bool set(std::string_view key, std::string_view val)                          { return cch()->lua_set(key, val); }
    bool del(std::string_view key)                                                { return cch()->lua_del(key); }
    bool lpush(std::string_view key, std::string_view val)                        { return cch()->lua_lpush(key, val); }
    bool rpush(std::string_view key, std::string_view val)                        { return cch()->lua_rpush(key, val); }
    std::string lpop(std::string_view key)                                        { return cch()->lua_lpop(key); }
    std::string rpop(std::string_view key)                                        { return cch()->lua_rpop(key); }
    int llen(std::string_view key)                                                { return cch()->lua_llen(key); }
    int sadd(std::string_view key, std::string_view member)                       { return cch()->lua_sadd(key, member); }
    bool srem(std::string_view key, std::string_view member)                      { return cch()->lua_srem(key, member); }
    bool sismember(std::string_view key, std::string_view member)                 { return cch()->lua_sismember(key, member); }
    int scard(std::string_view key)                                               { return cch()->lua_scard(key); }
    bool hset(std::string_view key, std::string_view field, std::string_view val) { return cch()->lua_hset(key, field, val); }
    std::string hget(std::string_view key, std::string_view field)                { return cch()->lua_hget(key, field); }
    bool hdel(std::string_view key, std::string_view field)                       { return cch()->lua_hdel(key, field); }
    int hlen(std::string_view key)                                                { return cch()->lua_hlen(key); }
    bool expire(std::string_view key, int seconds)                                { return cch()->lua_expire(key, seconds); }
    int ttl(std::string_view key)                                                 { return cch()->lua_ttl(key); }
    bool persist(std::string_view key)                                            { return cch()->lua_persist(key); }
    int publish(std::string_view channel, std::string_view msg)                   { return cch()->publish(channel, msg); }
    uint32_t size()                                                               { return cch()->get_size(); }
    size_t memory_used()                                                          { return cch()->store_memory_used(); }

    // ── Ownership / hierarchy ───────────────────────────────────────────
    cache& owner(std::string_view name)                    { raw()->set_owner(name); return *this; }
    cache& child_policy(runtime_instance::child_policy p)  { raw()->set_child_policy(p); return *this; }

    // ── Introspection ───────────────────────────────────────────────────
    size_t           connection_count()      { return raw()->get_connection_count(); }
    runtime_state    state()                 { return raw()->get_state(); }
    std::string_view name()                  { return raw()->get_name(); }
    uint16_t         port()                  { return raw()->get_port(); }
    std::string      stats()                 { return raw()->get_stats(); }
    std::string_view id()                    { return raw()->get_id(); }
    std::string_view get_group()             { return raw()->get_group(); }
    std::string_view get_owner()             { return raw()->get_owner(); }
    bool             get_drain()             { return raw()->get_drain(); }
    bool             get_tls()               { return raw()->get_tls(); }
    std::string_view get_cert_path()         { return raw()->get_cert_path(); }
    std::string_view get_key_path()          { return raw()->get_key_path(); }
    std::string_view get_ca_path()           { return raw()->get_ca_path(); }
    std::string_view get_log_file()          { return raw()->get_log_file(); }
    uint32_t         get_max_connections()   { return raw()->get_max_connections(); }
    uint32_t         get_idle_timeout()      { return raw()->get_idle_timeout(); }
    double           get_rate_limit()        { return raw()->get_rate_limit(); }
    double           get_global_rate_limit() { return raw()->get_global_rate_limit(); }
    runtime_instance::child_policy get_child_policy() { return raw()->get_child_policy(); }
    bool             reload_lua()            { return raw()->reload_lua_script(); }
    std::string_view lua_script()            { return raw()->get_lua_script_path(); }
    cache_mode       get_mode()              { return cch()->get_mode(); }
    std::string_view get_persistent()        { return cch()->get_persistent(); }
    bool             get_resp_forced()       { return cch()->get_resp_forced(); }
    std::string_view get_replicate_target()  { return cch()->get_replicate_target(); }
    cache_instance::repl_role get_repl_role(){ return cch()->get_repl_role(); }
    size_t           get_max_memory()        { return cch()->get_max_memory(); }
    eviction_policy  get_eviction()          { return cch()->get_eviction(); }
    uint64_t         stat_commands()         { return cch()->m_stat_commands; }
    uint64_t         stat_hits()             { return cch()->m_stat_get_hits; }
    uint64_t         stat_misses()           { return cch()->m_stat_get_misses; }
    uint64_t         stat_expired()          { return cch()->m_stat_keys_expired; }
    std::chrono::system_clock::time_point created_time() { return raw()->get_created_time(); }
    std::chrono::system_clock::time_point start_time()   { return raw()->get_start_time(); }

    // ── Raw command / persistence ────────────────────────────────────────
    std::string execute(std::string_view line) { return cch()->execute(line); }
    bool flush(std::string_view path = "")     { return path.empty() ? cch()->flush_to(cch()->get_persistent()) : cch()->flush_to(path); }
    bool load(std::string_view path = "")      { return path.empty() ? cch()->load_from(cch()->get_persistent()) : cch()->load_from(path); }

    // ── Lifecycle ───────────────────────────────────────────────────────
    void start() {
        if (!m_loop.init()) return;
        detail::install_signal_handlers(&m_loop);
        m_mgr.start(m_name, m_loop);
        m_loop.run();
        m_mgr.stop_all(m_loop);
    }
    void stop() { m_loop.request_stop(); }

    // ── Escape hatches ──────────────────────────────────────────────────
    cache_instance*  instance() { return cch(); }
    runtime_manager& manager()  { return m_mgr; }
    event_loop&      loop()     { return m_loop; }

private:
    runtime_instance* raw() { return m_mgr.get(m_name); }
    cache_instance*   cch() { return static_cast<cache_instance*>(raw()); }

    std::string     m_name;
    event_loop      m_loop;
    runtime_manager m_mgr;
};

} // namespace socketley
