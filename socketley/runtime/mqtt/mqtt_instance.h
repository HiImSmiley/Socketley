#pragma once
// The mqtt runtime: a broker for MQTT 3.1, 3.1.1 and 5.0 on TCP, TLS and WebSocket, whose sessions outlive their
// connections and a restart, and whose messages reach a cache, a db, a storage or a server by topic rules.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/ipc/request_channel.h"
#include "../../shared/runtime/retired_runs.h"
#include "../../shared/runtime/runtime_instance.h"

namespace socketley::mqtt
{
class mqtt_run;
}   // namespace socketley::mqtt

// <state>/mqtt/<name>.snapshot, where --persistent is not given a file of its own.
std::string mqtt_default_snapshot(std::string_view runtime_name);
// Those snapshots removed, a shard's included, so a broker made again under the name starts empty.
void mqtt_forget_snapshots(std::string_view runtime_name);

class mqtt_instance : public runtime_instance, public deferred_request_sink
{
public:
    explicit mqtt_instance(std::string_view name);
    ~mqtt_instance() override;

    void set_users(std::string_view path) { m_users = std::string(path); }
    std::string_view get_users() const { return m_users; }
    void set_idp(std::string_view runtime) { m_idp = std::string(runtime); }
    std::string_view get_idp() const { return m_idp; }
    // The clients of the idp whose access tokens are taken (--idp-audience), comma-separated.
    void set_idp_audience(std::string_view list) { m_idp_audience = std::string(list); }
    std::string_view get_idp_audience() const { return m_idp_audience; }
    void set_acl(std::string_view path) { m_acl = std::string(path); }
    std::string_view get_acl() const { return m_acl; }
    void set_routes(std::string_view path) { m_routes = std::string(path); }
    std::string_view get_routes() const { return m_routes; }
    void set_anonymous(bool on) { m_anonymous = on; }
    bool get_anonymous() const { return m_anonymous; }
    // The port browsers reach it on over WebSocket, 0 for none.
    void set_ws_port(uint16_t p) { m_ws_port = p; }
    uint16_t get_ws_port() const { return m_ws_port; }
    void set_max_packet(uint32_t n) { m_max_packet = n; }
    uint32_t get_max_packet() const { return m_max_packet; }
    // The longest a session outlives its connection, in seconds.
    void set_session_expiry(uint32_t s) { m_session_expiry = s; }
    uint32_t get_session_expiry() const { return m_session_expiry; }
    void set_session_queue(uint32_t n) { m_session_queue = n; }
    uint32_t get_session_queue() const { return m_session_queue; }
    void set_retained_max(uint64_t bytes) { m_retained_max = bytes; }
    uint64_t get_retained_max() const { return m_retained_max; }
    void set_max_sessions(uint32_t n) { m_max_sessions = n; }
    uint32_t get_max_sessions() const { return m_max_sessions; }
    void set_keepalive_max(uint16_t s) { m_keepalive_max = s; }
    uint16_t get_keepalive_max() const { return m_keepalive_max; }
    // --persistent: the snapshot file, "on" for the default one under the state directory.
    void set_persistent(std::string_view path) { m_persistent = std::string(path); }
    std::string_view get_persistent() const { return m_persistent; }
    std::string snapshot_path() const;
    void set_persist_interval(uint32_t secs) { m_persist_interval = secs; }
    uint32_t get_persist_interval() const { return m_persist_interval; }

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;

    // `socketley mqtt-*`, socketley.mqtt.publish and a storage's mqtt:// notifications reach the worker as requests
    // on the channel, answered on a later turn.
    request_sink* as_request_sink() override { return sink_or(this); }
    bool serve_deferred(uint64_t ticket, std::string_view target, std::string_view payload) override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    socketley::mqtt::mqtt_run* run() const { return m_run.get(); }

private:
    std::string m_users;
    std::string m_idp;
    std::string m_idp_audience;
    std::string m_acl;
    std::string m_routes;
    bool        m_anonymous{false};
    uint16_t    m_ws_port{0};
    uint32_t    m_max_packet{256u << 10};
    uint32_t    m_session_expiry{86400};
    uint32_t    m_session_queue{1000};
    uint64_t    m_retained_max{64u << 20};
    uint32_t    m_max_sessions{100000};
    uint16_t    m_keepalive_max{1200};
    std::string m_persistent;
    uint32_t    m_persist_interval{1};

    std::unique_ptr<socketley::mqtt::mqtt_run> m_run;
    socketley::retired_runs<socketley::mqtt::mqtt_run> m_graveyard;
};
