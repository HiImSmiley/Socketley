#include "mqtt_instance.h"

#include <algorithm>
#include <filesystem>

#include "mqtt_command.h"
#include "mqtt_run.h"
#include "../../shared/persist/paths.h"
#include "../../shared/util/logging.h"

std::string mqtt_default_snapshot(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "mqtt" / (std::string(runtime_name) + ".snapshot")).string();
}

void mqtt_forget_snapshots(std::string_view runtime_name)
{
    const std::filesystem::path base(mqtt_default_snapshot(runtime_name));
    const std::string stem = base.filename().string();
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(base.parent_path(), ec))
    {
        const std::string f = e.path().filename().string();
        const std::string_view rest = std::string_view(f).substr(std::min(f.size(), stem.size()));
        // The file itself, a shard's ".<n>", and a write a crash left as ".tmp".
        const bool ours = f.starts_with(stem) &&
                          (rest.empty() || (rest.front() == '.' && rest.size() > 1 &&
                                            (rest.find_first_not_of("0123456789", 1) == std::string_view::npos ||
                                             rest.ends_with(".tmp"))));
        if (ours)
            std::filesystem::remove(e.path(), ec);
    }
}

mqtt_instance::mqtt_instance(std::string_view name) : runtime_instance(runtime_mqtt, name) {}

mqtt_instance::~mqtt_instance() = default;

std::string mqtt_instance::snapshot_path() const
{
    if (m_persistent.empty())
        return {};
    // A shard of several keeps its own file, since each holds the sessions of the clients connected to it.
    std::string path = m_persistent == "on" ? mqtt_default_snapshot(get_name()) : m_persistent;
    if (get_shards() > 1)
        path += "." + std::to_string(get_shard_index());
    return path;
}

std::string mqtt_instance::config_refusal() const
{
    if (m_users.empty() && m_idp.empty() && get_ca_path().empty() && !m_anonymous)
        return "mqtt: say who may connect: --users <file>, --idp <runtime>, --ca <file> for client certificates, "
               "or --anonymous\n";
    if (!get_ca_path().empty() && !get_tls())
        return "mqtt: --ca verifies client certificates, which needs --tls\n";
    if (!get_listen_path().empty())
        return "mqtt: --listen unix: is not served; the broker listens on its port\n";
    if (m_ws_port && m_ws_port == effective_port())
        return "mqtt: --ws needs a port of its own, not the MQTT port " + std::to_string(m_ws_port) + "\n";
    if (m_max_packet < 64)
        return "mqtt: --max-packet below 64 bytes takes no CONNECT\n";
    return {};
}

void mqtt_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool mqtt_instance::setup(event_loop& loop)
{
    m_graveyard.reap();
    auto run = std::make_unique<socketley::mqtt::mqtt_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("mqtt " + std::string(get_name()) + ": " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void mqtt_instance::teardown(event_loop&)
{
    m_graveyard.retire(std::move(m_run));
}

bool mqtt_instance::runs_drained()
{
    return m_graveyard.drain();
}

void mqtt_instance::on_loop_turn()
{
    m_graveyard.reap();
    if (m_run)
        m_run->on_loop_turn();
}

bool mqtt_instance::serve_deferred(uint64_t ticket, std::string_view, std::string_view payload)
{
    if (m_run && payload.starts_with(socketley::mqtt::shard_prefix))
    {
        m_run->shard_request(ticket, payload);
        return true;
    }
    // Only the CLI's, a script's and a notification's commands; any other runtime's request is none this takes.
    if (!m_run || !payload.starts_with(socketley::mqtt::command_prefix))
        return false;
    m_run->command(ticket, payload);
    return true;
}

size_t mqtt_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string mqtt_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

void mqtt_instance::listen_addresses(std::vector<std::string>& out) const
{
    out.push_back("tcp:" + std::to_string(effective_port()));
    if (m_ws_port)
        out.push_back("tcp:" + std::to_string(m_ws_port));
}

uint16_t mqtt_instance::effective_port() const
{
    if (get_port())
        return get_port();
    return get_tls() ? 8883 : 1883;
}
