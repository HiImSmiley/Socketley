#include "db_instance.h"

#include "db_run.h"
#include "../../shared/util/logging.h"
#include "../../shared/persist/paths.h"
#include "../../shared/runtime/runtime_manager.h"

std::string db_data_dir(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "db" / std::string(runtime_name)).string();
}

db_instance::db_instance(std::string_view name) : runtime_instance(runtime_db, name) {}

db_instance::~db_instance() = default;

std::string db_instance::config_refusal() const
{
    if (get_port() == 0)
        return "db: -p is required: the port the entrance or a client reaches the database on\n";
    if (!get_listen_path().empty())
        return "db: --listen unix: is not served; the database listens on its port\n";
    if (m_keys.empty() && m_idp.empty() && m_replicate.empty())
        return "db: a database nobody can write is no use: give --keys, --idp or both\n";
    if (!m_replicate.empty() && m_replicate_key.empty())
        return "db: --replicate needs --replicate-key, the file holding a key of the database it copies\n";
    if (!m_replicate.empty() && !m_replicate.starts_with("http://") && !m_replicate.starts_with("https://"))
        return "db: --replicate is the http or https address of the database to copy: " + m_replicate + "\n";
    if (!m_backup_dir.empty() && m_backup_every < 1)
        return "db: --backup-every is at least a second\n";
    return {};
}

void db_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool db_instance::setup(event_loop& loop)
{
    auto run = std::make_unique<socketley::db::db_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("db " + std::string(get_name()) + ": " + why).c_str());
        run->stop();
        m_graveyard.push_back(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void db_instance::teardown(event_loop&)
{
    if (m_run)
    {
        m_run->stop();
        // Kept until the ring owes it nothing, since a cancelled read still completes into it.
        m_graveyard.push_back(std::move(m_run));
    }
}

void db_instance::on_loop_turn()
{
    if (!m_graveyard.empty())
        std::erase_if(m_graveyard, [](const auto& r) { return r->drained(); });
    if (m_run)
        m_run->on_loop_turn();
}

bool db_instance::serve_deferred(uint64_t ticket, std::string_view, std::string_view payload)
{
    // A reading shard's write for shard 0, and shard 0's word that more of its log is on the disk.
    if (m_run && payload.starts_with(socketley::db::cross_marker))
    {
        m_run->cross_call(ticket, payload);
        return true;
    }
    if (m_run && payload.starts_with(socketley::db::nudge_marker))
    {
        if (auto* mgr = get_runtime_manager())
            mgr->requests().complete_deferred(ticket, request_status::ok, {});
        m_run->nudged();
        return true;
    }
    // Only what socketley.db sends; any other runtime's request is no call this database takes.
    if (!m_run || !payload.starts_with(socketley::db::call_marker))
        return false;
    m_run->call(ticket, payload.substr(socketley::db::call_marker.size()));
    return true;
}

size_t db_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string db_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

void db_instance::listen_addresses(std::vector<std::string>& out) const
{
    if (get_port())
        out.push_back("tcp:" + std::to_string(get_port()));
}

uint16_t db_instance::effective_port() const
{
    return get_port();
}
