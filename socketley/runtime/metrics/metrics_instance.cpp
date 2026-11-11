#include "metrics_instance.h"

#include "metrics_query.h"
#include "metrics_run.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/persist/paths.h"
#include "../../shared/runtime/runtime_manager.h"

namespace socketley::metrics
{

bool parse_downsample(std::string_view text, std::vector<std::pair<int64_t, int64_t>>& tiers, std::string& why)
{
    tiers.clear();
    if (text.empty() || text == "none")
        return true;
    constexpr int64_t two_hours = 2 * 3600 * 1000, day = 24 * 3600 * 1000;
    for (std::string_view list = text; !list.empty();)
    {
        const std::string_view one = take_item(list);
        const size_t colon = one.find(':');
        int64_t step = 0, keep = 0;
        if (colon == std::string_view::npos || !parse_duration(one.substr(0, colon), step) ||
            !parse_duration(one.substr(colon + 1), keep) || step < 1000 || keep <= step)
            return why = "each tier is step:keep, such as 5m:1y, the step at least a second and below the keep", false;
        if (tiers.empty() && two_hours % step != 0)
            return why = "the first tier's step must divide two hours, as 5m or 10m does", false;
        if (!tiers.empty() && (step <= tiers.back().first || step % tiers.back().first != 0 || day % step != 0))
            return why = "each later tier's step is a larger multiple of the one before and divides a day, as 1h does",
                   false;
        tiers.emplace_back(step, keep);
    }
    if (tiers.size() > 8)
        return why = "at most eight tiers", false;
    return true;
}

}   // namespace socketley::metrics

bool socketley::metrics::parse_notify(std::string_view text, uint8_t& mask)
{
    if (text.empty())
        return mask = notify_webhook | notify_mail | notify_events, true;
    mask = 0;
    if (text == "none")
        return true;
    while (!text.empty())
    {
        const size_t c = text.find(',');
        const std::string_view w = text.substr(0, c);
        if (w == "webhook")
            mask |= notify_webhook;
        else if (w == "mail")
            mask |= notify_mail;
        else if (w == "events")
            mask |= notify_events;
        else
            return false;
        text = c == std::string_view::npos ? std::string_view{} : text.substr(c + 1);
    }
    return mask != 0;
}

std::string metrics_data_dir(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "metrics" / std::string(runtime_name)).string();
}

metrics_instance::metrics_instance(std::string_view name) : runtime_instance(runtime_metrics, name) {}

metrics_instance::~metrics_instance() = default;

std::string metrics_instance::config_refusal() const
{
    if (!get_listen_path().empty())
        return "metrics: --listen unix: is not served; the API listens on its port\n";
    if (m_c.every < 1 || m_c.every > 3600)
        return "metrics: --every is from 1s to 1h\n";
    if (m_c.keep < 3600)
        return "metrics: --keep is at least 1h\n";
    if (m_c.logs_keep < 3600)
        return "metrics: --logs-keep is at least 1h\n";
    std::vector<std::pair<int64_t, int64_t>> tiers;
    if (std::string why; !socketley::metrics::parse_downsample(m_c.downsample, tiers, why))
        return "metrics: --downsample " + m_c.downsample + ": " + why + "\n";
    if (m_c.max_series < 1)
        return "metrics: --max-series is at least 1\n";
    // A port open to the network answers every query to anybody, so it is guarded or it is loopback alone.
    if (!guarded() && !get_bind_address().empty() && get_bind_address() != "127.0.0.1")
        return "metrics: --bind " + std::string(get_bind_address()) +
               " opens the API to the network; give --keys or --idp to guard it\n";
    if (!m_c.scrape.empty() && m_c.scrape.front() != '/')
        return "metrics: --scrape is an absolute path\n";
    if (!m_c.rules.empty() && m_c.rules.front() != '/')
        return "metrics: --rules is an absolute path\n";
    if (!m_c.archive.empty() && m_c.archive_credentials.empty())
        return "metrics: --archive needs --archive-credentials, the file of the bucket's keys\n";
    if (!m_c.archive_credentials.empty() && m_c.archive_credentials.front() != '/')
        return "metrics: --archive-credentials is an absolute path\n";
    if (uint8_t m = 0; !socketley::metrics::parse_notify(m_c.notify, m))
        return "metrics: --notify is webhook, mail and events, a comma between, or none\n";
    return {};
}

void metrics_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool metrics_instance::setup(event_loop& loop)
{
    m_graveyard.reap();
    // A store waits on its tick and the disk, so a spin finds nothing and only spends CPU.
    loop.set_busy_spin(false);
    auto run = std::make_unique<socketley::metrics::metrics_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("metrics " + std::string(get_name()) + ": " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void metrics_instance::teardown(event_loop&)
{
    m_graveyard.retire(std::move(m_run));
}

bool metrics_instance::runs_drained()
{
    return m_graveyard.drain();
}

void metrics_instance::on_loop_turn()
{
    m_graveyard.reap();
    if (m_run)
        m_run->on_loop_turn();
}

size_t metrics_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string metrics_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

bool metrics_instance::serve_deferred(uint64_t ticket, std::string_view, std::string_view payload)
{
    // Only what the daemon's `metrics` command sends; any other runtime's request is no call this runtime takes.
    if (!m_run || !payload.starts_with(socketley::metrics::call_marker))
        return false;
    m_run->call(ticket, payload.substr(socketley::metrics::call_marker.size()));
    return true;
}

void metrics_instance::listen_addresses(std::vector<std::string>& out) const
{
    out.push_back("tcp:" + std::to_string(effective_port()));
}

uint16_t metrics_instance::effective_port() const
{
    return get_port() ? get_port() : socketley::metrics::default_port;
}

void metrics_instance::on_series_feed(std::string_view payload)
{
    if (m_run)
        m_run->on_series_feed(payload);
}

void metrics_instance::on_runtime_map(std::string_view payload)
{
    if (m_run)
        m_run->on_runtime_map(payload);
}
