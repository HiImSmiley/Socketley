#pragma once
// The metrics runtime: a time-series store of this daemon's own series, taken without text, and of the Prometheus
// endpoints it scrapes, answered with PromQL over the Prometheus HTTP API, so Grafana reads it as a Prometheus.
//
// It serves plain HTTP on 127.0.0.1 unless --keys or --idp guard it, and is reached through the entrance proxy, which
// terminates TLS for it as for every other name.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../shared/ipc/request_channel.h"
#include "../../shared/runtime/runtime_instance.h"
#include "shared/runtime/retired_runs.h"

namespace socketley::metrics
{
class metrics_run;

// The marker a CLI command from the daemon begins with, so no other runtime's request is taken for one.
inline constexpr std::string_view call_marker = "\x1fmetrics\x1f";

// The port a metrics runtime listens on when -p is not given, Prometheus's own.
inline constexpr uint16_t default_port = 9090;

// `5m:1y,1h:5y` as (step, keep) pairs in milliseconds, `none` as no tier; false with `why` when it is not one.
bool parse_downsample(std::string_view text, std::vector<std::pair<int64_t, int64_t>>& tiers, std::string& why);

// Where --notify sends an alert: the daemon's alert_webhook, its alert_mail, its events broker.
inline constexpr uint8_t notify_webhook = 1, notify_mail = 2, notify_events = 4;
// `webhook,mail,events` as a mask, empty for all three and `none` for nothing; false for another word.
bool parse_notify(std::string_view text, uint8_t& mask);
inline uint8_t notify_mask(std::string_view text)
{
    uint8_t m = 0;
    return parse_notify(text, m) ? m : 0;
}
}   // namespace socketley::metrics

// <state>/metrics/<name>/, the store's blocks and head.
std::string metrics_data_dir(std::string_view runtime_name);

class metrics_instance : public runtime_instance, public deferred_request_sink
{
public:
    explicit metrics_instance(std::string_view name);
    ~metrics_instance() override;

    // The file of service keys (--keys), `name secret` a line, read again when it changes.
    void set_keys_path(std::string_view p) { m_c.keys = std::string(p); }
    std::string_view get_keys_path() const { return m_c.keys; }
    // The idp runtime whose sign-ins and access tokens are let in (--idp), and the clients whose tokens are taken.
    void set_idp(std::string_view name) { m_c.idp = std::string(name); }
    std::string_view get_idp() const { return m_c.idp; }
    void set_idp_audience(std::string_view list) { m_c.idp_audience = std::string(list); }
    std::string_view get_idp_audience() const { return m_c.idp_audience; }

    // This daemon's own series, fed without text (--local, the default; --no-local).
    void set_local(bool on) { m_c.local = on; }
    bool get_local() const { return m_c.local; }
    // The file of targets to scrape (--scrape), `name url [every=dur] [timeout=dur] [label=value ...]` a line.
    void set_scrape_path(std::string_view p) { m_c.scrape = std::string(p); }
    std::string_view get_scrape_path() const { return m_c.scrape; }
    // Seconds between two samples (--every), a target's own every= aside.
    void set_every(uint32_t s) { m_c.every = s; }
    uint32_t get_every() const { return m_c.every; }
    // Seconds raw samples are kept (--keep).
    void set_keep(uint64_t s) { m_c.keep = s; }
    uint64_t get_keep() const { return m_c.keep; }
    // The coarser tiers (--downsample), `step:keep` a comma between each, or `none`.
    void set_downsample(std::string_view d) { m_c.downsample = std::string(d); }
    std::string_view get_downsample() const { return m_c.downsample; }
    // The most series the head holds before a new one is refused (--max-series).
    void set_max_series(uint32_t n) { m_c.max_series = n; }
    uint32_t get_max_series() const { return m_c.max_series; }
    // Every sample logged as it comes, so a crash loses none (--durable).
    void set_durable(bool on) { m_c.durable = on; }
    bool get_durable() const { return m_c.durable; }

    // The rules, where their notifications go, and whether remote_write is taken.
    void set_rules_path(std::string_view p) { m_c.rules = std::string(p); }
    std::string_view get_rules_path() const { return m_c.rules; }
    void set_notify(std::string_view n) { m_c.notify = std::string(n); }
    std::string_view get_notify() const { return m_c.notify; }
    void set_receive(bool on) { m_c.receive = on; }
    bool get_receive() const { return m_c.receive; }
    // The daemon's log lines kept too (--logs), and for how many seconds (--logs-keep).
    void set_logs(bool on) { m_c.logs = on; }
    bool get_logs() const { return m_c.logs; }
    void set_logs_keep(uint64_t s) { m_c.logs_keep = s; }
    uint64_t get_logs_keep() const { return m_c.logs_keep; }
    // An S3 bucket and prefix every finished block is copied to (--archive), and the credentials it is signed with.
    void set_archive(std::string_view u) { m_c.archive = std::string(u); }
    std::string_view get_archive() const { return m_c.archive; }
    void set_archive_credentials(std::string_view p) { m_c.archive_credentials = std::string(p); }
    std::string_view get_archive_credentials() const { return m_c.archive_credentials; }

    // Whether anything guards the API, without which it binds 127.0.0.1 alone.
    bool guarded() const { return !m_c.keys.empty() || !m_c.idp.empty(); }

    // Every setting of its own at once, for an edit that is undone when a later flag of it is refused.
    struct settings
    {
        std::string keys;
        std::string idp;
        std::string idp_audience;
        bool local{true};
        std::string scrape;
        uint32_t every{10};
        uint64_t keep{30ull * 86400};
        std::string downsample{"5m:1y,1h:5y"};
        uint32_t max_series{200'000};
        bool durable{false};
        std::string rules;
        std::string notify;
        bool receive{false};
        std::string archive;
        std::string archive_credentials;
        bool logs{false};
        uint64_t logs_keep{14ull * 86400};
    };
    const settings& get_settings() const { return m_c; }
    void set_settings(const settings& s) { m_c = s; }

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;

    // A CLI command reaches the worker as a request on the channel, answered at once.
    request_sink* as_request_sink() override { return sink_or(this); }
    bool serve_deferred(uint64_t ticket, std::string_view target, std::string_view payload) override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    void on_series_feed(std::string_view payload) override;
    void on_runtime_map(std::string_view payload) override;

private:
    settings m_c;

    std::unique_ptr<socketley::metrics::metrics_run> m_run;
    // Runs stopped but still owed completions by the ring.
    socketley::retired_runs<socketley::metrics::metrics_run> m_graveyard;
};
