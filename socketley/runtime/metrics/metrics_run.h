#pragma once
// The metrics runtime's running half: its store, the one timer that is due at the next sample or the store's next
// work, this daemon's series pulled at each tick, the targets it scrapes, and the Prometheus HTTP API on its port.
//
// Every sample carries the time its tick was due, not the time it was read, so a series' samples lie exactly an
// interval apart and compress to a bit or two each.
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <linux/time_types.h>

#include "metrics_archive.h"
#include "metrics_local.h"
#include "metrics_query.h"
#include "metrics_remote.h"
#include "metrics_rules.h"
#include "metrics_scrape.h"
#include "metrics_store.h"
#include "../db/db_schema.h"
#include "../idp/idp_session.h"
#include "../../shared/http/conn_server.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"
#include "../../shared/persist/watched_file.h"

class metrics_instance;

namespace socketley::metrics
{

// A request's parameters, from its query string and a form body, in order, a name given more than once kept each time.
struct api_params
{
    std::vector<std::pair<std::string, std::string>> kv;

    // The first value of `name`, and whether there was one.
    bool get(std::string_view name, std::string_view& out) const;
    void all(std::string_view name, std::vector<std::string_view>& out) const;
    // `name=value&...` decoded and appended; false for an escape that is no escape.
    bool add_form(std::string_view form);
};

struct api_reply
{
    int status{200};
    std::string body;
    std::string_view type{"application/json"};
};

class metrics_run : public io_handler, public socketley::http::conn_hooks
{
public:
    metrics_run(metrics_instance& owner, event_loop& loop);
    ~metrics_run() override;

    bool start(std::string& why);
    void stop();
    bool drained() const;
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    size_t conn_count() const { return m_http.size(); }
    std::string stats() const;

    void on_series_feed(std::string_view payload);
    void on_runtime_map(std::string_view payload);
    // The daemon's `metrics` command: `text|json`, a newline, the API path, a newline and its form; answered under
    // `ticket` as the HTTP status, a newline and the body.
    void call(uint64_t ticket, std::string_view payload);

    // One API request answered, as JSON in Prometheus's envelope or, for the CLI, as lines to read.
    void api(std::string_view path, const api_params& p, api_reply& out, bool text);

private:
    struct request
    {
        std::string method;
        std::string path;
        std::string query;
        std::string body;
        std::string authorization;
        std::string cookie;
        std::string content_type;
    };

    std::shared_ptr<socketley::http::server_conn> make_conn() override;
    void serve(const std::shared_ptr<socketley::http::server_conn>& c) override;

    int take_request(socketley::http::server_conn& c, request& rq, int& refusal);
    void handle(const std::shared_ptr<socketley::http::server_conn>& c, request& rq);
    void respond(socketley::http::server_conn& c, int status, std::string_view type, std::string_view body);
    // Whether the request may read the store: a key's secret by Bearer or Basic, or a sign-in of the idp.
    bool admitted(const request& rq);

    // The timer, due at whichever comes first: a sample of this daemon, a target's scrape, or the store's work.
    void arm_tick();
    void tick();
    void pull_local(int64_t stamp, bool extra, int64_t now);
    // The built-in rules and --rules read again when the file changed; false with `why` when they do not read.
    bool load_rules(std::string& why);
    void on_alert(const alert_event& e);
    // A remote_write body's samples stored (--receive); false with `why` when it is no WriteRequest.
    bool receive(std::string_view body, std::string& why);
    // An alert as the dashboard and the notifications have always carried one.
    std::string alert_json(const alert_event& e) const;
public:
    // The dashboard's alerts: `{"active":[...],"recent":[...]}`, the recent newest first.
    void dashboard_alerts(std::string& out) const;
private:

    // The API's parts, in metrics_api.cpp.
    void api_query(const api_params& p, api_reply& out, bool text, bool range);
    void api_series(const api_params& p, api_reply& out, bool text);
    void api_labels(const api_params& p, api_reply& out, std::string_view name);
    void api_metadata(const api_params& p, api_reply& out);
    void api_targets(api_reply& out, bool text);
    void api_stats(api_reply& out, bool text);
    void self_metrics(api_reply& out);
    // The ids every match[] selects in [mint, maxt], false with the reply filled in when one does not parse.
    bool matched(const api_params& p, int64_t mint, int64_t maxt, std::vector<uint32_t>& ids, api_reply& out,
                 bool& any);
    bool time_range(const api_params& p, int64_t& mint, int64_t& maxt, api_reply& out);

    metrics_instance& m_owner;
    event_loop& m_loop;
    file_io m_io;
    socketley::http::conn_server m_http;
    // The thread a target's host is resolved on, started by its first name.
    hash_pool m_resolver{1};
    store m_store;
    query_engine m_engine;
    local_feed m_local;
    scraper m_scrape;
    archiver m_archive;
    int64_t m_archive_due{INT64_MAX};
    uint64_t m_blocks_seen{0};
    std::unique_ptr<rule_engine> m_rules;
    remote::write_decoder m_remote;
    std::optional<socketley::file_stamp> m_rules_stamp;
    std::optional<socketley::file_stamp> m_rules_refused;
    int64_t m_rules_due{0};
    int64_t m_rules_checked{0};
    // The notifications of late, kept for the dashboard.
    struct told
    {
        int64_t at;
        bool raised;
        std::string alert;
    };
    std::deque<told> m_recent;
    static constexpr size_t max_recent = 50;
    // This machine's name, which a notification of an alert over its own series begins with.
    std::string m_host;
    socketley::idp::session_verifier m_idp;
    socketley::watched<std::vector<socketley::db::service_key>> m_keys;
    int64_t m_keys_checked{0};

    int64_t m_every_ms{10'000};
    int64_t m_local_next{0};
    // A lifecycle change seen while a pull for one was still out, asked again once it is answered.
    bool m_extra_owed{false};
    int64_t m_store_due{0};
    int64_t m_started_ms{0};

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};
    int64_t m_tick_at{0};
    bool m_stopped{false};
    bool m_opened{false};

    struct counters
    {
        uint64_t requests{0}, queries{0}, refused{0}, unauthorized{0}, ticks{0}, received{0}, received_refused{0};
    } m_c;
};

}   // namespace socketley::metrics
