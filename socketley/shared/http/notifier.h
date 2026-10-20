#pragma once
// Events on their way to webhooks and to the daemon's runtimes: a durable outbox per shard, and the HTTP(S) POSTs
// and requests that empty it, each on the loop and none on a request's path.  A storage runtime's buckets send theirs
// through one, and the daemon its alerts.
//
// ─── THE OUTBOX ─────────────────────────────────────────────────────────────
//   <dir>/.notify/outbox.<shard>   an entry's payload is its target's name and its JSON, each length-prefixed
//
// A change's events are synced beside the change and it is answered once both are durable, so an answered change's
// events survive a crash, and none is sent for a change a crash kept from being made (see outbox.h).
//
// A start sends again every event with no delivery record, so an event is delivered at least once.
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "outbound_http.h"
#include "../persist/outbox.h"
#include "../ipc/request_channel.h"
#include "../loop/backlog_gate.h"
#include "../loop/event_loop.h"
#include "../loop/file_io.h"
#include "../loop/hash_pool.h"

class runtime_manager;

namespace socketley
{

// Where a bucket's events may be sent, by the name its ARN gives it: a webhook, or another runtime of the daemon -- a
// cache's stream or pub/sub channel, a server that hands them to every client it has, or a broker's topic.
struct notify_target
{
    enum class kind : uint8_t { webhook, cache_stream, cache_channel, server, mqtt };
    std::string name;
    kind        k{kind::webhook};
    http_target http;
    // The runtime a target of another kind names, and the stream or channel of a cache's or the topic of a broker's.
    std::string runtime;
    std::string topic;
};

// The targets a file's text names, one `name url [ca=file]` per line with '#' starting a comment, the url a webhook's
// http(s) one or cache://<runtime>/stream/<key>, cache://<runtime>/channel/<channel>, server://<runtime> or
// mqtt://<runtime>/<topic>; false with
// `why` for a line that is none of these or a name given twice.  Nothing is resolved.
bool parse_notify_targets(std::string_view text, std::vector<notify_target>& out, std::string& why);

// The same read from `path`.
bool load_notify_targets(const std::string& path, std::vector<notify_target>& out, std::string& why);

struct notify_counters
{
    uint64_t sent{0};
    uint64_t failed{0};
    uint64_t dropped{0};
};

class notifier : public request_origin
{
public:
    // The most events a shard holds undelivered, beyond which a new one is dropped and counted.
    static constexpr size_t default_queue_max = 10000;
    // The pause after a target's first failure, doubled by each further one up to the cap.
    static constexpr int64_t backoff_first_ms = 250;
    static constexpr int64_t backoff_cap_ms   = 8000;

    // `owner` is the handler the timer's completion is delivered to, which hands it to on_timer(); `who` begins its
    // log lines and names it to a webhook.
    notifier(event_loop& loop, file_io& io, io_handler* owner, std::string who);
    ~notifier();

    notifier(const notifier&)            = delete;
    notifier& operator=(const notifier&) = delete;

    // Before set_targets(): the most events held undelivered, and the test aid's hosts file.
    void set_queue_max(size_t n) { m_queue_max = n; }
    void set_hosts_file(std::string path) { m_hosts_file = std::move(path); }
    void set_targets(std::vector<notify_target> targets);
    // Before open(): webhooks named by their URL rather than configured, each made by add_webhook() and by a start
    // that finds events for it.
    void set_dynamic() { m_dynamic = true; }
    // A webhook at `url` from now on, if there is none yet; false with `why` when the URL is not one.
    bool add_webhook(std::string_view url, std::string& why);
    // The webhooks with nothing to send and nothing sent for `idle` let go.
    void forget_idle(std::chrono::steady_clock::duration idle);
    // The daemon's runtimes a target of another runtime is reached through, and this runtime's own name, which a
    // server is told a broadcast comes from.
    void set_runtimes(runtime_manager* mgr, std::string self);
    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;
    bool has_target(std::string_view name) const;
    bool enabled() const { return !m_lanes.empty(); }

    // Opens the shard's outbox in `sub` under `dir` and queues again what it holds undelivered; blocking, so it runs
    // at start.
    bool open(const std::string& dir, std::string_view sub, uint32_t shard, const outbox::change_made& made,
              std::string& err);

    // Queues `json` for `target`, its record written with the next batch; false when it was dropped.  A broker
    // publishes it on its topic and then `sub`, kept as its retained message when `retain`, and an empty `json`
    // retained clears that.
    bool add(std::string_view target, std::string json, std::string_view sub = {}, bool retain = false);
    // Writes the events, each `{target, json}`, of a change about to be made, held back until settle(), and starts
    // their sync; returns the change's ticket, 0 when every event was dropped.
    uint64_t stage(std::string_view check, std::vector<std::pair<std::string, std::string>> events);
    // Runs `then` once the records of the change `ticket` names are synced.
    void staged(uint64_t ticket, std::function<void()> then) { m_box.staged(ticket, std::move(then)); }
    // The change was made or not: its events are queued or dropped, and `then` runs once that record is synced.
    void settle(uint64_t ticket, bool made, std::function<void()> then);
    // Runs `then` once every record added so far is synced.
    void sync(std::function<void()> then) { m_box.sync(std::move(then)); }

    // Whether `req` is the timer's, which the owner then hands to on_timer().
    bool owns(const io_request* req) const { return req == &m_timer_req; }
    void on_timer();

    // Every delivery is given up and nothing new is started.
    void stop();

    const notify_counters& counters() const { return m_c; }
    // Times a target's host was resolved, across every target.
    uint64_t resolves() const;
    // Connections made to every target, and deliveries that went on one kept from the delivery before.
    uint64_t connects() const;
    uint64_t reuses() const;
    // Events waiting for delivery, across every target.
    uint64_t queued() const { return m_queued; }

private:
    struct pending
    {
        uint64_t    id{0};
        std::string json;
        // A broker's: the topic under the target's it is published on, and whether the broker keeps it.
        std::string sub;
        bool        retain{false};
    };
    // One target's queue and the one delivery it has in flight.
    struct lane
    {
        std::string name;
        notify_target target;
        // A webhook's connection, none for a target of another runtime.
        std::unique_ptr<http_peer> peer;
        std::deque<pending> q;
        bool        busy{false};
        uint32_t    failures{0};
        std::chrono::steady_clock::time_point next_try{};
        // When an event was last queued for it, for forget_idle().
        std::chrono::steady_clock::time_point used{};
    };

    lane* find_lane(std::string_view name);
    // The lane of a webhook `t`, made and asked for its host now.
    lane& make_webhook_lane(notify_target t);
    // The resolver waited for on the loop, once; false when it cannot be.
    bool resolver_ready();
    void start(lane& l);
    // A delivery to another runtime of the daemon.
    void start_runtime(lane& l, const pending& ev);
    // The delivery at the front of the queue ended, delivered or not.
    void finish(lane& l, bool ok);
    // The event at the front of the lane was taken.
    void delivered(lane& l);
    // A delivery that did not happen is tried again after a pause that grows with each failure in a row.
    void back_off(lane& l);
    // A tick soon, which looks at every lane's deadline and pause.
    void arm_timer();

    event_loop& m_loop;
    file_io&    m_io;
    io_handler* m_owner;
    std::string m_who;
    std::string m_full_text;
    std::vector<std::unique_ptr<lane>> m_lanes;
    size_t      m_queue_max{default_queue_max};
    uint64_t    m_queued{0};
    // Says once that events are being dropped at m_queue_max, and how many when the queue is back under half.
    backlog_gate m_full;
    // The events of each change staged and not yet settled, by ticket, counted in m_queued.
    std::unordered_map<uint64_t, std::vector<std::pair<lane*, pending>>> m_staged;
    notify_counters m_c;
    bool        m_stopped{false};
    bool        m_dynamic{false};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    outbox      m_box;

    // The runtimes, the channel a cache is asked through, this runtime's name, and the lane each request out is for.
    runtime_manager* m_mgr{nullptr};
    request_channel* m_channel{nullptr};
    std::string      m_self;
    std::unordered_map<uint64_t, lane*> m_asked;
    uint64_t         m_next_cookie{0};

    // One thread that resolves hosts, its answers handed back through an eventfd the ring reads, and the test aid's
    // hosts file.
    hash_pool   m_resolver{1};
    bool        m_resolver_attached{false};
    std::string m_hosts_file;

    io_request  m_timer_req{};
    struct __kernel_timespec m_timer_ts{};
    bool        m_timer_armed{false};
};

}   // namespace socketley
