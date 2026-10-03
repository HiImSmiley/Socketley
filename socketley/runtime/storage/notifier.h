#pragma once
// The events of a storage runtime's buckets on their way to webhooks: a durable outbox per shard, and the HTTP(S)
// POSTs that empty it, each on the loop and none on a request's path.
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
#include "outbox.h"
#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"

namespace socketley::storage
{

// A webhook a bucket's events may be sent to, by the name its ARN gives it.
struct notify_target
{
    std::string name;
    http_target http;
};

// The targets a file's text names, one `name url [ca=file]` per line with '#' starting a comment; false with `why`
// for a line that is none of these or a name given twice.  Nothing is resolved.
bool parse_notify_targets(std::string_view text, std::vector<notify_target>& out, std::string& why);

// The same read from `path`.
bool load_notify_targets(const std::string& path, std::vector<notify_target>& out, std::string& why);

struct notify_counters
{
    uint64_t sent{0};
    uint64_t failed{0};
    uint64_t dropped{0};
};

class notifier
{
public:
    // The most events a shard holds undelivered, beyond which a new one is dropped and counted.
    static constexpr size_t default_queue_max = 10000;
    // The pause after a target's first failure, doubled by each further one up to the cap.
    static constexpr int64_t backoff_first_ms = 250;
    static constexpr int64_t backoff_cap_ms   = 8000;

    // `owner` is the handler the timer's completion is delivered to, which hands it to on_timer().
    notifier(event_loop& loop, file_io& io, io_handler* owner);
    ~notifier();

    notifier(const notifier&)            = delete;
    notifier& operator=(const notifier&) = delete;

    void set_targets(std::vector<notify_target> targets);
    bool has_target(std::string_view name) const;
    bool enabled() const { return !m_lanes.empty(); }

    // Opens the shard's outbox under `dir` and queues again what it holds undelivered; blocking, so it runs at start.
    bool open(const std::string& dir, uint32_t shard, const outbox::change_made& made, std::string& err);

    // Queues `json` for `target`, its record written with the next batch; false when it was dropped.
    bool add(std::string_view target, std::string json);
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
    };
    // One target's queue and the one delivery it has in flight.
    struct lane
    {
        std::string name;
        std::unique_ptr<http_peer> peer;
        std::deque<pending> q;
        bool        busy{false};
        uint32_t    failures{0};
        std::chrono::steady_clock::time_point next_try{};
    };

    lane* find_lane(std::string_view name);
    void start(lane& l);
    // The delivery at the front of the queue ended, delivered or not.
    void finish(lane& l, bool delivered);
    // A delivery that did not happen is tried again after a pause that grows with each failure in a row.
    void back_off(lane& l);
    // A tick soon, which looks at every lane's deadline and pause.
    void arm_timer();

    event_loop& m_loop;
    file_io&    m_io;
    io_handler* m_owner;
    std::vector<std::unique_ptr<lane>> m_lanes;
    size_t      m_queue_max{default_queue_max};
    uint64_t    m_queued{0};
    // The events of each change staged and not yet settled, by ticket, counted in m_queued.
    std::unordered_map<uint64_t, std::vector<std::pair<lane*, pending>>> m_staged;
    notify_counters m_c;
    bool        m_stopped{false};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    outbox      m_box;

    // One thread that resolves hosts, its answers handed back through an eventfd the ring reads, and the test aid's
    // hosts file (SOCKETLEY_STORAGE_NOTIFY_HOSTS).
    hash_pool   m_resolver{1};
    std::string m_hosts_file;

    io_request  m_timer_req{};
    struct __kernel_timespec m_timer_ts{};
    bool        m_timer_armed{false};
};

}   // namespace socketley::storage
