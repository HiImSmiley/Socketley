#pragma once
// The events of a storage runtime's buckets on their way to webhooks: a durable outbox per shard, and the HTTP(S)
// POSTs that empty it, each on the loop and none on a request's path.
//
// ─── THE OUTBOX ─────────────────────────────────────────────────────────────
//   <dir>/.notify/outbox.<shard>   records `u32 length | u32 crc32 | payload`, the payload an event ('E', its id,
//                                  its target and its JSON) or the delivery of one ('D', its id)
//
// An event's record is synced before the change it is about is answered, so an answered change's event survives a
// crash; a start sends again every event with no delivery record, so an event is delivered at least once.
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>

#include "../../shared/event_loop.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"
#include "../../shared/tls_context.h"

namespace socketley::storage
{

// A webhook a bucket's events may be sent to, by the name its ARN gives it.
struct notify_target
{
    std::string name;
    std::string url;
    bool        tls{false};
    std::string host;
    uint16_t    port{0};
    std::string path;
    // The CA an https target's certificate is checked against, the system's when empty.
    std::string ca_file;
};

// The targets a file's text names, one `name url [ca=file]` per line with '#' starting a comment; false with `why`
// for a line that is none of these or a name given twice.  Nothing is resolved.
bool parse_notify_targets(std::string_view text, std::vector<notify_target>& out, std::string& why);

// The same read from `path`.
bool load_notify_targets(const std::string& path, std::vector<notify_target>& out, std::string& why);

// One address a host resolved to.
struct notify_endpoint
{
    struct sockaddr_storage addr{};
    socklen_t len{0};
};

// The addresses `host` has, in the order the resolver gives them, a name in `hosts_file` (`name address` lines, a
// test aid) before the system's; blocking, so it runs on the resolver thread.
std::vector<notify_endpoint> resolve_notify_host(const std::string& host, uint16_t port, const std::string& hosts_file);

struct notify_counters
{
    uint64_t sent{0};
    uint64_t failed{0};
    uint64_t dropped{0};
    uint64_t resolves{0};
};

class notifier
{
public:
    // The most events a shard holds undelivered, beyond which a new one is dropped and counted.
    static constexpr size_t default_queue_max = 10000;
    // A POST that has not been answered in this long has failed.
    static constexpr int attempt_secs = 10;
    // The pause after a target's first failure, doubled by each further one up to the cap.
    static constexpr int64_t backoff_first_ms = 250;
    static constexpr int64_t backoff_cap_ms   = 8000;
    // A host's addresses are asked for again this often while it is delivered to, and at once after every address
    // it had refused a connection, but not twice within the floor.
    static constexpr int resolve_every_secs = 60;
    static constexpr int resolve_floor_ms   = 1000;

    // `owner` is the handler the timer's completion is delivered to, which hands it to on_timer().
    notifier(event_loop& loop, file_io& io, io_handler* owner);
    ~notifier();

    notifier(const notifier&)            = delete;
    notifier& operator=(const notifier&) = delete;

    void set_targets(std::vector<notify_target> targets);
    bool has_target(std::string_view name) const;
    bool enabled() const { return !m_lanes.empty(); }

    // Opens the shard's outbox under `dir` and queues again what it holds undelivered; blocking, so it runs at start.
    bool open(const std::string& dir, uint32_t shard, std::string& err);

    // Queues `json` for `target`, its record written with the next batch; false when it was dropped.
    bool add(std::string_view target, std::string json);
    // Runs `then` once every record added so far is synced.
    void sync(std::function<void()> then);

    // Whether `req` is the timer's, which the owner then hands to on_timer().
    bool owns(const io_request* req) const { return req == &m_timer_req; }
    void on_timer();

    // Every delivery is given up and nothing new is started.
    void stop();

    const notify_counters& counters() const { return m_c; }
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
        notify_target target;
        std::unique_ptr<tls_context> tls;
        // The host's addresses and the one tried next; a literal address is its own and never resolved.
        std::vector<notify_endpoint> addrs;
        size_t      cur{0};
        bool        literal{false};
        bool        resolving{false};
        std::chrono::steady_clock::time_point resolved_at{};
        std::deque<pending> q;
        // Bumped at the end of each attempt, so a completion of an earlier one is told from the current one's.
        uint64_t    gen{0};
        bool        busy{false};
        int         fd{-1};
        SSL*        ssl{nullptr};
        bool        handshaken{false};
        bool        request_given{false};
        bool        wrote_request{false};
        std::string response;
        uint32_t    failures{0};
        std::chrono::steady_clock::time_point deadline{};
        std::chrono::steady_clock::time_point next_try{};
    };

    lane* find_lane(std::string_view name);
    // Asks the resolver thread for the host's addresses unless it was asked within the floor; false when it cannot be asked.
    bool resolve(lane& l);
    void resolved(lane& l, std::vector<notify_endpoint> addrs);
    // A delivery that did not happen is tried again after a pause that grows with each failure in a row.
    void back_off(lane& l);
    void start(lane& l);
    void connected(lane& l, int64_t res);
    // The next step of an attempt: what is owed to the socket is written, or else the answer is read.
    void advance(lane& l);
    void send(lane& l, std::string bytes);
    void receive(lane& l);
    void got(lane& l, const char* p, size_t n);
    // The attempt ends here, delivered or not; true when what was read is a complete 2xx answer.
    void finish(lane& l, bool delivered);
    // A complete answer's status, 0 while the head has not all arrived.
    static int response_status(std::string_view r);
    // A tick soon, which looks at every lane's deadline and pause.
    void arm_timer();

    void append_record(char type, uint64_t id, std::string_view target, std::string_view json);
    void kick();
    void written(int64_t res, std::shared_ptr<std::string> buf, std::vector<std::function<void()>> cbs);
    void maybe_rotate();

    event_loop& m_loop;
    file_io&    m_io;
    io_handler* m_owner;
    std::vector<std::unique_ptr<lane>> m_lanes;
    size_t      m_queue_max{default_queue_max};
    uint64_t    m_queued{0};
    uint64_t    m_next_id{1};
    notify_counters m_c;
    bool        m_stopped{false};
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};

    // The outbox: its directory and file, where the next record goes, and what waits to be written and synced.
    int         m_dir_fd{-1};
    int         m_fd{-1};
    std::string m_name;
    uint64_t    m_off{0};
    std::string m_buf;
    std::vector<std::function<void()>> m_buf_cbs;
    bool        m_writing{false};
    bool        m_rotating{false};
    bool        m_write_failed{false};

    // One thread that resolves hosts, its answers handed back through an eventfd the ring reads, and the test aid's
    // hosts file (SOCKETLEY_STORAGE_NOTIFY_HOSTS).
    hash_pool   m_resolver{1};
    std::string m_hosts_file;

    io_request  m_timer_req{};
    struct __kernel_timespec m_timer_ts{};
    bool        m_timer_armed{false};
};

}   // namespace socketley::storage
