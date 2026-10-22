#pragma once
// Every SOCKETLEY_* variable this program reads, in one table: what it is, what it may hold, what it is for, and
// whether the daemon's configuration file may set it. Nothing reads one but through this table, and a name that is
// not in it does not compile.
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "logging.h"
#include "number_parse.h"

namespace socketley::settings
{

enum class kind : uint8_t
{
    number,
    // Unset or empty is its default; "0" turns it off, anything else on.
    flag,
    text,
};

enum class audience : uint8_t
{
    // A knob an operator may turn, in the environment or in the daemon's `settings` table.
    tuning,
    // A test's hook or shortcut, for the suite and nobody else.
    test,
    // Read by one command from the environment it is run in, never the daemon's file.
    command,
    // Which daemon and which file, so it can only come from the environment.
    bootstrap,
    // Set by the daemon for the processes it starts, and read there.
    internal,
};

struct setting
{
    std::string_view name;
    kind k;
    audience who;
    int64_t lo;
    int64_t hi;
    // What applies when it is unset, as said to whoever asks.
    std::string_view fallback;
    std::string_view meaning;
};

inline constexpr int64_t no_max = std::numeric_limits<int64_t>::max();

inline constexpr setting table[] = {
    // ─── which daemon ───
    {"SOCKETLEY_SOCKET", kind::text, audience::bootstrap, 0, 0, "/run/socketley/socketley.sock or /tmp/socketley.sock",
     "the daemon's socket, and with it its state directory"},
    {"SOCKETLEY_CONFIG", kind::text, audience::bootstrap, 0, 0, "the installed config path",
     "the daemon's configuration file"},

    // ─── the loop ───
    {"SOCKETLEY_CPUS", kind::text, audience::tuning, 0, 0, "max", "the CPUs the daemon's I/O thread may run on"},
    {"SOCKETLEY_NAPI_BUSY_POLL_US", kind::number, audience::tuning, 1, std::numeric_limits<uint32_t>::max(), "off",
     "io_uring NAPI busy polling, in microseconds"},
    {"SOCKETLEY_RECV_MULTISHOT", kind::text, audience::tuning, 0, 0, "adaptive",
     "0 turns multishot receives off, 1 arms them on every connection"},
    {"SOCKETLEY_RECV_BUNDLE", kind::flag, audience::tuning, 0, 0, "on where the kernel has it",
     "bundled receives into the provided-buffer ring"},
    {"SOCKETLEY_HUGEPAGE", kind::flag, audience::tuning, 0, 0, "on for a cache",
     "transparent huge pages for a cache worker's heap"},
    {"SOCKETLEY_TLS_FAILURE_REPORT_SECS", kind::number, audience::tuning, 1, 3600, "60",
     "how often a TLS runtime reports the handshakes that failed"},

    // ─── cache ───
    {"SOCKETLEY_CACHE_BUF_SIZE", kind::number, audience::tuning, 1024, std::numeric_limits<uint32_t>::max(), "65536",
     "bytes of each buffer in a cache's receive ring"},
    {"SOCKETLEY_CACHE_BUF_COUNT", kind::number, audience::tuning, 1, std::numeric_limits<uint32_t>::max(), "64",
     "buffers in a cache's receive ring"},
    {"SOCKETLEY_CACHE_TTL_SWEEP_MS", kind::number, audience::tuning, 1, 86400000, "500",
     "milliseconds between sweeps for expired cache keys"},

    // ─── lua ───
    {"SOCKETLEY_LUA_TIMEOUT_MS", kind::number, audience::tuning, 0, 3600000, "10000",
     "how long one Lua callback may hold the loop; 0 is unbounded"},
    {"SOCKETLEY_DNS_CACHE_MS", kind::number, audience::tuning, 0, no_max, "60000",
     "how long socketley.http() reuses a name it resolved"},

    // ─── server and proxy ───
    {"SOCKETLEY_HTTP_REVALIDATE", kind::flag, audience::tuning, 0, 0, "on",
     "a server's revalidation of the files it caches"},
    {"SOCKETLEY_PROXY_SPLICE", kind::flag, audience::tuning, 0, 0, "off",
     "splice for a tcp proxy's forwarding"},
    {"SOCKETLEY_PROXY_HTTP2", kind::flag, audience::tuning, 0, 0, "on", "HTTP/2 on a proxy's TLS listener"},
    {"SOCKETLEY_PROXY_HTTP3", kind::flag, audience::tuning, 0, 0, "on", "HTTP/3 on a proxy's TLS listener"},

    // ─── storage ───
    {"SOCKETLEY_STORAGE_HTTP2", kind::flag, audience::tuning, 0, 0, "on", "HTTP/2 on a storage runtime"},
    {"SOCKETLEY_STORAGE_HTTP3", kind::flag, audience::tuning, 0, 0, "on", "HTTP/3 on a storage runtime with TLS"},
    {"SOCKETLEY_STORAGE_HTTP3_ADVERTISE", kind::number, audience::tuning, 0, 65535, "the runtime's port",
     "the port Alt-Svc names for HTTP/3; 0 names none"},
    {"SOCKETLEY_STORAGE_HTTP3_CC", kind::text, audience::tuning, 0, 0, "bbr",
     "HTTP/3's congestion controller: bbr, cubic or reno"},
    {"SOCKETLEY_STORAGE_HTTP3_RETRY_AFTER", kind::number, audience::tuning, 0, no_max, "64",
     "QUIC handshakes under way past which a client must prove its address"},
    {"SOCKETLEY_STORAGE_SPLICE_MIN", kind::number, audience::tuning, 0, no_max, "65536",
     "the size from which a GET is spliced from its file"},
    {"SOCKETLEY_STORAGE_HOT_BYTES", kind::number, audience::tuning, 0, no_max, "33554432",
     "bytes of small objects a storage shard keeps in memory"},
    {"SOCKETLEY_STORAGE_HASH_THREADS", kind::number, audience::tuning, 0, 16, "3, fewer for many shards",
     "threads a storage worker hashes large uploads on"},
    {"SOCKETLEY_STORAGE_RECOVERY_THREADS", kind::number, audience::tuning, 1, 64, "the worker's CPUs, at most 16",
     "threads that read object headers after a stop that was not clean"},
    {"SOCKETLEY_STORAGE_RECOVERY_DEPTH", kind::number, audience::tuning, 0, 256, "32",
     "reads each of those threads keeps in flight"},
    {"SOCKETLEY_STORAGE_RECV_BUFS", kind::number, audience::tuning, 0, 4096, "64",
     "16 KiB buffers in a storage worker's receive ring, a power of two"},
    {"SOCKETLEY_STORAGE_NOTIFY_QUEUE", kind::number, audience::tuning, 1, no_max, "10000",
     "events a storage shard holds undelivered"},
    {"SOCKETLEY_STORAGE_CLUSTER_QUEUE", kind::number, audience::tuning, 1, no_max, "100000",
     "changes a storage shard queues for another node of its cluster"},
    {"SOCKETLEY_SHARE_NOTIFY_ALLOW", kind::text, audience::tuning, 0, 0, "Discord, Slack and ntfy.sh",
     "the URL prefixes a share link's webhook may begin with, comma-separated"},
    {"SOCKETLEY_FFMPEG", kind::text, audience::tuning, 0, 0, "the first ffmpeg on PATH",
     "the ffmpeg storage makes thumbnails and streams with"},
    {"SOCKETLEY_MEDIA_HWACCEL", kind::text, audience::tuning, 0, 0, "/dev/dri/renderD128",
     "where renditions are encoded: off, or a render node"},
    {"SOCKETLEY_MEDIA_CACHE_MB", kind::number, audience::tuning, 0, no_max, "10240",
     "MiB of made media past which the least asked for go"},

    // ─── cluster ───
    {"SOCKETLEY_RAFT_TICK_MS", kind::number, audience::tuning, 1, std::numeric_limits<uint32_t>::max(), "100",
     "the Raft tick of a daemon in a cluster"},
    {"SOCKETLEY_RAFT_COMPACT_EVERY", kind::number, audience::tuning, 1, no_max, "1000",
     "applied Raft entries between snapshots"},
    {"SOCKETLEY_NO_SHARD_MESH", kind::flag, audience::tuning, 0, 0, "off",
     "shards relay through the daemon instead of to each other"},
    {"SOCKETLEY_NO_PEER_LINKS", kind::flag, audience::tuning, 0, 0, "off",
     "no direct links between the daemons of a cluster"},
    {"SOCKETLEY_NO_COMPANION", kind::flag, audience::tuning, 0, 0, "off",
     "no companion process beside a unix listener"},

    // ─── acme, run as a worker's child ───
    {"SOCKETLEY_ACME_DIRECTORY", kind::text, audience::tuning, 0, 0, "Let's Encrypt", "the ACME CA's directory URL"},
    {"SOCKETLEY_ACME_CA", kind::text, audience::tuning, 0, 0, "the system's roots",
     "the roots the ACME CA's own HTTPS is checked against"},
    {"SOCKETLEY_ACME_CHALLENGE", kind::text, audience::tuning, 0, 0, "http-01",
     "the challenge acme issue answers: http-01, tls-alpn-01 or dns-01"},
    {"SOCKETLEY_ACME_DNS_WAIT", kind::number, audience::tuning, 1, 3600, "10",
     "seconds a DNS-01 answer is given to reach the zone's secondaries"},
    {"SOCKETLEY_ACME_DNS_PROBE", kind::text, audience::tuning, 0, 0, "the first nameserver of /etc/resolv.conf",
     "the resolver a DNS-01 answer is checked through, or off"},

    // ─── git-sync, given to it by the storage that runs it ───
    {"SOCKETLEY_GIT_TOKEN", kind::text, audience::command, 0, 0, "none", "a GitHub token git-sync clones with"},
    {"SOCKETLEY_GIT_ACCESS_KEY", kind::text, audience::command, 0, 0, "none", "the access key git-sync signs with"},
    {"SOCKETLEY_GIT_SECRET", kind::text, audience::command, 0, 0, "none", "that key's secret"},
    {"SOCKETLEY_GIT_SESSION_TOKEN", kind::text, audience::command, 0, 0, "none",
     "the session token of temporary credentials"},

    // ─── tests ───
    {"SOCKETLEY_STORAGE_KILL_AFTER_RENAME", kind::text, audience::test, 0, 0, "none",
     "a commit of a key with this prefix kills the worker"},
    {"SOCKETLEY_STORAGE_KILL_AFTER_EVENT", kind::text, audience::test, 0, 0, "none",
     "an event of a key with this prefix kills the worker"},
    {"SOCKETLEY_STORAGE_HOLD_CONFIRM", kind::text, audience::test, 0, 0, "none",
     "a change of a key with this prefix is never confirmed"},
    {"SOCKETLEY_STORAGE_DOC_FAULT", kind::text, audience::test, 0, 0, "none",
     "a directory of files that stop a shard at a phase of a document change"},
    {"SOCKETLEY_STORAGE_PART_LIST_MAX", kind::number, audience::test, 0, no_max, "4096",
     "bytes a multipart object's part list takes in its header"},
    {"SOCKETLEY_STORAGE_COMPACT_FLOOR", kind::number, audience::test, 0, no_max, "4096",
     "records a bucket's journal holds before it is compacted"},
    {"SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS", kind::number, audience::test, 1, 86400, "86400",
     "seconds a lifecycle rule counts as a day"},
    {"SOCKETLEY_SHARE_BURN_GRACE_SECS", kind::number, audience::test, 0, no_max / 1000, "600",
     "seconds a burnt share link's files outlive its last download"},
    {"SOCKETLEY_STORAGE_NOTIFY_HOSTS", kind::text, audience::test, 0, 0, "none",
     "a hosts file the notifier resolves names from"},
    {"SOCKETLEY_STORAGE_REPLICATION_HOSTS", kind::text, audience::test, 0, 0, "none",
     "a hosts file replication and tiering resolve names from"},
    {"SOCKETLEY_RESOLV_CONF", kind::text, audience::test, 0, 0, "/etc/resolv.conf",
     "the resolv.conf the resolver on the loop reads its nameservers from"},
    {"SOCKETLEY_MAIL_MX_PORT", kind::number, audience::test, 1, 65535, "25",
     "the port a mail runtime delivers to a domain's mail exchangers on"},
    {"SOCKETLEY_MAIL_TLS_CA", kind::text, audience::test, 0, 0, "the system's roots",
     "the CA file a mail runtime checks exchangers' certificates against"},
    {"SOCKETLEY_MAIL_STS_CA", kind::text, audience::test, 0, 0, "the system's roots",
     "the CA file a mail runtime checks an MTA-STS policy's server against"},
    {"SOCKETLEY_MAIL_STS_CONNECT", kind::text, audience::test, 0, 0, "none",
     "the host:port a mail runtime fetches every MTA-STS policy from, its name still checked"},
    {"SOCKETLEY_MAIL_DELAY_NOTICE_MS", kind::number, audience::test, 0, no_max, "14400000",
     "milliseconds a mail runtime tries a message before a sender who asked is told it is late"},
    {"SOCKETLEY_MAIL_SPOOL_MOVE_MS", kind::number, audience::test, 0, no_max, "60000",
     "milliseconds a mail spool segment is full before the few messages left in it are moved"},
    {"SOCKETLEY_MAIL_DEAD_DOMAIN_MS", kind::number, audience::test, 0, no_max, "600000",
     "milliseconds a mail runtime holds a domain found not to exist before it looks it up again"},
    {"SOCKETLEY_MAIL_SPOOL_KEEP_BYTES", kind::number, audience::test, 0, no_max, "67108864",
     "bytes of message bodies a mail spool keeps in memory beside its segments"},
    {"SOCKETLEY_STORAGE_STOP_HOLD_MS", kind::number, audience::test, 0, 3000, "0",
     "milliseconds a shard's stop holds its directory, times its shard number"},
    {"SOCKETLEY_STORAGE_START_SPIN_MS", kind::number, audience::test, 0, 30000, "0",
     "milliseconds a shard's start works before it opens its store"},
    {"SOCKETLEY_STORAGE_START_SLEEP_MS", kind::number, audience::test, 0, 60000, "0",
     "milliseconds a shard's start sleeps before it opens its store"},
    {"SOCKETLEY_STORAGE_LOG_FLUSH_MS", kind::number, audience::test, 100, 3600000, "60000",
     "milliseconds a server access log's lines are held"},
    {"SOCKETLEY_INV_PROGRESS_REPORT", kind::flag, audience::test, 0, 0, "off",
     "progress lines from the invariant checker"},

    // ─── set by the daemon for what it starts ───
    {"SOCKETLEY_LOG_LEVEL", kind::text, audience::internal, 0, 0, "the daemon's", "the log level a worker inherits"},
    {"SOCKETLEY_MANAGED", kind::flag, audience::internal, 0, 0, "off", "this process was started by a daemon"},
    {"SOCKETLEY_NAME", kind::text, audience::internal, 0, 0, "none", "the runtime this process runs"},
    {"SOCKETLEY_FAST_LO", kind::text, audience::internal, 0, 0, "none", "the loopback shortcut the daemon attached"},
};

consteval size_t index_of(std::string_view name)
{
    for (size_t i = 0; i < std::size(table); ++i)
        if (table[i].name == name)
            return i;
    // Reached only for a name the table lacks, where it stops the build.
    throw "not a setting: add it to shared/util/settings.h";
}

// A name checked against the table when the program is compiled.
struct key
{
    size_t i;
    consteval key(const char* name) : i(index_of(name)) {}
    const setting& operator*() const { return table[i]; }
    const setting* operator->() const { return &table[i]; }
};

// What the environment holds for `k`, null when it holds nothing.
inline const char* raw(key k)
{
    const char* v = std::getenv(k->name.data());
    return v && *v ? v : nullptr;
}

// Says once per process that a value was not taken, since a knob that is set and silently ignored is a lie.
inline void refused(key k, const char* value, int64_t lo, int64_t hi)
{
    static std::atomic<bool> said[std::size(table)]{};
    if (said[k.i].exchange(true))
        return;
    LOG_WARN((std::string(k->name) + "=" + value + " is not a whole number from " + std::to_string(lo) + " to " +
              std::to_string(hi) + "; " + std::string(k->fallback) + " is used")
                 .c_str());
}

// The whole number set for `k` within its range, nullopt when unset or refused.
template <class T>
std::optional<T> number(key k)
{
    const char* v = raw(k);
    if (!v)
        return std::nullopt;
    // The table's bounds, narrowed to what the reader's type holds.
    const int64_t lo = std::in_range<T>(k->lo) ? k->lo : static_cast<int64_t>(std::numeric_limits<T>::lowest());
    const int64_t hi = std::in_range<T>(k->hi) ? k->hi : static_cast<int64_t>(std::numeric_limits<T>::max());
    int64_t n = 0;
    if (!parse_whole(std::string_view(v), n) || n < lo || n > hi)
    {
        refused(k, v, lo, hi);
        return std::nullopt;
    }
    return static_cast<T>(n);
}

// Whether `k` is on, `fallback` when nothing says.
inline bool flag(key k, bool fallback)
{
    const char* v = raw(k);
    return v ? std::string_view(v) != "0" : fallback;
}

// The text set for `k`, null when unset or empty.
inline const char* text(key k)
{
    return raw(k);
}

// ─── the daemon's file and the listing ───

// The name the daemon's file writes a setting by: storage_hash_threads for SOCKETLEY_STORAGE_HASH_THREADS.
inline std::string config_name(const setting& s)
{
    std::string out(s.name.substr(std::string_view("SOCKETLEY_").size()));
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

// The setting a name in the daemon's file means, null for none.
inline const setting* by_config_name(std::string_view n)
{
    for (const setting& s : table)
        if (config_name(s) == n)
            return &s;
    return nullptr;
}

// Why `value` cannot be what `s` holds, empty when it can.
inline std::string refusal(const setting& s, std::string_view value)
{
    if (value.empty())
        return config_name(s) + " is empty";
    if (s.k == kind::number)
    {
        int64_t n = 0;
        if (!parse_whole(value, n) || n < s.lo || n > s.hi)
            return config_name(s) + " is " + std::string(value) + ", not a whole number from " + std::to_string(s.lo) +
                   " to " + std::to_string(s.hi);
    }
    if (s.k == kind::flag && value != "0" && value != "1")
        return config_name(s) + " is " + std::string(value) + ", not true or false";
    return {};
}

// Whether the daemon's file set `s`, which the listing tells apart from the environment.
inline std::atomic<bool>& from_file(const setting& s)
{
    static std::atomic<bool> set[std::size(table)]{};
    return set[static_cast<size_t>(&s - table)];
}

// Puts `value` in the environment, where the processes the daemon starts inherit it; the file outranks a variable
// the daemon was started with, which only counts for what the file leaves unset.
inline void apply(const setting& s, const std::string& value)
{
    if (::setenv(std::string(s.name).c_str(), value.c_str(), 1) == 0)
        from_file(s).store(true);
}

} // namespace socketley::settings
