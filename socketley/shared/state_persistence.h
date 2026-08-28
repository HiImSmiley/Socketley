#pragma once
#include <string>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include <string_view>
#include <vector>
#include <filesystem>
#include <cstdint>

#include "runtime_definitions.h"

namespace sp_detail
{
// Quote-and-backslash escaping for a JSON string body, without the quotes.
//
// Declared here because this file is no longer the only place that writes JSON:
// `ls --json` and `ps --json` build their documents by hand, and a runtime's
// group or owner is an arbitrary operator string that nothing validates.  A
// quote in one of those produced a document no parser would accept — measured,
// json.load() failing at column 27 of `ls --json`.
std::string json_escape(std::string_view s);
}

struct runtime_config
{
    std::string name;
    std::string id;
    runtime_type type = runtime_server;
    uint16_t port = 0;
    // `--listen unix:/path` — an AF_UNIX listener instead of a port.  See
    // runtime_instance::set_listen_path.  Mutually exclusive with `port`; the
    // refusal is where the flag is read, not here.
    std::string listen_path;
    bool was_running = false;

    // Common
    std::string log_file;
    std::string write_file;
    std::string lua_script;
    bool bash_output = false;
    bool bash_prefix = false;
    bool bash_timestamp = false;
    uint32_t max_connections = 0;
    double rate_limit = 0.0;
    double global_rate_limit = 0.0;
    uint32_t idle_timeout = 0;
    bool drain = false;
    int reconnect = -1;
    bool tls = false;
    std::string cert_path;
    std::string key_path;
    std::string ca_path;
    std::string target;
    std::string cache_name;

    // Group
    std::string group;

    // Ownership
    std::string owner;
    int child_policy = 0; // 0 = stop, 1 = remove

    // `out_of_process` used to live here, persisted because was_running
    // auto-restart had to bring a runtime back WHERE it was running and not
    // merely bring it back.  There is one where now, so there is nothing to
    // carry: daemon.cpp marks every restored runtime out of process
    // unconditionally, which also decides what to do with a file written by an
    // older build.  See the note there; the short version is that
    // `"out_of_process": false` described an arrangement this build cannot
    // create, so honouring it would restore something untestable.
    //
    // The field is not read and the key is not written.  An old file still
    // carrying it parses fine: json_get_* ignores keys nothing asks for.

    // How many worker processes serve this one runtime; see
    // runtime_instance::set_shards().  Persisted because the cost of not doing
    // so is sharp: a proxy restored
    // with one shard where the operator asked for four is a quarter of the
    // throughput they configured, reported by `ls` as running and by nothing at
    // all as wrong.
    uint32_t shards = 1;

    // WHICH of those processes this config frame is addressed to: 0..shards-1.
    //
    // Not a property of the runtime, unlike `shards` above — it is a property
    // of one child, and it is the only field in this struct that differs
    // between the N frames the daemon writes for one runtime.  A worker has no
    // other way to learn it: the whole point of SO_REUSEPORT is that the shards
    // are indistinguishable from the outside, and a process that cannot say
    // which one it is has neither an aggregation slot nor an ownership claim.
    //
    // The daemon's own placeholder always reads 0 here, so a state file never
    // carries it — see format_json_pretty, which writes it only above zero.  If
    // it ever did, a restore would give every shard the same index and the
    // region below would have N writers on one line.
    uint32_t shard_index = 0;

    // Ring policy: what this runtime's --cpus / --sqpoll asked its I/O to run
    // as.  See runtime_instance.h — these are a request, not a result, and the
    // daemon refuses one its ring cannot meet.
    //
    // Persisted because the refusal is the whole value of the request.  A ring
    // belongs to a process, so dropping these across a restart never changed
    // where a restored runtime's I/O ran; what it dropped was the operator's
    // stated requirement, and with it the refusal that would have said the new
    // ring does not meet it.  A daemon restarted without SOCKETLEY_CPUS brought
    // a runtime created with --cpus 0-1 back up on an unpinned ring, reported
    // cpus:max, and said nothing.
    //
    // `cpus` is stored as it would be typed — max | 0-3 | 0,1,2,3 — because
    // cpu_set_spec::to_string() round-trips through parse_cpu_set and a state
    // file a human can read is worth more here than a bitmask.  Empty means no
    // request was made, which is not the same as a request for the default:
    // see the note on has_cpus_request() in runtime_instance.h.
    std::string cpus;
    bool sqpoll = false;
    bool sqpoll_set = false;

    // External (attach) mode
    bool external_runtime = false;
    bool managed = false;
    std::string exec_path;
    int32_t pid = 0;  // PID of external process (0 = unknown)

    // Server/Client
    uint8_t mode = 0;       // server_mode or client_mode
    bool udp = false;

    // Server master mode
    std::string master_pw;
    bool master_forward = false;

    // Server HTTP static file serving
    std::string http_dir;
    bool http_cache = false;

    // Server upstreams
    std::vector<std::string> upstreams;

    // Proxy
    uint8_t protocol = 0;   // proxy_protocol
    uint8_t strategy = 0;   // proxy_strategy
    std::vector<std::string> backends;

    // Proxy service mesh
    uint8_t health_check = 0;    // mesh_config::health_type
    int health_interval = 5;
    std::string health_path;
    int health_threshold = 3;
    int circuit_threshold = 5;
    int circuit_timeout = 30;
    // Mirrors mesh_config::backend_timeout, default and all: 0 is a meaningful
    // value here ("no deadline"), so absence has to be told apart from it —
    // which is why the reader asks for this default rather than treating 0 as
    // "not set" the way the fields above do.
    int backend_timeout = 2;
    int retry_count = 0;
    bool retry_all = false;
    std::string mesh_client_ca;
    std::string mesh_client_cert;
    std::string mesh_client_key;

    // Cache
    std::string persistent_path;
    uint8_t cache_mode = 1;  // cache_mode (default readwrite)
    bool resp_forced = false;
    bool cluster = false;
    std::string replicate_target;
    size_t max_memory = 0;
    uint8_t eviction = 0;    // eviction_policy

    // ─── WHICH KEYS THE DOCUMENT ACTUALLY NAMED ─────────────────────────────
    //
    // Every field above has a default, and until this set existed there was no
    // way to tell a document that SET a field to its default from one that did
    // not mention it at all.  `import` applied all of them either way, so a
    // partial document cleared everything it left out.  Measured, against a
    // runtime with a port, a log path, two limits and a full TLS set:
    //
    //     socketley import c '{"name":"c"}'   ->  exit 0, no output
    //     ... and seven fields were gone, TLS among them.
    //
    // Filled by parse_json_string.  Empty after any other way of building a
    // runtime_config — read_from_instance() describes a live runtime, where
    // every field is present by construction and nothing is deciding whether
    // to apply it.
    std::set<std::string, std::less<>> present;

    bool has(std::string_view key) const { return present.find(key) != present.end(); }
};

class runtime_instance;
class runtime_manager;

class state_persistence
{
public:
    explicit state_persistence(const std::filesystem::path& state_dir);

    void save_runtime(const runtime_instance* instance);
    void remove_runtime(std::string_view name);
    void set_was_running(std::string_view name, bool running);

    std::vector<runtime_config> load_all();

    runtime_config read_from_instance(const runtime_instance* instance) const;
    std::string format_json_pretty(const runtime_config& cfg) const;
    bool parse_json_string(const std::string& json, runtime_config& cfg) const;

    // One field's value, exactly as the document wrote it.
    //
    // parse_json_string has no error channel for a single field -- it returns
    // false only for a document with no name -- so a field whose value is
    // syntactically fine and semantically wrong is silently normalised away.
    // `listen` is one of those: the `unix:` prefix is stripped on the way in,
    // and a value that never had one is indistinguishable afterwards from a
    // document that cleared the field.  `import` re-reads it through this and
    // judges it with the same function the flag parser uses.
    std::string raw_field(const std::string& json, std::string_view key) const;

    // Block until everything queued has reached disk.  For a caller that is
    // about to read the files back — a test, a shutdown that will be followed
    // by a restart — and for nothing else: taking this on the event loop
    // thread reintroduces exactly the stall the queue exists to remove.
    void drain();

private:
    // ─── WHY THE WRITES LEFT THE CALLING THREAD ─────────────────────────────
    //
    // write_json() ends in an fsync, and every one of these three methods was
    // called from the daemon's event loop thread — the one thread that serves
    // every runtime in the process.  Measured with a cache PING on the same
    // daemon while six `create` commands ran:
    //
    //     quiet            p50 0.012 ms   p99 0.018 ms   max 0.044 ms
    //     during creates   p50 0.015 ms   p99 0.244 ms   max 9.598 ms
    //
    // and fsync on that filesystem: p50 3.79 ms, p99 24.26 ms — the same
    // distribution.  A factor of 800 on the answer time of every runtime the
    // daemon holds, every time an operator typed create, start, stop or
    // remove.
    //
    // WHAT DOES NOT CHANGE IS THE GUARANTEE.  The fsync is there, in its own
    // words, to prevent "partial/empty state files on power loss or kernel
    // crash" — it is about never publishing a file whose contents are not on
    // disk, not about the CLI's reply meaning anything.  Moving the whole
    // write-fsync-rename sequence to another thread keeps that exactly: the
    // rename still happens after the fsync, so a published file is still an
    // intact one.  What the reply no longer means is "already on disk", and it
    // never legitimately meant that: if the machine dies between the two, the
    // runtime is not persisted either way.
    //
    // ORDER IS PRESERVED because there is one writer and one FIFO.  A create
    // followed by a remove reaches the disk in that order, which is the only
    // property the callers depend on.
    struct job
    {
        enum kind { write_cfg, remove_file, flip_running } k;
        runtime_config cfg;      // write_cfg
        std::string    name;     // remove_file, flip_running
        bool           running;  // flip_running
    };

    void writer_loop();
    void enqueue(job j);
    void flip_was_running(std::string_view name, bool running);

    std::thread             m_writer;
    std::mutex              m_mx;
    std::condition_variable m_cv;
    std::deque<job>         m_queue;
    bool                    m_stop{false};
    uint64_t                m_queued{0}; // jobs accepted, for drain()
    uint64_t                m_done{0};   // jobs completed, for drain()

    std::filesystem::path config_path(std::string_view name) const;
    bool write_json(const runtime_config& cfg) const;

    // Narrow any state file this directory already holds to 0600, returning
    // how many were changed.  Called once from load_all(); see the reasoning
    // there and at the definition.
    size_t tighten_existing() const;

    bool read_json(const std::filesystem::path& path, runtime_config& cfg) const;

    std::filesystem::path m_state_dir;

public:
    ~state_persistence();
};
