#pragma once
// The sync runtime: one job that carries files between a directory and a storage, in one direction or both.
//
// One runtime is one job, so a job that fails is a runtime that failed, with its reason in the log, its alert, its
// figures and its own line in `socketley ls` -- all of which a list of jobs inside one runtime would have had to
// grow again, worse. The job's state lives in an index of what was last carried, without which a deletion on one
// side cannot be told from a creation on the other.
//
// --mode says who sends: `out` carries the directory to the storage, `in` carries the storage to the directory, and
// `inout` both ways, as it does on a server and a client.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/runtime/runtime_instance.h"

namespace socketley::sync
{
class sync_run;
class repo_runner;
}

// Who carries what, the same three words a server and a client take.
enum sync_mode : uint8_t { sync_mode_out = 0, sync_mode_in = 1, sync_mode_inout = 2 };

// The mode a name gives, false for anything else.
bool parse_sync_runtime_mode(std::string_view s, sync_mode& out);
const char* sync_mode_name(sync_mode m);

// How often the whole of both sides is walked when nothing told the runtime of a change, in seconds; 0 is never.
inline constexpr uint32_t sync_default_every = 3600;

// One --storage entry taken apart: a runtime of this daemon and a bucket, or an address and a bucket.
struct sync_target_spec
{
    // As it was written, which is what the index keys by.
    std::string name;
    std::string bucket;
    // The runtime's name, empty when the entry is an address.
    std::string runtime;
    // `http://host:port` or `https://host[:port]`, empty when the entry names a runtime.
    std::string url;
};

// Where a sync's index is kept, <state>/sync/<name>.index, which a removal deletes and a rename carries along.
std::string sync_index_path(std::string_view runtime_name);

// `runtime/bucket`, `host:port/bucket` (http) or `http[s]://host[:port]/bucket`; false with `why` for anything else,
// so create refuses what the job could never reach.
bool parse_sync_target(std::string_view entry, sync_target_spec& out, std::string& why);

class sync_instance : public runtime_instance
{
public:
    explicit sync_instance(std::string_view name);
    ~sync_instance() override;

    // The directory the job's files are in (--dir); it must exist when the runtime starts.
    void set_dir(std::string_view path);
    std::string_view get_dir() const { return m_dir; }

    // Where they go (--storage): `runtime/bucket` for a storage runtime of this daemon, or a URL with a bucket for
    // one anywhere, comma-separated for more than one.
    void set_storage(std::string_view csv) { m_storage = std::string(csv); }
    std::string_view get_storage() const { return m_storage; }
    std::vector<std::string> storage_targets() const;

    // The key every object is written under, beneath the bucket (--prefix); empty is the bucket's root.
    void set_prefix(std::string_view p) { m_prefix = std::string(p); }
    std::string_view get_prefix() const { return m_prefix; }

    void set_mode(sync_mode m) { m_mode = m; }
    sync_mode get_mode() const { return m_mode; }

    // The file the job's credentials are read from (--credentials).
    void set_credentials(std::string_view path) { m_credentials = std::string(path); }
    std::string_view get_credentials() const { return m_credentials; }

    // Seconds between two walks of both sides (--every), 0 for only when something says a file changed.
    void set_every(uint32_t secs) { m_every = secs; }
    uint32_t get_every() const { return m_every; }

    // What is not carried (--exclude): shell patterns against the path below --dir, comma-separated.
    void set_exclude(std::string_view csv) { m_exclude = std::string(csv); }
    std::string_view get_exclude() const { return m_exclude; }

    // The file a storage writes for a user's own sync runtime (--repositories), which makes the job pulling that
    // user's git repositories into their libraries rather than carrying a directory.
    void set_repositories(std::string_view path) { m_repositories = std::string(path); }
    std::string_view get_repositories() const { return m_repositories; }

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;

    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    std::string config_refusal() const override;
    uint16_t effective_port() const override;

private:
    std::string m_dir;
    std::string m_storage;
    std::string m_prefix;
    std::string m_credentials;
    std::string m_exclude;
    std::string m_repositories;
    sync_mode   m_mode{sync_mode_out};
    uint32_t    m_every{sync_default_every};

    std::unique_ptr<socketley::sync::sync_run> m_run;
    // Runs that were stopped and that the ring still owes a completion.
    std::vector<std::unique_ptr<socketley::sync::sync_run>> m_graveyard;
    std::unique_ptr<socketley::sync::repo_runner> m_repos;
    std::vector<std::unique_ptr<socketley::sync::repo_runner>> m_repo_graveyard;
};
