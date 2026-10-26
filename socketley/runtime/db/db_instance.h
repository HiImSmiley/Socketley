#pragma once
// The db runtime: a document database for the data applications keep about their users -- characters, orders,
// settings -- each document owned by an account of an idp runtime, which reaches its own and no other's.
//
// It serves JSON over plain HTTP and is reached through the entrance proxy, which terminates TLS for it as for every
// other name; a script of this daemon reaches it as socketley.db.
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/ipc/request_channel.h"
#include "../../shared/runtime/runtime_instance.h"
#include "shared/runtime/retired_runs.h"

namespace socketley::db
{
class db_run;
}

// <state>/db/<name>/, the documents' snapshot and journal.
std::string db_data_dir(std::string_view runtime_name);

class db_instance : public runtime_instance, public deferred_request_sink
{
public:
    explicit db_instance(std::string_view name);
    ~db_instance() override;

    // The file the collections are declared in (--schema), read again when it changes.
    void set_schema_path(std::string_view p) { m_schema = std::string(p); }
    std::string_view get_schema_path() const { return m_schema; }

    // The file of service keys (--keys), read again when it changes.
    void set_keys_path(std::string_view p) { m_keys = std::string(p); }
    std::string_view get_keys_path() const { return m_keys; }

    // The idp runtime whose sign-ins and access tokens name the accounts that own documents (--idp).
    void set_idp(std::string_view name) { m_idp = std::string(name); }
    std::string_view get_idp() const { return m_idp; }
    // The clients of the idp whose access tokens are taken (--idp-audience), comma-separated.
    void set_idp_audience(std::string_view list) { m_idp_audience = std::string(list); }
    std::string_view get_idp_audience() const { return m_idp_audience; }

    // The web origins a browser may call it from (--origins), comma-separated; * for any, without its cookie.
    void set_origins(std::string_view list) { m_origins = std::string(list); }
    std::string_view get_origins() const { return m_origins; }

    // The most bytes the documents may hold (--max-bytes), 0 for no bound.
    void set_max_bytes(uint64_t b) { m_max_bytes = b; }
    uint64_t get_max_bytes() const { return m_max_bytes; }

    // The most memory the documents last read are kept in (--cache); the rest are read from the disk.
    void set_cache_bytes(uint64_t b) { m_cache_bytes = b; }
    uint64_t get_cache_bytes() const { return m_cache_bytes; }

    // The database this one is a copy of (--replicate), an http or https address, and the file holding the key it
    // asks with (--replicate-key); a replica answers reads and refuses writes.
    void set_replicate(std::string_view url) { m_replicate = std::string(url); }
    std::string_view get_replicate() const { return m_replicate; }
    void set_replicate_key(std::string_view path) { m_replicate_key = std::string(path); }
    std::string_view get_replicate_key() const { return m_replicate_key; }

    // Backups written into a directory (--backup-dir) every so many seconds (--backup-every), the newest kept
    // (--backup-keep).
    void set_backup_dir(std::string_view d) { m_backup_dir = std::string(d); }
    std::string_view get_backup_dir() const { return m_backup_dir; }
    void set_backup_every(uint32_t s) { m_backup_every = s; }
    uint32_t get_backup_every() const { return m_backup_every; }
    void set_backup_keep(uint32_t n) { m_backup_keep = n; }
    uint32_t get_backup_keep() const { return m_backup_keep; }

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;

    // A script's socketley.db reaches the worker as a request on the channel, answered once the change is on the disk.
    request_sink* as_request_sink() override { return sink_or(this); }
    bool serve_deferred(uint64_t ticket, std::string_view target, std::string_view payload) override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

private:
    std::string m_schema;
    std::string m_keys;
    std::string m_idp;
    std::string m_idp_audience;
    std::string m_origins;
    uint64_t m_max_bytes{0};
    uint64_t m_cache_bytes{64ull << 20};
    std::string m_replicate;
    std::string m_replicate_key;
    std::string m_backup_dir;
    uint32_t m_backup_every{86400};
    uint32_t m_backup_keep{7};

    std::unique_ptr<socketley::db::db_run> m_run;
    // Runs stopped but still owed completions by the ring.
    socketley::retired_runs<socketley::db::db_run> m_graveyard;
};
