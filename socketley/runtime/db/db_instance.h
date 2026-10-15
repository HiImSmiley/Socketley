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

#include "../../shared/request_channel.h"
#include "../../shared/runtime_instance.h"

namespace socketley::db
{
class db_run;
}

// <state>/db/<name>/, the documents' snapshot and journal.
std::string db_data_dir(std::string_view runtime_name);

class db_instance : public runtime_instance, public request_sink
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

    // The web origins a browser may call it from (--origins), comma-separated; * for any, without its cookie.
    void set_origins(std::string_view list) { m_origins = std::string(list); }
    std::string_view get_origins() const { return m_origins; }

    // The most bytes the documents may hold (--max-bytes), 0 for no bound.
    void set_max_bytes(uint64_t b) { m_max_bytes = b; }
    uint64_t get_max_bytes() const { return m_max_bytes; }

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;

    // A script's socketley.db reaches the worker as a request on the channel, answered once the change is on the disk.
    request_sink* as_request_sink() override
    {
        if (auto* o = runtime_instance::as_request_sink())
            return o;
        return this;
    }
    void serve_request(std::string_view, std::string& out) override { out.clear(); }
    bool serves_inline() const override { return false; }
    bool serve_deferred(uint64_t ticket, std::string_view target, std::string_view payload) override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

private:
    std::string m_schema;
    std::string m_keys;
    std::string m_idp;
    std::string m_origins;
    uint64_t m_max_bytes{0};

    std::unique_ptr<socketley::db::db_run> m_run;
    // Runs stopped but still owed completions by the ring.
    std::vector<std::unique_ptr<socketley::db::db_run>> m_graveyard;
};
