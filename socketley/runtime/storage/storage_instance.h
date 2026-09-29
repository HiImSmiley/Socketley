#pragma once
// The storage runtime: an S3 endpoint over one directory.
//
// This object is the configuration and the lifecycle.  Everything that serves
// lives in a storage_run, which setup() makes and teardown() lets go of, so a
// stop and a start in one process never share a connection or a descriptor.
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "s3_auth.h"
#include "../../shared/runtime_instance.h"

namespace socketley::storage
{
class storage_run;
}

// The port a storage runtime listens on when none was configured.  Named once
// because setup() and listen_addresses() have to answer with the same number.
inline constexpr uint16_t storage_default_port = 9000;

class storage_instance : public runtime_instance
{
public:
    explicit storage_instance(std::string_view name);
    ~storage_instance() override;

    // Where the buckets live.
    void set_dir(std::string_view dir) { m_dir = std::string(dir); }
    std::string_view get_dir() const { return m_dir; }

    // Requests are accepted without credentials.  Off unless asked for, and
    // the runtime refuses to start with neither this nor a way to
    // authenticate.
    void set_anonymous(bool on) { m_anonymous = on; }
    bool get_anonymous() const { return m_anonymous; }

    // A quota on the bytes held, 0 for none.
    void set_max_bytes(uint64_t bytes) { m_max_bytes = bytes; }
    uint64_t get_max_bytes() const { return m_max_bytes; }

    // What decides whether a request may go on.  Given, it is used instead of
    // the anonymous default; the SigV4 authenticator arrives here.
    void set_authenticator(std::unique_ptr<socketley::storage::authenticator> a);
    bool has_authenticator() const { return m_auth != nullptr; }

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;

    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    std::string config_refusal() const override;
    void refresh_cached_limits() override;

    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    // What was counted, for the tests that read it through `stats`.
    socketley::storage::storage_run* run() const { return m_run.get(); }

private:
    bool open_listener(uint16_t port, bool reuseport, int& out_fd);

    std::string m_dir;
    bool        m_anonymous{false};
    uint64_t    m_max_bytes{0};
    std::unique_ptr<socketley::storage::authenticator> m_auth;
    std::unique_ptr<socketley::storage::anonymous_authenticator> m_anon;

    std::unique_ptr<socketley::storage::storage_run> m_run;
    // Runs the ring still owes completions to, freed once it owes them none.
    std::vector<std::unique_ptr<socketley::storage::storage_run>> m_graveyard;
    event_loop* m_loop{nullptr};
    std::string m_bound_listen_path;
    uint32_t    m_max_conns_cached{0};
};
