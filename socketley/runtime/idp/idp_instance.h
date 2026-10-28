#pragma once
// The idp runtime: an OpenID Connect provider that keeps its own accounts, so one sign-in reaches every
// application that asks it, and a proxy, a storage or the dashboard can put a sign-in in front of what they serve.
//
// It serves plain HTTP and is reached through the entrance proxy, which terminates TLS for it as it does for every
// other name; the issuer is the https address the entrance answers on.
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/ipc/request_channel.h"
#include "../../shared/runtime/runtime_instance.h"
#include "shared/runtime/retired_runs.h"

namespace socketley::idp
{
class idp_run;
}

// <state>/idp/<name>.key, the provider's signing key, made at its first start and kept across restarts.
std::string idp_key_path(std::string_view runtime_name);

// <state>/idp/<name>.jwks, the public half beside it, which a proxy of this daemon verifies sessions with.
std::string idp_jwks_path(std::string_view runtime_name);

// <state>/idp/<name>.standing, beside it: each account's id and whether it may still be signed in, which that proxy
// checks every session against.
std::string idp_standing_path(std::string_view runtime_name);

// <state>/idp/<name>.accounts/, the accounts' snapshot and journal.
std::string idp_accounts_dir(std::string_view runtime_name);

// <state>/idp/<name>.ssh-ca, the Ed25519 key it signs SSH certificates with under --ssh-ca.
std::string idp_ssh_ca_path(std::string_view runtime_name);

class idp_instance : public runtime_instance, public deferred_request_sink
{
public:
    explicit idp_instance(std::string_view name);
    ~idp_instance() override;

    // The file the relying parties are declared in (--clients), read again when it changes.
    void set_clients(std::string_view path) { m_clients = std::string(path); }
    std::string_view get_clients() const { return m_clients; }

    // The https address this provider is reached at (--issuer); https://<first --domain> when not given.
    void set_issuer(std::string_view url) { m_issuer = std::string(url); }
    std::string_view get_issuer_flag() const { return m_issuer; }
    std::string issuer() const;

    // The domain the sign-in cookie is set for (--cookie-domain), so every name below it shares one sign-in.
    void set_cookie_domain(std::string_view d) { m_cookie_domain = std::string(d); }
    std::string_view get_cookie_domain() const { return m_cookie_domain; }

    // How many hours an SSH user certificate it signs holds (--ssh-ca), 0 when it signs none.
    void set_ssh_ca_hours(uint32_t h) { m_ssh_ca_hours = h; }
    uint32_t get_ssh_ca_hours() const { return m_ssh_ca_hours; }

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;

    // `socketley idp-user` reaches the worker as a request on the channel, answered on a later turn.
    request_sink* as_request_sink() override { return sink_or(this); }
    bool serve_deferred(uint64_t ticket, std::string_view target, std::string_view payload) override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

private:
    std::string m_clients;
    std::string m_issuer;
    std::string m_cookie_domain;
    uint32_t m_ssh_ca_hours{0};

    std::unique_ptr<socketley::idp::idp_run> m_run;
    // Runs stopped but still owed completions by the ring.
    socketley::retired_runs<socketley::idp::idp_run> m_graveyard;
};
