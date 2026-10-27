#pragma once
// The tunnel runtime: an edge that a machine without an address of its own dials out to, and that serves that
// machine's services under the edge's names; and the agent on that machine that dials and holds the connection.
//
//   edge    accepts agents and people on its port behind the entrance, each connection one multiplexed link
//           (tunnel_mux.h); serves every HTTP service an agent was invited to offer on a socket the entrance routes
//           <service>.<domain> to, and every TCP service on a port of its own; and carries a person's stream to a
//           --forward target, as ssh's ProxyCommand asks it to.
//   agent   dials --to over TLS, joins with the invitation the edge gave once and with its key after, and opens a
//           local connection to its --offer for every stream the edge opens.
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/runtime/runtime_instance.h"
#include "../../shared/runtime/retired_runs.h"

namespace socketley::tunnel
{
class tunnel_run;
}

class tunnel_instance : public runtime_instance
{
public:
    enum class mode : uint8_t
    {
        edge,
        agent,
    };

    explicit tunnel_instance(std::string_view name);
    ~tunnel_instance() override;

    void set_mode(mode m) { m_mode = m; }
    mode get_mode() const { return m_mode; }
    // The edge an agent dials (--to), https://host[:port] or http:// for one on this machine.
    void set_to(std::string_view url) { m_to = std::string(url); }
    std::string_view get_to() const { return m_to; }
    // The invitation an agent joins with once (--join), `<agent>.<secret>`.
    void set_join(std::string_view j) { m_join = std::string(j); }
    std::string_view get_join() const { return m_join; }
    // What an agent offers (--offer), `<service>=<host>:<port>` each.
    void set_offers(std::string_view csv) { m_offers = std::string(csv); }
    std::string_view get_offers() const { return m_offers; }
    // Where an edge carries a person's stream (--forward), `<host>:<port>` each, and the idp whose access tokens
    // say who may (--idp, --idp-audience).
    void set_forward(std::string_view csv) { m_forward = std::string(csv); }
    std::string_view get_forward() const { return m_forward; }
    void set_idp(std::string_view n) { m_idp = std::string(n); }
    std::string_view get_idp() const { return m_idp; }
    void set_idp_audience(std::string_view a) { m_idp_audience = std::string(a); }
    std::string_view get_idp_audience() const { return m_idp_audience; }

    // The HTTP services the edge's agents offer, as the daemon routes and publishes them: the name and its socket.
    std::vector<std::pair<std::string, std::string>> http_services() const;

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

private:
    mode m_mode{mode::edge};
    std::string m_to;
    std::string m_join;
    std::string m_offers;
    std::string m_forward;
    std::string m_idp;
    std::string m_idp_audience;

    std::unique_ptr<socketley::tunnel::tunnel_run> m_run;
    socketley::retired_runs<socketley::tunnel::tunnel_run> m_graveyard;
};
