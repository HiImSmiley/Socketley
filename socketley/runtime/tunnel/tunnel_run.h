#pragma once
// The tunnel runtime's running half, both its modes: the links (one multiplexed connection each), the legs (a local
// connection a stream is carried to), and what the edge and the agent each do with them.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include "tunnel_registry.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/http/conn_server.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/net/async_resolver.h"
#include "../../shared/net/tunnel_mux.h"

class tunnel_instance;
class proxy_auth;

namespace socketley::idp
{
class session_verifier;
}

namespace socketley::tunnel
{

class tunnel_run;
class link;

// A local connection a stream is carried to: a visitor at the edge, a target at either side.
struct leg : http::server_conn
{
    http::conn_server* srv{nullptr};
    link* l{nullptr};
    uint32_t stream{0};
    // Stream bytes written to this socket and not yet given back to the far side as credit.
    size_t unacked{0};
    // The far side writes no more, this socket wrote its last, and its write half is shut.
    bool far_closed{false};
    bool near_closed{false};
    bool shut{false};
    reset_code why{reset_code::gone};

    // An HTTP service's visitor: each request is asked of the listener's auth, where it has one, and its head
    // rewritten before any of it goes on, and only the bytes at the front of `in` that a request let through frames
    // (`cleared`) are sent.
    bool gated{false};
    size_t cleared{0};
    size_t body_left{0};
    bool chunked{false};
    http_chunked_decoder chunks{};
    // Upgraded past HTTP, after which everything goes on unasked, once the far side's answer begins with a 101.
    bool raw{false};
    bool await_101{false};
    std::string answer;
    // A refusal, written once the far side has answered all that went before it, and the visitor closed after.
    std::string refusal;
    bool refused{false};
    // Waiting for its link's transport to drain rather than for credit.
    bool parked{false};
};

// A UDP socket of the tunnel and its one receive in flight: a UDP service's port at the edge, or a flow's own socket
// at an agent, which says what came to `got`.
struct udp_port
{
    int fd{-1};
    io_request req{};
    msghdr msg{};
    iovec iov{};
    sockaddr_storage from{};
    std::vector<char> buf;
    bool pending{false};
    // Closed once the ring has answered the receive that was cancelled under it.
    bool dying{false};
    std::function<void(udp_port&, std::string_view)> got;
};

// One multiplexed connection: an agent or a person at the edge, or the edge at an agent.
class link : public events
{
public:
    enum class kind : uint8_t
    {
        agent,
        person,
        edge,
    };

    link(tunnel_run& run, kind k, std::string who, const std::shared_ptr<http::server_conn>& transport);

    tunnel_run& run;
    const kind k;
    // The agent's name, the person's username, or the edge's address.
    const std::string who;
    session s;
    // Frames waiting to go out on the transport.
    std::string out;
    // On a path with a round trip, how much stream data may wait unsent, so a frame that opens, credits or pings a
    // stream waits behind that and not behind every stream's window; and the streams waiting for it to drain.
    size_t out_high{SIZE_MAX};
    std::vector<uint32_t> parked;
    std::unordered_map<uint32_t, std::shared_ptr<leg>> legs;
    std::weak_ptr<http::server_conn> transport;
    // A person who is an admin of the edge's idp, who may reach an agent's TCP service by its name.
    bool admin{false};
    // A person's account and when it signed in, asked of the idp again for as long as the link lives.
    std::string sub;
    int64_t signed_in_ms{0};
    int64_t last_heard{0};
    int64_t last_ping{0};
    // The name a person's link shares one of its own ports under, empty for none.
    std::string share;
    // Told why it ends, and closed once that is written.
    bool ending{false};

    void on_hello(const fields& f) override;
    void on_open(uint32_t stream, std::string_view target, std::string_view peer) override;
    void on_data(uint32_t stream, std::string_view bytes) override;
    void on_close(uint32_t stream) override;
    void on_reset(uint32_t stream, reset_code code) override;
    void on_window(uint32_t stream) override;
    void on_pong(std::string_view token) override;
    void on_goaway(std::string_view why) override;
    void on_datagram(uint32_t flow, std::string_view service, std::string_view bytes) override;

private:
    std::shared_ptr<leg> leg_of(uint32_t stream);
};

// The hooks of one set of legs: a service's listener, or the dialler of targets and offers.
class leg_hooks : public http::conn_hooks
{
public:
    leg_hooks(tunnel_run& run, std::string agent, service svc);
    ~leg_hooks() override;
    tunnel_run& run;
    // The agent and service a listener's visitors are carried to; empty for a dialler.
    const std::string agent;
    const service svc;
    // What a protected HTTP service asks of each request, any one of them enough; none lets every visitor through.
    std::vector<std::unique_ptr<proxy_auth>> auth;
    http::conn_server srv;

    std::shared_ptr<http::server_conn> make_conn() override;
    void serve(const std::shared_ptr<http::server_conn>& c) override;
    void accepted(const std::shared_ptr<http::server_conn>& c) override;
    bool written(const std::shared_ptr<http::server_conn>& c) override;
    bool keeps_open(const http::server_conn&) const override { return true; }
    void closing(const std::shared_ptr<http::server_conn>& c) override;
    bool read_ended(const std::shared_ptr<http::server_conn>& c) override;
    void connected(const std::shared_ptr<http::server_conn>& c, int res) override;
};

// The edge's front: agents and people asking to upgrade, and once they have, their links.
class front_hooks : public http::conn_hooks
{
public:
    explicit front_hooks(tunnel_run& run);
    tunnel_run& run;
    http::conn_server srv;

    std::shared_ptr<http::server_conn> make_conn() override;
    void serve(const std::shared_ptr<http::server_conn>& c) override;
    bool written(const std::shared_ptr<http::server_conn>& c) override;
    bool keeps_open(const http::server_conn& c) const override;
    void closing(const std::shared_ptr<http::server_conn>& c) override;
};

// The agent's connection to the edge.
class upstream_hooks : public http::conn_hooks
{
public:
    explicit upstream_hooks(tunnel_run& run);
    tunnel_run& run;
    http::conn_server srv;

    std::shared_ptr<http::server_conn> make_conn() override;
    void serve(const std::shared_ptr<http::server_conn>& c) override;
    bool written(const std::shared_ptr<http::server_conn>& c) override;
    bool keeps_open(const http::server_conn&) const override { return true; }
    void closing(const std::shared_ptr<http::server_conn>& c) override;
    void connected(const std::shared_ptr<http::server_conn>& c, int res) override;
};

class tunnel_run : public io_handler
{
public:
    tunnel_run(tunnel_instance& owner, event_loop& loop);
    ~tunnel_run() override;

    bool start(std::string& why);
    void stop();
    bool drained() const;
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    size_t conn_count() const;
    std::string stats() const;

private:
    friend class link;
    friend class leg_hooks;
    friend class front_hooks;
    friend class upstream_hooks;

    // ── shared by both modes ──
    void arm_tick();
    void tick();
    // What the link has to say sent on its transport, through TLS at an agent.
    void flush_link(link& l);
    // What the link has handed its transport and the transport not yet written.
    size_t link_backlog(const link& l) const;
    // The streams that waited for the transport, read again now that it has written everything.
    void link_drained(link& l);
    // Every leg of a link that ended closed, and the link forgotten wherever it was named.
    void drop_link(link& l);
    // A link at the edge told why it ends and closed once that is written, so the far side reads the reason, not a cut.
    void end_link(link& l, std::string_view why);
    // The leg's buffered bytes handed to its stream as far as the credit goes.
    void pump(leg& g);
    void leg_done_writing(const std::shared_ptr<leg>& g);
    // A leg to `target` (`host:port`) for a stream the far side opened from `peer`, refused when it cannot be begun.
    void dial_leg(link& l, uint32_t stream, std::string_view target, std::string_view peer);

    // ── UDP, at both ends ──
    bool arm_udp(udp_port& p);
    void on_udp(udp_port& p, int res);
    // A socket given up, closed at once or once the ring owes it nothing.
    void retire_udp(std::unique_ptr<udp_port> p);
    // A datagram for the link, dropped when the link already holds more than a datagram should wait behind.
    void send_datagram(link& l, uint32_t flow, std::string_view service, std::string_view bytes);
    // At the edge, a visitor's datagram on a service's port carried to its agent, and an agent's back to its visitor.
    void udp_visitor(const std::string& service, const udp_port& p, std::string_view bytes);
    void udp_from_agent(link& l, uint32_t flow, std::string_view service, std::string_view bytes);
    // At an agent, the edge's datagram sent to the offer it names, through its flow's own socket.
    void udp_from_edge(link& l, uint32_t flow, std::string_view service, std::string_view bytes);
    // The UDP services' ports as the agents file says, at the edge.
    void reload_udp();
    // Flows silent for long forgotten, and a socket the ring once refused armed again.
    void tend_udp(int64_t now);
    link* edge_link();
    size_t flow_count() const;

    // ── the edge ──
    bool start_edge(std::string& why);
    void reload_agents();
    // A request on the front, answered and, for an agent or a person with a credential, upgraded.
    void front_request(const std::shared_ptr<http::server_conn>& c);
    void refuse_front(const std::shared_ptr<http::server_conn>& c, int status, std::string_view why);
    void answer_front(const std::shared_ptr<http::server_conn>& c, int status, std::string_view body);
    void join_by_person(const std::shared_ptr<http::server_conn>& c, std::string_view head);
    // An agent refused, said at once and then once a minute with how often since, as it dials again every few seconds.
    void note_refused(const std::string& name, const std::string& from);
    void upgraded(const std::shared_ptr<http::server_conn>& c, link::kind k, std::string who,
                  std::string_view extra_headers, std::string sub = {}, int64_t signed_in_ms = 0, bool admin = false);
    // Whether a person's sign-in still holds at the idp, its admin bit made what the account's is now.
    bool person_holds(link& l);
    // A listener under a name of the edge's choosing for a person to share a port of theirs on, open to every visitor
    // or to the idp's signed-in people, for `seconds`; the name, or empty with `status` and `why` set.
    std::string begin_share(const std::string& sub, const std::string& who, bool admin, bool open, int64_t seconds,
                            int& status, std::string& why);
    void end_share(const std::string& name);
    void write_shares();
    // A visitor on a service's listener, carried to the agent offering it; false when the agent is not connected.
    bool visitor(leg_hooks& h, const std::shared_ptr<leg>& g);
    // An HTTP service's visitor's requests, as far as they have come, asked of its auth where it has one, and what
    // passed sent on without what the agent must not be given.
    void gate(leg_hooks& h, const std::shared_ptr<leg>& g);
    // The far side's first bytes after an upgrade a visitor asked for, which must be its 101.
    void upgrade_answered(const std::shared_ptr<leg>& g, std::string_view bytes);
    // The visitor told `status` once everything before it is answered, then closed.
    void refuse_visitor(const std::shared_ptr<leg>& g, std::string_view status, std::string_view body,
                        std::string_view headers);

    // ── the agent ──
    bool start_agent(std::string& why);
    void dial_edge();
    // What the edge said in plaintext, its 101 first and then the link's frames.
    void from_edge(const std::shared_ptr<http::server_conn>& c, std::string plain);
    void edge_gone();

    tunnel_instance& m_owner;
    event_loop& m_loop;
    bool m_stopped{false};
    bool m_edge{true};
    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};

    // The edge's front, its dialler of --forward targets, and a listener per service.
    std::unique_ptr<front_hooks> m_front;
    std::unique_ptr<leg_hooks> m_dial;
    std::map<std::string, std::unique_ptr<leg_hooks>> m_listeners;
    // Listeners of services gone, kept until the ring owes them nothing.
    std::vector<std::unique_ptr<leg_hooks>> m_retired;
    std::vector<agent> m_agents;
    int64_t m_agents_mtime{-1};
    std::unordered_map<std::string, std::weak_ptr<link>> m_agent_links;
    // Per agent and address refused: when it was last said, and how often since; cleared past 256, as a stranger names any.
    std::unordered_map<std::string, std::pair<int64_t, uint64_t>> m_refused;
    // People's shares by name: whose they are, until when, and the link carrying them once it is up.
    struct share_entry
    {
        std::string sub;
        std::string who;
        int64_t until{0};
        std::weak_ptr<link> l;
        bool open{false};
    };
    std::map<std::string, share_entry> m_shares;
    std::vector<std::string> m_forward;
    std::unique_ptr<socketley::idp::session_verifier> m_idp;

    // A UDP service's port at the edge and its visitors' flows, each visitor's address one flow.
    struct udp_flow
    {
        sockaddr_storage peer{};
        socklen_t len{0};
        int64_t last{0};
        std::string key;
    };
    struct udp_service
    {
        std::string agent;
        service svc;
        std::unique_ptr<udp_port> port;
        std::unordered_map<std::string, uint32_t> by_peer;
        std::unordered_map<uint32_t, udp_flow> flows;
    };
    std::map<std::string, udp_service> m_udp;
    uint32_t m_next_flow{1};
    // At an agent, each flow the edge sent with its own socket to the offer, so the answers find their visitor.
    struct agent_flow
    {
        std::unique_ptr<udp_port> port;
        std::string service;
        int64_t last{0};
    };
    std::unordered_map<uint32_t, agent_flow> m_flows;
    std::vector<std::unique_ptr<udp_port>> m_udp_dying;

    // The agent's connection to the edge and its dialler of offers.
    std::unique_ptr<upstream_hooks> m_up;
    std::unique_ptr<leg_hooks> m_local;
    std::unordered_map<std::string, std::string> m_offers;
    std::string m_scheme, m_host, m_path_host;
    uint16_t m_port{0};
    tls_context m_tls;
    socketley::async_resolver m_resolver;
    std::string m_credential;
    bool m_joining{false};
    int64_t m_next_dial{0};
    int64_t m_backoff{1};

    struct counters
    {
        uint64_t links{0}, refused{0}, streams{0}, joined{0}, visitors_refused{0}, bytes_in{0}, bytes_out{0}, shared{0},
            datagrams{0}, datagrams_dropped{0};
    } m_c;
};

}   // namespace socketley::tunnel
