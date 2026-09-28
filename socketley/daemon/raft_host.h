#pragma once
// The daemon's Raft node: the core, its WAL and its peer transport on the daemon's own io_uring loop.
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../shared/cluster_state.h"
#include "../shared/event_loop_definitions.h"
#include "../shared/raft.h"
#include "../shared/raft_storage.h"
#include "../shared/tls_context.h"

#include <linux/time_types.h>
#include <netinet/in.h>

class event_loop;

// Everything `socketley daemon --raft-*` can say, judged before a host exists.
struct raft_host_config
{
    std::string listen;
    std::string advertise;
    std::string name;
    std::string join;
    bool        init     = false;
    bool        insecure = false;
    std::string cert, key, ca;
    std::string dir;
    uint32_t    tick_ms        = 100;
    uint32_t    election_ticks = 10;
    // Applied entries between snapshots.
    uint64_t    compact_every  = 1000;

    bool enabled() const { return !listen.empty(); }
};

// The operator's reason when the configuration cannot run, empty when it can.
std::string raft_config_refusal(const raft_host_config& c);

class raft_host : public io_handler
{
public:
    explicit raft_host(raft_host_config cfg);
    ~raft_host() override;

    // Recovers or initializes the state directory, binds the peer port and arms the tick; false with `err` when Raft cannot run.
    bool start(event_loop& loop, std::string& err);

    // Hands leadership to the most up-to-date voter and runs the loop until it moved or two election timeouts passed.
    void hand_over(event_loop& loop);

    // Closes every socket and waits for the ring to be done with this object's storage.
    void stop();

    // What `socketley cluster raft-status` prints, and the exit code it means.
    std::string status(int& exit_code) const;

    // Proposes an encoded cluster command at the leader, or hands it to the leader from a follower; false with `err` when it cannot go anywhere.
    bool submit(const std::string& data, std::string& err);

    // The cluster's desired state as this node has applied it.
    const socketley::cluster::state& cluster() const { return m_cluster; }
    // The name a member goes by, or its hex id when the book does not hold it.
    std::string node_name(socketley::raft::node_id id) const;

    void on_cqe(struct io_uring_cqe* cqe) override;

    struct link;

private:
    friend struct link;

    struct member
    {
        std::string name;
        std::string addr;
        bool        voter = true;
    };
    using book = std::map<socketley::raft::node_id, member>;

    using clock = std::chrono::steady_clock;

    bool load_identity(std::string& err);
    bool bind_listener(std::string& err);
    void arm_accept();
    void arm_tick();
    void arm_pump();

    void on_accept(int res);
    void on_tick();
    void maintain();

    void pump();
    void after_persist(bool ok);
    void apply(const socketley::raft::ready& r);
    void fail_stop(const std::string& why);

    void send(const socketley::raft::message& m);
    link* outbound(socketley::raft::node_id id);
    void enqueue(link* l, const std::string& payload);

    bool on_frame(link& l, std::string_view payload);
    void handle_command(const std::string& data);
    void handle_join(const std::string& payload_frame, socketley::raft::node_id id, const std::string& name,
                     const std::string& addr, bool voter);
    void try_join();
    void promote_learners();
    void ensure_own_record();

    void retire(link* l);
    void reap();

    const member* lookup(socketley::raft::node_id id) const;
    void refresh_book();
    std::string describe(socketley::raft::node_id id) const;

    static std::string encode_record(socketley::raft::node_id id, const member& m);
    static bool        decode_record(std::string_view data, socketley::raft::node_id& id, member& m);
    static std::string encode_book(const book& b);
    static bool        decode_book(std::string_view data, book& b);
    static std::string encode_snapshot(const book& b, const socketley::cluster::state& c);
    static bool        decode_snapshot(std::string_view data, book& b, socketley::cluster::state& c);
    void               apply_command(const std::string& data, socketley::raft::index_t index);

    raft_host_config m_cfg;
    event_loop*      m_loop = nullptr;
    socketley::raft::node_id    m_id   = socketley::raft::no_node;

    std::unique_ptr<socketley::raft::node>     m_node;
    socketley::raft::storage::wal              m_wal;
    socketley::raft::ready                     m_pending;
    bool                            m_stopped = false;
    std::string                     m_fatal;

    // Membership as applied, and as the whole log says it, which is where a message is addressed.
    book m_applied_book;
    book m_book;
    // The desired state of the cluster's runtimes, applied from the log like the book.
    socketley::cluster::state m_cluster;
    // What peers said about themselves in a hello, for a member whose record this node has not seen yet.
    book m_heard_book;

    socketley::raft::index_t m_applied = 0;
    socketley::raft::index_t m_snap_index = 0;

    tls_context m_server_tls;
    tls_context m_client_tls;
    bool        m_tls = false;

    int         m_listen_fd = -1;
    io_request  m_accept_req{};
    sockaddr_storage m_accept_addr{};
    socklen_t   m_accept_len = 0;
    bool        m_accept_armed = false;

    io_request  m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool        m_tick_armed = false;
    clock::time_point m_last_tick{};
    uint64_t    m_ticks = 0;

    io_request  m_pump_req{};
    bool        m_pump_armed = false;

    std::map<socketley::raft::node_id, std::unique_ptr<link>> m_out;
    std::unique_ptr<link>                          m_join_link;
    std::vector<std::unique_ptr<link>>             m_in;
    std::map<socketley::raft::node_id, clock::time_point>     m_dial_after;
    std::map<socketley::raft::node_id, clock::time_point>     m_heard;
    struct grave
    {
        std::unique_ptr<link> l;
        uint32_t              token = 0;
    };
    std::vector<grave> m_graveyard;

    uint64_t m_dropped = 0;
    uint64_t m_sent    = 0;
    uint64_t m_received = 0;
    socketley::raft::soft_state m_soft;
    uint32_t m_owner_token = 0;
};
