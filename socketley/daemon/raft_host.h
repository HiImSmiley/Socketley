#pragma once
// The daemon's Raft node: the core, its WAL and its peer transport on the daemon's own io_uring loop.
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../shared/cluster/cluster_brain.h"
#include "../shared/cluster/cluster_state.h"
#include "../shared/loop/event_loop_definitions.h"
#include "../shared/cluster/raft.h"
#include "../shared/cluster/raft_storage.h"
#include "../shared/crypto/tls_context.h"

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
    // How long a node may be silent before the leader moves its replicas, zero for four election timeouts.
    uint64_t    down_after_ms  = 0;

    bool enabled() const { return !listen.empty(); }
};

// The operator's reason when the configuration cannot run, empty when it can.
std::string raft_config_refusal(const raft_host_config& c);

// The operator's reason the failure timing cannot be safe against this tick and election timeout, empty when it can; judged once the tick is known.
std::string raft_timing_refusal(const raft_host_config& c);

// "4", "4s" or "3500ms" as milliseconds, false on anything else or on zero or more than a day.
bool parse_raft_down_after(std::string_view text, uint64_t& ms);

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
    const socketley::cluster::state& cluster() const { return m_brain->current(); }
    const socketley::cluster::brain& brain() const { return *m_brain; }
    // What this node should be running right now, and whether it may, with each cache follower told where its primary is.
    socketley::cluster::want desired() const;
    // How long the lease this node holds still has, which is how long an order to a replica may stand.
    uint64_t lease_left_ms() const { return m_brain->lease_left_ms(now_ms()); }
    // What this node's cache replicas say about their copies, for the next lease request.
    void set_replica_reports(std::vector<socketley::cluster::replica_report> r) { m_brain->set_reports(std::move(r)); }
    // Where each cache's primary is reached, as host and port, for the runtimes this node's applied state gives one.
    std::map<std::string, std::pair<std::string, uint16_t>> primary_endpoints() const;
    // Called at the end of every Raft tick, which is where the daemon reconciles its runtimes with desired().
    void set_on_tick(std::function<void()> fn) { m_on_tick = std::move(fn); }
    uint64_t now_ms() const;
    // The name a member goes by, or its hex id when the book does not hold it.
    std::string node_name(socketley::raft::node_id id) const;
    socketley::raft::node_id self() const { return m_id; }
    // What `socketley cluster placement` prints about the runtimes and the nodes, from this node's applied state.
    std::string placement() const;

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
    socketley::cluster::view make_view();
    void drive_cluster();
    void flush_cluster(socketley::cluster::output& out);
    void handle_join(const std::string& payload_frame, socketley::raft::node_id id, const std::string& name,
                     const std::string& addr, bool voter);
    void try_join();
    void promote_learners();
    void ensure_own_record();
    // Why `name` cannot be given to node `id`, empty when no other member's {node} label is the same.
    std::string name_conflict(socketley::raft::node_id id, const std::string& name) const;

    void retire(link* l);
    void reap();

    const member* lookup(socketley::raft::node_id id) const;
    // The address the followers of cache `name` dial, from its primary's flags and the host its node advertises; empty when nobody leads it.
    std::string primary_address(const std::string& name) const;
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
    // Placement, liveness and the serving lease, over the desired state applied from the log like the book.
    std::unique_ptr<socketley::cluster::brain> m_brain;
    socketley::raft::index_t m_last_proposed = 0;
    std::function<void()>    m_on_tick;
    clock::time_point        m_epoch = clock::now();
    // What is kept of nodes no membership lists, bounded since their ids are theirs to choose.
    static constexpr size_t max_heard = 1024;
    // Inbound links open at once, past which an accepted socket is closed.
    static constexpr size_t max_inbound = 256;
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
    uint64_t    m_join_tried = 0;

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
