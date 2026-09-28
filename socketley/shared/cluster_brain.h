#pragma once
// What a node decides about the cluster's runtimes: who is alive, where the replicas go, and whether it may still serve what it holds.
#include "cluster_state.h"
#include "raft.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace socketley::cluster
{

// Every duration in milliseconds of the caller's monotonic clock; the brain reads no clock of its own.
struct timing
{
    // The base election timeout, which a leader change takes one to two of.
    uint64_t election_ms = 1000;
    // A node the leader has not heard a lease request from for this long is down and its replicas move.
    uint64_t down_after_ms = 4000;

    // How long a granted lease lasts: long enough to carry a node through a leader change, and a quarter of down_after short of the leader moving its replicas.
    uint64_t lease_ms() const { return down_after_ms * 3 / 4; }
    uint64_t request_every_ms() const { return election_ms / 4 ? election_ms / 4 : 1; }
};

// The refusal a timing that would let a node serve after the leader moved its replicas, empty when it is safe.
std::string timing_refusal(const timing& t);

// What the host reads off its Raft node and hands over with every call.
struct view
{
    raft::role role = raft::role::follower;
    node_id    leader = 0;
    // Sorted, and only the members that vote.
    std::vector<node_id> voters;
    raft::index_t commit  = 0;
    raft::index_t applied = 0;
    // The end of the log, which holds every change that has been or may yet be committed.
    raft::index_t last    = 0;
    // A leader that heard from a quorum of voters within the last election timeout.
    bool quorum = false;
    // A leader that has committed an entry of its own term, so its commit index covers everything any earlier leader committed.
    bool stable = false;
    // A stable leader whose state machine has applied everything committed, its own proposals included, so a plan is made on the log's truth.
    bool settled = false;
};

// The view of a Raft node the brain works from, where `applied` is what the host's state machine has applied and `last_proposed` the last index the brain had proposed in this leadership.
view view_of(const raft::node& n, raft::index_t applied, raft::index_t last_proposed);

struct frame
{
    enum class kind : uint8_t { lease_req, lease_grant };

    kind     type = kind::lease_req;
    node_id  to   = 0;
    uint64_t nonce = 0;
    // On a grant, the end of the leader's log, which a node whose lease had lapsed must have applied before it serves.
    raft::index_t index = 0;
};

struct output
{
    // Encoded commands the leader should propose, in order.
    std::vector<std::string> proposals;
    std::vector<frame>       frames;
};

// What this node should be running.
struct want
{
    struct item
    {
        std::string name;
        std::string type;
        // The args with {node} already expanded for this node.
        std::string args;
    };

    // False when the node cannot confirm it still owns what it holds, and every replica must be stopped.
    bool              serving = false;
    std::vector<item> owned;
};

class brain
{
public:
    brain(node_id self, std::string self_name, timing t);

    // The state machine, driven by the committed log.
    bool apply(const command& c) { return m_state.apply(c); }
    void restore(state s) { m_state = std::move(s); }
    const state& current() const { return m_state; }
    // The host has applied the log through `index`.
    void note_applied(raft::index_t index) { m_applied = std::max(m_applied, index); }

    // Once per Raft tick: renews this node's lease, asks the leader for one, and on a leader plans the placement.
    void tick(uint64_t now, const view& v, output& out);
    // A follower asked to be counted alive; only a leader with a quorum answers, and only a voter is remembered.
    void on_lease_req(node_id from, uint64_t nonce, uint64_t now, const view& v, output& out);
    // The leader granted what this node asked for at the time `nonce` was sent, so the lease runs from then and not from now.
    void on_lease_grant(node_id from, uint64_t nonce, raft::index_t index, uint64_t now, const view& v);

    // Whether this node may run the replicas it holds.
    bool serving(uint64_t now) const { return now < m_lease_until && m_applied >= m_gate; }
    uint64_t lease_left_ms(uint64_t now) const { return now < m_lease_until ? m_lease_until - now : 0; }
    want desired(uint64_t now) const;

    // The voters this leader counts alive at `now`, itself included; empty on a node that is not the leader.
    std::vector<node_id> live(uint64_t now, const view& v) const;
    // How long ago the leader last heard `id` ask for a lease, or nothing when it has not since it became leader.
    std::optional<uint64_t> heard_ms_ago(node_id id, uint64_t now) const;

    node_id self() const { return m_self; }
    const timing& times() const { return m_timing; }

private:
    node_id     m_self;
    std::string m_name;
    timing      m_timing;
    state       m_state;

    bool     m_leading      = false;
    uint64_t m_leader_since = 0;
    std::map<node_id, uint64_t> m_last_req;

    uint64_t m_lease_until = 0;
    // A lease that lapsed and was granted again counts only once this node has applied what the leader had committed, since it may have been moved from in between.
    raft::index_t m_gate    = 0;
    raft::index_t m_applied = 0;
    uint64_t m_next_req    = 0;
    node_id  m_asked       = 0;
    uint64_t m_nonce       = 0;
    // Requests sent and not yet granted, by the time each was sent.
    std::map<uint64_t, uint64_t> m_sent;
};

}   // namespace socketley::cluster
