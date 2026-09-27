#pragma once
// Raft as a pure state machine: messages, ticks and proposals go in, a ready
// comes out, and the host owns every socket, disk write, clock and thread.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace socketley::raft
{

using node_id = uint64_t;
using term_t  = uint64_t;
using index_t = uint64_t;

inline constexpr node_id no_node = 0;

enum class entry_type : uint8_t { normal, noop, config };

struct entry
{
    term_t      term  = 0;
    index_t     index = 0;
    entry_type  type  = entry_type::normal;
    // A config entry's data is the whole voter set it installs, see encode_voters().
    std::string data;

    bool operator==(const entry&) const = default;
};

// The state machine as of `index`, plus the voter set in force at that index.
struct snapshot
{
    index_t              index = 0;
    term_t               term  = 0;
    std::vector<node_id> voters;
    std::string          data;
};

struct hard_state
{
    term_t  term = 0;
    node_id vote = no_node;

    bool operator==(const hard_state&) const = default;
};

enum class msg_type : uint8_t
{
    pre_vote, pre_vote_resp,
    vote, vote_resp,
    append, append_resp,
    heartbeat, heartbeat_resp,
    snapshot,
    read_index, read_index_resp,
};

struct message
{
    msg_type type = msg_type::append;
    node_id  from = no_node;
    node_id  to   = no_node;
    term_t   term = 0;

    // The log position before `entries` on append, the candidate's last on a vote, the probed one on append_resp.
    index_t  index    = 0;
    term_t   log_term = 0;
    index_t  commit   = 0;
    std::vector<entry> entries;

    bool     reject     = false;
    // On success the follower's last index known to match; on reject where its conflicting term begins.
    index_t  hint_index = 0;
    term_t   hint_term  = 0;

    // The leader's read round on append and heartbeat traffic, the request id on read_index traffic.
    uint64_t context = 0;

    std::shared_ptr<const raft::snapshot> snap;
};

enum class role : uint8_t { follower, pre_candidate, candidate, leader };

struct read_state
{
    uint64_t request = 0;
    // The host may answer the read once it has applied through this index.
    index_t  index   = 0;
};

struct soft_state
{
    raft::role role   = raft::role::follower;
    node_id    leader = no_node;
    term_t     term   = 0;

    bool operator==(const soft_state&) const = default;
};

// One batch of work, done in field order: everything above `messages` is durable before any message leaves.
struct ready
{
    std::optional<hard_state> hard;
    // Store it and drop every durable entry at or below its index.
    std::shared_ptr<const snapshot> snap;
    // Zero, or drop every durable entry at or above this index.
    index_t            truncate_from = 0;
    std::vector<entry> append;

    std::vector<message> messages;

    // Load into the state machine before applying `committed`.
    std::shared_ptr<const snapshot> restore;
    std::vector<entry>      committed;
    std::vector<read_state> reads;
    std::optional<soft_state> soft;
};

enum class propose_status : uint8_t { ok, not_leader, change_pending, no_change, busy };

struct proposal
{
    propose_status status = propose_status::ok;
    index_t        index  = 0;
    term_t         term   = 0;
    node_id        leader = no_node;
};

#ifdef SOCKETLEY_RAFT_FAULTS
// Defects the simulation harness must catch, compiled only into test builds.
enum fault : uint32_t
{
    fault_commit_prior_term   = 1u << 0,
    fault_vote_ignores_log    = 1u << 1,
    fault_forget_vote         = 1u << 2,
    fault_truncate_on_append  = 1u << 3,
    fault_read_without_quorum = 1u << 4,
    fault_concurrent_config   = 1u << 5,
    fault_skip_pre_vote       = 1u << 6,
    fault_no_check_quorum     = 1u << 7,
};
#endif

struct options
{
    node_id  id                 = no_node;
    uint32_t election_ticks     = 10;
    uint32_t heartbeat_ticks    = 1;
    size_t   max_append_entries = 64;
    // A leader refuses proposals while this many entries are uncommitted, so a slow quorum cannot grow the log without bound.
    size_t   max_uncommitted    = 4096;
    // Seeds the election-timeout jitter, the only randomness in the core.
    uint64_t seed               = 0;
#ifdef SOCKETLEY_RAFT_FAULTS
    uint32_t faults             = 0;
#endif
};

// What the host read back from disk; a new cluster member starts from an index-0 snapshot naming the voters.
struct persisted
{
    hard_state         hard;
    snapshot           snap;
    std::vector<entry> log;
};

std::string          encode_voters(const std::vector<node_id>& voters);
std::vector<node_id> decode_voters(const std::string& data);

class node
{
public:
    node(const options& opts, persisted state);

    void tick();
    void step(const message& m);

    proposal propose(std::string data);
    proposal propose_add(node_id id);
    proposal propose_remove(node_id id);

    // False when no leader is known; otherwise a read_state for `request` arrives in a later ready, or never.
    bool read_index(uint64_t request);

    // The host has a snapshot of its state machine through `index`, which must not exceed what it has applied.
    bool compact(index_t index, std::string data);

    bool  has_ready() const;
    ready take_ready();

    node_id    id() const { return m_opts.id; }
    raft::role current_role() const { return m_role; }
    term_t     term() const { return m_term; }
    node_id    vote() const { return m_vote; }
    node_id    leader() const { return m_leader; }
    index_t    commit_index() const { return m_commit; }
    index_t    applied_index() const { return m_applied; }
    index_t    first_index() const { return m_snap->index + 1; }
    index_t    last_index() const { return m_snap->index + m_log.size(); }
    term_t     last_term() const;
    std::optional<term_t> term_at(index_t i) const;
    const entry* entry_at(index_t i) const;
    const std::vector<node_id>& voters() const { return m_voters; }
    const snapshot& current_snapshot() const { return *m_snap; }

private:
    enum class progress_state : uint8_t { probe, replicate, snapshot };

    struct progress
    {
        index_t        next  = 1;
        index_t        match = 0;
        progress_state state = progress_state::probe;
        bool           paused        = false;
        bool           recent_active = false;
        index_t        match_at_heartbeat = 0;
        index_t        pending_snapshot   = 0;
        uint32_t       snapshot_ticks     = 0;
    };

    struct pending_read
    {
        node_id  from    = no_node;
        uint64_t request = 0;
        index_t  index   = 0;
        uint64_t round   = 0;
        std::vector<node_id> acks;
    };

    uint32_t random_below(uint32_t bound);
    message make(msg_type type, node_id to) const;

    bool is_voter(node_id id) const;
    size_t quorum() const { return m_voters.size() / 2 + 1; }
    bool promotable() const { return is_voter(m_opts.id); }
    bool in_lease() const;

    void reset(term_t term);
    void become_follower(term_t term, node_id leader);
    void become_leader();
    void campaign(bool pre);
    void tally(const message& m);
    size_t count_votes(bool granted) const;
    void tick_election();
    void tick_leader();

    void send(message m) { m_msgs.push_back(std::move(m)); }
    void send_append(node_id to, progress& p);
    void send_heartbeat(node_id to, const progress& p);
    void bcast_append();
    void bcast_heartbeat();

    void handle_vote_request(const message& m);
    void handle_append(const message& m);
    void handle_heartbeat(const message& m);
    void handle_snapshot(const message& m);
    void handle_append_resp(const message& m);
    void handle_heartbeat_resp(const message& m);
    void handle_leader_read(node_id from, uint64_t request);

    void append_entry(entry e);
    void truncate_from(index_t i);
    void commit_to(index_t i);
    bool maybe_commit();
    void after_commit();
    void refresh_config();
    void sync_progress();
    std::vector<node_id> voters_at(index_t i) const;
    proposal propose_config(std::vector<node_id> voters);
    bool backlogged() const;

    void ack_read(node_id from, uint64_t round);
    void release_reads();
    void release_read(const pending_read& r);

    options  m_opts;
    uint64_t m_rng;

    term_t     m_term   = 0;
    node_id    m_vote   = no_node;
    node_id    m_leader = no_node;
    raft::role m_role   = raft::role::follower;

    std::shared_ptr<const snapshot> m_snap;
    std::deque<entry> m_log;
    index_t m_commit  = 0;
    index_t m_applied = 0;

    std::vector<node_id> m_voters;
    // Index of the entry that installed m_voters, or the snapshot's index.
    index_t m_conf_index = 0;

    uint32_t m_election_elapsed   = 0;
    uint32_t m_heartbeat_elapsed  = 0;
    uint32_t m_randomized_timeout = 0;

    std::map<node_id, bool>     m_votes;
    std::map<node_id, progress> m_progress;
    // First index of the leader's own term, so "committed an entry of this term" is one comparison.
    index_t m_term_start = 0;

    uint64_t m_read_round = 0;
    std::deque<pending_read> m_pending_reads;
    // Reads that arrived before this leader committed in its term.
    std::vector<std::pair<node_id, uint64_t>> m_deferred_reads;

    // Output bookkeeping for take_ready().
    hard_state m_last_hard;
    soft_state m_last_soft;
    bool       m_snap_dirty = false;
    index_t    m_unstable_from = 1;
    index_t    m_truncate_from = 0;
    std::shared_ptr<const snapshot> m_pending_restore;
    std::vector<message>    m_msgs;
    std::vector<read_state> m_reads;
};

}   // namespace socketley::raft
