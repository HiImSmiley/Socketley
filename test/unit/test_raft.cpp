#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/cluster/raft.h"
#include "../../socketley/shared/cluster/raft_codec.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Whole Raft clusters simulated from one seed each, every step checked against the paper's safety invariants and raft.h's persistence contract.

namespace raft = socketley::raft;

namespace {

// ─── deterministic randomness ───

struct prng
{
    uint64_t s;

    uint64_t next()
    {
        uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    uint64_t below(uint64_t n) { return n ? next() % n : 0; }
    bool permille(uint32_t p) { return below(1000) < p; }
    template <class T> const T& pick(const std::vector<T>& v) { return v[below(v.size())]; }
};

uint64_t chain(uint64_t h, const raft::entry& e)
{
    auto mix = [&h](uint64_t v)
    {
        for (int b = 0; b < 8; ++b)
        {
            h ^= (v >> (8 * b)) & 0xFF;
            h *= 0x100000001B3ull;
        }
    };
    mix(e.index);
    mix(e.term);
    mix(static_cast<uint64_t>(e.type));
    for (unsigned char c : e.data)
    {
        h ^= c;
        h *= 0x100000001B3ull;
    }
    return h;
}

std::string encode_sm(raft::index_t applied, uint64_t hash)
{
    char buf[48];
    std::snprintf(buf, sizeof buf, "%llu:%llu",
                  static_cast<unsigned long long>(applied), static_cast<unsigned long long>(hash));
    return buf;
}

bool decode_sm(const std::string& s, raft::index_t& applied, uint64_t& hash)
{
    unsigned long long a = 0, h = 0;
    if (std::sscanf(s.c_str(), "%llu:%llu", &a, &h) != 2)
        return false;
    applied = a;
    hash    = h;
    return true;
}

const char* type_name(raft::msg_type t)
{
    switch (t)
    {
    case raft::msg_type::pre_vote:        return "pre_vote";
    case raft::msg_type::pre_vote_resp:   return "pre_vote_resp";
    case raft::msg_type::vote:            return "vote";
    case raft::msg_type::vote_resp:       return "vote_resp";
    case raft::msg_type::append:          return "append";
    case raft::msg_type::append_resp:     return "append_resp";
    case raft::msg_type::heartbeat:       return "heartbeat";
    case raft::msg_type::heartbeat_resp:  return "heartbeat_resp";
    case raft::msg_type::snapshot:        return "snapshot";
    case raft::msg_type::read_index:      return "read_index";
    case raft::msg_type::read_index_resp: return "read_index_resp";
    case raft::msg_type::timeout_now:     return "timeout_now";
    }
    return "?";
}

const char* role_name(raft::role r)
{
    switch (r)
    {
    case raft::role::follower:      return "follower";
    case raft::role::pre_candidate: return "pre_candidate";
    case raft::role::candidate:     return "candidate";
    case raft::role::leader:        return "leader";
    }
    return "?";
}

// ─── the simulated world ───

// How hostile one seed's world is, drawn from the seed itself.
struct profile
{
    uint32_t loss            = 0;   // permille of messages dropped
    uint32_t dup             = 0;   // permille of messages delivered twice
    uint32_t max_delay       = 1;   // ticks, on top of the one every message takes
    uint32_t crash           = 0;   // permille per node per tick
    uint32_t max_down        = 40;  // ticks a crashed node stays down, at most
    uint32_t partition_every = 0;   // ticks between network changes, 0 never
    uint32_t proposals       = 0;   // permille per tick
    uint32_t config          = 0;   // permille per tick
    uint32_t reads           = 0;   // permille per tick
    uint32_t transfers       = 0;   // permille per tick
    uint32_t compact_every   = 16;  // applied entries between snapshots
    size_t   batch           = 64;  // max entries per append
    size_t   backlog         = 16;  // max uncommitted entries at a leader
    uint32_t heartbeat       = 1;
    uint32_t tick_skip       = 50;  // permille of node ticks skipped, at most, each node drawing its own rate
};

profile random_profile(prng& r)
{
    static const std::vector<uint32_t> loss      = {0, 20, 100, 250};
    static const std::vector<uint32_t> dup       = {0, 30, 150};
    static const std::vector<uint32_t> delay     = {0, 1, 2, 4};
    static const std::vector<uint32_t> crash     = {0, 2, 6, 15};
    static const std::vector<uint32_t> part      = {0, 30, 80, 150};
    static const std::vector<uint32_t> config    = {0, 10, 60, 250};
    static const std::vector<uint32_t> compact   = {2, 4, 16, 64};
    static const std::vector<size_t>   batch     = {1, 2, 4, 64};
    static const std::vector<uint32_t> heartbeat = {1, 2};

    profile p;
    p.loss            = r.pick(loss);
    p.dup             = r.pick(dup);
    p.max_delay       = r.pick(delay);
    p.crash           = r.pick(crash);
    p.max_down        = 5 + static_cast<uint32_t>(r.below(60));
    p.partition_every = r.pick(part);
    p.proposals       = 100 + static_cast<uint32_t>(r.below(600));
    p.config          = r.pick(config);
    p.reads           = static_cast<uint32_t>(r.below(300));
    p.compact_every   = r.pick(compact);
    p.batch           = r.pick(batch);
    p.heartbeat       = r.pick(heartbeat);
    static const std::vector<uint32_t> drift = {0, 100, 400};
    p.tick_skip       = r.pick(drift);
    static const std::vector<uint32_t> transfer = {0, 10, 40, 150};
    p.transfers       = r.pick(transfer);
    return p;
}

struct sim_options
{
    int      voters         = 3;
    int      spares         = 1;
    uint64_t seed           = 1;
    uint32_t faults         = 0;
    uint32_t election       = 10;
    int      chaos_ticks    = 500;
    int      liveness_bound = 300;
    bool     check_contract = true;
    bool     trace          = false;
};

struct stats
{
    uint64_t steps = 0, delivered = 0, dropped = 0, crashes = 0;
    uint64_t leaders = 0, committed = 0, restores = 0, compactions = 0;
    uint64_t config_commits = 0, reads = 0, liveness_ticks = 0;
    uint64_t transfers = 0, learner_applies = 0;
};

struct outcome
{
    bool        ok = true;
    std::string invariant;
    std::string detail;
    uint64_t    step = 0;
    uint64_t    tick = 0;
    stats       st;
};

struct durable
{
    raft::hard_state         hard;
    raft::snapshot           snap;
    std::vector<raft::entry> log;

    raft::index_t last() const { return log.empty() ? snap.index : log.back().index; }
};

struct sim_node
{
    raft::node_id               id = 0;
    std::unique_ptr<raft::node> n;
    durable                     disk;
    int64_t                     restart_at = -1;
    // A slow clock, so a lease that trusts time can be caught trusting it.
    uint32_t                    clock_skip = 0;

    raft::index_t applied  = 0;
    uint64_t      sm_hash  = 0;
    raft::index_t commit_seen = 0;
    bool          log_dirty   = true;

    // The log a leader held at its last check, which it may only extend.
    raft::term_t             shadow_term = 0;
    raft::index_t            shadow_base = 0;
    std::vector<raft::entry> shadow;
};

struct flight
{
    uint64_t      at = 0;
    raft::message m;
};

struct committed_entry
{
    raft::entry  e;
    uint64_t     hash = 0;
    raft::term_t commit_term = 0;
};

class cluster
{
public:
    cluster(const sim_options& o, const profile& p) : m_o(o), m_p(p), m_rng{o.seed * 0x2545F4914F6CDD1Dull + 1}
    {
        const int total = o.voters + o.spares;
        m_blocked.assign(total + 1, std::vector<bool>(total + 1, false));
        std::vector<raft::node_id> voters;
        for (int i = 1; i <= o.voters; ++i)
            voters.push_back(static_cast<raft::node_id>(i));

        m_nodes.resize(total);
        for (int i = 0; i < total; ++i)
        {
            sim_node& sn = m_nodes[i];
            sn.id = static_cast<raft::node_id>(i + 1);
            sn.disk.snap.voters = i < o.voters ? voters : std::vector<raft::node_id>{};
            sn.disk.snap.data   = encode_sm(0, 0);
            sn.clock_skip       = static_cast<uint32_t>(m_rng.below(p.tick_skip + 1));
            boot(sn);
        }
    }

    // ─── driving ───

    void advance(int ticks)
    {
        for (int i = 0; i < ticks && !m_fail; ++i)
            one_tick();
    }

    // The chaos phase, then a healed network in which a leader must emerge and commit on every voter.
    outcome run()
    {
        advance(m_o.chaos_ticks);
        if (!m_fail)
            heal_and_prove_liveness();
        return result();
    }

    outcome result() const
    {
        outcome r;
        if (m_fail)
            r = *m_fail;
        r.st       = m_stats;
        r.st.steps = m_step;
        return r;
    }

    void block(raft::node_id a, raft::node_id b, bool on) { m_blocked[a][b] = on; }

    void isolate(raft::node_id id, bool on)
    {
        for (size_t o = 1; o < m_blocked.size(); ++o)
        {
            if (o == id)
                continue;
            m_blocked[id][o] = on;
            m_blocked[o][id] = on;
        }
    }

    const raft::node* node(raft::node_id id) const { return m_nodes[id - 1].n.get(); }
    raft::node*       node(raft::node_id id) { return m_nodes[id - 1].n.get(); }

    raft::node_id leader() const
    {
        raft::node_id best = 0;
        raft::term_t  term = 0;
        for (const sim_node& sn : m_nodes)
            if (sn.n && sn.n->current_role() == raft::role::leader && sn.n->term() >= term)
            {
                best = sn.id;
                term = sn.n->term();
            }
        return best;
    }

    bool propose(raft::node_id id, std::string data)
    {
        sim_node& sn = m_nodes[id - 1];
        bool ok = false;
        event(sn, [&](raft::node& n) { ok = n.propose(std::move(data)).status == raft::propose_status::ok; });
        return ok;
    }

    // Anything a host may call on a node, with the ready it produces handled like every other.
    template <class F>
    void act(raft::node_id id, F&& f) { event(m_nodes[id - 1], std::forward<F>(f)); }

    raft::index_t applied(raft::node_id id) const { return m_nodes[id - 1].applied; }
    const stats&  counters() const { return m_stats; }
    bool          failed() const { return m_fail.has_value(); }

private:
    // ─── node lifecycle ───

    void boot(sim_node& sn)
    {
        raft::options opts;
        opts.id                 = sn.id;
        opts.election_ticks     = m_o.election;
        opts.heartbeat_ticks    = m_p.heartbeat;
        opts.max_append_entries = m_p.batch;
        opts.max_uncommitted    = m_p.backlog;
        opts.seed               = m_rng.next();
        opts.faults             = m_o.faults;

        raft::persisted p;
        p.hard = sn.disk.hard;
        p.snap = sn.disk.snap;
        p.log  = sn.disk.log;
        sn.n   = std::make_unique<raft::node>(opts, std::move(p));

        raft::index_t a = 0;
        uint64_t h = 0;
        if (!decode_sm(sn.disk.snap.data, a, h) || a != sn.disk.snap.index)
            return fail("snapshot content", "node " + std::to_string(sn.id) + " booted from an unreadable snapshot");
        if (!oracle_matches(a, h))
            return fail("state machine safety",
                        "node " + std::to_string(sn.id) + " booted from a snapshot at " + std::to_string(a)
                        + " whose state differs from the committed prefix");
        sn.applied     = a;
        sn.sm_hash     = h;
        sn.commit_seen = a;
        sn.restart_at  = -1;
        sn.shadow_term = 0;
        sn.log_dirty   = true;
    }

    void crash(sim_node& sn)
    {
        if (!sn.n)
            return;
        trace("crash " + std::to_string(sn.id));
        sn.n.reset();
        sn.shadow_term = 0;
        sn.restart_at  = static_cast<int64_t>(m_tick + 1 + m_rng.below(m_p.max_down));
        ++m_stats.crashes;
    }

    // ─── one tick of the world ───

    void one_tick()
    {
        ++m_tick;

        for (sim_node& sn : m_nodes)
            if (!sn.n && sn.restart_at >= 0 && static_cast<uint64_t>(sn.restart_at) <= m_tick)
            {
                trace("restart " + std::to_string(sn.id));
                boot(sn);
                check();
            }

        if (m_p.partition_every && m_tick % m_p.partition_every == 0)
            reshape_network();

        deliver_due();

        for (size_t k : shuffled(m_nodes.size()))
        {
            sim_node& sn = m_nodes[k];
            if (sn.n && !m_rng.permille(sn.clock_skip))
                event(sn, [](raft::node& n) { n.tick(); });
        }

        for (sim_node& sn : m_nodes)
            if (sn.n && m_rng.permille(m_p.crash))
                crash(sn);

        clients();
    }

    void clients()
    {
        std::vector<raft::node_id> leaders, live;
        for (const sim_node& sn : m_nodes)
        {
            if (!sn.n)
                continue;
            live.push_back(sn.id);
            if (sn.n->current_role() == raft::role::leader)
                leaders.push_back(sn.id);
        }

        if (!leaders.empty() && m_rng.permille(m_p.proposals))
        {
            const std::string data = "s" + std::to_string(m_o.seed) + "-" + std::to_string(++m_proposal);
            event(m_nodes[m_rng.pick(leaders) - 1], [&](raft::node& n) { n.propose(data); });
        }

        if (!leaders.empty() && m_rng.permille(m_p.config))
        {
            sim_node& sn = m_nodes[m_rng.pick(leaders) - 1];
            event(sn, [&](raft::node& n) { change_membership(n); });
        }

        if (!leaders.empty() && m_rng.permille(m_p.transfers))
        {
            sim_node& sn = m_nodes[m_rng.pick(leaders) - 1];
            event(sn, [&](raft::node& n)
            {
                std::vector<raft::node_id> others;
                for (raft::node_id v : n.voters())
                    if (v != n.id())
                        others.push_back(v);
                if (!others.empty() && n.transfer_leadership(m_rng.pick(others)))
                    ++m_stats.transfers;
            });
        }

        if (!live.empty() && m_rng.permille(m_p.reads))
        {
            const uint64_t request = ++m_read_request;
            const raft::index_t floor = m_oracle.size();
            // Half go to a node that believes it leads, because a deposed leader is where a stale read lives.
            const bool at_leader = !leaders.empty() && m_rng.below(2);
            sim_node& sn = m_nodes[m_rng.pick(at_leader ? leaders : live) - 1];
            event(sn, [&](raft::node& n)
            {
                // Everything committed before the read began is the floor its answer may not go under.
                if (n.read_index(request))
                    m_read_floor[request] = floor;
            });
        }
    }

    // One single-server change: a spare joins as a learner or a voter, a learner is promoted, or a member leaves.
    void change_membership(raft::node& n)
    {
        const std::vector<raft::node_id>& v = n.voters();
        const std::vector<raft::node_id>& l = n.learners();
        if (static_cast<int>(v.size()) > m_o.voters)
        {
            n.propose_remove(m_rng.pick(v));
            return;
        }
        std::vector<raft::node_id> outside;
        for (const sim_node& o : m_nodes)
            if (!n.is_voter(o.id) && !n.is_learner(o.id))
                outside.push_back(o.id);

        switch (m_rng.below(4))
        {
        case 0:
            if (!outside.empty())
                n.propose_add_learner(m_rng.pick(outside));
            return;
        case 1:
            if (!l.empty())
                n.propose_add(m_rng.pick(l));
            return;
        case 2:
            if (!l.empty())
                n.propose_remove(m_rng.pick(l));
            return;
        default:
            if (!outside.empty())
                n.propose_add(m_rng.pick(outside));
            return;
        }
    }

    void reshape_network()
    {
        for (auto& row : m_blocked)
            std::fill(row.begin(), row.end(), false);

        const size_t total = m_nodes.size();
        switch (m_rng.below(5))
        {
        case 0:
            trace("network: whole");
            break;
        case 1:
        {
            std::vector<bool> side(total + 1);
            for (size_t i = 1; i <= total; ++i)
                side[i] = m_rng.below(2);
            for (size_t a = 1; a <= total; ++a)
                for (size_t b = 1; b <= total; ++b)
                    m_blocked[a][b] = side[a] != side[b];
            trace("network: split");
            break;
        }
        case 2:
            isolate(1 + m_rng.below(total), true);
            trace("network: one isolated");
            break;
        case 3:
            for (size_t a = 1; a <= total; ++a)
                for (size_t b = 1; b <= total; ++b)
                    m_blocked[a][b] = a != b && m_rng.permille(300);
            trace("network: asymmetric links");
            break;
        default:
        {
            // A leader that can hear but not speak, or speak but not hear.
            const raft::node_id l = leader() ? leader() : 1 + m_rng.below(total);
            const bool out = m_rng.below(2);
            for (size_t o = 1; o <= total; ++o)
                if (o != l)
                    (out ? m_blocked[l][o] : m_blocked[o][l]) = true;
            trace(out ? "network: leader mute" : "network: leader deaf");
            break;
        }
        }
    }

    std::vector<size_t> shuffled(size_t n)
    {
        std::vector<size_t> v(n);
        for (size_t i = 0; i < n; ++i)
            v[i] = i;
        for (size_t i = n; i > 1; --i)
            std::swap(v[i - 1], v[m_rng.below(i)]);
        return v;
    }

    void deliver_due()
    {
        std::vector<flight> due;
        for (size_t i = 0; i < m_net.size();)
        {
            if (m_net[i].at <= m_tick)
            {
                due.push_back(std::move(m_net[i]));
                m_net[i] = std::move(m_net.back());
                m_net.pop_back();
            }
            else
            {
                ++i;
            }
        }
        for (size_t k : shuffled(due.size()))
        {
            if (m_fail)
                return;
            const raft::message& m = due[k].m;
            sim_node& to = m_nodes[m.to - 1];
            if (!to.n || m_blocked[m.from][m.to])
            {
                ++m_stats.dropped;
                continue;
            }
            ++m_stats.delivered;
            if (m_o.trace)
                trace_msg("deliver", m);
            event(to, [&](raft::node& n) { n.step(m); });
        }
    }

    void send(const raft::message& sent)
    {
        // Every message crosses the wire codec, so the sweep proves the encoding along with the core.
        raft::message m;
        std::string why;
        const std::string payload = raft::wire::encode(sent);
        raft::wire::frame f;
        if (!raft::wire::decode(payload, f, &why) || f.kind != raft::wire::kind::message || !raft::wire::same(sent, f.msg))
            return fail("wire codec", std::string(type_name(sent.type)) + " from node " + std::to_string(sent.from)
                        + " did not survive encoding: " + (why.empty() ? "decoded to something else" : why));
        m = std::move(f.msg);

        if (m_rng.permille(m_p.loss))
        {
            ++m_stats.dropped;
            return;
        }
        const int copies = m_rng.permille(m_p.dup) ? 2 : 1;
        for (int c = 0; c < copies; ++c)
            m_net.push_back(flight{m_tick + 1 + m_rng.below(m_p.max_delay + 1), m});
    }

    // ─── the host's side of the ready contract ───

    template <class F>
    void event(sim_node& sn, F&& f)
    {
        if (m_fail || !sn.n)
            return;
        ++m_step;
        f(*sn.n);
        for (int guard = 0; sn.n && sn.n->has_ready() && !m_fail && guard < 8; ++guard)
            process_ready(sn);
        if (!m_fail)
            check();
    }

    // A crash inside the host's handling of a ready, where the contract says what may have happened.
    bool crash_point(sim_node& sn)
    {
        if (!m_rng.permille(m_p.crash * 10))
            return false;
        crash(sn);
        return true;
    }

    void process_ready(sim_node& sn)
    {
        raft::ready r = sn.n->take_ready();
        if (r.soft)
        {
            trace("node " + std::to_string(sn.id) + " is " + role_name(r.soft->role)
                  + " term " + std::to_string(r.soft->term) + " leader " + std::to_string(r.soft->leader));
            if (r.soft->role == raft::role::leader)
                ++m_stats.leaders;
        }

        if (crash_point(sn))
            return;

        durable& d = sn.disk;
        if (r.snap || r.truncate_from || !r.append.empty() || r.restore)
            sn.log_dirty = true;
        if (r.hard)
            d.hard = *r.hard;
        if (r.snap)
        {
            d.snap = *r.snap;
            std::erase_if(d.log, [&](const raft::entry& e) { return e.index <= d.snap.index; });
            if (!check_snapshot(sn, d.snap))
                return;
        }
        if (r.truncate_from)
            std::erase_if(d.log, [&](const raft::entry& e) { return e.index >= r.truncate_from; });
        for (const raft::entry& e : r.append)
        {
            if (e.index != d.last() + 1)
                return fail("persistence contract", "node " + std::to_string(sn.id) + " asked to persist entry "
                            + std::to_string(e.index) + " after durable " + std::to_string(d.last()));
            d.log.push_back(e);
        }
        if (!d.log.empty() && d.log.front().index != d.snap.index + 1)
            return fail("persistence contract", "node " + std::to_string(sn.id) + " durable log does not continue its snapshot");

        if (m_o.check_contract && !check_contract(sn, r))
            return;

        if (crash_point(sn))
            return;

        for (const raft::message& m : r.messages)
            send(m);

        if (crash_point(sn))
            return;

        if (r.restore)
        {
            ++m_stats.restores;
            raft::index_t a = 0;
            uint64_t h = 0;
            if (!decode_sm(r.restore->data, a, h) || a != r.restore->index)
                return fail("snapshot content", "node " + std::to_string(sn.id) + " was sent an unreadable snapshot");
            if (!oracle_matches(a, h))
                return fail("state machine safety", "node " + std::to_string(sn.id) + " restored a snapshot at "
                            + std::to_string(a) + " that differs from the committed prefix");
            sn.applied     = a;
            sn.sm_hash     = h;
            sn.commit_seen = std::max(sn.commit_seen, a);
        }

        for (const raft::entry& e : r.committed)
        {
            if (e.index != sn.applied + 1)
                return fail("apply order", "node " + std::to_string(sn.id) + " applied " + std::to_string(e.index)
                            + " after " + std::to_string(sn.applied));
            if (!record(e, sn.n->term(), sn.id))
                return;
            if (sn.n->is_learner(sn.id))
                ++m_stats.learner_applies;
            sn.sm_hash = chain(sn.sm_hash, e);
            sn.applied = e.index;
            if (e.type == raft::entry_type::config)
                ++m_stats.config_commits;
        }

        for (const raft::read_state& rs : r.reads)
        {
            auto it = m_read_floor.find(rs.request);
            // A duplicated read_index is answered twice, and the host keeps the first answer.
            if (it == m_read_floor.end() && rs.request <= m_read_request)
                continue;
            if (it == m_read_floor.end())
                return fail("linearizable read", "node " + std::to_string(sn.id) + " answered read "
                            + std::to_string(rs.request) + " that it was never asked");
            if (rs.index < it->second)
                return fail("linearizable read", "node " + std::to_string(sn.id) + " answered read "
                            + std::to_string(rs.request) + " at index " + std::to_string(rs.index)
                            + " though " + std::to_string(it->second) + " had committed before it was asked");
            m_read_floor.erase(it);
            ++m_stats.reads;
        }

        if (m_p.compact_every && sn.applied >= sn.n->current_snapshot().index + m_p.compact_every)
            if (sn.n->compact(sn.applied, encode_sm(sn.applied, sn.sm_hash)))
                ++m_stats.compactions;
    }

    // Nothing leaves a node that the node could not stand behind after losing its memory.
    bool check_contract(sim_node& sn, const raft::ready& r)
    {
        const durable& d = sn.disk;
        const raft::node& n = *sn.n;
        const std::string who = node_name(sn.id);

        if (d.hard.term != n.term() || d.hard.vote != n.vote())
        {
            fail("persistence contract", who + " holds term " + std::to_string(n.term()) + " vote "
                 + std::to_string(n.vote()) + " but made durable term " + std::to_string(d.hard.term)
                 + " vote " + std::to_string(d.hard.vote));
            return false;
        }
        if (d.last() != n.last_index() || d.snap.index != n.current_snapshot().index)
        {
            fail("persistence contract", who + " log ends at " + std::to_string(n.last_index())
                 + " but the durable one at " + std::to_string(d.last()));
            return false;
        }
        for (const raft::message& m : r.messages)
        {
            const bool future = m.type == raft::msg_type::pre_vote || m.type == raft::msg_type::pre_vote_resp;
            if (!future && m.term > d.hard.term)
            {
                fail("persistence contract", who + " spoke at term " + std::to_string(m.term)
                     + " with " + std::to_string(d.hard.term) + " durable");
                return false;
            }
            if (m.type == raft::msg_type::vote_resp && !m.reject && d.hard.vote != m.to)
            {
                fail("persistence contract", who + " granted a vote to " + std::to_string(m.to)
                     + " that is not durable");
                return false;
            }
            if (m.type == raft::msg_type::append_resp && !m.reject && m.hint_index > d.last())
            {
                fail("persistence contract", who + " acknowledged " + std::to_string(m.hint_index)
                     + " with only " + std::to_string(d.last()) + " durable");
                return false;
            }
        }
        return true;
    }

    // ─── the oracle ───

    bool oracle_matches(raft::index_t i, uint64_t hash) const
    {
        if (i == 0)
            return hash == 0;
        return i <= m_oracle.size() && m_oracle[i - 1].hash == hash;
    }

    bool check_snapshot(const sim_node& sn, const raft::snapshot& s)
    {
        if (s.index == 0)
            return true;
        if (s.index > m_oracle.size() || m_oracle[s.index - 1].e.term != s.term)
        {
            fail("state machine safety", "node " + std::to_string(sn.id) + " holds a snapshot at "
                 + std::to_string(s.index) + " term " + std::to_string(s.term) + " that nobody committed");
            return false;
        }
        return true;
    }

    // Every committed index names exactly one entry, whoever commits or applies it and whenever.
    bool record(const raft::entry& e, raft::term_t observer_term, raft::node_id who)
    {
        if (e.index <= m_oracle.size())
        {
            committed_entry& c = m_oracle[e.index - 1];
            if (!(c.e == e))
            {
                fail("state machine safety", "node " + std::to_string(who) + " committed index "
                     + std::to_string(e.index) + " as term " + std::to_string(e.term) + " '" + e.data
                     + "' where term " + std::to_string(c.e.term) + " '" + c.e.data + "' was committed");
                return false;
            }
            if (observer_term < c.commit_term)
            {
                c.commit_term  = observer_term;
                m_oracle_dirty = true;
            }
            return true;
        }
        if (e.index != m_oracle.size() + 1)
        {
            fail("state machine safety", "node " + std::to_string(who) + " committed index "
                 + std::to_string(e.index) + " with nothing known committed after " + std::to_string(m_oracle.size()));
            return false;
        }
        const uint64_t prev = m_oracle.empty() ? 0 : m_oracle.back().hash;
        m_oracle.push_back(committed_entry{e, chain(prev, e), observer_term});
        m_oracle_dirty = true;
        ++m_stats.committed;
        return true;
    }

    static std::string node_name(raft::node_id id) { return "node " + std::to_string(id); }

    // Logs change only through a ready, so the O(log) checks run on the steps where one did.
    void check()
    {
        bool any_log_changed = false;
        for (sim_node& sn : m_nodes)
        {
            if (!sn.n || m_fail)
                continue;
            const raft::node& n = *sn.n;
            any_log_changed |= sn.log_dirty;

            if (n.commit_index() > n.last_index())
                return fail("log holds its commit", node_name(sn.id) + " commit " + std::to_string(n.commit_index())
                            + " is past its last entry " + std::to_string(n.last_index()));

            for (raft::index_t i = sn.commit_seen + 1; i <= n.commit_index(); ++i)
            {
                const raft::entry* e = n.entry_at(i);
                if (e && !record(*e, n.term(), sn.id))
                    return;
            }
            sn.commit_seen = std::max(sn.commit_seen, n.commit_index());

            if (n.current_role() != raft::role::leader)
            {
                sn.shadow_term = 0;
                continue;
            }

            auto [it, fresh] = m_leader_of_term.emplace(n.term(), sn.id);
            if (!fresh && it->second != sn.id)
                return fail("election safety", "nodes " + std::to_string(it->second) + " and "
                            + std::to_string(sn.id) + " both led term " + std::to_string(n.term()));

            const bool same_leadership = sn.shadow_term == n.term();
            if (same_leadership && !sn.log_dirty)
            {
                const raft::index_t end = sn.shadow_base + sn.shadow.size();
                if (end != n.last_index() || (!sn.shadow.empty() && n.last_term() != sn.shadow.back().term))
                    return fail("persistence contract", node_name(sn.id) + " changed its log without a ready");
            }
            else
            {
                if (same_leadership && !check_append_only(sn, n))
                    return;
                sn.shadow_term = n.term();
                sn.shadow_base = n.current_snapshot().index;
                sn.shadow.clear();
                for (raft::index_t i = n.first_index(); i <= n.last_index(); ++i)
                    sn.shadow.push_back(*n.entry_at(i));
            }

            if ((!same_leadership || sn.log_dirty || m_oracle_dirty) && !check_completeness(sn, n))
                return;
        }

        if (any_log_changed)
            check_log_matching();
        for (sim_node& sn : m_nodes)
            sn.log_dirty = false;
        m_oracle_dirty = false;
    }

    // A leader never rewrites or drops an entry of its own log while it leads.
    bool check_append_only(const sim_node& sn, const raft::node& n)
    {
        for (size_t k = 0; k < sn.shadow.size(); ++k)
        {
            const raft::index_t i = sn.shadow_base + 1 + k;
            if (i <= n.current_snapshot().index)
                continue;
            const raft::entry* e = n.entry_at(i);
            if (!e || !(*e == sn.shadow[k]))
            {
                fail("leader append-only", node_name(sn.id) + " rewrote or dropped index "
                     + std::to_string(i) + " while leading term " + std::to_string(n.term()));
                return false;
            }
        }
        return true;
    }

    // Every entry committed in an earlier term is in this leader's log.
    bool check_completeness(const sim_node& sn, const raft::node& n)
    {
        for (raft::index_t i = n.current_snapshot().index + 1; i <= m_oracle.size(); ++i)
        {
            const committed_entry& c = m_oracle[i - 1];
            if (c.commit_term >= n.term())
                continue;
            const raft::entry* e = n.entry_at(i);
            if (!e || !(*e == c.e))
            {
                fail("leader completeness", node_name(sn.id) + " leads term " + std::to_string(n.term())
                     + " without index " + std::to_string(i) + " committed by term "
                     + std::to_string(c.commit_term));
                return false;
            }
        }
        return true;
    }

    // Two logs holding one term at one index agree on everything before it.
    void check_log_matching()
    {
        for (size_t a = 0; a < m_nodes.size() && !m_fail; ++a)
        {
            const raft::node* x = m_nodes[a].n.get();
            if (!x)
                continue;
            for (size_t b = a + 1; b < m_nodes.size(); ++b)
            {
                const raft::node* y = m_nodes[b].n.get();
                if (!y || !(m_nodes[a].log_dirty || m_nodes[b].log_dirty))
                    continue;
                const raft::index_t lo = std::max(x->first_index(), y->first_index());
                raft::index_t hi = std::min(x->last_index(), y->last_index());
                while (hi >= lo && x->term_at(hi) != y->term_at(hi))
                    --hi;
                for (raft::index_t i = lo; i <= hi; ++i)
                    if (!(*x->entry_at(i) == *y->entry_at(i)))
                        return fail("log matching", "nodes " + std::to_string(a + 1) + " and "
                                    + std::to_string(b + 1) + " agree on index " + std::to_string(hi)
                                    + " but differ at " + std::to_string(i));
            }
        }
    }

    // ─── liveness ───

    void heal_and_prove_liveness()
    {
        for (auto& row : m_blocked)
            std::fill(row.begin(), row.end(), false);
        m_p.loss            = 0;
        m_p.dup             = 0;
        m_p.crash           = 0;
        m_p.partition_every = 0;
        m_p.proposals       = 0;
        m_p.config          = 0;
        m_p.reads           = 0;
        m_p.max_delay       = std::min<uint32_t>(m_p.max_delay, 2);
        for (sim_node& sn : m_nodes)
            if (!sn.n)
                boot(sn);
        trace("healed");

        const uint64_t healed = m_tick;
        std::vector<std::pair<raft::index_t, std::string>> probes;
        raft::node_id probe_leader = 0;
        raft::term_t  probe_term   = 0;

        while (!m_fail && m_tick < healed + static_cast<uint64_t>(m_o.liveness_bound))
        {
            one_tick();
            if (m_fail)
                return;

            const raft::node_id l = leader();
            if (!l)
                continue;
            raft::node& n = *m_nodes[l - 1].n;

            if (l != probe_leader || n.term() != probe_term)
            {
                const std::string data = "live-" + std::to_string(m_o.seed) + "-" + std::to_string(probes.size());
                sim_node& sn = m_nodes[l - 1];
                raft::proposal p;
                event(sn, [&](raft::node& x) { p = x.propose(data); });
                if (p.status == raft::propose_status::ok)
                {
                    probes.emplace_back(p.index, data);
                    probe_leader = l;
                    probe_term   = p.term;
                }
                continue;
            }

            for (const auto& [index, data] : probes)
            {
                if (index > m_oracle.size() || m_oracle[index - 1].e.data != data)
                    continue;
                bool everywhere = true;
                for (raft::node_id v : n.voters())
                    if (m_nodes[v - 1].applied < index)
                        everywhere = false;
                if (everywhere)
                {
                    m_stats.liveness_ticks = m_tick - healed;
                    return;
                }
            }
        }

        std::string state;
        for (const sim_node& sn : m_nodes)
        {
            if (!sn.n)
                continue;
            state += " [" + std::to_string(sn.id) + " " + role_name(sn.n->current_role()) + " t"
                   + std::to_string(sn.n->term()) + " c" + std::to_string(sn.n->commit_index())
                   + " a" + std::to_string(sn.applied) + " last" + std::to_string(sn.n->last_index())
                   + " voters" + std::to_string(sn.n->voters().size()) + "]";
        }
        fail("liveness", "no proposal committed on every voter within " + std::to_string(m_o.liveness_bound)
             + " ticks of healing:" + state);
    }

    // ─── reporting ───

    void fail(std::string invariant, std::string detail)
    {
        if (m_fail)
            return;
        outcome o;
        o.ok        = false;
        o.invariant = std::move(invariant);
        o.detail    = std::move(detail);
        o.step      = m_step;
        o.tick      = m_tick;
        m_fail      = std::move(o);
        trace("VIOLATION " + m_fail->invariant + ": " + m_fail->detail);
    }

    void trace(const std::string& s) const
    {
        if (m_o.trace)
            std::printf("t=%llu s=%llu %s\n", static_cast<unsigned long long>(m_tick),
                        static_cast<unsigned long long>(m_step), s.c_str());
    }

    void trace_msg(const char* what, const raft::message& m) const
    {
        std::printf("t=%llu s=%llu %s %llu->%llu %s term=%llu idx=%llu lt=%llu n=%zu commit=%llu rej=%d hint=%llu/%llu\n",
                    static_cast<unsigned long long>(m_tick), static_cast<unsigned long long>(m_step), what,
                    static_cast<unsigned long long>(m.from), static_cast<unsigned long long>(m.to),
                    type_name(m.type), static_cast<unsigned long long>(m.term),
                    static_cast<unsigned long long>(m.index), static_cast<unsigned long long>(m.log_term),
                    m.entries.size(), static_cast<unsigned long long>(m.commit), m.reject ? 1 : 0,
                    static_cast<unsigned long long>(m.hint_index), static_cast<unsigned long long>(m.hint_term));
    }

    sim_options m_o;
    profile     m_p;
    prng        m_rng;

    std::vector<sim_node> m_nodes;
    std::vector<flight>   m_net;
    std::vector<std::vector<bool>> m_blocked;
    uint64_t m_tick = 0;
    uint64_t m_step = 0;
    uint64_t m_proposal = 0;
    uint64_t m_read_request = 0;

    std::map<raft::term_t, raft::node_id> m_leader_of_term;
    std::vector<committed_entry>          m_oracle;
    bool                                  m_oracle_dirty = false;
    std::map<uint64_t, raft::index_t>     m_read_floor;

    stats m_stats;
    std::optional<outcome> m_fail;
};

// ─── seed sweeps ───

#ifdef NDEBUG
constexpr uint64_t default_seeds = 1000;
#else
// The sanitizer build is there for memory errors, which the first seeds find as well as the last.
constexpr uint64_t default_seeds = 200;
#endif

uint64_t env_u64(const char* name, uint64_t fallback)
{
    const char* v = std::getenv(name);
    return v && *v ? std::strtoull(v, nullptr, 10) : fallback;
}

outcome run_seed(int voters, uint64_t seed, uint32_t faults = 0, bool contract = true)
{
    sim_options o;
    o.voters         = voters;
    o.spares         = voters == 3 ? 1 : 2;
    o.seed           = seed;
    o.faults         = faults;
    o.check_contract = contract;
    o.trace          = env_u64("RAFT_TRACE", 0) != 0;
    prng pr{seed ^ 0xA5A5A5A5DEADBEEFull};
    return cluster(o, random_profile(pr)).run();
}

std::string describe(const outcome& r, uint64_t seed)
{
    return "seed " + std::to_string(seed) + " step " + std::to_string(r.step) + " tick " + std::to_string(r.tick)
         + ": " + r.invariant + ": " + r.detail;
}

void sweep(int voters)
{
    const uint64_t first = env_u64("RAFT_SEED", 1);
    const uint64_t count = env_u64("RAFT_SEED", 0) ? 1 : env_u64("RAFT_SEEDS", default_seeds);

    const auto t0 = std::chrono::steady_clock::now();
    stats total;
    uint64_t worst_liveness = 0, worst_seed = 0;
    for (uint64_t seed = first; seed < first + count; ++seed)
    {
        const outcome r = run_seed(voters, seed);
        if (!r.ok)
        {
            FAIL_CHECK(describe(r, seed));
            return;
        }
        total.steps          += r.st.steps;
        total.delivered      += r.st.delivered;
        total.dropped        += r.st.dropped;
        total.crashes        += r.st.crashes;
        total.leaders        += r.st.leaders;
        total.committed      += r.st.committed;
        total.restores       += r.st.restores;
        total.compactions    += r.st.compactions;
        total.config_commits += r.st.config_commits;
        total.reads          += r.st.reads;
        total.transfers      += r.st.transfers;
        total.learner_applies += r.st.learner_applies;
        if (r.st.liveness_ticks > worst_liveness)
        {
            worst_liveness = r.st.liveness_ticks;
            worst_seed     = seed;
        }
    }
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    MESSAGE(voters << " nodes, " << count << " seeds from " << first << " in " << secs << " s: "
            << total.steps << " steps, " << total.delivered << " delivered, " << total.dropped << " dropped, "
            << total.crashes << " crashes, " << total.leaders << " leaderships, " << total.committed
            << " committed, " << total.compactions << " compactions, " << total.restores
            << " snapshot installs, " << total.config_commits << " config entries applied, " << total.reads
            << " reads served, " << total.transfers << " transfers started, " << total.learner_applies
            << " entries applied by learners; slowest recovery " << worst_liveness << " ticks (seed " << worst_seed << ")");

    // A sweep that never crashed, restored, reconfigured or read would be green about nothing.
    if (count >= 100)
    {
        CHECK(total.crashes > 0);
        CHECK(total.restores > 0);
        CHECK(total.compactions > 0);
        CHECK(total.config_commits > 0);
        CHECK(total.reads > 0);
        CHECK(total.transfers > 0);
        CHECK(total.learner_applies > 0);
    }
}

}   // namespace

TEST_CASE("three-node clusters keep every safety invariant and recover once healed")
{
    sweep(3);
}

TEST_CASE("five-node clusters keep every safety invariant and recover once healed")
{
    sweep(5);
}

// ─── the harness's own teeth ───

// Defects real Raft implementations have shipped, each of which the sweep must turn red.

namespace {

struct planted
{
    const char* name;
    uint32_t    fault;
    bool        contract;
};

// The first seed that breaks a safety invariant, with a liveness failure on the way reported but not accepted.
void hunt(const planted& d, int voters, uint64_t budget)
{
    const std::string name = std::string(d.name) + " (" + std::to_string(voters) + " nodes"
                           + (d.contract ? "" : ", contract checks off") + ")";
    const auto t0 = std::chrono::steady_clock::now();
    uint64_t stalled = 0;
    for (uint64_t seed = 1; seed <= budget; ++seed)
    {
        const outcome r = run_seed(voters, seed, d.fault, d.contract);
        if (r.ok)
            continue;
        if (r.invariant == "liveness")
        {
            if (!stalled++)
                MESSAGE(name << " first stalled a cluster at " << describe(r, seed));
            continue;
        }
        const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        MESSAGE(name << " caught after " << seed << " seeds (" << stalled << " stalled first), " << secs
                << " s: " << describe(r, seed));
        return;
    }
    FAIL_CHECK(name << " survived " << budget << " seeds");
}

}   // namespace

TEST_CASE("every planted safety defect is caught by the sweep")
{
    const planted defects[] = {
        {"commit a previous term's entry by counting", raft::fault_commit_prior_term,   true},
        {"grant a vote without the up-to-date check",  raft::fault_vote_ignores_log,    true},
        {"leave votedFor out of the durable state",     raft::fault_forget_vote,         true},
        {"leave votedFor out of the durable state",     raft::fault_forget_vote,         false},
        {"truncate the log after every append",         raft::fault_truncate_on_append,  true},
        {"answer ReadIndex without a quorum round",     raft::fault_read_without_quorum, true},
        {"allow a second config change in flight",      raft::fault_concurrent_config,   true},
        {"count a learner's log toward the commit",     raft::fault_learner_in_quorum,   true},
        {"count a learner's vote toward an election",   raft::fault_learner_votes,       true},
        {"grant a handed-over vote a second time",      raft::fault_transfer_revotes,    true},
    };
    // Five nodes take thousands of seeds to stage Figure 8, so they are opt-in with RAFT_DEFECT_SEEDS.
    const uint64_t budget = env_u64("RAFT_DEFECT_SEEDS", 5000);
    const bool     both   = env_u64("RAFT_DEFECT_SEEDS", 0) != 0;
    for (const planted& d : defects)
    {
        hunt(d, 3, budget);
        if (both)
            hunt(d, 5, budget);
    }
}

// ─── what the safety sweep cannot see ───

namespace {

profile quiet()
{
    profile p;
    p.max_delay     = 1;
    p.tick_skip     = 0;
    p.compact_every = 0;
    return p;
}

sim_options three(uint32_t faults)
{
    sim_options o;
    o.voters = 3;
    o.spares = 0;
    o.faults = faults;
    return o;
}

// Whether a follower cut off for twenty election timeouts moves the cluster's term when it returns.
bool rejoin_moves_term(uint32_t faults)
{
    cluster c(three(faults), quiet());
    c.advance(100);
    const raft::node_id l = c.leader();
    REQUIRE(l != 0);
    const raft::term_t before = c.node(l)->term();
    const raft::node_id f = l == 1 ? 2 : 1;

    c.isolate(f, true);
    c.advance(200);
    c.isolate(f, false);
    c.advance(100);
    REQUIRE(!c.failed());
    REQUIRE(c.leader() != 0);
    return c.node(c.leader())->term() != before;
}

// Whether a leader cut off from every follower still believes it leads three election timeouts later.
bool isolated_leader_stays(uint32_t faults)
{
    cluster c(three(faults), quiet());
    c.advance(100);
    const raft::node_id l = c.leader();
    REQUIRE(l != 0);
    c.isolate(l, true);
    c.advance(30);
    REQUIRE(!c.failed());
    return c.node(l)->current_role() == raft::role::leader;
}

}   // namespace

TEST_CASE("pre-vote keeps a rejoining node from deposing a healthy leader")
{
    CHECK_FALSE(rejoin_moves_term(0));
    // The same check with pre-vote planted out, to show it can tell.
    CHECK(rejoin_moves_term(raft::fault_skip_pre_vote));
}

TEST_CASE("check-quorum makes a leader cut off from its quorum step down")
{
    CHECK_FALSE(isolated_leader_stays(0));
    CHECK(isolated_leader_stays(raft::fault_no_check_quorum));
}

TEST_CASE("a proposal commits and applies on every node of a quiet cluster")
{
    cluster c(three(0), quiet());
    c.advance(50);
    const raft::node_id l = c.leader();
    REQUIRE(l != 0);
    REQUIRE(c.propose(l, "x"));
    c.advance(10);
    REQUIRE(!c.failed());
    const raft::index_t target = c.node(l)->last_index();
    for (raft::node_id id = 1; id <= 3; ++id)
        CHECK(c.applied(id) == target);
}

// ─── learners and leadership transfer, directed ───

namespace {

sim_options with_spare(uint32_t faults)
{
    sim_options o = three(faults);
    o.spares = 1;
    return o;
}

// Whether the leader, asked to hand over, has a new leader in its place within a few round trips.
bool transfer_lands(uint32_t faults)
{
    cluster c(three(faults), quiet());
    c.advance(50);
    const raft::node_id l = c.leader();
    REQUIRE(l != 0);
    const raft::term_t before = c.node(l)->term();
    const raft::node_id t = l == 1 ? 2 : 1;

    bool started = false;
    raft::propose_status during = raft::propose_status::ok;
    c.act(l, [&](raft::node& n)
    {
        started = n.transfer_leadership(t);
        during  = n.propose("during").status;
    });
    REQUIRE(started);
    // A leader handing over takes nothing new, or the target could never catch up.
    CHECK(during == raft::propose_status::transferring);
    // The old leader cannot hear the target, so only the third node's vote, given inside its lease, can elect it.
    c.block(t, l, true);

    c.advance(8);
    REQUIRE(!c.failed());
    return c.leader() == t && c.node(t)->term() == before + 1;
}

// Whether a leader that can reach only a learner still commits a new entry.
bool learner_commits_alone(uint32_t faults)
{
    cluster c(with_spare(faults), quiet());
    c.advance(50);
    const raft::node_id l = c.leader();
    REQUIRE(l != 0);
    c.act(l, [](raft::node& n) { REQUIRE(n.propose_add_learner(4).status == raft::propose_status::ok); });
    c.advance(20);
    REQUIRE(!c.failed());
    REQUIRE(c.node(l)->is_learner(4));
    REQUIRE(!c.node(l)->is_voter(4));
    // The learner holds and applies everything the leader has.
    REQUIRE(c.applied(4) == c.node(l)->last_index());

    for (raft::node_id v = 1; v <= 3; ++v)
        if (v != l)
        {
            c.block(l, v, true);
            c.block(v, l, true);
        }
    REQUIRE(c.propose(l, "cut off"));
    const raft::index_t target = c.node(l)->last_index();
    c.advance(5);
    REQUIRE(!c.failed());
    return c.node(l)->commit_index() >= target;
}

}   // namespace

TEST_CASE("a leader hands over to an up-to-date voter within a few round trips")
{
    CHECK(transfer_lands(0));
    // The same handover with the lease still refusing the target's votes, to show the check can tell.
    CHECK_FALSE(transfer_lands(raft::fault_transfer_in_lease));
}

TEST_CASE("a learner receives the log but never makes a quorum")
{
    CHECK_FALSE(learner_commits_alone(0));
    CHECK(learner_commits_alone(raft::fault_learner_in_quorum));
}

TEST_CASE("a learner promoted by a single-server change votes and counts")
{
    cluster c(with_spare(0), quiet());
    c.advance(50);
    const raft::node_id l = c.leader();
    REQUIRE(l != 0);
    c.act(l, [](raft::node& n) { REQUIRE(n.propose_add_learner(4).status == raft::propose_status::ok); });
    c.advance(10);
    raft::propose_status promoted = raft::propose_status::not_leader;
    c.act(l, [&](raft::node& n) { promoted = n.propose_add(4).status; });
    REQUIRE(promoted == raft::propose_status::ok);
    c.advance(10);
    REQUIRE(!c.failed());
    for (raft::node_id id = 1; id <= 4; ++id)
    {
        CHECK(c.node(id)->is_voter(4));
        CHECK_FALSE(c.node(id)->is_learner(4));
        CHECK(c.node(id)->voters().size() == 4);
    }
}

TEST_CASE("membership encoding keeps voters and learners apart")
{
    const std::string both = raft::encode_config({3, 1, 2}, {9, 7});
    const raft::membership m = raft::decode_config(both);
    CHECK(m.voters == std::vector<raft::node_id>{1, 2, 3});
    CHECK(m.learners == std::vector<raft::node_id>{7, 9});
    // Voters alone encode as they did before learners existed.
    CHECK(raft::encode_config({1, 2}).size() == 16);
    CHECK(raft::decode_config(raft::encode_config({1, 2})).learners.empty());
    // A node named on both sides is a voter.
    CHECK(raft::decode_config(raft::encode_config({1, 2}, {2, 5})).learners == std::vector<raft::node_id>{5});
}
