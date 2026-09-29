#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/cluster_brain.h"
#include "../../socketley/shared/raft.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

// Whole clusters of the real Raft core and the real brain in virtual time, where a node dies, a link is cut in one
// direction, a message arrives late, and no runtime may ever run on more nodes than it has replicas.

namespace raft = socketley::raft;
namespace cl   = socketley::cluster;

namespace {

constexpr uint64_t tick_ms = 100;

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
};

struct envelope
{
    size_t from = 0, to = 0;
    bool   is_raft = true;
    raft::message msg;
    cl::frame::kind kind = cl::frame::kind::lease_req;
    uint64_t nonce = 0;
    raft::index_t index = 0;
    std::vector<cl::replica_report> reports;
};

// A cache replica's worker as the daemon leaves it: the real role state machine, and a link to a primary that copies at a rate.
struct sim_cache
{
    explicit sim_cache(uint64_t inc) : role(inc) {}

    cl::replica_role role;
    // The primary this copy is attached to and the epoch it asked for, and when its dump has landed.
    long     attached       = -1;
    uint64_t attached_epoch = 0;
    uint64_t synced_at      = 0;
    bool     synced         = false;
};

struct sim_node
{
    size_t        idx = 0;
    raft::node_id id  = 0;
    std::unique_ptr<raft::node>  rn;
    std::unique_ptr<cl::brain>   br;
    raft::index_t applied = 0, snap_index = 0, last_proposed = 0;
    // What the WAL holds, which is all a rebooted node has of its Raft state.
    raft::persisted disk;
    bool alive = true;
    // What this node's runtimes are doing, as the daemon's reconciliation leaves them.
    std::set<std::string> running;
    std::map<std::string, uint64_t> stopping;
    uint64_t moves = 0;
    // The cache replicas this node's workers hold; a hung daemon leaves them running and stops ordering them.
    std::map<std::string, sim_cache> caches;
    bool frozen = false;
    // How many records a follower here copies each tick.
    uint64_t copy_rate = 1000000;
};

// A replica that became the primary, and what the others held at that instant.
struct promotion
{
    uint64_t now = 0;
    size_t   node = 0;
    uint64_t epoch = 0;
    uint64_t offset = 0;
    // The highest offset any other live replica held of the epoch the promoted one came from.
    uint64_t best_other = 0;
    // Writes the old primary acknowledged in that epoch and the promoted replica did not have.
    uint64_t lost = 0;
};

class world
{
public:
    world(uint64_t seed, size_t n, cl::timing t = {}, uint64_t compact_every = 0)
        : m_rng{seed}, m_timing(t), m_compact(compact_every)
    {
        std::vector<raft::node_id> ids;
        for (size_t i = 0; i < n; ++i)
            ids.push_back(100 + i);
        for (size_t i = 0; i < n; ++i)
        {
            auto sn = std::make_unique<sim_node>();
            sn->idx = i;
            sn->id  = ids[i];
            raft::options o;
            o.id             = sn->id;
            o.election_ticks = static_cast<uint32_t>(t.election_ms / tick_ms);
            o.seed           = m_rng.next();
            sn->disk.snap.voters = ids;
            sn->disk.snap.data   = cl::encode(cl::state{});
            sn->rn = std::make_unique<raft::node>(o, sn->disk);
            sn->br = std::make_unique<cl::brain>(sn->id, "n" + std::to_string(i), t);
            m_nodes.push_back(std::move(sn));
        }
        m_up.assign(n, std::vector<bool>(n, true));
    }

    // ─── the environment ───

    void cut(size_t from, size_t to) { m_up[from][to] = false; }
    void heal_all() { for (auto& row : m_up) std::fill(row.begin(), row.end(), true); }
    void isolate(size_t i)
    {
        for (size_t j = 0; j < m_nodes.size(); ++j)
            if (j != i)
            {
                cut(i, j);
                cut(j, i);
            }
    }
    // Cuts every link between the nodes in `side` and the rest, both ways.
    void split(const std::set<size_t>& side)
    {
        for (size_t a = 0; a < m_nodes.size(); ++a)
            for (size_t b = 0; b < m_nodes.size(); ++b)
                if (side.count(a) != side.count(b))
                    cut(a, b);
    }
    // Everything `from` sends to `to` takes this many ticks longer.
    void slow(size_t from, size_t to, uint32_t ticks) { m_extra[{from, to}] = ticks; }
    void kill(size_t i)
    {
        sim_node& n = *m_nodes[i];
        n.alive = false;
        n.frozen = false;
        n.running.clear();
        n.stopping.clear();
        // The workers die with their daemon, and what they held goes with them.
        n.caches.clear();
    }
    // The daemon hangs: it neither ticks nor hears anyone, and its workers run on with whatever order they last had.
    void freeze(size_t i) { m_nodes[i]->frozen = true; }
    // The daemon wakes, and its first act is to stop what it no longer holds a lease for, at once: that is the whole of the hung daemon's gap for a server.
    void thaw(size_t i)
    {
        sim_node& n = *m_nodes[i];
        if (!n.frozen)
            return;
        n.frozen = false;
        if (!n.alive)
            return;
        // The host counts ticks from the elapsed clock, capped at four election timeouts, so a node that hung comes back having missed them.
        for (uint32_t k = 0; k < 4 * static_cast<uint32_t>(m_timing.election_ms / tick_ms); ++k)
            n.rn->tick();
        const cl::want w = n.br->desired(m_now);
        std::set<std::string> wanted;
        if (w.serving)
            for (const auto& item : w.owned)
                if (!item.cache)
                    wanted.insert(item.name);
        std::erase_if(n.running, [&](const std::string& name) { return !wanted.count(name); });
        n.stopping.clear();
    }
    // The caches whose primaries the invariant counts, and how many writes each primary takes a tick.
    void expect_cache(const std::string& name, uint64_t writes_per_tick = 0)
    {
        m_caches[name] = writes_per_tick;
    }
    void copy_rate(size_t i, uint64_t per_tick) { m_nodes[i]->copy_rate = per_tick; }
    // A rebooted daemon has lost its role, its lease and its runtimes, and kept what its WAL holds.
    void revive(size_t i)
    {
        sim_node& n = *m_nodes[i];
        raft::options o;
        o.id             = n.id;
        o.election_ticks = static_cast<uint32_t>(m_timing.election_ms / tick_ms);
        o.seed           = m_rng.next();
        n.rn = std::make_unique<raft::node>(o, n.disk);
        n.br = std::make_unique<cl::brain>(n.id, "n" + std::to_string(i), m_timing);
        n.caches.clear();
        n.frozen = false;
        cl::state s;
        if (!cl::decode(n.disk.snap.data, s))
            m_violation = "node " + std::to_string(i) + " rebooted from a snapshot it cannot read";
        n.br->restore(std::move(s));
        n.applied       = n.disk.snap.index;
        n.snap_index    = n.disk.snap.index;
        n.last_proposed = 0;
        n.br->note_applied(n.applied);
        n.alive = true;
    }
    void weather(uint32_t loss_permille, uint32_t max_delay_ticks)
    {
        m_loss  = loss_permille;
        m_delay = max_delay_ticks;
    }

    // ─── running ───

    void run(uint64_t ms)
    {
        for (uint64_t end = m_now + ms; m_now < end && m_violation.empty();)
            step();
    }

    template <class Pred>
    bool run_until(uint64_t ms, Pred pred)
    {
        for (uint64_t end = m_now + ms; m_now < end && m_violation.empty();)
        {
            if (pred())
                return true;
            step();
        }
        return pred() && m_violation.empty();
    }

    // The runtimes whose replica counts the invariant holds the world to.
    void expect(const std::string& name, uint32_t replicas) { m_replicas[name] = replicas; }

    // Proposes until some live node has applied the runtime, since a proposal accepted by a leader can still be lost with it.
    bool declare_visible(const cl::command& c)
    {
        for (int attempt = 0; attempt < 30; ++attempt)
        {
            for (auto& sn : m_nodes)
                if (sn->alive && sn->br->current().specs.count(c.name))
                    return true;
            propose(c);
            run(1000);
        }
        return false;
    }

    bool propose(const cl::command& c)
    {
        for (auto& sn : m_nodes)
            if (sn->alive && sn->rn->current_role() == raft::role::leader)
                return sn->rn->propose(cl::encode(c)).status == raft::propose_status::ok;
        return false;
    }

    // ─── observations ───

    uint64_t now() const { return m_now; }
    const std::string& violation() const { return m_violation; }
    sim_node& node(size_t i) { return *m_nodes[i]; }
    size_t size() const { return m_nodes.size(); }

    long leader() const
    {
        long best = -1;
        raft::term_t term = 0;
        for (auto& sn : m_nodes)
            if (sn->alive && sn->rn->current_role() == raft::role::leader && sn->rn->term() >= term)
            {
                best = static_cast<long>(sn->idx);
                term = sn->rn->term();
            }
        return best;
    }

    // A hung daemon cannot stop the servers it started, which the manual says, so what it holds is not counted against the placement.
    size_t running_count(const std::string& name) const
    {
        size_t k = 0;
        for (auto& sn : m_nodes)
            k += sn->frozen ? 0 : sn->running.count(name);
        return k;
    }

    size_t alive_count() const
    {
        size_t k = 0;
        for (auto& sn : m_nodes)
            k += sn->alive;
        return k;
    }

    // Every live node runs exactly what its own state says it holds, and every runtime has as many replicas as the live nodes allow.
    bool converged() const
    {
        const cl::state* ref = nullptr;
        for (auto& sn : m_nodes)
        {
            if (!sn->alive || sn->frozen)
                continue;
            if (ref && !(sn->br->current() == *ref))
                return false;
            ref = &sn->br->current();
            // A cache is judged by cache_settled(), since its replica is a worker that outlives a lease.
            std::set<std::string> holds;
            for (const auto& [name, held] : sn->br->current().owners)
                if (held.count(sn->id) && sn->br->current().specs.at(name).type != "cache")
                    holds.insert(name);
            if (holds != sn->running)
                return false;
            // No owner is a node that is gone, and every runtime holds as many replicas as the live nodes allow.
            for (const auto& [name, held] : sn->br->current().owners)
            {
                for (raft::node_id o : held)
                    if (!m_nodes[o - 100]->alive)
                        return false;
                if (held.size() != std::min<size_t>(sn->br->current().specs.at(name).replicas, alive_count()))
                    return false;
            }
        }
        for (const auto& [name, want] : m_replicas)
            if (running_count(name) != std::min<size_t>(want, alive_count()))
                return false;
        return ref != nullptr;
    }

    // The live nodes whose worker of cache `name` takes writes right now.
    std::vector<size_t> primaries_of(const std::string& name) const
    {
        std::vector<size_t> out;
        for (auto& sn : m_nodes)
        {
            auto c = sn->caches.find(name);
            if (sn->alive && c != sn->caches.end() && c->second.role.mode(m_now) == cl::replica_mode::primary)
                out.push_back(sn->idx);
        }
        return out;
    }

    // The primary is unique, every other replica of it follows it and holds its epoch, and the leader's log names that one.
    bool cache_settled(const std::string& name, uint32_t replicas) const
    {
        const auto lead = primaries_of(name);
        if (lead.size() != 1)
            return false;
        const sim_cache& p = m_nodes[lead[0]]->caches.at(name);
        size_t copies = 0;
        for (auto& sn : m_nodes)
        {
            auto c = sn->caches.find(name);
            if (!sn->alive || c == sn->caches.end())
                continue;
            ++copies;
            if (sn->idx == lead[0])
                continue;
            if (!c->second.role.following() || !c->second.synced || c->second.role.epoch() != p.role.epoch()
                || c->second.role.mode(m_now) != cl::replica_mode::follower)
                return false;
        }
        for (auto& sn : m_nodes)
            if (sn->alive && !sn->frozen)
            {
                const auto& lead_rec = sn->br->current().primaries.find(name);
                if (lead_rec == sn->br->current().primaries.end() || lead_rec->second.node != m_nodes[lead[0]]->id)
                    return false;
            }
        return copies == std::min<size_t>(replicas, alive_count());
    }

    const std::vector<promotion>& promotions() const { return m_promotions; }
    // Acknowledged writes of a cache in an epoch: the highest offset its primary reached.
    uint64_t acked(const std::string& name, uint64_t epoch) const
    {
        auto c = m_acked.find({name, epoch});
        return c == m_acked.end() ? 0 : c->second;
    }
    sim_cache* cache_at(size_t i, const std::string& name)
    {
        auto c = m_nodes[i]->caches.find(name);
        return c == m_nodes[i]->caches.end() ? nullptr : &c->second;
    }

    std::vector<std::string> owners_of(const std::string& name) const
    {
        std::vector<std::string> out;
        for (auto& sn : m_nodes)
            if (sn->alive && sn->running.count(name))
                out.push_back("n" + std::to_string(sn->idx));
        return out;
    }

    // Where every node stands, for the message of a check that failed.
    std::string describe(bool leases = false) const
    {
        std::string out;
        for (auto& sn : m_nodes)
        {
            if (leases)
                out += "  lease " + std::to_string(sn->br->lease_left_ms(m_now)) + " ";
            out += "n" + std::to_string(sn->idx) + (sn->alive ? "" : " DEAD") + " " + (sn->rn->current_role() == raft::role::leader ? "leader" : "follower")
                 + " term " + std::to_string(sn->rn->term()) + " applied " + std::to_string(sn->applied) + " commit "
                 + std::to_string(sn->rn->commit_index()) + " runs [";
            for (const std::string& r : sn->running)
                out += r + " ";
            out += "] ";
            // A cache replica: the mode it acts in, the epoch and offset of its copy, its incarnation, and what the log says leads it.
            for (const auto& [name, c] : sn->caches)
            {
                out += name + "(" + cl::mode_name(c.role.mode(m_now)) + " e" + std::to_string(c.role.epoch()) + " @" + std::to_string(c.role.offset())
                     + " #" + std::to_string(c.role.incarnation()) + ") ";
                auto p = sn->br->current().primaries.find(name);
                if (p != sn->br->current().primaries.end())
                    out += "log:n" + std::to_string(p->second.node ? p->second.node - 100 : 0) + "/e" + std::to_string(p->second.epoch) + "/#"
                         + std::to_string(p->second.incarnation) + " ";
            }
            out += "owners {";
            for (const auto& [name, held] : sn->br->current().owners)
            {
                out += name + ":";
                for (raft::node_id o : held)
                    out += "n" + std::to_string(o - 100) + ",";
                out += " ";
            }
            out += "}\n";
        }
        return out;
    }

    uint64_t stop_latency = 300;

private:
    void step()
    {
        m_now += tick_ms;
        deliver();
        for (auto& sn : m_nodes)
        {
            if (!sn->alive || sn->frozen)
                continue;
            sn->rn->tick();
            sn->br->set_reports(reports_of(*sn));
            cl::output out;
            sn->br->tick(m_now, view_of(*sn), out);
            flush(*sn, out);
        }
        drain();
        for (auto& sn : m_nodes)
            if (sn->alive && !sn->frozen)
                reconcile(*sn);
        run_workers();
        check();
        if (m_trace && m_now % m_trace_every == 0)
            std::printf("t=%llu\n%s", static_cast<unsigned long long>(m_now), describe(true).c_str());
    }

    cl::view view_of(sim_node& sn)
    {
        if (sn.rn->current_role() != raft::role::leader)
            sn.last_proposed = 0;
        return cl::view_of(*sn.rn, sn.applied, sn.last_proposed);
    }

    void send(envelope e)
    {
        if (!m_up[e.from][e.to] || m_rng.permille(m_loss))
            return;
        uint64_t delay = tick_ms * (1 + m_rng.below(m_delay + 1));
        if (auto x = m_extra.find({e.from, e.to}); x != m_extra.end())
            delay += tick_ms * x->second;
        m_mail.emplace(m_now + delay, std::move(e));
    }

    void flush(sim_node& sn, cl::output& out)
    {
        for (const std::string& data : out.proposals)
        {
            const raft::proposal p = sn.rn->propose(data);
            if (p.status != raft::propose_status::ok)
                break;
            sn.last_proposed = p.index;
        }
        for (const cl::frame& f : out.frames)
        {
            envelope e;
            e.from    = sn.idx;
            e.to      = f.to - 100;
            e.is_raft = false;
            e.kind    = f.type;
            e.nonce   = f.nonce;
            e.index   = f.index;
            e.reports = f.reports;
            send(std::move(e));
        }
    }

    void deliver()
    {
        while (!m_mail.empty() && m_mail.begin()->first <= m_now)
        {
            envelope e = std::move(m_mail.begin()->second);
            m_mail.erase(m_mail.begin());
            sim_node& to = *m_nodes[e.to];
            if (!to.alive || to.frozen)
                continue;
            if (e.is_raft)
            {
                to.rn->step(e.msg);
                continue;
            }
            cl::output out;
            if (e.kind == cl::frame::kind::lease_req)
                to.br->on_lease_req(m_nodes[e.from]->id, e.nonce, m_now, view_of(to), out, e.reports);
            else
                to.br->on_lease_grant(m_nodes[e.from]->id, e.nonce, e.index, m_now, view_of(to));
            flush(to, out);
        }
    }

    void drain()
    {
        for (int round = 0; round < 64; ++round)
        {
            bool any = false;
            for (auto& sn : m_nodes)
            {
                if (!sn->alive || sn->frozen || !sn->rn->has_ready())
                    continue;
                any = true;
                process(*sn);
            }
            if (!any)
                return;
        }
    }

    void process(sim_node& sn)
    {
        raft::ready r = sn.rn->take_ready();
        if (r.hard)
            sn.disk.hard = *r.hard;
        if (r.snap)
        {
            sn.disk.snap = *r.snap;
            std::erase_if(sn.disk.log, [&](const raft::entry& e) { return e.index <= sn.disk.snap.index; });
        }
        if (r.truncate_from)
            std::erase_if(sn.disk.log, [&](const raft::entry& e) { return e.index >= r.truncate_from; });
        for (const raft::entry& e : r.append)
            sn.disk.log.push_back(e);
        for (raft::message& m : r.messages)
        {
            envelope e;
            e.from = sn.idx;
            e.to   = m.to - 100;
            e.msg  = std::move(m);
            send(std::move(e));
        }
        if (r.restore)
        {
            cl::state s;
            if (!cl::decode(r.restore->data, s))
            {
                m_violation = "node " + std::to_string(sn.idx) + " was sent a snapshot it cannot read";
                return;
            }
            sn.br->restore(std::move(s));
            sn.applied = r.restore->index;
            sn.br->note_applied(sn.applied);
            ++m_restores;
        }
        for (const raft::entry& e : r.committed)
        {
            sn.applied = e.index;
            sn.br->note_applied(e.index);
            cl::command c;
            if (e.type == raft::entry_type::normal && cl::is_command(e.data) && cl::decode(e.data, c) && sn.br->apply(c)
                && (c.op == cl::op::assign || c.op == cl::op::unassign))
                ++sn.moves;
        }
        if (m_compact && sn.applied >= sn.snap_index + m_compact && sn.rn->compact(sn.applied, cl::encode(sn.br->current())))
            sn.snap_index = sn.applied;
    }

    std::vector<cl::replica_report> reports_of(const sim_node& sn) const
    {
        std::vector<cl::replica_report> out;
        for (const auto& [name, c] : sn.caches)
            out.push_back(cl::replica_report{name, c.role.incarnation(), c.role.epoch(), c.role.offset(),
                                             c.role.mode(m_now) == cl::replica_mode::primary});
        return out;
    }

    // The daemon's word to each cache replica it holds, every tick; a replica is made when the node may serve and none exists.
    void order_caches(sim_node& sn, const cl::want& w)
    {
        std::set<std::string> held;
        for (const auto& item : w.owned)
        {
            if (!item.cache)
                continue;
            held.insert(item.name);
            auto c = sn.caches.find(item.name);
            if (c == sn.caches.end())
            {
                if (!w.serving)
                    continue;
                c = sn.caches.emplace(item.name, sim_cache(m_next_incarnation++)).first;
            }
            cl::replica_order o;
            o.incarnation = c->second.role.incarnation();
            o.epoch       = item.epoch;
            o.valid_ms    = static_cast<uint32_t>(item.valid_ms);
            if (item.valid_ms != 0 && item.role == cl::replica_mode::primary)
            {
                o.mode = cl::replica_mode::primary;
            }
            else if (item.valid_ms != 0 && item.role == cl::replica_mode::follower && item.primary != 0)
            {
                o.mode   = cl::replica_mode::follower;
                o.target = "n" + std::to_string(item.primary - 100);
            }
            c->second.role.order(o, m_now);
        }
        // A replica the node no longer owns is removed and its data with it.
        for (auto it = sn.caches.begin(); it != sn.caches.end();)
            it = held.count(it->first) ? std::next(it) : sn.caches.erase(it);
    }

    // What the workers do on their own between the daemon's orders: the primary takes its writes, and a follower dials, syncs and copies.
    void run_workers()
    {
        for (const auto& [name, rate] : m_caches)
        {
            for (auto& sn : m_nodes)
            {
                auto c = sn->caches.find(name);
                if (!sn->alive || c == sn->caches.end() || c->second.role.mode(m_now) != cl::replica_mode::primary)
                    continue;
                for (uint64_t k = 0; k < rate; ++k)
                    c->second.role.record();
                if (rate != 0)
                {
                    uint64_t& a = m_acked[{name, c->second.role.epoch()}];
                    a = std::max(a, c->second.role.offset());
                }
            }
            for (auto& sn : m_nodes)
            {
                auto c = sn->caches.find(name);
                if (!sn->alive || c == sn->caches.end())
                    continue;
                sim_cache& f = c->second;
                if (!f.role.following())
                {
                    f.attached = -1;
                    f.synced   = false;
                    continue;
                }
                const size_t t = static_cast<size_t>(std::strtoull(f.role.target().c_str() + 1, nullptr, 10));
                const uint64_t epoch = f.role.follow_epoch();
                sim_cache* p = t < m_nodes.size() && t != sn->idx && m_nodes[t]->alive ? cache_at(t, name) : nullptr;
                const bool link = p && m_up[t][sn->idx] && m_up[sn->idx][t];
                // A link that stands stays while the other end is still the primary of that epoch, lease or not; a new one needs a primary that answers.
                const bool stands = link && f.attached == static_cast<long>(t) && f.attached_epoch == epoch
                                 && p->role.epoch() == epoch && !p->role.following();
                if (!stands)
                {
                    f.attached = -1;
                    f.synced   = false;
                    if (!link || p->role.mode(m_now) != cl::replica_mode::primary || p->role.epoch() != epoch)
                        continue;
                    f.attached       = static_cast<long>(t);
                    f.attached_epoch = epoch;
                    f.synced_at      = m_now + dump_ms;
                    f.role.sync_started();
                    continue;
                }
                if (!f.synced)
                {
                    if (m_now >= f.synced_at)
                    {
                        f.role.sync_done(p->role.offset());
                        f.synced = true;
                    }
                    continue;
                }
                for (uint64_t k = 0; k < sn->copy_rate && f.role.offset() < p->role.offset(); ++k)
                    f.role.record();
            }
            note_promotions(name);
        }
    }

    // A replica that took a higher epoch than any before it has been promoted, and here is what it held against the rest.
    void note_promotions(const std::string& name)
    {
        for (auto& sn : m_nodes)
        {
            auto c = sn->caches.find(name);
            if (!sn->alive || c == sn->caches.end() || c->second.role.mode(m_now) != cl::replica_mode::primary)
                continue;
            const uint64_t epoch = c->second.role.epoch();
            uint64_t& seen = m_seen_epoch[name];
            if (epoch <= seen)
                continue;
            promotion p;
            p.now    = m_now;
            p.node   = sn->idx;
            p.epoch  = epoch;
            p.offset = c->second.role.offset();
            for (auto& other : m_nodes)
            {
                auto o = other->caches.find(name);
                if (other->idx != sn->idx && other->alive && o != other->caches.end() && o->second.role.epoch() == seen)
                    p.best_other = std::max(p.best_other, o->second.role.offset());
            }
            p.lost = acked(name, seen) > p.offset ? acked(name, seen) - p.offset : 0;
            m_promotions.push_back(p);
            seen = epoch;
        }
    }

    // The daemon's reconciliation: start what is owned and leased at once, stop what is not after the time a stop takes.
    void reconcile(sim_node& sn)
    {
        const cl::want w = sn.br->desired(m_now);
        order_caches(sn, w);
        std::set<std::string> wanted;
        if (w.serving)
            for (const auto& item : w.owned)
                if (!item.cache)
                    wanted.insert(item.name);
        for (const std::string& name : wanted)
        {
            sn.running.insert(name);
            sn.stopping.erase(name);
        }
        for (auto it = sn.running.begin(); it != sn.running.end();)
        {
            if (wanted.count(*it))
            {
                ++it;
                continue;
            }
            auto s = sn.stopping.emplace(*it, m_now).first;
            if (m_now - s->second >= stop_latency)
            {
                sn.stopping.erase(s);
                it = sn.running.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    void check()
    {
        // No cache is ever led by two replicas at one instant, whichever way its nodes are cut, frozen or killed.
        for (const auto& [name, rate] : m_caches)
        {
            const auto lead = primaries_of(name);
            if (lead.size() > 1 && m_violation.empty())
            {
                std::string who;
                for (size_t n : lead)
                    who += " n" + std::to_string(n);
                m_violation = "at " + std::to_string(m_now) + " ms cache " + name + " has " + std::to_string(lead.size())
                            + " primaries (" + who.substr(1) + ")";
            }
        }
        for (const auto& [name, want] : m_replicas)
        {
            const size_t k = running_count(name);
            if (k > want && m_violation.empty())
            {
                std::string who;
                for (const std::string& n : owners_of(name))
                    who += " " + n;
                m_violation = "at " + std::to_string(m_now) + " ms " + name + " runs on " + std::to_string(k)
                            + " nodes (" + who.substr(1) + ") though it has " + std::to_string(want) + " replicas";
            }
        }
    }

    prng       m_rng;
    cl::timing m_timing;
    uint64_t   m_compact;
    uint64_t   m_now = 1000;
    std::vector<std::unique_ptr<sim_node>> m_nodes;
    std::vector<std::vector<bool>> m_up;
    std::multimap<uint64_t, envelope> m_mail;
    std::map<std::string, uint32_t> m_replicas;
    uint32_t m_loss = 0, m_delay = 0;
    std::map<std::pair<size_t, size_t>, uint32_t> m_extra;
    std::string m_violation;
    // The caches under watch and the writes a tick their primary takes, what each primary acknowledged, and who was promoted.
    std::map<std::string, uint64_t> m_caches;
    std::map<std::pair<std::string, uint64_t>, uint64_t> m_acked;
    std::map<std::string, uint64_t> m_seen_epoch;
    std::vector<promotion> m_promotions;
    uint64_t m_next_incarnation = 1000;
    // How long a follower's dump takes to land.
    static constexpr uint64_t dump_ms = 300;

public:
    uint64_t m_restores = 0;
    bool m_trace = false;
    uint64_t m_trace_every = 500;
};

cl::command declare(const std::string& name, uint32_t replicas)
{
    cl::command c;
    c.op   = cl::op::create;
    c.name = name;
    c.sp   = cl::spec{"server", {"-p", "8080"}, replicas};
    return c;
}

cl::command declare_cache(const std::string& name, uint32_t replicas)
{
    cl::command c;
    c.op   = cl::op::create;
    c.name = name;
    c.sp   = cl::spec{"cache", {"-p", "6300"}, replicas};
    return c;
}

// The seeds each scenario is run under, each one a different election order and message schedule.
constexpr uint64_t seeds = 60;

}   // namespace

TEST_CASE("a declared runtime is placed on distinct nodes and runs there")
{
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect("api", 2);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare("api", 2)));
        INFO("seed " << seed);
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));
        CHECK(w.running_count("api") == 2);
        // Nothing moves in a healthy cluster: a plan on a converged state proposes nothing, for a minute.
        const uint64_t moves = w.node(0).moves;
        w.run(60000);
        CHECK(w.violation().empty());
        CHECK(w.node(0).moves == moves);
        CHECK(w.running_count("api") == 2);
    }
}

TEST_CASE("a node killed while it holds a replica loses it to a survivor within the failure timeout, and never runs it twice")
{
    uint64_t worst = 0, best = ~uint64_t{0};
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect("api", 2);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare("api", 2)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));

        // A node that holds a replica, the leader when it does, so both the election and the failure timeout are in the bill.
        size_t victim = 3;
        for (size_t i = 0; i < 3; ++i)
            if (w.node(i).running.count("api") && (victim == 3 || static_cast<long>(i) == w.leader()))
                victim = i;
        REQUIRE(victim < 3);
        INFO("seed " << seed << ", victim n" << victim);
        const uint64_t t0 = w.now();
        const bool was_leader = static_cast<long>(victim) == w.leader();
        w.kill(victim);
        REQUIRE(w.run_until(30000, [&] { return w.running_count("api") == 2; }));
        const uint64_t took = w.now() - t0;
        worst = std::max(worst, took);
        best  = std::min(best, took);
        // A follower's death costs the failure timeout and a commit; a leader's costs an election first, which a split vote can stretch.
        CHECK(took <= cl::timing{}.down_after_ms + (was_leader ? 5 : 1) * cl::timing{}.election_ms);
        CHECK(w.violation().empty());

        // The dead node is back: it holds nothing it no longer owns, and the runtime still has its two replicas.
        w.revive(victim);
        w.run(20000);
        CHECK(w.violation().empty());
        CHECK(w.running_count("api") == 2);
        CHECK(w.node(victim).running.count("api") == 0);
        CHECK(w.converged());
    }
    std::printf("  failover in virtual time: %llu..%llu ms over %llu seeds\n", static_cast<unsigned long long>(best),
                static_cast<unsigned long long>(worst), static_cast<unsigned long long>(seeds));
}

TEST_CASE("a leader change alone moves nothing, and stops what the survivors hold only when the election outlasts the lease")
{
    uint64_t bounced = 0, runs = 0;
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect("a", 1);
        w.expect("b", 1);
        w.expect("c", 1);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare("a", 1)));
        REQUIRE(w.propose(declare("b", 1)));
        REQUIRE(w.propose(declare("c", 1)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));

        const size_t old = static_cast<size_t>(w.leader());
        std::map<size_t, std::set<std::string>> before;
        for (size_t i = 0; i < 3; ++i)
            if (i != old)
                before[i] = w.node(i).running;
        w.kill(old);
        ++runs;
        // Only what the dead leader held may move, and only after the failure timeout; a survivor never stops what it keeps.
        bool bounce = false;
        for (uint64_t t = 0; t < 30000 && w.violation().empty(); t += tick_ms)
        {
            w.run(tick_ms);
            for (const auto& [i, held] : before)
                for (const std::string& name : held)
                    if (!w.node(i).running.count(name))
                        bounce = true;
        }
        bounced += bounce;
        CHECK(w.violation().empty());
    }
    // A leader change takes one to two election timeouts, more after a split vote, and the lease covers three; a
    // lease shorter than an election bounces every kill.
    CHECK(bounced * 5 < runs);
    std::printf("  %llu of %llu leader kills bounced a survivor's replica\n", static_cast<unsigned long long>(bounced),
                static_cast<unsigned long long>(runs));
}

TEST_CASE("a node cut off from the cluster stops serving within its lease, and a healed node runs only what it still owns")
{
    const cl::timing t;
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect("api", 2);
        w.expect("web", 1);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare("api", 2)));
        REQUIRE(w.propose(declare("web", 1)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));

        size_t victim = 0;
        for (size_t i = 0; i < 3; ++i)
            if (w.node(i).running.count("api"))
                victim = i;
        INFO("seed " << seed << ", isolated n" << victim);
        const uint64_t t0 = w.now();
        w.isolate(victim);
        // It cannot confirm it still owns anything, so it stops inside its lease and does not wait to be told.
        REQUIRE(w.run_until(t.lease_ms() + 2 * t.election_ms, [&] { return w.node(victim).running.empty(); }));
        CHECK(w.now() - t0 <= t.lease_ms() + t.election_ms);
        // The majority moves what it held after the failure timeout, with no second copy at any instant.
        REQUIRE(w.run_until(30000, [&] { return w.running_count("api") == 2 && w.running_count("web") == 1; }));
        CHECK(w.violation().empty());
        w.run(20000);
        CHECK(w.node(victim).running.empty());

        w.heal_all();
        INFO(w.describe());
        REQUIRE(w.run_until(30000, [&] { return w.converged(); }));
        CHECK(w.violation().empty());
        // What moved away stays away, and nothing runs twice.
        CHECK(w.running_count("api") == 2);
        CHECK(w.running_count("web") == 1);
    }
}

TEST_CASE("a node that hears the leader but is not heard by it stops serving, and one it hears but cannot answer is not duplicated")
{
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect("api", 2);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare("api", 2)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));
        const size_t leader = static_cast<size_t>(w.leader());
        size_t victim = 0;
        for (size_t i = 0; i < 3; ++i)
            if (i != leader && w.node(i).running.count("api"))
                victim = i;
        INFO("seed " << seed << ", leader n" << leader << ", victim n" << victim);

        // The victim's answers never reach the leader, though the leader's heartbeats still reach the victim.
        w.cut(victim, leader);
        w.run(40000);
        CHECK(w.violation().empty());
        w.heal_all();
        REQUIRE(w.run_until(30000, [&] { return w.converged(); }));
        CHECK(w.running_count("api") == 2);
    }
}

TEST_CASE("a leader stranded in a minority with a follower grants that follower nothing once it has lost its quorum")
{
    // The cut lands at every phase of the leader's election-timeout window, since the quorum it last saw goes stale at the window's end.
    for (uint64_t seed = 1; seed <= 10 * seeds; ++seed)
    {
        world w(seed, 5);
        w.expect("api", 2);
        w.expect("web", 2);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.declare_visible(declare("api", 2)));
        REQUIRE(w.declare_visible(declare("web", 2)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));
        w.run(100 * (seed % 10));
        INFO("seed " << seed);

        // The leader and one more node are cut off from the other three, which elect a leader of their own.
        const size_t old = static_cast<size_t>(w.leader());
        const size_t mate = (old + 1) % 5;
        w.split({old, mate});
        w.run(60000);
        CHECK(w.violation().empty());
        // The minority serves nothing, and the majority holds every replica.
        CHECK(w.node(old).running.empty());
        CHECK(w.node(mate).running.empty());
        CHECK(w.running_count("api") == 2);
        CHECK(w.running_count("web") == 2);

        w.heal_all();
        REQUIRE(w.run_until(30000, [&] { return w.converged(); }));
        CHECK(w.violation().empty());
    }
}

TEST_CASE("a grant that arrives late extends the lease from when the request was sent, not from when it came back")
{
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect("api", 2);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.declare_visible(declare("api", 2)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));
        const size_t leader = static_cast<size_t>(w.leader());
        size_t victim = 0;
        for (size_t i = 0; i < 3; ++i)
            if (i != leader && w.node(i).running.count("api"))
                victim = i;
        INFO("seed " << seed << ", leader n" << leader << ", victim n" << victim);

        // The leader's answers take two seconds to reach the victim, whose own requests arrive at once, and then the victim is cut off.
        w.slow(leader, victim, 20);
        w.run(10000);
        w.isolate(victim);
        w.run(30000);
        CHECK(w.violation().empty());
        CHECK(w.node(victim).running.empty());
        CHECK(w.running_count("api") == 2);
    }
}

TEST_CASE("without a quorum every node stops serving, and the cluster serves again once it has one")
{
    const cl::timing t;
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect("api", 2);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare("api", 2)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));
        INFO("seed " << seed);

        size_t a = 0, b = 1;
        w.kill(a);
        w.kill(b);
        // The survivor is alone, cannot reach a quorum, and stops what it holds.
        REQUIRE(w.run_until(t.lease_ms() + 3 * t.election_ms, [&] { return w.node(2).running.empty(); }));
        w.run(30000);
        CHECK(w.node(2).running.empty());
        CHECK(w.violation().empty());

        w.revive(a);
        w.revive(b);
        REQUIRE(w.run_until(40000, [&] { return w.converged(); }));
        CHECK(w.running_count("api") == 2);
    }
}

TEST_CASE("more replicas than nodes runs what fits, and the rest is placed when a node returns")
{
    for (uint64_t seed = 1; seed <= 20; ++seed)
    {
        world w(seed, 3);
        w.expect("api", 3);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare("api", 3)));
        REQUIRE(w.run_until(15000, [&] { return w.converged(); }));
        CHECK(w.running_count("api") == 3);
        w.kill(static_cast<size_t>((w.leader() + 1) % 3));
        REQUIRE(w.run_until(30000, [&] { return w.converged(); }));
        // Two nodes, three replicas: two run, and the shortfall is what the state says is missing.
        CHECK(w.running_count("api") == 2);
        size_t alive = 0;
        for (size_t i = 0; i < 3; ++i)
            if (w.node(i).alive)
            {
                ++alive;
                CHECK(w.node(i).br->current().missing("api") == 1);
            }
        CHECK(alive == 2);
    }
}

TEST_CASE("under loss, delay, asymmetric cuts, kills and reboots no runtime ever runs on more nodes than it has replicas")
{
    uint64_t moves = 0, kills = 0, cuts = 0, restores = 0;
    // CLUSTER_SEED=n runs that one seed, to look at a failure.
    const char* only = std::getenv("CLUSTER_SEED");
    const char* many = std::getenv("CLUSTER_SEEDS");
    const uint64_t total = many ? std::strtoull(many, nullptr, 10) : 300;
    for (uint64_t seed = 1; seed <= total; ++seed)
    {
        if (only && std::strtoull(only, nullptr, 10) != seed)
            continue;
        prng r{seed * 7919};
        const size_t n = 3 + r.below(3);
        cl::timing t;
        // Half the worlds run a short failure timeout, which is the harder one for the lease.
        if (r.below(2))
            t.down_after_ms = 3 * t.election_ms;
        world w(seed, n, t, r.below(2) ? 8 : 0);
        w.expect("api", 2);
        w.expect("web", 1);
        const uint32_t job_replicas = static_cast<uint32_t>(1 + r.below(3));
        w.expect("job", job_replicas);
        // A cache in the mix, taking writes, so that a fault meets a primary, its followers and the copying between them.
        const uint32_t db_replicas = static_cast<uint32_t>(1 + r.below(3));
        w.expect_cache("db", r.below(3) * 30);
        INFO("seed " << seed << ", " << n << " nodes, down after " << t.down_after_ms);
        w.m_trace = only != nullptr && std::getenv("CLUSTER_TRACE") != nullptr;
        if (const char* e = std::getenv("CLUSTER_TRACE_EVERY"))
            w.m_trace_every = std::strtoull(e, nullptr, 10);
        REQUIRE(w.run_until(15000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.declare_visible(declare("api", 2)));
        REQUIRE(w.declare_visible(declare("web", 1)));
        REQUIRE(w.declare_visible(declare("job", job_replicas)));
        REQUIRE(w.declare_visible(declare_cache("db", db_replicas)));

        for (int phase = 0; phase < 12 && w.violation().empty(); ++phase)
        {
            w.weather(static_cast<uint32_t>(r.below(3) * 60), static_cast<uint32_t>(r.below(6)));
            switch (r.below(7))
            {
            case 6:
            {
                // A hung daemon: its workers run on with the last order they were given.
                const size_t v = r.below(n);
                if (w.node(v).alive)
                    w.freeze(v);
                break;
            }
            case 5:
            {
                // A random side of the cluster is cut off from the rest, which is how a minority keeps a stale leader.
                std::set<size_t> side;
                for (size_t i = 0; i < n; ++i)
                    if (r.below(2))
                        side.insert(i);
                w.split(side);
                ++cuts;
                break;
            }
            case 0:
                w.isolate(r.below(n));
                ++cuts;
                break;
            case 1:
                w.cut(r.below(n), r.below(n));
                w.cut(r.below(n), r.below(n));
                ++cuts;
                break;
            case 2:
            {
                const size_t v = r.below(n);
                if (w.node(v).alive && w.alive_count() > 1)
                {
                    w.kill(v);
                    ++kills;
                }
                break;
            }
            case 3:
                for (size_t i = 0; i < n; ++i)
                    if (!w.node(i).alive && r.below(2))
                        w.revive(i);
                break;
            default:
                w.heal_all();
                for (size_t i = 0; i < n; ++i)
                    w.thaw(i);
                break;
            }
            w.run(2000 + r.below(9000));
        }
        CHECK(w.violation().empty());
        if (!w.violation().empty())
            std::printf("  seed %llu: %s\n%s", static_cast<unsigned long long>(seed), w.violation().c_str(), w.describe().c_str());

        // Everything mends: no faults, every node back, and the cluster converges on one placement.
        w.weather(0, 0);
        w.heal_all();
        for (size_t i = 0; i < n; ++i)
        {
            w.thaw(i);
            if (!w.node(i).alive)
                w.revive(i);
        }
        const bool mended = w.run_until(60000, [&] { return w.converged() && w.cache_settled("db", db_replicas); });
        CHECK(mended);
        if (!mended)
            std::printf("  seed %llu did not converge: %s\n%s", static_cast<unsigned long long>(seed), w.violation().c_str(), w.describe().c_str());
        CHECK(w.violation().empty());
        for (size_t i = 0; i < n; ++i)
            moves += w.node(i).moves;
        restores += w.m_restores;
    }
    std::printf("  %llu assignment changes, %llu kills, %llu cuts, %llu snapshot installs\n",
                static_cast<unsigned long long>(moves), static_cast<unsigned long long>(kills),
                static_cast<unsigned long long>(cuts), static_cast<unsigned long long>(restores));
    // A sweep that never cut, killed or installed a snapshot would be green about nothing.
    CHECK(kills > 100);
    CHECK(cuts > 100);
    CHECK(restores > 0);
}

// ─── a cache: one primary, followers that copy it, and a promotion when its node is lost ───

namespace {

// A world with a leader and a cache declared and settled: one primary, every other replica following it and holding its epoch.
bool settle_cache(world& w, const std::string& name, uint32_t replicas, uint64_t within_ms = 30000)
{
    return w.run_until(within_ms, [&] { return w.cache_settled(name, replicas); });
}

size_t the_primary(world& w, const std::string& name)
{
    const auto lead = w.primaries_of(name);
    return lead.size() == 1 ? lead[0] : 99;
}

}   // namespace

TEST_CASE("a declared cache gets one primary, the others copy it, and a healthy cluster promotes nobody again")
{
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 50);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        INFO("seed " << seed);
        REQUIRE(settle_cache(w, "db", 3));
        CHECK(w.promotions().size() == 1);
        CHECK(w.promotions()[0].epoch == 1);
        // A minute of writes and heartbeats moves nothing: the epoch is the first, and the followers stay attached.
        w.run(60000);
        CHECK(w.violation().empty());
        CHECK(w.promotions().size() == 1);
        CHECK(w.cache_settled("db", 3));
    }
}

TEST_CASE("when the primary's node dies the follower with the most records is promoted, within the failure timeout and an election")
{
    const cl::timing t;
    // Indexed by whether the dead node was the Raft leader too.
    uint64_t best[2] = {~uint64_t{0}, ~uint64_t{0}}, worst[2] = {0, 0}, kills[2] = {0, 0};
    uint64_t lost_most = 0, lost_least = ~uint64_t{0};
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 50);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        REQUIRE(settle_cache(w, "db", 3));
        const size_t lead = the_primary(w, "db");
        REQUIRE(lead < 3);
        // The two followers copy at different speeds, so one is behind by what the primary wrote and the other has not yet copied.
        const size_t fast = (lead + 1 + seed % 2) % 3, slow = 3 - lead - fast;
        w.copy_rate(fast, 45);
        w.copy_rate(slow, 20);
        w.run(10000);
        INFO("seed " << seed << ", primary n" << lead << ", fast n" << fast << ", slow n" << slow);
        const uint64_t before = w.promotions().size();
        const uint64_t t0 = w.now();
        const bool was_leader = static_cast<long>(lead) == w.leader();
        w.kill(lead);
        REQUIRE(w.run_until(30000, [&] { return w.promotions().size() == before + 1; }));
        const promotion& p = w.promotions().back();
        const uint64_t took = p.now - t0;
        best[was_leader]  = std::min(best[was_leader], took);
        worst[was_leader] = std::max(worst[was_leader], took);
        ++kills[was_leader];
        // The follower that had copied more of the stream, whichever node id it has.
        CHECK(p.node == fast);
        CHECK(p.offset >= p.best_other);
        CHECK(p.epoch == 2);
        CHECK(took <= t.down_after_ms + (was_leader ? 5 : 1) * t.election_ms);
        // What the old primary acknowledged and the promoted copy lacked: the writes of an asynchronous stream, and nothing else.
        CHECK(p.lost > 0);
        lost_most  = std::max(lost_most, p.lost);
        lost_least = std::min(lost_least, p.lost);
        CHECK(w.violation().empty());
        REQUIRE(settle_cache(w, "db", 3));
        CHECK(w.node(p.node).caches.at("db").role.epoch() == 2);
    }
    std::printf("  promoted %llu..%llu ms after the kill of a follower node (%llu kills), %llu..%llu after the kill of the leader's (%llu), "
                "%llu..%llu acknowledged writes missing from the copy\n",
                static_cast<unsigned long long>(best[0]), static_cast<unsigned long long>(worst[0]),
                static_cast<unsigned long long>(kills[0]), static_cast<unsigned long long>(best[1]),
                static_cast<unsigned long long>(worst[1]), static_cast<unsigned long long>(kills[1]),
                static_cast<unsigned long long>(lost_least), static_cast<unsigned long long>(lost_most));
    // A run that never killed a node that was not the leader, or never the leader, would say nothing about one of them.
    CHECK(kills[0] > 5);
    CHECK(kills[1] > 5);
}

TEST_CASE("with every follower keeping up, the promoted copy has every write the primary acknowledged")
{
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 50);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        REQUIRE(settle_cache(w, "db", 3));
        w.run(5000);
        const size_t lead = the_primary(w, "db");
        const uint64_t before = w.promotions().size();
        w.kill(lead);
        REQUIRE(w.run_until(30000, [&] { return w.promotions().size() == before + 1; }));
        INFO("seed " << seed);
        CHECK(w.promotions().back().lost == 0);
    }
}

TEST_CASE("the old primary comes back as a follower of the one that replaced it, and never leads again")
{
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 20);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        REQUIRE(settle_cache(w, "db", 3));
        w.run(3000);
        const size_t old = the_primary(w, "db");
        INFO("seed " << seed << ", old primary n" << old);
        w.kill(old);
        REQUIRE(w.run_until(30000, [&] { return w.primaries_of("db").size() == 1; }));
        const size_t now_leads = the_primary(w, "db");
        CHECK(now_leads != old);

        // A day later, as far as the cluster is concerned: the node is given its replica back and holds a copy of the new primary.
        w.run(10000);
        w.revive(old);
        bool led = false;
        REQUIRE(w.run_until(60000, [&] {
            led |= w.cache_at(old, "db") && w.cache_at(old, "db")->role.mode(w.now()) == cl::replica_mode::primary;
            return w.cache_settled("db", 3);
        }));
        CHECK_FALSE(led);
        CHECK(w.violation().empty());
        CHECK(the_primary(w, "db") == now_leads);
        REQUIRE(w.cache_at(old, "db") != nullptr);
        CHECK(w.cache_at(old, "db")->role.mode(w.now()) == cl::replica_mode::follower);
        CHECK(w.cache_at(old, "db")->role.epoch() == 2);
        CHECK(w.promotions().size() == 2);
    }
}

TEST_CASE("a primary restarted before it was declared down comes back empty, and does not lead: a follower with data is promoted")
{
    uint64_t restarts = 0;
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 20);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        REQUIRE(settle_cache(w, "db", 3));
        w.run(3000);
        const size_t old = the_primary(w, "db");
        const uint64_t old_incarnation = w.cache_at(old, "db")->role.incarnation();
        INFO("seed " << seed << ", primary n" << old);
        // The process dies and a new one starts under the same node in a second, well inside the failure timeout.
        w.kill(old);
        w.run(1000);
        w.revive(old);
        ++restarts;
        bool led = false;
        REQUIRE(w.run_until(60000, [&] {
            led |= w.cache_at(old, "db") && w.cache_at(old, "db")->role.mode(w.now()) == cl::replica_mode::primary;
            return w.promotions().size() == 2 && w.cache_settled("db", 3);
        }));
        // The new incarnation held nothing the old one did, so a replica that had the data leads, and the restarted one follows it.
        CHECK_FALSE(led);
        CHECK(the_primary(w, "db") != old);
        CHECK(w.cache_at(old, "db")->role.incarnation() != old_incarnation);
        CHECK(w.promotions().back().offset > 0);
        CHECK(w.violation().empty());
    }
    CHECK(restarts == seeds);
}

TEST_CASE("a primary whose daemon hangs fences itself within its lease, before any other replica may lead")
{
    const cl::timing t;
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 20);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        REQUIRE(settle_cache(w, "db", 3));
        w.run(3000);
        const size_t old = the_primary(w, "db");
        INFO("seed " << seed << ", primary n" << old);
        const uint64_t t0 = w.now();
        // The daemon stops ticking and hearing anyone; its worker is untouched, and holds the last order it was given.
        w.freeze(old);
        REQUIRE(w.run_until(t.lease_ms() + t.election_ms, [&] { return w.cache_at(old, "db")->role.mode(w.now()) == cl::replica_mode::fenced; }));
        CHECK(w.now() - t0 <= t.lease_ms());
        // The others declare it down and promote after the failure timeout, and at no tick are there two.
        REQUIRE(w.run_until(30000, [&] { return w.promotions().size() == 2; }));
        CHECK(w.violation().empty());
        CHECK(w.promotions().back().node != old);
        // The daemon wakes: what it holds is a copy of an epoch that is over, and it follows the primary of this one.
        w.thaw(old);
        REQUIRE(settle_cache(w, "db", 3, 60000));
        CHECK(w.violation().empty());
        CHECK(w.cache_at(old, "db")->role.mode(w.now()) == cl::replica_mode::follower);
    }
}

TEST_CASE("a primary cut off from the cluster stops within its lease, the majority promotes, and the healed node follows")
{
    const cl::timing t;
    for (uint64_t seed = 1; seed <= seeds; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 20);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        REQUIRE(settle_cache(w, "db", 3));
        w.run(3000);
        const size_t old = the_primary(w, "db");
        INFO("seed " << seed << ", primary n" << old);
        const uint64_t t0 = w.now();
        w.isolate(old);
        REQUIRE(w.run_until(t.lease_ms() + 2 * t.election_ms, [&] { return w.cache_at(old, "db")->role.mode(w.now()) == cl::replica_mode::fenced; }));
        CHECK(w.now() - t0 <= t.lease_ms() + t.election_ms);
        REQUIRE(w.run_until(30000, [&] { return w.promotions().size() == 2; }));
        CHECK(w.violation().empty());
        w.run(20000);
        CHECK(w.violation().empty());
        w.heal_all();
        REQUIRE(settle_cache(w, "db", 3, 60000));
        CHECK(w.violation().empty());
        CHECK(w.cache_at(old, "db")->role.mode(w.now()) == cl::replica_mode::follower);
    }
}

TEST_CASE("a cache with one replica has that replica as its primary, and a new one leads empty when its node is lost and another is found")
{
    for (uint64_t seed = 1; seed <= 20; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 10);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 1)));
        REQUIRE(settle_cache(w, "db", 1));
        w.run(3000);
        const size_t old = the_primary(w, "db");
        w.kill(old);
        REQUIRE(w.run_until(30000, [&] { return w.promotions().size() == 2 && w.cache_settled("db", 1); }));
        CHECK(the_primary(w, "db") != old);
        // Nothing else held the data, so the new primary starts from nothing in the next epoch.
        CHECK(w.promotions().back().epoch == 2);
        CHECK(w.violation().empty());
    }
}

TEST_CASE("scaling a cache down keeps its primary and drops a follower")
{
    for (uint64_t seed = 1; seed <= 20; ++seed)
    {
        world w(seed, 3);
        w.expect_cache("db", 10);
        REQUIRE(w.run_until(10000, [&] { return w.leader() >= 0; }));
        REQUIRE(w.propose(declare_cache("db", 3)));
        REQUIRE(settle_cache(w, "db", 3));
        const size_t lead = the_primary(w, "db");
        cl::command c;
        c.op          = cl::op::scale;
        c.name        = "db";
        c.sp.replicas = 2;
        REQUIRE(w.propose(c));
        REQUIRE(settle_cache(w, "db", 2));
        CHECK(the_primary(w, "db") == lead);
        CHECK(w.promotions().size() == 1);
    }
}

TEST_CASE("timing that would let a leader change look like a node loss is refused")
{
    cl::timing t;
    CHECK(cl::timing_refusal(t).empty());
    t.down_after_ms = 2 * t.election_ms;
    CHECK(cl::timing_refusal(t).find("three election timeouts") != std::string::npos);
    t.down_after_ms = 3 * t.election_ms;
    CHECK(cl::timing_refusal(t).empty());
    // The lease is shorter than the failure timeout by a quarter of it, which is what a node has to stop serving in.
    for (uint64_t d = 3000; d < 60000; d += 500)
    {
        cl::timing u;
        u.down_after_ms = d;
        CHECK(u.down_after_ms - u.lease_ms() >= 750);
    }
}

// ─── the brain's rules one at a time, where a whole cluster cannot tell a rule from a margin ───

namespace {

cl::view leading(std::vector<raft::node_id> voters, bool quorum = true, bool settled = true)
{
    cl::view v;
    v.role    = raft::role::leader;
    v.leader  = 1;
    v.voters  = std::move(voters);
    v.quorum  = quorum;
    v.stable  = true;
    v.settled = settled;
    v.commit  = 10;
    v.last    = 12;
    return v;
}

cl::view following(raft::node_id leader, raft::index_t applied = 0)
{
    cl::view v;
    v.role    = raft::role::follower;
    v.leader  = leader;
    v.voters  = {1, 2, 3};
    v.applied = applied;
    return v;
}

}   // namespace

TEST_CASE("a leader without a quorum remembers a lease request and grants nothing, and one with a quorum grants the log's end")
{
    cl::brain b(1, "n1", cl::timing{});
    cl::output out;
    b.on_lease_req(2, 7, 5000, leading({1, 2, 3}, false), out);
    CHECK(out.frames.empty());
    b.on_lease_req(2, 8, 5100, leading({1, 2, 3}), out);
    REQUIRE(out.frames.size() == 1);
    CHECK(out.frames[0].type == cl::frame::kind::lease_grant);
    CHECK(out.frames[0].to == 2);
    CHECK(out.frames[0].nonce == 8);
    // The end of the log, not the commit index: a move away from the asker may be proposed and not yet committed.
    CHECK(out.frames[0].index == 12);
}

TEST_CASE("only a voter's request is counted, and only a leader counts one")
{
    cl::brain b(1, "n1", cl::timing{});
    cl::output out;
    b.on_lease_req(9, 1, 5000, leading({1, 2, 3}), out);
    CHECK(out.frames.empty());
    CHECK_FALSE(b.heard_ms_ago(9, 5000).has_value());
    cl::view f = following(2);
    b.on_lease_req(2, 1, 5000, f, out);
    CHECK(out.frames.empty());
    CHECK_FALSE(b.heard_ms_ago(2, 5000).has_value());
}

TEST_CASE("a new leader counts every voter alive for the failure timeout from its own election, and then only the ones that asked")
{
    const cl::timing t;
    cl::brain b(1, "n1", t);
    cl::output out;
    const cl::view v = leading({1, 2, 3});
    b.tick(10000, v, out);
    CHECK(b.live(10000, v) == std::vector<cl::node_id>{1, 2, 3});
    CHECK(b.live(10000 + t.down_after_ms - 1, v) == std::vector<cl::node_id>{1, 2, 3});
    // Node 2 asked at 12000; node 3 stayed silent since the election.
    b.on_lease_req(2, 1, 12000, v, out);
    CHECK(b.live(10000 + t.down_after_ms, v) == std::vector<cl::node_id>{1, 2});
    CHECK(b.live(12000 + t.down_after_ms, v) == std::vector<cl::node_id>{1});
    // A leader that steps down forgets, and one that is not leading counts nobody.
    b.tick(13000, following(2), out);
    CHECK(b.live(13000, following(2)).empty());
    CHECK_FALSE(b.heard_ms_ago(2, 13000).has_value());
}

TEST_CASE("a lease runs from when the request was sent, so a grant that took two seconds is two seconds shorter")
{
    const cl::timing t;
    cl::brain b(2, "n2", t);
    cl::output out;
    b.tick(10000, following(1), out);
    REQUIRE(out.frames.size() == 1);
    const uint64_t nonce = out.frames[0].nonce;
    CHECK_FALSE(b.serving(10000));
    b.on_lease_grant(1, nonce, 0, 12000, following(1));
    CHECK(b.serving(12000));
    CHECK(b.lease_left_ms(12000) == t.lease_ms() - 2000);
    CHECK(b.serving(10000 + t.lease_ms() - 1));
    CHECK_FALSE(b.serving(10000 + t.lease_ms()));
}

TEST_CASE("a grant from a node that is not the leader, or answering a request never sent, extends nothing")
{
    cl::brain b(2, "n2", cl::timing{});
    cl::output out;
    b.tick(10000, following(1), out);
    const uint64_t nonce = out.frames[0].nonce;
    b.on_lease_grant(3, nonce, 0, 10100, following(1));
    b.on_lease_grant(1, nonce + 5, 0, 10100, following(1));
    CHECK_FALSE(b.serving(10100));
    // A grant is used once: its request leaves the table with everything older.
    b.on_lease_grant(1, nonce, 0, 10100, following(1));
    CHECK(b.serving(10100));
    const uint64_t left = b.lease_left_ms(10100);
    b.on_lease_grant(1, nonce, 0, 10200, following(1));
    CHECK(b.lease_left_ms(10200) == left - 100);
}

TEST_CASE("a lease that had lapsed is used only once the node has applied what the leader's log held, and one renewed in time never waits")
{
    const cl::timing t;
    cl::brain b(2, "n2", t);
    cl::output out;
    b.tick(10000, following(1, 5), out);
    b.on_lease_grant(1, out.frames[0].nonce, 40, 10100, following(1, 5));
    // The lease is back but the log behind it is not: the replicas may have moved while this node was away.
    CHECK_FALSE(b.serving(10100));
    b.note_applied(39);
    CHECK_FALSE(b.serving(10100));
    b.note_applied(40);
    CHECK(b.serving(10100));

    // A renewal while the lease holds does not raise the bar, however far the leader's log has moved on.
    cl::output again;
    b.tick(10400, following(1, 40), again);
    REQUIRE_FALSE(again.frames.empty());
    b.on_lease_grant(1, again.frames[0].nonce, 90, 10500, following(1, 40));
    CHECK(b.serving(10500));
}

TEST_CASE("the placement is planned only by a settled leader that holds a quorum")
{
    cl::brain b(1, "n1", cl::timing{});
    cl::command c;
    c.op   = cl::op::create;
    c.name = "api";
    c.sp   = cl::spec{"server", {}, 2};
    b.apply(c);

    cl::output out;
    b.tick(1000, leading({1, 2, 3}, true, false), out);
    CHECK(out.proposals.empty());
    b.tick(1100, leading({1, 2, 3}, false, true), out);
    CHECK(out.proposals.empty());
    b.tick(1200, following(2), out);
    CHECK(out.proposals.empty());
    b.tick(1300, leading({1, 2, 3}), out);
    CHECK(out.proposals.size() == 2);
    for (const std::string& p : out.proposals)
    {
        cl::command back;
        REQUIRE(cl::decode(p, back));
        CHECK(back.op == cl::op::assign);
    }
}

TEST_CASE("a node serves exactly the replicas the state gives it, with {node} spelled as its own name")
{
    cl::brain b(5, "edge-1", cl::timing{});
    cl::command c;
    c.op   = cl::op::create;
    c.name = "api";
    c.sp   = cl::spec{"server", {"--listen", "unix:/run/{node} x.sock"}, 1};
    b.apply(c);
    c.name = "web";
    b.apply(c);
    cl::command a;
    a.op   = cl::op::assign;
    a.name = "api";
    a.node = 5;
    b.apply(a);
    a.name = "web";
    a.node = 6;
    b.apply(a);
    const cl::want w = b.desired(1);
    REQUIRE(w.owned.size() == 1);
    CHECK(w.owned[0].name == "api");
    CHECK(w.owned[0].args == std::vector<std::string>{"--listen", "unix:/run/edge-1 x.sock"});
    CHECK_FALSE(w.serving);
}

TEST_CASE("a leader whose lease had lapsed serves again only from a state that has applied what its log committed, and only once it committed in its term")
{
    const cl::timing t;
    cl::brain b(1, "n1", t);
    cl::output out;
    cl::view v = leading({1, 2, 3});
    v.applied = 4;
    b.tick(10000, v, out);
    // Everything up to 10 is committed and this node has applied 4 of it.
    CHECK_FALSE(b.serving(10000));
    v.applied = 10;
    v.stable  = false;
    b.tick(10100, v, out);
    CHECK_FALSE(b.serving(10100));
    v.stable = true;
    b.tick(10200, v, out);
    CHECK(b.serving(10200));
    CHECK(b.lease_left_ms(10200) == t.lease_ms());
    // Once held, a lease is renewed from the quorum alone, whatever the state machine is doing.
    v.applied = 6;
    b.tick(10300, v, out);
    CHECK(b.lease_left_ms(10300) == t.lease_ms());
    // And a leader without a quorum renews nothing.
    v.quorum = false;
    b.tick(10400, v, out);
    CHECK(b.lease_left_ms(10400) == t.lease_ms() - 100);
}

// ─── a cache's primary, one rule at a time ───

namespace {

// A cache named db with these owners, led by `lead` (none when zero) as incarnation `inc` in `epoch`.
cl::state cache_state(cl::node_id lead, uint64_t inc, uint64_t epoch, std::set<cl::node_id> owners)
{
    cl::state s;
    s.specs["db"]     = cl::spec{"cache", {"-p", "6300"}, static_cast<uint32_t>(owners.size())};
    s.owners["db"]    = owners;
    s.primaries["db"] = cl::primary_record{lead, inc, epoch};
    return s;
}

cl::replica_report db(uint64_t inc, uint64_t epoch, uint64_t offset, bool primary = false)
{
    return cl::replica_report{"db", inc, epoch, offset, primary};
}

std::vector<cl::command> proposed(const cl::output& out)
{
    std::vector<cl::command> cmds;
    for (const std::string& p : out.proposals)
    {
        cl::command c;
        REQUIRE(cl::decode(p, c));
        cmds.push_back(std::move(c));
    }
    return cmds;
}

// A leader with id 1 that has been leading since 10000, with the replicas of `db` on nodes 1, 2 and 3 reporting as given, each asking every 250 ms
// until `until` (a node absent from the map does not ask), and the proposals of every tick collected.
struct db_cluster
{
    cl::timing t;
    cl::brain  b{1, "n1", t};
    std::vector<std::pair<uint64_t, cl::command>> proposals;
    std::map<cl::node_id, cl::replica_report> says;
    std::map<cl::node_id, uint64_t> until;
    uint64_t now = 10000;

    explicit db_cluster(cl::state s)
    {
        b.restore(std::move(s));
    }

    // Runs to `end` in ticks of 100 ms, the followers' requests arriving every 500, and each proposal applied at once as though it had committed.
    void run_to(uint64_t end)
    {
        for (; now < end; now += 100)
        {
            for (const auto& [node, rep] : says)
                if (now % 500 == 0 && now < (until.count(node) ? until.at(node) : ~uint64_t{0}))
                {
                    cl::output o;
                    b.on_lease_req(node, now, now, leading({1, 2, 3}), o, {rep});
                }
            cl::output out;
            b.set_reports(local ? std::vector<cl::replica_report>{*local} : std::vector<cl::replica_report>{});
            b.tick(now, leading({1, 2, 3}), out);
            for (const cl::command& c : proposed(out))
            {
                proposals.emplace_back(now, c);
                b.apply(c);
            }
        }
    }

    std::optional<cl::replica_report> local;
};

// The tick at which the first promotion was proposed, or nothing.
std::optional<uint64_t> promoted_at(const db_cluster& c)
{
    for (const auto& [at, cmd] : c.proposals)
        if (cmd.op == cl::op::promote)
            return at;
    return std::nullopt;
}

}   // namespace

TEST_CASE("a primary whose node keeps naming the process the log says leads it is never replaced, whatever the followers hold")
{
    db_cluster c(cache_state(2, 20, 1, {1, 2, 3}));
    c.local = db(10, 1, 900);
    c.says  = {{2, db(20, 1, 500, true)}, {3, db(30, 1, 5000)}};
    c.run_to(70000);
    CHECK(c.proposals.empty());
    // Even a primary that says it is fenced is still that process, and its own daemon decides what it does under its lease.
    c.says[2] = db(20, 1, 500, false);
    c.run_to(140000);
    CHECK(c.proposals.empty());
}

TEST_CASE("when a primary's node is declared down the follower with the most records is promoted in the same round, one epoch up")
{
    const cl::timing t;
    db_cluster c(cache_state(2, 20, 1, {1, 2, 3}));
    c.local = db(10, 1, 480);
    c.says  = {{2, db(20, 1, 500, true)}, {3, db(30, 1, 495)}};
    // Node 2 asks for the last time at 19500 and is declared down when the failure timeout has run from it.
    c.until = {{2, 20000}};
    c.run_to(19500 + t.down_after_ms);
    CHECK(c.proposals.empty());
    c.run_to(19500 + t.down_after_ms + 500);
    REQUIRE(c.proposals.size() == 2);
    CHECK(c.proposals[0].first == 19500 + t.down_after_ms);
    // The replica is taken from the dead node first, and the promotion is of the copy that held more of the stream.
    CHECK(c.proposals[0].second.op == cl::op::unassign);
    CHECK(c.proposals[0].second.node == 2);
    REQUIRE(c.proposals[1].second.op == cl::op::promote);
    CHECK(c.proposals[1].second.node == 3);
    CHECK(c.proposals[1].second.incarnation == 30);
    CHECK(c.proposals[1].second.epoch == 2);
}

TEST_CASE("a copy of a newer epoch outranks a longer copy of an older one when a primary is replaced")
{
    const cl::timing t;
    db_cluster c(cache_state(2, 20, 5, {1, 2, 3}));
    c.local = db(10, 4, 9000);
    c.says  = {{2, db(20, 5, 500, true)}, {3, db(30, 5, 40)}};
    c.until = {{2, 20000}};
    c.run_to(20000 + t.down_after_ms + 500);
    const cl::command& p = c.proposals.back().second;
    REQUIRE(p.op == cl::op::promote);
    CHECK(p.node == 3);
    CHECK(p.epoch == 6);
}

TEST_CASE("a primary whose node answers with another process is replaced after the failure timeout and not before, and its node keeps its replica")
{
    const cl::timing t;
    db_cluster c(cache_state(2, 20, 1, {1, 2, 3}));
    c.local = db(10, 1, 480);
    // Node 2 is restarted at 20000: it asks as before, and its replica is a new, empty process.  The last request that named the old one is at 19500.
    c.says = {{2, db(20, 1, 500, true)}, {3, db(30, 1, 495)}};
    c.run_to(20000);
    c.says[2] = db(21, 0, 0);
    c.run_to(19500 + t.down_after_ms);
    CHECK_FALSE(promoted_at(c).has_value());
    c.run_to(19500 + t.down_after_ms + 500);
    REQUIRE(promoted_at(c).has_value());
    CHECK(*promoted_at(c) == 19500 + t.down_after_ms);
    for (const auto& [at, cmd] : c.proposals)
    {
        CHECK(cmd.op == cl::op::promote);
        // The follower with data leads, and the restarted node, still alive, is not taken from.
        CHECK(cmd.node == 3);
    }
}

TEST_CASE("a leader gives the primary the whole failure timeout to show itself from when it first sees the record")
{
    const cl::timing t;
    db_cluster c(cache_state(2, 20, 1, {1, 2, 3}));
    c.local = db(10, 1, 480);
    // Node 2 answers, as a process the log does not name, from the first request.
    c.says = {{2, db(21, 0, 0)}, {3, db(30, 1, 495)}};
    c.run_to(10000 + t.down_after_ms - 300);
    CHECK_FALSE(promoted_at(c).has_value());
    c.run_to(10000 + t.down_after_ms + 500);
    REQUIRE(promoted_at(c).has_value());
    CHECK(*promoted_at(c) >= 10000 + t.down_after_ms - 100);
}

TEST_CASE("the first primary of a cache waits for every replica to speak and then is the lowest node, or the only one that did after an election timeout")
{
    const cl::timing t;
    {
        // The leader is node 2, whose own report is always first.
        cl::brain b(2, "n2", t);
        b.restore(cache_state(0, 0, 0, {1, 2, 3}));
        b.set_reports({db(20, 0, 0)});
        cl::output out;
        cl::view v = leading({1, 2, 3});
        v.leader   = 2;
        b.tick(10000, v, out);
        CHECK(out.proposals.empty());
        b.on_lease_req(3, 1, 10100, v, out, {db(30, 0, 0)});
        b.tick(10200, v, out);
        CHECK(out.proposals.empty());
        b.on_lease_req(1, 1, 10250, v, out, {db(10, 0, 0)});
        b.tick(10300, v, out);
        const auto cmds = proposed(out);
        REQUIRE(cmds.size() == 1);
        CHECK(cmds[0].op == cl::op::promote);
        CHECK(cmds[0].node == 1);
        CHECK(cmds[0].incarnation == 10);
        CHECK(cmds[0].epoch == 1);
    }
    {
        // A replica that never speaks is waited for one election timeout, and then the others choose without it.
        cl::brain b(2, "n2", t);
        b.restore(cache_state(0, 0, 0, {1, 2, 3}));
        b.set_reports({db(20, 0, 0)});
        cl::view v = leading({1, 2, 3});
        v.leader   = 2;
        cl::output out;
        b.tick(10000, v, out);
        b.on_lease_req(3, 1, 10100, v, out, {db(30, 0, 0)});
        b.on_lease_req(1, 1, 10100, v, out, {});
        b.tick(10500, v, out);
        CHECK(out.proposals.empty());
        b.tick(10000 + t.election_ms, v, out);
        const auto cmds = proposed(out);
        REQUIRE(cmds.size() == 1);
        CHECK(cmds[0].node == 2);
    }
}

TEST_CASE("nobody is promoted while no replica has reported, however long that lasts")
{
    const cl::timing t;
    db_cluster c(cache_state(2, 20, 1, {1, 2, 3}));
    // Nothing is said by anyone: the silent nodes are declared down and their replicas taken, and there is no copy to choose.
    c.run_to(10000 + 3 * t.down_after_ms);
    CHECK_FALSE(c.proposals.empty());
    CHECK_FALSE(promoted_at(c).has_value());
}

TEST_CASE("a cache replica is told to lead only as the process the log names, under a lease, and otherwise follows or waits")
{
    const cl::timing t;
    auto want_for = [&](cl::node_id self, cl::state s, std::optional<cl::replica_report> mine, bool lease) {
        cl::brain b(self, "n" + std::to_string(self), t);
        b.restore(std::move(s));
        if (mine)
            b.set_reports({*mine});
        cl::output out;
        if (lease)
        {
            const cl::node_id leader = self == 3 ? 2 : 3;
            b.tick(10000, following(leader), out);
            b.on_lease_grant(leader, out.frames.at(0).nonce, 0, 10000, following(leader));
        }
        return b.desired(10500).owned.at(0);
    };
    const cl::state led = cache_state(2, 20, 3, {1, 2, 3});

    auto lead = want_for(2, led, db(20, 3, 100), true);
    CHECK(lead.cache);
    CHECK(lead.role == cl::replica_mode::primary);
    CHECK(lead.epoch == 3);
    CHECK(lead.valid_ms == t.lease_ms() - 500);

    // The same node with another incarnation, a restart, is not the primary, and neither is one that has no replica yet.
    CHECK(want_for(2, led, db(21, 0, 0), true).role == cl::replica_mode::fenced);
    CHECK(want_for(2, led, std::nullopt, true).role == cl::replica_mode::fenced);
    // Another node's replica follows it, under a lease, and only then.
    auto follow = want_for(1, led, db(10, 3, 100), true);
    CHECK(follow.role == cl::replica_mode::follower);
    CHECK(follow.primary == 2);
    CHECK(follow.epoch == 3);
    // Without a lease it answers nobody, and has no time to act on.
    auto lapsed = want_for(2, led, db(20, 3, 100), false);
    CHECK(lapsed.role == cl::replica_mode::fenced);
    CHECK(lapsed.valid_ms == 0);
    CHECK(want_for(1, led, db(10, 3, 100), false).role == cl::replica_mode::fenced);
    // Nobody leads it yet: everyone waits.
    CHECK(want_for(1, cache_state(0, 0, 0, {1, 2, 3}), db(10, 0, 0), true).role == cl::replica_mode::fenced);
    // A server has no part to play, and is not marked as a cache.
    cl::state srv;
    srv.specs["api"]  = cl::spec{"server", {"-p", "80"}, 1};
    srv.owners["api"] = {1};
    CHECK_FALSE(want_for(1, srv, std::nullopt, true).cache);
}

TEST_CASE("the replicas a node runs travel on its lease request, and the leader keeps what a voter said and nothing a stranger did")
{
    const cl::timing t;
    cl::brain f(2, "n2", t);
    f.set_reports({db(20, 3, 100, true)});
    cl::output out;
    f.tick(10000, following(1), out);
    REQUIRE(out.frames.size() == 1);
    CHECK(out.frames[0].reports == std::vector<cl::replica_report>{db(20, 3, 100, true)});

    cl::brain l(1, "n1", t);
    cl::output o2;
    l.on_lease_req(2, 1, 10000, leading({1, 2, 3}), o2, out.frames[0].reports);
    l.on_lease_req(9, 1, 10000, leading({1, 2, 3}), o2, {db(90, 1, 1)});
    CHECK(l.report_of(2, "db") == db(20, 3, 100, true));
    CHECK_FALSE(l.report_of(9, "db").has_value());
    CHECK_FALSE(l.report_of(2, "other").has_value());
    CHECK(l.report_age_ms(2, "db", 10300) == 300);
}
