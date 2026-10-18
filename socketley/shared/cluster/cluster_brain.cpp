#include "cluster_brain.h"

#include <algorithm>

namespace socketley::cluster
{

std::string timing_refusal(const timing& t)
{
    if (t.election_ms == 0)
        return "the election timeout is zero";
    // A lease is three quarters of it, and a node must have stopped serving before the leader moves its replicas.
    if (t.down_after_ms < 3 * t.election_ms)
        return "a node is declared down after " + std::to_string(t.down_after_ms) + " ms, which is less than three election timeouts ("
             + std::to_string(3 * t.election_ms) + " ms): a leader change would look like a node loss";
    return {};
}

view view_of(const raft::node& n, raft::index_t applied, raft::index_t last_proposed)
{
    view v;
    v.role   = n.current_role();
    v.leader = n.leader();
    v.voters = n.voters();
    v.commit  = n.commit_index();
    v.applied = applied;
    v.last    = n.last_index();
    if (v.role != raft::role::leader)
        return v;
    v.quorum = n.quorum_active();
    // The plan is made on what the log says, so everything committed must be applied, an entry of this term among it,
    // and everything this leader proposed.
    const auto term_at_commit = n.term_at(n.commit_index());
    v.stable  = term_at_commit && *term_at_commit == n.term();
    v.settled = v.stable && applied >= n.commit_index() && applied >= last_proposed;
    return v;
}

brain::brain(node_id self, std::string self_name, timing t) : m_self(self), m_name(std::move(self_name)), m_timing(t) {}

void brain::tick(uint64_t now, const view& v, output& out)
{
    note_applied(v.applied);
    const bool leading = v.role == raft::role::leader;
    if (leading && !m_leading)
    {
        // A new leader starts every node's clock at its own election, because it was not there to hear the requests before.
        m_leader_since = now;
        m_last_req.clear();
        m_heard.clear();
        m_confirmed.clear();
        m_seen.clear();
    }
    if (!leading && m_leading)
    {
        m_last_req.clear();
        m_heard.clear();
        m_confirmed.clear();
        m_seen.clear();
    }
    m_leading = leading;

    if (leading)
    {
        // A leader's own lease is its last look at a quorum, since nobody else grants it one, and one that had lapsed
        // is taken up again only from a state that has caught up.
        if (v.quorum && (now < m_lease_until || (v.stable && m_applied >= v.commit)))
            m_lease_until = std::max(m_lease_until, now + m_timing.lease_ms());
        confirm(m_self, m_local, now);
        if (v.quorum && v.settled)
        {
            const std::vector<node_id> alive = live(now, v);
            // Placement first, and the promotion judged on the state that placement leaves, so a primary whose node is
            // gone is replaced in the same round that gives the replica away.
            state after = m_state;
            for (const command& c : plan(m_state, alive))
            {
                after.apply(c);
                out.proposals.push_back(encode(c));
            }
            for (const command& c : promotions(after, alive, now))
                out.proposals.push_back(encode(c));
        }
        return;
    }

    // A new leader is asked at once, so a node that just lost its old one is not left waiting out the request interval.
    if (v.leader != m_asked)
    {
        m_asked    = v.leader;
        m_next_req = 0;
    }
    if (v.leader == 0 || v.leader == m_self || now < m_next_req)
        return;
    m_next_req = now + m_timing.request_every_ms();
    const uint64_t nonce = ++m_nonce;
    m_sent[nonce] = now;
    // Anything older than one lease can never extend it, so the table stays a handful of entries however long the leader is silent.
    while (!m_sent.empty() && m_sent.begin()->second + m_timing.lease_ms() < now)
        m_sent.erase(m_sent.begin());
    out.frames.push_back(frame{frame::kind::lease_req, v.leader, nonce, 0, m_local});
}

void brain::on_lease_req(node_id from, uint64_t nonce, uint64_t now, const view& v, output& out,
                         const std::vector<replica_report>& reports)
{
    note_applied(v.applied);
    if (v.role != raft::role::leader || !std::binary_search(v.voters.begin(), v.voters.end(), from))
        return;
    m_last_req[from] = now;
    m_heard[from]    = heard{reports, now};
    confirm(from, reports, now);
    // Without a quorum this leader is about to be replaced, and a lease it granted could outlive the replicas' move.
    // The index is the log's end and not the commit index, since a move away from this very node may be proposed and not yet committed.
    if (v.quorum)
        out.frames.push_back(frame{frame::kind::lease_grant, from, nonce, v.last, {}});
}

void brain::on_lease_grant(node_id from, uint64_t nonce, raft::index_t index, uint64_t now, const view& v)
{
    note_applied(v.applied);
    if (from == m_self || from != v.leader)
        return;
    auto it = m_sent.find(nonce);
    if (it == m_sent.end())
        return;
    const uint64_t until = it->second + m_timing.lease_ms();
    // A lease that had lapsed comes back only once this node has applied what the leader had committed, because the
    // replicas may have moved while it was away.
    if (now >= m_lease_until && until > now)
        m_gate = std::max(m_gate, index);
    // The lease runs from when the request left, which is never later than when the leader heard it.
    m_lease_until = std::max(m_lease_until, until);
    m_sent.erase(m_sent.begin(), std::next(it));
}

std::vector<node_id> brain::live(uint64_t now, const view& v) const
{
    std::vector<node_id> out;
    if (v.role != raft::role::leader)
        return out;
    for (node_id id : v.voters)
    {
        if (id == m_self)
        {
            out.push_back(id);
            continue;
        }
        auto it = m_last_req.find(id);
        const uint64_t heard = std::max(it == m_last_req.end() ? uint64_t{0} : it->second, m_leader_since);
        if (now - heard < m_timing.down_after_ms)
            out.push_back(id);
    }
    return out;
}

std::optional<uint64_t> brain::heard_ms_ago(node_id id, uint64_t now) const
{
    auto it = m_last_req.find(id);
    if (it == m_last_req.end())
        return std::nullopt;
    return now - it->second;
}

std::optional<replica_report> brain::report_of(node_id id, const std::string& name) const
{
    const std::vector<replica_report>* from = &m_local;
    if (id != m_self)
    {
        auto it = m_heard.find(id);
        if (it == m_heard.end())
            return std::nullopt;
        from = &it->second.reports;
    }
    for (const replica_report& r : *from)
        if (r.name == name)
            return r;
    return std::nullopt;
}

std::optional<uint64_t> brain::report_age_ms(node_id id, const std::string& name, uint64_t now) const
{
    if (!report_of(id, name))
        return std::nullopt;
    if (id == m_self)
        return 0;
    return now - m_heard.at(id).at;
}

void brain::confirm(node_id from, const std::vector<replica_report>& reports, uint64_t now)
{
    for (const replica_report& r : reports)
    {
        auto p = m_state.primaries.find(r.name);
        // The process the log names, still on that node: a restarted replica is another process, and it is the daemon
        // beside this one that decides whether the process it holds leads, which it does only under a lease.
        if (p != m_state.primaries.end() && p->second.node == from && p->second.incarnation == r.incarnation)
            m_confirmed[r.name] = now;
    }
}

std::vector<command> brain::promotions(const state& after, const std::vector<node_id>& alive, uint64_t now)
{
    std::vector<command> out;
    for (const auto& [name, rec] : after.primaries)
    {
        if (!after.specs.count(name))
            continue;
        // The clock of a record starts when this leader first sees it, so a promotion just made or a leader just elected
        // gives the primary the whole failure timeout to show itself.
        auto sn = m_seen.find(name);
        if (sn == m_seen.end() || !(sn->second.rec == rec))
            sn = m_seen.insert_or_assign(name, seen{rec, now}).first;
        auto cf = m_confirmed.find(name);
        const uint64_t last = std::max(cf == m_confirmed.end() ? uint64_t{0} : cf->second, sn->second.since);
        if (rec.node != 0 && now - last < m_timing.down_after_ms)
            continue;

        // The first primary of a cache waits for every replica to have spoken, so that it is chosen by node and not by whose report arrived first
        // (the leader's own always does), with an election timeout of grace for one that never will.
        if (rec.epoch == 0 && now - sn->second.since < m_timing.election_ms)
        {
            bool spoken = true;
            for (node_id n : after.owners.at(name))
                spoken = spoken && (!std::binary_search(alive.begin(), alive.end(), n) || report_of(n, name));
            if (!spoken)
                continue;
        }

        std::vector<candidate> cands;
        for (node_id n : after.owners.at(name))
        {
            if (!std::binary_search(alive.begin(), alive.end(), n))
                continue;
            auto rep = report_of(n, name);
            // A primary that failed to lead is not chosen again, and a replica that has said nothing has no copy to judge.
            if (!rep || (n == rec.node && rep->incarnation == rec.incarnation))
                continue;
            cands.push_back(candidate{n, rep->incarnation, rep->epoch, rep->offset});
        }
        if (auto best = best_candidate(cands))
        {
            command c;
            c.op          = op::promote;
            c.name        = name;
            c.node        = best->node;
            c.incarnation = best->incarnation;
            c.epoch       = rec.epoch + 1;
            out.push_back(std::move(c));
        }
    }
    return out;
}

want brain::desired(uint64_t now) const
{
    want w;
    w.serving = serving(now);
    for (const auto& [name, held] : m_state.owners)
    {
        if (!held.count(m_self))
            continue;
        const spec& sp = m_state.specs.at(name);
        want::item it;
        it.name = name;
        it.type = sp.type;
        it.args = expand_args(sp.args, m_name);
        if (sp.type == "cache")
        {
            it.cache = true;
            primary_record rec;
            if (auto p = m_state.primaries.find(name); p != m_state.primaries.end())
                rec = p->second;
            const auto mine = report_of(m_self, name);
            it.primary     = rec.node;
            it.epoch       = rec.epoch;
            it.incarnation = mine ? mine->incarnation : 0;
            // Without a lease or a primary the replica answers nobody; it leads only as the process the log names, and follows whoever does.
            if (w.serving && rec.node != 0)
            {
                it.role     = rec.node != m_self ? replica_mode::follower
                            : (mine && mine->incarnation == rec.incarnation ? replica_mode::primary : replica_mode::fenced);
                it.valid_ms = lease_left_ms(now);
            }
        }
        w.owned.push_back(std::move(it));
    }
    return w;
}

}   // namespace socketley::cluster
