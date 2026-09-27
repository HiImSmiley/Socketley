#include "raft.h"

#include <algorithm>

#ifdef SOCKETLEY_RAFT_FAULTS
#define RAFT_FAULT(f) ((m_opts.faults & (f)) != 0)
#else
#define RAFT_FAULT(f) false
#endif

namespace socketley::raft
{

std::string encode_voters(const std::vector<node_id>& voters)
{
    std::string out;
    out.reserve(voters.size() * 8);
    for (node_id v : voters)
        for (int b = 0; b < 8; ++b)
            out += static_cast<char>((v >> (8 * b)) & 0xFF);
    return out;
}

std::vector<node_id> decode_voters(const std::string& data)
{
    std::vector<node_id> out;
    for (size_t off = 0; off + 8 <= data.size(); off += 8)
    {
        node_id v = 0;
        for (int b = 0; b < 8; ++b)
            v |= static_cast<node_id>(static_cast<unsigned char>(data[off + b])) << (8 * b);
        out.push_back(v);
    }
    std::sort(out.begin(), out.end());
    return out;
}

node::node(const options& opts, persisted state)
    : m_opts(opts)
    , m_rng(opts.seed ^ (opts.id * 0x9E3779B97F4A7C15ull))
{
    if (m_opts.election_ticks < 2)
        m_opts.election_ticks = 2;
    if (m_opts.heartbeat_ticks < 1)
        m_opts.heartbeat_ticks = 1;
    if (m_opts.max_append_entries < 1)
        m_opts.max_append_entries = 1;

    std::sort(state.snap.voters.begin(), state.snap.voters.end());
    m_snap = std::make_shared<const snapshot>(std::move(state.snap));

    // A log that does not continue the snapshot contiguously is cut at the first gap.
    for (entry& e : state.log)
    {
        if (e.index <= m_snap->index)
            continue;
        if (e.index != last_index() + 1)
            break;
        m_log.push_back(std::move(e));
    }

    m_term      = state.hard.term;
    m_vote      = state.hard.vote;
    m_commit    = m_snap->index;
    m_applied   = m_snap->index;
    m_last_hard = state.hard;
    m_unstable_from = last_index() + 1;

    reset(m_term);
    refresh_config();
    m_last_soft = soft_state{m_role, m_leader, m_term};
}

uint32_t node::random_below(uint32_t bound)
{
    // splitmix64, so a seed reproduces every election timeout exactly.
    uint64_t z = (m_rng += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z ^= z >> 31;
    return bound ? static_cast<uint32_t>(z % bound) : 0;
}

message node::make(msg_type type, node_id to) const
{
    message m;
    m.type = type;
    m.from = m_opts.id;
    m.to   = to;
    m.term = m_term;
    return m;
}

term_t node::last_term() const
{
    return m_log.empty() ? m_snap->term : m_log.back().term;
}

std::optional<term_t> node::term_at(index_t i) const
{
    if (i == m_snap->index)
        return m_snap->term;
    if (i < m_snap->index || i > last_index())
        return std::nullopt;
    return m_log[i - m_snap->index - 1].term;
}

const entry* node::entry_at(index_t i) const
{
    if (i <= m_snap->index || i > last_index())
        return nullptr;
    return &m_log[i - m_snap->index - 1];
}

bool node::is_voter(node_id id) const
{
    return std::binary_search(m_voters.begin(), m_voters.end(), id);
}

bool node::in_lease() const
{
    if (RAFT_FAULT(fault_no_check_quorum))
        return false;
    return m_leader != no_node && m_election_elapsed < m_opts.election_ticks;
}

// ─── roles ───

void node::reset(term_t term)
{
    if (term != m_term)
    {
        m_term = term;
        m_vote = no_node;
    }
    m_leader             = no_node;
    m_election_elapsed   = 0;
    m_heartbeat_elapsed  = 0;
    m_randomized_timeout = m_opts.election_ticks + random_below(m_opts.election_ticks);
    m_votes.clear();
    m_progress.clear();
    m_pending_reads.clear();
    m_deferred_reads.clear();
}

void node::become_follower(term_t term, node_id leader)
{
    reset(term);
    m_role   = role::follower;
    m_leader = leader;
}

void node::become_leader()
{
    reset(m_term);
    m_role   = role::leader;
    m_leader = m_opts.id;
    sync_progress();

    entry noop;
    noop.term  = m_term;
    noop.index = last_index() + 1;
    noop.type  = entry_type::noop;
    append_entry(std::move(noop));
    m_term_start = last_index();

    if (maybe_commit() && m_role != role::leader)
        return;
    bcast_append();
}

void node::campaign(bool pre)
{
    if (pre)
    {
        reset(m_term);
        m_role = role::pre_candidate;
    }
    else
    {
        reset(m_term + 1);
        m_role = role::candidate;
        m_vote = m_opts.id;
    }
    m_votes[m_opts.id] = true;

    if (count_votes(true) >= quorum())
    {
        if (pre)
            campaign(false);
        else
            become_leader();
        return;
    }

    for (node_id v : m_voters)
    {
        if (v == m_opts.id)
            continue;
        message m = make(pre ? msg_type::pre_vote : msg_type::vote, v);
        // A pre-vote asks about the term the candidate would take, without taking it.
        if (pre)
            m.term = m_term + 1;
        m.index    = last_index();
        m.log_term = last_term();
        send(std::move(m));
    }
}

size_t node::count_votes(bool granted) const
{
    size_t n = 0;
    for (const auto& [id, g] : m_votes)
        if (g == granted && is_voter(id))
            ++n;
    return n;
}

void node::tally(const message& m)
{
    if (!is_voter(m.from))
        return;
    m_votes.emplace(m.from, !m.reject);

    if (count_votes(true) >= quorum())
    {
        if (m_role == role::pre_candidate)
            campaign(false);
        else
            become_leader();
    }
    else if (count_votes(false) >= quorum())
    {
        become_follower(m_term, no_node);
    }
}

// ─── ticks ───

void node::tick()
{
    if (m_role == role::leader)
        tick_leader();
    else
        tick_election();
}

void node::tick_election()
{
    ++m_election_elapsed;
    if (promotable() && m_election_elapsed >= m_randomized_timeout)
        campaign(!RAFT_FAULT(fault_skip_pre_vote));
}

void node::tick_leader()
{
    ++m_heartbeat_elapsed;
    ++m_election_elapsed;

    if (m_election_elapsed >= m_opts.election_ticks)
    {
        m_election_elapsed = 0;
        if (!RAFT_FAULT(fault_no_check_quorum))
        {
            size_t active = is_voter(m_opts.id) ? 1 : 0;
            for (const auto& [id, p] : m_progress)
                if (p.recent_active && is_voter(id))
                    ++active;
            if (active < quorum())
            {
                become_follower(m_term, no_node);
                return;
            }
        }
        for (auto& [id, p] : m_progress)
            p.recent_active = false;
    }

    if (m_heartbeat_elapsed >= m_opts.heartbeat_ticks)
    {
        m_heartbeat_elapsed = 0;
        bcast_heartbeat();
    }
}

// ─── messages ───

void node::step(const message& m)
{
    if (m.to != m_opts.id)
        return;

    const bool from_leader = m.type == msg_type::append
                          || m.type == msg_type::heartbeat
                          || m.type == msg_type::snapshot;

    if (m.term > m_term)
    {
        const bool vote_request = m.type == msg_type::vote || m.type == msg_type::pre_vote;
        // A node that heard from a live leader within an election timeout will not help depose it.
        if (vote_request && in_lease())
            return;

        const bool keeps_term = m.type == msg_type::pre_vote
                             || (m.type == msg_type::pre_vote_resp && !m.reject);
        if (!keeps_term)
            become_follower(m.term, from_leader ? m.from : no_node);
    }
    else if (m.term < m_term)
    {
        // A deposed leader learns the newer term from the answer, so a rejoining node cannot be ignored for ever.
        if (from_leader)
        {
            message r = make(msg_type::append_resp, m.from);
            r.reject = true;
            r.index  = m.index;
            send(std::move(r));
        }
        else if (m.type == msg_type::pre_vote)
        {
            message r = make(msg_type::pre_vote_resp, m.from);
            r.reject = true;
            send(std::move(r));
        }
        return;
    }

    switch (m.type)
    {
    case msg_type::pre_vote:
    case msg_type::vote:
        handle_vote_request(m);
        return;

    case msg_type::pre_vote_resp:
        if (m_role == role::pre_candidate && (m.reject || m.term == m_term + 1))
            tally(m);
        return;

    case msg_type::vote_resp:
        if (m_role == role::candidate)
            tally(m);
        return;

    case msg_type::append:
    case msg_type::heartbeat:
    case msg_type::snapshot:
        if (m_role == role::leader)
            return;
        if (m_role != role::follower)
            become_follower(m_term, m.from);
        m_leader           = m.from;
        m_election_elapsed = 0;
        if (m.type == msg_type::append)
            handle_append(m);
        else if (m.type == msg_type::heartbeat)
            handle_heartbeat(m);
        else
            handle_snapshot(m);
        return;

    case msg_type::append_resp:
        if (m_role == role::leader)
            handle_append_resp(m);
        return;

    case msg_type::heartbeat_resp:
        if (m_role == role::leader)
            handle_heartbeat_resp(m);
        return;

    case msg_type::read_index:
        if (m_role == role::leader)
            handle_leader_read(m.from, m.context);
        return;

    case msg_type::read_index_resp:
        if (m_role == role::follower && m.from == m_leader)
            m_reads.push_back(read_state{m.context, m.index});
        return;
    }
}

void node::handle_vote_request(const message& m)
{
    const bool pre = m.type == msg_type::pre_vote;
    const bool can_vote = m_vote == m.from
                       || (m_vote == no_node && m_leader == no_node)
                       || (pre && m.term > m_term);
    const bool up_to_date = m.log_term > last_term()
                         || (m.log_term == last_term() && m.index >= last_index());

    message r = make(pre ? msg_type::pre_vote_resp : msg_type::vote_resp, m.from);
    if (can_vote && (up_to_date || RAFT_FAULT(fault_vote_ignores_log)))
    {
        r.term = m.term;
        if (!pre)
        {
            m_vote             = m.from;
            m_election_elapsed = 0;
        }
    }
    else
    {
        r.reject = true;
    }
    send(std::move(r));
}

void node::handle_append(const message& m)
{
    message r = make(msg_type::append_resp, m.from);
    r.index   = m.index;
    r.context = m.context;

    // Everything at or below the commit index already matches, so the answer is the commit index.
    if (m.index < m_commit)
    {
        r.hint_index = m_commit;
        send(std::move(r));
        return;
    }

    if (term_at(m.index) != m.log_term)
    {
        r.reject = true;
        if (m.index > last_index())
        {
            r.hint_index = last_index() + 1;
        }
        else
        {
            // The whole conflicting term is skipped in one round trip rather than one entry per round trip.
            const term_t t = *term_at(m.index);
            index_t h = m.index;
            while (h - 1 > m_commit && term_at(h - 1) == t)
                --h;
            r.hint_term  = t;
            r.hint_index = h;
        }
        send(std::move(r));
        return;
    }

    size_t k = 0;
    if (RAFT_FAULT(fault_truncate_on_append))
    {
        truncate_from(m.index + 1);
    }
    else
    {
        for (; k < m.entries.size(); ++k)
        {
            const std::optional<term_t> t = term_at(m.entries[k].index);
            if (!t)
                break;
            // Only a conflict truncates, because a stale or duplicated append must not undo a newer one.
            if (*t != m.entries[k].term)
            {
                truncate_from(m.entries[k].index);
                break;
            }
        }
    }
    for (; k < m.entries.size(); ++k)
        append_entry(m.entries[k]);

    const index_t last_new = m.index + m.entries.size();
    commit_to(std::min(m.commit, last_new));

    r.hint_index = last_new;
    send(std::move(r));
}

void node::handle_heartbeat(const message& m)
{
    // The leader sends no more than what it knows this follower holds, so this commit is safe to take.
    commit_to(m.commit);
    message r = make(msg_type::heartbeat_resp, m.from);
    r.context = m.context;
    send(std::move(r));
}

void node::handle_snapshot(const message& m)
{
    message r = make(msg_type::append_resp, m.from);
    r.context = m.context;
    const snapshot& s = *m.snap;

    if (s.index <= m_commit)
    {
        r.hint_index = m_commit;
        send(std::move(r));
        return;
    }

    if (term_at(s.index) == s.term)
    {
        commit_to(s.index);
        r.hint_index = s.index;
        send(std::move(r));
        return;
    }

    m_snap    = m.snap;
    m_log.clear();
    m_commit  = s.index;
    m_applied = s.index;
    m_snap_dirty      = true;
    m_pending_restore = m.snap;
    m_truncate_from   = m_truncate_from ? std::min(m_truncate_from, s.index + 1) : s.index + 1;
    m_unstable_from   = s.index + 1;
    refresh_config();

    r.hint_index = s.index;
    send(std::move(r));
}

void node::handle_append_resp(const message& m)
{
    auto it = m_progress.find(m.from);
    if (it == m_progress.end())
        return;
    progress& p = it->second;
    p.recent_active = true;
    // A rejection still answers at this term, so it confirms leadership for a read as well as a success does.
    if (m.context)
        ack_read(m.from, m.context);

    if (m.reject)
    {
        if (p.state == progress_state::snapshot)
            return;
        // A rejection of anything but the probe in flight is a stale answer.
        if (p.state == progress_state::replicate ? m.index <= p.match : m.index != p.next - 1)
            return;

        index_t next = m.hint_index;
        if (m.hint_term != 0)
        {
            index_t j = std::min(m.index, last_index());
            while (j > m_snap->index && *term_at(j) > m.hint_term)
                --j;
            if (term_at(j) == m.hint_term)
                next = j + 1;
        }
        next = std::max(next, p.match + 1);
        next = std::min(next, m.index);
        next = std::max<index_t>(next, 1);

        p.next   = next;
        p.state  = progress_state::probe;
        p.paused = false;
        send_append(m.from, p);
        return;
    }

    bool updated = false;
    if (m.hint_index > p.match)
    {
        p.match = m.hint_index;
        updated = true;
    }
    p.next = std::max(p.next, m.hint_index + 1);

    if (p.state == progress_state::snapshot)
    {
        if (p.match < p.pending_snapshot)
            return;
        p.state = progress_state::probe;
    }
    if (p.state == progress_state::probe && updated)
        p.state = progress_state::replicate;
    p.paused = false;

    if (updated && maybe_commit())
    {
        if (m_role != role::leader)
            return;
        bcast_append();
    }

    // The commit may have changed the voter set, so the progress is looked up again.
    it = m_progress.find(m.from);
    if (it != m_progress.end() && it->second.next <= last_index())
        send_append(m.from, it->second);
}

void node::handle_heartbeat_resp(const message& m)
{
    auto it = m_progress.find(m.from);
    if (it == m_progress.end())
        return;
    progress& p = it->second;
    p.recent_active = true;
    if (p.state == progress_state::probe)
        p.paused = false;

    if (p.state != progress_state::snapshot && p.match < last_index())
    {
        // Two heartbeats with no progress in between mean the optimistic window was lost.
        if (p.state == progress_state::replicate && p.match == p.match_at_heartbeat)
            p.next = p.match + 1;
        p.match_at_heartbeat = p.match;
        send_append(m.from, p);
    }

    if (m.context)
        ack_read(m.from, m.context);
}

// ─── replication ───

void node::send_append(node_id to, progress& p)
{
    if (p.state == progress_state::snapshot || p.paused)
        return;

    const index_t prev = p.next - 1;
    const std::optional<term_t> prev_term = term_at(prev);
    if (!prev_term)
    {
        message m = make(msg_type::snapshot, to);
        m.snap    = m_snap;
        m.context = m_read_round;
        send(std::move(m));
        p.state            = progress_state::snapshot;
        p.pending_snapshot = m_snap->index;
        p.snapshot_ticks   = 0;
        return;
    }

    message m = make(msg_type::append, to);
    m.index    = prev;
    m.log_term = *prev_term;
    m.commit   = m_commit;
    m.context  = m_read_round;
    for (index_t i = p.next; i <= last_index() && m.entries.size() < m_opts.max_append_entries; ++i)
        m.entries.push_back(*entry_at(i));

    if (p.state == progress_state::replicate)
    {
        if (!m.entries.empty())
            p.next = m.entries.back().index + 1;
    }
    else
    {
        p.paused = true;
    }
    send(std::move(m));
}

void node::send_heartbeat(node_id to, const progress& p)
{
    message m = make(msg_type::heartbeat, to);
    m.commit  = std::min(p.match, m_commit);
    m.context = m_read_round;
    send(std::move(m));
}

void node::bcast_append()
{
    for (auto& [id, p] : m_progress)
        send_append(id, p);
}

void node::bcast_heartbeat()
{
    for (auto& [id, p] : m_progress)
    {
        if (p.state == progress_state::snapshot)
        {
            // A lost snapshot is sent again once an election timeout has gone by without an answer.
            if (++p.snapshot_ticks * m_opts.heartbeat_ticks >= m_opts.election_ticks)
            {
                p.state  = progress_state::probe;
                p.paused = false;
                send_append(id, p);
            }
        }
        else if (p.state == progress_state::probe)
        {
            p.paused = false;
        }
        send_heartbeat(id, p);
    }
}

void node::append_entry(entry e)
{
    const bool config = e.type == entry_type::config;
    m_log.push_back(std::move(e));
    if (config)
    {
        m_voters     = decode_voters(m_log.back().data);
        m_conf_index = m_log.back().index;
        if (m_role == role::leader)
            sync_progress();
    }
}

void node::truncate_from(index_t i)
{
    while (!m_log.empty() && m_log.back().index >= i)
        m_log.pop_back();
    if (i < m_unstable_from)
    {
        m_unstable_from = i;
        m_truncate_from = m_truncate_from ? std::min(m_truncate_from, i) : i;
    }
    if (m_conf_index >= i)
        refresh_config();
}

void node::commit_to(index_t i)
{
    if (i > m_commit)
        m_commit = i;
}

bool node::maybe_commit()
{
    if (m_voters.empty())
        return false;

    std::vector<index_t> match;
    match.reserve(m_voters.size());
    for (node_id v : m_voters)
    {
        if (v == m_opts.id)
        {
            match.push_back(last_index());
            continue;
        }
        auto it = m_progress.find(v);
        match.push_back(it == m_progress.end() ? 0 : it->second.match);
    }
    std::sort(match.begin(), match.end(), std::greater<>());
    const index_t n = match[quorum() - 1];

    if (n <= m_commit)
        return false;
    // Counting replicas commits only this term's entries; earlier ones commit beneath them (Raft 5.4.2).
    if (term_at(n) != m_term && !RAFT_FAULT(fault_commit_prior_term))
        return false;

    m_commit = n;
    after_commit();
    return true;
}

void node::after_commit()
{
    if (m_role != role::leader)
        return;

    // A leader that has committed its own removal stops leading.
    if (!is_voter(m_opts.id) && m_commit >= m_conf_index)
    {
        become_follower(m_term, no_node);
        return;
    }

    if (m_commit >= m_term_start && !m_deferred_reads.empty())
    {
        auto deferred = std::move(m_deferred_reads);
        m_deferred_reads.clear();
        for (const auto& [from, request] : deferred)
            handle_leader_read(from, request);
    }
}

// ─── configuration ───

void node::refresh_config()
{
    m_voters     = m_snap->voters;
    m_conf_index = m_snap->index;
    for (auto it = m_log.rbegin(); it != m_log.rend(); ++it)
    {
        if (it->type == entry_type::config)
        {
            m_voters     = decode_voters(it->data);
            m_conf_index = it->index;
            break;
        }
    }
    if (m_role == role::leader)
        sync_progress();
}

void node::sync_progress()
{
    for (node_id v : m_voters)
    {
        if (v == m_opts.id || m_progress.count(v))
            continue;
        progress p;
        p.next          = last_index() + 1;
        p.recent_active = true;
        m_progress.emplace(v, p);
    }
    for (auto it = m_progress.begin(); it != m_progress.end();)
    {
        if (is_voter(it->first))
            ++it;
        else
            it = m_progress.erase(it);
    }
}

std::vector<node_id> node::voters_at(index_t i) const
{
    for (index_t j = std::min(i, last_index()); j > m_snap->index; --j)
    {
        const entry* e = entry_at(j);
        if (e->type == entry_type::config)
            return decode_voters(e->data);
    }
    return m_snap->voters;
}

// ─── client API ───

bool node::backlogged() const
{
    return last_index() - m_commit >= m_opts.max_uncommitted;
}

proposal node::propose(std::string data)
{
    if (m_role != role::leader)
        return proposal{propose_status::not_leader, 0, 0, m_leader};
    if (backlogged())
        return proposal{propose_status::busy, 0, 0, m_leader};

    entry e;
    e.term  = m_term;
    e.index = last_index() + 1;
    e.data  = std::move(data);
    const proposal out{propose_status::ok, e.index, e.term, m_opts.id};
    append_entry(std::move(e));

    if (maybe_commit() && m_role != role::leader)
        return out;
    bcast_append();
    return out;
}

proposal node::propose_config(std::vector<node_id> voters)
{
    if (m_role != role::leader)
        return proposal{propose_status::not_leader, 0, 0, m_leader};

    // One change at a time, and only once this leader has committed in its term (Ongaro, raft-dev 2015).
    const bool pending = m_conf_index > m_commit || m_commit < m_term_start;
    if (pending && !RAFT_FAULT(fault_concurrent_config))
        return proposal{propose_status::change_pending, 0, 0, m_leader};
    if (backlogged())
        return proposal{propose_status::busy, 0, 0, m_leader};

    std::sort(voters.begin(), voters.end());
    if (voters == m_voters || voters.empty())
        return proposal{propose_status::no_change, 0, 0, m_leader};

    entry e;
    e.term  = m_term;
    e.index = last_index() + 1;
    e.type  = entry_type::config;
    e.data  = encode_voters(voters);
    const proposal out{propose_status::ok, e.index, e.term, m_opts.id};
    append_entry(std::move(e));

    if (maybe_commit() && m_role != role::leader)
        return out;
    bcast_append();
    return out;
}

proposal node::propose_add(node_id id)
{
    if (is_voter(id))
        return proposal{propose_status::no_change, 0, 0, m_leader};
    std::vector<node_id> v = m_voters;
    v.push_back(id);
    return propose_config(std::move(v));
}

proposal node::propose_remove(node_id id)
{
    if (!is_voter(id))
        return proposal{propose_status::no_change, 0, 0, m_leader};
    std::vector<node_id> v = m_voters;
    v.erase(std::find(v.begin(), v.end(), id));
    return propose_config(std::move(v));
}

// ─── ReadIndex ───

bool node::read_index(uint64_t request)
{
    if (m_role == role::leader)
    {
        handle_leader_read(m_opts.id, request);
        return true;
    }
    if (m_leader == no_node)
        return false;

    message m = make(msg_type::read_index, m_leader);
    m.context = request;
    send(std::move(m));
    return true;
}

void node::handle_leader_read(node_id from, uint64_t request)
{
    // Until an entry of its own term commits, a new leader's commit index may be behind the cluster's.
    if (m_commit < m_term_start)
    {
        m_deferred_reads.emplace_back(from, request);
        return;
    }

    pending_read r;
    r.from    = from;
    r.request = request;
    r.index   = m_commit;
    r.round   = ++m_read_round;
    if (is_voter(m_opts.id))
        r.acks.push_back(m_opts.id);

    if (RAFT_FAULT(fault_read_without_quorum))
    {
        release_read(r);
        return;
    }

    m_pending_reads.push_back(std::move(r));
    release_reads();
    if (m_pending_reads.empty())
        return;
    for (const auto& [id, p] : m_progress)
        send_heartbeat(id, p);
}

void node::ack_read(node_id from, uint64_t round)
{
    if (!is_voter(from))
        return;
    for (pending_read& r : m_pending_reads)
    {
        if (r.round > round)
            break;
        if (std::find(r.acks.begin(), r.acks.end(), from) == r.acks.end())
            r.acks.push_back(from);
    }
    release_reads();
}

void node::release_reads()
{
    while (!m_pending_reads.empty())
    {
        const pending_read& r = m_pending_reads.front();
        const size_t n = static_cast<size_t>(std::count_if(r.acks.begin(), r.acks.end(),
            [this](node_id id) { return is_voter(id); }));
        if (n < quorum())
            return;
        release_read(r);
        m_pending_reads.pop_front();
    }
}

void node::release_read(const pending_read& r)
{
    if (r.from == m_opts.id)
    {
        m_reads.push_back(read_state{r.request, r.index});
        return;
    }
    message m = make(msg_type::read_index_resp, r.from);
    m.context = r.request;
    m.index   = r.index;
    send(std::move(m));
}

// ─── compaction ───

bool node::compact(index_t index, std::string data)
{
    if (index <= m_snap->index || index > m_applied)
        return false;

    auto s = std::make_shared<snapshot>();
    s->index  = index;
    s->term   = *term_at(index);
    s->voters = voters_at(index);
    s->data   = std::move(data);

    while (!m_log.empty() && m_log.front().index <= index)
        m_log.pop_front();
    m_snap          = std::move(s);
    m_snap_dirty    = true;
    m_unstable_from = std::max(m_unstable_from, index + 1);
    return true;
}

// ─── output ───

bool node::has_ready() const
{
    const hard_state hs{m_term, RAFT_FAULT(fault_forget_vote) ? no_node : m_vote};
    return hs != m_last_hard
        || m_snap_dirty
        || m_truncate_from != 0
        || m_unstable_from <= last_index()
        || !m_msgs.empty()
        || m_pending_restore
        || m_commit > m_applied
        || !m_reads.empty()
        || soft_state{m_role, m_leader, m_term} != m_last_soft;
}

ready node::take_ready()
{
    ready r;

    hard_state hs{m_term, RAFT_FAULT(fault_forget_vote) ? no_node : m_vote};
    if (hs != m_last_hard)
    {
        r.hard      = hs;
        m_last_hard = hs;
    }

    if (m_snap_dirty)
    {
        r.snap       = m_snap;
        m_snap_dirty = false;
    }

    r.truncate_from = m_truncate_from;
    m_truncate_from = 0;
    for (index_t i = m_unstable_from; i <= last_index(); ++i)
        r.append.push_back(*entry_at(i));
    m_unstable_from = last_index() + 1;

    r.messages = std::move(m_msgs);
    m_msgs.clear();

    r.restore = std::move(m_pending_restore);
    m_pending_restore.reset();
    for (index_t i = m_applied + 1; i <= m_commit; ++i)
    {
        const entry* e = entry_at(i);
        if (!e)
            break;
        r.committed.push_back(*e);
        m_applied = i;
    }

    r.reads = std::move(m_reads);
    m_reads.clear();

    const soft_state ss{m_role, m_leader, m_term};
    if (ss != m_last_soft)
    {
        r.soft      = ss;
        m_last_soft = ss;
    }
    return r;
}

}   // namespace socketley::raft
