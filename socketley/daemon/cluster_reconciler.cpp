#include "cluster_reconciler.h"

#include "daemon_handler.h"
#include "raft_host.h"
#include "../shared/util/logging.h"
#include "../shared/util/random_id.h"
#include "../shared/cluster/replica_role.h"
#include "../shared/runtime/runtime_manager.h"

#include <algorithm>
#include <set>
#include <shared_mutex>

namespace cl = socketley::cluster;

namespace {

// A failed start is tried again after this, so a port that is still held or a file that is not there yet does not become a spin.
constexpr std::chrono::seconds retry_after{3};

std::string first_line(const std::string& text)
{
    const size_t end = text.find('\n');
    return text.substr(0, end);
}

std::string signature(const cl::want::item& item)
{
    std::string s = item.type;
    for (const std::string& a : item.args)
        s += '\x1f' + a;
    return s;
}

}   // namespace

cluster_reconciler::cluster_reconciler(daemon_handler& handler, runtime_manager& manager, raft_host& raft)
    : m_handler(handler), m_manager(manager), m_raft(raft)
{
}

std::vector<std::string> cluster_reconciler::local_replicas() const
{
    std::vector<std::string> out;
    std::shared_lock lock(m_manager.mutex);
    for (const auto& [name, instance] : m_manager.list())
        if (instance->is_cluster_owned())
            out.push_back(name);
    return out;
}

bool cluster_reconciler::spend()
{
    if (m_budget == 0)
        return false;
    --m_budget;
    return true;
}

int cluster_reconciler::act(const std::vector<std::string>& words, std::string& out, bool cluster_owned)
{
    return m_handler.run_internal(words, out, cluster_owned);
}

void cluster_reconciler::note(const std::string& name, const char* state, const std::string& detail)
{
    m_rows.push_back(row{name, state, detail});
}

void cluster_reconciler::fail(const std::string& name, const std::string& why)
{
    // Said once per distinct reason, so a replica that cannot start does not fill the log every retry.
    if (m_error[name] != why)
        LOG_WARN(("cluster: replica " + name + " could not start: " + why).c_str());
    m_error[name]    = why;
    m_retry_at[name] = clock::now() + retry_after;
    // A half-made runtime is removed, so the next try starts from nothing.
    std::string out;
    if (m_manager.get(name))
        act({"remove", name}, out, false);
    m_made.erase(name);
    m_incarnation.erase(name);
}

void cluster_reconciler::begin(const cl::want::item& item)
{
    std::string out;
    std::vector<std::string> words = {"create", item.type, item.name};
    words.insert(words.end(), item.args.begin(), item.args.end());
    // A cache replica is a process the log can name, so it is numbered as it is made, and starts fenced.
    const uint64_t incarnation = item.cache ? socketley::random_u64() : 0;
    if (item.cache)
    {
        words.push_back("--cluster-replica");
        words.push_back(std::to_string(incarnation));
    }
    words.push_back("-s");
    if (act(words, out, true) != 0)
        return fail(item.name, first_line(out).empty() ? "the create was refused" : first_line(out));
    if (item.cache)
        m_incarnation[item.name] = incarnation;
    m_made[item.name] = signature(item);
    m_error.erase(item.name);
    m_retry_at.erase(item.name);
    LOG_INFO(("cluster: started replica " + item.name).c_str());
    note(item.name, "running");
}

void cluster_reconciler::reconcile_one(const cl::want::item& item, bool serving)
{
    runtime_instance* inst = m_manager.get(item.name);
    const auto retry = m_retry_at.find(item.name);
    const bool waiting = retry != m_retry_at.end() && clock::now() < retry->second;

    if (!inst)
    {
        if (!serving)
            return note(item.name, "waiting", "no lease: this node cannot confirm it still owns the replica");
        if (waiting)
            return note(item.name, "failed", m_error[item.name]);
        if (!spend())
            return note(item.name, "waiting", "queued: this node is starting other replicas first");
        begin(item);
        if (m_error.count(item.name))
            note(item.name, "failed", m_error[item.name]);
        return;
    }

    if (!inst->is_cluster_owned())
        return note(item.name, "blocked", "a local runtime of this name exists on this node");

    // A cache holds data, so a lapsed lease fences it and does not stop it: what it holds is the copy the cluster may
    // need, and the daemon's order (or its silence) is what decides whether the worker answers anybody.
    if (item.cache && inst->get_state() == runtime_running)
    {
        order(item);
        return note(item.name, "running", std::string(cl::mode_name(!serving ? cl::replica_mode::fenced : item.role))
                    + (item.role == cl::replica_mode::fenced && serving ? ": the cluster has not named a primary yet" : "")
                    + (!serving ? ": no lease, so it answers nobody" : ""));
    }

    if (!serving && !item.cache)
    {
        if (inst->get_state() == runtime_running)
        {
            // Not budgeted: a lapsed lease must stop what it fences at once, and a stop returns as soon as the worker is signalled.
            std::string out;
            if (act({"stop", item.name}, out, false) == 0)
                LOG_INFO(("cluster: stopped replica " + item.name + ", no lease").c_str());
            else
                LOG_ERROR(("cluster: replica " + item.name + " has no lease and could not be stopped: " + out).c_str());
        }
        return note(item.name, "waiting", "no lease: this node cannot confirm it still owns the replica");
    }

    if (inst->get_state() == runtime_running)
        return note(item.name, "running");

    if (waiting)
        return note(item.name, "failed", m_error[item.name]);

    // A replica stopped for want of a lease comes back through `start`, and one that failed is made again from nothing.
    if (inst->get_state() == runtime_stopped && !item.cache)
    {
        if (!spend())
            return note(item.name, "waiting", "queued: this node is starting other replicas first");
        std::string out;
        if (act({"start", item.name}, out, false) == 0)
        {
            LOG_INFO(("cluster: restarted replica " + item.name).c_str());
            return note(item.name, "running");
        }
        fail(item.name, first_line(out).empty() ? "the start was refused" : first_line(out));
        return note(item.name, "failed", m_error[item.name]);
    }
    fail(item.name, inst->get_state() == runtime_failed ? "the worker did not come up (the daemon log says why)" : "the runtime is not running");
    note(item.name, "failed", m_error[item.name]);
}

void cluster_reconciler::order(const cl::want::item& item)
{
    auto inc = m_incarnation.find(item.name);
    if (inc == m_incarnation.end())
        return;
    cl::replica_order o;
    o.incarnation = inc->second;
    o.epoch       = item.epoch;
    // The lease is read as the word is sent and not when the tick began, since a tick that created other replicas first has spent some of it.
    const uint64_t left = m_raft.lease_left_ms();
    o.valid_ms = static_cast<uint32_t>(std::min<uint64_t>(left, 0xFFFFFFFFull));
    if (left != 0 && item.role == cl::replica_mode::primary)
        o.mode = cl::replica_mode::primary;
    else if (left != 0 && item.role == cl::replica_mode::follower && !item.target.empty())
    {
        o.mode   = cl::replica_mode::follower;
        o.target = item.target;
    }
    if (!m_handler.send_replica_order(item.name, cl::encode(o)))
        LOG_WARN(("cluster: the worker of replica " + item.name + " could not be told its part").c_str());
}

void cluster_reconciler::report_replicas(const cl::want& want)
{
    std::vector<cl::replica_report> reports;
    for (const cl::want::item& item : want.owned)
    {
        auto inc = m_incarnation.find(item.name);
        runtime_instance* inst = m_manager.get(item.name);
        if (!item.cache || inc == m_incarnation.end() || !inst || !inst->is_cluster_owned() || inst->get_state() != runtime_running)
            continue;
        // A worker that has not published yet has said nothing about a copy, which is an empty one; and what a worker
        // published before it was made again belongs to another incarnation.
        cl::replica_report rep{item.name, inc->second, 0, 0, false};
        if (auto seen = cl::parse_report(m_handler.worker_detail(item.name), item.name); seen && seen->incarnation == inc->second)
            rep = *seen;
        reports.push_back(std::move(rep));
    }
    m_raft.set_replica_reports(std::move(reports));
}

void cluster_reconciler::publish_primaries(const cl::want& want)
{
    // Only a node that may serve says where the primaries are, since one that holds no lease may be looking at a state that has moved on.
    auto now = want.serving ? m_raft.primary_endpoints() : std::map<std::string, std::pair<std::string, uint16_t>>{};
    if (now == m_published)
        return;
    m_published = now;
    m_manager.set_cluster_primaries(std::move(now));
}

void cluster_reconciler::tick()
{
    if (m_busy)
        return;
    m_busy   = true;
    m_budget = per_tick;

    const cl::want want = m_raft.desired();
    std::map<std::string, const cl::want::item*> owned;
    for (const cl::want::item& item : want.owned)
        owned[item.name] = &item;

    // What this node no longer owns, or owns under another spec, goes first so its port is free for what replaces it.
    for (const std::string& name : local_replicas())
    {
        auto it = owned.find(name);
        if (it != owned.end() && (!m_made.count(name) || m_made[name] == signature(*it->second)))
            continue;
        // A removal is only budgeted to keep one tick short: the port it frees is what the next replica waits for.
        if (!spend())
            continue;
        std::string out;
        // Forgotten only when gone, or the next tick would not know to try again.
        if (act({"remove", name}, out, false) != 0)
        {
            LOG_ERROR(("cluster: replica " + name + " is no longer this node's and could not be removed: " + out).c_str());
            continue;
        }
        m_made.erase(name);
        m_incarnation.erase(name);
        m_retry_at.erase(name);
        m_error.erase(name);
        LOG_INFO(("cluster: removed replica " + name + ", this node no longer owns it").c_str());
    }
    for (auto it = m_error.begin(); it != m_error.end();)
        it = owned.count(it->first) ? std::next(it) : m_error.erase(it);
    for (auto it = m_retry_at.begin(); it != m_retry_at.end();)
        it = owned.count(it->first) ? std::next(it) : m_retry_at.erase(it);

    m_rows.clear();
    for (const cl::want::item& item : want.owned)
        reconcile_one(item, want.serving);
    report_replicas(want);
    publish_primaries(want);
    m_busy = false;
}
