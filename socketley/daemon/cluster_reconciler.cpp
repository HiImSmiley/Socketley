#include "cluster_reconciler.h"

#include "daemon_handler.h"
#include "raft_host.h"
#include "../shared/logging.h"
#include "../shared/runtime_manager.h"

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
    return item.type + " " + item.args;
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
        m_handler.run_internal("remove " + name, out, false);
    m_made.erase(name);
}

void cluster_reconciler::begin(const cl::want::item& item)
{
    std::string out;
    const std::string line = "create " + item.type + " " + item.name + (item.args.empty() ? "" : " " + item.args) + " -s";
    if (m_handler.run_internal(line, out, true) != 0)
        return fail(item.name, first_line(out).empty() ? "the create was refused" : first_line(out));
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
        begin(item);
        if (m_error.count(item.name))
            note(item.name, "failed", m_error[item.name]);
        return;
    }

    if (!inst->is_cluster_owned())
        return note(item.name, "blocked", "a local runtime of this name exists on this node");

    if (!serving)
    {
        if (inst->get_state() == runtime_running)
        {
            std::string out;
            m_handler.run_internal("stop " + item.name, out, false);
            LOG_INFO(("cluster: stopped replica " + item.name + ", no lease").c_str());
        }
        return note(item.name, "waiting", "no lease: this node cannot confirm it still owns the replica");
    }

    if (inst->get_state() == runtime_running)
        return note(item.name, "running");

    if (waiting)
        return note(item.name, "failed", m_error[item.name]);

    // A replica stopped for want of a lease comes back through `start`, and one that failed is made again from nothing.
    if (inst->get_state() == runtime_stopped)
    {
        std::string out;
        if (m_handler.run_internal("start " + item.name, out, false) == 0)
        {
            LOG_INFO(("cluster: restarted replica " + item.name).c_str());
            return note(item.name, "running");
        }
        fail(item.name, first_line(out).empty() ? "the start was refused" : first_line(out));
        return note(item.name, "failed", m_error[item.name]);
    }
    fail(item.name, "the runtime is " + std::string(inst->get_state() == runtime_failed ? "failed" : "not running"));
    note(item.name, "failed", m_error[item.name]);
}

void cluster_reconciler::tick()
{
    if (m_busy)
        return;
    m_busy = true;

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
        std::string out;
        m_handler.run_internal("remove " + name, out, false);
        m_made.erase(name);
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
    m_busy = false;
}
