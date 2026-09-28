#pragma once
// Brings the replicas this node holds in line with what the cluster's log says it should run, through the same verbs an operator types.
#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "../shared/cluster_brain.h"

class daemon_handler;
class raft_host;
class runtime_manager;

class cluster_reconciler
{
public:
    cluster_reconciler(daemon_handler& handler, runtime_manager& manager, raft_host& raft);

    // Once per Raft tick: creates and starts what this node owns and holds a lease for, stops what it cannot confirm, removes what it lost.
    void tick();

    struct row
    {
        std::string name;
        // running, stopped, waiting, failed or blocked.
        std::string state;
        std::string detail;
    };
    // One row for every replica this node is assigned, as the last tick left it.
    const std::vector<row>& report() const { return m_rows; }

private:
    using clock = std::chrono::steady_clock;

    void reconcile_one(const socketley::cluster::want::item& item, bool serving);
    void begin(const socketley::cluster::want::item& item);
    void fail(const std::string& name, const std::string& why);
    void note(const std::string& name, const char* state, const std::string& detail = {});
    std::vector<std::string> local_replicas() const;

    daemon_handler&  m_handler;
    runtime_manager& m_manager;
    raft_host&       m_raft;

    bool m_busy = false;
    std::vector<row> m_rows;
    // The type and flags each running replica was created from, so a spec that changed under it is recreated.
    std::map<std::string, std::string> m_made;
    std::map<std::string, clock::time_point> m_retry_at;
    std::map<std::string, std::string> m_error;
};
