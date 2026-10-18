#pragma once
// Brings the replicas this node holds in line with what the cluster's log says it should run, through the same verbs an operator types.
#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "../shared/cluster/cluster_brain.h"

class daemon_handler;
class raft_host;
class runtime_manager;

class cluster_reconciler
{
public:
    cluster_reconciler(daemon_handler& handler, runtime_manager& manager, raft_host& raft);

    // Once per Raft tick: creates and starts what this node owns and holds a lease for, stops what it cannot confirm, removes what it lost.
    // It never waits for a worker and does at most a few commands a tick, so the Raft loop keeps its heartbeats however many replicas arrive or hang.
    void tick();

    // The most commands one tick runs; the rest are said to be queued and go on the next tick.
    static constexpr unsigned per_tick = 4;

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
    // Tells the worker of a cache replica what it is, with the lease this node has left as the time the word stands.
    void order(const socketley::cluster::want::item& item);
    // What each cache replica this node runs says about its copy, for the leader's next lease request.
    void report_replicas(const socketley::cluster::want& want);
    // Tells the proxies where each cache's primary is, when it has moved.
    void publish_primaries(const socketley::cluster::want& want);
    void fail(const std::string& name, const std::string& why);
    void note(const std::string& name, const char* state, const std::string& detail = {});
    bool spend();
    int  act(const std::vector<std::string>& words, std::string& out, bool cluster_owned);
    std::vector<std::string> local_replicas() const;

    daemon_handler&  m_handler;
    runtime_manager& m_manager;
    raft_host&       m_raft;

    bool m_busy = false;
    unsigned m_budget = 0;
    std::vector<row> m_rows;
    // The type and flags each running replica was created from, so a spec that changed under it is recreated.
    std::map<std::string, std::string> m_made;
    // Which incarnation of each cache replica this node made, a new number every time the process is made again.
    std::map<std::string, uint64_t> m_incarnation;
    std::map<std::string, std::pair<std::string, uint16_t>> m_published;
    std::map<std::string, clock::time_point> m_retry_at;
    std::map<std::string, std::string> m_error;
};
