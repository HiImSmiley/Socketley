#pragma once
// What socketley.cluster.* needs to answer in a process that cannot run
// cluster discovery, as a reader's snapshot rather than a second
// cluster_discovery, which would claim the node name and read as a second
// daemon.
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// remote_daemon / remote_runtime, reused rather than redeclared because the
// daemon builds a view straight out of cluster_discovery::get_all_daemons().
#include "cluster_discovery.h"

// One cluster event with its members already resolved by the daemon, so a
// script in a worker is handed the same table a script in the daemon is, by
// construction rather than by agreement.
struct cluster_ev_member
{
    std::string daemon;
    std::string host;
    uint16_t    port{0};
};

struct cluster_ev_wire
{
    uint8_t     kind{0};        // cluster_event::type_t
    std::string daemon_name;    // join / leave
    std::string host;           // join
    std::string group_name;     // group_change
    std::vector<cluster_ev_member> members;   // group_change
};

// One process's read-only answer to what the cluster looks like, built by the
// daemon for a worker, which cannot have a cluster_discovery of its own.
struct cluster_view
{
    // cd->get_daemon_name() — the name this daemon publishes under.
    std::string daemon_name;

    // The address the daemon advertises, used as the `host` of every local
    // member, which is why it has to travel.
    std::string host;

    // cd->get_all_daemons(), verbatim.  Remote members carry their own host.
    std::vector<remote_daemon> remote;
};

using cluster_view_ptr = std::shared_ptr<const cluster_view>;
