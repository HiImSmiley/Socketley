#pragma once
// What socketley.cluster.* needs to answer, in a process that cannot run
// cluster discovery.
//
// ─── WHY THIS IS NOT "just push the runtime map" ────────────────────────────
//
// The four cluster bindings look like map reads and are not.  Each of them
// starts:
//
//     auto* cd = mgr->get_cluster_discovery();
//     if (!cd) return result;                  // an EMPTY TABLE
//
// and then reads three things off `cd` that no amount of local runtime map
// supplies: the local daemon's NAME, the address it advertises to the cluster,
// and get_all_daemons() — every remote daemon and every runtime on it.
//
// So handing a worker the runtime map and deleting the four refusals in the
// same commit would not make these calls work.  It would make them return an
// empty table, silently, which is precisely what a *successful* call returns on
// a daemon that is alone in its cluster.  That is the lie the refusals were
// added to prevent, reintroduced by the change that removed them.  This header
// exists so that cannot happen by accident: the bindings read a view, and while
// there is no view they stay refused.
//
// ─── WHY A SNAPSHOT AND NOT A cluster_discovery ─────────────────────────────
//
// The obvious shortcut is to build a cluster_discovery inside the worker and
// let the existing code run unchanged.  It is not available: a
// cluster_discovery publishes into the shared cluster directory and claims the
// node name there, and claim_is_ours() is what tells "me, restarted" from
// "somebody else with my name".  A worker doing that would be a second daemon
// as far as every other member is concerned.
//
// A worker is a reader, so it gets a reader's object: immutable once published,
// held by shared_ptr so a call that is mid-iteration keeps the view it started
// with rather than watching daemons appear underneath it.  Exactly the
// arrangement endpoint_table.h already uses, and for the same reason.
//
// ─── FRESHNESS ──────────────────────────────────────────────────────────────
//
// The daemon's own copy is a scan behind reality already — get_all_daemons()
// reads what the last sweep of the cluster directory found — so a view pushed
// on the same cadence is no staler than what a script in the daemon reads.
// That is the standard to meet and it is a reachable one.  What is NOT
// acceptable is publishing this only when local membership changes: a remote
// daemon joining or leaving moves none of the local map, and a view frozen at
// the worker's fork would report a cluster that no longer exists.
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// remote_daemon / remote_runtime.  Reused rather than redeclared: the daemon
// builds a view straight out of cluster_discovery::get_all_daemons(), and a
// second pair of structs with the same fields is a conversion nobody would keep
// correct.  If the include weight ever matters, the two structs move here and
// cluster_discovery.h includes this instead — they own no behaviour.
#include "cluster_discovery.h"

// ── One cluster event, with everything it needs already resolved ────────────
//
// on_cluster_join / on_cluster_leave / on_group_change.  The daemon observes
// them, and every runtime that wants one is somewhere else -- so the event has
// to travel, and what travels is the ANSWER rather than the question.
//
// on_group_change is handed a members list built from the local map plus every
// remote daemon's runtimes.  A worker could rebuild that from its own view and
// its replica map; that version is deliberately not written, because two
// derivations of one list are two things to keep level and the worker's two
// inputs are each stale in a different way.  The daemon resolves it once, and a
// script in a worker is then handed the same table a script in the daemon is,
// by construction rather than by agreement.
//
// Here rather than in worker_protocol.h because both sides need it and only one
// of them is a wire: lua_context runs the callbacks off this struct whether it
// arrived over a socket or was built one function away.
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

// One process's read-only answer to "what does the cluster look like".
//
// Built by the daemon, which has a cluster_discovery; used by a worker, which
// cannot have one.  The daemon reads its own cluster_discovery directly and
// never needs this — the bindings take whichever source the process has.
struct cluster_view
{
    // cd->get_daemon_name() — the name this daemon publishes under.
    std::string daemon_name;

    // cd->get_cluster_addr() — the address it advertises.  Used as the `host`
    // of every LOCAL member, which is why it has to travel: a worker guessing
    // 127.0.0.1 here would hand a script an address no other node can reach.
    std::string host;

    // cd->get_all_daemons(), verbatim.  Remote members carry their own host.
    std::vector<remote_daemon> remote;
};

using cluster_view_ptr = std::shared_ptr<const cluster_view>;
