#include "runtime_manager.h"
#include "route_relay.h"
#include <algorithm>
#include "runtime_factory.h"
#include "event_loop.h"
#include "cluster_discovery.h"
#include "lua_context.h"
#include "route_table.h"
#include "logging.h"
#include <cctype>
#include <map>
#include <mutex>
#include <shared_mutex>

namespace
{

// A replica is the base class plus a type tag, file-local so nothing can reach
// past runtime_instance's interface into it, because building one out of the
// real type would cost megabytes of fd-indexed tables per proxy per worker.
class replica_instance final : public runtime_instance
{
public:
    replica_instance(runtime_type type, std::string_view name)
        : runtime_instance(type, name)
    {
        // Every read that distinguishes a runtime elsewhere from one here goes
        // through this flag, and a replica is out of process by definition.
        mark_out_of_process();
    }

    void on_cqe(struct io_uring_cqe*) override {}
    bool setup(event_loop&) override { return false; }
    void teardown(event_loop&) override {}
};

} // namespace

void runtime_manager::mark_replica()
{
    m_replica = true;
}

void runtime_manager::replica_note(std::string_view op, std::string_view name,
                                   const replica_entry& e)
{
    // Only a replica has one of these to correct, since a daemon calling this
    // would write over the authority with a copy of itself.
    if (!m_replica)
        return;

    std::unique_ptr<runtime_instance> dropped;
    {
        std::unique_lock lock(mutex);
        auto it = runtimes.find(name);

        if (op == "remove")
        {
            if (it == runtimes.end())
                return;
            // Out of the map and not destroyed, because a script is mid-frame
            // and entitled to hold the pointer get() handed it one statement
            // ago.
            dropped = std::move(it->second);
            runtimes.erase(it);
        }
        else if (op == "create")
        {
            if (it == runtimes.end())
                it = runtimes.emplace(
                    std::string(name),
                    std::make_unique<replica_instance>(e.type, name)).first;
            runtime_instance* inst = it->second.get();
            inst->set_port(e.port);
            inst->set_owner(e.owner);
            inst->set_group(e.group);
            inst->set_replicated_state(e.state);
        }
        else
        {
            // start / stop, where the row must already exist and only its
            // state moved, because inventing a row would be this process
            // having an opinion rather than a copy.
            if (it == runtimes.end())
                return;
            it->second->set_replicated_state(e.state);
        }
    }

    if (dropped)
        retire(std::move(dropped));
}

void runtime_manager::install_replica(const std::vector<replica_entry>& entries)
{
    // Never under a script frame, because a replica the snapshot has dropped
    // is freed below and a callback may be holding the pointer get() handed
    // it.
    if (script_frame_live())
        return;

    // Freed with the lock released, like every other instance destruction
    // here, and for a replica that is a deallocation and nothing more.
    std::vector<std::unique_ptr<runtime_instance>> dropped;
    {
        std::unique_lock lock(mutex);

        for (const auto& e : entries)
        {
            auto it = runtimes.find(e.name);

            // A type change under one name means the daemon replaced the
            // runtime between two pushes, so the object is rebuilt rather than
            // re-tagged, get_type() being fixed at construction.
            if (it != runtimes.end() && it->second->get_type() != e.type)
            {
                dropped.push_back(std::move(it->second));
                runtimes.erase(it);
                it = runtimes.end();
            }

            if (it == runtimes.end())
            {
                auto inst = std::make_unique<replica_instance>(e.type, e.name);
                it = runtimes.emplace(e.name, std::move(inst)).first;
            }

            // Updated in place so a pointer from get() still names this
            // object, with the state stored straight rather than through
            // start()/stop(), which are transitions this process is not
            // making.
            runtime_instance* inst = it->second.get();
            inst->set_port(e.port);
            inst->set_owner(e.owner);
            inst->set_group(e.group);
            inst->set_replicated_state(e.state);

            // The same two fields the daemon writes into its placeholder from
            // a stats frame, with the detail text empty because a replica has
            // none.
            inst->set_worker_stats({}, e.connections);
        }

        // Whatever the daemon no longer has, collected first because erasing
        // from a map while walking it is what this loop must not get wrong.
        for (auto it = runtimes.begin(); it != runtimes.end();)
        {
            const bool still_there =
                std::any_of(entries.begin(), entries.end(),
                            [&](const replica_entry& e) { return e.name == it->first; });
            if (still_there)
            {
                ++it;
                continue;
            }
            dropped.push_back(std::move(it->second));
            it = runtimes.erase(it);
        }
    }

    dropped.clear();
}

// One place that decides what a runtime may be called, because a name reaches
// the filesystem, a JSON document, a command line and a cluster file, and this
// character set is what all four carry without escaping.
bool runtime_manager::valid_name(std::string_view name)
{
    // A leading '-' is refused because the CLI can never address it again:
    // `create client --help` made a runtime that could not be removed.
    if (name.empty() || name.size() > 128 || name[0] == '.' || name[0] == '-')
        return false;

    // And '..' anywhere, because state_persistence::config_path() already
    // refuses it -- by answering an empty path, silently.  So a name like
    // `a..b` passed this door, ran, and was never written down: it disappeared
    // at the next daemon start with nothing having said no.  The two rules
    // belong at one door, and this is the one that can still answer the
    // operator.
    if (name.find("..") != std::string_view::npos)
        return false;
    for (char c : name)
    {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.')
            return false;
    }
    return true;
}

runtime_manager::create_result
runtime_manager::try_create(runtime_type type, std::string_view name)
{
    // A replica's map is read-only, enforced in try_create rather than the
    // create() wrapper, so no caller can walk around it -- a runtime built
    // here would exist in this worker alone and vanish at the next snapshot.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::create in a worker process: the map here is a "
                 "replica of the daemon's and cannot be written; nothing created");
        return create_result::internal;
    }

    std::unique_lock lock(mutex);

    if (!valid_name(name))
        return create_result::invalid_name;

    if (runtimes.find(name) != runtimes.end())
        return create_result::name_taken;

    auto instance = create_runtime(type, name);
    if (!instance)
        return create_result::internal;

    runtimes.emplace(std::string(name), std::move(instance));
    lock.unlock();

    // A name that can be routed to exists now, even if it has no port yet.
    publish_endpoints();
    return create_result::ok;
}

bool runtime_manager::start(std::string_view name, event_loop& loop)
{
    // See create(): starting a replica would move a copy's state and bind
    // nothing anywhere.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::start in a worker process: the map here is a "
                 "replica of the daemon's; nothing started");
        return false;
    }

    // Before, because a proxy resolves its backends inside setup(): the table
    // has to be in its hands by the time start() below reaches that code.
    publish_endpoints();

    // The lock covers the lookup and stops there, because start() runs
    // on_start, which may call back into this manager for the same
    // non-recursive shared_mutex and deadlock the one event-loop thread
    // against itself.
    runtime_instance* inst = nullptr;
    {
        std::shared_lock lock(mutex);

        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return false;

        inst = it->second.get();
    }

    const bool started = inst->start(loop);

    // And after, because this runtime is now a member others may route to.
    if (started)
        publish_endpoints();

    return started;
}

// Ownership is a directed graph that nothing validates, so every cascade
// carries the set of names it has descended into -- threaded through rather
// than a member, because a script's on_stop may start a second cascade inside
// the first.
bool runtime_manager::stop(std::string_view name, event_loop& loop)
{
    // See create().
    if (m_replica)
    {
        LOG_WARN("runtime_manager::stop in a worker process: the map here is a "
                 "replica of the daemon's; nothing stopped");
        return false;
    }

    cascade_seen seen;
    return stop_cascading(name, loop, seen);
}

bool runtime_manager::stop_cascading(std::string_view name, event_loop& loop,
                                     cascade_seen& seen)
{
    // The same shape as start(), for the same reason and with the same
    // reasoning: stop() runs the script's on_stop, which may call back in here.
    runtime_instance* inst = nullptr;
    {
        std::shared_lock lock(mutex);
        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return false;
        inst = it->second.get();
    }
    if (!inst->stop(loop))
        return false;

    // Every runtime that had a connection routed to or from this one has to
    // let go, done here because in another process the departing runtime's own
    // frames never arrive.
    route_relay::forget(this, name);

    // Marked before descending, and the answer is what decides whether to
    // descend at all: a name already on this path has had its children walked
    // by the frame that put it there.
    if (!seen.insert(std::string(name)).second)
    {
        publish_endpoints();
        return true;
    }

    // Cascade to children based on child_policy
    auto children = get_children(name);
    for (const auto& child : children)
    {
        if (seen.count(child))
            continue;

        auto* child_inst = get(child);
        if (!child_inst) continue;

        if (child_inst->get_child_policy() == runtime_instance::child_policy::remove)
            remove_children_cascading(child, loop, seen);
        else
            stop_children_cascading(child, loop, seen);

        // Re-resolved: the walk above ran on_stop for a whole subtree, and a
        // script there is entitled to have removed this child.
        child_inst = get(child);
        if (!child_inst) continue;

        if (child_inst->get_child_policy() == runtime_instance::child_policy::remove)
        {
            if (child_inst->get_state() == runtime_running)
                stop_cascading(child, loop, seen);
            remove(child);
        }
        else
        {
            if (child_inst->get_state() == runtime_running)
                stop_cascading(child, loop, seen);
        }
    }

    // This runtime is no longer a routable group member, nor are any children
    // that went down with it, and one publish covers the lot.
    publish_endpoints();
    return true;
}

// Removal never destroys, because an instance is the storage for its own
// io_requests and io_uring keeps whatever addresses it was handed; the
// instance leaves the map and is freed once the loop reports nothing of its is
// still in the ring.
void runtime_manager::retire(std::unique_ptr<runtime_instance> inst)
{
    if (!inst)
        return;

    // An instance that never reached setup() put no io_request in the ring,
    // which covers create-then-reject-a-flag and external runtimes, which must
    // keep being dropped untouched.
    // ─── The ring is not the only holder ───────────────────────────────────
    // The C++ stack is the other holder: a script's top level removing its own
    // runtime stands on frames inside the lua_context this return would
    // destroy, so the free is deferred one health tick.
    if (!inst->has_armed_io() && !script_frame_live())
        return;

    // A backstop rather than a path, because retiring a still-armed runtime
    // would leave one nobody can see or name still serving traffic; done with
    // the map lock released, since on_stop may run Lua.
    if (inst->get_state() == runtime_running)
    {
        if (event_loop* loop = inst->get_event_loop())
            inst->stop(*loop);
        else
            LOG_WARN("removed a running runtime that has no event loop: "
                     "its fds stay open until the daemon exits");
    }

    // Read before the instance is handed on: this is the loop that can say when
    // the graveyard's older residents are finished with.
    event_loop* reap_loop = inst->get_event_loop();

    size_t retired = 0;
    {
        std::unique_lock lock(mutex);
        m_retired.push_back(std::move(inst));
        if (m_retired.size() >= m_retired_warn_at)
        {
            retired = m_retired.size();
            m_retired_warn_at = retired * 2;
        }
    }

    // Clear out whatever the ring has finished with, which can never reach the
    // instance being retired right now, so the daemon's periodic timer reaps
    // as well.
    if (reap_loop)
        retired -= std::min(retired, reap_retired(*reap_loop));

    // The warning below says nothing until 32 instances are waiting, and a
    // graveyard far below that already costs whole runtimes, so the size is
    // readable here with debug logging on.
    if (logger::g_level <= log_debug)
    {
        std::string waiting = "retired runtime instances waiting: "
                            + std::to_string(retired_count());
        LOG_DEBUG(waiting.c_str());
    }

    if (retired > 0)
    {
        std::string msg = "retired runtime instances the ring has not finished with: "
                        + std::to_string(retired);
        LOG_WARN(msg.c_str());
    }
}

// Conservative on purpose: it says a callback is running somewhere on this
// thread, because the narrow question cannot be asked and the broad answer
// costs one health tick of deferral.
bool runtime_manager::script_frame_live()
{
#ifndef SOCKETLEY_NO_LUA
    return lua_deadline::in_callback();
#else
    // No interpreter in this build, so no callback can be on the stack and
    // nothing can reach remove() from inside one.
    return false;
#endif
}

void runtime_manager::enable_offthread_stats()
{
    m_offthread_stats.store(true, std::memory_order_relaxed);
}

void runtime_manager::publish_offthread_stats()
{
    if (!m_offthread_stats.load(std::memory_order_relaxed))
        return;

    // A shared lock and never an exclusive one, because everything that
    // mutates the map runs on this thread and an exclusive lock would make it
    // wait on a reader.
    std::shared_lock lock(mutex);
    for (auto& [name, instance] : runtimes)
        instance->publish_offthread_stats();
}

size_t runtime_manager::reap_retired(const event_loop& loop)
{
    // Hung off the health timer, which is the only fixed-period call the
    // manager gets on the event-loop thread, and before the graveyard lock
    // because shared_mutex does not nest.
    publish_offthread_stats();

    if (loop.owner_table_full())
        return 0;

    // Not from inside a callback, because retire() reaches here from
    // socketley.remove -- though no case has been built where this half fires,
    // since inflight only falls when the loop dispatches and it does not
    // dispatch under a Lua frame.
    if (script_frame_live())
        return 0;

    std::vector<std::unique_ptr<runtime_instance>> doomed;
    {
        std::unique_lock lock(mutex);
        for (auto it = m_retired.begin(); it != m_retired.end(); )
        {
#ifdef SOCKETLEY_INVARIANTS
            // What this number is doing is the whole question when a graveyard
            // stops draining: anything but zero means the ring still owes this
            // instance a completion, and it cannot be freed until that lands.
            if (*it)
            {
                uint32_t by_type[op_type_count];
                loop.owner_inflight_breakdown(it->get(), by_type);
                std::string dbg = "reap: instance still owes the ring "
                                + std::to_string(loop.owner_inflight(it->get()))
                                + " completion(s):";
                for (uint8_t t = 0; t < op_type_count; ++t)
                    if (by_type[t])
                        dbg += " " + std::string(io_op_name(t)) + "=" + std::to_string(by_type[t]);
                LOG_DEBUG(dbg.c_str());
            }
#endif
            if (*it && loop.owner_inflight(it->get()) == 0)
            {
                doomed.push_back(std::move(*it));
                it = m_retired.erase(it);
            }
            else
            {
                ++it;
            }
        }
        // Let the warning threshold fall again, or a graveyard that grew once
        // would stay silent through every later growth up to that mark.
        if (m_retired.size() * 2 < m_retired_warn_at)
            m_retired_warn_at = std::max<size_t>(32, m_retired.size() * 2);
    }

    // Destructors out here: a runtime unwinding through Lua can reach back into
    // the manager, and this mutex does not nest.
    size_t freed = doomed.size();
    doomed.clear();
    return freed;
}

bool runtime_manager::remove(std::string_view name)
{
    // See create(): removing a replica takes the copy out of this worker's map
    // and leaves the runtime running in the daemon until the next snapshot
    // puts it back.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::remove in a worker process: the map here is a "
                 "replica of the daemon's; nothing removed");
        return false;
    }

    std::unique_ptr<runtime_instance> inst;
    {
        std::unique_lock lock(mutex);

        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return false;

        inst = std::move(it->second);
        runtimes.erase(it);
    }

    retire(std::move(inst));

    // See stop_cascading(): removal reaches here for a runtime that was never
    // started as well as one just stopped, and forget_runtime finds nothing
    // either way.
    route_relay::forget(this, name);

    // The name is free and the endpoint is gone; a proxy still routing to it
    // would otherwise keep the old port until the next membership change.
    publish_endpoints();
    return true;
}

void runtime_manager::free_retired()
{
    std::vector<std::unique_ptr<runtime_instance>> doomed;
    {
        std::unique_lock lock(mutex);
        doomed.swap(m_retired);
    }

    // The destructors run out here, with the map lock released: a runtime that
    // unwinds through Lua can reach back into the manager, and this mutex does
    // not nest.
    doomed.clear();
}

size_t runtime_manager::retired_count() const
{
    std::shared_lock lock(mutex);
    return m_retired.size();
}

bool runtime_manager::rename(std::string_view old_name, std::string_view new_name)
{
    // See create(): nothing in the Lua API renames, so this is the guard for a
    // call site that does not exist yet.
    if (m_replica)
    {
        LOG_WARN("runtime_manager::rename in a worker process: the map here is a "
                 "replica of the daemon's; nothing renamed");
        return false;
    }

    std::unique_lock lock(mutex);

    // The same rule create() enforces, on the door `import` comes through.
    if (!valid_name(new_name))
        return false;

    auto it = runtimes.find(old_name);
    if (it == runtimes.end())
        return false;

    if (runtimes.find(new_name) != runtimes.end())
        return false;

    auto instance = std::move(it->second);
    runtimes.erase(it);
    instance->set_name(new_name);
    runtimes.emplace(std::string(new_name), std::move(instance));
    lock.unlock();

    publish_endpoints();
    return true;
}

std::vector<std::string> runtime_manager::get_children(std::string_view parent_name) const
{
    std::shared_lock lock(mutex);
    std::vector<std::string> children;
    for (const auto& [name, instance] : runtimes)
    {
        if (instance->get_owner() == parent_name)
            children.push_back(name);
    }
    return children;
}

// The public spellings start a fresh walk, each carrying the set of names it
// has already descended into.
void runtime_manager::stop_children(std::string_view parent_name, event_loop& loop)
{
    cascade_seen seen;
    seen.insert(std::string(parent_name));
    stop_children_cascading(parent_name, loop, seen);
}

void runtime_manager::remove_children(std::string_view parent_name, event_loop& loop)
{
    cascade_seen seen;
    seen.insert(std::string(parent_name));
    remove_children_cascading(parent_name, loop, seen);
}

void runtime_manager::stop_children_cascading(std::string_view parent_name,
                                              event_loop& loop, cascade_seen& seen)
{
    auto children = get_children(parent_name);
    for (const auto& child : children)
    {
        // Marked on the way in, or a child that owns its own parent sends the
        // next line straight back here with the same argument.
        if (!seen.insert(child).second)
            continue;

        // Recurse: stop grandchildren first
        stop_children_cascading(child, loop, seen);
        stop_cascading(child, loop, seen);
    }
}

void runtime_manager::remove_children_cascading(std::string_view parent_name,
                                                event_loop& loop, cascade_seen& seen)
{
    auto children = get_children(parent_name);
    for (const auto& child : children)
    {
        if (!seen.insert(child).second)
            continue;

        // Recurse: remove grandchildren first
        remove_children_cascading(child, loop, seen);
        auto* inst = get(child);
        if (inst && inst->get_state() == runtime_running)
            stop_cascading(child, loop, seen);
        remove(child);
    }
}

void runtime_manager::stop_all(event_loop& loop)
{
    // Names rather than pointers, with the lock released before any of them is
    // stopped, because on_stop may create or remove and a pointer collected
    // beforehand could name an instance already gone.
    std::vector<std::string> names;
    {
        std::unique_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [name, instance] : runtimes)
            if (instance->get_state() == runtime_running)
                names.emplace_back(name);
    }

    for (const auto& name : names)
    {
        auto* inst = get(name);
        if (inst && inst->get_state() == runtime_running)
            inst->stop(loop);
    }
}

void runtime_manager::dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message)
{
    // Names rather than pointers, re-resolved per delivery because
    // socketley.remove is bound in the very VM these callbacks run in, and
    // only runtimes that have a Lua VM are collected at all.
    if (m_publish_sink)
        m_publish_sink(cache_name, channel, message);

    // A runtime that lives in a worker process is skipped on purpose, because
    // the frame goes to the process serving the traffic and its subscribers
    // run there.
    // ─── And only a runtime that is running ─────────────────────────────────
    // A runtime that is not running executes no script, decided here at the
    // delivery rather than at the registration, because a top-level
    // socketley.subscribe is a live handler on a runtime `ls` reports as
    // Created.
    std::vector<std::string> names;
    {
        std::shared_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [n, inst] : runtimes)
        {
            if (inst->get_state() != runtime_running)
                continue;
            if (inst->lua() && !inst->is_out_of_process())
                names.push_back(n);
        }
    }

    for (const auto& n : names)
    {
        // Re-resolve and re-read the state, then drop the lock before the
        // callback runs, because one subscriber can stop or remove another in
        // the middle of this fan-out.
        runtime_instance* inst;
        {
            std::shared_lock lock(mutex);
            auto it = runtimes.find(n);
            if (it == runtimes.end()) continue;
            inst = it->second.get();
            if (inst->get_state() != runtime_running) continue;
        }

        inst->on_publish_dispatch(cache_name, channel, message);
    }
}

void runtime_manager::dispatch_cluster_events([[maybe_unused]] const std::vector<cluster_event>& events)
{
    // Republish before any Lua runs, so a callback that opens a connection
    // routes on the new membership rather than the one that just expired.
    publish_endpoints();

    // Snapshot names under the read lock and re-look-up each before invoking,
    // skipping a runtime a previous callback removed or stopped -- because a
    // runtime that is not running executes no script.
    std::vector<std::string> names;
    {
        std::shared_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [n, _] : runtimes)
            names.push_back(n);
    }

#ifndef SOCKETLEY_NO_LUA
    // ─── Resolved once, for every consumer ──────────────────────────────────
    // The members list is resolved here, once per event rather than once per
    // runtime, because neither this daemon's cluster_discovery nor its map is
    // available in a worker.
    std::vector<cluster_ev_wire> resolved;
    resolved.reserve(events.size());
    for (const auto& ev : events)
    {
        cluster_ev_wire w;
        w.kind        = static_cast<uint8_t>(ev.kind);
        w.daemon_name = ev.daemon_name;
        w.group_name  = ev.group_name;

        if (ev.kind == cluster_event::daemon_join && m_cluster)
        {
            for (const auto& rd : m_cluster->get_all_daemons())
                if (rd.name == ev.daemon_name) { w.host = rd.host; break; }
        }
        else if (ev.kind == cluster_event::group_change && m_cluster)
        {
            {
                std::shared_lock lock(mutex);
                for (const auto& [_, rinst] : runtimes)
                    if (rinst->get_group() == ev.group_name &&
                        rinst->get_state() == runtime_running &&
                        rinst->get_port() > 0)
                        w.members.push_back({std::string(m_cluster->get_daemon_name()),
                                             std::string(m_cluster->get_cluster_addr()),
                                             rinst->get_port()});
            }
            for (const auto& rd : m_cluster->get_all_daemons())
                for (const auto& rt : rd.runtimes)
                    if (rt.group == ev.group_name && rt.state == "running" &&
                        rt.port > 0)
                        w.members.push_back({rt.daemon_name, rt.host, rt.port});
        }
        resolved.push_back(std::move(w));
    }

    // Out of process first, and for the reason the publish sink gives one
    // screen up: a callback here may create or remove a runtime, and a frame
    // already written to a socket cannot be affected by what it does.
    if (m_cluster_event_sink)
        for (const auto& w : resolved)
            m_cluster_event_sink(w);

    for (auto& n : names)
    {
        runtime_instance* inst;
        {
            std::shared_lock lock(mutex);
            auto it = runtimes.find(n);
            if (it == runtimes.end()) continue;
            inst = it->second.get();
            if (inst->get_state() != runtime_running) continue;
        }

        auto* lua = inst->lua();
        if (!lua) continue;

        for (const auto& w : resolved)
        {
            // Re-validate, because a previous event callback may have removed
            // or stopped this runtime, and both end its batch.
            {
                std::shared_lock lock(mutex);
                auto it = runtimes.find(n);
                if (it == runtimes.end()) break;
                if (it->second->get_state() != runtime_running) break;
            }

            lua->dispatch_cluster_event(w);
        }
    }
#endif
}

void runtime_manager::publish_endpoints()
{
    // Never from a replica, guarded here rather than only at the five callers,
    // because those are all refused above and this line is here for the sixth.
    if (m_replica)
        return;

    auto tbl = std::make_shared<endpoint_table>();

    // Every running member of every group and what it declares, ordered by
    // member name through std::map because the fold decides the order of the
    // Allow header a client is given.
    std::map<std::string, std::map<std::string, std::shared_ptr<const route_table>>> group_members;

    {
        std::shared_lock lock(mutex);
        for (const auto& [name, inst] : runtimes)
        {
            const uint16_t port = inst->get_port();
            // A unix listener publishes its socket path in the host field with
            // the port at 0, which cannot be mistaken for a network endpoint
            // because the path is absolute and no hostname is.
            const std::string_view listen_path = inst->get_listen_path();
            if (port == 0 && listen_path.empty())
                continue;

            // Where this runtime is, as one value, because it is published
            // twice below and a member reached one way by name and another
            // way by group is the same process on the same box.
            // A runtime with a port may also have a node beside it; a runtime
            // that has only a node keeps publishing it where it always did,
            // in the host field with the port at 0.  The two are different
            // runtimes and not two spellings of one, so they take different
            // fields.
            const runtime_endpoint local =
                listen_path.empty()
                    ? runtime_endpoint{"127.0.0.1", port, inst->get_companion_paths()}
                    : runtime_endpoint{std::string(listen_path), 0, {}};

            // By name: no state filter, because this is what a backend given as
            // a bare runtime name resolves to, and that resolution happens while
            // the proxy itself is starting — before the target may have.
            tbl->set_name(name, local);

            // By group: running and endpoint_live(), because a worker-backed
            // runtime is `running` from the fork rather than from the bind,
            // and never a unix listener, which the group path has no route to
            // dial.  The node goes with it; a remote member, added below,
            // never carries one because a path means nothing off this box.
            const std::string_view group = inst->get_group();
            const bool running = (inst->get_state() == runtime_running) &&
                                 inst->endpoint_live();
            if (!group.empty() && running && listen_path.empty())
                tbl->add_to_group(group, local);

            // And what this runtime says it will answer, taking the worker's
            // copy first because a runtime in another process has no
            // interpreter here.
            std::shared_ptr<const route_table> decl = inst->worker_routes();
            if (!decl)
            {
                const auto* lctx = inst->lua();
                if (lctx && lctx->has_routes())
                    decl = std::make_shared<const route_table>(lctx->declared_routes());
            }
            if (decl && !decl->empty())
                tbl->set_name_routes(name, decl);
            if (!group.empty() && running)
                group_members[std::string(group)][name] = std::move(decl);
        }
    }

    // One declaration per group describing every member at once, so a single
    // member that declares nothing leaves the group with nothing, which is the
    // point.
    for (const auto& [group, members] : group_members)
    {
        route_table merged;
        bool started = false;
        for (const auto& [member, decl] : members)
        {
            if (!decl)
            {
                started = false;
                break;
            }
            if (!started)
            {
                merged = *decl;
                started = true;
            }
            else
            {
                merged.merge_alternative(*decl);
            }
        }
        if (started && !merged.empty())
            tbl->set_group_routes(group, std::make_shared<const route_table>(std::move(merged)));
    }

    // Remote members from the cluster's last scan, filtered exactly as
    // cluster_discovery::get_remote_group() does.
    if (m_cluster)
    {
        for (const auto& daemon : m_cluster->get_all_daemons())
        {
            for (const auto& rt : daemon.runtimes)
            {
                if (!rt.group.empty() && rt.state == "running" && rt.port > 0)
                    tbl->add_to_group(rt.group, runtime_endpoint{rt.host, rt.port, {}});
            }
        }
    }

    // Hand the finished table out, immutable from here on, so every runtime
    // holds the same one.
    {
        std::shared_lock lock(mutex);
        for (const auto& [_, inst] : runtimes)
            inst->set_endpoints(tbl);
    }

    // The other half of the same snapshot -- who answers a request addressed
    // to a name -- rebuilt wholesale at the same moments, running only, with a
    // worker's placeholder answering through its supervisor.
    {
        std::shared_lock lock(mutex);
        m_requests.clear_sinks();
        for (const auto& [name, inst] : runtimes)
        {
            if (inst->get_state() != runtime_running)
                continue;
            if (auto* sink = inst->as_request_sink())
                m_requests.register_sink(name, sink);
        }
    }

    // The per-shard entries, after the by-name pass and never instead of it,
    // outside the lock because this walks the daemon's supervisor map.
    if (m_shard_sink_publisher)
        m_shard_sink_publisher(m_requests);

    // And to whatever lives outside this address space, last and outside the
    // lock, because the sink writes to sockets.
    if (m_endpoint_sink)
        m_endpoint_sink(*tbl);
}

void runtime_manager::set_endpoint_sink(std::function<void(const endpoint_table&)> sink)
{
    m_endpoint_sink = std::move(sink);
}

void runtime_manager::set_shard_sink_publisher(std::function<void(request_channel&)> sink)
{
    m_shard_sink_publisher = std::move(sink);
}

void runtime_manager::set_publish_sink(
    std::function<void(std::string_view, std::string_view, std::string_view)> sink)
{
    m_publish_sink = std::move(sink);
}

void runtime_manager::set_deliver_sink(
    std::function<bool(std::string_view, std::string_view)> sink)
{
    m_deliver_sink = std::move(sink);
}

bool runtime_manager::deliver_out_of_process(std::string_view name,
                                             std::string_view message) const
{
    return m_deliver_sink ? m_deliver_sink(name, message) : false;
}

void runtime_manager::set_map_sink(
    std::function<bool(std::string_view, std::string_view,
                       std::string_view, std::string&)> sink)
{
    m_map_sink = std::move(sink);
}

bool runtime_manager::map_mutate(std::string_view op, std::string_view name,
                                 std::string_view config, std::string& err) const
{
    if (!m_map_sink)
    {
        err = "no map sink installed";
        return false;
    }
    return m_map_sink(op, name, config, err);
}

void runtime_manager::set_worker_release_sink(std::function<void()> sink)
{
    m_worker_release_sink = std::move(sink);
}

void runtime_manager::release_workers() const
{
    if (m_worker_release_sink)
        m_worker_release_sink();
}

const runtime_manager::runtime_map& runtime_manager::list() const
{
    return runtimes;
}

runtime_instance* runtime_manager::get(std::string_view name)
{
    std::shared_lock lock(mutex);

    auto it = runtimes.find(name);
    if (it != runtimes.end())
        return it->second.get();
    return nullptr;
}

void runtime_manager::set_cluster_discovery(cluster_discovery* cd)
{
    m_cluster = cd;
}

cluster_discovery* runtime_manager::get_cluster_discovery() const
{
    return m_cluster;
}
