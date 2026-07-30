#include "runtime_manager.h"
#include <algorithm>
#include "runtime_factory.h"
#include "event_loop.h"
#include "cluster_discovery.h"
#include "lua_context.h"
#include "logging.h"
#include <cctype>
#include <mutex>
#include <shared_mutex>

namespace
{

// What extract() answers with now that the real instance may not leave the
// manager's hands.  It carries the removed runtime's identity, so a caller that
// looks at it sees the runtime it asked about; it owns no I/O of its own, so it
// can be destroyed at any moment — which is exactly what its one caller does, a
// tick after taking it.
struct detached_shell final : runtime_instance
{
    detached_shell(runtime_type type, std::string_view name)
        : runtime_instance(type, name) {}

    void on_cqe(struct io_uring_cqe*) override {}
    bool setup(event_loop&) override { return false; }
    void teardown(event_loop&) override {}
};

}  // namespace

bool runtime_manager::create(runtime_type type, std::string_view name)
{
    std::unique_lock lock(mutex);

    // Validate name: alphanumeric + -_. only, max 128 chars, no leading dot
    if (name.empty() || name.size() > 128 || name[0] == '.')
        return false;
    for (char c : name)
    {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.')
            return false;
    }

    if (runtimes.find(name) != runtimes.end())
        return false;

    auto instance = create_runtime(type, name);
    if (!instance)
        return false;

    runtimes.emplace(std::string(name), std::move(instance));
    return true;
}

bool runtime_manager::start(std::string_view name, event_loop& loop)
{
    std::shared_lock lock(mutex);

    auto it = runtimes.find(name);
    if (it == runtimes.end())
        return false;

    return it->second->start(loop);
}

bool runtime_manager::stop(std::string_view name, event_loop& loop)
{
    {
        std::shared_lock lock(mutex);
        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return false;
        if (!it->second->stop(loop))
            return false;
    }

    // Cascade to children based on child_policy
    auto children = get_children(name);
    for (const auto& child : children)
    {
        auto* child_inst = get(child);
        if (!child_inst) continue;

        if (child_inst->get_child_policy() == runtime_instance::child_policy::remove)
            remove_children(child, loop);
        else
            stop_children(child, loop);

        if (child_inst->get_child_policy() == runtime_instance::child_policy::remove)
        {
            if (child_inst->get_state() == runtime_running)
                stop(child, loop);
            remove(child);
        }
        else
        {
            if (child_inst->get_state() == runtime_running)
                stop(child, loop);
        }
    }

    return true;
}

// A runtime instance is the storage for its own io_requests: the accept
// request, the timers, and — through the connection structs it owns — one set
// per connection.  io_uring keeps whatever addresses we hand it, so destroying
// an instance while any of its completions is still queued leaves the event
// loop reading freed memory; that is the segfault in event_loop::run() on
// `req->owner`.  Nulling req->owner in teardown() does not save us, because
// that convention only carries while there is still an object there to read the
// null out of.
//
// So removal never destroys.  The instance leaves the map — which is what ps,
// stats, start, rename and the rest look at, so it is gone as far as anyone can
// tell, and its name is free again — and lands here instead, to be freed once
// the ring is gone.
void runtime_manager::retire(std::unique_ptr<runtime_instance> inst)
{
    if (!inst)
        return;

    // An instance that never reached setup() never put an io_request of its own
    // into the ring, so nothing can point into it and it goes now.  That covers
    // create-then-reject-a-flag, and external runtimes, which do no I/O of
    // their own — and which have to keep being dropped untouched, the way
    // removal has always treated them, rather than being handed the SIGTERM
    // that stopping one sends.
    if (!inst->has_armed_io())
        return;

    // Every caller that can reach a running runtime stops it first, so this is
    // a backstop rather than a path.  It has to be here all the same: retiring
    // a runtime that is still armed would turn the old crash into something
    // quieter and worse — a runtime nobody can see or name that keeps serving
    // traffic for the rest of the daemon's life.  Done with the map lock
    // released, because on_stop may run Lua that calls back into the manager.
    if (inst->get_state() == runtime_running)
    {
        if (event_loop* loop = inst->get_event_loop())
            inst->stop(*loop);
        else
            LOG_WARN("removed a running runtime that has no event loop: "
                     "its fds stay open until the daemon exits");
    }

    // The graveyard is only emptied at shutdown, so a daemon that creates and
    // removes started runtimes in a loop grows.  Nothing available here can
    // bound that without help from the event loop, so say it out loud on every
    // doubling instead of letting it be found later as a leak.
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

    // Clear out whatever the ring has finished with.  Retiring is the only
    // moment the graveyard grows, so reaping here is what keeps it from
    // growing: what is left afterwards is exactly the instances the kernel is
    // still working through, plus at most one that has nothing outstanding and
    // is waiting for the next retirement or for shutdown.
    if (reap_loop)
        retired -= std::min(retired, reap_retired(*reap_loop));

    if (retired > 0)
    {
        std::string msg = "retired runtime instances the ring has not finished with: "
                        + std::to_string(retired);
        LOG_WARN(msg.c_str());
    }
}

size_t runtime_manager::reap_retired(const event_loop& loop)
{
    if (loop.owner_table_full())
        return 0;

    std::vector<std::unique_ptr<runtime_instance>> doomed;
    {
        std::unique_lock lock(mutex);
        for (auto it = m_retired.begin(); it != m_retired.end(); )
        {
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
    return true;
}

std::unique_ptr<runtime_instance> runtime_manager::extract(std::string_view name)
{
    std::unique_ptr<runtime_instance> inst;
    {
        std::unique_lock lock(mutex);

        auto it = runtimes.find(name);
        if (it == runtimes.end())
            return nullptr;

        inst = std::move(it->second);
        runtimes.erase(it);
    }

    // Built before the instance is handed on, while its name and id are still
    // ours to read.
    std::unique_ptr<runtime_instance> shell =
        std::make_unique<detached_shell>(inst->get_type(), inst->get_name());
    shell->set_id(inst->get_id());

    retire(std::move(inst));
    return shell;
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
    std::unique_lock lock(mutex);

    auto it = runtimes.find(old_name);
    if (it == runtimes.end())
        return false;

    if (runtimes.find(new_name) != runtimes.end())
        return false;

    auto instance = std::move(it->second);
    runtimes.erase(it);
    instance->set_name(new_name);
    runtimes.emplace(std::string(new_name), std::move(instance));
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

void runtime_manager::stop_children(std::string_view parent_name, event_loop& loop)
{
    auto children = get_children(parent_name);
    for (const auto& child : children)
    {
        // Recurse: stop grandchildren first
        stop_children(child, loop);
        stop(child, loop);
    }
}

void runtime_manager::remove_children(std::string_view parent_name, event_loop& loop)
{
    auto children = get_children(parent_name);
    for (const auto& child : children)
    {
        // Recurse: remove grandchildren first
        remove_children(child, loop);
        auto* inst = get(child);
        if (inst && inst->get_state() == runtime_running)
            stop(child, loop);
        remove(child);
    }
}

void runtime_manager::stop_all(event_loop& loop)
{
    std::unique_lock lock(mutex);

    for (auto& [name, instance] : runtimes)
    {
        if (instance->get_state() == runtime_running)
            instance->stop(loop);
    }
}

void runtime_manager::dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message)
{
    // Snapshot pointers under a single read lock — avoids per-runtime re-lock overhead.
    // Safe because on_publish_dispatch only invokes Lua subscribe callbacks which
    // do not modify the runtime map (stop/remove go through the daemon handler).
    std::vector<runtime_instance*> snapshot;
    {
        std::shared_lock lock(mutex);
        snapshot.reserve(runtimes.size());
        for (auto& [_, inst] : runtimes)
            snapshot.push_back(inst.get());
    }
    for (auto* inst : snapshot)
        inst->on_publish_dispatch(cache_name, channel, message);
}

void runtime_manager::dispatch_cluster_events([[maybe_unused]] const std::vector<cluster_event>& events)
{
    // Snapshot names under read lock — same pattern as dispatch_publish().
    // Re-lookup each name before invoking callbacks so that if a prior callback
    // removed/stopped a runtime, we safely skip it instead of dereferencing
    // a dangling pointer.
    std::vector<std::string> names;
    {
        std::shared_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [n, _] : runtimes)
            names.push_back(n);
    }

#ifndef SOCKETLEY_NO_LUA
    for (auto& n : names)
    {
        runtime_instance* inst;
        {
            std::shared_lock lock(mutex);
            auto it = runtimes.find(n);
            if (it == runtimes.end()) continue;
            inst = it->second.get();
        }

        auto* lua = inst->lua();
        if (!lua) continue;

        for (const auto& ev : events)
        {
            // Re-validate: a previous event callback may have removed this runtime
            {
                std::shared_lock lock(mutex);
                if (runtimes.find(n) == runtimes.end()) break;
            }

            try {
                switch (ev.kind)
                {
                    case cluster_event::daemon_join:
                        if (lua->has_on_cluster_join())
                        {
                            sol::table dt = lua->state().create_table();
                            dt["name"] = ev.daemon_name;
                            // Look up host from remote daemons
                            if (m_cluster)
                            {
                                auto daemons = m_cluster->get_all_daemons();
                                for (const auto& rd : daemons)
                                {
                                    if (rd.name == ev.daemon_name)
                                    {
                                        dt["host"] = rd.host;
                                        break;
                                    }
                                }
                            }
                            lua->on_cluster_join()(dt);
                        }
                        break;

                    case cluster_event::daemon_leave:
                        if (lua->has_on_cluster_leave())
                        {
                            sol::table dt = lua->state().create_table();
                            dt["name"] = ev.daemon_name;
                            lua->on_cluster_leave()(dt);
                        }
                        break;

                    case cluster_event::group_change:
                        if (lua->has_on_group_change())
                        {
                            // Build members table
                            sol::table members = lua->state().create_table();
                            int mi = 1;
                            if (m_cluster)
                            {
                                // Local group members
                                {
                                    std::shared_lock lock(mutex);
                                    for (const auto& [_, rinst] : runtimes)
                                    {
                                        if (rinst->get_group() == ev.group_name &&
                                            rinst->get_state() == runtime_running &&
                                            rinst->get_port() > 0)
                                        {
                                            sol::table m = lua->state().create_table();
                                            m["daemon"] = std::string(m_cluster->get_daemon_name());
                                            m["host"] = std::string(m_cluster->get_cluster_addr());
                                            m["port"] = rinst->get_port();
                                            members[mi++] = m;
                                        }
                                    }
                                }
                                // Remote group members
                                auto daemons = m_cluster->get_all_daemons();
                                for (const auto& rd : daemons)
                                {
                                    for (const auto& rt : rd.runtimes)
                                    {
                                        if (rt.group == ev.group_name &&
                                            rt.state == "running" && rt.port > 0)
                                        {
                                            sol::table m = lua->state().create_table();
                                            m["daemon"] = rt.daemon_name;
                                            m["host"] = rt.host;
                                            m["port"] = rt.port;
                                            members[mi++] = m;
                                        }
                                    }
                                }
                            }
                            lua->on_group_change()(ev.group_name, members);
                        }
                        break;
                }
            } catch (const sol::error& e) {
                fprintf(stderr, "[lua] cluster event callback error: %s\n", e.what());
            }
        }
    }
#endif
}

std::vector<runtime_instance*> runtime_manager::get_by_group(std::string_view group) const
{
    std::shared_lock lock(mutex);
    std::vector<runtime_instance*> result;
    for (const auto& [_, inst] : runtimes)
    {
        if (inst->get_group() == group && inst->get_state() == runtime_running)
            result.push_back(inst.get());
    }
    return result;
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
