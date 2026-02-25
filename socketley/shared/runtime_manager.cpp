#include "runtime_manager.h"
#include "runtime_factory.h"
#include "event_loop.h"
#include "cluster_discovery.h"
#include "lua_context.h"
#include <cctype>
#include <mutex>
#include <shared_mutex>

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

bool runtime_manager::remove(std::string_view name)
{
    std::unique_lock lock(mutex);

    auto it = runtimes.find(name);
    if (it == runtimes.end())
        return false;

    runtimes.erase(it);
    return true;
}

std::unique_ptr<runtime_instance> runtime_manager::extract(std::string_view name)
{
    std::unique_lock lock(mutex);

    auto it = runtimes.find(name);
    if (it == runtimes.end())
        return nullptr;

    auto ptr = std::move(it->second);
    runtimes.erase(it);
    return ptr;
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
    // Snapshot names under read lock — do NOT hold the lock during callbacks.
    // A Lua subscribe callback may call socketley.stop/remove which needs a write lock,
    // which would deadlock if we held the read lock here.
    // We snapshot names (not raw pointers) so that if a callback removes a runtime,
    // we safely skip it on re-lookup instead of dereferencing a dangling pointer.
    std::vector<std::string> names;
    {
        std::shared_lock lock(mutex);
        names.reserve(runtimes.size());
        for (auto& [n, _] : runtimes)
            names.push_back(n);
    }
    for (auto& n : names)
    {
        runtime_instance* inst;
        {
            std::shared_lock lock(mutex);
            auto it = runtimes.find(n);
            if (it == runtimes.end()) continue;
            inst = it->second.get();
        }
        inst->on_publish_dispatch(cache_name, channel, message);
    }
}

void runtime_manager::dispatch_cluster_events(const std::vector<cluster_event>& events)
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
