#include "runtime_manager.h"
#include "runtime_factory.h"
#include "event_loop.h"
#include <mutex>
#include <shared_mutex>

bool runtime_manager::create(runtime_type type, std::string_view name)
{
    std::unique_lock lock(mutex);

    if (runtimes.find(name) != runtimes.end())
        return false;

    auto instance = create_runtime(type, name);
    if (!instance)
        return false;

    runtimes.emplace(std::string(name), std::move(instance));
    return true;
}

bool runtime_manager::run(std::string_view name, event_loop& loop)
{
    std::shared_lock lock(mutex);

    auto it = runtimes.find(name);
    if (it == runtimes.end())
        return false;

    return it->second->start(loop);
}

bool runtime_manager::stop(std::string_view name, event_loop& loop)
{
    std::shared_lock lock(mutex);

    auto it = runtimes.find(name);
    if (it == runtimes.end())
        return false;

    return it->second->stop(loop);
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

void runtime_manager::stop_all(event_loop& loop)
{
    std::unique_lock lock(mutex);

    for (auto& [name, instance] : runtimes)
    {
        if (instance->get_state() == runtime_running)
            instance->stop(loop);
    }
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
