#pragma once

#include <unordered_map>
#include <memory>
#include <string>
#include <string_view>
#include <shared_mutex>
#include <functional>

#include "runtime_instance.h"

class event_loop;

// Transparent hash for heterogeneous lookup (avoids string copies on find)
struct runtime_string_hash
{
    using is_transparent = void;

    size_t operator()(std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }

    size_t operator()(const std::string& s) const noexcept
    {
        return std::hash<std::string_view>{}(s);
    }
};

struct runtime_string_equal
{
    using is_transparent = void;

    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept
    {
        return lhs == rhs;
    }
};

class runtime_manager
{
public:
    using runtime_map = std::unordered_map<std::string, std::unique_ptr<runtime_instance>,
                                            runtime_string_hash, runtime_string_equal>;

    bool create(runtime_type type, std::string_view name);
    bool run(std::string_view name, event_loop& loop);
    bool stop(std::string_view name, event_loop& loop);
    bool remove(std::string_view name);
    bool rename(std::string_view old_name, std::string_view new_name);
    void stop_all(event_loop& loop);

    // Ownership cascading
    std::vector<std::string> get_children(std::string_view parent_name) const;
    void stop_children(std::string_view parent_name, event_loop& loop);
    void remove_children(std::string_view parent_name, event_loop& loop);

    const runtime_map& list() const;
    runtime_instance* get(std::string_view name);

    mutable std::shared_mutex mutex;

private:
    runtime_map runtimes;
};
