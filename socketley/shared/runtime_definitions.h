#pragma once
#include <cstdint>

enum runtime_state : uint8_t
{
    runtime_created = 0,
    runtime_running = 1,
    runtime_stopped = 2,
    runtime_failed  = 3
};

enum runtime_type : uint8_t
{
    runtime_server = 0,
    runtime_client = 1,
    runtime_proxy  = 2,
    runtime_cache  = 3
};

inline constexpr const char* type_to_string(runtime_type t)
{
    switch (t)
    {
        case runtime_server: return "server";
        case runtime_client: return "client";
        case runtime_proxy:  return "proxy";
        case runtime_cache:  return "cache";
    }
    return "unknown";
}
