#pragma once

#include <cstdint>
#include <string_view>
#include "command_hashing.h"
#include "../shared/runtime_definitions.h"

inline bool parse_runtime_type(std::string_view str, runtime_type& out)
{
    switch (fnv1a(str))
    {
        case fnv1a("server"):
            out = runtime_server;
            return true;
        case fnv1a("client"):
            out = runtime_client;
            return true;
        case fnv1a("proxy"):
            out = runtime_proxy;
            return true;
        case fnv1a("cache"):
            out = runtime_cache;
            return true;
        default:
            return false;
    }
}
