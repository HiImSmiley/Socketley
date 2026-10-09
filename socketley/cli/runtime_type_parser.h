#pragma once

#include <cstdint>
#include <string_view>
#include "command_hashing.h"
#include "../shared/runtime_definitions.h"
#include "../shared/type_registry.h"

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
        case fnv1a("storage"):
            out = runtime_storage;
            return true;
        case fnv1a("dns"):
            out = runtime_dns;
            return true;
        case fnv1a("sync"):
            out = runtime_sync;
            return true;
        default:
            return type_registry::lookup(str, out);
    }
}
