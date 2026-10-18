#pragma once

#include <cstdint>
#include <string_view>
#include "command_hashing.h"
#include "../shared/runtime/runtime_definitions.h"
#include "../shared/runtime/type_registry.h"

inline bool parse_runtime_type(std::string_view str, runtime_type& out)
{
    return type_registry::lookup(str, out);
}
