#pragma once
// A qualified NAME rather than a new frame, so the request channel's tickets,
// liveness and bounds still apply, and '#' cannot collide because
// runtime_manager admits no such name.
#include <cstdint>
#include <string>
#include <string_view>

#include "../runtime/runtime_definitions.h"   // max_shards

inline constexpr char shard_target_sep = '#';

// `name` + '#' + index, cheap enough to build per crossing.
inline std::string shard_target(std::string_view name, uint32_t index)
{
    std::string out;
    out.reserve(name.size() + 4);
    out.append(name);
    out.push_back(shard_target_sep);
    out.append(std::to_string(index));
    return out;
}

// False, outputs untouched, for anything but `base#<decimal>` in range; a
// target that fails here is an ordinary runtime name.
inline bool parse_shard_target(std::string_view target,
                               std::string_view& base, uint32_t& index)
{
    const size_t hash = target.rfind(shard_target_sep);
    if (hash == std::string_view::npos || hash == 0 || hash + 1 >= target.size())
        return false;

    uint64_t n = 0;
    for (size_t i = hash + 1; i < target.size(); ++i)
    {
        const char c = target[i];
        if (c < '0' || c > '9')
            return false;
        n = n * 10 + static_cast<uint64_t>(c - '0');
        if (n >= max_shards)          // 64; anything larger is not an index
            return false;
    }

    base  = target.substr(0, hash);
    index = static_cast<uint32_t>(n);
    return true;
}
