#pragma once
// How a request names ONE shard of a runtime instead of the runtime.
//
// ─── WHY A NAME AND NOT A NEW FRAME ─────────────────────────────────────────
//
// The request channel already carries a request from any process to any
// runtime, by name, with the ticket bookkeeping, the liveness check and the
// bounds that go with it: a worker's default sink puts it on the control
// socket, the daemon looks the name up in the map only it holds, and the answer
// comes back with the cookie the caller posted.  Cross-shard routing needs
// exactly that, one step finer — the daemon holds N supervisors under one name
// and has to pick one.
//
// A second wire beside it would be a second set of tickets, a second liveness
// rule and a second place for a reply to go missing.  A qualified NAME needs
// none of that: `register_sink("c#3", shard_3)` makes the existing table answer
// the finer question, and every hop between the two shards is code that already
// runs.  What crosses the boundary is a string either way.
//
// ─── WHY '#' CANNOT COLLIDE ─────────────────────────────────────────────────
//
// runtime_manager's name check (runtime_manager.cpp) admits alphanumerics, '-',
// '_' and '.' and nothing else, so no runtime can be called `c#3` and no
// qualified target can be mistaken for a runtime that exists.  That is the
// whole of why this is safe to overload onto the name, and it is checked here
// rather than remembered: parse() refuses a base that is empty and an index
// that is not decimal, so a name carrying a stray '#' from somewhere resolves
// to nothing rather than to shard 0.
//
// ─── THE CYCLE, AND WHERE IT IS CUT ─────────────────────────────────────────
//
// proxy_supervisor::on_chan_req already refuses a worker asking for its own
// runtime's name, because the daemon's sink for that name is the supervisor of
// the worker that asked and the request would come straight back.  A qualified
// name reopens exactly that door for shard i addressing shard i, so the same
// guard asks this parser and refuses the same way.  A router that never
// produces its own index is the first lock; that guard is the second.
#include <cstdint>
#include <string>
#include <string_view>

#include "runtime_definitions.h"   // max_shards

inline constexpr char shard_target_sep = '#';

// `name` + '#' + index.  Cheap enough to build per crossing — one crossing is
// a round trip through two event loops.
inline std::string shard_target(std::string_view name, uint32_t index)
{
    std::string out;
    out.reserve(name.size() + 4);
    out.append(name);
    out.push_back(shard_target_sep);
    out.append(std::to_string(index));
    return out;
}

// Split one back apart.  False — and both outputs untouched — for anything that
// is not exactly `base#<decimal>` with a non-empty base and an index inside
// max_shards.  A target that fails here is an ordinary runtime name and is
// looked up as one.
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
