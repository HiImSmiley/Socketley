#pragma once
// Which sync runtimes a storage runtime makes to pull its users' git repositories, as --sync names it.
#include <cstdint>
#include <string_view>

namespace socketley::storage
{

// None at all, one for the whole storage that pulls every user's repositories, or one for each user.
enum class sync_runners : uint8_t { never, active, per_user };

// The setting a name gives, false for anything but never, active and per-user.
inline bool parse_sync_runners(std::string_view s, sync_runners& out)
{
    if (s == "never")
        out = sync_runners::never;
    else if (s == "active")
        out = sync_runners::active;
    else if (s == "per-user")
        out = sync_runners::per_user;
    else
        return false;
    return true;
}

}   // namespace socketley::storage
