#pragma once
// When a storage runtime's answered writes reach the disk, as --fsync names it.
#include <cstdint>
#include <string_view>

namespace socketley::storage
{

// Before the answer, within an interval after it, or whenever the kernel writes it back; a stop syncs everything.
enum class sync_mode : uint8_t { always, interval, never };

// The mode a name gives, false for anything but always, interval and never.
inline bool parse_sync_mode(std::string_view s, sync_mode& out)
{
    if (s == "always")
        out = sync_mode::always;
    else if (s == "interval")
        out = sync_mode::interval;
    else if (s == "never")
        out = sync_mode::never;
    else
        return false;
    return true;
}

}   // namespace socketley::storage
