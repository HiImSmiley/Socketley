#pragma once

#include <string>
#include <string_view>

namespace socketley
{

// What marks a cache payload as exactly one command, whose value may hold newlines that the cache's line-split text
// protocol would otherwise read as further commands.
inline constexpr std::string_view one_command_marker = "\x01skl-one\n";

// `command`, verbatim, under the marker.
inline std::string one_command(std::string_view command)
{
    std::string out;
    out.reserve(one_command_marker.size() + command.size());
    out.append(one_command_marker);
    out.append(command);
    return out;
}

} // namespace socketley
