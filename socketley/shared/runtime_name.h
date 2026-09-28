#pragma once
// What a runtime may be called, in one place because a name reaches the filesystem, a JSON document, a command line and the replicated cluster state.
#include <cctype>
#include <string_view>

namespace socketley
{

inline bool valid_runtime_name(std::string_view name)
{
    // A leading '-' is refused because the CLI can never address it again, and a leading '.' or a '..' because a state file is named after it.
    if (name.empty() || name.size() > 128 || name[0] == '.' || name[0] == '-')
        return false;
    if (name.find("..") != std::string_view::npos)
        return false;
    for (char c : name)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.')
            return false;
    return true;
}

}   // namespace socketley
