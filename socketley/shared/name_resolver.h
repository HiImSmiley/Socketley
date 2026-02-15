#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <fnmatch.h>

template<typename MapT>
std::vector<std::string> resolve_names_impl(
    const std::string_view* args, size_t count,
    const MapT& names, size_t start = 1)
{
    std::vector<std::string> result;
    for (size_t i = start; i < count; ++i)
    {
        std::string_view arg = args[i];
        if (arg.empty() || arg[0] == '-')
            continue;

        bool is_glob = arg.find_first_of("*?[") != std::string_view::npos;
        if (is_glob)
        {
            std::string pattern(arg);
            for (const auto& [name, val] : names)
                if (fnmatch(pattern.c_str(), name.c_str(), 0) == 0)
                    result.push_back(name);
        }
        else
        {
            if (names.find(arg) != names.end())
                result.push_back(std::string(arg));
        }
    }
    return result;
}
