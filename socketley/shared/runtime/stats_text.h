#pragma once

#include <string_view>
#include <type_traits>

#include "../util/text_list.h"

namespace socketley::stats_text
{

// Each key:value line of a runtime's stats text, the last one too when no newline ends it, until `f` returns false.
template <class F>
void for_each_field(std::string_view text, F&& f)
{
    while (!text.empty())
    {
        const std::string_view line = take_item(text, '\n');
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        if constexpr (std::is_same_v<std::invoke_result_t<F&, std::string_view, std::string_view>, bool>)
        {
            if (!f(line.substr(0, colon), line.substr(colon + 1)))
                return;
        }
        else
            f(line.substr(0, colon), line.substr(colon + 1));
    }
}

// The value of the first line under `key`, empty when there is none.
inline std::string_view field(std::string_view text, std::string_view key)
{
    std::string_view out;
    for_each_field(text, [&](std::string_view k, std::string_view v) {
        if (k != key)
            return true;
        out = v;
        return false;
    });
    return out;
}

}   // namespace socketley::stats_text
