#pragma once
#include <cstdint>
#include <string_view>

constexpr uint32_t fnv1a(std::string_view sv)
{
    uint32_t hash = 2166136261u;
    for (char c : sv)
        hash = (hash ^ static_cast<uint8_t>(c)) * 16777619u;
    return hash;
}

// Case-insensitive hash (converts to lowercase on the fly, no allocation)
constexpr uint32_t fnv1a_lower(std::string_view sv)
{
    uint32_t hash = 2166136261u;
    for (char c : sv)
    {
        char lower = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        hash = (hash ^ static_cast<uint8_t>(lower)) * 16777619u;
    }
    return hash;
}
