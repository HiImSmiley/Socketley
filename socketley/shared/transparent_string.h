#pragma once

// Looking a std::string key up with a std::string_view, without building a
// std::string to do it.
//
// Both halves are needed: is_transparent on the hash AND on the comparator, or
// the container quietly falls back to constructing the key type.  That is how
// note_write_for_watch came to allocate a std::string on every write and how
// the script cache came to SHA1 its body on every EVAL -- the lookup looked
// free at the call site and was not.
//
// It lives here because the cache store and the script engine both want it and
// a second copy is a copy that drifts.

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>

struct string_hash
{
    using is_transparent = void;

    size_t operator()(std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }

    size_t operator()(const std::string& s) const noexcept
    {
        return std::hash<std::string_view>{}(s);
    }
};

struct string_equal
{
    using is_transparent = void;

    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept
    {
        return lhs == rhs;
    }
};
