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
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

struct string_hash
{
    using is_transparent = void;

    // Left as libstdc++'s Murmur64A.  A hand-rolled wyhash-shaped replacement
    // was written and measured: equal distribution (chi2/df 1.035 against
    // 1.000 over 300k keys of three shapes, no full-hash collisions, same
    // deepest bucket) and SLOWER, 0.975 of the median over six interleaved
    // passes with only two of them in its favour.  The 2.62 per cent
    // _Hash_bytes costs at depth 100 is not recovered by mixing it by hand.

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

    // std::string_view's own == checks the size and then calls memcmp, and for
    // a key the length of "k:000000000123" that is a call into libc for
    // fourteen bytes.  Profiled at pipeline depth 100, __memcmp_avx2_movbe is
    // 5.55 per cent of a cache worker -- the second largest symbol after the
    // find that calls it.
    //
    // Every load below stays inside [data, data + size): the two eight-byte
    // reads overlap in the middle rather than running past the end, which is
    // what makes the short case safe without a tail branch per byte.
    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept
    {
        const size_t n = lhs.size();
        if (n != rhs.size())
            return false;

        const char* a = lhs.data();
        const char* b = rhs.data();

        if (n >= 8)
        {
            if (n <= 16)
            {
                uint64_t a0, a1, b0, b1;
                __builtin_memcpy(&a0, a, 8);
                __builtin_memcpy(&b0, b, 8);
                __builtin_memcpy(&a1, a + n - 8, 8);
                __builtin_memcpy(&b1, b + n - 8, 8);
                return ((a0 ^ b0) | (a1 ^ b1)) == 0;
            }
            return __builtin_memcmp(a, b, n) == 0;
        }

        // Under eight bytes there is no word to load without leaving the
        // string, so the two halves overlap at four, then at two, then one.
        if (n >= 4)
        {
            uint32_t a0, a1, b0, b1;
            __builtin_memcpy(&a0, a, 4);
            __builtin_memcpy(&b0, b, 4);
            __builtin_memcpy(&a1, a + n - 4, 4);
            __builtin_memcpy(&b1, b + n - 4, 4);
            return ((a0 ^ b0) | (a1 ^ b1)) == 0;
        }
        if (n == 0)
            return true;
        return a[0] == b[0] && a[n / 2] == b[n / 2] && a[n - 1] == b[n - 1];
    }
};
