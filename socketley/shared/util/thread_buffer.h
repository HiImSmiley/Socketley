#pragma once
// A thread's own scratch array, allocated on its first use, because a thread_local array sits in the static TLS block
// that glibc copies and zeroes at the start of every thread, every runtime's threads that never touch it included.
#include <cstddef>
#include <memory>

namespace socketley
{

// `Site` is a type of the caller's own, so two call sites with the same element type and size never share an array.
template <typename T, size_t N, typename Site>
T* thread_buffer()
{
    static thread_local std::unique_ptr<T[]> buf;
    if (!buf)
        buf = std::make_unique_for_overwrite<T[]>(N);
    return buf.get();
}

}   // namespace socketley
