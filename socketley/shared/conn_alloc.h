#pragma once

// How a connection struct is built.
//
// std::make_unique<T>() VALUE-initialises, which for a class with no
// user-provided default constructor zero-fills the whole object first.  A
// connection carries large buffers that are written before they are read --
// the proxy's is sixty-four kilobytes -- so that zeroing is work nobody asked
// for, and it shows up twice: as resident pages that were never used, and as
// clear_highpages in the kernel, profiled at 2.86 per cent of a proxy worker.
//
// Default-initialising instead skips it.  That is only correct while EVERY
// member either is a class type with its own default constructor or carries an
// initialiser of its own, which is why io_request was given initialisers on
// all five of its members.  The one exception is `struct iovec write_iovs[]`,
// which is filled from index 0 to `count` and passed to the kernel with that
// same count, so no entry is ever read before it is written.
//
// SOCKETLEY_POISON_CONN fills the storage with 0xAA instead.  Anything that
// quietly relied on the old zeroing then reads a large, obviously wrong value
// rather than a plausible one, which is how this was checked without MSan:
// the whole suite under poison, green.

#include <cstring>
#include <memory>
#include <new>
#include <cstddef>

namespace socketley
{

template <typename T>
std::unique_ptr<T> make_connection()
{
#ifdef SOCKETLEY_POISON_CONN
    // The ALIGNED operator new, because these structs are alignas(64) and
    // unique_ptr's delete then calls the aligned operator delete.  The plain
    // form here was a new-delete-type-mismatch that ASan caught inside
    // fuzz_proxy_ops -- a defect in this instrument, not in the tree, and
    // exactly the kind a poison run exists to surface.
    void* raw = ::operator new(sizeof(T), std::align_val_t{alignof(T)});
    std::memset(raw, 0xAA, sizeof(T));
    return std::unique_ptr<T>(new (raw) T);
#else
    return std::make_unique_for_overwrite<T>();
#endif
}

}   // namespace socketley
