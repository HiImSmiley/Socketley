#pragma once
// A random number that is never zero, for the identities that must not repeat across a restart: a Raft node, a replica's incarnation.
#include <chrono>
#include <cstdint>
#include <sys/random.h>
#include <unistd.h>

namespace socketley
{

inline uint64_t random_u64()
{
    uint64_t v = 0;
    while (v == 0)
        if (::getrandom(&v, sizeof v, 0) != static_cast<ssize_t>(sizeof v))
            v = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^ ::getpid();
    return v;
}

}   // namespace socketley
