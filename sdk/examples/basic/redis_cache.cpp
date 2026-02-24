// Socketley SDK — minimal Redis-compatible cache example
//
// Build:
//   g++ -std=c++23 sdk/examples/basic/redis_cache.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/redis_cache
//
// Run: /tmp/redis_cache
// Test: redis-cli -p 6379 SET foo bar && redis-cli -p 6379 GET foo

#include <socketley/cache.h>

int main()
{
    socketley::cache c(6379);
    c.persistent("/tmp/socketley_cache.dat")
     .resp()
     .max_memory(256 * 1024 * 1024)
     .eviction(evict_allkeys_lru);
    c.start();
    return 0;
}
