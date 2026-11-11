// socketley/store.h -- the keyed store, as a data structure
//
// cache_store is what the cache runtime keeps its keys in, and nothing about
// it is tied to that runtime: the header brings the store's own containers and
// standard headers and nothing of the engine's loop, so a program can hold one
// without an event loop, a daemon, or io_uring.  It was reachable only by including the cache runtime's
// own header, which is to say it was reachable by accident.
//
//   cache_store s;
//   s.set("user:1", "ada");            // string
//   s.hset("cfg", "port", "9000");     // hash
//   s.lpush("jobs", "build");          // list
//   s.sadd("tags", "fast");            // set
//   s.set_expiry("user:1", 60);
//   const std::string* v = s.get_ptr("user:1");   // no copy
//   if (auto f = s.hget("cfg", "port")) ...        // optional<string_view>
//
// hget() and lindex() answer views and not std::string*, and list_ptr()'s
// list is read through at() and iterators of views, because a small hash and a
// small list are packed and hold no std::string to point at.
//
// What it gives you over the std:: container you would otherwise reach for:
// lookups take a string_view and build no temporary key, get_ptr() hands back
// the stored string rather than a copy, keys can carry a TTL, a memory budget
// can refuse a write, an LRU can evict, SCAN walks all six types from one
// packed cursor, and save()/load() plus adopt_owned() are what the cache
// runtime uses for its dumps and its shard moves.
//
// The type is per key and exclusive: a key that is a list refuses set(), which
// is why several of these return bool or a sentinel rather than void.
#pragma once

#ifndef __linux__
#  error "Socketley requires Linux (io_uring)"
#endif

#include "../../../../socketley/runtime/cache/cache_store.h"
