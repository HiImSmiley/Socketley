// Socketley SDK — the keyed store on its own, without a runtime
//
// A runtime type of your own has to keep its data somewhere, and the examples
// that do reach for std::map.  cache_store is already in the library and is
// tied to nothing: no event loop, no daemon, no io_uring.  This program holds
// one and never starts anything.
//
// Build:
//   g++ -std=c++23 sdk/examples/basic/store.cpp \
//       $(sdk/socketley-config --cflags --libs) -o /tmp/store
//
// Run:
//   /tmp/store
#include <socketley/store.h>

#include <cstdio>
#include <string>

int main()
{
    cache_store s;

    // Four types, one keyspace, and the type belongs to the key rather than to
    // a variable: type() answers at runtime and a key is only ever one of them.
    s.set("user:1", "ada");
    s.hset("cfg", "port", "9000");
    s.lpush("jobs", "build");
    s.sadd("tags", "fast");

    printf("types: %.*s %.*s %.*s %.*s\n",
           (int)s.type("user:1").size(), s.type("user:1").data(),
           (int)s.type("cfg").size(),    s.type("cfg").data(),
           (int)s.type("jobs").size(),   s.type("jobs").data(),
           (int)s.type("tags").size(),   s.type("tags").data());

    // A key that is a list refuses set() rather than overwriting it, which is
    // the difference between a keyed store and a map.
    printf("set over a list: %s\n", s.set("jobs", "nope") ? "took it" : "refused");

    // get_ptr() hands back the stored string; get() copies into a caller's
    // buffer.  The hot path wants the first one.
    if (const std::string* v = s.get_ptr("user:1"))
        printf("user:1 = %s\n", v->c_str());

    // A value that leaves without anybody deleting it.
    s.set_expiry("user:1", 60);
    printf("user:1 ttl = %lld s\n", (long long)s.get_ttl("user:1"));

    // The lookup takes a string_view and builds no temporary key, so this
    // costs a hash and a compare and no allocation at all -- and answers a
    // view, because a small hash keeps its fields packed and holds no
    // std::string to point at.
    const char* field = "port";
    if (auto p = s.hget("cfg", std::string_view(field)))
        printf("cfg.port = %.*s\n", static_cast<int>(p->size()), p->data());

    printf("keys = %u\n", s.size());
    return 0;
}
