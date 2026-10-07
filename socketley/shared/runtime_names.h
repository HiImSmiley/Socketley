#pragma once
// The names runtimes are reached by, and the one rule about them: a name belongs to one runtime, or to the runtimes
// of one group, which share it for a proxy to spread requests over. Kept here because create, import and the table
// the daemon publishes for dns runtimes and entrances must all read a runtime's names the same way.
#include <string>
#include <string_view>
#include <vector>

class runtime_instance;

namespace runtime_names
{

// `name` as names are compared: lower case, without a trailing dot.
std::string normal(std::string_view name);

// The names `rt` declares it is reached by: --domain, and a storage runtime's --domain and --website-domain, each
// normalised; a storage runtime's also with the wildcard its buckets are addressed under when `with_buckets`.
std::vector<std::string> of(const runtime_instance& rt, bool with_buckets = false);

// Why `rt` may not have its names beside `others`, empty when it may: a name another runtime has, outside a shared
// group, or a name on a proxy that is an entrance (no --backend), which is reached by every name and owns none.
std::string refusal(const runtime_instance& rt, const std::vector<const runtime_instance*>& others);

// Whether `rt` is an entrance: a proxy speaking HTTP with no --backend, which routes each request by its name to
// the runtime that has it.
bool is_entrance(const runtime_instance& rt);

// Whether a request for `rt`'s names may be routed to it over HTTP: a server, a storage runtime, or a proxy that
// speaks HTTP and is no entrance.
bool speaks_http(const runtime_instance& rt);

}   // namespace runtime_names
