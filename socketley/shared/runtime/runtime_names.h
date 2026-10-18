#pragma once
// The names runtimes are reached by, and the one rule about them: a name belongs to one runtime, or to the runtimes
// of one group, which share it for a proxy to spread requests over. Kept here because create, import and the table
// the daemon publishes for dns runtimes and entrances must all read a runtime's names the same way.
#include <functional>
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

// The table an entrance routes by, as text (dns_feed.h's routes-<entrance>): a `zone <origin>` line for each zone of
// the dns runtimes that name it with --proxy, then a `route <name> <address>...` line for each name of a runtime that
// speaks HTTP -- a name without a dot once under each zone, the addresses of a group's runtimes together.
// `origins_of` gives a dns runtime's zone origins. A runtime with --tls of its own is left out: the entrance is where
// TLS ends, and it does not speak TLS to what it routes to.
std::string entrance_table(const runtime_instance& entrance, const std::vector<const runtime_instance*>& all,
                           const std::function<std::vector<std::string>(const runtime_instance&)>& origins_of);

}   // namespace runtime_names
