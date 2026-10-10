#pragma once
#include <string_view>
// Applying a runtime_config to a live runtime in one place, because the daemon
// restores from disk and a worker rebuilds from a config frame and the two
// must agree field for field.

#include <string>

class cache_instance;
class proxy_instance;
class storage_instance;
class dns_instance;
class sync_instance;
class runtime_instance;
struct runtime_config;

// Everything in `cfg` that describes how a proxy forwards: protocol, strategy,
// backends and the mesh settings.
//
// `by_presence` chooses which question decides whether a field was asked for.
// The restore path has only the value -- a state file is the whole truth and an
// absent field means the default -- so it leaves this false and the "!=
// default" tests inside stand in for it.  `import` has the document's key set
// and needs it: an operator setting circuit_timeout back to 30 is asking for
// 30, and a "!= 30" test drops the request.  One list either way, because a
// tenth mesh field added to a copy of this list is a field one of the two doors
// would not apply.
void apply_proxy_config(proxy_instance& prx, const runtime_config& cfg,
                        bool by_presence = false);

// A cache's own fields, with `by_presence` meaning what it means for the
// proxy -- one list, because restore and import each kept a copy of it and
// --public reached neither.
void apply_cache_config(cache_instance& cache, const runtime_config& cfg,
                        bool by_presence = false);

// A storage runtime's own fields, with `by_presence` meaning what it means for the
// cache.
// A DNS runtime's zones, transfer and notify lists and rate limit, the same way.
void apply_dns_config(dns_instance& dns, const runtime_config& cfg, bool by_presence = false);

void apply_storage_config(storage_instance& stg, const runtime_config& cfg,
                          bool by_presence = false);

// A sync runtime's directory, targets, mode and schedule, the same way.
void apply_sync_config(sync_instance& sy, const runtime_config& cfg, bool by_presence = false);

// The fields every type has; not the ring settings, and not --lua, whose
// failure to load means different things to a daemon and to a worker.
void apply_common_config(runtime_instance& rt, const runtime_config& cfg);

// The subset a runtime already serving traffic can take without being rebuilt.
//
// Every field here is read at the moment it is used -- per accept, per message,
// per idle sweep -- so changing it under a live worker changes the next
// decision and nothing that has already been decided.  Everything else needs
// the object rebuilt: a port or a listen path is a bound socket, TLS is a
// context the handshakes already used, backends are open connections, and a
// server's mode decides how bytes were framed on connections that are still
// open.  Those keep waiting for the next start, which is what man/socketley.1
// and `edit --help` say.
//
// Guarded the way apply_common_config guards, and for the same reason: zero is
// how these fields say "not configured", so an unguarded assignment would let
// an edit of one limit clear another.
void apply_live_config(runtime_instance& rt, const runtime_config& cfg);

// The configuration keys apply_live_config takes, as `show` and `import` name them, kept beside it so the dashboard
// says which edits wait for a restart.
inline constexpr std::string_view live_config_keys[] = {
    "max_connections", "rate_limit", "global_rate_limit", "idle_timeout", "write_buffer", "read_buffer", "write_file",
    "strategy", "health_interval", "health_path", "health_threshold", "circuit_threshold", "circuit_timeout",
    "backend_timeout", "retry_count", "retry_all", "max_bytes"};

// The fields belonging to one type, touching nothing that needs a
// runtime_manager.
void apply_typed_config(runtime_instance& rt, const runtime_config& cfg);
