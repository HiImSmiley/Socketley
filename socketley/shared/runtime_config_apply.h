#pragma once
// Applying a runtime_config to a live runtime in one place, because the daemon
// restores from disk and a worker rebuilds from a config frame and the two
// must agree field for field.

#include <string>

class proxy_instance;
class runtime_instance;
struct runtime_config;

// Everything in `cfg` that describes how a proxy forwards: protocol, strategy,
// backends and the mesh settings.
void apply_proxy_config(proxy_instance& prx, const runtime_config& cfg);

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

// The fields belonging to one type, touching nothing that needs a
// runtime_manager.
void apply_typed_config(runtime_instance& rt, const runtime_config& cfg);
