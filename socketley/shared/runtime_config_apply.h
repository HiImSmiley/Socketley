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

// The fields belonging to one type, touching nothing that needs a
// runtime_manager.
void apply_typed_config(runtime_instance& rt, const runtime_config& cfg);
