#pragma once
// Applying a runtime_config to a live proxy, in one place.
//
// The daemon's restore path did this inline, which was fine while the daemon
// was the only thing that ever rebuilt a runtime from a config.  A proxy worker
// rebuilds one too — from the same runtime_config, arriving over the control
// socket instead of off disk — and the two have to agree field for field.  A
// second copy of this list would drift, and the failure when it drifts is a
// proxy that behaves differently depending on which side of the process
// boundary it happens to be running on.

class proxy_instance;
struct runtime_config;

// Everything in `cfg` that describes how a proxy forwards: protocol, strategy,
// backends and the mesh settings.  Not the fields common to every runtime type
// (port, name, limits, Lua) — the caller applies those, because a worker and
// the daemon disagree about some of them on purpose.
void apply_proxy_config(proxy_instance& prx, const runtime_config& cfg);
