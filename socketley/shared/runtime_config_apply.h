#pragma once
// Applying a runtime_config to a live runtime, in one place.
//
// The daemon's restore path did this inline, which was fine while the daemon
// was the only thing that ever rebuilt a runtime from a config.  A worker
// rebuilds one too — from the same runtime_config, arriving over the control
// socket instead of off disk — and the two have to agree field for field.  A
// second copy of this list would drift, and the failure when it drifts is a
// runtime that behaves differently depending on which side of the process
// boundary it happens to be running on.
//
// It drifted. The proxy half was shared from the start; everything else was
// written twice, and the worker's copy applied 37 of the 62 fields. What the
// other 17 produced was not a missing feature but a DIFFERENT RUNTIME:
//
//   * mode, udp             — `create client x --udp` ran a TCP client in a
//                             worker, and started cleanly, because the
//                             configuration that would have been refused never
//                             arrived
//   * master_pw, master_forward
//                           — master mode never authenticated: the exchange
//                             did not happen at all, in either direction
//   * http_dir, http_cache, upstreams
//                           — an https:// server answered 404 for a file it
//                             was configured to serve
//   * cache_mode, resp_forced, replicate_target, max_memory, eviction,
//     persistent_path       — a replica cache received nothing, and no
//                             memory bound was in force
//   * reconnect             — a client's redial policy
//
// None of that was reported. The worker started, bound its port, pushed its
// figures and answered `stats` — as a runtime the operator did not ask for.
//
// So the list lives here now and both callers use it. test_worker_config_
// coverage.sh reads runtime_config's fields out of the header and fails on any
// that neither this file nor a named exception accounts for, so the next field
// added cannot quietly go missing on one side of the boundary.

#include <string>

class proxy_instance;
class runtime_instance;
struct runtime_config;

// Everything in `cfg` that describes how a proxy forwards: protocol, strategy,
// backends and the mesh settings.
void apply_proxy_config(proxy_instance& prx, const runtime_config& cfg);

// The fields every runtime type has — port, group, logging, limits, TLS paths,
// the target and the cache link.  Not the ring settings (see below) and not
// --lua, which the caller loads itself because a failure to load means
// different things to the daemon and to a worker.
void apply_common_config(runtime_instance& rt, const runtime_config& cfg);

// The fields that belong to one type, dispatched on rt.get_type(): a server's
// mode and master settings, a client's mode and redial policy, a proxy's
// forwarding, a cache's store and replication.
//
// Deliberately does not touch anything that needs a runtime_manager: a worker
// holds one runtime and the daemon holds the map, so wiring that pointer is the
// caller's business and differs between them.
void apply_typed_config(runtime_instance& rt, const runtime_config& cfg);
