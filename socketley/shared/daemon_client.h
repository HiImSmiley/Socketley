#pragma once
#include <cstdint>
#include <string_view>

namespace socketley {

// Attach this process to a running Socketley daemon.
// Shows up in `socketley ps/ls`; `socketley stop <name>` sends SIGTERM.
// On success calls atexit(daemon_detach) automatically. Returns true on success.
bool daemon_attach(std::string_view name, std::string_view type, uint16_t port);

// Remove this process from the daemon registry.
// Safe to call multiple times; no-op if not attached or already detached.
void daemon_detach();

} // namespace socketley
