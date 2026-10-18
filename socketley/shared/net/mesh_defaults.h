#pragma once

// What a proxy's health checks, breakers and backend deadline are when nobody set them, for the proxy and its record.
namespace socketley::mesh_defaults
{

inline constexpr int health_interval   = 5;    // seconds
inline constexpr int health_threshold  = 3;    // consecutive failures to mark unhealthy
inline constexpr int circuit_threshold = 5;    // errors to open circuit
inline constexpr int circuit_timeout   = 30;   // seconds before half-open
inline constexpr int backend_timeout   = 2;    // seconds, 0 = disabled

}   // namespace socketley::mesh_defaults
