# Socketley Examples

This directory contains practical examples demonstrating all features of socketley.

## Directory Structure

```
examples/
├── basic/              # Getting started, minimal setups
├── server-client/      # Server-client communication patterns
├── proxy/              # HTTP/TCP proxy configurations
├── cache/              # Caching with persistence
├── lua-config/         # Lua configuration and scripting
├── udp/                # UDP server/client examples
└── advanced/           # Complex multi-runtime setups
```

## Quick Start

1. **Start the daemon** (required for all examples):
   ```bash
   socketley daemon &
   ```

2. **Choose an example** and follow its README.

3. **Clean up** when done:
   ```bash
   socketley ls                    # See all runtimes
   socketley stop <name>           # Stop each runtime
   socketley remove <name>         # Remove each runtime
   ```

## Examples Overview

### Basic
- `01-hello-server.sh` - Your first server
- `02-hello-client.sh` - Your first client
- `03-combined.sh` - Server + client together

### Server-Client
- `echo-server.sh` - Echo server pattern
- `broadcast.sh` - One-to-many messaging
- `bidirectional.sh` - Full duplex communication
- `modes.sh` - in/out/inout message modes

### Proxy
- `http-proxy.sh` - Basic HTTP reverse proxy
- `load-balancer.sh` - Round-robin load balancing
- `group-discovery.sh` - Dynamic backends with `@group` discovery
- `tcp-proxy.sh` - Raw TCP byte forwarding
- `multi-backend.lua` - Multiple backends with Lua

### Cache
- `basic-cache.sh` - In-memory key-value store
- `persistent-cache.sh` - Cache with file persistence
- `cache-integration.lua` - Cache with server/client

### Lua Config
- `simple-config.lua` - Basic Lua configuration
- `callbacks.lua` - Event callbacks (on_start, on_stop, etc.)
- `custom-routing.lua` - Lua-based proxy routing
- `full-setup.lua` - Complete orchestration

### UDP
- `udp-echo.sh` - Fire-and-forget UDP messaging

### Advanced
- `microservices.lua` - Microservice architecture
- `high-availability.lua` - HA setup with failover
- `logging-pipeline.lua` - Centralized logging
- `development-env.lua` - Development environment setup
