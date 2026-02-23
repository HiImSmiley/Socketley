# Advanced Examples

Complex multi-runtime setups for production-like scenarios.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Examples

### Microservices
Complete microservice architecture with service discovery.

### High Availability
HA setup with multiple backends and failover.

### Logging Pipeline
Centralized logging across all services.

### Development Environment
Local development setup with hot reload simulation.

## Architecture Patterns

### Service Mesh Pattern
```
[client] → [proxy] → [service-a]
                  → [service-b]
                  → [service-c]
```

### Fan-Out Pattern
```
[gateway] → [load-balancer] → [worker-1]
                           → [worker-2]
                           → [worker-n]
```

### Sidecar Pattern
```
[main-service] ←→ [sidecar-client]
                        ↓
               [monitoring-service]
```
