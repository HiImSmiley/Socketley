-- =============================================================================
-- high-availability.lua - High Availability Setup
-- =============================================================================
--
-- Demonstrates HA patterns:
-- - Multiple instances of each service
-- - Load balancing across replicas
-- - Health tracking in cache
--
-- USAGE:
--   socketley --lua high-availability.lua
--
-- =============================================================================

runtimes = {
    -- Health tracking cache
    {
        type = "cache",
        name = "health-store",
        port = 9000,
        autostart = true
    },

    -- API Service - 3 replicas
    {
        type = "server",
        name = "api-replica-1",
        port = 9001,
        mode = "inout",
        autostart = true
    },
    {
        type = "server",
        name = "api-replica-2",
        port = 9002,
        mode = "inout",
        autostart = true
    },
    {
        type = "server",
        name = "api-replica-3",
        port = 9003,
        mode = "inout",
        autostart = true
    },

    -- Load Balancer
    {
        type = "proxy",
        name = "api-lb",
        port = 8080,
        protocol = "http",
        strategy = "round-robin",
        backends = {
            "api-replica-1",
            "api-replica-2",
            "api-replica-3"
        },
        autostart = true
    },

    -- Worker Service - 2 replicas
    {
        type = "server",
        name = "worker-replica-1",
        port = 9011,
        mode = "inout",
        autostart = true
    },
    {
        type = "server",
        name = "worker-replica-2",
        port = 9012,
        mode = "inout",
        autostart = true
    },

    -- Worker Load Balancer (random for stateless work)
    {
        type = "proxy",
        name = "worker-lb",
        port = 8081,
        protocol = "tcp",
        strategy = "random",
        backends = {
            "worker-replica-1",
            "worker-replica-2"
        },
        autostart = true
    }
}

-- Track replica health
local replica_starts = {}

function on_start()
    local name = self.name

    -- Track start time for health monitoring
    replica_starts[name] = os.time()

    if name:match("^api%-lb") then
        socketley.log("╔════════════════════════════════════════════╗")
        socketley.log("║        High Availability Setup             ║")
        socketley.log("╠════════════════════════════════════════════╣")
        socketley.log("║  API LB:    http://localhost:8080          ║")
        socketley.log("║  Worker LB: tcp://localhost:8081           ║")
        socketley.log("╠════════════════════════════════════════════╣")
        socketley.log("║  API Replicas: 3 (round-robin)             ║")
        socketley.log("║  Worker Replicas: 2 (random)               ║")
        socketley.log("╚════════════════════════════════════════════╝")
    end

    if name:match("replica") then
        socketley.log("[HA] " .. name .. " started (healthy)")
    end
end

function on_stop()
    local name = self.name
    if name:match("replica") then
        local uptime = os.time() - (replica_starts[name] or os.time())
        socketley.log("[HA] " .. name .. " stopped (uptime: " .. uptime .. "s)")
    end
end

--[[
Architecture:

                   API Requests                    Worker Tasks
                        │                               │
                        ▼                               ▼
              ┌─────────────────┐             ┌─────────────────┐
              │    api-lb       │             │   worker-lb     │
              │    :8080        │             │   :8081         │
              │  round-robin    │             │   random        │
              └────────┬────────┘             └────────┬────────┘
                       │                               │
        ┌──────────────┼──────────────┐         ┌──────┴──────┐
        ▼              ▼              ▼         ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐ ┌──────────┐
│ api-replica │ │ api-replica │ │ api-replica │ │ worker-1 │ │ worker-2 │
│      1      │ │      2      │ │      3      │ │  :9011   │ │  :9012   │
│   :9001     │ │   :9002     │ │   :9003     │ └──────────┘ └──────────┘
└─────────────┘ └─────────────┘ └─────────────┘

                                ┌─────────────┐
                                │health-store │
                                │   :9000     │
                                └─────────────┘

Test Load Balancing:
  # Watch requests distribute across replicas
  for i in {1..10}; do curl -s localhost:8080/api-lb/test; done

Simulate Failover:
  # Stop one replica
  socketley stop api-replica-2

  # Traffic redistributes to remaining replicas
  for i in {1..6}; do curl -s localhost:8080/api-lb/test; done

  # Restore replica
  socketley start api-replica-2

Cleanup:
  socketley stop api-lb worker-lb api-replica-1 api-replica-2 api-replica-3 worker-replica-1 worker-replica-2 health-store
  socketley remove api-lb worker-lb api-replica-1 api-replica-2 api-replica-3 worker-replica-1 worker-replica-2 health-store
]]
