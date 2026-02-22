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

    -- API Service - 3 replicas (group: api)
    {
        type = "server",
        name = "api-replica-1",
        port = 9001,
        mode = "inout",
        group = "api",
        autostart = true
    },
    {
        type = "server",
        name = "api-replica-2",
        port = 9002,
        mode = "inout",
        group = "api",
        autostart = true
    },
    {
        type = "server",
        name = "api-replica-3",
        port = 9003,
        mode = "inout",
        group = "api",
        autostart = true
    },

    -- Load Balancer — discovers API replicas via @api group
    {
        type = "proxy",
        name = "api-lb",
        port = 8080,
        protocol = "http",
        strategy = "round-robin",
        backends = { "@api" },
        autostart = true
    },

    -- Worker Service - 2 replicas (group: workers)
    {
        type = "server",
        name = "worker-replica-1",
        port = 9011,
        mode = "inout",
        group = "workers",
        autostart = true
    },
    {
        type = "server",
        name = "worker-replica-2",
        port = 9012,
        mode = "inout",
        group = "workers",
        autostart = true
    },

    -- Worker Load Balancer — discovers workers via @workers group
    {
        type = "proxy",
        name = "worker-lb",
        port = 8081,
        protocol = "tcp",
        strategy = "random",
        backends = { "@workers" },
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
        socketley.log("║  API LB:    http://localhost:8080 (@api)   ║")
        socketley.log("║  Worker LB: tcp://localhost:8081 (@workers)║")
        socketley.log("╠════════════════════════════════════════════╣")
        socketley.log("║  API Replicas: 3 (round-robin, @api)       ║")
        socketley.log("║  Worker Replicas: 2 (random, @workers)     ║")
        socketley.log("║  Groups enable dynamic scaling!             ║")
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
  # Stop one replica — proxy excludes it automatically via @api group
  socketley stop api-replica-2

  # Traffic redistributes to remaining replicas
  for i in {1..6}; do curl -s localhost:8080/api-lb/test; done

  # Restore replica — proxy picks it up on next connection
  socketley start api-replica-2

Scale Up (no proxy restart needed):
  socketley create server api-replica-4 -p 9004 -g api -s
  # api-lb automatically includes api-replica-4 via @api group

Cleanup:
  socketley stop api-lb worker-lb api-replica-1 api-replica-2 api-replica-3 worker-replica-1 worker-replica-2 health-store
  socketley remove api-lb worker-lb api-replica-1 api-replica-2 api-replica-3 worker-replica-1 worker-replica-2 health-store
]]
