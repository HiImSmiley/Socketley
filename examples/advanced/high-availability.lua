-- =============================================================================
-- high-availability.lua - High Availability Setup
-- =============================================================================
--
-- Demonstrates HA patterns:
-- - Multiple instances of each service
-- - Load balancing across replicas
-- - Health tracking in cache
--
-- USAGE (from the repository root):
--   socketley --lua examples/advanced/high-availability.lua
--
-- WHY THE CALLBACKS ARE IN high-availability-handler.lua
--
-- This file runs in the CLI process.  socketley reads `daemon` and `runtimes`
-- out of it, emits `create` commands, and exits -- it never reaches the
-- daemon.  A callback written here would never be loaded and never called.
-- The `config` key is what attaches a handler: it becomes `--lua <path>` on
-- the create, and the DAEMON opens that path against its own working
-- directory, which is why it is spelled from the repository root.  An
-- absolute path always works.
--
-- =============================================================================

local HANDLER = "examples/advanced/high-availability-handler.lua"

runtimes = {
    -- Health tracking cache
    {
        type = "cache",
        name = "health-store",
        port = 9000,
        start = true
    },

    -- API Service - 3 replicas (group: api)
    {
        type = "server",
        name = "api-replica-1",
        port = 9001,
        mode = "inout",
        group = "api",
        config = HANDLER,
        start = true
    },
    {
        type = "server",
        name = "api-replica-2",
        port = 9002,
        mode = "inout",
        group = "api",
        config = HANDLER,
        start = true
    },
    {
        type = "server",
        name = "api-replica-3",
        port = 9003,
        mode = "inout",
        group = "api",
        config = HANDLER,
        start = true
    },

    -- Load Balancer — discovers API replicas via @api group
    {
        type = "proxy",
        name = "api-lb",
        port = 8080,
        protocol = "http",
        strategy = "round-robin",
        backends = { "@api" },
        config = HANDLER,
        start = true
    },

    -- Worker Service - 2 replicas (group: workers)
    {
        type = "server",
        name = "worker-replica-1",
        port = 9011,
        mode = "inout",
        group = "workers",
        config = HANDLER,
        start = true
    },
    {
        type = "server",
        name = "worker-replica-2",
        port = 9012,
        mode = "inout",
        group = "workers",
        config = HANDLER,
        start = true
    },

    -- Worker Load Balancer — discovers workers via @workers group
    {
        type = "proxy",
        name = "worker-lb",
        port = 8081,
        protocol = "tcp",
        strategy = "random",
        backends = { "@workers" },
        start = true
    }
}

--[[
Architecture:

                   API Requests                    Worker Tasks
                        |                               |
                        v                               v
              +-----------------+             +-----------------+
              |    api-lb       |             |   worker-lb     |
              |    :8080        |             |   :8081         |
              |  round-robin    |             |   random        |
              +--------+--------+             +--------+--------+
                       |                               |
        +--------------+--------------+         +------+------+
        v              v              v         v             v
+-------------+ +-------------+ +-------------+ +----------+ +----------+
| api-replica | | api-replica | | api-replica | | worker-1 | | worker-2 |
|      1      | |      2      | |      3      | |  :9011   | |  :9012   |
|   :9001     | |   :9002     | |   :9003     | +----------+ +----------+
+-------------+ +-------------+ +-------------+

                                +-------------+
                                |health-store |
                                |   :9000     |
                                +-------------+

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
  socketley create server api-replica-4 -p 9004 -g api -s \
    --lua examples/advanced/high-availability-handler.lua
  # api-lb automatically includes api-replica-4 via @api group

Cleanup:
  socketley stop api-lb worker-lb api-replica-1 api-replica-2 api-replica-3 worker-replica-1 worker-replica-2 health-store
  socketley remove api-lb worker-lb api-replica-1 api-replica-2 api-replica-3 worker-replica-1 worker-replica-2 health-store
]]
