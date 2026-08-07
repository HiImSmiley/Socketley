-- =============================================================================
-- microservices.lua - Microservice Architecture
-- =============================================================================
--
-- Demonstrates a typical microservice architecture:
-- - API Gateway for routing
-- - Multiple backend services
-- - Service-to-service communication
-- - Shared state via cache
--
-- USAGE (from the repository root):
--   socketley --lua examples/advanced/microservices.lua
--
-- WHY on_route IS IN microservices-handler.lua
--
-- This file runs in the CLI process: socketley reads `daemon` and `runtimes`,
-- emits `create` commands, and exits.  A callback written here would never be
-- loaded and never called.  The gateway asks for its handler with the `config`
-- key, which becomes `--lua <path>` on the create; the DAEMON opens that path
-- against its own working directory, hence the repository-root spelling.
--
-- strategy = "lua" is required for on_route to be consulted at all.  Without
-- it the gateway keeps round-robin and the handler silently does nothing.
--
-- =============================================================================

-- Service registry (simulated)
local services = {
    gateway     = { port = 8080, type = "proxy" },
    users       = { port = 9001, type = "server" },
    products    = { port = 9002, type = "server" },
    orders      = { port = 9003, type = "server" },
    inventory   = { port = 9004, type = "server" },
    cache       = { port = 9005, type = "cache" }
}

runtimes = {
    -- Shared cache for all services
    {
        type = "cache",
        name = "service-cache",
        port = services.cache.port,
        persistent = "/tmp/microservices-cache.bin",
        start = true
    },

    -- User Service (group: users)
    {
        type = "server",
        name = "user-service",
        port = services.users.port,
        mode = "inout",
        group = "users",
        start = true
    },

    -- Product Service (group: products)
    {
        type = "server",
        name = "product-service",
        port = services.products.port,
        mode = "inout",
        group = "products",
        start = true
    },

    -- Order Service (group: orders)
    {
        type = "server",
        name = "order-service",
        port = services.orders.port,
        mode = "inout",
        group = "orders",
        start = true
    },

    -- Inventory Service (group: inventory)
    {
        type = "server",
        name = "inventory-service",
        port = services.inventory.port,
        mode = "inout",
        group = "inventory",
        start = true
    },

    -- API Gateway — uses runtime names for Lua-routed backends,
    -- but each service is also grouped for horizontal scaling.
    -- To scale a service, just add more servers to its group:
    --   socketley create server user-service-2 -p 9006 -g users -s
    {
        type = "proxy",
        name = "api-gateway",
        port = services.gateway.port,
        protocol = "http",
        strategy = "lua",   -- REQUIRED: on_route is consulted under this only
        backends = {
            "user-service",       -- 0
            "product-service",    -- 1
            "order-service",      -- 2
            "inventory-service"   -- 3
        },
        config = "examples/advanced/microservices-handler.lua",
        start = true
    }
}

--[[
Architecture:

                        +------------------+
                        |  api-gateway     |
                        |  :8080           |
                        +--------+---------+
                                 |
        +------------+-----------+-----------+------------+
        v            v           v           v            v
+----------+  +----------+  +----------+  +----------+  +----------+
|  users   |  | products |  |  orders  |  |inventory |  |  cache   |
|  :9001   |  |  :9002   |  |  :9003   |  |  :9004   |  |  :9005   |
+----------+  +----------+  +----------+  +----------+  +----------+

Test:
  curl localhost:8080/api-gateway/users
  curl localhost:8080/api-gateway/products
  curl localhost:8080/api-gateway/orders
  curl localhost:8080/api-gateway/inventory

Cleanup:
  socketley stop api-gateway user-service product-service order-service inventory-service service-cache
  socketley remove api-gateway user-service product-service order-service inventory-service service-cache
]]
