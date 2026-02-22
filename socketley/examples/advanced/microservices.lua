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
-- USAGE:
--   socketley --lua microservices.lua
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
        autostart = true
    },

    -- User Service (group: users)
    {
        type = "server",
        name = "user-service",
        port = services.users.port,
        mode = "inout",
        group = "users",
        autostart = true
    },

    -- Product Service (group: products)
    {
        type = "server",
        name = "product-service",
        port = services.products.port,
        mode = "inout",
        group = "products",
        autostart = true
    },

    -- Order Service (group: orders)
    {
        type = "server",
        name = "order-service",
        port = services.orders.port,
        mode = "inout",
        group = "orders",
        autostart = true
    },

    -- Inventory Service (group: inventory)
    {
        type = "server",
        name = "inventory-service",
        port = services.inventory.port,
        mode = "inout",
        group = "inventory",
        autostart = true
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
        strategy = "lua",
        backends = {
            "user-service",       -- 0
            "product-service",    -- 1
            "order-service",      -- 2
            "inventory-service"   -- 3
        },
        autostart = true
    }
}

-- Route requests to appropriate service
function on_route(method, path)
    local routes = {
        { pattern = "^/users",      backend = 0, name = "user-service" },
        { pattern = "^/auth",       backend = 0, name = "user-service" },
        { pattern = "^/products",   backend = 1, name = "product-service" },
        { pattern = "^/catalog",    backend = 1, name = "product-service" },
        { pattern = "^/orders",     backend = 2, name = "order-service" },
        { pattern = "^/checkout",   backend = 2, name = "order-service" },
        { pattern = "^/inventory",  backend = 3, name = "inventory-service" },
        { pattern = "^/stock",      backend = 3, name = "inventory-service" }
    }

    for _, route in ipairs(routes) do
        if path:match(route.pattern) then
            socketley.log(method .. " " .. path .. " → " .. route.name)
            return route.backend
        end
    end

    -- Default to user service
    return 0
end

function on_start()
    if self.name == "api-gateway" then
        socketley.log("╔════════════════════════════════════════╗")
        socketley.log("║     Microservices Architecture         ║")
        socketley.log("╠════════════════════════════════════════╣")
        socketley.log("║  Gateway: http://localhost:8080        ║")
        socketley.log("╠════════════════════════════════════════╣")
        socketley.log("║  Routes:                               ║")
        socketley.log("║    /users, /auth     → user-service    ║")
        socketley.log("║    /products, /catalog → product-svc   ║")
        socketley.log("║    /orders, /checkout → order-service  ║")
        socketley.log("║    /inventory, /stock → inventory-svc  ║")
        socketley.log("╚════════════════════════════════════════╝")
    end
end

--[[
Architecture:

                        ┌──────────────────┐
                        │  api-gateway     │
                        │  :8080           │
                        └────────┬─────────┘
                                 │
        ┌────────────┬───────────┼───────────┬────────────┐
        ▼            ▼           ▼           ▼            ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  users   │  │ products │  │  orders  │  │inventory │  │  cache   │
│  :9001   │  │  :9002   │  │  :9003   │  │  :9004   │  │  :9005   │
└──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘

Test:
  curl localhost:8080/api-gateway/users
  curl localhost:8080/api-gateway/products
  curl localhost:8080/api-gateway/orders
  curl localhost:8080/api-gateway/inventory

Cleanup:
  socketley stop api-gateway user-service product-service order-service inventory-service service-cache
  socketley remove api-gateway user-service product-service order-service inventory-service service-cache
]]
