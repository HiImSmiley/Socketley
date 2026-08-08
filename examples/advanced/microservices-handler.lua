-- =============================================================================
-- microservices-handler.lua - Path-to-service routing for the API gateway
-- =============================================================================
--
-- The handler microservices.lua attaches to the api-gateway proxy.  The daemon
-- loads it into that proxy's own interpreter, and `self` is the proxy.
--
-- on_route is consulted only under --strategy lua, which the configuration
-- sets.  On a round-robin proxy this file loads, reports nothing, and changes
-- nothing.
--
-- =============================================================================

-- on_route is handed both paths: `raw_path` as the client sent it, prefix
-- and all, and `path` with this proxy's own "/<name>/" prefix already
-- removed -- which is what the backend receives and what the patterns
-- below are written against.  This file used to compute the second from
-- the first; the proxy knows it, so it hands it over.

-- Route requests to the appropriate service.
--
-- method and raw_path arrive on --protocol http only.  A TCP proxy calls
-- on_route with no arguments at all, so the match below would raise there on
-- the first request -- this handler belongs to an HTTP gateway, nothing else.
function on_route(method, raw_path, path)

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
            socketley.log(method .. " " .. raw_path .. " -> " .. route.name)
            return route.backend
        end
    end

    -- Default to user service
    return 0
end

function on_start()
    socketley.log("=== Microservices Architecture ===")
    socketley.log("  Gateway: http://localhost:8080")
    socketley.log("  Routes:")
    socketley.log("    /users, /auth        -> user-service")
    socketley.log("    /products, /catalog  -> product-service")
    socketley.log("    /orders, /checkout   -> order-service")
    socketley.log("    /inventory, /stock   -> inventory-service")

    -- The indices on_route returns, against the addresses they select.
    -- self.backends() is 1-based like every Lua array while on_route is
    -- 0-based, so index n above is self.backends()[n + 1].
    local addrs = self.backends()
    for i = 1, #addrs do
        socketley.log("    on_route " .. (i - 1) .. " -> " .. addrs[i])
    end
end
