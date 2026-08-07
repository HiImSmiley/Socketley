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

-- The path on_route is handed is the one the CLIENT sent, and it still carries
-- this proxy's own "/<name>/" prefix -- the proxy strips that only on the way
-- to the backend.  "^/users" therefore never matches "/api-gateway/users", so
-- strip the prefix once and write the patterns against what the services
-- actually serve.
local PREFIX = "/" .. self.name

local function backend_path(p)
    if p:sub(1, #PREFIX) ~= PREFIX then return p end
    local rest = p:sub(#PREFIX + 1)
    return rest ~= "" and rest or "/"
end

-- Route requests to the appropriate service.
--
-- method and raw_path arrive on --protocol http only.  A TCP proxy calls
-- on_route with no arguments at all, so the match below would raise there on
-- the first request -- this handler belongs to an HTTP gateway, nothing else.
function on_route(method, raw_path)
    local path = backend_path(raw_path)

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
