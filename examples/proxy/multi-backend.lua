-- =============================================================================
-- multi-backend.lua - Custom Routing with Lua
-- =============================================================================
--
-- Demonstrates custom proxy routing using Lua callbacks.
-- The on_route() function determines which backend handles each request.
--
-- USAGE:
--   socketley --lua multi-backend.lua
--
-- =============================================================================

-- Define all runtimes
runtimes = {
    -- Backend for read operations
    {
        type = "server",
        name = "read-backend",
        port = 9001,
        start = true
    },
    -- Backend for write operations
    {
        type = "server",
        name = "write-backend",
        port = 9002,
        start = true
    },
    -- Backend for admin operations
    {
        type = "server",
        name = "admin-backend",
        port = 9003,
        start = true
    },
    -- Proxy with Lua-based routing
    {
        type = "proxy",
        name = "smart-proxy",
        port = 8080,
        protocol = "http",
        strategy = "lua",  -- Use Lua routing
        backends = {
            "127.0.0.1:9001",  -- Index 0: read-backend
            "127.0.0.1:9002",  -- Index 1: write-backend
            "127.0.0.1:9003"   -- Index 2: admin-backend
        },
        start = true
    }
}

-- Custom routing logic
-- Parameters:
--   method: HTTP method (GET, POST, PUT, DELETE, etc.)
--   path: Request path (e.g., /api/users)
-- Returns:
--   Backend index (0-based) or nil for default
function on_route(method, path)
    socketley.log("Routing: " .. method .. " " .. path)

    -- Admin routes go to admin-backend
    if path:match("^/admin") then
        socketley.log(" → admin-backend (index 2)")
        return 2
    end

    -- Write operations go to write-backend
    if method == "POST" or method == "PUT" or method == "DELETE" then
        socketley.log(" → write-backend (index 1)")
        return 1
    end

    -- All other requests (GET, HEAD, OPTIONS) go to read-backend
    socketley.log(" → read-backend (index 0)")
    return 0
end

function on_start()
    socketley.log("Smart proxy started with custom routing")
    socketley.log("Routes:")
    socketley.log("  /admin/*        → admin-backend:9003")
    socketley.log("  POST/PUT/DELETE → write-backend:9002")
    socketley.log("  GET/HEAD/...    → read-backend:9001")
end

--[[
Test commands:

# Read operations → read-backend
curl localhost:8080/smart-proxy/api/users
curl localhost:8080/smart-proxy/api/items

# Write operations → write-backend
curl -X POST localhost:8080/smart-proxy/api/users
curl -X PUT localhost:8080/smart-proxy/api/users/1
curl -X DELETE localhost:8080/smart-proxy/api/users/1

# Admin operations → admin-backend
curl localhost:8080/smart-proxy/admin/status
curl -X POST localhost:8080/smart-proxy/admin/restart

Cleanup:
socketley stop smart-proxy read-backend write-backend admin-backend
socketley remove smart-proxy read-backend write-backend admin-backend
]]
