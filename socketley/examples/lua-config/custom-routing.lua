-- =============================================================================
-- custom-routing.lua - Lua-Based Proxy Routing
-- =============================================================================
--
-- Demonstrates the on_route() callback for custom proxy routing logic.
-- This allows dynamic backend selection based on HTTP method and path.
--
-- USAGE:
--   socketley --lua custom-routing.lua
--
-- =============================================================================

runtimes = {
    -- Backend: Fast cache for static content
    {
        type = "server",
        name = "static-backend",
        port = 9001,
        autostart = true
    },
    -- Backend: API server for dynamic content
    {
        type = "server",
        name = "api-backend",
        port = 9002,
        autostart = true
    },
    -- Backend: Heavy compute tasks
    {
        type = "server",
        name = "compute-backend",
        port = 9003,
        autostart = true
    },
    -- Smart proxy with Lua routing
    {
        type = "proxy",
        name = "smart-router",
        port = 8080,
        protocol = "http",
        strategy = "lua",  -- Enable Lua routing
        backends = {
            "127.0.0.1:9001",  -- 0: static
            "127.0.0.1:9002",  -- 1: api
            "127.0.0.1:9003"   -- 2: compute
        },
        autostart = true
    }
}

-- =============================================================================
-- CALLBACK: on_route
-- Triggered for each HTTP request in 'lua' strategy mode
-- Parameters:
--   method - HTTP method (GET, POST, PUT, DELETE, etc.)
--   path   - Request path (e.g., /api/users)
-- Returns:
--   Backend index (0-based) or nil for round-robin default
-- =============================================================================
function on_route(method, path)
    socketley.log("Routing: " .. method .. " " .. path)

    -- Static content: images, CSS, JS, fonts
    if path:match("%.css$") or
       path:match("%.js$") or
       path:match("%.png$") or
       path:match("%.jpg$") or
       path:match("%.woff") or
       path:match("^/static/") then
        socketley.log(" → static-backend")
        return 0
    end

    -- Compute-heavy operations
    if path:match("^/compute/") or
       path:match("^/ml/") or
       path:match("^/analytics/") then
        socketley.log(" → compute-backend")
        return 2
    end

    -- API requests
    if path:match("^/api/") or
       path:match("^/v1/") or
       path:match("^/v2/") then
        socketley.log(" → api-backend")
        return 1
    end

    -- Health checks to API
    if path == "/health" or path == "/status" then
        socketley.log(" → api-backend (health)")
        return 1
    end

    -- Default: static backend for everything else
    socketley.log(" → static-backend (default)")
    return 0
end

function on_start()
    if self.type == "proxy" then
        socketley.log("Smart router started")
        socketley.log("Routing rules:")
        socketley.log("  /static/*, *.css, *.js, images → static-backend:9001")
        socketley.log("  /api/*, /v1/*, /v2/*          → api-backend:9002")
        socketley.log("  /compute/*, /ml/*, /analytics → compute-backend:9003")
    end
end

--[[
Test:
  # Static content → static-backend
  curl localhost:8080/smart-router/static/logo.png
  curl localhost:8080/smart-router/styles/main.css

  # API calls → api-backend
  curl localhost:8080/smart-router/api/users
  curl localhost:8080/smart-router/v1/products

  # Compute tasks → compute-backend
  curl localhost:8080/smart-router/compute/process
  curl localhost:8080/smart-router/ml/predict

Cleanup:
  socketley stop smart-router static-backend api-backend compute-backend
  socketley remove smart-router static-backend api-backend compute-backend
]]
