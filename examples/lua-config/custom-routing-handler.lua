-- =============================================================================
-- custom-routing-handler.lua - on_route for the smart-router proxy
-- =============================================================================
--
-- The runtime handler that custom-routing.lua attaches to the proxy.
--
-- on_route is consulted only when the proxy was created --strategy lua.  On a
-- round-robin or random proxy this file loads, reports nothing, and changes
-- nothing -- which is the usual reason an on_route "that works" appears to do
-- nothing at all.
--
-- Standalone:
--   socketley create proxy smart-router -p 8080 --protocol http \
--     --strategy lua --backend 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 \
--     --lua examples/lua-config/custom-routing-handler.lua -s
--
-- =============================================================================

-- on_route is handed both paths: `raw_path` as the client sent it, prefix
-- and all, and `path` with this proxy's own "/<name>/" prefix already
-- removed -- which is what the backend receives and what the patterns
-- below are written against.  This file used to compute the second from
-- the first; the proxy knows it, so it hands it over.

-- =============================================================================
-- CALLBACK: on_route
-- Triggered for each HTTP request in 'lua' strategy mode
-- Parameters:
--   method   - HTTP method (GET, POST, PUT, DELETE, etc.)
--   raw_path - Request path AS THE CLIENT SENT IT: "/smart-router/api/users".
--              The filter chain is handed the same one.
--   path     - the same request with this proxy's "/<name>/" prefix removed:
--              "/api/users".  That is what the backend receives, and what the
--              patterns below are written against.
--     All three arrive on --protocol http only.  A TCP proxy has no request
--     line to read them from and calls on_route with NO arguments, so
--     `path:match(...)` below would raise there on the first request.
-- Returns:
--   Backend index (0-based).  Anything else -- a raise, a nil, an index past
--   the end of the backend list -- is logged and the proxy falls back to the
--   pick it would have made anyway.  The request is forwarded either way;
--   refusing one is the filter chain's job, not this callback's.
-- =============================================================================
function on_route(method, raw_path, path)
    socketley.log("Routing: " .. method .. " " .. raw_path .. " (as " .. path .. ")")

    -- Static content: images, CSS, JS, fonts
    if path:match("%.css$") or
       path:match("%.js$") or
       path:match("%.png$") or
       path:match("%.jpg$") or
       path:match("%.woff") or
       path:match("^/static/") then
        socketley.log(" -> static-backend")
        return 0
    end

    -- Compute-heavy operations
    if path:match("^/compute/") or
       path:match("^/ml/") or
       path:match("^/analytics/") then
        socketley.log(" -> compute-backend")
        return 2
    end

    -- API requests
    if path:match("^/api/") or
       path:match("^/v1/") or
       path:match("^/v2/") then
        socketley.log(" -> api-backend")
        return 1
    end

    -- Health checks to API
    if path == "/health" or path == "/status" then
        socketley.log(" -> api-backend (health)")
        return 1
    end

    -- Default: static backend for everything else
    socketley.log(" -> static-backend (default)")
    return 0
end

function on_start()
    socketley.log("Smart router started")
    socketley.log("Routing rules:")

    -- self.backends() is 1-based, the way every Lua array is, while on_route
    -- returns a 0-based index -- so the address on_route picks with n is
    -- self.backends()[n + 1].  Printing them together is the cheapest way to
    -- catch an off-by-one before it becomes a mystery in production.
    local addrs = self.backends()
    for i = 1, #addrs do
        socketley.log("  on_route " .. (i - 1) .. " -> " .. addrs[i])
    end
end
