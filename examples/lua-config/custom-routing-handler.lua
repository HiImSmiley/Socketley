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

-- The path on_route is handed is the one the CLIENT sent, and it still carries
-- this proxy's own "/<name>/" prefix -- the proxy strips that only on the way
-- to the backend.  A pattern anchored "^/api/" therefore never matches
-- "/smart-router/api/users", and every request falls through to the default.
-- Strip the prefix once, here, and write the patterns against the paths the
-- backends actually serve.
local PREFIX = "/" .. self.name

local function backend_path(p)
    if p:sub(1, #PREFIX) ~= PREFIX then return p end
    local rest = p:sub(#PREFIX + 1)
    return rest ~= "" and rest or "/"
end

-- =============================================================================
-- CALLBACK: on_route
-- Triggered for each HTTP request in 'lua' strategy mode
-- Parameters:
--   method - HTTP method (GET, POST, PUT, DELETE, etc.)
--   path   - Request path AS THE CLIENT SENT IT: "/smart-router/api/users",
--            not "/api/users".  See backend_path() above.
--     Both arguments arrive on --protocol http only.  A TCP proxy has no
--     request line to read them from and calls on_route with NO arguments, so
--     `path:match(...)` below would raise there on the first request.
-- Returns:
--   Backend index (0-based).  Anything else -- a raise, a nil, an index past
--   the end of the backend list -- is logged and the proxy falls back to the
--   pick it would have made anyway.  The request is forwarded either way;
--   refusing one is the filter chain's job, not this callback's.
-- =============================================================================
function on_route(method, raw_path)
    local path = backend_path(raw_path)
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
