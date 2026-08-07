-- =============================================================================
-- multi-backend-handler.lua - Method- and path-based backend selection
-- =============================================================================
--
-- The handler multi-backend.lua attaches to the smart-proxy runtime.  The
-- daemon loads it into that proxy's own interpreter, and `self` is the proxy.
--
-- Standalone:
--   socketley create proxy smart-proxy -p 8080 --protocol http \
--     --strategy lua \
--     --backend 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 \
--     --lua examples/proxy/multi-backend-handler.lua -s
--
-- --strategy lua is what makes on_route be consulted at all.  A proxy without
-- it loads this file, routes round-robin, and reports nothing.
--
-- =============================================================================

-- The path on_route is handed is the one the CLIENT sent, and it still carries
-- this proxy's own "/<name>/" prefix -- the proxy strips that only on the way
-- to the backend.  "^/admin" therefore never matches "/smart-proxy/admin/x",
-- so strip the prefix once and write the patterns against what the backends
-- actually serve.
local PREFIX = "/" .. self.name

local function backend_path(p)
    if p:sub(1, #PREFIX) ~= PREFIX then return p end
    local rest = p:sub(#PREFIX + 1)
    return rest ~= "" and rest or "/"
end

-- Custom routing logic
-- Parameters:
--   method:   HTTP method (GET, POST, PUT, DELETE, etc.)
--   raw_path: Request path AS THE CLIENT SENT IT -- "/smart-proxy/api/users",
--             not "/api/users".
--   Both arrive on --protocol http only.  A TCP proxy has no request line and
--   calls on_route with NO arguments, so the match below would raise there.
-- Returns:
--   Backend index (0-based).  A raise, or an index outside the backend list,
--   is logged and the proxy falls back to the pick it would have made anyway;
--   the request is forwarded either way.  Refusing one is the filter chain's
--   job -- see filter-chain.lua.
function on_route(method, raw_path)
    local path = backend_path(raw_path)
    socketley.log("Routing: " .. method .. " " .. raw_path .. " (as " .. path .. ")")

    -- Admin routes go to admin-backend
    if path:match("^/admin") then
        socketley.log(" -> admin-backend (index 2)")
        return 2
    end

    -- Write operations go to write-backend
    if method == "POST" or method == "PUT" or method == "DELETE" then
        socketley.log(" -> write-backend (index 1)")
        return 1
    end

    -- All other requests (GET, HEAD, OPTIONS) go to read-backend
    socketley.log(" -> read-backend (index 0)")
    return 0
end

function on_start()
    socketley.log("Smart proxy started with custom routing")
    socketley.log("  /admin/*        -> admin-backend:9003")
    socketley.log("  POST/PUT/DELETE -> write-backend:9002")
    socketley.log("  GET/HEAD/...    -> read-backend:9001")

    -- self.backends() is 1-based like every Lua array; on_route returns a
    -- 0-based index.  Index n above selects self.backends()[n + 1].
    local addrs = self.backends()
    for i = 1, #addrs do
        socketley.log("  on_route " .. (i - 1) .. " -> " .. addrs[i])
    end
end
