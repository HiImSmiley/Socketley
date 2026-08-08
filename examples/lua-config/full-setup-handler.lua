-- =============================================================================
-- full-setup-handler.lua - The handler every full-setup.lua runtime attaches
-- =============================================================================
--
-- One file, loaded by the daemon into each runtime that names it.  Each gets
-- its OWN interpreter, so the locals below are per-runtime and `self` is
-- whichever runtime is running the callback.  That is why every body branches
-- on self.name rather than assuming one.
--
-- =============================================================================

-- Per-runtime state.  Each runtime has its own copy of these.
local startup_time  = os.time()   -- the whole os table is here; a handler is not sandboxed
local request_count = 0

-- on_route is handed both paths: `raw_path` as the client sent it, prefix
-- and all, and `path` with this proxy's own "/<name>/" prefix already
-- removed -- which is what the backend receives and what the patterns
-- below are written against.  This file used to compute the second from
-- the first; the proxy knows it, so it hands it over.

-- =============================================================================
-- ROUTING LOGIC (api-gateway only; needs --strategy lua, which the config sets)
-- =============================================================================
function on_route(method, raw_path, path)

    -- Authentication endpoints
    if path:match("^/auth") or
       path:match("^/login") or
       path:match("^/logout") or
       path:match("^/token") then
        return 0  -- auth-service
    end

    -- User management endpoints
    if path:match("^/users") or
       path:match("^/profile") or
       path:match("^/account") then
        return 1  -- user-service
    end

    -- Order/transaction endpoints
    if path:match("^/orders") or
       path:match("^/cart") or
       path:match("^/checkout") or
       path:match("^/payment") then
        return 2  -- order-service
    end

    -- Default to user-service
    return 1
end

-- =============================================================================
-- LIFECYCLE CALLBACKS
-- =============================================================================
function on_start()
    socketley.log("[" .. self.name .. "] Started")

    if self.name == "api-gateway" then
        socketley.log("=== API Gateway Ready ===")
        socketley.log("Listening on http://localhost:8080")
        socketley.log("Routes:")
        socketley.log("  /api-gateway/auth/*    -> auth-service:9001")
        socketley.log("  /api-gateway/users/*   -> user-service:9002")
        socketley.log("  /api-gateway/orders/*  -> order-service:9003")
    end

    if self.name == "state-store" then
        -- self.get/set/del are CACHE bindings.  They exist here because this
        -- runtime is the cache; on a server they are not bound at all, and a
        -- server reaches a cache with --cache <name> and the wire protocol
        -- ("cache set foo bar") instead.
        self.set("stats:startup_time", tostring(startup_time))
        self.set("stats:request_count", "0")
    end
end

function on_stop()
    socketley.log("[" .. self.name .. "] Stopped")

    if self.name == "state-store" then
        local uptime = os.time() - startup_time
        socketley.log("Uptime: " .. uptime .. " seconds")
        socketley.log("Total requests: " .. request_count)
    end
end

function on_message(msg)
    request_count = request_count + 1
    socketley.log("[" .. self.name .. "] Message #" .. request_count .. ": " .. msg:sub(1, 50))

    -- Defining on_message CLAIMS message handling: the default broadcast these
    -- servers would do in mode="inout" is suppressed.  Counting messages was
    -- never meant to stop them being delivered, so relay explicitly.
    if self.type == "server" then
        self.broadcast(msg)
    end
end
