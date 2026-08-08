-- =============================================================================
-- development-env-handler.lua - Routing, seed data and echo for the dev stack
-- =============================================================================
--
-- The handler development-env.lua attaches to all four runtimes.  Each loads
-- it into its own interpreter, so `self` is whichever runtime is running the
-- callback -- which is why every body branches on self.name.
--
-- =============================================================================

-- on_route is handed both paths: `raw_path` as the client sent it, prefix
-- and all, and `path` with this proxy's own "/<name>/" prefix already
-- removed -- which is what the backend receives and what the patterns
-- below are written against.  This file used to compute the second from
-- the first; the proxy knows it, so it hands it over.

-- Route based on path.  Consulted on dev-proxy only, and only because that
-- proxy was created --strategy lua.  method and raw_path arrive on --protocol
-- http only; a TCP proxy would call this with no arguments and the match
-- would raise.
function on_route(method, raw_path, path)

    -- WebSocket upgrades
    if path:match("^/ws") or path:match("^/socket") then
        return 1  -- dev-ws
    end

    -- API routes
    if path:match("^/api") then
        return 0  -- dev-api
    end

    -- Default to API
    return 0
end

function on_start()
    if self.name == "dev-proxy" then
        socketley.log("=== Development Environment Ready ===")
        socketley.log("  Main entry point: http://localhost:3000")
        socketley.log("  /dev-proxy/api/*  -> API server  (localhost:3001)")
        socketley.log("  /dev-proxy/ws/*   -> WebSocket   (localhost:3002)")
        socketley.log("  Direct: API 3001, WebSocket 3002, Database 5432")
        socketley.log("  Logs:   /tmp/socketley-dev/")
    end

    -- Initialize dev database with sample data.
    --
    -- self.get/set/del are CACHE bindings and exist only on a cache runtime.
    -- The same three lines on dev-api would be "attempt to call field 'set'
    -- (a nil value)" -- a server reaches a cache through --cache <name> and
    -- the "cache <command>" wire protocol, not through self.
    if self.name == "dev-db" then
        -- Sample users
        self.set("user:1", '{"id":1,"name":"Alice","email":"alice@dev.local"}')
        self.set("user:2", '{"id":2,"name":"Bob","email":"bob@dev.local"}')

        -- Sample config
        self.set("config:app_name", "Socketley Dev App")
        self.set("config:version", "1.0.0-dev")
        self.set("config:debug", "true")

        socketley.log("Dev database initialized with sample data")
    end
end

-- Simulate request handling.  Defining on_message claims message handling, so
-- each branch below broadcasts its own answer explicitly.
function on_message(msg)
    if self.name == "dev-api" then
        socketley.log("[API] " .. msg)

        -- Simple REST simulation
        if msg:match("^GET /users") then
            self.broadcast('{"users":[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]}')
        elseif msg:match("^GET /config") then
            self.broadcast('{"app":"Socketley Dev","debug":true}')
        else
            self.broadcast('{"status":"ok"}')
        end
    end

    if self.name == "dev-ws" then
        socketley.log("[WS] " .. msg)
        -- Echo for WebSocket testing
        self.broadcast('{"type":"echo","data":"' .. msg .. '"}')
    end
end
