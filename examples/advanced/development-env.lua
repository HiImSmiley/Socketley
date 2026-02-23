-- =============================================================================
-- development-env.lua - Local Development Environment
-- =============================================================================
--
-- A complete local development setup with:
-- - Frontend proxy
-- - Backend API server
-- - Database cache mock
-- - Hot reload simulation via callbacks
--
-- USAGE:
--   socketley --lua development-env.lua
--
-- =============================================================================

local DEV_DIR = "/tmp/socketley-dev"
os.execute("mkdir -p " .. DEV_DIR)

runtimes = {
    -- Mock database (persistent cache)
    {
        type = "cache",
        name = "dev-db",
        port = 5432,  -- Familiar port
        persistent = DEV_DIR .. "/dev-db.bin",
        start = true
    },

    -- Backend API server
    {
        type = "server",
        name = "dev-api",
        port = 3001,
        mode = "inout",
        log = DEV_DIR .. "/api.log",
        start = true
    },

    -- WebSocket server (for real-time updates)
    {
        type = "server",
        name = "dev-ws",
        port = 3002,
        mode = "inout",
        log = DEV_DIR .. "/ws.log",
        start = true
    },

    -- Development proxy (combines all services)
    {
        type = "proxy",
        name = "dev-proxy",
        port = 3000,
        protocol = "http",
        strategy = "lua",
        backends = {
            "dev-api",  -- 0: API
            "dev-ws"    -- 1: WebSocket
        },
        log = DEV_DIR .. "/proxy.log",
        start = true
    }
}

-- Route based on path
function on_route(method, path)
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
        print("")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║           Development Environment Ready                  ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║                                                          ║")
        print("║  Main entry point:  http://localhost:3000                ║")
        print("║                                                          ║")
        print("║  Routes:                                                 ║")
        print("║    /dev-proxy/api/*  → API server  (localhost:3001)      ║")
        print("║    /dev-proxy/ws/*   → WebSocket   (localhost:3002)      ║")
        print("║                                                          ║")
        print("║  Direct access:                                          ║")
        print("║    API:       http://localhost:3001                      ║")
        print("║    WebSocket: ws://localhost:3002                        ║")
        print("║    Database:  localhost:5432                             ║")
        print("║                                                          ║")
        print("║  Logs: " .. DEV_DIR .. "/")
        print("║                                                          ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print("")
    end

    -- Initialize dev database with sample data
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

-- Simulate request handling
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

--[[
Development Environment Layout:

                    ┌────────────────────────┐
                    │   http://localhost:3000│
                    │      (dev-proxy)       │
                    └───────────┬────────────┘
                                │
              ┌─────────────────┴─────────────────┐
              │                                   │
              ▼                                   ▼
    ┌──────────────────┐              ┌──────────────────┐
    │   dev-api:3001   │              │   dev-ws:3002    │
    │  (REST API)      │              │  (WebSocket)     │
    └────────┬─────────┘              └──────────────────┘
             │
             ▼
    ┌──────────────────┐
    │   dev-db:5432    │
    │  (Mock Database) │
    └──────────────────┘

Quick Tests:

# Test API
curl localhost:3000/dev-proxy/api/users
curl localhost:3000/dev-proxy/api/config

# Direct API access
curl localhost:3001

# Watch logs
tail -f /tmp/socketley-dev/*.log

Cleanup:
socketley stop dev-proxy dev-api dev-ws dev-db
socketley remove dev-proxy dev-api dev-ws dev-db
rm -rf /tmp/socketley-dev
]]
