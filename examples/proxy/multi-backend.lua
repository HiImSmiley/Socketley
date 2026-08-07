-- =============================================================================
-- multi-backend.lua - Custom Routing with Lua
-- =============================================================================
--
-- Creates three backends and a proxy that picks between them per request.
--
-- USAGE (from the repository root):
--   socketley --lua examples/proxy/multi-backend.lua
--
-- WHY on_route IS IN multi-backend-handler.lua
--
-- This file runs in the CLI process: socketley reads `daemon` and `runtimes`,
-- emits `create` commands, and exits.  A callback written here would never be
-- loaded and never called.  The proxy asks for its handler with the `config`
-- key, which becomes `--lua <path>` on the create; the DAEMON opens that path
-- against its own working directory, hence the repository-root spelling.  An
-- absolute path always works.
--
-- strategy = "lua" is required.  on_route is consulted under that strategy and
-- no other -- without it the proxy keeps round-robin, never looks the callback
-- up, and the handler silently does nothing.
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
        strategy = "lua",  -- REQUIRED: on_route is consulted under this only
        backends = {
            "127.0.0.1:9001",  -- Index 0: read-backend
            "127.0.0.1:9002",  -- Index 1: write-backend
            "127.0.0.1:9003"   -- Index 2: admin-backend
        },
        config = "examples/proxy/multi-backend-handler.lua",
        start = true
    }
}

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
