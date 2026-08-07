-- =============================================================================
-- development-env.lua - Local Development Environment
-- =============================================================================
--
-- A complete local development setup with:
-- - Frontend proxy
-- - Backend API server
-- - Database cache mock
-- - Sample data seeded on start
--
-- USAGE (from the repository root):
--   mkdir -p /tmp/socketley-dev
--   socketley --lua examples/advanced/development-env.lua
--
-- WHY THE mkdir IS A SHELL COMMAND
--
-- This file is read by the CLI's own interpreter, which opens base, package
-- and table and nothing else.  There is no `os` here, so
--
--     os.execute("mkdir -p " .. DEV_DIR)
--
-- is `attempt to index global 'os' (a nil value)`: the file fails on that
-- line, exit 1, and nothing is created.  The daemon opens the log files named
-- below, so the directory has to exist before this runs.
--
-- WHY THE CALLBACKS ARE IN development-env-handler.lua
--
-- socketley reads `daemon` and `runtimes` out of this file, emits `create`
-- commands, and exits.  Callbacks written here would never be loaded and
-- never called.  The `config` key attaches the handler -- it becomes
-- `--lua <path>` on the create, and the DAEMON opens that path against its own
-- working directory, hence the repository-root spelling.
--
-- =============================================================================

local DEV_DIR = "/tmp/socketley-dev"
local HANDLER = "examples/advanced/development-env-handler.lua"

runtimes = {
    -- Mock database (persistent cache)
    {
        type = "cache",
        name = "dev-db",
        port = 5432,  -- Familiar port
        persistent = DEV_DIR .. "/dev-db.bin",
        config = HANDLER,
        start = true
    },

    -- Backend API server
    {
        type = "server",
        name = "dev-api",
        port = 3001,
        mode = "inout",
        log = DEV_DIR .. "/api.log",
        config = HANDLER,
        start = true
    },

    -- WebSocket server (for real-time updates)
    {
        type = "server",
        name = "dev-ws",
        port = 3002,
        mode = "inout",
        log = DEV_DIR .. "/ws.log",
        config = HANDLER,
        start = true
    },

    -- Development proxy (combines all services)
    {
        type = "proxy",
        name = "dev-proxy",
        port = 3000,
        protocol = "http",
        strategy = "lua",   -- REQUIRED: on_route is consulted under this only
        backends = {
            "dev-api",  -- 0: API
            "dev-ws"    -- 1: WebSocket
        },
        log = DEV_DIR .. "/proxy.log",
        config = HANDLER,
        start = true
    }
}

--[[
Development Environment Layout:

                    +------------------------+
                    | http://localhost:3000  |
                    |      (dev-proxy)       |
                    +-----------+------------+
                                |
              +-----------------+-----------------+
              |                                   |
              v                                   v
    +------------------+              +------------------+
    |   dev-api:3001   |              |   dev-ws:3002    |
    |  (REST API)      |              |  (WebSocket)     |
    +--------+---------+              +------------------+
             |
             v
    +------------------+
    |   dev-db:5432    |
    |  (Mock Database) |
    +------------------+

Quick Tests:

# Test API
curl localhost:3000/dev-proxy/api/users
curl localhost:3000/dev-proxy/api/config

# Direct API access
curl localhost:3001

# Read the seeded rows straight out of the cache
nc localhost 5432        # then: get user:1

# Watch logs
tail -f /tmp/socketley-dev/*.log

Cleanup:
socketley stop dev-proxy dev-api dev-ws dev-db
socketley remove dev-proxy dev-api dev-ws dev-db
rm -rf /tmp/socketley-dev
]]
