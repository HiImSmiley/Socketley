-- =============================================================================
-- full-setup.lua - Complete Orchestration
-- =============================================================================
--
-- A complete production-like setup demonstrating all socketley features:
-- - Multiple servers with different modes
-- - Clients for inter-service communication
-- - Load-balanced proxy with custom routing
-- - Persistent cache for shared state
-- - Comprehensive logging and callbacks
--
-- USAGE (from the repository root):
--   mkdir -p /tmp/socketley-logs
--   socketley --lua examples/lua-config/full-setup.lua
--
-- WHY THE mkdir IS A SHELL COMMAND AND NOT A LINE IN THIS FILE
--
-- This file is read by the CLI's own interpreter, which opens base, package
-- and table -- and nothing else.  There is no `os` here at all, so
--
--     os.execute("mkdir -p " .. CONFIG.log_dir)
--
-- is not a sandbox refusal but `attempt to index global 'os' (a nil value)`:
-- the whole file fails on that line, exit 1, and not one runtime is created.
-- There is no `string` either, so `string.format` and `path:match()` are out.
-- Concatenation with `..` and tostring() are core and still work, which is all
-- the arithmetic below needs.
--
-- WHY THE CALLBACKS ARE IN full-setup-handler.lua
--
-- socketley reads `daemon` and `runtimes` out of this file, turns them into
-- `create` commands, and exits.  Callbacks written here would never be loaded
-- and never called.  The `config` key attaches the handler: it becomes
-- `--lua <path>` on the create, and the DAEMON opens that path against its own
-- working directory -- hence the repository-root spelling.  An absolute path
-- always works.
--
-- =============================================================================

-- Configuration
local CONFIG = {
    log_dir = "/tmp/socketley-logs",
    cache_file = "/tmp/socketley-state.bin",
    base_port = 9000,
    handler = "examples/lua-config/full-setup-handler.lua"
}

-- =============================================================================
-- RUNTIME DEFINITIONS
-- =============================================================================
runtimes = {
    -- =========================================================================
    -- LAYER 1: Data Layer (Cache)
    -- =========================================================================
    {
        type = "cache",
        name = "state-store",
        port = CONFIG.base_port,
        persistent = CONFIG.cache_file,
        log = CONFIG.log_dir .. "/state-store.log",
        config = CONFIG.handler,
        start = true
    },

    -- =========================================================================
    -- LAYER 2: Backend Services
    -- =========================================================================
    {
        type = "server",
        name = "auth-service",
        port = CONFIG.base_port + 1,
        mode = "inout",
        log = CONFIG.log_dir .. "/auth-service.log",
        write = CONFIG.log_dir .. "/auth-messages.log",
        config = CONFIG.handler,
        start = true
    },
    {
        type = "server",
        name = "user-service",
        port = CONFIG.base_port + 2,
        mode = "inout",
        log = CONFIG.log_dir .. "/user-service.log",
        write = CONFIG.log_dir .. "/user-messages.log",
        config = CONFIG.handler,
        start = true
    },
    {
        type = "server",
        name = "order-service",
        port = CONFIG.base_port + 3,
        mode = "inout",
        log = CONFIG.log_dir .. "/order-service.log",
        write = CONFIG.log_dir .. "/order-messages.log",
        config = CONFIG.handler,
        start = true
    },

    -- =========================================================================
    -- LAYER 3: API Gateway (Proxy)
    -- =========================================================================
    {
        type = "proxy",
        name = "api-gateway",
        port = 8080,
        protocol = "http",
        strategy = "lua",   -- REQUIRED: on_route is consulted under this only
        backends = {
            "auth-service",   -- 0
            "user-service",   -- 1
            "order-service"   -- 2
        },
        log = CONFIG.log_dir .. "/api-gateway.log",
        config = CONFIG.handler,
        start = true
    },

    -- =========================================================================
    -- LAYER 4: Inter-service Communication Clients
    -- =========================================================================
    {
        type = "client",
        name = "service-mesh-auth",
        target = "127.0.0.1:" .. (CONFIG.base_port + 1),
        mode = "inout",
        start = true
    },
    {
        type = "client",
        name = "service-mesh-user",
        target = "127.0.0.1:" .. (CONFIG.base_port + 2),
        mode = "inout",
        start = true
    }
}

--[[
=== FULL SETUP ARCHITECTURE ===

                    +-----------------------------------------+
                    |           Internet / Clients            |
                    +-----------------+-----------------------+
                                      |
                                      v
                    +-----------------------------------------+
                    |         api-gateway:8080                |
                    |         (HTTP Proxy, Lua routing)       |
                    +----+----------+--------------+----------+
                         |          |              |
           +-------------+          |              +-------------+
           v                        v                            v
+------------------+    +------------------+        +------------------+
| auth-service     |    | user-service     |        | order-service    |
| :9001            |    | :9002            |        | :9003            |
+--------+---------+    +--------+---------+        +--------+---------+
         |                       |                           |
         +---------------+-------+---------------------------+
                         |
                         v
              +---------------------+
              | state-store:9000    |
              | (Persistent Cache)  |
              +---------------------+

=== TEST COMMANDS ===

# Auth routes
curl localhost:8080/api-gateway/auth/login
curl localhost:8080/api-gateway/token/refresh

# User routes
curl localhost:8080/api-gateway/users
curl localhost:8080/api-gateway/profile/settings

# Order routes
curl localhost:8080/api-gateway/orders
curl localhost:8080/api-gateway/cart/items
curl localhost:8080/api-gateway/checkout

# Check logs
tail -f /tmp/socketley-logs/*.log

# View all runtimes
socketley ls

=== CLEANUP ===

socketley stop api-gateway auth-service user-service order-service state-store service-mesh-auth service-mesh-user
socketley remove api-gateway auth-service user-service order-service state-store service-mesh-auth service-mesh-user
rm -rf /tmp/socketley-logs /tmp/socketley-state.bin
]]
