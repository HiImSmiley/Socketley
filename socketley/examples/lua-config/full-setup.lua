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
-- USAGE:
--   socketley --config full-setup.lua
--
-- =============================================================================

-- Configuration
local CONFIG = {
    log_dir = "/tmp/socketley-logs",
    cache_file = "/tmp/socketley-state.bin",
    base_port = 9000
}

-- Ensure log directory exists (via shell)
os.execute("mkdir -p " .. CONFIG.log_dir)

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
        autostart = true
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
        autostart = true
    },
    {
        type = "server",
        name = "user-service",
        port = CONFIG.base_port + 2,
        mode = "inout",
        log = CONFIG.log_dir .. "/user-service.log",
        write = CONFIG.log_dir .. "/user-messages.log",
        autostart = true
    },
    {
        type = "server",
        name = "order-service",
        port = CONFIG.base_port + 3,
        mode = "inout",
        log = CONFIG.log_dir .. "/order-service.log",
        write = CONFIG.log_dir .. "/order-messages.log",
        autostart = true
    },

    -- =========================================================================
    -- LAYER 3: API Gateway (Proxy)
    -- =========================================================================
    {
        type = "proxy",
        name = "api-gateway",
        port = 8080,
        protocol = "http",
        strategy = "lua",
        backends = {
            "auth-service",   -- 0
            "user-service",   -- 1
            "order-service"   -- 2
        },
        log = CONFIG.log_dir .. "/api-gateway.log",
        autostart = true
    },

    -- =========================================================================
    -- LAYER 4: Inter-service Communication Clients
    -- =========================================================================
    {
        type = "client",
        name = "service-mesh-auth",
        target = "127.0.0.1:" .. (CONFIG.base_port + 1),
        mode = "inout",
        autostart = true
    },
    {
        type = "client",
        name = "service-mesh-user",
        target = "127.0.0.1:" .. (CONFIG.base_port + 2),
        mode = "inout",
        autostart = true
    }
}

-- =============================================================================
-- ROUTING LOGIC
-- =============================================================================
function on_route(method, path)
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
local startup_time = os.time()
local request_count = 0

function on_start()
    socketley.log("[" .. self.name .. "] Started")

    if self.name == "api-gateway" then
        socketley.log("=== API Gateway Ready ===")
        socketley.log("Listening on http://localhost:8080")
        socketley.log("")
        socketley.log("Routes:")
        socketley.log("  /api-gateway/auth/*    → auth-service:9001")
        socketley.log("  /api-gateway/users/*   → user-service:9002")
        socketley.log("  /api-gateway/orders/*  → order-service:9003")
    end

    if self.name == "state-store" then
        -- Initialize counters
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
end

--[[
=== FULL SETUP ARCHITECTURE ===

                    ┌─────────────────────────────────────────┐
                    │           Internet / Clients            │
                    └─────────────────┬───────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │         api-gateway:8080                │
                    │         (HTTP Proxy, Lua routing)       │
                    └────┬──────────┬──────────────┬──────────┘
                         │          │              │
           ┌─────────────┘          │              └─────────────┐
           ▼                        ▼                            ▼
┌──────────────────┐    ┌──────────────────┐        ┌──────────────────┐
│ auth-service     │    │ user-service     │        │ order-service    │
│ :9001            │    │ :9002            │        │ :9003            │
└────────┬─────────┘    └────────┬─────────┘        └────────┬─────────┘
         │                       │                           │
         └───────────────┬───────┴───────────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ state-store:9000    │
              │ (Persistent Cache)  │
              └─────────────────────┘

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
