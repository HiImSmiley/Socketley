-- =============================================================================
-- custom-routing.lua - Lua-Based Proxy Routing
-- =============================================================================
--
-- Creates three backends and a proxy that picks between them from Lua.
--
-- USAGE (from the repository root):
--   socketley --lua examples/lua-config/custom-routing.lua
--
-- TWO THINGS THIS FILE CANNOT DO ITSELF
--
-- 1. It cannot hold on_route.  This file runs in the CLI process, which reads
--    `daemon` and `runtimes` and exits; a callback written here is never
--    loaded and never called.  on_route lives in custom-routing-handler.lua,
--    which the proxy asks for with the `config` key below.  The daemon opens
--    that path relative to ITS working directory, so it is written from the
--    repository root; an absolute path always works.
--
-- 2. strategy = "lua" is not decoration.  on_route is consulted only under
--    --strategy lua.  Leave it out and the proxy keeps round-robin, never
--    looks the callback up, and the handler silently does nothing.
--
-- =============================================================================

runtimes = {
    -- Backend: Fast cache for static content
    {
        type = "server",
        name = "static-backend",
        port = 9001,
        start = true
    },
    -- Backend: API server for dynamic content
    {
        type = "server",
        name = "api-backend",
        port = 9002,
        start = true
    },
    -- Backend: Heavy compute tasks
    {
        type = "server",
        name = "compute-backend",
        port = 9003,
        start = true
    },
    -- Smart proxy with Lua routing
    {
        type = "proxy",
        name = "smart-router",
        port = 8080,
        protocol = "http",
        strategy = "lua",  -- REQUIRED: without it on_route is never consulted
        backends = {
            "127.0.0.1:9001",  -- 0: static
            "127.0.0.1:9002",  -- 1: api
            "127.0.0.1:9003"   -- 2: compute
        },
        config = "examples/lua-config/custom-routing-handler.lua",
        start = true
    }
}

--[[
Test:
  # Static content → static-backend
  curl localhost:8080/smart-router/static/logo.png
  curl localhost:8080/smart-router/styles/main.css

  # API calls → api-backend
  curl localhost:8080/smart-router/api/users
  curl localhost:8080/smart-router/v1/products

  # Compute tasks → compute-backend
  curl localhost:8080/smart-router/compute/process
  curl localhost:8080/smart-router/ml/predict

  # What the proxy is actually enforcing and relaying
  socketley stats smart-router

Cleanup:
  socketley stop smart-router static-backend api-backend compute-backend
  socketley remove smart-router static-backend api-backend compute-backend
]]
