-- =============================================================================
-- logging-pipeline.lua - Centralized Logging
-- =============================================================================
--
-- Demonstrates a centralized logging setup:
-- - All services send logs to a central collector
-- - Logs are persisted and searchable
-- - Real-time log streaming
--
-- USAGE:
--   socketley --lua logging-pipeline.lua
--
-- =============================================================================

local LOG_DIR = "/tmp/socketley-central-logs"
os.execute("mkdir -p " .. LOG_DIR)

runtimes = {
    -- Central log collector (receives logs from all services)
    {
        type = "server",
        name = "log-collector",
        port = 9999,
        mode = "in",  -- Only receives, no broadcasts
        write = LOG_DIR .. "/all-logs.log",
        autostart = true
    },

    -- Log aggregation cache (for metrics/counts)
    {
        type = "cache",
        name = "log-metrics",
        port = 9998,
        persistent = LOG_DIR .. "/metrics.bin",
        autostart = true
    },

    -- Application services with log forwarding
    {
        type = "server",
        name = "web-app",
        port = 9001,
        log = LOG_DIR .. "/web-app.log",
        autostart = true
    },
    {
        type = "server",
        name = "api-app",
        port = 9002,
        log = LOG_DIR .. "/api-app.log",
        autostart = true
    },
    {
        type = "server",
        name = "worker-app",
        port = 9003,
        log = LOG_DIR .. "/worker-app.log",
        autostart = true
    },

    -- Log forwarders (clients that send to collector)
    {
        type = "client",
        name = "web-log-forwarder",
        target = "127.0.0.1:9999",
        mode = "out",  -- Only sends
        autostart = true
    },
    {
        type = "client",
        name = "api-log-forwarder",
        target = "127.0.0.1:9999",
        mode = "out",
        autostart = true
    },
    {
        type = "client",
        name = "worker-log-forwarder",
        target = "127.0.0.1:9999",
        mode = "out",
        autostart = true
    }
}

-- Log counters
local log_counts = {
    total = 0,
    by_service = {}
}

function on_start()
    if self.name == "log-collector" then
        socketley.log("╔════════════════════════════════════════════╗")
        socketley.log("║       Centralized Logging Pipeline         ║")
        socketley.log("╠════════════════════════════════════════════╣")
        socketley.log("║  Collector: localhost:9999                 ║")
        socketley.log("║  Metrics:   localhost:9998                 ║")
        socketley.log("╠════════════════════════════════════════════╣")
        socketley.log("║  Log files: " .. LOG_DIR)
        socketley.log("║  - all-logs.log (aggregated)               ║")
        socketley.log("║  - web-app.log                             ║")
        socketley.log("║  - api-app.log                             ║")
        socketley.log("║  - worker-app.log                          ║")
        socketley.log("╚════════════════════════════════════════════╝")
    end

    -- Initialize service counter
    if not log_counts.by_service[self.name] then
        log_counts.by_service[self.name] = 0
    end

    -- Log startup
    local startup_msg = string.format("[%s] %s started on port %d",
        os.date("%Y-%m-%d %H:%M:%S"), self.name, self.port)
    socketley.log(startup_msg)
end

function on_message(msg)
    log_counts.total = log_counts.total + 1
    log_counts.by_service[self.name] = (log_counts.by_service[self.name] or 0) + 1

    -- Parse and enrich log message
    local enriched = string.format("[%s] [%s] %s",
        os.date("%Y-%m-%d %H:%M:%S"), self.name, msg)

    socketley.log(enriched)

    -- Update metrics in cache
    if self.set then
        self.set("log:total", tostring(log_counts.total))
        self.set("log:" .. self.name, tostring(log_counts.by_service[self.name]))
    end
end

function on_stop()
    socketley.log("[" .. self.name .. "] Stopping. Total logs processed: " ..
        (log_counts.by_service[self.name] or 0))
end

--[[
Architecture:

┌──────────┐  ┌──────────┐  ┌──────────┐
│ web-app  │  │ api-app  │  │worker-app│
│  :9001   │  │  :9002   │  │  :9003   │
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │
     ▼             ▼             ▼
┌──────────┐  ┌──────────┐  ┌──────────┐
│ web-log  │  │ api-log  │  │worker-log│
│forwarder │  │forwarder │  │forwarder │
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │
     └─────────────┼─────────────┘
                   │
                   ▼
          ┌────────────────┐
          │  log-collector │
          │     :9999      │
          │ (all-logs.log) │
          └────────┬───────┘
                   │
                   ▼
          ┌────────────────┐
          │  log-metrics   │
          │     :9998      │
          └────────────────┘

Watch logs in real-time:
  tail -f /tmp/socketley-central-logs/all-logs.log

Check metrics (connect to cache and query):
  # Total logs
  # Logs by service

Cleanup:
  socketley stop log-collector log-metrics web-app api-app worker-app web-log-forwarder api-log-forwarder worker-log-forwarder
  socketley remove log-collector log-metrics web-app api-app worker-app web-log-forwarder api-log-forwarder worker-log-forwarder
  rm -rf /tmp/socketley-central-logs
]]
