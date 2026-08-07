-- =============================================================================
-- logging-pipeline.lua - Centralized Logging
-- =============================================================================
--
-- Demonstrates a centralized logging setup:
-- - All services send logs to a central collector
-- - Logs are persisted and searchable
-- - Real-time log streaming
--
-- USAGE (from the repository root):
--   mkdir -p /tmp/socketley-central-logs
--   socketley --lua examples/advanced/logging-pipeline.lua
--
-- WHY THE mkdir IS A SHELL COMMAND
--
-- This file is read by the CLI's own interpreter, which opens base, package
-- and table and nothing else.  There is no `os` here, so
--
--     os.execute("mkdir -p " .. LOG_DIR)
--
-- is `attempt to index global 'os' (a nil value)`: the file fails on that
-- line, exit 1, and not one runtime is created.  The daemon needs those
-- directories to exist before it opens the log files named below, so they are
-- made by the shell that runs this.
--
-- WHY THE CALLBACKS ARE IN logging-pipeline-handler.lua
--
-- socketley reads `daemon` and `runtimes` out of this file, emits `create`
-- commands, and exits.  Callbacks written here would never be loaded and never
-- called.  The `config` key attaches the handler -- it becomes `--lua <path>`
-- on the create, and the DAEMON opens that path against its own working
-- directory, hence the repository-root spelling.
--
-- =============================================================================

local LOG_DIR = "/tmp/socketley-central-logs"
local HANDLER = "examples/advanced/logging-pipeline-handler.lua"

runtimes = {
    -- Central log collector (receives logs from all services)
    {
        type = "server",
        name = "log-collector",
        port = 9999,
        mode = "in",  -- Only receives, no broadcasts
        write = LOG_DIR .. "/all-logs.log",
        config = HANDLER,
        start = true
    },

    -- Log aggregation cache (for metrics/counts)
    {
        type = "cache",
        name = "log-metrics",
        port = 9998,
        persistent = LOG_DIR .. "/metrics.bin",
        start = true
    },

    -- Application services with log forwarding.
    --
    -- cache = "log-metrics" does two things, and the second is the useful one
    -- for a logging pipeline:
    --
    --   1. A CLIENT of that server may run cache commands over the same
    --      connection: "cache get log:total".  It does NOT give the server's
    --      Lua handler self.get/self.set -- those are cache bindings and exist
    --      on a cache runtime only.
    --   2. Every ordinary message is ARCHIVED into log-metrics under an
    --      auto-incrementing integer key (1, 2, 3, ...) as well as being
    --      handled normally.  That is a searchable copy of every log line,
    --      which is what this pipeline wants -- but it is a write per message
    --      into a --persistent cache, so it grows without bound.  Give the
    --      cache a --maxmemory and an --eviction policy in production.
    {
        type = "server",
        name = "web-app",
        port = 9001,
        log = LOG_DIR .. "/web-app.log",
        cache = "log-metrics",
        config = HANDLER,
        start = true
    },
    {
        type = "server",
        name = "api-app",
        port = 9002,
        log = LOG_DIR .. "/api-app.log",
        cache = "log-metrics",
        config = HANDLER,
        start = true
    },
    {
        type = "server",
        name = "worker-app",
        port = 9003,
        log = LOG_DIR .. "/worker-app.log",
        cache = "log-metrics",
        config = HANDLER,
        start = true
    },

    -- Log forwarders (clients that send to collector)
    {
        type = "client",
        name = "web-log-forwarder",
        target = "127.0.0.1:9999",
        mode = "out",  -- Only sends
        start = true
    },
    {
        type = "client",
        name = "api-log-forwarder",
        target = "127.0.0.1:9999",
        mode = "out",
        start = true
    },
    {
        type = "client",
        name = "worker-log-forwarder",
        target = "127.0.0.1:9999",
        mode = "out",
        start = true
    }
}

--[[
Architecture:

+----------+  +----------+  +----------+
| web-app  |  | api-app  |  |worker-app|
|  :9001   |  |  :9002   |  |  :9003   |
+----+-----+  +----+-----+  +----+-----+
     |             |             |
     v             v             v
+----------+  +----------+  +----------+
| web-log  |  | api-log  |  |worker-log|
|forwarder |  |forwarder |  |forwarder |
+----+-----+  +----+-----+  +----+-----+
     |             |             |
     +-------------+-------------+
                   |
                   v
          +----------------+
          |  log-collector |
          |     :9999      |
          | (all-logs.log) |
          +--------+-------+
                   |
                   v
          +----------------+
          |  log-metrics   |
          |     :9998      |
          +----------------+

Watch logs in real-time:
  tail -f /tmp/socketley-central-logs/all-logs.log

Check metrics (the cache is a runtime like any other):
  socketley stats log-metrics
  nc localhost 9998        # then: get log:total

Cleanup:
  socketley stop log-collector log-metrics web-app api-app worker-app web-log-forwarder api-log-forwarder worker-log-forwarder
  socketley remove log-collector log-metrics web-app api-app worker-app web-log-forwarder api-log-forwarder worker-log-forwarder
  rm -rf /tmp/socketley-central-logs
]]
