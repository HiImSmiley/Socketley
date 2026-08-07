-- =============================================================================
-- logging-pipeline-handler.lua - Enrich and count what each service logs
-- =============================================================================
--
-- The handler logging-pipeline.lua attaches to the collector and to the three
-- application servers.  Each loads it into its own interpreter, so the counter
-- below is per-runtime and `self` is whichever runtime is running the
-- callback.
--
-- os.date() is available here -- the handler sandbox keeps os.time, os.clock,
-- os.date and os.difftime, and removes only os.execute, os.remove, os.rename,
-- os.tmpname and os.exit.
--
-- =============================================================================

local log_count = 0

function on_start()
    if self.name == "log-collector" then
        socketley.log("=== Centralized Logging Pipeline ===")
        socketley.log("  Collector: localhost:9999  (mode 'in': receives only)")
        socketley.log("  Metrics:   localhost:9998  (cache)")
        socketley.log("  Aggregated file: /tmp/socketley-central-logs/all-logs.log")
    end

    socketley.log(string.format("[%s] %s started on port %d",
        os.date("%Y-%m-%d %H:%M:%S"), self.name, self.port))
end

function on_message(msg)
    log_count = log_count + 1

    -- Parse and enrich the log line
    socketley.log(string.format("[%s] [%s] #%d %s",
        os.date("%Y-%m-%d %H:%M:%S"), self.name, log_count, msg))

    -- The collector is mode="in" and broadcasts nothing by design.  The
    -- application servers default to inout, and defining on_message CLAIMS
    -- message handling -- their default broadcast is suppressed unless it is
    -- done here.  Counting a message was not meant to stop it being delivered.
    if self.name ~= "log-collector" then
        self.broadcast(msg)
    end

    -- The counter stays in this process.  A server has no self.set: those are
    -- cache bindings, and cache = "log-metrics" in the configuration links the
    -- cache for this server's CLIENTS ("cache get log:total"), not for its
    -- Lua.  The line itself has already been archived into log-metrics under
    -- an integer key by the link -- `nc localhost 9998` then `get 1` reads it
    -- back.  socketley stats is where the counters are read from.
end

function on_stop()
    socketley.log("[" .. self.name .. "] Stopping. Logs processed: " .. log_count)
end
