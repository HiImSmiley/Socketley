-- =============================================================================
-- high-availability-handler.lua - Per-replica lifecycle logging
-- =============================================================================
--
-- The handler high-availability.lua attaches to every replica and to the API
-- load balancer.  Each runtime loads it into its OWN interpreter, so the local
-- below is per-runtime and `self` is whichever runtime is running the
-- callback -- which is why the bodies branch on self.name.
--
-- =============================================================================

-- Per-runtime start time.  Each replica keeps its own.
local started_at = nil

function on_start()
    started_at = os.time()

    if self.name:match("^api%-lb") then
        socketley.log("=== High Availability Setup ===")
        socketley.log("  API LB:    http://localhost:8080 (@api)")
        socketley.log("  Worker LB: tcp://localhost:8081 (@workers)")
        socketley.log("  API replicas:    3, round-robin over @api")
        socketley.log("  Worker replicas: 2, random over @workers")
        socketley.log("  Groups enable dynamic scaling: create another server")
        socketley.log("  with -g api and this proxy picks it up unrestarted.")

        -- Proxy-only bindings.  backend_health() is 1-based and in the same
        -- order as backends(); on_route's 0-based n is backends()[n + 1].
        -- A breaker only has a state once one is configured, so it is reported
        -- only when there is one -- an @group that has not resolved yet lists
        -- nothing here rather than inventing a row.
        local addrs  = self.backends()
        local health = self.backend_health()
        for i = 1, #addrs do
            socketley.log("  backend " .. addrs[i] ..
                          (health[i] and (" circuit=" .. health[i]) or ""))
        end
    end

    if self.name:match("replica") then
        socketley.log("[HA] " .. self.name .. " started (healthy)")
    end
end

function on_stop()
    if self.name:match("replica") then
        local uptime = os.time() - (started_at or os.time())
        socketley.log("[HA] " .. self.name .. " stopped (uptime: " .. uptime ..
                      "s, " .. tostring(self.connections()) .. " connections)")
    end
end
