-- =============================================================================
-- callbacks-handler.lua - Every core callback, and when it fires
-- =============================================================================
--
-- The runtime handler that callbacks.lua attaches.  The daemon loads this file
-- into the 'callback-demo' server's own interpreter; `self` is that server.
--
-- Can also be used on its own, without a configuration file:
--   socketley create server callback-demo -p 9000 \
--     --lua examples/lua-config/callbacks-handler.lua -s
--
-- =============================================================================

-- =============================================================================
-- CALLBACK: on_start
-- Triggered when runtime transitions to 'running' state
-- =============================================================================
function on_start()
    socketley.log("=== on_start() called ===")
    socketley.log("Runtime '" .. self.name .. "' is now running")
    socketley.log("Listening on port " .. self.port)

    -- Access runtime properties
    socketley.log("Properties:")
    socketley.log("  self.name  = " .. self.name)
    socketley.log("  self.port  = " .. tostring(self.port))
    socketley.log("  self.type  = " .. self.type)
    socketley.log("  self.state = " .. self.state)
    -- Bound on all four runtime types, not just the server
    socketley.log("  self.connections() = " .. tostring(self.connections()))
end

-- =============================================================================
-- CALLBACK: on_stop
-- Triggered when runtime transitions to 'stopped' state
-- =============================================================================
function on_stop()
    socketley.log("=== on_stop() called ===")
    socketley.log("Runtime '" .. self.name .. "' is shutting down")

    -- Cleanup code can go here
    socketley.log("Performing cleanup...")
end

-- =============================================================================
-- CALLBACK: on_message
-- Triggered when a message is received
-- Parameter: msg - the received message string
-- NOTE: Defining on_message claims message handling — the default broadcast
--       (inout/master modes) is suppressed. Use self.broadcast() to relay.
-- =============================================================================
function on_message(msg)
    socketley.log("=== on_message() called ===")
    socketley.log("Received: '" .. msg .. "'")
    socketley.log("Length: " .. #msg .. " bytes")

    -- Example: Echo back with modification
    -- Since on_message claims handling, we must broadcast explicitly
    local response = "[ECHO] " .. msg
    self.broadcast(response)
    socketley.log("Broadcasted: '" .. response .. "'")
end

-- =============================================================================
-- CALLBACK: on_send
-- Triggered when a message is sent
-- Parameter: msg - the sent message string
-- =============================================================================
function on_send(msg)
    socketley.log("=== on_send() called ===")
    socketley.log("Sent: '" .. msg .. "'")
end
