-- =============================================================================
-- callbacks.lua - Event Callbacks
-- =============================================================================
--
-- Demonstrates all available Lua callbacks and when they fire.
--
-- USAGE:
--   socketley --lua callbacks.lua
--
-- =============================================================================

runtimes = {
    {
        type = "server",
        name = "callback-demo",
        port = 9000,
        autostart = true
    }
}

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
-- =============================================================================
function on_message(msg)
    socketley.log("=== on_message() called ===")
    socketley.log("Received: '" .. msg .. "'")
    socketley.log("Length: " .. #msg .. " bytes")

    -- Example: Echo back with modification
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

--[[
Test:
  1. Run: socketley --lua callbacks.lua
  2. Connect: nc localhost 9000
  3. Type messages and observe callback logs
  4. Stop: socketley stop callback-demo

Cleanup:
  socketley remove callback-demo
]]
