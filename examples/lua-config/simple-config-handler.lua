-- =============================================================================
-- simple-config-handler.lua - The handler simple-config.lua attaches
-- =============================================================================
--
-- This is the file the DAEMON loads, into each runtime that names it with
-- `config = "..."`.  It gets its own interpreter per runtime, so `self` below
-- is whichever runtime is running it -- the same file serves the server and
-- the client in simple-config.lua, and each sees its own name and port.
--
-- Nothing here runs when the configuration is read.  These callbacks fire on
-- the daemon's event loop, against a runtime that exists.
--
-- =============================================================================

function on_start()
    socketley.log("Runtime started: " .. self.name)
    socketley.log("  Type: " .. self.type)
    socketley.log("  Port: " .. tostring(self.port))
end

function on_stop()
    socketley.log("Runtime stopped: " .. self.name)
end
