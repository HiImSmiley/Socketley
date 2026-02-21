-- =============================================================================
-- simple-config.lua - Basic Lua Configuration
-- =============================================================================
--
-- Shows the basic structure of a Lua configuration file.
--
-- USAGE:
--   socketley --lua simple-config.lua
--
-- =============================================================================

-- The 'runtimes' table defines all runtimes to create
runtimes = {
    -- Server runtime
    {
        type = "server",        -- Runtime type (required)
        name = "my-server",     -- Unique name (required)
        port = 9000,            -- Listening port
        mode = "inout",         -- Message mode: inout|in|out
        autostart = true,       -- Start immediately
        log = "/tmp/server.log" -- Log file
    },

    -- Client runtime
    {
        type = "client",
        name = "my-client",
        target = "127.0.0.1:9000",  -- Target server
        mode = "inout",
        autostart = true,
        log = "/tmp/client.log"
    }
}

-- Optional: Callback when any runtime starts
function on_start()
    socketley.log("Runtime started: " .. self.name)
    socketley.log("  Type: " .. self.type)
    socketley.log("  Port: " .. self.port)
end

-- Optional: Callback when any runtime stops
function on_stop()
    socketley.log("Runtime stopped: " .. self.name)
end

--[[
After running:
  socketley ls

Output:
  my-server    server    running
  my-client    client    running

Cleanup:
  socketley stop my-server my-client
  socketley remove my-server my-client
]]
