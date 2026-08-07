-- =============================================================================
-- simple-config.lua - Basic Lua Configuration
-- =============================================================================
--
-- Shows the basic structure of a Lua configuration file.
--
-- USAGE (from the repository root):
--   socketley --lua examples/lua-config/simple-config.lua
--
-- A CONFIGURATION IS NOT A HANDLER
--
-- This file runs in the CLI process.  socketley reads `daemon` and `runtimes`
-- out of it, turns them into `create` commands, and exits -- it never reaches
-- the daemon.  Callbacks written HERE are dead code: nothing loads them and
-- nothing calls them.
--
-- The callbacks live in simple-config-handler.lua, and each runtime asks for
-- that file by name with the `config` key below.  That path is opened by the
-- DAEMON, so it is resolved against the daemon's working directory, not
-- against this file's -- which is why it is written out from the repository
-- root here.  An absolute path always works.
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
        config = "examples/lua-config/simple-config-handler.lua",
        start = true,           -- Start immediately
        log = "/tmp/server.log" -- Log file
    },

    -- Client runtime
    {
        type = "client",
        name = "my-client",
        target = "127.0.0.1:9000",  -- Target server
        mode = "inout",
        config = "examples/lua-config/simple-config-handler.lua",
        start = true,
        log = "/tmp/client.log"
    }
}

--[[
After running:
  socketley ls

Output:
  my-server    server    running
  my-client    client    running

The handler's on_start lines appear in the daemon's log, one per runtime,
each naming the runtime it came from -- which is the point, since both lines
come from the same handler file:
  [12:04:31] [INFO] [lua my-server] Runtime started: my-server
  [12:04:31] [INFO] [lua my-client] Runtime started: my-client

Cleanup:
  socketley stop my-server my-client
  socketley remove my-server my-client
]]
