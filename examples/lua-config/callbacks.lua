-- =============================================================================
-- callbacks.lua - Event Callbacks
-- =============================================================================
--
-- Creates the runtime whose callbacks callbacks-handler.lua defines.
--
-- USAGE (from the repository root):
--   socketley --lua examples/lua-config/callbacks.lua
--
-- WHY THE CALLBACKS ARE IN THE OTHER FILE
--
-- This file runs in the CLI process: socketley reads `daemon` and `runtimes`,
-- emits `create` commands, and exits.  A `function on_start()` written here
-- would never be loaded by anything and never called -- and nothing would say
-- so, which is the worst way for an example to be wrong.  The `config` key is
-- what attaches a handler: it becomes `--lua <path>` on the create, and the
-- daemon loads that file into the runtime's own interpreter.
--
-- The daemon opens that path relative to ITS working directory, not this
-- file's, so it is spelled from the repository root below.  An absolute path
-- always works.
--
-- =============================================================================

runtimes = {
    {
        type = "server",
        name = "callback-demo",
        port = 9000,
        config = "examples/lua-config/callbacks-handler.lua",
        start = true
    }
}

--[[
Test:
  1. Run: socketley --lua examples/lua-config/callbacks.lua
  2. Connect: nc localhost 9000
  3. Type messages and watch the daemon's log for the callback lines
     (journalctl -u socketley -f when installed, or the terminal the daemon
     was started in when run by hand)
  4. Stop: socketley stop callback-demo

Cleanup:
  socketley remove callback-demo
]]
