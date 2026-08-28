-- =============================================================================
-- game-routing.lua - Game Lobby With Mode-Based Routing
-- =============================================================================
--
-- A lobby that creates mode-specific sub-servers and routes players into them.
--
-- USAGE (from the repository root):
--   socketley --lua examples/advanced/game-routing.lua
--   # Then connect: nc localhost 9000
--   # Send "modes"      to list the game modes and their player counts
--   # Send "join rapid" to be routed to the rapid-mode sub-server
--
-- WHAT THIS EXAMPLE USED TO BE ABOUT, AND WHY IT NO LONGER IS
--
-- The lobby entry carried `daemon_process = true` and this comment explained
-- at length why it was REQUIRED.  The key is gone -- a configuration file
-- carrying it is now refused, naming the line -- because every call the
-- handler makes works in a worker.
--
-- The reason is worth keeping, because the failure it described was invisible
-- and the same shape can come back.  The handler calls socketley.create,
-- .start, .get, .list and self.route.  self.route was refused in a worker; a
-- raise inside a callback is caught and logged and the runtime carries on.  So
-- without the key the lobby came up looking healthier than a broken thing has
-- any right to: measured, `ls` showed lobby, chess-rapid and chess-blitz all
-- Up, on_start reported "game modes ready", port 9000 accepted connections --
-- and "join rapid" answered nothing at all.  The only sign was a line in the
-- daemon log, and everything an operator would check first said fine.
--
-- What changed is not that routing became cheaper.  The refusal named the
-- wrong missing thing: a route hands no descriptor to another process, it
-- keeps the socket where it is and relays.  What it needed was a way to name
-- the far end's connection.


runtimes = {
    -- The lobby.  chess-rapid and chess-blitz are not declared here: the
    -- handler's on_start creates them, on port 0 -- they are reached by
    -- routing, never dialled directly, so they need no port of their own.
    {
        type = "server",
        name = "lobby",
        port = 9000,
        config = "examples/advanced/game-routing-handler.lua",
        start = true
    }
}

--[[
Test:
  printf 'modes\n'      | nc -q2 localhost 9000     # available: chess-rapid (0 players), ...
  printf 'join rapid\n' | nc -q2 localhost 9000

  socketley ls                                      # lobby, chess-rapid, chess-blitz

Cleanup:
  socketley stop lobby                              # takes the game modes with it
  socketley remove lobby
]]
