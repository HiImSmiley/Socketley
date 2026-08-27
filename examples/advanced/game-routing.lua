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
-- WHY daemon_process = true IS THE POINT OF THIS EXAMPLE
--
-- The lobby's handler calls socketley.create, socketley.start, socketley.get,
-- socketley.list and self.route.  Four of those five work in a worker now --
-- the reads are answered from the replica map the daemon pushes, and the two
-- map changes are asked of the daemon and wait for its answer.
--
-- self.route is the one that does not, and it is the one this example turns
-- on.  A route moves a CONNECTION into another runtime's tables, and a
-- connection does not travel in a snapshot of anything.
--
-- Inside a callback that raise is caught and logged, and the runtime carries
-- on.  Drop the key and the lobby comes up looking perfectly healthy -- and it
-- looks healthier than it used to, which makes this worse rather than better:
-- measured without the key, `ls` shows lobby, chess-rapid and chess-blitz all
-- Up, on_start reports "game modes ready", port 9000 accepts connections --
-- and "join rapid" answers nothing at all.  The only sign is a line in the
-- daemon's log, and everything an operator would check first says fine.
--
-- `edit` will not add the flag afterwards, because honouring it would mean
-- moving a configured runtime between address spaces underneath whatever
-- already points at it.  A lobby created without it has to be removed and
-- created again.
--
-- The sub-servers the lobby creates do not need it: a runtime created by
-- socketley.create is created inside the daemon that ran the call -- which is
-- true whichever process made the call, and is where self.route needs it to
-- be.
--
-- WHY THE CALLBACKS ARE IN game-routing-handler.lua
--
-- socketley reads `daemon` and `runtimes` out of this file, emits `create`
-- commands, and exits.  Callbacks written here would never be loaded and never
-- called.  The `config` key attaches the handler -- it becomes `--lua <path>`
-- on the create, and the DAEMON opens that path against its own working
-- directory, hence the repository-root spelling.
--
-- =============================================================================

runtimes = {
    -- The lobby.  chess-rapid and chess-blitz are not declared here: the
    -- handler's on_start creates them, on port 0 -- they are reached by
    -- routing, never dialled directly, so they need no port of their own.
    {
        type = "server",
        name = "lobby",
        port = 9000,
        config = "examples/advanced/game-routing-handler.lua",
        daemon_process = true,   -- REQUIRED: see above
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
