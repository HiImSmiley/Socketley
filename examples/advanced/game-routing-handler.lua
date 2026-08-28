-- Game lobby handler: creates the game modes, routes players into them.
--
-- Loaded by the DAEMON, into the lobby's own interpreter, because
-- game-routing.lua names this path in its `config` key.  Every callback below
-- runs there; nothing in here is read by the CLI.
--
-- THE LOBBY RUNS IN ITS OWN PROCESS, LIKE EVERY RUNTIME.
--
-- This file used to open with the opposite instruction, in capitals: the lobby
-- had to be created with `--daemon-process` or `daemon_process = true`, and
-- self.route was the reason.  Both the flag and the reason are gone.
--
-- The reason is worth keeping because the failure it described was invisible,
-- and the same shape can come back.  self.route was refused in a worker; the
-- raise is caught and logged wherever a callback runs, so without the flag the
-- lobby came up looking perfectly healthy -- `ls` green, the port accepting,
-- the game modes created and running -- and "join rapid" answered nothing at
-- all, because the route was the step that failed and the only sign was a line
-- in the daemon log.  Measured both ways at the time: without the flag, no
-- reply; with it, "join rapid" answered by the rapid handler.
--
-- What changed is not that route became cheaper.  It is that the refusal named
-- the wrong missing thing: a route does not hand a descriptor to another
-- process, it keeps the socket here and relays.  So it needed a way to name the
-- far end's connection, which shared/route_relay.h is, and it now works between
-- any two runtimes wherever they run.
--
-- The handler paths below are opened by the DAEMON, so they resolve against
-- the daemon's working directory, not this file's.  Run from the repository
-- root, or use absolute paths.

function on_start()
    socketley.log("lobby started, creating game modes...")

    socketley.create("server", "chess-rapid", {
        port = 0,
        config = "examples/advanced/rapid-handler.lua",
        on_parent_stop = "remove"
    })
    socketley.start("chess-rapid")

    socketley.create("server", "chess-blitz", {
        port = 0,
        config = "examples/advanced/blitz-handler.lua",
        on_parent_stop = "remove"
    })
    socketley.start("chess-blitz")

    socketley.log("game modes ready")
end

function on_client_message(client_id, msg)
    if msg:match("^join ") then
        local mode = msg:match("^join (%S+)")
        local target = "chess-" .. mode

        local info = socketley.get(target)
        if not info then
            self.send(client_id, "unknown mode: " .. mode)
            return
        end

        if self.route(client_id, target) then
            socketley.log("routed client " .. client_id .. " to " .. target)
        else
            self.send(client_id, "could not join " .. mode)
        end
        return
    end

    if msg == "modes" then
        local names = socketley.list()
        local modes = {}
        for _, name in ipairs(names) do
            if name:match("^chess%-") then
                local info = socketley.get(name)
                table.insert(modes, name .. " (" .. info.connections .. " players)")
            end
        end
        self.send(client_id, "available: " .. table.concat(modes, ", "))
        return
    end

    -- Unrouted messages are broadcast normally
end

function on_stop()
    -- Children auto-removed via on_parent_stop = "remove"
    socketley.log("lobby shutting down")
end
