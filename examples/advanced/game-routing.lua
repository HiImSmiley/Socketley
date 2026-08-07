-- Game server with mode-based routing
-- Main server (lobby) routes players to mode-specific sub-servers
--
-- Usage (from the repository root):
--   socketley create server lobby -p 9000 --daemon-process \
--     --lua examples/advanced/game-routing.lua -s
--   # Then connect: nc localhost 9000
--   # Send "join rapid" to route to rapid mode
--   # Send "join blitz" to route to blitz mode
--
-- --daemon-process IS REQUIRED.  Do not drop it.
--
-- A runtime gets its own worker process unless that flag is given, and a
-- worker holds one runtime and no runtime map.  Everything this file does
-- reaches for that map: socketley.create, socketley.start, socketley.get,
-- socketley.list, and self.route -- which names another runtime and so counts
-- as reaching for it too.  In a worker every one of them raises.
--
-- The raise is caught and logged wherever a callback runs, which is what makes
-- this worth a paragraph rather than a footnote: without the flag the lobby
-- comes up looking perfectly healthy.  `ls` is green, the port accepts
-- connections, on_start reports "creating game modes..." -- and no game mode
-- exists, "join rapid" answers nothing at all, and the only sign is a line in
-- the daemon's log.  Measured both ways: without the flag, zero sub-servers
-- and no reply; with it, chess-rapid and chess-blitz running and "join rapid"
-- answered by the rapid handler.
--
-- It cannot be added afterwards -- `edit` rejects it, because honouring it
-- would mean moving a configured runtime between address spaces underneath
-- whatever already points at it.  Create the lobby with it or recreate it.
--
-- The sub-servers do not need the flag: a runtime created by socketley.create
-- is created inside the daemon that ran the call, which is where self.route
-- needs it to be.
--
-- The --lua path is opened by the DAEMON, so it resolves against the daemon's
-- working directory, not this file's.  Run from the repository root, or use an
-- absolute path.

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
