-- Game lobby handler: creates the game modes, routes players into them.
--
-- Loaded by the DAEMON, into the lobby's own interpreter, because
-- game-routing.lua names this path in its `config` key.  Every callback below
-- runs there; nothing in here is read by the CLI.
--
-- THE LOBBY MUST RUN IN THE DAEMON.  game-routing.lua says so with
-- `daemon_process = true`; a `create` command line says so with
-- `--daemon-process`.  Do not drop it.
--
-- self.route is why, and it is the ONLY reason left.  A route moves a
-- CONNECTION into another runtime's tables, and a connection does not travel
-- in a snapshot of anything; it is one of the two calls still refused in a
-- worker.  The rest of what this file does no longer needs the flag:
-- socketley.get and .list are answered from the replica map the daemon pushes,
-- and socketley.create and .start are asked of the daemon and wait for its
-- answer.  Those four used to raise here too.
--
-- The raise is caught and logged wherever a callback runs, which is what makes
-- this worth a paragraph rather than a footnote: without the flag the lobby
-- comes up looking perfectly healthy.  `ls` is green, the port accepts
-- connections, the game modes are created and running -- and "join rapid"
-- answers nothing at all, because the route is the step that fails, and the
-- only sign is a line in the daemon's log.  Measured both ways: without the
-- flag, no reply; with it, "join rapid" answered by the rapid handler.
--
-- It cannot be added afterwards -- `edit` rejects it, because honouring it
-- would mean moving a configured runtime between address spaces underneath
-- whatever already points at it.  Create the lobby with it or recreate it.
--
-- The sub-servers do not need the flag: a runtime created by socketley.create
-- is created inside the daemon that ran the call, which is where self.route
-- needs it to be.
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
