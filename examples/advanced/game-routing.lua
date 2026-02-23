-- Game server with mode-based routing
-- Main server (lobby) routes players to mode-specific sub-servers
--
-- Usage:
--   socketley create server lobby -p 9000 --lua examples/advanced/game-routing.lua -s
--   # Then connect: nc localhost 9000
--   # Send "join rapid" to route to rapid mode
--   # Send "join blitz" to route to blitz mode

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
