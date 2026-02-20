-- Sub-server for chess rapid mode
-- Receives forwarded clients from lobby, can send back through owner

function on_client_message(client_id, msg)
    if msg == "status" then
        -- Send response back to this specific client through the owner (lobby)
        self.owner_send(client_id, "mode:rapid players:" .. self.connections())
    elseif msg == "announce" then
        -- Broadcast to ALL of the owner's clients (entire lobby)
        self.owner_broadcast("[rapid] tournament starting!")
    else
        -- Echo back to just this client
        self.send(client_id, "rapid> " .. msg)
    end
end

function on_connect(client_id)
    socketley.log("player " .. client_id .. " joined rapid mode")
    self.send(client_id, "welcome to rapid chess!")
end

function on_disconnect(client_id)
    socketley.log("player " .. client_id .. " left rapid mode")
end
