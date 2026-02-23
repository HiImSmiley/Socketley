-- Sub-server for chess blitz mode
-- Similar to rapid-handler but for blitz games

function on_client_message(client_id, msg)
    if msg == "status" then
        self.owner_send(client_id, "mode:blitz players:" .. self.connections())
    else
        self.send(client_id, "blitz> " .. msg)
    end
end

function on_connect(client_id)
    socketley.log("player " .. client_id .. " joined blitz mode")
    self.send(client_id, "welcome to blitz chess!")
end
