-- Sub-server for chess rapid mode
-- Receives forwarded clients from lobby, can send back through owner
--
-- client_id here is opaque.  A connection routed in from the lobby lives in the
-- lobby, not here, so its id is a handle rather than a descriptor -- pass it
-- back to self.send/self.owner_send and do not read anything into the number.
-- A handle whose connection has closed makes owner_send return false, which is
-- the answer a script wants: the alternative, which this used to do, was to
-- write into whoever inherited the descriptor.

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
