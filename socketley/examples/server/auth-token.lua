-- First-message token authentication using self.disconnect
-- Clients must send the secret token as their first message.
-- Authenticated clients get broadcast access; others are dropped.

local SECRET = "my-secret-token"
local authenticated = {}

function on_connect(client_id)
    authenticated[client_id] = false
end

function on_disconnect(client_id)
    authenticated[client_id] = nil
end

function on_client_message(client_id, msg)
    if not authenticated[client_id] then
        -- First message must be the secret token
        if msg == SECRET then
            authenticated[client_id] = true
            self.send(client_id, "AUTH OK")
        else
            self.send(client_id, "AUTH FAIL")
            self.disconnect(client_id)
        end
        return
    end
    -- Authenticated: relay to everyone
    self.broadcast("[" .. tostring(client_id) .. "] " .. msg)
end
