-- IP allowlist using on_auth + self.peer_ip
-- Rejects any client whose IP does not start with the allowed prefix.
-- Rejected clients are disconnected before on_connect fires.

local allowed_prefix = "192.168."

function on_auth(client_id)
    local ip = self.peer_ip(client_id)
    local ok = ip:sub(1, #allowed_prefix) == allowed_prefix
    if not ok then
        socketley.log("rejected client " .. tostring(client_id) .. " from " .. ip)
    end
    return ok
end

function on_connect(client_id)
    -- Only reachable if on_auth returned true
    socketley.log("accepted client " .. tostring(client_id)
                  .. " from " .. self.peer_ip(client_id))
end

function on_client_message(client_id, msg)
    self.broadcast("[" .. tostring(client_id) .. "] " .. msg)
end
