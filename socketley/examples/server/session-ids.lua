-- Assign a UUID to every connection for end-to-end tracing.
-- Session IDs appear in logs and are embedded in every outbound JSON envelope,
-- making it easy to correlate events across logs, metrics, and external systems.
-- Requires: luarocks install uuid   (also uses cjson, bundled with LuaJIT)

local uuid = require "uuid"
local cjson = require "cjson"
uuid.seed()

local session_ids = {}

function on_connect(client_id)
    session_ids[client_id] = uuid()
    socketley.log("connect sid=" .. session_ids[client_id]
                  .. " ip=" .. self.peer_ip(client_id))
end

function on_disconnect(client_id)
    socketley.log("disconnect sid=" .. (session_ids[client_id] or "?"))
    session_ids[client_id] = nil
end

function on_client_message(client_id, msg)
    -- Embed the session ID in every outbound message for distributed tracing
    local envelope = cjson.encode({
        sid  = session_ids[client_id],
        from = client_id,
        data = msg,
    })
    self.broadcast(envelope)
end
