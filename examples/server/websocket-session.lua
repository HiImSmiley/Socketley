-- WebSocket session tracking via browser Cookie header.
-- on_websocket fires after the WS handshake; browser sends Cookie automatically.
-- TCP clients use on_connect only (on_websocket does not fire for them).

local cjson    = require "cjson"
local sessions = {}   -- client_id → { sid, ip, origin }

function on_connect(client_id)
    -- Both TCP and WS clients pass through on_connect.
    -- WS clients will also call on_websocket below with header details.
    sessions[client_id] = { sid = tostring(client_id), ip = self.peer_ip(client_id) }
end

function on_websocket(client_id, headers)
    -- Extract durable session cookie (browser sends automatically)
    local sid = sessions[client_id] and sessions[client_id].sid or tostring(client_id)
    if headers.cookie then
        sid = headers.cookie:match("session_id=([^;%s]+)") or sid
    end
    sessions[client_id] = {
        sid    = sid,
        ip     = self.peer_ip(client_id),
        origin = headers.origin or "unknown",
    }
    socketley.log("ws connect sid=" .. sid .. " origin=" .. (headers.origin or "?"))
end

function on_disconnect(client_id)
    local s = sessions[client_id]
    if s then
        socketley.log("disconnect sid=" .. s.sid)
        sessions[client_id] = nil
    end
end

function on_client_message(client_id, msg)
    local s = sessions[client_id] or {}
    self.broadcast(cjson.encode({ sid = s.sid, data = msg }))
end
