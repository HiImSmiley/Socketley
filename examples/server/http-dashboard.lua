-- http-dashboard.lua
-- Serves a static HTML dashboard via --http and handles WebSocket messages.
--
-- Usage:
--   socketley create server dashboard -p 8080 \
--     --http ./examples/server/http-dashboard/ \
--     --lua ./examples/server/http-dashboard.lua -s
--
-- Open http://localhost:8080 in a browser. The page loads with an
-- auto-injected WebSocket connection (`socketley` global). Messages
-- typed in the UI are broadcast to all connected clients.

local clients = {}

-- self.connections() is the binding, on all four runtime types.  There is no
-- self.count(): calling it is "attempt to call field 'count' (a nil value)",
-- which raises inside on_connect before the broadcast is reached, so nobody is
-- ever told that anybody joined.
function on_connect(id)
    clients[id] = true
    self.broadcast("system: client " .. id .. " joined (" .. self.connections() .. " online)")
end

function on_disconnect(id)
    clients[id] = nil
    self.broadcast("system: client " .. id .. " left (" .. self.connections() .. " online)")
end

function on_client_message(id, msg)
    self.broadcast("[" .. id .. "] " .. msg)
end
