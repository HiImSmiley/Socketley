-- http-dashboard.lua
-- Serves a static HTML dashboard via --http and handles WebSocket messages.
--
-- Usage:
--   socketley create server dashboard -p 8080 \
--     --http ./socketley/examples/server/http-dashboard/ \
--     --lua ./socketley/examples/server/http-dashboard.lua -s
--
-- Open http://localhost:8080 in a browser. The page loads with an
-- auto-injected WebSocket connection (`socketley` global). Messages
-- typed in the UI are broadcast to all connected clients.

local clients = {}

function on_connect(id)
    clients[id] = true
    self.broadcast("system: client " .. id .. " joined (" .. self.count() .. " online)")
end

function on_disconnect(id)
    clients[id] = nil
    self.broadcast("system: client " .. id .. " left (" .. self.count() .. " online)")
end

function on_client_message(id, msg)
    self.broadcast("[" .. id .. "] " .. msg)
end
