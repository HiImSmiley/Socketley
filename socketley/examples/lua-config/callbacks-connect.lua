-- =============================================================================
-- Lua Callbacks: on_connect / on_disconnect
-- =============================================================================
-- Demonstrates client connection tracking with Lua callbacks.
--
-- USAGE:
--   socketley create server tracker -p 9000 --config callbacks-connect.lua -s
--   # Connect clients to see callbacks fire:
--   nc localhost 9000
-- =============================================================================

-- Track connected clients
local clients = {}

function on_start()
    socketley.log("Server started, waiting for connections...")
end

function on_connect(client_id)
    clients[client_id] = os.time()
    socketley.log("Client connected: " .. tostring(client_id) ..
                  " (total: " .. tostring(table_size(clients)) .. ")")
end

function on_disconnect(client_id)
    local connected_at = clients[client_id]
    clients[client_id] = nil
    local duration = connected_at and (os.time() - connected_at) or 0
    socketley.log("Client disconnected: " .. tostring(client_id) ..
                  " (was connected " .. tostring(duration) .. "s)")
end

function on_message(msg)
    socketley.log("Message: " .. msg)
    -- Echo back with client count
    self.broadcast("[" .. tostring(table_size(clients)) .. " online] " .. msg)
end

function on_stop()
    socketley.log("Server stopping, " .. tostring(table_size(clients)) .. " clients will disconnect")
end

-- Helper: count table entries
function table_size(t)
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    return count
end
