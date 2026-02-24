-- upstream-hub.lua — Server that bridges clients and upstream services
--
-- Usage:
--   socketley create server hub -p 8080 -u "127.0.0.1:9000" --lua upstream-hub.lua -s
--
-- The server connects outbound to an upstream on port 9000 and relays
-- data bidirectionally between clients and the upstream.

function on_upstream_connect(conn_id)
    socketley.log("upstream " .. conn_id .. " connected")
    self.broadcast("upstream " .. conn_id .. " online\n")
end

function on_upstream_disconnect(conn_id)
    socketley.log("upstream " .. conn_id .. " disconnected")
    self.broadcast("upstream " .. conn_id .. " offline\n")
end

function on_upstream(conn_id, data)
    -- Forward upstream data to all connected clients
    self.broadcast("[upstream:" .. conn_id .. "] " .. data)
end

function on_client_message(client_id, msg)
    -- Forward client messages to all upstreams
    self.upstream_broadcast(msg)
end

function on_start()
    socketley.log("hub started, waiting for upstreams...")
end
