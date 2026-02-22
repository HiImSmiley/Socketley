-- Consul service registration using socketley.http in on_start/on_stop
-- Registers this server with Consul when it starts, deregisters on stop.
-- Replace CONSUL with your Consul agent address.

local CONSUL = "http://127.0.0.1:8500"

function on_start()
    local payload = string.format(
        '{"ID":"%s","Name":"%s","Port":%d,"Address":"127.0.0.1"}',
        self.name, self.name, self.port
    )
    local res = socketley.http({
        method  = "PUT",
        url     = CONSUL .. "/v1/agent/service/register",
        body    = payload,
        headers = { ["Content-Type"] = "application/json" },
    })
    if res.ok then
        socketley.log("registered with Consul as " .. self.name)
    else
        socketley.log("Consul registration failed: " .. tostring(res.error))
    end
end

function on_stop()
    local res = socketley.http({
        method = "PUT",
        url    = CONSUL .. "/v1/agent/service/deregister/" .. self.name,
    })
    if res.ok then
        socketley.log("deregistered from Consul: " .. self.name)
    end
end

function on_client_message(client_id, msg)
    self.broadcast("[" .. tostring(client_id) .. "] " .. msg)
end
