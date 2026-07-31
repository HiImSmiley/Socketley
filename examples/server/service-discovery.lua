-- Consul service registration using socketley.http in on_start/on_stop
-- Registers this server with Consul when it starts, deregisters on stop.
-- Replace CONSUL with your Consul agent address.
--
-- socketley.http blocks the event loop thread for the length of the call, which
-- is why this only runs in on_start/on_stop. timeout_ms (default 5000) is one
-- deadline for the whole exchange, so the stall is bounded, not absent.
--
-- An https:// URL is fully verified: the chain against the system CA store and
-- the certificate against the host in the URL, TLS 1.2 minimum. There is no way
-- to switch that off, so a Consul agent behind a private CA needs that CA in the
-- trust store (SSL_CERT_FILE / SSL_CERT_DIR) or the call returns ok=false with
-- the reason in res.error. An IPv6 literal must be bracketed:
-- "https://[::1]:8501".

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
