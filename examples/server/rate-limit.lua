-- Per-client rate limiting using self.disconnect + on_tick
-- Each client is allowed up to MAX_MSGS messages per tick interval.
-- Clients that exceed the limit are disconnected.

local MAX_MSGS = 10   -- messages per tick window
local counts   = {}

tick_ms = 1000        -- reset window every 1 second

function on_connect(client_id)
    counts[client_id] = 0
end

function on_disconnect(client_id)
    counts[client_id] = nil
end

function on_client_message(client_id, msg)
    counts[client_id] = (counts[client_id] or 0) + 1
    if counts[client_id] > MAX_MSGS then
        self.send(client_id, "ERROR rate limit exceeded")
        self.disconnect(client_id)
        return
    end
    self.broadcast(msg)
end

function on_tick(dt)
    -- Reset all per-client counters at the start of each new window
    for id in pairs(counts) do
        counts[id] = 0
    end
end
