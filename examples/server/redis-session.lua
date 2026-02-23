-- Distributed session / shared state via redis-lua
-- Demonstrates: distributed rate limiting (INCR/EXPIRE per IP),
-- presence tracking (SADD/SREM), and session key-value store.
-- Requires: luarocks install redis-lua

local redis = require "redis"
local r     = redis.connect("127.0.0.1", 6379)

local RATE_LIMIT = 20  -- max messages per second per IP

function on_connect(client_id)
    -- Track presence across all instances
    r:sadd("socketley:online", tostring(client_id))
    -- Store per-connection session data
    local key = "session:" .. tostring(client_id)
    r:hset(key, "ip", self.peer_ip(client_id))
    r:hset(key, "connected_at", tostring(os.time()))
    r:expire(key, 3600)  -- auto-expire session after 1 hour
    socketley.log("connect id=" .. tostring(client_id)
                  .. " online=" .. tostring(r:scard("socketley:online")))
end

function on_disconnect(client_id)
    r:srem("socketley:online", tostring(client_id))
    r:del("session:" .. tostring(client_id))
end

function on_client_message(client_id, msg)
    -- Distributed rate limiting: shared across all server instances
    local rl_key = "rl:" .. self.peer_ip(client_id)
    local n = r:incr(rl_key)
    if n == 1 then r:expire(rl_key, 1) end  -- 1-second window
    if n > RATE_LIMIT then
        self.send(client_id, "ERROR rate limit exceeded")
        self.disconnect(client_id)
        return
    end
    self.broadcast(msg)
end
