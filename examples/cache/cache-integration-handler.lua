-- =============================================================================
-- cache-integration-handler.lua - One file, two runtimes, two different `self`
-- =============================================================================
--
-- cache-integration.lua attaches this to both the cache and the server.  Each
-- loads it into its own interpreter, and `self` carries a different set of
-- methods depending on the type it belongs to:
--
--   cache   self.get / set / del / lpush / sadd / hset / expire / publish ...
--   server  self.broadcast / send(id, msg) / clients / peer_ip / route ...
--   client  self.send(msg)               -- ONE argument, not two
--   proxy   self.backends / backend_health / close_client / stats ...
--
--   self.connections() and self.name / port / type / state are on all four.
--
-- Calling a cache method on a server is "attempt to call field 'get' (a nil
-- value)", which is why every body below asks self.type first.
--
-- =============================================================================

local message_count = 0

function on_start()
    if self.type == "cache" then
        -- Seed some state.  These bindings exist because this runtime IS the
        -- cache; they are not available to api-server.
        if self.get("config:timeout") == "" then
            self.set("config:timeout", "30")
        end
        socketley.log("[shared-state] cache ready on port " .. self.port)
        return
    end

    socketley.log("[" .. self.name .. "] ready on port " .. self.port)
    socketley.log("  clients may send: cache set <k> <v> | cache get <k> | cache del <k>")
    socketley.log("  those are answered by shared-state, to the sender only")
end

-- Defining on_message CLAIMS message handling: the server's default broadcast
-- is suppressed, so nothing is echoed to the other clients.
--
-- on_client_message fires FIRST and fires for everything, "cache ..." commands
-- included.  on_message does not: a cache command is answered from the linked
-- cache and returns before it, so it is the one to count ordinary traffic in.
function on_message(msg)
    if self.type ~= "server" then return end
    message_count = message_count + 1
end

function on_client_message(client_id, msg)
    -- self.send on a SERVER takes (client_id, msg).  The one-argument form
    -- self.send(msg) is the CLIENT binding and does not exist here.
    --
    -- The count is of messages handled BEFORE this one, because this callback
    -- runs ahead of on_message rather than after it.
    if msg:sub(1, 6) == "cache " then
        self.send(client_id, "(asking shared-state)")
    else
        self.send(client_id, "ack #" .. (message_count + 1) .. ": " .. msg)
    end
end

-- Cache-only.  Fires after every successful SET, whichever way it arrived --
-- from a client's "cache set", from the cache's own port, or from Lua.
--
-- It also fires for writes nobody asked for: a server created --cache <name>
-- ARCHIVES every ordinary message into that cache under an auto-incrementing
-- integer key, so sending "hello" to api-server shows up here as a write to
-- the key "1".  That is what the link does, not a bug -- but it is why this
-- log distinguishes the two.
function on_write(key, value, ttl)
    local kind = key:match("^%d+$") and "archived" or "wrote"
    socketley.log("[shared-state] " .. kind .. " " .. key ..
                  (ttl and ttl > 0 and (" ttl=" .. ttl) or ""))
end

function on_delete(key)
    socketley.log("[shared-state] deleted " .. key)
end

function on_stop()
    if self.type == "server" then
        socketley.log("[" .. self.name .. "] messages handled: " .. message_count)
    end
end
