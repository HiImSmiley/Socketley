-- =============================================================================
-- cache-integration.lua - Cache with Server/Client Integration
-- =============================================================================
--
-- Demonstrates using cache as a shared data store between
-- server and client runtimes via Lua.
--
-- USAGE:
--   socketley --lua cache-integration.lua
--
-- =============================================================================

runtimes = {
    -- Persistent cache for shared state
    {
        type = "cache",
        name = "shared-state",
        port = 9000,
        persistent = "/tmp/shared-state.bin",
        start = true
    },
    -- Server that reads/writes to cache
    {
        type = "server",
        name = "api-server",
        port = 9001,
        start = true
    },
    -- Client that interacts with server
    {
        type = "client",
        name = "api-client",
        port = 9001,
        target = "127.0.0.1:9001",
        start = true
    }
}

-- Track message count in cache
local message_count = 0

function on_start()
    socketley.log("Cache integration started")
    socketley.log("Architecture:")
    socketley.log("  [api-client] <-> [api-server] <-> [shared-state]")
end

function on_message(msg)
    -- Parse command (simple protocol: GET key / SET key value)
    local cmd, key, value = msg:match("^(%w+)%s+(%S+)%s*(.*)")

    if cmd == "GET" then
        local result = self.get(key)
        if result then
            socketley.log("GET " .. key .. " = " .. result)
            self.send("OK: " .. result)
        else
            socketley.log("GET " .. key .. " = (not found)")
            self.send("NOT_FOUND")
        end
    elseif cmd == "SET" then
        self.set(key, value)
        socketley.log("SET " .. key .. " = " .. value)
        self.send("OK")
    elseif cmd == "DEL" then
        self.del(key)
        socketley.log("DEL " .. key)
        self.send("OK")
    else
        socketley.log("Unknown command: " .. msg)
        self.send("ERROR: Unknown command")
    end

    -- Track stats in cache
    message_count = message_count + 1
    self.set("_stats:message_count", tostring(message_count))
end

function on_stop()
    socketley.log("Total messages processed: " .. message_count)
end

--[[
Test commands:

# Connect to server and use cache commands:
nc localhost 9001

# Store data:
SET user:1 {"name":"Alice","age":30}
SET user:2 {"name":"Bob","age":25}
SET config:timeout 30

# Retrieve data:
GET user:1
GET user:2
GET config:timeout

# Delete data:
DEL user:2

# Check stats:
GET _stats:message_count

Cleanup:
socketley stop api-client api-server shared-state
socketley remove api-client api-server shared-state
rm -f /tmp/shared-state.bin
]]
