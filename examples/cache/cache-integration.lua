-- =============================================================================
-- cache-integration.lua - Cache as shared state between a server and its clients
-- =============================================================================
--
-- USAGE (from the repository root):
--   socketley --lua examples/cache/cache-integration.lua
--
-- WHY THE CALLBACKS ARE IN cache-integration-handler.lua
--
-- This file runs in the CLI process: socketley reads `daemon` and `runtimes`,
-- emits `create` commands, and exits.  A callback written here would never be
-- loaded and never called.  The `config` key attaches the handler -- it
-- becomes `--lua <path>` on the create, and the DAEMON opens that path against
-- its own working directory, hence the repository-root spelling.
--
-- WHY THE SERVER HAS cache = "shared-state"
--
-- A server's `self` has no get/set/del.  Those are CACHE bindings, and they
-- exist on a cache runtime only -- calling self.get from a server handler is
-- "attempt to call field 'get' (a nil value)".
--
-- --cache <name> is the link that makes a cache reachable from a server, and
-- it is reached from the WIRE, not from Lua: a client connected to api-server
-- sends "cache set user:1 alice" and gets "ok" back on the same connection,
-- answered by shared-state.  See socketley(1), "Cache Access via Server".
-- Replies come back in request order and go to the sender alone, never to the
-- other clients.
--
-- The link ARCHIVES as well, which is easy to miss: an ordinary message --
-- anything not starting with "cache " -- is also written into shared-state
-- under an auto-incrementing integer key, on top of being handled normally.
-- Send "hello" here and `get 1` at the cache's own port answers "hello".
-- That is worth wanting before linking a cache; it is a write per message.
--
-- =============================================================================

local HANDLER = "examples/cache/cache-integration-handler.lua"

runtimes = {
    -- Persistent cache for shared state
    {
        type = "cache",
        name = "shared-state",
        port = 9000,
        persistent = "/tmp/shared-state.bin",
        config = HANDLER,
        start = true
    },
    -- Server that its clients reach the cache through
    {
        type = "server",
        name = "api-server",
        port = 9001,
        cache = "shared-state",   -- enables "cache <command>" from clients
        config = HANDLER,
        start = true
    },
    -- Client that interacts with the server
    {
        type = "client",
        name = "api-client",
        target = "127.0.0.1:9001",
        start = true
    }
}

--[[
Test commands:

# Connect to the server.  The "cache ..." prefix is answered by shared-state;
# anything else is an ordinary message handled by the server's own callbacks.
nc localhost 9001

# Store data (answered "ok"):
cache set user:1 {"name":"Alice","age":30}
cache set user:2 {"name":"Bob","age":25}
cache set config:timeout 30

# Retrieve data (answered with the value, or "nil"):
cache get user:1
cache get config:timeout

# Delete data:
cache del user:2

# Anything without the prefix is a plain message; the handler answers the
# sender with a short acknowledgement instead of broadcasting it:
hello

# The cache is also a runtime in its own right:
socketley stats shared-state
nc localhost 9000        # then: get user:1

Cleanup:
socketley stop api-client api-server shared-state
socketley remove api-client api-server shared-state
rm -f /tmp/shared-state.bin
]]
