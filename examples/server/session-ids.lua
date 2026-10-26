-- Assign a session ID to every connection for end-to-end tracing.
-- Session IDs appear in logs and are embedded in every outbound JSON envelope,
-- making it easy to correlate events across logs, metrics, and external systems.
--
-- No external modules.  cjson is NOT bundled with LuaJIT -- nothing is; no
-- binary module ships with socketley and package.cpath is left at its default,
-- so `require "cjson"` is `module 'cjson' not found` and the script fails to
-- load, which leaves the runtime failed.  socketley.json_encode is already in
-- the interpreter and is all this file used cjson for.
--
-- The IDs are generated here rather than with `require "uuid"` for the same
-- reason.  They are unique within this runtime's lifetime, which is what
-- correlating one server's logs needs.  For IDs that must be unique across
-- machines, install a uuid module where the system Lua will find it and
-- require it -- the rest of this file is unchanged.

local session_ids = {}
local seq = 0

local function new_session_id()
    seq = seq + 1
    -- Time, a per-process random prefix and a counter: distinct for every
    -- connection this runtime ever accepts, and distinct between two runtimes
    -- started in the same second.
    return string.format("%x-%04x-%x", os.time(), math.random(0, 0xffff), seq)
end

local urandom = io.open("/dev/urandom", "rb")
local entropy = urandom and urandom:read(4)
if urandom then urandom:close() end
math.randomseed(os.time() + (entropy and (entropy:byte(1) * 16777216 + entropy:byte(2) * 65536 + entropy:byte(3) * 256 + entropy:byte(4)) or 0))

function on_connect(client_id)
    session_ids[client_id] = new_session_id()
    socketley.log("connect sid=" .. session_ids[client_id]
                  .. " ip=" .. self.peer_ip(client_id))
end

function on_disconnect(client_id)
    socketley.log("disconnect sid=" .. (session_ids[client_id] or "?"))
    session_ids[client_id] = nil
end

function on_client_message(client_id, msg)
    -- Embed the session ID in every outbound message for distributed tracing
    local envelope = socketley.json_encode({
        sid  = session_ids[client_id],
        from = client_id,
        data = msg,
    })
    self.broadcast(envelope)
end
