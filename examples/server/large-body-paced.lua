-- Sending a body larger than the write-queue bound, without losing the client
-- A write is queued rather than performed, and the queue has a hard bound: fill
-- it and the runtime closes the connection. So a loop that sends a large body
-- as fast as it can loses the client partway through, however fast the machine.
--
-- The three pieces that make it work instead:
--   self.pending(id)  bytes queued for that client and not yet on the wire
--   self.watermark()  the number on_writable fires on the way down through
--   on_writable(id)   the queue has come back under it; carry on

local CHUNK_SIZE = 65536
local CHUNKS     = 500          -- 32 MB, well past the bound

local remaining = {}

local function pump(id)
    local left = remaining[id]
    if not left then return end

    while left > 0 do
        -- Pace against self.watermark() and not a literal. on_writable fires on
        -- the crossing, so a producer that stops below the watermark never
        -- crosses it and is never called back -- it would wait for an event
        -- its own caution prevented.
        if (self.pending(id) or 0) >= self.watermark() then
            remaining[id] = left
            return
        end

        -- false here means the bytes are not going: the client is gone, or the
        -- producer ignored the watermark long enough to reach the hard bound.
        if not self.send(id, string.rep("x", CHUNK_SIZE)) then
            remaining[id] = nil
            return
        end
        left = left - 1
    end

    remaining[id] = nil
    self.send(id, "DONE")
end

function on_writable(client_id)
    pump(client_id)
end

function on_client_message(client_id, msg)
    if msg == "send" then
        remaining[client_id] = CHUNKS
        pump(client_id)
    end
end

function on_disconnect(client_id)
    remaining[client_id] = nil
end
