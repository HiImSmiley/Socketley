-- Answering with a generated body larger than memory
-- on_http_request has to RETURN its body, so an answer this server generates
-- rather than reads from disk had to fit in memory first. A file of any size was
-- already served by the splice path; a generated one of any size was not
-- expressible at all -- an export assembled from a cache, a CSV of ten million
-- rows, anything transcoded.
--
--   self.respond_stream(id, status, headers)   begin one
--   self.send_chunk(id, data)                  one piece; false = not taken
--   self.end_response(id)                      finish it
--
-- Measured: 200 MB of generated rows through an 8 MiB write queue, delivered in
-- 51,200 chunks with on_writable resuming it 67 times, for 6 MB resident.
--
-- The chunk size is the one number worth tuning here: measured against a C
-- server writing the same bytes, one send_chunk costs 0.28 us against 4.5 us for
-- a write(), so fine chunks are where this wins -- 13x at 64 bytes and 2x at
-- 8 KiB. And with many of these streams at once a SMALLER --write-buffer is
-- faster as well as smaller, because what is owed to all of them has to fit in
-- cache; socketley(1) has the crossover.

-- Two things about the deadline, measured on exactly this shape of handler.
--
-- callback_timeout_ms = 0 installs no instruction hook, which is the only way
-- LuaJIT's trace compiler opens at all -- worth 34% here, and 48% at 64
-- concurrent requests. It gives up being able to interrupt a runaway callback,
-- which is a real thing to give up; socketley(1) has both sides.
--
-- string.format instead of a chain of .. is worth nothing on its own (4% behind,
-- inside the noise) and +23% once the compiler is on, because it builds one
-- string per row instead of a chain of intermediates and formats an integer
-- rather than a double -- the double formatter alone was 15.6% of the core.
-- The two together are +64% at 8 streams and +110% at 64, for half the CPU.
--
-- What neither fixes: a C server building these rows with snprintf still serves
-- 2.4x this. How much of a stream's per-byte work belongs in Lua is the question
-- underneath, and the answer is "as little as possible".
callback_timeout_ms = 0

local fmt  = string.format
local ROWS = 10000000          -- ten million, which is ~400 MB of CSV
local jobs = {}

-- The producer. It stops at the watermark and returns; on_writable brings it
-- back. That pacing is not an optimisation -- without it the queue reaches its
-- hard bound, the connection is closed, and this is just a slower way to run
-- out of memory.
local function pump(client_id)
    local job = jobs[client_id]
    if not job then return end

    while job.row <= ROWS do
        if (self.pending(client_id) or 0) >= self.watermark() then
            return                      -- full enough; on_writable resumes
        end

        -- One line per chunk is the simple form; batching a few hundred rows
        -- per chunk costs less framing per byte if the rows are small.
        local line = fmt("%d,item-%d,generated\n", job.row, job.row)
        local sent, why = self.send_chunk(client_id, line)
        if not sent then
            -- Not backpressure: pending() was checked above. The client is
            -- gone, or this was a HEAD. Either way there is nothing to finish.
            socketley.log("export: stopped at row " .. job.row .. ": " .. tostring(why))
            jobs[client_id] = nil
            return
        end
        job.row = job.row + 1
    end

    self.end_response(client_id)
    jobs[client_id] = nil
end

function on_writable(client_id)
    pump(client_id)
end

function on_http_request(req)
    if req.path ~= "/export.csv" then
        return { status = 404, body = "not found\n" }
    end

    -- Content-Length is deliberately absent: the length is not known when the
    -- headers go out, which is what chunked exists for. Setting one here would
    -- be dropped anyway -- a Content-Length beside a chunked body is a message
    -- carrying two answers to its own length.
    local started = self.respond_stream(req.client_id, 200, {
        ["Content-Type"]        = "text/csv",
        ["Content-Disposition"] = 'attachment; filename="export.csv"',
    })
    if not started then
        return { status = 503, body = "could not start the export\n" }
    end

    jobs[req.client_id] = { row = 1 }
    pump(req.client_id)

    -- Nothing is returned: the response is already on its way, and the
    -- static-file and 404 fallbacks are skipped for a request that has been
    -- answered this way.
end

-- A client that closes mid-export leaves a job behind, and nothing else would
-- clear it: the response never finished, so pump() never reached its end.
function on_disconnect(client_id)
    local job = jobs[client_id]
    if job then
        socketley.log("export: client left after " .. (job.row - 1) .. " rows")
        jobs[client_id] = nil
    end
end
