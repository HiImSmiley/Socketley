-- Receiving a request body larger than memory, by not holding it
-- A server without on_http_body waits for the whole body to arrive and answers
-- 413 past --read-buffer. Defining this callback is the opt-in for the other
-- behaviour: the bytes are handed over as they arrive and erased behind them,
-- so the body's size stops being the server's business.
--
-- Measured on one worker: 500 MB received inside 37 MB resident memory, and
-- three consecutive 50 MB uploads with no growth at all between them.
--
-- Both forms arrive here. With Content-Length, `remaining` counts down; with
-- Transfer-Encoding: chunked it is nil, because how much is still owed is not
-- knowable -- and either way it is 0 exactly once, on the call that ends the
-- body. So nothing below has to know which form the client chose.

local UPLOAD_DIR = "/tmp/socketley-uploads"

-- Keyed by connection, and that is the pattern rather than a detail. A body
-- that is abandoned never reaches on_http_request, so nothing there can be the
-- reset -- which is why on_disconnect below is half of this and not an extra.
local uploads = {}

-- A sequence and not os.time(): a descriptor is reused, so two uploads in the
-- same second get the same client_id AND the same timestamp, and the second
-- one's path collides with the first's. Measured -- an aborted upload then
-- removed a COMPLETED one's file, because both had resolved to the same name.
local seq = 0

function on_start()
    os.execute("mkdir -p " .. UPLOAD_DIR)
end

function on_http_body(client_id, chunk, remaining)
    local up = uploads[client_id]
    if not up then
        -- Opened on the first chunk rather than at the headers, so a request
        -- that never sends a body leaves no file behind.
        seq = seq + 1
        local path = UPLOAD_DIR .. "/upload-" .. client_id .. "-" .. seq
        local fh = io.open(path, "wb")
        if not fh then
            socketley.log("upload: cannot open " .. path)
            self.disconnect(client_id)
            return
        end
        up = { fh = fh, path = path, bytes = 0 }
        uploads[client_id] = up
    end

    if up.failed then return end
    if not up.fh:write(chunk) then
        socketley.log("upload: write failed for " .. up.path)
        up.fh:close()
        up.fh = nil
        os.remove(up.path)
        up.failed = true
        return
    end
    up.bytes = up.bytes + #chunk

    -- `remaining` is what is still owed after this chunk, or nil for a chunked
    -- body where that is unknown.  Either way it is 0 exactly once, on the call
    -- that ends the body -- which is why this test is the same for both.
    if remaining == 0 then
        local closed = up.fh:close()
        up.fh = nil
        if closed then
            up.done = true
        else
            socketley.log("upload: close failed for " .. up.path)
            os.remove(up.path)
            up.failed = true
        end
    end
end

function on_http_request(req)
    local up = uploads[req.client_id]
    uploads[req.client_id] = nil

    if up and up.failed then
        return { status = 507, body = "upload failed\n" }
    end

    if not up or not up.done then
        return { status = 400, body = "no body\n" }
    end

    -- req.body is empty on purpose: every byte was handed to on_http_body and
    -- carrying them here again is the memory this whole path avoids.
    -- Header names keep the case the client sent, so "Content-Type" and not
    -- "content-type".
    local kind = (req.headers and req.headers["Content-Type"]) or "application/octet-stream"
    return {
        status = 201,
        headers = { ["Content-Type"] = "text/plain" },
        body = "stored " .. up.bytes .. " bytes of " .. kind .. " at " .. up.path .. "\n",
    }
end

-- The other half. An upload that is abandoned mid-body produces no
-- on_http_request, and this is the only signal it produces at all -- without
-- it every interrupted upload leaves a partial file nobody will ever remove.
function on_disconnect(client_id)
    local up = uploads[client_id]
    if not up then return end
    if up.fh then up.fh:close() end
    if not up.done and not up.failed then
        os.remove(up.path)
        socketley.log("upload: removed partial " .. up.path
            .. " (" .. up.bytes .. " bytes)")
    end
    uploads[client_id] = nil
end
