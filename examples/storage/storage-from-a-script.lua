-- =============================================================================
-- storage-from-a-script.lua - A server that keeps its messages in object storage
-- =============================================================================
--
-- USAGE:
--   socketley create storage media -p 9000 --dir /srv/objects --anonymous -s
--   curl -X PUT localhost:9000/notes
--   socketley create server notes -p 8000 --lua examples/storage/storage-from-a-script.lua -s
--
--   echo "save todo buy milk" | nc localhost 8000     -> saved todo (8 bytes)
--   echo "load todo"          | nc localhost 8000     -> buy milk
--   echo "list"               | nc localhost 8000     -> todo
--   echo "drop todo"          | nc localhost 8000     -> dropped todo
--   curl localhost:9000/notes/todo                      (an S3 client sees it too)
--
-- socketley.storage.put/get/head/delete/list(runtime, bucket, ...) ask a storage
-- runtime by name, in this daemon or another process.  In on_client_message the
-- call waits for the answer without stopping the daemon and returns it, or nil
-- and a reason.  Where a callback cannot wait -- an on_tick, a cache's on_write,
-- a proxy filter -- pass a function as the last argument instead and it is
-- called with the same values.  At most 1 MiB per call.
-- =============================================================================

function on_client_message(client_id, msg)
    local cmd, key, rest = msg:match("^(%S+)%s*(%S*)%s*(.*)$")

    if cmd == "save" then
        local meta, code = socketley.storage.put("media", "notes", key, rest,
            { content_type = "text/plain", metadata = { author = "client" .. client_id } })
        self.send(client_id, meta and ("saved " .. key .. " (" .. meta.size .. " bytes)")
                                   or ("failed: " .. tostring(code)))

    elseif cmd == "load" then
        local data, meta = socketley.storage.get("media", "notes", key)
        self.send(client_id, data or ("failed: " .. tostring(meta)))

    elseif cmd == "list" then
        local page, code = socketley.storage.list("media", "notes")
        if not page then
            self.send(client_id, "failed: " .. tostring(code))
            return
        end
        local keys = {}
        for _, o in ipairs(page.objects) do keys[#keys + 1] = o.key end
        self.send(client_id, table.concat(keys, " "))

    elseif cmd == "drop" then
        local ok, code = socketley.storage.delete("media", "notes", key)
        self.send(client_id, ok and ("dropped " .. key) or ("failed: " .. tostring(code)))
    end
end
