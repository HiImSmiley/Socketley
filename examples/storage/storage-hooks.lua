-- =============================================================================
-- storage-hooks.lua - Policy and an audit trail on a storage runtime
-- =============================================================================
--
-- USAGE:
--   socketley create storage policy -p 9001 --dir /srv/policy --anonymous -s
--   socketley create storage media  -p 9000 --dir /srv/objects --anonymous \
--       --lua examples/storage/storage-hooks.lua -s
--   curl -X PUT localhost:9001/rules; curl -X PUT localhost:9001/audit
--   curl -X PUT --data-binary x localhost:9001/rules/secret.txt
--
--   curl -X PUT localhost:9000/docs
--   curl -X PUT --data-binary hi localhost:9000/docs/public.txt   # allowed
--   curl -X PUT --data-binary hi localhost:9000/docs/secret.txt   # 403: named in `policy`
--   curl -X DELETE localhost:9000/docs/public.txt                 # 403: no deletes
--
-- on_request runs after authentication and before the operation.  It may wait for
-- another runtime -- here the `policy` storage runtime -- and the loop goes on
-- serving meanwhile; the connection is not read from until it answers, so a
-- refused upload is answered before its body is read.
--
-- Return nothing or true to let the request go on, false for AccessDenied, an S3
-- error code as a string, or {deny=, message=, status=}.  A raise is a refusal.
--
-- on_put and on_delete are told after the commit.  Here they write an audit
-- object into the `policy` runtime's `audit` bucket with the callback form of
-- socketley.storage, which works where a callback cannot wait.
-- =============================================================================

local BLOCK_DELETES = true

function on_request(req)
    if BLOCK_DELETES and (req.operation == "DeleteObject" or req.operation == "DeleteObjects") then
        return { deny = "AccessDenied", message = "deletes are switched off", status = 403 }
    end

    if req.operation == "PutObject" then
        -- One question to the policy runtime; only NoSuchKey means "not named", any other failure refuses.
        local meta, code = socketley.storage.head("policy", "rules", req.key)
        if meta or code ~= "NoSuchKey" then
            return "AccessDenied"
        end
    end
end

local function audit(what, bucket, key, extra)
    local name = string.format("%s/%s/%s", what, bucket, key)
    socketley.storage.put("policy", "audit", name, extra or "", function(meta, code)
        if not meta then
            socketley.log("audit of " .. name .. " failed: " .. tostring(code))
        end
    end)
end

function on_put(bucket, key, meta)
    audit("put", bucket, key, meta.etag .. " " .. meta.size)
end

function on_delete(bucket, key)
    audit("delete", bucket, key)
end
