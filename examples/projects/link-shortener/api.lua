-- link-shortener: the HTTP API, as one on_http_request handler.
--
-- Attached to a server runtime.  Three routes:
--
--   POST /shorten   body: a URL          -> 201 with the short code
--   GET  /<code>                         -> 302 to the target
--   GET  /stats                          -> 200, JSON counters
--
-- ─── WHERE THE STATE LIVES, AND WHY IT IS HERE ──────────────────────────────
--
-- In this table, in this process.  That is a real limitation and worth stating
-- rather than hiding behind a demo that never restarts:
--
--   * it is lost when the runtime stops;
--   * with --shards N it is N separate tables, because each shard is its own
--     process and a Lua table does not cross one.  The gateway in front of this
--     is therefore configured WITHOUT shards on this runtime -- see run.sh.
--
-- A cache runtime is the durable answer, and socketley's Lua cannot reach one
-- synchronously from a server: socketley.send() is fire-and-forget and
-- socketley.subscribe() is pub/sub, so neither gives a read-back inside a
-- request.  The honest options are a cache-linked client (`--cache`, which is a
-- client-facing passthrough, not a Lua API) or the C++ SDK, whose cache_get()
-- is synchronous.  See README.md.
local links   = {}
local hits    = {}
local created = 0
local served  = 0

-- Deterministic, short, and good enough to read aloud.  Not a hash: collisions
-- are resolved by counting up, so two different URLs never share a code.
local ALPHABET = "23456789abcdefghijkmnpqrstuvwxyz"
local function code_for(n)
    local out = ""
    repeat
        local d = n % #ALPHABET
        out = ALPHABET:sub(d + 1, d + 1) .. out
        n = math.floor((n - d) / #ALPHABET)   -- not //: LuaJIT is Lua 5.1
    until n == 0
    return out
end

local function json_escape(s)
    return (s:gsub('[\\"]', '\\%0'):gsub('\n', '\\n'))
end

local function bad(status, why)
    return { status = status,
             headers = { ["Content-Type"] = "application/json" },
             body = '{"error":"' .. json_escape(why) .. '"}' }
end

function on_start()
    socketley.log("link-shortener api up")
end

function on_http_request(req)
    -- POST /shorten
    if req.method == "POST" and req.path == "/shorten" then
        local url = (req.body or ""):gsub("^%s+", ""):gsub("%s+$", "")
        if url == "" then
            return bad(400, "empty body: send the URL as the request body")
        end
        if not url:match("^https?://") then
            return bad(400, "only http:// and https:// are shortened")
        end

        created = created + 1
        local code = code_for(created)
        links[code] = url
        hits[code]  = 0

        return { status = 201,
                 headers = { ["Content-Type"] = "application/json" },
                 body = '{"code":"' .. code .. '","url":"' .. json_escape(url) .. '"}' }
    end

    -- GET /stats  -- before the redirect route, or "stats" would be a code
    if req.method == "GET" and req.path == "/stats" then
        local parts = {}
        for code, n in pairs(hits) do
            parts[#parts + 1] = '"' .. code .. '":' .. n
        end
        return { status = 200,
                 headers = { ["Content-Type"] = "application/json" },
                 body = '{"created":' .. created ..
                        ',"served":' .. served ..
                        ',"hits":{' .. table.concat(parts, ",") .. '}}' }
    end

    -- GET /health -- what the gateway's --health-check http asks for
    if req.method == "GET" and req.path == "/health" then
        return { status = 200, body = "ok" }
    end

    -- GET /<code>
    if req.method == "GET" then
        local code = req.path:match("^/([%w]+)$")
        local target = code and links[code]
        if target then
            hits[code] = hits[code] + 1
            served = served + 1
            return { status = 302,
                     headers = { ["Location"] = target,
                                 ["Cache-Control"] = "no-store" },
                     body = "" }
        end
        return bad(404, "no such code")
    end

    return bad(405, req.method .. " is not allowed here")
end
