-- =============================================================================
-- filter-chain.lua - Filters that run before the proxy picks a backend
-- =============================================================================
--
-- on_route() answers "where does this request go".  Authentication, per-user
-- rate limiting and header rewriting are not that question, and putting them
-- inside on_route() means they run once a backend has already been chosen for
-- the request.  A rejection at that point has already cost the connection it
-- exists to prevent.
--
-- `filters` is an array of functions run in order, before backend selection.
-- Each one either says nothing — carry on to the next — or returns the answer,
-- which ends the request there: no backend is selected, no endpoint resolved,
-- no socket opened or taken from the pool.
--
-- USAGE:
--   socketley create proxy gateway -p 8080 --backend 127.0.0.1:9001 \
--       --protocol http --lua filter-chain.lua -s
--
-- The chain is not a routing strategy.  It runs whatever --strategy chooses the
-- backend afterwards, and it runs on a proxy that has no on_route() at all.
--
-- =============================================================================

-- Simple in-memory state.  A filter is called on the event loop thread, like
-- every other callback here, so an ordinary table needs no locking — and for
-- the same reason a filter must not block: no sleeping, no synchronous I/O, no
-- long loops.  Whatever a filter does, every request on this proxy waits for.
local hits = {}
local WINDOW_LIMIT = 20

local TOKENS = {
    ["Bearer alice-key"] = "alice",
    ["Bearer bob-key"]   = "bob",
}

filters = {

    -- ── 1. authentication ────────────────────────────────────────────────
    --
    -- Returning a table with `status` is the answer.  The chain stops and the
    -- request is never forwarded.
    function(req)
        if string.find(req.path, "/public/", 1, true) then
            return   -- nothing: carry on
        end

        -- Header names in req.headers are lowercased; values are trimmed, and
        -- a field sent more than once is joined with ", ".
        local user = TOKENS[req.headers["authorization"] or ""]
        if not user then
            return {
                status = 401,
                body = "authentication required\n",
                headers = { ["WWW-Authenticate"] = 'Bearer realm="gateway"' },
            }
        end

        -- Returning a table with `set_headers` and no `status` carries on, with
        -- those headers set on the request that goes to the backend.  A header
        -- set here replaces one the client sent under the same name — which is
        -- the point: the backend must not be able to be told who the user is by
        -- the client.
        return { set_headers = { ["x-authenticated-user"] = user } }
    end,

    -- ── 2. rate limiting ─────────────────────────────────────────────────
    --
    -- Per client address, using the peer_ip() the proxy table already exposes.
    function(req)
        local ip = self.peer_ip(req.client_id)
        local n = (hits[ip] or 0) + 1
        hits[ip] = n
        if n > WINDOW_LIMIT then
            return {
                status = 429,
                body = "rate limit exceeded\n",
                headers = { ["Retry-After"] = "60" },
            }
        end
    end,

    -- ── 3. header rewriting ──────────────────────────────────────────────
    function(req)
        return {
            set_headers = {
                ["x-forwarded-proto"] = "http",
                ["x-gateway"] = self.name,
            },
        }
    end,
}

-- The window this example's counter is measured over.  A tick is the right
-- place for it: filters run on the request path and should do as little as
-- possible.
tick_ms = 60000
function on_tick()
    hits = {}
end

--[[
What a filter may NOT set, on either side:

  Content-Length, Transfer-Encoding   framing.  The proxy forwards exactly the
                                      body the parsed request declared; a filter
                                      that could change the length would make the
                                      proxy and the backend disagree about where
                                      the request ends.
  Host                                the proxy rewrites it to the endpoint it
                                      actually selected.
  Connection, Keep-Alive, TE,         hop-by-hop; the proxy strips these on
  Trailer, Upgrade, Proxy-*           purpose.

They are dropped with a line on stderr rather than sent.  So is any name that is
not a bare token, and any value carrying CR or LF — a filter is often echoing
something the client supplied, and that is header injection if it reaches the
wire.

Other rules worth knowing:

  * A filter that returns anything other than nil or a table, or that raises an
    error, refuses the request with 500.  A chain is where authentication lives,
    so a filter that did not say "carry on" is not treated as though it had.
  * A request answered by a filter closes its connection, like every other
    response this proxy writes itself.
  * A `filters` entry that is not a function refuses the whole script at load
    time.  A silently dropped auth filter looks exactly like one that admits
    everybody.

Test:
  socketley create server api -p 9001 -s
  socketley create proxy gateway -p 8080 --backend 127.0.0.1:9001 \
      --protocol http --lua filter-chain.lua -s

  # 401 — refused before any backend is contacted
  curl -i localhost:8080/gateway/api/users

  # 200 — forwarded, carrying X-Authenticated-User: alice
  curl -i -H 'Authorization: Bearer alice-key' localhost:8080/gateway/api/users

  # no credentials needed
  curl -i localhost:8080/gateway/public/health

  # 429 after twenty requests in a minute
  for i in $(seq 1 25); do
      curl -s -o /dev/null -w '%{http_code}\n' \
          -H 'Authorization: Bearer alice-key' localhost:8080/gateway/api/x
  done

Cleanup:
  socketley stop gateway api && socketley remove gateway api
]]
