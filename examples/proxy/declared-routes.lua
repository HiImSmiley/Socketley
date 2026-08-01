-- =============================================================================
-- declared-routes.lua - A handler states what it answers; the gateway enforces it
-- =============================================================================
--
-- This script runs on the SERVER, not on the proxy.  That is the whole idea.
--
-- A gateway in front of an HTTP handler can refuse a request the handler was
-- always going to refuse — a DELETE on a login endpoint that takes POST and GET
-- — and refusing it at the edge costs no connect, no pooled socket, no round
-- trip and no work in the handler.  What the gateway cannot do is know which
-- methods those are.
--
-- Written on the proxy, that method list would be a second copy of something
-- this file already states, in another runtime and soon in another process.
-- Two copies drift: this handler grows PATCH, the gateway goes on refusing it,
-- and the 405 is explicable from neither side alone.  So the declaration lives
-- here, next to the code that implements it, and the daemon publishes it to
-- whichever proxies forward to this runtime — the same way it already publishes
-- where this runtime is.
--
-- USAGE:
--   socketley create server api -p 9001 --lua declared-routes.lua -s
--   socketley create proxy gateway -p 8080 --backend api --protocol http -s
--
-- Note the backend is the runtime NAME.  A backend written as 127.0.0.1:9001 is
-- an address, not a name, and an address has no declaration to look up: that
-- proxy forwards everything, exactly as before.
--
-- =============================================================================

routes = {
    -- The AJAX endpoint.  A browser posting to this from another origin sends
    -- an OPTIONS preflight first — see the note at the bottom; declaring only
    -- POST here does NOT break it.
    { path = "/endpoint/login",  methods = { "POST", "GET" } },
    { path = "/endpoint/logout", methods = { "POST" } },

    -- A single method may be written as a bare string.
    { path = "/health", methods = "GET" },

    -- A trailing '*' is a literal prefix, and that is the whole pattern
    -- language.  Exact paths win over prefixes; the longest prefix wins among
    -- prefixes.
    { path = "/static/*", methods = { "GET" } },
}

function on_http_request(req)
    -- Still validating, and this is not belt and braces.
    --
    -- The gateway confirmed the METHOD.  It did not confirm that this body is a
    -- well-formed login, and it is not the only way in: this server listens on
    -- 9001, and anything that reaches 9001 passed no edge at all.  A handler
    -- that stops checking because "the gateway checks" is safe only for as long
    -- as every request arrives through the gateway — a property of the
    -- deployment, not of this file.
    if req.path == "/endpoint/login" and req.method == "POST" then
        local user = string.match(req.body or "", "user=([%w_%-]+)")
        if not user then
            return { status = 400, body = "user required\n" }
        end
        return {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            body = '{"ok":true,"user":"' .. user .. '"}',
        }
    end

    if req.path == "/health" then
        return { status = 200, body = "ok\n" }
    end

    -- A path this script never declared.  Perfectly legal: a declaration speaks
    -- about the paths it names and says nothing about the others, so the
    -- gateway forwards these untouched.  Declaring one route does not hide the
    -- rest of the site.
    return { status = 404, body = "not found\n" }
end

--[[
WHAT THE GATEWAY DOES WITH THIS

  POST /gateway/endpoint/login     forwarded — declared
  DELETE /gateway/endpoint/login   405 at the edge, with
                                     Allow: POST, GET, HEAD, OPTIONS
                                   and the server never hears about it
  HEAD /gateway/endpoint/login     forwarded.  HEAD is allowed wherever GET is
                                   (RFC 9110 9.3.2); refusing it would break
                                   every cache validator and link checker.
  OPTIONS /gateway/endpoint/login  answered 204 + Allow out of this declaration
                                   — "what may I do here", RFC 9110 9.3.7.
  DELETE /gateway/reports/2024     forwarded.  Nothing declares /reports/*.

CORS, WHICH IS WHERE THIS FEATURE USUALLY GOES WRONG

A browser sends an OPTIONS *preflight* before any request that is not simple —
any POST that is not a form encoding, anything carrying Authorization or a
custom header.  A gateway that answers that preflight out of the declaration
answers it without Access-Control-Allow-Origin, because a declaration says
nothing about origins.  The browser then blocks the real request, which is never
sent at all, and what you see is a CORS error on a request your code never made.

So a preflight — an OPTIONS carrying Origin and Access-Control-Request-Method —
is always forwarded here, whatever this declaration says.  Origin policy lives
with the handler:

    function on_http_request(req)
        if req.method == "OPTIONS" then
            return { status = 204, headers = {
                ["Access-Control-Allow-Origin"]  = "https://app.example",
                ["Access-Control-Allow-Methods"] = "POST, GET",
                ["Access-Control-Allow-Headers"] = "content-type",
            } }
        end
        ...
    end

A route that declares OPTIONS itself always gets it, preflight or not.

WHAT A DECLARATION MAY HOLD

A path and a set of methods.  Not content types, not schemas, not roles, not
parameter types.  Those are rules that would have to be right in two runtimes at
once, and a declaration with enough of them is a gateway configuration language
whose every sentence is a second place to be wrong.  Policy that needs more than
the request line belongs in the proxy's filter chain — see filter-chain.lua.

SEVERAL BACKENDS, OR AN @group

One rule: nothing is refused that EITHER possible target might have served.

  * A path only some of them declare is dropped.  A runtime that never mentioned
    /login may well serve /login, and the request could land on that one.
  * A path all of them declare keeps the UNION of their methods.  The proxy
    picks a target per connection and cannot know which.

So one member that declares nothing leaves the gateway in front of that group
enforcing nothing at all — quietly, and on purpose.  It has told us nothing
about what it answers.  The same is true of a backend written as an address
rather than a name: an address has no declaration to look up.

CHANGING IT

Edit this file and run `socketley reload-lua api`.  The gateway is not
restarted, not reconfigured and not told anything: the new declaration is
published to it.  A malformed entry refuses the script at load time with the
reason on stderr, rather than being dropped — a declaration that is not the one
in the file is invisible from both sides.

Test:
  socketley create server api -p 9001 --lua declared-routes.lua -s
  socketley create proxy gateway -p 8080 --backend api --protocol http -s

  curl -i -X DELETE localhost:8080/gateway/endpoint/login   # 405 + Allow
  curl -i -X OPTIONS localhost:8080/gateway/endpoint/login  # 204 + Allow
  curl -i -d 'user=alice' localhost:8080/gateway/endpoint/login
  socketley stats api | grep bytes_in    # unchanged by the two refusals
]]
