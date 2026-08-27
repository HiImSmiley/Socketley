-- chat-room: a browser chat in one server runtime.
--
--   socketley create server chat -p 8080 \
--       --http  examples/projects/chat-room/www \
--       --lua   examples/projects/chat-room/chat.lua -s
--
-- ─── WHY THERE IS NO on_http_request HERE ───────────────────────────────────
--
-- A server answers an HTTP request with on_http_request if the script defines
-- one, with the static file server if --http is set, and 404 otherwise -- in
-- that order.  Defining on_http_request here would therefore take the page away
-- from --http and make this file responsible for serving it.  It is not
-- defined, so www/ is served and this file only handles the socket.
--
-- WebSocket needs no flag either.  It is detected per connection from the
-- Upgrade header, frames are decoded before on_client_message sees them, and a
-- raw TCP client on the same port still works -- which is why the run script
-- can talk to this with netcat as well as with a browser.

local nicks   = {}   -- client_id -> nick
local history = {}   -- last N lines, so a joiner sees context
local HISTORY = 20

local function esc(s)
    return (s:gsub("[<>&]", { ["<"] = "&lt;", [">"] = "&gt;", ["&"] = "&amp;" }))
end

local function push(line)
    history[#history + 1] = line
    if #history > HISTORY then table.remove(history, 1) end
end

local function say(line)
    push(line)
    self.broadcast(line)
end

function on_start()
    socketley.log("chat-room up")
end

function on_connect(id)
    -- A name that is stable for the session and needs no round trip.
    nicks[id] = "guest" .. id
    for _, line in ipairs(history) do
        self.send(id, line)
    end
    say("* " .. nicks[id] .. " joined (" .. #self.clients() .. " here)")
end

-- Fires after the upgrade, and only for WebSocket clients.  on_connect has
-- already run by then, so this is where a browser-only fact belongs -- the
-- origin it came from, a cookie, a Sec-WebSocket-Protocol.
function on_websocket(id, headers)
    if headers.origin then
        socketley.log("ws client " .. id .. " from " .. headers.origin)
    end
end

function on_client_message(id, msg)
    msg = msg:gsub("^%s+", ""):gsub("%s+$", "")
    if msg == "" then return end

    local nick = nicks[id] or ("guest" .. id)

    local newnick = msg:match("^/nick%s+(%S+)$")
    if newnick then
        say("* " .. nick .. " is now " .. esc(newnick))
        nicks[id] = esc(newnick)
        return
    end

    if msg == "/who" then
        local names = {}
        for _, cid in ipairs(self.clients()) do
            names[#names + 1] = nicks[cid] or ("guest" .. cid)
        end
        self.send(id, "* here: " .. table.concat(names, ", "))
        return
    end

    if msg == "/quit" then
        self.send(id, "* bye")
        self.disconnect(id)
        return
    end

    say(nick .. ": " .. esc(msg))
end

function on_disconnect(id)
    local nick = nicks[id]
    nicks[id] = nil
    if nick then
        say("* " .. nick .. " left")
    end
end
