-- =============================================================================
-- game-moves.lua - A game server whose moves reach players through a broker
-- =============================================================================
--
-- USAGE:
--   socketley create mqtt games --anonymous --persistent on -s
--   socketley create server referee -p 9000 --lua examples/mqtt/game-moves.lua -s
--   mosquitto_sub -i alice -c -q 1 -t 'game/42/#' -v    # a player's session
--   echo 'move 42 e2e4' | nc -q2 localhost 9000          # the referee takes a move
--
-- The referee checks a move and hands it to the broker: once on game/<id>/moves
-- at QoS 1, which every player's session keeps while the player is away, and
-- retained on game/<id>/last, which a player who opens the game later is given
-- the moment they subscribe.  A player whose connection broke comes back to
-- the moves they missed, in order, without asking the referee for anything.
-- =============================================================================

local games = {}

local function reply(id, text)
    self.send(id, text .. "\n")
end

function on_client_message(client_id, msg)
    local game, move = msg:match("^move (%w+) (%w+)")
    if not game then
        return reply(client_id, "usage: move <game> <move>")
    end
    if not move:match("^[a-h][1-8][a-h][1-8]$") then
        return reply(client_id, "refused: " .. move .. " is no move")
    end
    local g = games[game] or { n = 0 }
    games[game] = g
    g.n = g.n + 1
    local record = socketley.json_encode({ n = g.n, move = move })
    local ok, err = socketley.mqtt.publish("games", "game/" .. game .. "/moves", record, { qos = 1 })
    if not ok then
        return reply(client_id, "not sent: " .. tostring(err))
    end
    socketley.mqtt.publish("games", "game/" .. game .. "/last", record, { qos = 1, retain = true })
    reply(client_id, "move " .. g.n .. " sent")
end
