-- =============================================================================
-- presence.lua - Who is online, and devices that sign in with a token of their own
-- =============================================================================
--
-- USAGE:
--   socketley create mqtt broker --anonymous --persistent on \
--       --lua examples/mqtt/presence.lua -s
--   mosquitto_sub -t 'presence/#' -v                   # online / offline, retained
--   mosquitto_sub -i phone-1 -t 'chat/#'                # phone-1 goes online
--   mosquitto_pub -u device -P device-token-1 -t 'telemetry/t' -m 21.5
--
-- on_connect and on_disconnect publish each client's state retained, so a client
-- subscribing later is told at once who is there.  on_auth lets in the devices
-- this script knows, whatever the broker's own files say, and keeps the broker's
-- verdict for everyone else by returning nothing.  on_publish turns a message
-- that is too large for the channel away.
-- =============================================================================

local DEVICES = { ["device-token-1"] = true, ["device-token-2"] = true }

function on_auth(c)
    if c.username == "device" then
        return DEVICES[c.password] == true
    end
end

function on_connect(client)
    self.publish("presence/" .. client.id, "online", { qos = 1, retain = true })
end

function on_disconnect(client, why)
    self.publish("presence/" .. client.id, "offline", { qos = 1, retain = true })
end

function on_publish(client, msg)
    if msg.topic:sub(1, 5) == "chat/" and #msg.payload > 4096 then
        return false
    end
end
