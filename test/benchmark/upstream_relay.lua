-- Relay fixture: a client's message goes to the upstream and its answer comes
-- back to that client.
--
-- `--upstream` is an OUTBOUND connection with Lua callbacks, not a transparent
-- relay -- a server given one without a script forwards nothing, which is how
-- the first draft of the server matrix came to report "port answered nothing".
-- Measuring the relay shape therefore needs the relay to be written down.
--
-- One client at a time, and that is deliberate rather than a limitation
-- overlooked: an upstream's answer carries no client identity, so with several
-- clients in flight there is nothing to route it by.  The benchmark drives one
-- connection on this fixture and a fixture that pretended otherwise would
-- deliver somebody else's reply.
local waiting = nil

function on_message(msg)
end

function on_client_message(client_id, msg)
    waiting = client_id
    self.upstream_send(1, msg)
end

function on_upstream(conn_id, data)
    if waiting then
        self.send(waiting, data)
    end
end
