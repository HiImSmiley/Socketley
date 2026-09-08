-- Ping-pong fixture for measuring a CLIENT runtime.
--
-- A client dials out, so nothing can point a load generator at it -- bench.c
-- has no client category at all.  The runtime has to generate its own traffic,
-- and this is the smallest thing that does: send once on connect, and send
-- again for every reply.  The target echoes, so the loop runs at whatever rate
-- the client and the kernel allow.
--
-- The rate is read from the runtime's own message counter through `stats`
-- rather than printed here: a print per message would measure the print.
--
-- The floor for this shape is socketley_bench's own `server msg`, which is a C
-- client doing the same round trips against the same echo target.  The distance
-- between them is what the runtime costs over a C client -- which is the same
-- question the server matrix asks of the server, asked from the other end.
-- @BYTES@ is substituted by the harness before the runtime loads this: the
-- worker inherits the daemon's environment, not the CLI call's, so a size
-- passed as a variable never reaches here.
local payload = string.rep("x", @BYTES@)

function on_connect()
    self.send(payload)
end

function on_message(msg)
    self.send(payload)
end
