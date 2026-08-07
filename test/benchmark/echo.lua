-- Echo backend for every benchmark that measures a round trip.
--
-- A plain server runtime answers nothing.  Neither `--mode in` nor
-- `--mode inout` sends anything back -- they describe which directions the
-- runtime accepts, not a reply -- so a benchmark pointed at one can only ever
-- time its own writes.  Measuring how fast a request is served needs the
-- request to be served, so the fixture has to answer.  This is the smallest
-- thing that answers.
--
-- on_client_message and not on_message, and self.send and not self.broadcast.
-- That difference is the whole file:
--
--   self.broadcast reaches every connection, so with N concurrent clients one
--   request produces N replies.  A benchmark measuring N clients would then be
--   measuring N^2 work and calling the quotient a per-client rate.  It also
--   makes each client read replies to other clients' requests, which turns a
--   round trip into "read anything at all" and defeats the point of reading.
--
--   self.send answers the connection that asked, so one request is one reply,
--   and the client that reads one has had its own request served.
--
-- The empty on_message is load-bearing rather than left over.  Defining
-- on_message is what claims message handling and suppresses the default
-- broadcast of `--mode inout`; without it, an inout server would relay every
-- request to every other client on top of the reply below, and the fixture
-- would depend on which --mode the caller happened to pick.  With it, the same
-- file behaves identically in `in` and `inout`.
--
-- Works for WebSocket clients unchanged: self.send goes out through the
-- connection's own framing, so a WS client gets a text frame and a TCP client
-- gets a line.
function on_message(msg)
end

function on_client_message(client_id, msg)
    self.send(client_id, msg)
end
