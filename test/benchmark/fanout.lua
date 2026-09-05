-- The broadcast arm of `fanout`, and only that arm.
--
-- echo.lua is the opposite fixture and says why: it uses self.send precisely so
-- that one request is one reply.  Here the fan-out is the thing being measured,
-- so self.broadcast is the point rather than the trap -- and the client counts
-- deliveries, not round trips, which is what makes the number mean something.
--
-- on_client_message and not on_message, for the same reason echo.lua gives: an
-- empty on_message claims message handling and suppresses the default relay of
-- `--mode inout`, so this file measures self.broadcast alone instead of
-- self.broadcast plus a relay of every message on top of it.  Without it, the
-- broadcast arm would do 2N writes per publish and read as half the speed.
function on_message(msg)
end

function on_client_message(client_id, msg)
    self.broadcast(msg)
end
