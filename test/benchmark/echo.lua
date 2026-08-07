-- Echo backend for the proxy overhead benchmark.
--
-- A plain server runtime answers nothing.  Neither `--mode in` nor
-- `--mode inout` sends anything back -- they describe which directions the
-- runtime accepts, not a reply -- so a benchmark pointed at one can only ever
-- time its own writes.  That is what the overhead test used to do on both of
-- its legs, which is why it could report that going through a proxy was faster
-- than not going through one.
--
-- Comparing a direct path against a proxied one needs a completed round trip on
-- each, so the backend has to answer.  This is the smallest thing that answers.
--
-- broadcast rather than a reply to one connection: it is the send path the
-- examples use, and the overhead test drives a single connection at a time --
-- the direct leg's own, then the proxy's -- so there is never a second client
-- for it to reach.
function on_message(msg)
    self.broadcast(msg)
end
