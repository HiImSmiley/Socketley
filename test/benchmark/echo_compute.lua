-- The other end of the count-hook question: an echo whose callback actually
-- computes something.
--
-- echo.lua's on_client_message is two bytecodes and one C call, and a trace
-- compiler has nothing to do with that -- which is why the deadline count hook
-- measured free against it (bench_lua_share.sh, 2026-08-25: 42581/43130 with
-- the hook against 42571/42644 without).  That result says nothing about a
-- script that loops, because the hook's whole cost is that LuaJIT cannot
-- compile a trace while one is installed, and a script with no hot loop has no
-- trace to lose.
--
-- So this fixture is echo.lua with a hot loop bolted on and nothing else
-- changed: same --mode, same reply bytes, same self.send, same empty
-- on_message.  The only difference between the two files is the bytecode
-- between arrival and reply, which is exactly the variable the hook acts on.
--
-- The arithmetic is deliberately dull.  `bit` is not one of the libraries the
-- sandbox opens (base, string, table, math, os, io, package -- see
-- lua_context.cpp), so the mix is multiply-add-modulo, kept under 2^21 at
-- every step so a double holds it exactly and the loop cannot drift into
-- floating-point behaviour that differs between the interpreter and a
-- compiled trace.
--
-- 20 passes over a 64-byte payload is ~1280 iterations per message: enough
-- that a trace is worth compiling, small enough that the round trip is still
-- recognisably the same benchmark.

local byte = string.byte

local PASSES = 20

function on_message(msg)
end

function on_client_message(client_id, msg)
    local h = 5381
    local n = #msg
    for _ = 1, PASSES do
        for i = 1, n do
            h = (h * 31 + byte(msg, i)) % 65536
        end
    end
    -- h is in [0, 65536) and the reply does not depend on it.  The comparison
    -- is what keeps the loop from being dead code the compiler may drop: it
    -- never fires, and it cannot be proven not to without running the loop.
    if h < 0 then return end
    self.send(client_id, msg)
end
