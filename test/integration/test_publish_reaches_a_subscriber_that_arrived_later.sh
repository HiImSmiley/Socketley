#!/usr/bin/env bash
# Integration test: a subscriber that starts after the publisher still gets fed.
#
# A worker sends one control frame per PUBLISH so the daemon can fan it out to
# the other workers, and it does that whether or not any exist.  Measured on a
# cache with fifty subscribers and nothing else running, that frame was a fifth
# of the worker: 0.079 microseconds of worker per delivery against 0.063 with
# it suppressed, spent building three copies of a payload that MAX_BACKLOG then
# dropped.  So the daemon now tells each worker whether anybody is out there.
#
# Which buys exactly one way to lose a message, and this is the test for it.
# A cache running on its own is told there is nobody.  If it is still being
# told that when a second runtime starts and subscribes, every publish in
# between is dropped by the sender -- and nothing anywhere reports it, because
# from the cache's side not sending is what it was asked to do.
#
# So the order here is the point: the cache is alone and publishing FIRST, and
# the subscriber arrives SECOND.  test_worker_pubsub.sh creates both up front
# and so can never fail this way.
#
# The oracle is that file's, for the reason it gives at length: a proxy's
# placeholder inside the daemon loads the same script, so a log line proves
# nothing about which process heard the publish.  What only the serving process
# can do is answer a request with what it heard.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate publatecomer

# No backend runtime, and that is the test rather than an economy: every
# runtime is a worker process, so a second one anywhere makes the interest true
# before the cache ever publishes.  The first version of this file created a
# `server` for the proxy to forward to and passed against a deliberately broken
# daemon for exactly that reason.  The filter below answers /probe itself, so
# the backend is never dialled and this port stays empty on purpose.
BE_PORT=$((SL_PORT_BASE+430))
CACHE_PORT=$((SL_PORT_BASE+431))
PX_PORT=$((SL_PORT_BASE+432))
EARLY="early-at-$$"
LATE="late-at-$$"

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop px cachepub 2>/dev/null || true
    sleep 0.3
    "$BIN" remove px cachepub 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a publish reaches a subscriber that arrived later ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/px.lua"
cat > "$LUA" <<'LUAEOF'
local seen = "none"

socketley.subscribe("cachepub", "news", function(chan, msg)
    seen = msg
end)

filters = {
    function(req)
        if string.find(req.path, "/probe", 1, true) then
            return { status = 200, body = "seen=" .. seen .. "\n" }
        end
    end,
}
LUAEOF

probe() { curl -s --max-time 3 "http://127.0.0.1:$PX_PORT/px/probe" 2>/dev/null || printf ''; }
publish() { printf 'publish news %s\n' "$1" | timeout 5 nc -q0 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1 || true; }

create_ok "cache created" "$BIN" create cache cachepub -p "$CACHE_PORT" -s
ready_resp 127.0.0.1 "$CACHE_PORT" 20 || true

# Said out loud, because the whole test rests on it and it is one line to check.
RUNTIMES=$("$BIN" ls 2>/dev/null | tail -n +2 | grep -c . || true)
if [ "${RUNTIMES:-0}" = "1" ]; then
    pass
else
    fail "the cache is the only runtime" \
         "\`ls\` reports ${RUNTIMES:-0} runtimes, wanted 1" \
         "with a second worker anywhere the daemon has receivers to name, and" \
         "the state this test exists to enter is never entered"
fi

# ── The cache is alone, and it publishes ────────────────────────────────────
#
# Not decoration: this is what makes the daemon tell it there are no receivers,
# which is the state the assertion below has to survive.  Several, so a worker
# that only settles into that state after a few frames settles into it here.
for _ in $(seq 1 5); do publish "$EARLY"; done

# Five seconds, and the number is the point rather than padding.  The daemon
# decides who has receivers on its health tick, which is two seconds, so a test
# that does everything quickly never reaches the state it is here to test --
# the worker is still carrying the `true` it was born with, and a broken build
# passes.  This file did exactly that until the sleep was long enough for two
# ticks.
sleep 5

# ── And now a subscriber arrives ────────────────────────────────────────────
create_ok "proxy created" "$BIN" create proxy px -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$LUA" -s

# ── The assertion, published immediately and not after a readiness loop ─────
#
# The health tick is two seconds, and it refreshes the interest too -- so a
# build that only refreshes there passes this test comfortably if anything
# waits first.  The first version of this file waited for the proxy to answer
# an HTTP probe, which took long enough for a tick, and it passed against a
# deliberately broken daemon.  It is written this way because of that.
#
# Publishing here is sound and not merely fast: `create --start` returns after
# the worker has loaded its script, which is when socketley.subscribe has run,
# and reconcile_proxy_workers() forked that worker on the way.
publish "$LATE"

# Only now the readiness loop, which is a read and cannot repair a message
# that was never sent.
AFTER=""
for _ in $(seq 1 60); do
    AFTER=$(probe)
    [ "$AFTER" = "seen=$LATE" ] && break
    sleep 0.1
done

if [ "$AFTER" = "seen=$LATE" ]; then
    pass
else
    fail "a publish reaches a subscriber that started later" \
         "probe said '${AFTER:-<nothing>}', wanted 'seen=$LATE'" \
         "the cache was told there were no receivers while it was alone, and" \
         "went on believing it after this proxy's worker was forked"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
