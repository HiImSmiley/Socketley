#!/usr/bin/env bash
# Integration test: the pacing point follows what the runtime actually owes
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# self.watermark() used to be half the write buffer and nothing else, so nothing
# could observe it changing.  It is now divided by the live connection count --
# but only while the runtime is holding more than write_pacing_budget, because
# dividing unconditionally measured 4,412 responses a second against 5,463 at
# eight streams: there the queues never fill, so the only effect was stopping a
# producer four times as often.
#
# Every clause of that rule is worth pinning, because each one was arrived at by
# a measurement that disagreed with the previous version:
#
#   * the deep value is still half the bound, for a runtime with nothing to do
#   * one stream is never paced lower, whatever the budget says
#   * thirty-two streams that ARE backed up are paced at budget/32 exactly
#   * and it is a hold, not a latch: once the backlog drains the deep value comes
#     back.  A runtime that got busy once must not pace for ever.
#   * a configured buffer still caps it from above -- the division can only make
#     the point smaller, never larger than the operator allowed
#
# What a build WITHOUT the rule does: assertion 3 reports the deep value, and
# nothing else in this file changes.  That is the assertion the file exists for.
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate pacing
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: the pacing point follows what the runtime owes ==="

DEEP=4194304        # half of the 8 MiB default bound
BUDGET=8388608      # write_pacing_budget
STREAMS=32
EXPECT=$(( BUDGET / STREAMS ))

cat > "$WORK/wm.lua" <<'LUA'
-- Streams on any path, and reports the smallest pacing point it was given.
local CHUNK = string.rep("x", 65536)
local PIECES = 200
local jobs, minwm = {}, nil
local function pump(cid)
    local job = jobs[cid]
    if not job then return end
    while job.sent < PIECES do
        local wm = self.watermark()
        if minwm == nil or wm < minwm then minwm = wm end
        if (self.pending(cid) or 0) >= wm then return end
        if not self.send_chunk(cid, CHUNK) then jobs[cid] = nil; return end
        job.sent = job.sent + 1
    end
    self.end_response(cid)
    jobs[cid] = nil
end
function on_writable(cid) pump(cid) end
function on_http_request(req)
    if req.path == "/report" then
        return { status = 200, body = "min=" .. tostring(minwm or 0) ..
                                     " now=" .. tostring(self.watermark()) }
    end
    if req.path == "/reset" then minwm = nil; return { status = 200, body = "ok" } end
    if not self.respond_stream(req.client_id, 200, {}) then
        return { status = 503, body = "no" }
    end
    jobs[req.client_id] = { sent = 0 }
    pump(req.client_id)
end
function on_disconnect(cid) jobs[cid] = nil end
LUA

# A reader per stream that falls behind on purpose, so the queues are genuinely
# holding bytes while the report is taken.  Bounded by bytes AND by time, so a
# build that never finishes a stream cannot hang the suite.
cat > "$WORK/slow.py" <<'PY'
import socket, sys, threading, time
port, n, want = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
deadline = time.monotonic() + 12
def one(i):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError:
        return
    s.settimeout(5)
    s.sendall(b"GET /s HTTP/1.1\r\nHost: x\r\n\r\n")
    got, paused = 0, False
    while got < want and time.monotonic() < deadline:
        try:
            b = s.recv(65536)
        except OSError:
            break
        if not b:
            break
        got += len(b)
        # A pause once the stream has begun backs every queue up, however slowly the runtime produces.
        if got >= 65536 and not paused:
            paused = True
            time.sleep(2)
        if got % (512 * 1024) < 65536:
            time.sleep(0.004)
    try:
        s.close()
    except OSError:
        pass
ts = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(n)]
for t in ts: t.start()
for t in ts: t.join(14)
PY

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1660))
"$BIN" create server pace -p $((P+1)) --lua "$WORK/wm.lua" -s >/dev/null 2>&1 || true
"$BIN" create server small -p $((P+2)) --lua "$WORK/wm.lua" --write-buffer 256K -s >/dev/null 2>&1 || true
for i in $(seq 1 100); do
    ready=1
    for p in $((P+1)) $((P+2)); do ss -ltn 2>/dev/null | grep -q ":$p " || ready=0; done
    [ "$ready" = 1 ] && break
    sleep 0.1
done
if [ "${ready:-0}" != 1 ]; then
    echo "  FATAL: the listeners never came up, so nothing below measures this build"
    echo "  Results: 0/0 passed (0 failed)"
    exit 2
fi
report(){ curl -s -m 10 "http://127.0.0.1:$1/report" 2>/dev/null || echo ""; }
field(){ printf '%s' "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k {print $2}'; }

# ── 1. the deep value is half the bound ─────────────────────────────────────
R=$(report $((P+1))); NOW=$(field "$R" now)
if [ "${NOW:-0}" = "$DEEP" ]; then pass
else fail "an idle runtime paces at half its bound" "report said '$R', expected now=$DEEP"; fi

# ── 2. one stream is never paced lower ──────────────────────────────────────
curl -s -m 20 "http://127.0.0.1:$((P+1))/one" -o /dev/null 2>/dev/null || true
R=$(report $((P+1))); MIN=$(field "$R" min)
if [ "${MIN:-0}" = "$DEEP" ]; then pass
else fail "a single stream keeps the deep pacing point" \
          "report said '$R', expected min=$DEEP -- one connection has nobody to share with"; fi

# ── 3. thirty-two backed-up streams are paced at budget/32 ──────────────────
curl -s -m 10 "http://127.0.0.1:$((P+1))/reset" -o /dev/null 2>/dev/null || true
python3 "$WORK/slow.py" $((P+1)) "$STREAMS" $((6 * 1024 * 1024)) >/dev/null 2>&1 || true
R=$(report $((P+1))); MIN=$(field "$R" min)
# MIN must be positive as well: the script reports min=0 when it never streamed
# at all, and 0 satisfies both bounds below -- so without this the assertion
# passes on a run where the load never arrived.
if [ -n "${MIN:-}" ] && [ "$MIN" -gt 0 ] && [ "$MIN" -le "$EXPECT" ] && [ "$MIN" -lt "$DEEP" ]; then
    echo "  the $STREAMS streams were paced at $MIN bytes (budget/$STREAMS is $EXPECT)"
    pass
else fail "$STREAMS backed-up streams share the budget" \
          "report said '$R', expected 0 < min <= $EXPECT (the $BUDGET budget over $STREAMS streams)" \
          "and strictly under the deep $DEEP -- a build that paces on the bound alone" \
          "reports exactly $DEEP here, which is what this assertion is for"; fi

# ── 4. it is a hold and not a latch ─────────────────────────────────────────
sleep 1
R=$(report $((P+1))); NOW=$(field "$R" now)
if [ "${NOW:-0}" = "$DEEP" ]; then pass
else fail "the deep point returns once the backlog drains" \
          "report said '$R' a second after the last stream ended, expected now=$DEEP;" \
          "a runtime that got busy once must not pace for the rest of its life"; fi

# ── 5. the configured buffer still caps it ──────────────────────────────────
R=$(report $((P+2))); NOW=$(field "$R" now)
if [ "${NOW:-0}" = "131072" ]; then pass
else fail "a smaller --write-buffer still decides the ceiling" \
          "report said '$R' on a 256K runtime, expected now=131072 -- the division" \
          "may only make the point smaller, never larger than was allowed"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
