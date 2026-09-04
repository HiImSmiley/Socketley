#!/usr/bin/env bash
# Integration test: reload-lua does not wait on a runtime that has no script.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# reload-lua asks each matching runtime's worker to re-run its script and then
# waits for the route declaration that comes back.  It waited for one from
# runtimes that have no script at all -- and the worker is coded never to send
# one in that case:
#
#     void on_reload(...)  { ...
#         if (m_rt->get_lua_script_path().empty())
#             return;              // <- before send_routes()
#
# So the daemon spent its entire deadline on an answer nothing was going to
# send.  That wait is a ::poll inside a command handler, which is to say the
# daemon answers NOTHING while it runs.  Measured, interleaved over three
# passes, the only difference between the two runtimes being the script:
#
#     with a script     0.01s      without one     2.01s
#
# and a second client's ping during that window went from 0.7ms to 1997ms.
# `reload-lua *` across a mixed set is the ordinary case, and most runtimes do
# not carry a script.
#
# ─── HOW IT IS ASSERTED ────────────────────────────────────────────────────
#
# By what a SECOND client sees, not by how long the reload took.  The daemon
# being unable to answer anyone is the actual complaint, and it is also the
# robust signal: the defect is two full seconds against a healthy sub-10ms, so
# the threshold has three orders of magnitude of room and does not become a
# timing assertion that suite load can tip over.
#
# The scripted runtime is here so the fix cannot be "never wait for anything".
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: reload-lua does not wait on a scriptless runtime ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PA=$((SL_PORT_BASE+1494))
PB=$((SL_PORT_BASE+1495))

daemon_isolate reloadnoscript
trap 'kill ${PROBE:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/s.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, "A:" .. msg) end
LUAEOF

"$BIN" create server rl_lua -p "$PA" --lua "$SOCKETLEY_TMPD/s.lua" -s >/dev/null 2>&1
"$BIN" create server rl_bare -p "$PB" -s >/dev/null 2>&1
for _ in $(seq 1 60); do
    nc -z 127.0.0.1 "$PA" 2>/dev/null && nc -z 127.0.0.1 "$PB" 2>/dev/null && break
    sleep 0.1
done
sleep 1

# Both must really be out of process, or "the daemon did not block" is trivially
# true because there was no worker to wait for.
LUA_PID=$("$BIN" stats rl_lua  2>/dev/null | awk -F: '$1=="pid"{print $2;exit}')
BARE_PID=$("$BIN" stats rl_bare 2>/dev/null | awk -F: '$1=="pid"{print $2;exit}')
if [ -n "$LUA_PID" ] && [ "$LUA_PID" != "0" ] && [ -n "$BARE_PID" ] && [ "$BARE_PID" != "0" ]; then
    ok "both runtimes have a worker (pids $LUA_PID, $BARE_PID)"
else
    bad "both runtimes are out of process" \
        "pids were '${LUA_PID:-<none>}' and '${BARE_PID:-<none>}';" \
        "with no worker there is nothing for reload-lua to wait on and the" \
        "assertion below would pass for the wrong reason"
fi

# A second client, asking the daemon a trivial question over and over.  What it
# reports is the longest it ever had to wait for an answer.
cat > "$SOCKETLEY_TMPD/probe.py" <<'PYEOF'
import socket, sys, time
path, dur = sys.argv[1], float(sys.argv[2])
worst = 0.0
end = time.time() + dur
while time.time() < end:
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(30); s.connect(path); s.sendall(b"ping\n")
        buf = b""
        while b"\0" not in buf:
            c = s.recv(4096)
            if not c: break
            buf += c
        s.close()
    except Exception:
        pass
    worst = max(worst, (time.perf_counter() - t0) * 1000.0)
    time.sleep(0.005)
print(f"{worst:.1f}")
PYEOF

python3 "$SOCKETLEY_TMPD/probe.py" "$SOCKETLEY_SOCKET" 6 > "$SOCKETLEY_TMPD/worst.txt" 2>/dev/null &
PROBE=$!
sleep 1
"$BIN" reload-lua '*' >/dev/null 2>&1
RRC=$?
wait "$PROBE" 2>/dev/null
PROBE=""
WORST=$(cat "$SOCKETLEY_TMPD/worst.txt" 2>/dev/null)

# 1000ms sits three orders of magnitude above a healthy answer and half a
# second below the deadline the defect spends, so neither suite load nor a slow
# sanitizer build can move it across.
if [ -n "$WORST" ] && python3 -c "import sys; sys.exit(0 if $WORST < 1000 else 1)"; then
    ok "the daemon kept answering during reload-lua '*' (worst ${WORST}ms)"
else
    bad "reload-lua does not stop the daemon answering" \
        "a second client's worst wait was ${WORST:-<none>}ms while reload-lua ran;" \
        "~2000ms is the defect: the scriptless runtime was put on the wait list" \
        "and the worker returns from on_reload before it sends a declaration," \
        "so the whole deadline went on an answer nothing would send"
fi

if [ "$RRC" -eq 0 ]; then
    ok "and reload-lua itself succeeded (rc $RRC)"
else
    bad "reload-lua still works" "it returned $RRC"
fi

# The counter-assertion: the runtime that DOES have a script still runs it after
# the reload, so "wait for nothing" cannot be passed by waiting for nothing ever.
ANS=$(python3 -c "
import socket
try:
    s = socket.create_connection(('127.0.0.1', $PA), timeout=3)
    s.sendall(b'x\n'); print(s.recv(32).decode().strip()); s.close()
except Exception: print('ERR')" 2>/dev/null)
if [ "$ANS" = "A:x" ]; then
    ok "and the scripted runtime still runs its script after the reload ($ANS)"
else
    bad "the reload still reloads" \
        "the scripted runtime answered '${ANS:-<nothing>}' rather than 'A:x';" \
        "skipping the wait must not mean skipping the reload"
fi

for n in rl_lua rl_bare; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
