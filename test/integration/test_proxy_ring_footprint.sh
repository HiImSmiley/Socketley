#!/usr/bin/env bash
# Integration test: what a proxy holds once traffic has turned its receive ring
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A provided-buffer ring hands out its buffers in turn, so once a proxy has
# read a few hundred times every buffer has been written and the whole ring is
# resident.  The proxy's was 512 buffers of 64 KiB -- 32 MiB per proxy process
# for as long as it lived, which no idle-connection test sees, because an idle
# connection never draws a buffer.  Measured after 32 clients relayed through
# it for five seconds: 43.5 MB, and 14.6 MB with a ring of 64.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the ring's footprint growing back: the worker's growth across enough
#     reads to turn any ring of up to 4,096 buffers
#   * the traffic not having arrived, in which case the growth measures nothing
#     -- every byte echoed must come back
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
BEPID=""
cleanup(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
not_asserted(){ TOTAL=$((TOTAL+1)); echo "  NOT ASSERTED [$1]: $2"; }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a proxy's receive ring costs what it is, once turned ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
# Not grep -q: it exits at the first match, nm dies of SIGPIPE, and pipefail
# reports the pipeline as failed -- this check never fired under Sanitize.
SANITIZED=""
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && SANITIZED=1

P=$((SL_PORT_BASE + 117)); BP=$((P + 1))
BUDGET_MB=16          # 4 MiB of ring and the relay's own buffers; 512 x 64 KiB read 33

cat > "$WORK/echo.py" <<'PY'
import socket, sys, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(128)
def echo(c):
    while True:
        b = c.recv(65536)
        if not b: break
        c.sendall(b)
while True:
    c, _ = srv.accept(); threading.Thread(target=echo, args=(c,), daemon=True).start()
PY
python3 "$WORK/echo.py" "$BP" >/dev/null 2>&1 &
BEPID=$!
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$BP " && break; sleep 0.1; done

daemon_isolate proxyring
daemon_start "$BIN"
"$BIN" create proxy pr -p "$P" --backend "127.0.0.1:$BP" --protocol tcp -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$P" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
if [ -z "${WORKER:-}" ]; then
    echo "  FATAL: no worker on $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi
rss(){ awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo 0; }

BEFORE=$(rss)
# 32 connections, each 256 round trips of 16 KiB: 8,192 reads a side, enough
# to turn a ring of any size this proxy has had.
ECHOED=$(timeout 120 python3 - "$P" <<'PY'
import socket, sys, threading
port, total = int(sys.argv[1]), [0]
lock = threading.Lock()
def one():
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(10)
    msg, got = b"r" * 16384, 0
    for _ in range(256):
        s.sendall(msg)
        need = len(msg)
        while need:
            b = s.recv(need)
            if not b: break
            need -= len(b); got += len(b)
    s.close()
    with lock: total[0] += got
ts = [threading.Thread(target=one) for _ in range(32)]
for t in ts: t.start()
for t in ts: t.join()
print(total[0])
PY
) || ECHOED=0
sleep 0.5
AFTER=$(rss)
GREW=$(( (AFTER - BEFORE) / 1024 ))
WANT=$(( 32 * 256 * 16384 ))
echo "  $ECHOED of $WANT bytes echoed; worker RSS $((BEFORE / 1024)) -> $((AFTER / 1024)) MB, grew $GREW MB"

# ── 1. the traffic arrived ──────────────────────────────────────────────────
if [ "$ECHOED" = "$WANT" ]; then pass
else fail "every byte relayed comes back" "$ECHOED of $WANT"; fi

# ── 2. and the ring it turned costs what it is ──────────────────────────────
if [ -n "$SANITIZED" ]; then
    not_asserted "a turned ring stays within ${BUDGET_MB} MB" \
        "grew $GREW MB; RSS under ASan measures its redzones and quarantine"
elif [ "$GREW" -le "$BUDGET_MB" ]; then pass
else fail "a turned ring stays within ${BUDGET_MB} MB" "the worker grew $GREW MB" \
          "-- a provided-buffer ring is resident in full once turned, so its count" \
          "   times its size is what every proxy process holds"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
