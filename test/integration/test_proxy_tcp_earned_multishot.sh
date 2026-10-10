#!/usr/bin/env bash
# suite: quiet -- compares two arms' RSS under an upload that load beside it
# would reshape.
# Integration test: a TCP relay arms multishot only for connections that
# exchange messages, and a stream keeps what single-shot holds
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Below MULTISHOT_MIN_CLIENTS every proxy read was single-shot, which costs a
# re-arm per message: on 64-byte round trips through 32 connections the same
# binary with the arm toggled measured -10.2% CPU per round trip with
# multishot.  Arming every TCP connection bought that and gave up the reason
# single-shot was kept -- a multishot recv drains the socket into the queue
# before any decline lands, so 16 uploads into a backend that does not read held
# 60-69 MB against 25.  A connection now earns multishot after a run of reads
# that each drained the socket, and loses it at the first that filled its
# buffer or left more behind, so a stream -- which is what fills a socket --
# never has it.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a stream holding more than a single-shot arm holds -- the ratio is taken
#     against SOCKETLEY_RECV_MULTISHOT=0 on the same binary, and arming every
#     connection read 2.6x here
#   * a connection that earned multishot and then streams losing bytes when its
#     armed read is declined mid-upload: a cancelled multishot recv can have
#     data completions queued ahead of its -ECANCELED
#   * the small exchanges still being answered, byte for byte
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
cleanup(){ [ -n "$BEPID" ] && kill -9 "$BEPID" 2>/dev/null; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a TCP relay's multishot arm is earned by exchanges ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
SANITIZED=""
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && SANITIZED=1

P=$((SL_PORT_BASE + 113)); BP=$((P + 1))

# C for the uploads, because a Python uploader is slow enough that the socket
# never holds much for a multishot read to drain -- the arm-every-connection
# build read 1.3x through it and 2.6x through this.
if ! gcc -O2 -pthread -o "$WORK/load" "$HERE/lib_hold_load.c" 2>"$WORK/cc.log"; then
    echo "  SKIP: no C compiler"; cat "$WORK/cc.log"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

# A backend that never reads, for the hold rows, and one that reads slowly and
# counts every byte per connection, for the integrity row.
cat > "$WORK/be.py" <<'PY'
import socket, sys, threading, time
port, mode, log = int(sys.argv[1]), sys.argv[2], sys.argv[3]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(512)
held, lock = [], threading.Lock()
def count(c):
    got = 0
    while True:
        time.sleep(0.002)
        try: b = c.recv(16384)
        except OSError: break
        if not b: break
        got += len(b)
    with lock:
        with open(log, "a") as f: f.write("%d\n" % got)
while True:
    c, _ = srv.accept()
    if mode == "sink": held.append(c)
    else: threading.Thread(target=count, args=(c,), daemon=True).start()
PY

cat > "$WORK/client.py" <<'PY'
# n connections: `small` 64-byte writes 5 ms apart, then `bulk` bytes, then hold.
import socket, sys, threading, time
port, n, small, bulk, hold = (int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]),
                              int(sys.argv[4]), float(sys.argv[5]))
def one():
    s = socket.create_connection(("127.0.0.1", port), 10)
    for _ in range(small):
        s.sendall(b"m" * 64); time.sleep(0.005)
    if bulk: s.sendall(b"b" * bulk)
    time.sleep(hold); s.close()
ts = [threading.Thread(target=one) for _ in range(n)]
for t in ts: t.start()
for t in ts: t.join()
PY

run_proxy() {   # tag -> a daemon and a TCP proxy, WORKER set; an env prefix reaches the daemon
    daemon_isolate "earnms-$1"
    daemon_start "$BIN"
    "$BIN" create proxy em -p "$P" --backend "127.0.0.1:$BP" --protocol tcp -s >/dev/null 2>&1 || true
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
    WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$P" '$4 ~ p"$" {
        if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
}
rss(){ awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo 0; }
held_mb() {   # clients bytes -> MB the worker added at its peak while C clients upload
    local base peak r cp
    base=$(rss); peak=$base
    "$WORK/load" up "$P" "$1" "$2" >/dev/null 2>&1 &
    cp=$!
    while kill -0 "$cp" 2>/dev/null; do r=$(rss); [ "${r:-0}" -gt "$peak" ] && peak=$r; sleep 0.05; done
    echo $(( (peak - base) / 1024 ))
}

python3 "$WORK/be.py" "$BP" sink "$WORK/unused" >/dev/null 2>&1 &
BEPID=$!
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$BP " && break; sleep 0.1; done

# ── 1. a stream holds what single-shot holds ────────────────────────────────
if [ -n "$SANITIZED" ]; then
    echo "  SKIP: RSS measures ASan's redzones and quarantine under Sanitize"
else
    SOCKETLEY_RECV_MULTISHOT=0 run_proxy single
    SINGLE=$(held_mb 16 4194304)
    # A worker that was never found, or is gone after the load, reads as 0 MB on both arms.
    SW=$WORKER; [ -n "$SW" ] && kill -0 "$SW" 2>/dev/null && SUP=up || SUP=gone
    daemon_stop
    run_proxy rule
    RULE=$(held_mb 16 4194304)
    RW=$WORKER; [ -n "$RW" ] && kill -0 "$RW" 2>/dev/null && RUP=up || RUP=gone
    daemon_stop
    echo "  16 uploads of 4 MiB into a backend that never reads: single-shot $SINGLE MB, this rule $RULE MB"
    if [ "$SUP" != up ] || [ "$RUP" != up ]; then
        fail "a stream keeps the single-shot hold" \
             "the proxy worker was not there to measure: single-shot pid '${SW}' $SUP, rule pid '${RW}' $RUP"
    elif [ "$RULE" -le $(( SINGLE * 3 / 2 + 4 )) ]; then pass
    else fail "a stream keeps the single-shot hold" \
              "the rule held $RULE MB against $SINGLE MB single-shot" \
              "-- a stream earned multishot, which drains the socket into the queue"; fi
fi

kill -9 "$BEPID" 2>/dev/null; wait "$BEPID" 2>/dev/null || true
: > "$WORK/counts"
python3 "$WORK/be.py" "$BP" count "$WORK/counts" >/dev/null 2>&1 &
BEPID=$!
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$BP " && break; sleep 0.1; done

# ── 2. a connection that earned the arm and then streams loses nothing ──────
run_proxy mixed
BULK=2097152
timeout 120 python3 "$WORK/client.py" "$P" 16 20 "$BULK" 1 >/dev/null 2>&1 || true
WANT=$(( 20 * 64 + BULK ))
for _ in $(seq 1 300); do [ "$(wc -l < "$WORK/counts")" -ge 16 ] && break; sleep 0.1; done
WHOLE=$(awk -v w="$WANT" '$1 == w { n++ } END { print n + 0 }' "$WORK/counts")
if [ "$WHOLE" = "16" ]; then pass
else fail "every byte of a mixed connection reaches the backend" \
          "$WHOLE of 16 connections delivered $WANT bytes; got: $(sort -n "$WORK/counts" | uniq -c | tr '\n' ' ')" \
          "-- a declined multishot read whose queued data completions were dropped"; fi

# ── 3. and the small exchanges are answered ─────────────────────────────────
daemon_stop
kill -9 "$BEPID" 2>/dev/null; wait "$BEPID" 2>/dev/null || true
cat > "$WORK/echo.py" <<'PY'
import socket, sys, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(64)
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
run_proxy echo
GOT=$(python3 - "$P" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(5)
ok = 0
for i in range(200):
    m = b"ping-%04d" % i
    s.sendall(m)
    d = b""
    while len(d) < len(m): d += s.recv(64)
    ok += d == m
print(ok)
PY
)
if [ "$GOT" = "200" ]; then pass
else fail "200 small round trips are answered byte for byte" "$GOT of 200"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
