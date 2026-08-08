#!/usr/bin/env bash
# Integration test: a member joining an @group while the gateway is saturated.
#
# ─── WHY THIS EXISTS BESIDE test_proxy_group_keepalive_load.sh ───────────────
#
# That file already makes the right assertion — "a member that joined starts
# receiving traffic" — and it passed for months while the thing it names was
# broken, because it runs at twelve clients paced at 20 ms.  The defect needs
# the gateway to be *busy*: the new member's address is announced, the gateway
# tries it, and only a gateway with thousands of requests a second in flight
# gets refused enough times in that window to matter.  At the paced rate it gets
# refused once or twice and carries on.
#
# So the load here is unpaced and the assertion is the same one.  It is a
# separate file rather than a higher CLIENTS in that one because that one is in
# the suite for other reasons — crossed delivery, ordering, drain-on-leave — and
# making all of it saturate would cost every run minutes to re-prove what one
# assertion needs.
#
# ─── WHAT IT DISCRIMINATES, AND WHY THE BOUND IS DERIVED ────────────────────
#
# Before the fix the joining member is announced to the gateway while its
# listener is still being bound in another process.  The gateway routes to it,
# is refused, and five refusals open the group circuit breaker — after which the
# member is excluded for the whole circuit timeout.  It does eventually serve;
# it serves when the breaker expires.
#
# That is why the bound is not a number picked to feel generous.  The only way
# a broken build reaches the assertion is by waiting out the circuit timeout, so
# the bound is derived from that timeout and nothing else: pass means "it served
# for some reason other than the breaker giving up".  The timeout is set here
# rather than left at its 30 s default so the number is stated once, in one
# place, and a failing run costs seconds instead of half a minute.
set -uo pipefail

SDIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-$SDIR/../../bin/Release/socketley}"
[ -x "$BIN" ] || { echo "ERROR: socketley not found at $BIN"; exit 1; }
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"

. "$SDIR/lib_ready.sh"
. "$SDIR/lib_create.sh"
. "$SDIR/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

# ── the one number, and everything derived from it ──────────────────────────
#
# Long enough that a build which only recovers when the breaker expires cannot
# beat the bound by luck; short enough that a failing run is quick.
CIRCUIT_TIMEOUT=10
# Half of it.  A correct build announces the member when its worker reports the
# listener is up, which is tens of milliseconds; a broken one cannot answer
# before CIRCUIT_TIMEOUT by construction.  Anywhere strictly between the two
# discriminates, and the midpoint is the furthest point from both.
JOIN_BOUND=$((CIRCUIT_TIMEOUT / 2))

# Unpaced.  This is the property under test: see the header.
CLIENTS=${CLIENTS:-48}
LOAD_SECS=${LOAD_SECS:-4}
# Below this the gateway was not saturated and the run proves nothing about the
# case this file exists for, so it is reported as a setup failure rather than a
# pass.  Far under what the machine does when it is idle (~25k/s observed).
MIN_RATE=3000

PORT_BASE=$((SL_PORT_BASE+860))
BE1=$((PORT_BASE+1)); BE2=$((PORT_BASE+2)); BE3=$((PORT_BASE+3))
M1=$((PORT_BASE+11)); M2=$((PORT_BASE+12)); M3=$((PORT_BASE+13))
GW=$((PORT_BASE+20))
GRP=sjgrp; GW_NAME=sjgw

daemon_isolate grpsat
TMPD="$SOCKETLEY_TMPD"
BEPID=""; LPID=""

cleanup() {
    [ -n "$LPID" ] && kill "$LPID" 2>/dev/null
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    for n in "$GW_NAME" sjm1 sjm2 sjm3; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a member joins an @group while the gateway is saturated ==="

# ── backends: three HTTP servers that name themselves ───────────────────────
cat >"$TMPD/be.py" <<'PY'
import socket, sys, threading

def serve(port, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(512)
    body = name.encode()
    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
            b"Connection: keep-alive\r\n\r\n%s" % (len(body), body))
    while True:
        try:
            c, _ = s.accept()
        except OSError:
            return
        threading.Thread(target=conn, args=(c, resp), daemon=True).start()

def conn(c, resp):
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    buf = b""
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
            while b"\r\n\r\n" in buf:
                _, buf = buf.split(b"\r\n\r\n", 1)
                c.sendall(resp)
    except OSError:
        pass
    finally:
        c.close()

for spec in sys.argv[1:]:
    p, n = spec.split("=")
    threading.Thread(target=serve, args=(int(p), n), daemon=True).start()
threading.Event().wait()
PY
python3 "$TMPD/be.py" "$BE1=be1" "$BE2=be2" "$BE3=be3" >/dev/null 2>&1 &
BEPID=$!
for p in $BE1 $BE2 $BE3; do ready_tcp 127.0.0.1 "$p" 5 || true; done

daemon_start "$BIN"

create_ok "member 1" \
    "$BIN" create proxy sjm1 -p $M1 --backend "127.0.0.1:$BE1" --protocol tcp -g $GRP -s
create_ok "member 2" \
    "$BIN" create proxy sjm2 -p $M2 --backend "127.0.0.1:$BE2" --protocol tcp -g $GRP -s
# The gateway owns the breaker whose timeout the bound is derived from.
create_ok "gateway" \
    "$BIN" create proxy "$GW_NAME" -p $GW --backend "@$GRP" --protocol http \
        --circuit-timeout "$CIRCUIT_TIMEOUT" -s

# Through the gateway's own prefix: an http proxy answers 404 to anything that
# does not start with "/<name>/", so a bare "/" would probe nothing but the
# gateway's own listener.  A 200 here means the group resolved to a member and
# that member answered.
if ! ready_http 127.0.0.1 "$GW" "/$GW_NAME/ready" 10; then
    echo "  FAIL [setup]: the gateway never answered on $GW"
    echo "  Results: $PASS/$((TOTAL+1)) passed"
    exit 1
fi

# ── the load: unpaced keep-alive clients, each recording who answered ───────
cat >"$TMPD/drv.py" <<'PY'
import socket, sys, threading, time

host, port, nclients, stopf, evf, path = (sys.argv[1], int(sys.argv[2]), int(sys.argv[3]),
                                          sys.argv[4], sys.argv[5], sys.argv[6])
import os
lock = threading.Lock()
out = open(evf, "w", buffering=1)

def client():
    req = ("GET %s HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n" % path).encode()
    s = None
    buf = b""
    while not os.path.exists(stopf):
        try:
            if s is None:
                s = socket.create_connection((host, port), timeout=5)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                buf = b""
            s.sendall(req)
            while b"\r\n\r\n" not in buf:
                d = s.recv(65536)
                if not d:
                    raise OSError("eof")
                buf += d
            head, rest = buf.split(b"\r\n\r\n", 1)
            n = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    n = int(line.split(b":")[1])
            while len(rest) < n:
                d = s.recv(65536)
                if not d:
                    raise OSError("eof")
                rest += d
            body, buf = rest[:n], rest[n:]
            with lock:
                out.write("%.6f %s\n" % (time.time(), body.decode(errors="replace")))
        except Exception:
            try:
                if s: s.close()
            except Exception:
                pass
            s = None
            with lock:
                out.write("%.6f ERR\n" % time.time())
            time.sleep(0.002)

ts = [threading.Thread(target=client, daemon=True) for _ in range(nclients)]
for t in ts: t.start()
while not os.path.exists(stopf):
    time.sleep(0.05)
PY

STOPF="$TMPD/stop"; EVF="$TMPD/events"
python3 "$TMPD/drv.py" 127.0.0.1 "$GW" "$CLIENTS" "$STOPF" "$EVF" "/$GW_NAME/x" \
    >"$TMPD/drv.err" 2>&1 &
LPID=$!

# Let it reach a steady rate, then measure that rate: an unsaturated run cannot
# fail the way this file is about, so it must not be allowed to pass either.
sleep 1
N0=$(wc -l <"$EVF" 2>/dev/null || echo 0)
sleep "$LOAD_SECS"
N1=$(wc -l <"$EVF" 2>/dev/null || echo 0)
RATE=$(( (N1 - N0) / LOAD_SECS ))
if [ "$RATE" -ge "$MIN_RATE" ]; then ok; else
    bad "the gateway was actually saturated" \
        "$RATE responses a second, wanted >= $MIN_RATE -- this run cannot show the defect"
fi

# ── the join ────────────────────────────────────────────────────────────────
T0=$(date +%s.%N)
create_ok "member 3 joins under load" \
    "$BIN" create proxy sjm3 -p $M3 --backend "127.0.0.1:$BE3" --protocol tcp -g $GRP -s

# The assertion.  Anchored on the create returning, bounded by half the circuit
# timeout -- see the header for why that is the discriminating bound and not a
# generous one.
FOUND=""
DEADLINE=$(python3 -c "print($T0 + $JOIN_BOUND)")
while :; do
    NOW=$(date +%s.%N)
    if awk -v t0="$T0" '$1 >= t0 && $2 == "be3" {found=1; exit} END{exit !found}' "$EVF" 2>/dev/null; then
        FOUND=$(awk -v t0="$T0" '$1 >= t0 && $2 == "be3" {print $1; exit}' "$EVF")
        break
    fi
    if python3 -c "import sys; sys.exit(0 if $NOW >= $DEADLINE else 1)"; then break; fi
    sleep 0.05
done

if [ -n "$FOUND" ]; then
    ELAPSED=$(python3 -c "print(f'{($FOUND - $T0)*1000:.0f}')")
    echo "  joined member first served after ${ELAPSED}ms (bound ${JOIN_BOUND}s, circuit timeout ${CIRCUIT_TIMEOUT}s)"
    ok
else
    bad "a member that joined under load starts receiving traffic" \
        "the new member served nothing in ${JOIN_BOUND}s; a build that only recovers when the
        group circuit breaker expires cannot answer before ${CIRCUIT_TIMEOUT}s, which is what
        that bound is derived from"
fi

: >"$STOPF"
wait "$LPID" 2>/dev/null
LPID=""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
