#!/usr/bin/env bash
# Integration test: three backends under load, one of them breaks mid-traffic.
#
# It breaks in three different ways, because the proxy notices them by three
# different routes and only two of those work:
#
#   down   the listener goes away          -> connect is refused
#   rst    it accepts, then aborts         -> the connection dies mid-request
#   stall  it accepts and never answers    -> nothing fails, ever
#
# "stall" is the one that is not handled, and this test runs the configuration
# in which it is not handled: --health-check tcp.  A TCP health check connects
# successfully to a process that has stopped answering, so the backend stays
# healthy; a request that never completes is never recorded as an error, so the
# circuit breaker never opens; and no timeout bounds how long a backend may take
# to reply.  The backend therefore stays in rotation indefinitely and every
# request routed to it is held until the *client* gives up.  With a fixed client
# connection pool -- which is what every real client has -- those connections are
# consumed one by one and throughput collapses rather than degrading by the
# share of the pool that is broken.
#
# Two things make that configuration the one worth testing.  --sidecar, the
# documented shorthand for a service-mesh proxy, expands to exactly it
# (health_tcp + circuit + retry + drain).  And with no health check configured
# at all the same stall is unbounded: a single request against a stalled backend
# was measured still open, unanswered and unclosed after 100 s, with the daemon
# reporting the backend healthy and no circuit open.  Only --idle-timeout ever
# ends it, by closing the *client* as idle -- and the sweep that enforces it
# runs every 30 s, so a 5 s idle timeout first acted at 29 s.
#
# --health-check http is the configuration that copes: it needs a 2xx from
# --health-path, which a stalled backend cannot produce, so it is marked
# unhealthy and traffic fails over cleanly.  Measured on the same load, one of
# three backends stalled: 37415 requests in the settled window, zero failures,
# nothing routed to the stalled backend.  That contrast is the shape of the fix
# -- the tcp probe and the breaker both need a notion of "answered in time".
#
# Every request carries a marker "<connection>-<sequence>" that the backend
# echoes, and each backend stamps its own id beside it.  That second stamp is
# what makes this a failover test instead of an availability test: it shows
# where traffic actually went, so "the proxy took the broken backend out of
# rotation" is checked directly rather than inferred from requests happening to
# succeed.
#
# This test wants a quiet machine: it is a closed-loop load test, so anything
# else competing for the four cores shows up as connect failures that belong to
# the machine and not to the proxy.
#
# Window boundaries are measured, never assumed.  The fault reports the instant
# it took effect and the analysis is offset from the load driver's own start, so
# a control command that takes a moment to land cannot shift a whole phase and
# make the wrong window look clean.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-failover-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

CTRL=19570; BE1=19571; BE2=19572; BE3=19573; PX=19580
NAME=foprox
CLIENTS=${CLIENTS:-12}
WIN=${WIN:-6}              # seconds per measured window
FAULTS=${FAULTS:-"down rst stall"}
MIN_REQS=1500              # a window thinner than this proved nothing
DPID=""; BEPID=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop $NAME >/dev/null 2>&1 || true
    "$BIN" remove $NAME >/dev/null 2>&1 || true
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: proxy failover under load ==="

if ! command -v python3 >/dev/null 2>&1; then echo "  SKIP: python3 required"; exit 0; fi

# ---- backends: one process, three ports, each able to break on command -----
cat > "$TMPD/be.py" <<'PYEOF'
import asyncio, socket, sys

LINGER = b"\x01\x00\x00\x00\x00\x00\x00\x00"


class Backend:
    def __init__(self, bid, port):
        self.bid, self.port = bid, port
        self.mode, self.server = "ok", None
        self.conns = set()

    async def listen(self):
        if self.server is None:
            self.server = await asyncio.start_server(
                self.handle, "127.0.0.1", self.port, reuse_address=True, backlog=256)

    async def unlisten(self):
        # No wait_closed(): it waits for live handlers, and under load there are
        # always live handlers, so the control reply would arrive seconds after
        # the effect and every window after it would be misaligned.
        if self.server is not None:
            self.server.close()
            self.server = None
        for w in list(self.conns):
            try:
                s = w.get_extra_info("socket")
                if s is not None:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER)
                w.close()
            except Exception:
                pass
        self.conns.clear()

    def abort(self, writer):
        try:
            s = writer.get_extra_info("socket")
            if s is not None:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER)
            writer.close()
        except Exception:
            pass

    async def handle(self, reader, writer):
        self.conns.add(writer)
        try:
            if self.mode == "rst":
                self.abort(writer); return
            buf = b""
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n\r\n" in buf:
                    head, buf = buf.split(b"\r\n\r\n", 1)
                    if self.mode == "stall":
                        await asyncio.sleep(3600)   # up, accepting, never answering
                        return
                    if self.mode == "rst":
                        self.abort(writer); return
                    line = head.split(b"\r\n", 1)[0].split(b" ")
                    marker = line[1].lstrip(b"/") if len(line) > 1 else b"?"
                    body = marker + b"|" + self.bid.encode()
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                                 b"Connection: keep-alive\r\n\r\n%s" % (len(body), body))
                await writer.drain()
        except Exception:
            pass
        finally:
            self.conns.discard(writer)
            try:
                writer.close()
            except Exception:
                pass


async def main():
    ctrl = int(sys.argv[1])
    bes = {}
    for spec in sys.argv[2:]:
        bid, port = spec.split(":")
        bes[bid] = Backend(bid, int(port))
        await bes[bid].listen()
    print("ready", flush=True)

    async def ctl(reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                p = line.decode().split()
                if len(p) < 2 or p[1] not in bes:
                    writer.write(b"err\n"); await writer.drain(); continue
                b = bes[p[1]]
                if p[0] == "down":
                    await b.unlisten()
                elif p[0] == "up":
                    b.mode = "ok"; await b.listen()
                elif p[0] in ("stall", "rst", "ok"):
                    b.mode = p[0]
                else:
                    writer.write(b"err\n"); await writer.drain(); continue
                writer.write(b"ok\n"); await writer.drain()
        except Exception:
            pass
    srv = await asyncio.start_server(ctl, "127.0.0.1", ctrl, reuse_address=True)
    async with srv:
        await srv.serve_forever()


asyncio.run(main())
PYEOF

# ---- load driver: marker-verified, reconnecting, timestamped ---------------
cat > "$TMPD/drv.py" <<'PYEOF'
import asyncio, re, sys, time

port, name, clients, secs = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
CLEN = re.compile(rb"Content-Length: (\d+)", re.I)
STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")
MARKER = re.compile(r"^(\d+)-(\d+)$")
events = []
counter = [0]


async def worker(deadline):
    while time.time() < deadline:
        counter[0] += 1
        cid = counter[0]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=4)
        except Exception:
            events.append((time.time(), "connectfail", "-"))
            await asyncio.sleep(0.02)
            continue
        seq = 0
        try:
            while time.time() < deadline:
                marker = f"{cid}-{seq}"
                writer.write(f"GET /{name}/{marker} HTTP/1.1\r\nHost: h\r\n"
                             f"Connection: keep-alive\r\n\r\n".encode())
                await writer.drain()
                t_send = time.time()
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=4)
                    if not chunk:
                        events.append((t_send, "missing", "-")); raise StopIteration
                    head += chunk
                hdr, rest = head.split(b"\r\n\r\n", 1)
                m = STATUS.match(hdr); code = int(m.group(1)) if m else 0
                m = CLEN.search(hdr); need = int(m.group(1)) if m else 0
                while len(rest) < need:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=4)
                    if not chunk:
                        events.append((t_send, "truncated", "-")); raise StopIteration
                    rest += chunk
                if code != 200:
                    events.append((t_send, f"http{code}", "-")); raise StopIteration
                got, _, be = rest[:need].decode("latin1").partition("|")
                if got == marker:
                    events.append((t_send, "ok", be or "?"))
                else:
                    mm = MARKER.match(got)
                    events.append((t_send, "garbled" if not mm else
                                   "crossed" if int(mm.group(1)) != cid else "wrongseq",
                                   be or "?"))
                    raise StopIteration
                seq += 1
                await asyncio.sleep(0.004)
        except StopIteration:
            pass
        except asyncio.TimeoutError:
            events.append((time.time(), "timeout", "-"))
        except (ConnectionResetError, BrokenPipeError):
            events.append((time.time(), "reset", "-"))
        except Exception:
            events.append((time.time(), "err", "-"))
        finally:
            try:
                writer.close()
            except Exception:
                pass


async def main():
    t0 = time.time()
    print(f"START {t0!r}", flush=True)
    await asyncio.gather(*(worker(t0 + secs) for _ in range(clients)))
    sys.stdout.write("".join(f"{t!r} {k} {b}\n" for t, k, b in events))


asyncio.run(main())
PYEOF

cat > "$TMPD/an.py" <<'PYEOF'
import sys
from collections import Counter
path = sys.argv[1]
wins = [(s.split(":")[0], float(s.split(":")[1]), float(s.split(":")[2])) for s in sys.argv[2:]]
ev = []
for line in open(path):
    p = line.split()
    if len(p) != 3 or p[0] == "START":
        continue
    try:
        ev.append((float(p[0]), p[1], p[2]))
    except ValueError:
        pass
for label, a, b in wins:
    k, be = Counter(), Counter()
    for t, kind, bid in ev:
        if a <= t < b:
            k[kind] += 1
            if kind == "ok" and bid != "-":
                be[bid] += 1
    tot = sum(k.values()); okn = k.get("ok", 0)
    print(f"WINDOW {label} total={tot} ok={okn} fail={tot-okn} "
          f"be:{','.join(f'{x}={y}' for x, y in sorted(be.items())) or 'none'} "
          f"kinds:{','.join(f'{x}={y}' for x, y in sorted(k.items()) if x != 'ok') or 'none'}")
PYEOF

ctl() { python3 -c "
import socket, sys, time
s = socket.create_connection(('127.0.0.1', $CTRL), timeout=5)
s.sendall(('$1 $2').encode() + b'\n')
s.settimeout(5)
try:
    r = s.recv(64).decode().strip()
except socket.timeout:
    r = 'TIMEOUT'
s.close()
print(r or 'EMPTY', repr(time.time()))
"; }

python3 "$TMPD/be.py" $CTRL be1:$BE1 be2:$BE2 be3:$BE3 >"$TMPD/be.log" 2>&1 &
BEPID=$!
for _ in $(seq 1 60); do grep -q ready "$TMPD/be.log" 2>/dev/null && break; sleep 0.1; done

"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do "$BIN" ps >/dev/null 2>&1 && break; sleep 0.1; done

# health-interval 1 / threshold 2 and circuit-timeout 5 keep every reaction the
# proxy is capable of well inside a 6 s window -- a slower configuration would
# make a clean window mean "the test was too short", not "the proxy coped".
"$BIN" create proxy $NAME -p $PX \
    --backend "127.0.0.1:$BE1,127.0.0.1:$BE2,127.0.0.1:$BE3" --protocol http \
    --health-check tcp --health-interval 1 --health-threshold 2 \
    --circuit-threshold 3 --circuit-timeout 5 --retry 2 -s >/dev/null 2>&1 || true
for _ in $(seq 1 60); do nc -z 127.0.0.1 $PX 2>/dev/null && break; sleep 0.1; done
sleep 0.5

if "$BIN" stats $NAME >/dev/null 2>&1; then ok; else
    bad "setup" "the proxy runtime is not up -- everything below is meaningless"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

field() { printf '%s\n' "$1" | grep "^WINDOW $2 " | grep -o "\b$3=[0-9]*" | cut -d= -f2 | head -1; }

for F in $FAULTS; do
    echo "  -- fault: $F --"

    # Longer than circuit-timeout, so a breaker left open by the previous fault
    # has closed again.  Without this the "healthy" window of the next fault
    # starts with a backend still out of rotation, and the run reports an
    # imbalance that belongs to the test rather than to the proxy.
    sleep 7

    # Warm-up, discarded: the first connections pay for pool fill.
    python3 "$TMPD/drv.py" "$PX" "$NAME" 6 2 >/dev/null 2>&1 || true

    python3 "$TMPD/drv.py" "$PX" "$NAME" "$CLIENTS" "$((WIN * 3))" \
        >"$TMPD/ev_$F.txt" 2>"$TMPD/drv_$F.err" &
    LPID=$!
    START=""
    for _ in $(seq 1 40); do
        START=$(head -1 "$TMPD/ev_$F.txt" 2>/dev/null | awk '{print $2}')
        [ -n "$START" ] && break
        sleep 0.2
    done
    if [ -z "$START" ]; then
        bad "$F: driver started" "no START line -- $(head -3 "$TMPD/drv_$F.err" 2>/dev/null | tr '\n' ' ')"
        kill $LPID 2>/dev/null; continue
    fi

    sleep "$WIN"
    R=$(ctl "$F" be2); FAULT_T=$(echo "$R" | awk '{print $2}')
    # Sampled late in the fault window, after every reaction the proxy is
    # configured for has had time to happen: health threshold 2 at 1 s, and a
    # circuit that opens on the 3rd error.
    sleep $((WIN - 2))
    MIDSTATS=$("$BIN" stats $NAME 2>/dev/null)
    sleep 2
    R=$(ctl up be2); RESTORE_T=$(echo "$R" | awk '{print $2}')
    wait $LPID 2>/dev/null

    if [ -z "${FAULT_T:-}" ] || [ -z "${RESTORE_T:-}" ]; then
        bad "$F: fault timestamps readable" "fault='${FAULT_T:-}' restore='${RESTORE_T:-}'"
        continue
    fi

    # The settled window starts 3 s after the fault: health threshold 2 at a 1 s
    # interval, and a circuit that opens on the 3rd error, both land inside it.
    OUT=$(python3 "$TMPD/an.py" "$TMPD/ev_$F.txt" \
        "healthy:$(python3 -c "print($START+1)"):${FAULT_T}" \
        "settled:$(python3 -c "print($FAULT_T+3)"):${RESTORE_T}" \
        "restored:$(python3 -c "print($RESTORE_T+3)"):$(python3 -c "print($RESTORE_T+3600)")")
    echo "$OUT" | sed 's/^/     /'

    H_TOT=$(field "$OUT" healthy total);  H_OK=$(field "$OUT" healthy ok)
    S_TOT=$(field "$OUT" settled total);  S_OK=$(field "$OUT" settled ok)
    R_TOT=$(field "$OUT" restored total)
    S_BE2=$(field "$OUT" settled be2);    R_BE2=$(field "$OUT" restored be2)

    if [ -n "$H_TOT" ] && [ "$H_TOT" -ge "$MIN_REQS" ]; then ok; else
        bad "$F: healthy window carried load" "only ${H_TOT:-<none>} requests, wanted >= $MIN_REQS"
    fi
    if [ -n "$H_TOT" ] && [ -n "$H_OK" ] && [ "$H_TOT" -eq "$H_OK" ] && [ "$H_TOT" -gt 0 ]; then ok; else
        bad "$F: nothing fails while all three backends are healthy" \
            "${H_OK:-<none>} of ${H_TOT:-<none>} correct"
    fi

    # The broken backend must be out of rotation once the window has settled.
    # Judged two ways, because neither alone is enough.  No successful response
    # may carry its stamp -- but a backend that holds requests open produces no
    # responses at all, so silence there is not evidence.  The daemon's own view
    # settles it: either the health check marked it unhealthy or the breaker
    # opened.  "backends:" is checked first because it is printed
    # unconditionally: without it, an unreadable stats call and a healthy proxy
    # produce the same empty strings and compare equal.
    if [ "${S_BE2:-0}" -eq 0 ] 2>/dev/null; then ok; else
        bad "$F: the broken backend serves no more responses" "it still served ${S_BE2} requests"
    fi

    if ! printf '%s\n' "$MIDSTATS" | grep -q '^backends:'; then
        bad "$F: the daemon's view is readable" "stats printed no 'backends:' line -- the check below would compare two empty strings"
    else
        HB=$(printf '%s\n' "$MIDSTATS" | grep -o '^healthy_backends:[0-9]*' | cut -d: -f2)
        OC=$(printf '%s\n' "$MIDSTATS" | grep -o '^open_circuits:[0-9]*' | cut -d: -f2)
        OC=${OC:-0}     # printed only when non-zero, and 'backends:' proved the read
        if { [ -n "$HB" ] && [ "$HB" -lt 3 ]; } || [ "$OC" -ge 1 ]; then ok; else
            bad "$F: the proxy notices the backend is broken" \
                "with one of three backends $F, it still reports healthy_backends=${HB:-<absent>} and open_circuits=$OC"
        fi
    fi

    # And the clients must stop noticing.  Not "zero": a breaker that half-opens
    # every circuit-timeout spends a request finding out whether the backend is
    # back, and that cost is by design.  A backend still taking its full share
    # of a three-way rotation would show ~33% here.
    if [ -n "$S_TOT" ] && [ -n "$S_OK" ] && [ "$S_TOT" -gt 0 ] && \
       [ "$(( (S_TOT - S_OK) * 1000 / S_TOT ))" -le 5 ]; then ok; else
        bad "$F: clients see no failures once failover has settled" \
            "${S_OK:-<none>} of ${S_TOT:-<none>} correct -- $(printf '%s\n' "$OUT" | grep '^WINDOW settled' | sed 's/.*kinds://')"
    fi

    # Throughput, not just success rate.  A backend that holds requests open
    # instead of refusing them consumes the client's connections one by one, so
    # the surviving two backends can look perfect while almost nothing gets
    # through.  Two of three backends should carry well over half the load.
    if [ -n "$H_TOT" ] && [ -n "$S_TOT" ] && [ "$H_TOT" -gt 0 ] && \
       [ "$((S_TOT * 100 / H_TOT))" -ge 50 ]; then ok; else
        bad "$F: throughput survives the loss of one backend" \
            "${S_TOT:-<none>} requests in the settled window against ${H_TOT:-<none>} while healthy"
    fi

    if [ "${R_BE2:-0}" -gt 0 ] 2>/dev/null; then ok; else
        bad "$F: the backend returns to rotation after it recovers" \
            "it served ${R_BE2:-0} requests in ${R_TOT:-0} after restore"
    fi
done

if "$BIN" stats $NAME >/dev/null 2>&1; then ok; else bad "runtime alive" "the proxy did not survive"; fi
if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
