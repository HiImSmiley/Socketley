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
# Window boundaries are measured, never assumed -- and "measured" now means an
# event was observed, not that a stopwatch reached a number.  Each window opens
# on something that happened:
#
#   healthy   the first response the proxy serves
#   settled   the moment the daemon's own stats show it has noticed the fault
#   restored  the first response the repaired backend serves again
#
# and each closes only once it has carried traffic.  The old boundaries were
# "the fault instant plus three seconds" and "the restore instant plus three",
# against a driver that stopped at a fixed 3 x WIN -- so a control command that
# took a second longer than usual, which is what happens inside
# `bash test/run_all.sh`, moved the restored window past the end of the run and
# left it empty.  An empty window has to be reported as one; see lib_window.sh.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_window.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"

TMPD=$(mktemp -d /tmp/socketley-failover-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

# Ports come off one base so two runs can share a machine -- the socket and the
# state directory already do.
PORT_BASE=${PORT_BASE:-19570}
CTRL=$PORT_BASE
BE1=$((PORT_BASE+1)); BE2=$((PORT_BASE+2)); BE3=$((PORT_BASE+3))
PX=$((PORT_BASE+10))
NAME=foprox
CLIENTS=${CLIENTS:-12}
WIN=${WIN:-6}              # least seconds a measured window stays open
FAULTS=${FAULTS:-"down rst stall"}
MIN_REQS=1500              # a window thinner than this proved nothing
MIN_LATE=600               # ... in the two windows that follow a change
WIN_LATE=3                 # least seconds for those two
PHASE_CAP=45               # a window that has not filled by now is not going to
ANCHOR_WAIT=20             # bound on every "wait until it happened"
DRIVER_CAP=240             # the driver's own dead-man switch
DPID=""; BEPID=""; LPID=""
PASS=0; FAIL=0; HERR=0; TOTAL=0

cleanup() {
    [ -n "$LPID" ] && kill "$LPID" 2>/dev/null
    "$BIN" stop $NAME >/dev/null 2>&1 || true
    "$BIN" remove $NAME >/dev/null 2>&1 || true
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Kill by socket, not only by pid.  A CLI command run against a daemon that
    # is not up yet -- or not up any more -- starts one of its own, detached from
    # this shell; killing $DPID would leave that one running for good, holding
    # this test's ports.  The socket path comes from mktemp, so matching on it
    # can only ever hit daemons belonging to this run.
    # Matched by exact process name, never by a command-line pattern.  `pgrep -f
    # 'socketley daemon'` also matches a shell whose own command line merely
    # carries that string — a test runner, or this file — and the environ check
    # below cannot rule it out, because such a shell exports the very
    # SOCKETLEY_SOCKET being matched on.  The two tests together are what make
    # this reach daemons of this run and nothing else.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
# A claim this run could not put a question to -- an empty or too-thin window.
# Distinct from bad() because the two used to print the same sentence, and a run
# that measured nothing was read as a proxy that routed wrongly.  Both end the
# run non-zero; only one of them is about the product.
herr() { TOTAL=$((TOTAL+1)); HERR=$((HERR+1)); echo "  NOT MEASURABLE [$1]: $2"; }

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
#
# It writes each request down as it finishes -- when it was sent, when it was
# answered, what came back and which backend stamped it -- and keeps going until
# a stop file appears.  Both changes exist for the same reason: the windows are
# decided from these events while the run is still going, so the events have to
# be readable while the run is still going, and the run has to still be going
# when the last window opens.  The old driver buffered everything to the end and
# stopped at a fixed 3 x WIN, which is how the restored window came to be
# measured after the traffic had stopped.
cat > "$TMPD/drv.py" <<'PYEOF'
import asyncio, os, re, sys, time

port, name, clients = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
cap, stopfile = float(sys.argv[4]), sys.argv[5]
CLEN = re.compile(rb"Content-Length: (\d+)", re.I)
STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")
MARKER = re.compile(r"^(\d+)-(\d+)$")
out = sys.stdout
counter = [0]
stop = None


class Dead(Exception):
    """This connection cannot carry another request."""


def ev(t_send, kind, be, cid):
    out.write(f"EV {t_send!r} {time.time()!r} {kind} {be} {cid}\n")


async def flusher():
    while not stop.is_set():
        out.flush()
        await asyncio.sleep(0.1)
    out.flush()


async def watchdog():
    end = time.time() + cap
    while time.time() < end and not os.path.exists(stopfile):
        await asyncio.sleep(0.05)
    stop.set()


async def worker():
    while not stop.is_set():
        counter[0] += 1
        cid = counter[0]
        t_send = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=4)
        except Exception:
            ev(t_send, "connectfail", "-", cid)
            await asyncio.sleep(0.02)
            continue
        out.write(f"CONN {cid} {time.time()!r}\n")
        seq = 0
        try:
            while not stop.is_set():
                marker = f"{cid}-{seq}"
                writer.write(f"GET /{name}/{marker} HTTP/1.1\r\nHost: h\r\n"
                             f"Connection: keep-alive\r\n\r\n".encode())
                await writer.drain()
                t_send = time.time()
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=4)
                    if not chunk:
                        ev(t_send, "missing", "-", cid); raise Dead
                    head += chunk
                hdr, rest = head.split(b"\r\n\r\n", 1)
                m = STATUS.match(hdr); code = int(m.group(1)) if m else 0
                m = CLEN.search(hdr); need = int(m.group(1)) if m else 0
                while len(rest) < need:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=4)
                    if not chunk:
                        ev(t_send, "truncated", "-", cid); raise Dead
                    rest += chunk
                if code != 200:
                    ev(t_send, f"http{code}", "-", cid); raise Dead
                got, _, be = rest[:need].decode("latin1").partition("|")
                if got == marker:
                    ev(t_send, "ok", be or "?", cid)
                else:
                    mm = MARKER.match(got)
                    ev(t_send, "garbled" if not mm else
                       "crossed" if int(mm.group(1)) != cid else "wrongseq",
                       be or "?", cid)
                    raise Dead
                seq += 1
                await asyncio.sleep(0.004)
        except Dead:
            pass
        except asyncio.TimeoutError:
            ev(t_send, "timeout", "-", cid)
        except (ConnectionResetError, BrokenPipeError):
            ev(t_send, "reset", "-", cid)
        except Exception:
            ev(t_send, "err", "-", cid)
        finally:
            try:
                writer.close()
            except Exception:
                pass


async def main():
    global stop
    stop = asyncio.Event()
    await asyncio.gather(*([worker() for _ in range(clients)]
                           + [flusher(), watchdog()]), return_exceptions=True)


asyncio.run(main())
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

# Wait on the daemon's IPC socket directly, never by polling with a CLI command.
# Every CLI command auto-starts a daemon when the socket does not answer yet --
# cli.cpp's ensure_daemon() forks, setsids and re-execs 'socketley daemon' -- so
# polling 'ps' against the daemon this test has just launched races it and spawns
# a second, orphaned one.  Whichever loses the bind exits, and when the loser is
# $DPID the pid this test watches becomes a zombie while an orphan serves the
# run.  Measured at 2 spawned orphans in 30 startups of this sequence.
cat > "$TMPD/waitsock.py" <<'PYEOF'
import socket, sys, time

path = sys.argv[1]
end = time.time() + float(sys.argv[2])
while time.time() < end:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(0.4)
        s.connect(path)
        s.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.02)
    finally:
        try:
            s.close()
        except OSError:
            pass
sys.exit(1)
PYEOF

SOCKETLEY_DLOG="$TMPD/daemon.log"
"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
python3 "$TMPD/waitsock.py" "$SOCKETLEY_SOCKET" 8 >/dev/null 2>&1 || true

# The daemon that answers is the one this test launched.  A zombie $DPID has an
# empty /proc/<pid>/fd while an orphaned daemon serves the run, and 'kill -0'
# cannot tell the two apart -- so without this the run would go on measuring a
# corpse and only notice, if at all, at the very end.
#
# `|| true` because of `set -o pipefail`: when the pid really is gone -- the
# case this check exists for -- `ls` fails and the pipeline fails with it.
# This file runs without `set -e`, so that leaves nothing worse than a status
# behind; in the sibling tests that do set it, the one check able to report a
# dead daemon exited the run before it could report one.  The `|| true` is what
# makes this line safe to copy into a file that has the -e.
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l || true)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        bad "setup" "pid $DPID is not a live process -- the daemon that answers is not the one this test launched" ;;
    *) ok ;;
esac

# health-interval 1 / threshold 2 and circuit-timeout 5 keep every reaction the
# proxy is capable of well inside a 6 s window -- a slower configuration would
# make a clean window mean "the test was too short", not "the proxy coped".
create_ok "proxy created" "$BIN" create proxy $NAME -p $PX \
    --backend "127.0.0.1:$BE1,127.0.0.1:$BE2,127.0.0.1:$BE3" --protocol http \
    --health-check tcp --health-interval 1 --health-threshold 2 \
    --circuit-threshold 3 --circuit-timeout 5 --retry 2 -s
# Not "the port accepts, now wait half a second and hope".  A request that
# comes back 200 has gone through the proxy, been routed to a backend that
# passed its health checks, and been answered -- which is what the windows
# below measure.  With --health-interval 1 --health-threshold 2 a backend is
# not in rotation for up to two seconds after the listener is armed, and the
# fixed sleep was shorter than that whenever the machine was busy.
if ! ready_http 127.0.0.1 $PX "/$NAME/ready" 20; then
    bad "setup" "the proxy never answered a request on $PX"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"; exit $((FAIL+HERR))
fi

if "$BIN" stats $NAME >/dev/null 2>&1; then ok; else
    bad "setup" "the proxy runtime is not up -- everything below is meaningless"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"; exit $((FAIL+HERR))
fi

for F in $FAULTS; do
    echo "  -- fault: $F --"

    # Longer than circuit-timeout, so a breaker left open by the previous fault
    # has closed again.  Without this the "healthy" window of the next fault
    # starts with a backend still out of rotation, and the run reports an
    # imbalance that belongs to the test rather than to the proxy.
    sleep 7

    EVF="$TMPD/ev_$F.txt"; STOPF="$TMPD/stop_$F"
    : >"$EVF"
    # Warm-up, discarded: the first connections pay for pool fill.
    python3 "$TMPD/drv.py" "$PX" "$NAME" 6 2 "$TMPD/nostop" >/dev/null 2>&1 || true

    python3 "$TMPD/drv.py" "$PX" "$NAME" "$CLIENTS" "$DRIVER_CAP" "$STOPF" \
        >"$EVF" 2>"$TMPD/drv_$F.err" &
    LPID=$!

    # The healthy window opens on the first response, which is the earliest
    # instant at which "the proxy is serving" is an observation rather than an
    # assumption.  The old +1 s after the driver's start was standing in for it.
    START=$(win_wait_backend "$EVF" any 0 "$ANCHOR_WAIT")
    if [ -z "$START" ]; then
        bad "$F: the proxy serves the load" \
            "no response in ${ANCHOR_WAIT}s -- $(head -3 "$TMPD/drv_$F.err" 2>/dev/null | tr '\n' ' ')"
        : >"$STOPF"; wait $LPID 2>/dev/null; LPID=""; continue
    fi
    if H_N=$(win_wait_events "$EVF" "$START" "$MIN_REQS" "$WIN" "$PHASE_CAP"); then ok; else
        herr "$F: the healthy window carried enough traffic to judge" \
             "${H_N:-0} requests in ${PHASE_CAP}s, wanted >= $MIN_REQS"
    fi

    R=$(ctl "$F" be2); FAULT_T=$(echo "$R" | awk '{print $2}')
    if [ -z "${FAULT_T:-}" ]; then
        bad "$F: fault timestamp readable" "the backend did not report when the fault took effect"
        : >"$STOPF"; wait $LPID 2>/dev/null; LPID=""; continue
    fi

    # The settled window opens when the daemon's own stats say it has noticed --
    # the health check having marked the backend unhealthy, or the breaker
    # having opened.  That is the event the old "+3 s" was guessing at, and it is
    # also the assertion: a proxy that never notices never opens the window, and
    # the bound expiring is reported as the failure it is rather than as a
    # window full of errors.
    NOTICE_T=$(win_wait_output "$ANCHOR_WAIT" \
        '^healthy_backends:[012]$|^open_circuits:[1-9]' "$BIN" stats $NAME)
    if [ -n "$NOTICE_T" ]; then ok; else
        bad "$F: the proxy notices the backend is broken" \
            "with one of three backends $F it still reports every backend healthy and no circuit open after ${ANCHOR_WAIT}s -- $("$BIN" stats $NAME 2>/dev/null | grep -E '^(backends|healthy_backends|open_circuits):' | tr '\n' ' ')"
        NOTICE_T=$(win_now)
    fi
    if S_N=$(win_wait_events "$EVF" "$NOTICE_T" "$MIN_LATE" "$WIN_LATE" "$PHASE_CAP"); then ok; else
        herr "$F: the settled window carried enough traffic to judge" \
             "${S_N:-0} requests in ${PHASE_CAP}s, wanted >= $MIN_LATE"
    fi

    R=$(ctl up be2); RESTORE_T=$(echo "$R" | awk '{print $2}')
    if [ -z "${RESTORE_T:-}" ]; then
        bad "$F: restore timestamp readable" "the backend did not report when it came back"
        : >"$STOPF"; wait $LPID 2>/dev/null; LPID=""; continue
    fi

    # And the restored window opens on the repaired backend's first response.
    # Reaching it is the claim -- a breaker that never half-opens never gets
    # there, and that is what the bound catches.  The window after it is where
    # "it is carrying its share again" is measured.
    RETURN_T=$(win_wait_backend "$EVF" be2 "$RESTORE_T" "$ANCHOR_WAIT")
    if [ -n "$RETURN_T" ]; then ok; else
        bad "$F: the backend returns to rotation after it recovers" \
            "it served nothing in the ${ANCHOR_WAIT}s after it came back"
        RETURN_T=$(win_now)
    fi
    if R_N=$(win_wait_events "$EVF" "$RETURN_T" "$MIN_LATE" "$WIN_LATE" "$PHASE_CAP"); then ok; else
        herr "$F: the restored window carried enough traffic to judge" \
             "${R_N:-0} requests in ${PHASE_CAP}s, wanted >= $MIN_LATE"
    fi
    REST_END=$(win_now)

    : >"$STOPF"; wait $LPID 2>/dev/null; LPID=""

    OUT=$(win_report "$EVF" \
        "healthy:$START:$FAULT_T" \
        "settled:$NOTICE_T:$RESTORE_T" \
        "restored:$RETURN_T:$REST_END")
    printf '%s\n' "$OUT" | sed 's/^/     /'

    H_TOT=$(win_field "$OUT" healthy total);  H_OK=$(win_field "$OUT" healthy ok)
    S_TOT=$(win_field "$OUT" settled total);  S_OK=$(win_field "$OUT" settled ok)
    R_TOT=$(win_field "$OUT" restored total)
    H_RATE=$(win_field "$OUT" healthy rate); S_RATE=$(win_field "$OUT" settled rate)
    S_BE2=$(win_field "$OUT" settled be2);    R_BE2=$(win_field "$OUT" restored be2)

    if [ -n "$H_TOT" ] && [ -n "$H_OK" ] && [ "$H_TOT" -eq "$H_OK" ] && [ "$H_TOT" -gt 0 ]; then ok; else
        bad "$F: nothing fails while all three backends are healthy" \
            "${H_OK:-<none>} of ${H_TOT:-<none>} correct -- $(printf '%s\n' "$OUT" | grep '^WINDOW healthy' | sed 's/.*kinds://')"
        # Not a tolerance and not rounded away: one lost request in fifteen
        # thousand is still a client that asked and was never answered, and the
        # only useful thing a test can add is what the loss looked like.
        win_detail "$EVF" "$START" "$FAULT_T"
    fi

    # The broken backend must be out of rotation once the window has settled.
    # The daemon's own view opened this window, so this is the other half of the
    # same claim: no successful response may carry its stamp either.
    if [ -n "$S_TOT" ] && [ "$S_TOT" -gt 0 ]; then
        if [ "${S_BE2:-0}" -eq 0 ] 2>/dev/null; then ok; else
            bad "$F: the broken backend serves no more responses" "it still served ${S_BE2} requests"
        fi
    else
        herr "$F: the broken backend serves no more responses" "the settled window is empty"
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
    # through.  Compared as rates, not as totals: the windows are as long as they
    # needed to be to carry traffic, so their totals are not comparable and a
    # settled window that simply ran longer would otherwise pass this.
    if [ -n "$H_RATE" ] && [ -n "$S_RATE" ] && [ "$H_RATE" -gt 0 ] && \
       [ "$((S_RATE * 100 / H_RATE))" -ge 50 ]; then ok; else
        bad "$F: throughput survives the loss of one backend" \
            "${S_RATE:-<none>} requests a second in the settled window against ${H_RATE:-<none>} while healthy"
    fi

    if [ "${R_BE2:-0}" -gt 0 ] 2>/dev/null; then ok; else
        if [ -n "$R_TOT" ] && [ "$R_TOT" -gt 0 ]; then
            bad "$F: the recovered backend keeps taking traffic" \
                "it served ${R_BE2:-0} of ${R_TOT} requests after it returned"
        else
            herr "$F: the recovered backend keeps taking traffic" "the restored window is empty"
        fi
    fi
done

if "$BIN" stats $NAME >/dev/null 2>&1; then ok; else bad "runtime alive" "the proxy did not survive"; fi
if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
if [ "$FAIL" -eq 0 ] && [ "$HERR" -eq 0 ]; then echo "  OK"
elif [ "$FAIL" -eq 0 ]; then echo "  NOT MEASURABLE -- this run could not put the question, see above"
else echo "  FAILED"; fi
exit $((FAIL+HERR))
