#!/usr/bin/env bash
# An @group HTTP gateway under concurrent keep-alive load with members joining
# and leaving, because only the first request on a connection was rewritten and
# the rest reached the member with the gateway's prefix still on them -- with
# every request carrying a marker the backend echoes beside its own id, and
# three windows anchored to observed events rather than to the clock.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_window.sh"
. "$(dirname "$0")/lib_create.sh"
# For daemon_sweep in cleanup only, sourced because that defines functions
# without running anything.
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-grpka-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

# Ports come off one base so two runs can share a machine, because a collision
# looks exactly like a broken gateway.
PORT_BASE=$((SL_PORT_BASE+540))
CTRL=$PORT_BASE
BE1=$((PORT_BASE+1)); BE2=$((PORT_BASE+2)); BE3=$((PORT_BASE+3)); BE4=$((PORT_BASE+4))
M1=$((PORT_BASE+11)); M2=$((PORT_BASE+12)); M3=$((PORT_BASE+13)); M4=$((PORT_BASE+14))
GW=$((PORT_BASE+20))
GRP=kagrp; GW_NAME=kagw
CLIENTS=${CLIENTS:-12}
SEQ_REQS=8          # requests on the single deterministic connection

# Twelve connections, paced, because concurrency is what this test needs and
# rate is not -- the pace was forced by an unpooled group path that put 26,000
# sockets into TIME_WAIT, and it stays now that the pool is fixed because a
# burst answers this test's question no better.
PACE=${PACE:-0.02}

# Each window stays open until it has carried enough traffic and been open long
# enough, whichever takes longer, and one that reaches neither is reported as
# not measurable rather than as a routing failure.
LOAD_SECS=${LOAD_SECS:-5}
MIN_REQS=2000       # below this the load window proved nothing
PHASE_SECS=${PHASE_SECS:-4}
MIN_PHASE_REQS=1000
MIN_PRE_OK=200      # responses on connections older than the change
PHASE_CAP=30        # a window that has not filled by now is not going to
ANCHOR_WAIT=20      # bound on every "wait until it happened"
DRIVER_CAP=300      # the driver's own dead-man switch
DRAIN_CLEAR=60      # consecutive clean responses that prove a member is drained
DPID=""; BEPID=""; LPID=""
PASS=0; FAIL=0; HERR=0; TOTAL=0

cleanup() {
    [ -n "$LPID" ] && kill "$LPID" 2>/dev/null
    for n in "$GW_NAME" kam1 kam2 kam3 kam4; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Killed through daemon_sweep, which asks the socket who is serving it,
    # because a `pgrep -f` pattern one character too broad kills the run doing
    # the killing -- which has happened twice in this project.
    daemon_sweep "$SOCKETLEY_SOCKET"
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check(){ if [ "$1" = "$2" ]; then ok; else bad "$3" "got '$1', expected '$2'"; fi; }
# A claim the run was unable to put a question to, kept apart from bad()
# because an empty window and a mis-routed one used to print the same sentence.
herr() { TOTAL=$((TOTAL+1)); HERR=$((HERR+1)); echo "  NOT MEASURABLE [$1]: $2"; }

echo "=== Integration: @group HTTP gateway under keep-alive load ==="

if ! command -v python3 >/dev/null 2>&1; then echo "  SKIP: python3 required"; exit 0; fi

# ---- backends: one process, four ports, each stamping its own id -----------
cat > "$TMPD/be.py" <<'PYEOF'
import asyncio, sys


class Backend:
    def __init__(self, bid, port):
        self.bid, self.port, self.server = bid, port, None

    async def listen(self):
        if self.server is None:
            self.server = await asyncio.start_server(
                self.handle, "127.0.0.1", self.port, reuse_address=True, backlog=256)

    async def handle(self, reader, writer):
        buf = b""
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n\r\n" in buf:
                    head, buf = buf.split(b"\r\n\r\n", 1)
                    line = head.split(b"\r\n", 1)[0].split(b" ")
                    # The path is echoed exactly as it arrived, prefix and all:
                    # a request that was not rewritten has to be visible as
                    # wrong content rather than merely as a 404.
                    marker = line[1].lstrip(b"/") if len(line) > 1 else b"?"
                    body = marker + b"|" + self.bid.encode()
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                                 b"Connection: keep-alive\r\n\r\n%s" % (len(body), body))
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


async def main():
    ctrl = int(sys.argv[1])
    backends = {}
    for spec in sys.argv[2:]:
        bid, port = spec.split(":")
        backends[bid] = Backend(bid, int(port))
        await backends[bid].listen()
    print("ready", flush=True)

    async def ctl(reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                writer.write(b"ok\n")
                await writer.drain()
        except Exception:
            pass
    srv = await asyncio.start_server(ctl, "127.0.0.1", ctrl, reuse_address=True)
    async with srv:
        await srv.serve_forever()


asyncio.run(main())
PYEOF

python3 "$TMPD/be.py" $CTRL be1:$BE1 be2:$BE2 be3:$BE3 be4:$BE4 >"$TMPD/be.log" 2>&1 &
BEPID=$!
for _ in $(seq 1 60); do grep -q ready "$TMPD/be.log" 2>/dev/null && break; sleep 0.1; done

# Wait on the IPC socket itself, never by polling with a CLI command, because
# polling auto-starts a second daemon and when the loser is $DPID the samples
# below are a corpse's.
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

# The daemon that answers is the one this test launched, asked of the
# descriptor table because `kill -0` cannot tell a zombie from a live process
# -- with `|| true` so pipefail does not make the one check able to report a
# dead daemon exit before it can.
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l || true)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        bad "setup" "pid $DPID is not a live process -- the daemon that answers is not the one this test launched" ;;
    *) ok ;;
esac

# Group members are TCP proxies each in front of one backend, with one
# assertion per member because which member is missing is the whole question in
# a group test.
create_ok "group member 1 created" \
    "$BIN" create proxy kam1 -p $M1 --backend "127.0.0.1:$BE1" --protocol tcp -g $GRP -s
create_ok "group member 2 created" \
    "$BIN" create proxy kam2 -p $M2 --backend "127.0.0.1:$BE2" --protocol tcp -g $GRP -s
create_ok "group member 3 created" \
    "$BIN" create proxy kam3 -p $M3 --backend "127.0.0.1:$BE3" --protocol tcp -g $GRP -s
create_ok "gateway created" \
    "$BIN" create proxy "$GW_NAME" -p $GW --backend "@$GRP" --protocol http -s
# A 200 through the gateway proves the group resolved and a member answered,
# where an accepted connection proves only that the gateway is listening.
if ! ready_http 127.0.0.1 $GW "/$GW_NAME/ready" 20; then
    bad "setup" "the gateway never answered a request on $GW"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"; exit $((FAIL+HERR))
fi

if "$BIN" stats "$GW_NAME" >/dev/null 2>&1; then ok; else
    bad "setup" "the gateway runtime is not up -- everything below is meaningless"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"; exit $((FAIL+HERR))
fi

FD0=$(ls /proc/"$DPID"/fd 2>/dev/null | wc -l || true)
if [ -z "$FD0" ] || [ "$FD0" -eq 0 ] 2>/dev/null; then FD0=""; fi

# One connection and several requests, with no concurrency and no timing, so a
# failure here fails identically on every machine and every run.
SEQ_OUT=$(python3 - "$GW" "$GW_NAME" "$SEQ_REQS" <<'PYEOF'
import socket, sys
port, name, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
good = 0
wrong = []
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(8)
except OSError as e:
    print(f"RESULT good=0 of={n} note=connect-failed:{e}")
    sys.exit(0)
for i in range(n):
    want = f"k-{i}"
    try:
        s.sendall(f"GET /{name}/{want} HTTP/1.1\r\nHost: h\r\n"
                  f"Connection: keep-alive\r\n\r\n".encode())
        chunk = s.recv(65536)
    except OSError:
        wrong.append(f"req{i}=error"); break
    if not chunk:
        wrong.append(f"req{i}=closed"); break
    body = chunk.split(b"\r\n\r\n", 1)[-1].decode("latin1")
    if body.startswith(want + "|"):
        good += 1
    else:
        wrong.append(f"req{i}={body!r}")
try:
    s.close()
except OSError:
    pass
print(f"RESULT good={good} of={n} note={' '.join(wrong[:3]) or 'none'}")
PYEOF
)
SEQ_GOOD=$(printf '%s\n' "$SEQ_OUT" | grep -o 'good=[0-9]*' | cut -d= -f2 | head -1)
if [ "${SEQ_GOOD:-0}" = "$SEQ_REQS" ]; then ok; else
    bad "every request on a keep-alive connection is routed" \
        "${SEQ_GOOD:-<none>} of $SEQ_REQS correct -- $(printf '%s\n' "$SEQ_OUT" | sed 's/.*note=//')"
fi

# The driver is a load generator and nothing else, because the old one ran its
# control commands with subprocess.run and blocked its own event loop,
# consuming the window it was supposed to measure.
cat > "$TMPD/drv.py" <<'PYEOF'
import asyncio, os, re, sys, time

port, name, clients = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
cap, stopfile, pace = float(sys.argv[4]), sys.argv[5], float(sys.argv[6])

CLEN = re.compile(rb"Content-Length: (\d+)", re.I)
STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")
MARKER = re.compile(r"^(\d+)-(\d+)$")
out = sys.stdout
stop = None
cid_counter = 0


class Dead(Exception):
    """This connection cannot carry another request."""


def ev(t_send, kind, be, cid):
    out.write(f"EV {t_send!r} {time.time()!r} {kind} {be} {cid}\n")


async def flusher():
    # The anchors are read out of this file while the run is still going, so a
    # block-buffered stdout would hand the shell a view of the traffic that is
    # thousands of requests behind the traffic itself.
    while not stop.is_set():
        out.flush()
        await asyncio.sleep(0.1)
    out.flush()


async def watchdog():
    end = time.time() + cap
    while time.time() < end and not os.path.exists(stopfile):
        await asyncio.sleep(0.05)
    stop.set()


async def one(timeout=4.0):
    # A client reconnects after a hard error.  The old driver returned instead,
    # and a membership change costs every open connection one failed request --
    # so twelve clients meant twelve deaths and a run that stopped generating
    # traffic exactly when the next window was about to open.  An empty window
    # is not evidence of anything, least of all of correctness.  Which
    # connections predate a change is written down (CONN) rather than assumed,
    # so the membership claims are still judged on connections that were already
    # open when it happened.
    global cid_counter
    while not stop.is_set():
        cid_counter += 1
        cid = cid_counter
        t_send = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=timeout)
        except Exception:
            ev(t_send, "connectfail", "-", cid)
            await asyncio.sleep(0.05)
            continue
        out.write(f"CONN {cid} {time.time()!r}\n")
        seq = 0
        try:
            while not stop.is_set():
                marker = f"{cid}-{seq}"
                t_send = time.time()
                writer.write(f"GET /{name}/{marker} HTTP/1.1\r\nHost: h\r\n"
                             f"Connection: keep-alive\r\n\r\n".encode())
                await writer.drain()
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                    if not chunk:
                        ev(t_send, "missing", "-", cid)
                        raise Dead
                    head += chunk
                hdr, rest = head.split(b"\r\n\r\n", 1)
                m = STATUS.match(hdr)
                code = int(m.group(1)) if m else 0
                m = CLEN.search(hdr)
                need = int(m.group(1)) if m else 0
                while len(rest) < need:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                    if not chunk:
                        ev(t_send, "truncated", "-", cid)
                        raise Dead
                    rest += chunk
                if code != 200:
                    ev(t_send, f"http{code}", "-", cid)
                    raise Dead
                got, _, be = rest[:need].decode("latin1").partition("|")
                if got == marker:
                    ev(t_send, "ok", be or "?", cid)
                else:
                    mm = MARKER.match(got)
                    ev(t_send, "garbled" if not mm else
                       "crossed" if int(mm.group(1)) != cid else "wrongseq",
                       be or "?", cid)
                    # Deliberately staying on the connection: reconnecting after
                    # the first bad answer would make any per-request defect
                    # report exactly 50%, which is a property of the driver.
                seq += 1
                await asyncio.sleep(pace)
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
        await asyncio.sleep(0.02)


async def main():
    global stop
    stop = asyncio.Event()
    await asyncio.gather(*( [one() for _ in range(clients)]
                           + [flusher(), watchdog()] ), return_exceptions=True)


asyncio.run(main())
PYEOF

# Warm-up, discarded: the first connections pay for pool fill and first resolve.
python3 - "$GW" "$GW_NAME" <<'PYEOF' >/dev/null 2>&1 || true
import socket, sys
port, name = int(sys.argv[1]), sys.argv[2]
for _ in range(20):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(f"GET /{name}/w-0 HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".encode())
        s.recv(65536); s.close()
    except OSError:
        pass
PYEOF

EVF="$TMPD/events.txt"; STOPF="$TMPD/stop"
: >"$EVF"
python3 "$TMPD/drv.py" "$GW" "$GW_NAME" "$CLIENTS" "$DRIVER_CAP" "$STOPF" "$PACE" \
    >"$EVF" 2>"$TMPD/drv.err" &
LPID=$!

# The load window opens on the first response rather than the driver's start,
# because opening twelve connections is setup and a window containing it
# measures the setup.
LOAD_START=$(win_wait_backend "$EVF" any 0 "$ANCHOR_WAIT")
if [ -z "$LOAD_START" ]; then
    bad "the gateway serves the load" \
        "no response in ${ANCHOR_WAIT}s from a gateway that had just answered a probe -- $(head -2 "$TMPD/drv.err" | tr '\n' ' ')"
    : >"$STOPF"; wait "$LPID" 2>/dev/null
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"; exit $((FAIL+HERR))
fi

if LOAD_N=$(win_wait_events "$EVF" "$LOAD_START" "$MIN_REQS" "$LOAD_SECS" "$PHASE_CAP"); then ok; else
    herr "the load window carried enough traffic to judge" \
        "${LOAD_N:-0} requests in ${PHASE_CAP}s, wanted >= $MIN_REQS"
fi
LOAD_END=$(win_now)

# ---- the member leaves ----------------------------------------------------
# Two anchors in the order the change travels -- the daemon's view, then the
# last response the departing member served -- because only after both is "it
# serves nothing" a claim about the gateway.
T_LEAVE_CMD=$(win_now)
"$BIN" stop kam3 >/dev/null 2>&1
CTRL_LEAVE=$(win_wait_output "$ANCHOR_WAIT" '!"name":"kam3"[^}]*"status":"running"' "$BIN" ls --json)
if [ -z "$CTRL_LEAVE" ]; then
    bad "the daemon takes a stopped member out of the group" \
        "kam3 still listed as running ${ANCHOR_WAIT}s after stop returned"
    CTRL_LEAVE=$(win_now)
fi
LEAVE_START=$(win_wait_drained "$EVF" be3 "$CTRL_LEAVE" "$DRAIN_CLEAR" "$ANCHOR_WAIT")
if [ -n "$LEAVE_START" ]; then ok; else
    bad "traffic stops reaching a member that left" \
        "no run of $DRAIN_CLEAR consecutive good responses without kam3 in ${ANCHOR_WAIT}s after the daemon dropped it"
    LEAVE_START=$(win_now)
fi
if LEAVE_N=$(win_wait_events "$EVF" "$LEAVE_START" "$MIN_PHASE_REQS" "$PHASE_SECS" "$PHASE_CAP"); then ok; else
    herr "the after-leave window carried enough traffic to judge" \
        "${LEAVE_N:-0} requests in ${PHASE_CAP}s, wanted >= $MIN_PHASE_REQS"
fi
LEAVE_END=$(win_now)

# ---- the member joins -----------------------------------------------------
T_JOIN_CMD=$(win_now)
"$BIN" create proxy kam4 -p "$M4" --backend "127.0.0.1:$BE4" --protocol tcp -g "$GRP" -s >/dev/null 2>&1
CTRL_JOIN=$(win_wait_output "$ANCHOR_WAIT" '"name":"kam4"[^}]*"status":"running"' "$BIN" ls --json)
if [ -z "$CTRL_JOIN" ]; then
    bad "the daemon starts a member that joins the group" \
        "kam4 not listed as running ${ANCHOR_WAIT}s after create returned"
    CTRL_JOIN=$(win_now)
fi
# The join anchor is the first response the new member serves, and reaching it
# at all is the assertion, because a gateway routing to the old membership
# never does.
JOIN_START=$(win_wait_backend "$EVF" be4 "$CTRL_JOIN" "$ANCHOR_WAIT")
if [ -n "$JOIN_START" ]; then ok; else
    bad "a member that joined starts receiving traffic" \
        "kam4 served nothing in ${ANCHOR_WAIT}s after the daemon reported it running"
    JOIN_START=$(win_now)
fi
if JOIN_N=$(win_wait_events "$EVF" "$JOIN_START" "$MIN_PHASE_REQS" "$PHASE_SECS" "$PHASE_CAP"); then ok; else
    herr "the after-join window carried enough traffic to judge" \
        "${JOIN_N:-0} requests in ${PHASE_CAP}s, wanted >= $MIN_PHASE_REQS"
fi
JOIN_END=$(win_now)

: >"$STOPF"
wait "$LPID" 2>/dev/null
LPID=""

# The two gap windows cover the change itself and are printed rather than
# asserted on, because the disruption now falls between the measured windows
# and a number that stops being printed is one nobody looks at again.
OUT=$(win_report "$EVF" \
        "load:$LOAD_START:$LOAD_END" \
        "leave-gap:$T_LEAVE_CMD:$LEAVE_START" \
        "after-leave:$LEAVE_START:$LEAVE_END:$T_LEAVE_CMD" \
        "join-gap:$T_JOIN_CMD:$JOIN_START" \
        "after-join:$JOIN_START:$JOIN_END:$T_JOIN_CMD")
printf '%s\n' "$OUT" | sed 's/^/  /'

L_TOTAL=$(win_field "$OUT" load total); L_OK=$(win_field "$OUT" load ok)

# The headline assertion: every request that came back has to be the one that
# was asked for, rather than most having succeeded.
if [ -n "$L_TOTAL" ] && [ -n "$L_OK" ] && [ "$L_TOTAL" -gt 0 ] && [ "$L_OK" -eq "$L_TOTAL" ]; then
    ok
else
    RATE="n/a"
    if [ -n "$L_TOTAL" ] && [ -n "$L_OK" ] && [ "$L_TOTAL" -gt 0 ]; then
        RATE=$(python3 -c "print(f'{100.0*($L_TOTAL-$L_OK)/$L_TOTAL:.2f}%')")
    fi
    bad "every response under load is the one that was requested" \
        "${L_OK:-<none>} of ${L_TOTAL:-<none>} correct ($RATE wrong)"
    # What each loss looked like rather than only how many, because a request
    # that waited the backend deadline is a different animal from one whose
    # connection went away instantly.
    win_detail "$EVF" "$LOAD_START" "$LOAD_END"
fi

for K in crossed garbled wrongseq; do
    N=$(win_kind "$OUT" load "$K")
    check "${N:-0}" "0" "no $K responses under load"
done

# Membership, judged on connections already open when it changed and on
# responses both sent and answered inside the window, with too few reported as
# not measurable.
LEAVE_PRE=$(win_field "$OUT" after-leave preok)
if [ -n "$LEAVE_PRE" ] && [ "$LEAVE_PRE" -ge "$MIN_PRE_OK" ]; then
    BE3_AFTER=$(printf '%s\n' "$OUT" | grep "^WINDOW after-leave " | sed 's/.*prebe://;s/ .*//' \
                | tr ',' '\n' | grep '^be3=' | cut -d= -f2 | head -1)
    check "${BE3_AFTER:-0}" "0" "a member that left stops receiving traffic on open connections"
else
    herr "a member that left stops receiving traffic on open connections" \
        "only ${LEAVE_PRE:-0} responses on connections older than the change, wanted >= $MIN_PRE_OK"
fi

JOIN_PRE=$(win_field "$OUT" after-join preok)
if [ -n "$JOIN_PRE" ] && [ "$JOIN_PRE" -ge "$MIN_PRE_OK" ]; then
    BE4_AFTER=$(printf '%s\n' "$OUT" | grep "^WINDOW after-join " | sed 's/.*prebe://;s/ .*//' \
                | tr ',' '\n' | grep '^be4=' | cut -d= -f2 | head -1)
    if [ -n "$BE4_AFTER" ] && [ "$BE4_AFTER" -gt 0 ]; then ok; else
        bad "a member that joined receives traffic on connections opened before it did" \
            "the new member served ${BE4_AFTER:-0} of those requests"
    fi
else
    herr "a member that joined receives traffic on connections opened before it did" \
        "only ${JOIN_PRE:-0} responses on connections older than the change, wanted >= $MIN_PRE_OK"
fi

# ---- survival ------------------------------------------------------------
if "$BIN" stats "$GW_NAME" >/dev/null 2>&1; then ok; else
    bad "gateway alive" "the gateway did not survive the load"
fi
if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

# Descriptors can only be bounded rather than returned to baseline, at seven
# per pooled connection because the members are themselves splicing proxies in
# this daemon, with a flat 40 of slack and the larger of two readings winning
# because the idle sweep may fire between them.
POOL_A_RAW=$("$BIN" stats "$GW_NAME" 2>/dev/null); POOL_A_RC=$?
FD1=$(ls /proc/"$DPID"/fd 2>/dev/null | wc -l || true)
POOL_B_RAW=$("$BIN" stats "$GW_NAME" 2>/dev/null); POOL_B_RC=$?
# Absent means zero: the runtime only prints the line when the pool is non-empty.
POOL_SED='s/^pooled_connections:\([0-9][0-9]*\)$/\1/p'
POOL_A=$(printf '%s\n' "$POOL_A_RAW" | sed -n "$POOL_SED" | head -1)
POOL_B=$(printf '%s\n' "$POOL_B_RAW" | sed -n "$POOL_SED" | head -1)
POOLED=${POOL_A:-0}
[ "${POOL_B:-0}" -gt "$POOLED" ] && POOLED=${POOL_B:-0}
FD_CEIL=$((FD0 + 7 * POOLED + 40))

if [ -z "$FD0" ] || [ -z "$FD1" ] || [ "$FD1" -eq 0 ] 2>/dev/null; then
    bad "descriptor count readable" "could not read /proc/$DPID/fd (baseline '${FD0:-}', now '${FD1:-}')"
elif [ "$POOL_A_RC" -ne 0 ] || [ "$POOL_B_RC" -ne 0 ]; then
    # Without the pool's size the ceiling cannot be computed at all, and a
    # guess here would be indistinguishable from the bound this replaced.
    herr "descriptors bounded after load" \
        "the gateway did not answer stats, so what the pool is holding is unknown"
elif [ "$FD1" -le "$FD_CEIL" ]; then
    ok
else
    bad "descriptors bounded after load" \
        "baseline $FD0, now $FD1, ceiling $FD_CEIL ($POOLED pooled connections at 7 descriptors each)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
if [ "$FAIL" -eq 0 ] && [ "$HERR" -eq 0 ]; then echo "  OK"
elif [ "$FAIL" -eq 0 ]; then echo "  NOT MEASURABLE -- this run could not put the question, see above"
else echo "  FAILED"; fi
exit $((FAIL+HERR))
