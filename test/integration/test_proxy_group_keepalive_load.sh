#!/usr/bin/env bash
# Integration test: an @group HTTP gateway under concurrent keep-alive load,
# with members joining and leaving while traffic flows.
#
# The existing @group test sends one request per connection, which is the only
# shape that works.  A keep-alive connection is the ordinary shape -- curl
# reuses, browsers reuse, every HTTP client library reuses -- and through a
# group gateway only the *first* request on a connection is rewritten.  Every
# request after it is forwarded to the member verbatim, with the gateway's own
# path prefix still on the request line, so a real backend answers 404 to all
# of them.  The same connection is also pinned to the member chosen for request
# one, so a member that leaves the group keeps receiving its traffic.
#
# The cause is one guard.  A finished HTTP response detaches the backend and
# resets the client for the next request only when
#     !m_backends[conn->backend_idx].is_group
# and the group selection path never assigns backend_idx -- it writes the
# chosen endpoint onto the connection instead.  So the guard always reads slot
# 0.  With the group in slot 0 the reset never runs and header_parsed stays
# true, which sends the next request down the "subsequent data (request body)
# -- forward as-is" branch.  Listing a direct backend first is enough to make
# the same group route correctly, which is what pins the guard as the cause.
#
# Every request carries a marker "<connection>-<sequence>" that the backend
# echoes, and each backend stamps its own id beside it, so a response answers
# two questions at once: did this connection get its own data back, and which
# member produced it.  The second is what makes a claim about failover or
# membership checkable rather than merely plausible -- "the request succeeded"
# says nothing about where it went.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-grpka-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

CTRL=19540; BE1=19541; BE2=19542; BE3=19543; BE4=19544
M1=19551; M2=19552; M3=19553; M4=19554; GW=19560
GRP=kagrp; GW_NAME=kagw
CLIENTS=${CLIENTS:-12}
LOAD_SECS=${LOAD_SECS:-5}    # length of ONE measured window; three are run
SEQ_REQS=8          # requests on the single deterministic connection
MIN_REQS=2000       # below this the load run proved nothing
DPID=""; BEPID=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
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
    # Kill by socket, not only by pid.  A CLI command run against a daemon that
    # is not up yet -- or not up any more -- starts one of its own, detached from
    # this shell; killing $DPID would leave that one running for good, holding
    # this test's ports.  The socket path comes from mktemp, so matching on it
    # can only ever hit daemons belonging to this run.
    for p in $(pgrep -f 'socketley daemon' 2>/dev/null || true); do
        if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET"; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check(){ if [ "$1" = "$2" ]; then ok; else bad "$3" "got '$1', expected '$2'"; fi; }

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

# Wait on the daemon's IPC socket directly, never by polling with a CLI command.
# Every CLI command auto-starts a daemon when the socket does not answer yet --
# cli.cpp's ensure_daemon() forks, setsids and re-execs 'socketley daemon' -- so
# polling 'ps' against the daemon this test has just launched races it and spawns
# a second, orphaned one.  Whichever loses the bind exits, and when the loser is
# $DPID the pid this test watches becomes a zombie while an orphan serves the
# run: the FD0/FD1 samples below are then a corpse's.  Measured at 2 spawned
# orphans in 30 startups of this sequence.
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

"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
python3 "$TMPD/waitsock.py" "$SOCKETLEY_SOCKET" 8 >/dev/null 2>&1 || true

# The daemon that answers is the one this test launched.  A zombie $DPID has an
# empty /proc/<pid>/fd while an orphaned daemon serves the run, and 'kill -0'
# cannot tell the two apart -- so this looks at the descriptor table, which only
# a live process has.  Said here rather than left to the FD0/FD1 check at the
# end, which would report it as a descriptor problem long after the fact.
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        bad "setup" "pid $DPID is not a live process -- the daemon that answers is not the one this test launched" ;;
    *) ok ;;
esac

# Group members are TCP proxies in the group, each in front of one backend --
# the same shape as test_proxy_group_http.sh, so the member is a real runtime
# whose membership the daemon controls.
"$BIN" create proxy kam1 -p $M1 --backend "127.0.0.1:$BE1" --protocol tcp -g $GRP -s >/dev/null 2>&1 || true
"$BIN" create proxy kam2 -p $M2 --backend "127.0.0.1:$BE2" --protocol tcp -g $GRP -s >/dev/null 2>&1 || true
"$BIN" create proxy kam3 -p $M3 --backend "127.0.0.1:$BE3" --protocol tcp -g $GRP -s >/dev/null 2>&1 || true
"$BIN" create proxy "$GW_NAME" -p $GW --backend "@$GRP" --protocol http -s >/dev/null 2>&1 || true
# A 200 through the gateway proves the group resolved to at least one member
# and that member answered.  An accepted connection proves only that the
# gateway is listening, which it does before any member is routable.
if ! ready_http 127.0.0.1 $GW "/$GW_NAME/ready" 20; then
    bad "setup" "the gateway never answered a request on $GW"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

if "$BIN" stats "$GW_NAME" >/dev/null 2>&1; then ok; else
    bad "setup" "the gateway runtime is not up -- everything below is meaningless"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

FD0=$(ls /proc/"$DPID"/fd 2>/dev/null | wc -l)
if [ -z "$FD0" ] || [ "$FD0" -eq 0 ] 2>/dev/null; then FD0=""; fi

# ---- 1. deterministic: one connection, several requests -------------------
# No concurrency and no timing in this one.  If it fails, it fails identically
# on every machine and every run.
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

# ---- 2 & 3. concurrent load, then membership churn -------------------------
cat > "$TMPD/drv.py" <<'PYEOF'
import asyncio, re, subprocess, sys, time
from collections import Counter

port, name, clients, secs, binp = (int(sys.argv[1]), sys.argv[2], int(sys.argv[3]),
                                   float(sys.argv[4]), sys.argv[5])
victim, joiner_port, joiner_be = sys.argv[6], sys.argv[7], sys.argv[8]

CLEN = re.compile(rb"Content-Length: (\d+)", re.I)
STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")
MARKER = re.compile(r"^(\d+)-(\d+)$")
events = []          # (t, kind, backend)
cid_counter = 0
phase = {"name": "load", "since": 0.0}


async def one(port, cid, deadline, timeout=4.0):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=timeout)
    except Exception:
        events.append((time.time(), "connectfail", "-", phase["name"]))
        return
    seq = 0
    try:
        while time.time() < deadline:
            marker = f"{cid}-{seq}"
            writer.write(f"GET /{name}/{marker} HTTP/1.1\r\nHost: h\r\n"
                         f"Connection: keep-alive\r\n\r\n".encode())
            await writer.drain()
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    events.append((time.time(), "missing", "-", phase["name"]))
                    return
                head += chunk
            hdr, rest = head.split(b"\r\n\r\n", 1)
            m = STATUS.match(hdr)
            code = int(m.group(1)) if m else 0
            m = CLEN.search(hdr)
            need = int(m.group(1)) if m else 0
            while len(rest) < need:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    events.append((time.time(), "truncated", "-", phase["name"]))
                    return
                rest += chunk
            if code != 200:
                events.append((time.time(), f"http{code}", "-", phase["name"]))
                return
            body = rest[:need].decode("latin1")
            got, _, be = body.partition("|")
            if got == marker:
                events.append((time.time(), "ok", be or "?", phase["name"]))
            else:
                mm = MARKER.match(got)
                kind = ("garbled" if not mm else
                        "crossed" if int(mm.group(1)) != cid else "wrongseq")
                events.append((time.time(), kind, be or "?", phase["name"]))
                # Deliberately staying on the connection: reconnecting after the
                # first bad answer would make any per-request defect report
                # exactly 50%, which is a property of the driver.
            seq += 1
            await asyncio.sleep(0.004)
    except asyncio.TimeoutError:
        events.append((time.time(), "timeout", "-", phase["name"]))
    except (ConnectionResetError, BrokenPipeError):
        events.append((time.time(), "reset", "-", phase["name"]))
    except Exception:
        events.append((time.time(), "err", "-", phase["name"]))
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def churn(win):
    # Members change while the connections above are mid-stream: that is the
    # only moment at which "picked up at connection time" can be told apart
    # from "picked up per request".  The settle pauses after each change are
    # inside the schedule, not taken out of the window being measured -- a
    # window that closes before the change has landed reports the phase before
    # it, and reports it as clean.
    await asyncio.sleep(win)
    subprocess.run([binp, "stop", victim], capture_output=True)
    await asyncio.sleep(1.0)
    phase["name"] = "after-leave"
    await asyncio.sleep(win)
    subprocess.run([binp, "create", "proxy", "kam4", "-p", joiner_port,
                    "--backend", f"127.0.0.1:{joiner_be}", "--protocol", "tcp",
                    "-g", "kagrp", "-s"], capture_output=True)
    await asyncio.sleep(1.5)
    phase["name"] = "after-join"


async def main():
    global cid_counter
    t0 = time.time()
    # secs is the length of ONE measured window; the run covers three of them
    # plus the two settle pauses the churn schedule takes between changes.
    deadline = t0 + 3 * secs + 2.5
    tasks = []
    for _ in range(clients):
        cid_counter += 1
        tasks.append(asyncio.create_task(one(port, cid_counter, deadline)))
    tasks.append(asyncio.create_task(churn(secs)))
    await asyncio.gather(*tasks, return_exceptions=True)

    for ph in ("load", "after-leave", "after-join"):
        kinds = Counter()
        bes = Counter()
        for _, kind, be, p in events:
            if p != ph:
                continue
            kinds[kind] += 1
            if kind == "ok" and be != "-":
                bes[be] += 1
        total = sum(kinds.values())
        okn = kinds.get("ok", 0)
        print(f"PHASE {ph} total={total} ok={okn} "
              f"be:{','.join(f'{k}={v}' for k, v in sorted(bes.items())) or 'none'} "
              f"kinds:{','.join(f'{k}={v}' for k, v in sorted(kinds.items()) if k != 'ok') or 'none'}")


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

DRV=$(python3 "$TMPD/drv.py" "$GW" "$GW_NAME" "$CLIENTS" "$LOAD_SECS" "$BIN" \
        kam3 "$M4" "$BE4" 2>"$TMPD/drv.err")
echo "$DRV" | sed 's/^/  /'

phase_field() {   # phase, field -> value ("" when the phase line is missing)
    printf '%s\n' "$DRV" | grep "^PHASE $1 " | grep -o "\b$2=[0-9]*" | cut -d= -f2 | head -1
}

L_TOTAL=$(phase_field load total); L_OK=$(phase_field load ok)
if [ -n "$L_TOTAL" ] && [ "$L_TOTAL" -ge "$MIN_REQS" ]; then ok; else
    bad "load actually ran" "only ${L_TOTAL:-<no phase line>} requests, wanted >= $MIN_REQS"
fi

# The headline assertion.  Not "most succeeded" -- every request that came back
# has to be the one that was asked for.
if [ -n "$L_TOTAL" ] && [ -n "$L_OK" ] && [ "$L_TOTAL" -gt 0 ] && [ "$L_OK" -eq "$L_TOTAL" ]; then
    ok
else
    RATE="n/a"
    if [ -n "$L_TOTAL" ] && [ -n "$L_OK" ] && [ "$L_TOTAL" -gt 0 ]; then
        RATE=$(python3 -c "print(f'{100.0*($L_TOTAL-$L_OK)/$L_TOTAL:.2f}%')")
    fi
    bad "every response under load is the one that was requested" \
        "${L_OK:-<none>} of ${L_TOTAL:-<none>} correct ($RATE wrong)"
fi

for K in crossed garbled wrongseq; do
    N=$(printf '%s\n' "$DRV" | grep "^PHASE load " | grep -o "\b$K=[0-9]*" | cut -d= -f2 | head -1)
    check "${N:-0}" "0" "no $K responses under load"
done

# Membership, judged only on correctly-routed responses.  A phase whose routing
# is broken cannot say anything about where traffic went, so too few good
# responses is reported as "could not be measured" rather than passed.
leave_ok=$(phase_field after-leave ok)
if [ -n "$leave_ok" ] && [ "$leave_ok" -ge 50 ]; then
    BE3_AFTER=$(printf '%s\n' "$DRV" | grep "^PHASE after-leave " | grep -o "\bbe3=[0-9]*" | cut -d= -f2 | head -1)
    check "${BE3_AFTER:-0}" "0" "a member that left stops receiving traffic on open connections"
else
    bad "a member that left stops receiving traffic on open connections" \
        "only ${leave_ok:-0} correctly routed responses in that phase -- not measurable"
fi

join_ok=$(phase_field after-join ok)
if [ -n "$join_ok" ] && [ "$join_ok" -ge 50 ]; then
    BE4_AFTER=$(printf '%s\n' "$DRV" | grep "^PHASE after-join " | grep -o "\bbe4=[0-9]*" | cut -d= -f2 | head -1)
    if [ -n "$BE4_AFTER" ] && [ "$BE4_AFTER" -gt 0 ]; then ok; else
        bad "a member that joined starts receiving traffic on open connections" \
            "the new member served ${BE4_AFTER:-0} requests"
    fi
else
    bad "a member that joined starts receiving traffic on open connections" \
        "only ${join_ok:-0} correctly routed responses in that phase -- not measurable"
fi

# ---- survival ------------------------------------------------------------
if "$BIN" stats "$GW_NAME" >/dev/null 2>&1; then ok; else
    bad "gateway alive" "the gateway did not survive the load"
fi
if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

# Descriptors: the backend pool holds sockets for POOL_IDLE_TIMEOUT_SEC (60)
# and the sweep that evicts them runs every 30 s, so a check here can only be
# a ceiling, never "back to baseline".  An unreadable count is reported as
# unreadable -- two numbers that are both empty compare equal.
FD1=$(ls /proc/"$DPID"/fd 2>/dev/null | wc -l)
if [ -z "$FD0" ] || [ -z "$FD1" ] || [ "$FD1" -eq 0 ] 2>/dev/null; then
    bad "descriptor count readable" "could not read /proc/$DPID/fd (baseline '${FD0:-}', now '${FD1:-}')"
elif [ "$FD1" -le $((FD0 + 4 * CLIENTS + 40)) ]; then
    ok
else
    bad "descriptors bounded after load" "baseline $FD0, now $FD1"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
