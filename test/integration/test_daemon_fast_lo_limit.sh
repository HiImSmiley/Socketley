#!/usr/bin/env bash
# suite: quiet -- stalled readers against a per-pair and a global budget, whose reconciler a loaded box starves
# Integration test: `daemon --fast-lo-limit` bounds the redirected backlog
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A redirected send lands straight in the receiver's ingress queue and never
# waits for the reader, so without a bound a receiver that stops reading can
# hold hundreds of MiB of the host's TCP memory (measured: 731 MiB before the
# kernel's tcp_mem ran out).  The limiter counts each pair's sends in a BPF
# map; past a mark it asks a reconciler thread, through a ring buffer, for the
# receiver's true queue, and the answer snaps the count back.  A pair whose
# receiver really holds the per-pair bound, or whose count reaches twice it
# unanswered, is tainted to TCP -- which then gives real backpressure -- and
# the sum across pairs is capped at the global budget.  The taint is permanent
# for the pair, which is what keeps bytes in order: tcp_bpf_recvmsg drains the
# redirect queue before the TCP receive queue.
#
# Since the receiver rule (redirect only into a socket we own), the receiver
# whose backlog can grow is always one of our workers.  The controllable case
# is a proxy (ours) flooded by a client while its foreign backend pauses: the
# client -> proxy direction is on the shortcut (into the proxy, which we own),
# and while the proxy cannot drain to the paused backend the client's
# redirected bytes pile in the proxy's client-facing ingress queue.  That is
# the ours-receiver stall the limiter is for.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a --fast-lo-limit value that is not two positive MiB integers accepted
#   * a proxy's client-facing socket holding far more than the per-pair ceiling
#     (the bound not enforced) -- shown red by raising the ceiling to 512 MiB
#   * a byte delivered out of order once the backend resumes and the proxy
#     drains
#   * trust: a paused foreign backend's own socket, into which trust redirects,
#     holding far more than the ceiling -- the receiver rule is gone there, so
#     the limiter is all that bounds it (red with the ceiling raised) -- or the
#     metrics not saying mode trust
#   * the sum across many stalled pairs exceeding the global budget -- shown red
#     by raising the budget
#   * a fast pair whose backend keeps up tainted anyway, because its count was
#     corrected too late or not at all -- red on a limiter that corrects on a
#     timer (f6b10a60 sent 3.7 of its 4.3 GB by TCP)
#   * `daemon stats` and the metrics endpoint not showing what the shortcut
#     did: a stalled pair tainted for its bound, held and counted as on TCP
#     while it lasts; a pair tainted by the global budget; a fast pair entered
#     and never tainted -- red with the sk_msg program's taint count removed,
#     and with the sockops program's entry count removed
#   * fast_lo_held_bytes not what the stalled receiver's socket holds, which
#     after the taint is whatever it has not yet read -- red with the sweep's
#     store of the held gauge removed, which leaves the answer's figure stale
#     once the receiver reads below it (every Sanitize run; Release by chance)
#
# The bound cases need CAP_BPF and CAP_NET_ADMIN, given to a copy of the binary
# with `sudo -n setcap`; without sudo they are skipped.
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: daemon --fast-lo-limit ==="
if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi
if ! command -v ss >/dev/null 2>&1; then
    echo "  SKIP: ss not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

daemon_isolate fastlolim
WORK=$(mktemp -d /tmp/socketley-fastlolim-work-XXXXXX)
daemon_watch "$WORK"
BEPID=""
CAPDIR=""
cleanup(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; daemon_stop; cap_sweep "$CAPDIR"; rm -rf "$WORK"; [ -z "$CAPDIR" ] || rm -rf "$CAPDIR"; }
trap cleanup EXIT

PXPORT=$((SL_PORT_BASE + 1836))
BEPORT=$((SL_PORT_BASE + 1837))
MPORT=$((SL_PORT_BASE + 1838))
cat >"$WORK/metrics.lua" <<LUA
daemon = { metrics_port = $MPORT }
LUA

# A socket's receive memory as the kernel counts it, the redirected backlog
# included: the largest among the established sockets on local port $1.
rmem_of(){ local v; v=$(ss -tmnH "( sport = :$1 )" | grep -oE 'skmem:\(r[0-9]+' | grep -oE '[0-9]+$' | sort -n | tail -1) || true; echo "${v:-0}"; }

# One figure out of `daemon stats`.
figure(){ { grep -oE "^$1:[0-9]+" <<<"$2" || echo "$1:-1"; } | head -1 | cut -d: -f2; }

# A foreign backend that accepts and never reads: the proxy can never drain to
# it, so a client's redirected bytes pile in the proxy's ingress queue.
cat >"$WORK/sink.py" <<'PY'
import socket, sys
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(16)
held = []
while True:
    c, _ = l.accept(); held.append(c)
PY

# A foreign backend that pauses `hold` seconds without reading, then echoes:
# the pause builds the backlog, the echo lets the client check order on resume.
cat >"$WORK/pecho.py" <<'PY'
import socket, sys, threading, time
port, hold = int(sys.argv[1]), float(sys.argv[2])
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", port)); l.listen(16)
def serve(c):
    if hold > 0: time.sleep(hold)
    while True:
        d = c.recv(1 << 16)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = l.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

# Floods a proxy for `hold` s, sampling the proxy's client-facing socket rmem
# (its accepted socket, source port PXPORT, which includes the psock backlog).
# Then, if the backend echoes, drains and checks the stream came back in order
# and whole.  Prints the client's tcpi_bytes_acked too: 1 while its sends are
# redirected (client -> proxy on the shortcut), large once the pair is tainted.
cat >"$WORK/flood.py" <<'PY'
import socket, struct, subprocess, sys, time
pp, hold, maxmib, sport = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
blk = bytes(((i * 131 + 7) & 0xff) for i in range(65536)); blk2 = blk + blk
maxb = maxmib << 20
s = socket.create_connection(("127.0.0.1", pp), timeout=10); s.setblocking(False)
def rmem():
    out = subprocess.run(["ss", "-tmnH", "( sport = :%d )" % sport], capture_output=True, text=True).stdout
    return max([int(x.split("skmem:(r", 1)[1].split(",", 1)[0]) for x in out.splitlines() if "skmem:(r" in x] or [0])
sent = 0; soff = 0; got = bytearray(); peak = 0; t0 = time.time(); last = 0.0
while time.time() - t0 < hold:
    if sent < maxb:
        try:
            n = s.send(blk2[soff:soff + 65536]); sent += n; soff = (soff + n) % 65536
        except BlockingIOError:
            time.sleep(0.001)
    else:
        time.sleep(0.005)
    try:
        while True:
            d = s.recv(1 << 20)
            if not d: break
            got += d
    except BlockingIOError:
        pass
    if time.time() - last > 0.05:
        peak = max(peak, rmem()); last = time.time()
s.setblocking(True); s.settimeout(30)
try:
    while len(got) < sent:
        d = s.recv(1 << 20)
        if not d: break
        got += d
except socket.timeout:
    pass
exp = (blk2 * ((len(got) // 65536) + 2))[:len(got)]
acked = struct.unpack_from("Q", s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256), 120)[0]
print("peak_mib=%.2f in_order=%d complete=%d sent_mib=%.1f acked=%d" %
      (peak / 1048576.0, int(bytes(got) == exp), int(len(got) == sent), sent / 1048576.0, acked))
PY

# A client that keeps a bounded window of bytes in flight through the proxy for
# `dur` seconds, draining the echo as it goes, so the backlog never nears the
# bound: the pair should stay on the shortcut and never be tainted.  Prints
# what it moved, whether the echo came back in order, and its bytes_acked.
cat >"$WORK/windowed.py" <<'PY'
import socket, struct, sys, time
pp, dur, win_mib = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
blk = bytes(((i * 131 + 7) & 0xff) for i in range(65536)); blk2 = blk + blk
win = win_mib << 20
s = socket.create_connection(("127.0.0.1", pp), timeout=10); s.setblocking(False)
sent = 0; soff = 0; recvd = 0; ok = True; roff = 0; t0 = time.time()
while time.time() - t0 < dur:
    while sent - recvd < win:
        try:
            n = s.send(blk2[soff:soff + 65536]); sent += n; soff = (soff + n) % 65536
        except BlockingIOError:
            break
    try:
        d = s.recv(1 << 20)
        if d:
            need = roff + len(d)
            exp = (blk * ((need // 65536) + 2))[roff:need]
            if d != exp: ok = False
            recvd += len(d); roff = need % 65536
    except BlockingIOError:
        time.sleep(0.001)
acked = struct.unpack_from("Q", s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256), 120)[0]
print("moved_mib=%d in_order=%d acked=%d" % (recvd >> 20, int(ok), acked))
PY

# Many clients flooding one proxy into a paused backend; the summed rmem across
# the proxy's client-facing sockets, which the global budget caps.
cat >"$WORK/flood_many.py" <<'PY'
import socket, subprocess, sys, time
pp, k, hold, maxmib, sport = (int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]),
                              int(sys.argv[4]), int(sys.argv[5]))
blk = bytes(((i * 131 + 7) & 0xff) for i in range(65536)); blk2 = blk + blk
maxb = maxmib << 20
conns = []
# Stagger the stalls across reconcile ticks: the global budget stops new sends
# once the reconciler has seen the sum cross it, so a synchronized burst all
# commits before it acts.
for _ in range(k):
    s = socket.create_connection(("127.0.0.1", pp), timeout=10); s.setblocking(False)
    conns.append([s, 0, 0])
    time.sleep(0.25)
def sum_rmem():
    out = subprocess.run(["ss", "-tmnH", "( sport = :%d )" % sport], capture_output=True, text=True).stdout
    return sum(int(x.split("skmem:(r", 1)[1].split(",", 1)[0]) for x in out.splitlines() if "skmem:(r" in x)
peak = 0; t0 = time.time(); last = 0.0
while time.time() - t0 < hold:
    for st in conns:
        s, sent, soff = st
        if sent < maxb:
            try:
                n = s.send(blk2[soff:soff + 65536]); st[1] = sent + n; st[2] = (soff + n) % 65536
            except BlockingIOError:
                pass
    if time.time() - last > 0.05:
        peak = max(peak, sum_rmem()); last = time.time()
    time.sleep(0.001)
print("sum_mib=%.2f" % (peak / 1048576.0))
PY

wait_port(){ local i; for i in $(seq 1 50); do python3 -c "import socket,sys;socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=1)" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
restart(){ daemon_stop; daemon_isolate fastlolim; daemon_watch "$WORK"; daemon_start "$@"; }
backend(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; python3 "$1" "${@:2}" >/dev/null 2>&1 & BEPID=$!; disown; wait_port "$BEPORT" || true; }

# ─── (a) the flag's value ───────────────────────────────────────────────────
for bad in "" "4" "4,0" "0,64" "4," "x,y" "4,2"; do
    OUT=$("$BIN" daemon --fast-lo all --fast-lo-limit "$bad" 2>&1) && RC=0 || RC=$?
    if [ "$RC" = 1 ] && grep -q 'fast-lo-limit' <<<"$OUT"; then :; else
        fail "bad limit '$bad'" "should exit 1 naming the flag" "rc=$RC out: $OUT"; fi
done
pass  # the loop above only fails; reaching here is the pass

# ─── the capped copy ────────────────────────────────────────────────────────
CAPDIR=$(cap_dir); CAPBIN="$CAPDIR/socketley-fastlolim"
daemon_watch "$CAPDIR"   # an interrupted run's capped copies go with it
cp "$BIN" "$CAPBIN"; chmod 755 "$CAPBIN"
if ! sudo -n setcap cap_bpf,cap_net_admin+ep "$CAPBIN" 2>/dev/null; then
    echo "  SKIP: the bound itself (no sudo -n setcap for CAP_BPF/CAP_NET_ADMIN)"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    [ "$FAIL" = 0 ] && exit 0 || exit 1
fi
attached(){ if grep -q 'fast-lo: unavailable' "$SOCKETLEY_DLOG"; then
    # Only a refusal the environment explains is a skip; any other is the attach path failing.
    grep 'fast-lo: unavailable' "$SOCKETLEY_DLOG" | grep -qE 'no CAP_|needs cgroup v2|this kernel has no|Function not implemented|Operation not supported' ||
        fail "attach" "with the capabilities set the shortcut attaches, or names an environment reason" "$(grep fast-lo "$SOCKETLEY_DLOG")"
    echo "  SKIP: the shortcut did not attach: $(grep fast-lo "$SOCKETLEY_DLOG")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; [ "$FAIL" = 0 ] && exit 0 || exit 1; fi; }

# ─── (b) per-pair bound holds the proxy's backlog, order survives resume ─────
SOCKETLEY_CONFIG="$WORK/metrics.lua" restart "$CAPBIN" --fast-lo all --fast-lo-limit 4,256
attached
backend "$WORK/pecho.py" "$BEPORT" 3
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$BEPORT" --protocol tcp -s >/dev/null; wait_port "$PXPORT" || true
python3 "$WORK/flood.py" "$PXPORT" 3 64 "$PXPORT" >"$WORK/flood.out" 2>&1 & FLPID=$!
# Mid-stall, once a sweep has seen the taint and the receiver's queue holds
# still across the read: held_bytes is that sweep's measurement of the queue,
# which the receiver may have drained below the bound since the taint.
MID=""; HELD=-1; KERN=-1
while kill -0 "$FLPID" 2>/dev/null; do
    K1=$(rmem_of "$PXPORT"); S=$("$BIN" daemon stats 2>&1 || true); K2=$(rmem_of "$PXPORT")
    MID=$S
    if [ $(( $(figure fast_lo_tainted_bound "$S") + $(figure fast_lo_tainted_unanswered "$S") )) -ge 1 ] &&
       [ "$(figure fast_lo_sockets_tcp "$S")" -ge 1 ] && [ "$K1" = "$K2" ] && [ "$K1" -ge 262144 ]; then
        HELD=$(figure fast_lo_held_bytes "$S"); KERN=$K1
        [ $(( HELD > KERN ? HELD - KERN : KERN - HELD )) -le 65536 ] && break
    fi
    sleep 0.05
done
SCRAPE=$(python3 -c "import sys,urllib.request;print(urllib.request.urlopen('http://127.0.0.1:%s/metrics' % sys.argv[1], timeout=5).read().decode())" "$MPORT" 2>&1 || true)
wait "$FLPID" || true
R=$(cat "$WORK/flood.out")
read -r PK IO CO SM AK <<<"$R"; PKV=${PK#peak_mib=}
if awk "BEGIN{exit !($PKV <= 8)}" && [ "$IO" = in_order=1 ] && [ "$CO" = complete=1 ]; then pass
else fail "per-pair bound" "the proxy's backlog stays near the 4 MiB ceiling and drains in order" "probe: $R (peak<=8, in_order, complete)"; fi

# A stalled pair is stopped at its bound either way: by the answer that its peer
# holds the bound, or, when a loaded box delays that answer past twice the
# bound, as unanswered -- the peak above is what holds the memory claim.
if grep -q '^fast_lo:all$' <<<"$MID" && [ "$(figure fast_lo_entered "$MID")" -ge 2 ] &&
   [ $(( $(figure fast_lo_tainted_bound "$MID") + $(figure fast_lo_tainted_unanswered "$MID") )) -ge 1 ] &&
   [ "$(figure fast_lo_sockets_tcp "$MID")" -ge 1 ] &&
   [ "$KERN" -ge 262144 ] && [ $(( HELD > KERN ? HELD - KERN : KERN - HELD )) -le 65536 ]; then pass
else fail "stats: stalled" "daemon stats shows the pair entered, stopped at its bound (bound, or unanswered on a loaded box), on TCP, and held_bytes equal to the stalled receiver's queue" \
    "held=$HELD kernel=$KERN (kernel>=256 KiB, within 64 KiB)" "$(tr '\n' ' ' <<<"$MID")"; fi
if grep -q 'socketley_fast_lo_info{mode="all"} 1' <<<"$SCRAPE" &&
   grep -qE 'socketley_fast_lo_tainted_total\{reason="(bound|unanswered)"\} [1-9]' <<<"$SCRAPE" &&
   grep -qE 'socketley_fast_lo_sockets\{path="tcp"\} [1-9]' <<<"$SCRAPE"; then pass
else fail "metrics: stalled" "the metrics endpoint carries the mode, the bound taint and the socket on TCP" \
    "$(grep fast_lo <<<"$SCRAPE" | grep -v '^#' | tr '\n' ' ')"; fi

# ─── (c) red: with the ceiling raised the same flood holds far more ──────────
restart "$CAPBIN" --fast-lo all --fast-lo-limit 512,1024
attached
backend "$WORK/sink.py" "$BEPORT"
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$BEPORT" --protocol tcp -s >/dev/null; wait_port "$PXPORT" || true
R=$(python3 "$WORK/flood.py" "$PXPORT" 4 256 "$PXPORT")
read -r PK IO CO SM AK <<<"$R"; PKV=${PK#peak_mib=}
if awk "BEGIN{exit !($PKV > 8)}"; then pass
else fail "per-pair red" "a 512 MiB ceiling must let the backlog exceed 8 MiB (else the bound is untested)" "probe: $R"; fi

# ─── (c2) trust: the bound covers a foreign receiver too ─────────────────────
# Under trust the proxy's sends into a paused foreign backend are redirected, so
# its backlog grows in the backend's socket, which the limiter must still bound;
# the backend's own socket (local port BEPORT) is the one sampled.  The same
# flood with the ceiling raised shows the sample can see an unbounded backlog.
SOCKETLEY_CONFIG="$WORK/metrics.lua" restart "$CAPBIN" --fast-lo trust --fast-lo-limit 4,256
attached
backend "$WORK/pecho.py" "$BEPORT" 3
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$BEPORT" --protocol tcp -s >/dev/null; wait_port "$PXPORT" || true
python3 "$WORK/flood.py" "$PXPORT" 3 64 "$BEPORT" >"$WORK/flood.out" 2>&1 & FLPID=$!
sleep 2
SCRAPE=$(python3 -c "import sys,urllib.request;print(urllib.request.urlopen('http://127.0.0.1:%s/metrics' % sys.argv[1], timeout=5).read().decode())" "$MPORT" 2>&1 || true)
wait "$FLPID" || true
R=$(cat "$WORK/flood.out")
read -r PK IO CO SM AK <<<"$R"; PKV=${PK#peak_mib=}
if awk "BEGIN{exit !($PKV <= 8)}" && [ "$IO" = in_order=1 ] && [ "$CO" = complete=1 ]; then pass
else fail "trust: per-pair bound" "a foreign backend's socket stays near the 4 MiB ceiling under trust and the echo drains in order" "probe: $R (peak<=8, in_order, complete)"; fi
if grep -q 'socketley_fast_lo_info{mode="trust"} 1' <<<"$SCRAPE" &&
   grep -qE 'socketley_fast_lo_tainted_total\{reason="(bound|unanswered)"\} [1-9]' <<<"$SCRAPE"; then pass
else fail "trust: metrics" "the metrics endpoint carries mode trust and the bound taint of the foreign receiver" \
    "$(grep fast_lo <<<"$SCRAPE" | grep -v '^#' | tr '\n' ' ')"; fi

restart "$CAPBIN" --fast-lo trust --fast-lo-limit 512,1024
attached
backend "$WORK/pecho.py" "$BEPORT" 3
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$BEPORT" --protocol tcp -s >/dev/null; wait_port "$PXPORT" || true
R=$(python3 "$WORK/flood.py" "$PXPORT" 3 256 "$BEPORT")
read -r PK IO CO SM AK <<<"$R"; PKV=${PK#peak_mib=}
if awk "BEGIN{exit !($PKV > 8)}"; then pass
else fail "trust: per-pair red" "a 512 MiB ceiling must let the foreign backend's backlog exceed 8 MiB (else the bound is untested)" "probe: $R"; fi

# ─── (d) global budget caps the sum across many stalled pairs ───────────────
restart "$CAPBIN" --fast-lo all --fast-lo-limit 4,12
attached
backend "$WORK/sink.py" "$BEPORT"
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$BEPORT" --protocol tcp -s >/dev/null; wait_port "$PXPORT" || true
BOUNDED=$(python3 "$WORK/flood_many.py" "$PXPORT" 8 6 16 "$PXPORT"); BV=${BOUNDED#sum_mib=}
AFTER=$("$BIN" daemon stats 2>&1 || true)
if [ "$(figure fast_lo_tainted_budget "$AFTER")" -ge 1 ]; then pass
else fail "stats: budget" "daemon stats counts the pairs the global budget tainted" "$(tr '\n' ' ' <<<"$AFTER")"; fi

restart "$CAPBIN" --fast-lo all --fast-lo-limit 4,4096
attached
backend "$WORK/sink.py" "$BEPORT"
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$BEPORT" --protocol tcp -s >/dev/null; wait_port "$PXPORT" || true
OPEN=$(python3 "$WORK/flood_many.py" "$PXPORT" 8 6 16 "$PXPORT"); OV=${OPEN#sum_mib=}

if awk "BEGIN{exit !($BV <= 20 && $OV > $BV + 4)}"; then pass
else fail "global budget" "the summed backlog stays near the 12 MiB budget and grows without it" "bounded=$BV MiB open=$OV MiB (bounded<=20 and open>bounded+4)"; fi

# ─── (e) a fast pair whose backend keeps up is never tainted ────────────────
# The backend echoes at once, so the proxy drains and the backlog stays small
# while the client streams megabytes; a counter corrected too late would taint
# it, and its client -> proxy sends must stay redirected (acked ~ 1).
restart "$CAPBIN" --fast-lo all
attached
backend "$WORK/pecho.py" "$BEPORT" 0
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$BEPORT" --protocol tcp -s >/dev/null; wait_port "$PXPORT" || true
R=$(python3 "$WORK/windowed.py" "$PXPORT" 3 1)
read -r MV IO AK <<<"$R"
if [ "${MV#moved_mib=}" -gt 64 ] && [ "$IO" = in_order=1 ] && [ "${AK#acked=}" -le 1 ]; then pass
else fail "fast pair" "a backend that keeps up keeps the pair on the shortcut (client sends redirected, in order)" "probe: $R (moved>64 MiB, in_order, acked<=1)"; fi
AFTER=$("$BIN" daemon stats 2>&1 || true)
TAINTS=$(( $(figure fast_lo_tainted_bound "$AFTER") + $(figure fast_lo_tainted_unanswered "$AFTER") +
           $(figure fast_lo_tainted_budget "$AFTER") + $(figure fast_lo_tainted_peer_off "$AFTER") ))
if [ "$(figure fast_lo_entered "$AFTER")" -ge 2 ] && [ "$TAINTS" = 0 ]; then pass
else fail "stats: fast pair" "daemon stats shows the fast pair entered and no taint of any kind" "$(tr '\n' ' ' <<<"$AFTER")"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ]
