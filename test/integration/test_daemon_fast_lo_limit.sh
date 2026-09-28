#!/usr/bin/env bash
# Integration test: `daemon --fast-lo-limit` bounds the redirected backlog
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A redirected send lands straight in the peer's ingress queue and never waits
# for the reader, so without a bound one stalled reader can hold hundreds of
# MiB of the host's TCP memory (measured: 731 MiB before the kernel's tcp_mem
# ran out).  The limiter counts each pair's sends in a BPF map; past a mark it
# asks a reconciler thread, through a ring buffer, for the peer's true queue,
# and the answer snaps the count back.  A pair whose peer really holds the
# per-pair bound, or whose count reaches twice it unanswered, is tainted to TCP
# -- which then gives real backpressure -- and the sum across pairs is capped at
# the global budget.  The taint is permanent for the pair, which is what keeps
# bytes in order: tcp_bpf_recvmsg drains the redirect queue before the TCP
# receive queue.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a --fast-lo-limit value that is not two positive MiB integers accepted
#   * a stalled reader holding far more than the per-pair ceiling (the bound
#     not enforced) -- shown red by raising the ceiling to 512 MiB
#   * a byte delivered out of order once the reader resumes
#   * the sum across many stalled pairs exceeding the global budget -- shown red
#     by raising the budget
#   * a fast pair whose reader keeps up tainted anyway, because its count was
#     corrected too late or not at all -- red on a limiter that corrects on a
#     timer (f6b10a60 sent 3.7 of its 4.3 GB by TCP)
#   * a proxy's pair to a stalled local backend of another process -- which is
#     on the shortcut because the proxy's connect is this daemon's -- left
#     unbounded; its red is the same backend under a 64 MiB bound holding more
#     than TCP gives a reader that never read (tcp_rmem default), which shows the
#     pair was on the shortcut at all
#   * `daemon stats` and the metrics endpoint not showing what the shortcut
#     did: a stalled reader's pair tainted for its bound, held and counted as
#     on TCP while it lasts; a pair tainted by the global budget; a fast pair
#     entered and never tainted -- red with the sk_msg program's taint count
#     removed, and with the sockops program's entry count removed
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
SINKPID=""
cleanup(){ [ -n "$SINKPID" ] && { kill -9 "$SINKPID" 2>/dev/null || true; }; daemon_stop; rm -rf "$WORK"; }
trap cleanup EXIT

CPORT=$((SL_PORT_BASE + 1831))
PXPORT=$((SL_PORT_BASE + 1836))
SINKPORT=$((SL_PORT_BASE + 1837))
MPORT=$((SL_PORT_BASE + 1838))
cat >"$WORK/metrics.lua" <<LUA
daemon = { metrics_port = $MPORT }
LUA

# One figure out of `daemon stats`.
figure(){ { grep -oE "^$1:[0-9]+" <<<"$2" || echo "$1:-1"; } | head -1 | cut -d: -f2; }

# A local backend of another process that accepts and never reads.
cat >"$WORK/sink.py" <<'PY'
import socket, sys
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(8)
held = []
while True:
    c, _ = l.accept(); held.append(c)
PY

# Pushes through a proxy for 2 s and samples the backend's rmem (its accepted
# socket, source port SINKPORT), which includes the psock backlog.
cat >"$WORK/push.py" <<'PY'
import socket, subprocess, sys, time
pp, ep = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", pp), timeout=10); s.setblocking(False)
buf = b"y" * 65536; peak = 0; t0 = time.time(); last = 0
def rmem():
    out = subprocess.run(["ss", "-tmnH", "( sport = :%d )" % ep], capture_output=True, text=True).stdout
    return max([int(x.split("skmem:(r", 1)[1].split(",", 1)[0]) for x in out.splitlines() if "skmem:(r" in x] or [0])
while time.time() - t0 < 2:
    try: s.send(buf)
    except BlockingIOError: time.sleep(0.001)
    if time.time() - last > 0.05: peak = max(peak, rmem()); last = time.time()
print("peak_mib=%.2f" % (peak / 1048576.0))
PY

# A stalled reader: pipeline GETs of a big value and never read the replies;
# sample our own socket's rmem (which includes the psock backlog on this
# kernel); then read everything and check it arrived, in order.
cat >"$WORK/stall.py" <<'PY'
import socket, sys, time, subprocess, os
port, val_kib, ngets, hold = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
v = os.urandom(val_kib << 10)
s.sendall(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$%d\r\n%s\r\n" % (len(v), v))
assert s.recv(100).startswith(b"+OK"), "SET failed"
s.setblocking(False)
sent = 0
for _ in range(ngets):
    try: s.sendall(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n"); sent += 1
    except BlockingIOError: break
def rmem():
    lp = s.getsockname()[1]
    out = subprocess.run(["ss","-tmn","( sport = :%d or dport = :%d )" % (lp, lp)],
                         capture_output=True, text=True).stdout
    return max([int(x.split("skmem:(r",1)[1].split(",",1)[0]) for x in out.splitlines() if "skmem:(r" in x] or [0])
peak = 0; t0 = time.time()
while time.time() - t0 < hold:
    peak = max(peak, rmem()); time.sleep(0.05)
s.setblocking(True); s.settimeout(30)
want = (b"$%d\r\n%s\r\n" % (len(v), v)) * sent
got = bytearray()
try:
    while len(got) < len(want):
        d = s.recv(1 << 20)
        if not d: break
        got += d
except socket.timeout: pass
print("peak_mib=%.2f in_order=%d complete=%d" %
      (peak/1048576.0, int(bytes(got) == want[:len(got)]), int(len(got) == len(want))))
PY

# Many stalled readers at once; report the summed rmem across them all.
cat >"$WORK/stall_many.py" <<'PY'
import socket, sys, time, subprocess, os
port, k, val_kib, ngets, hold = (int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]),
                                 int(sys.argv[4]), float(sys.argv[5]))
v = os.urandom(val_kib << 10)
conns = []
# Stagger the stalls across reconcile ticks: the global budget cannot reclaim a
# backlog already frozen, only stop new ones once the reconciler has seen the
# sum cross the budget, so a synchronized burst would all commit before it acts.
for _ in range(k):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$%d\r\n%s\r\n" % (len(v), v)); s.recv(100)
    s.setblocking(False)
    for _ in range(ngets):
        try: s.sendall(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")
        except BlockingIOError: break
    conns.append(s)
    time.sleep(0.25)
def sum_rmem():
    out = subprocess.run(["ss","-tmn","dst 127.0.0.1"], capture_output=True, text=True).stdout
    tot, ports = 0, {c.getsockname()[1] for c in conns}
    lines = out.splitlines()
    for i, ln in enumerate(lines):
        if ":" in ln and "skmem" not in ln:
            try: lp = int(ln.split()[3].rsplit(":",1)[1])
            except Exception: continue
            if lp in ports and i+1 < len(lines) and "skmem:(r" in lines[i+1]:
                tot += int(lines[i+1].split("skmem:(r",1)[1].split(",",1)[0])
    return tot
peak = 0; t0 = time.time()
while time.time() - t0 < hold:
    peak = max(peak, sum_rmem()); time.sleep(0.05)
print("sum_mib=%.2f" % (peak/1048576.0))
PY

# A fast pair whose reader keeps up: pipelined GETs of a 64 KiB value, 32 in
# flight (about 2 MiB unread at most), for 2 s; then the client's own TCP
# counters -- received bytes are what the cache sent by TCP, 0 on the shortcut.
cat >"$WORK/fast.py" <<'PY'
import socket, struct, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
v = b"z" * 65536
s.sendall(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$65536\r\n" + v + b"\r\n"); s.recv(100)
req = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n" * 32
want = 32 * (len(b"$65536\r\n") + 65536 + 2)
t0 = time.time(); n = 0
while time.time() - t0 < 2:
    s.sendall(req); got = 0
    while got < want: got += len(s.recv(1 << 22))
    n += want
acked, rcvd = struct.unpack_from("QQ", s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256), 120)
print("moved_mib=%d acked=%d rcvd=%d" % (n >> 20, acked, rcvd))
PY

wait_port(){ local i; for i in $(seq 1 50); do python3 -c "import socket,sys;socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=1)" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
restart(){ daemon_stop; daemon_isolate fastlolim; daemon_watch "$WORK"; daemon_start "$@"; }

# ─── (a) the flag's value ───────────────────────────────────────────────────
for bad in "" "4" "4,0" "0,64" "4," "x,y" "4,2"; do
    OUT=$("$BIN" daemon --fast-lo all --fast-lo-limit "$bad" 2>&1) && RC=0 || RC=$?
    if [ "$RC" = 1 ] && grep -q 'fast-lo-limit' <<<"$OUT"; then :; else
        fail "bad limit '$bad'" "should exit 1 naming the flag" "rc=$RC out: $OUT"; fi
done
pass  # the loop above only fails; reaching here is the pass

# ─── the capped copy ────────────────────────────────────────────────────────
CAPBIN="$WORK/socketley-fastlolim"
cp "$BIN" "$CAPBIN"; chmod 755 "$CAPBIN"
if ! sudo -n setcap cap_bpf,cap_net_admin+ep "$CAPBIN" 2>/dev/null; then
    echo "  SKIP: the bound itself (no sudo -n setcap for CAP_BPF/CAP_NET_ADMIN)"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    [ "$FAIL" = 0 ] && exit 0 || exit 1
fi
attached(){ if grep -q 'fast-lo: unavailable' "$SOCKETLEY_DLOG"; then
    echo "  SKIP: the shortcut did not attach: $(grep fast-lo "$SOCKETLEY_DLOG")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; [ "$FAIL" = 0 ] && exit 0 || exit 1; fi; }

# ─── (b) per-pair bound holds a stalled reader, and order survives resume ────
SOCKETLEY_CONFIG="$WORK/metrics.lua" restart "$CAPBIN" --fast-lo all --fast-lo-limit 4,256
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null; wait_port "$CPORT" || true
python3 "$WORK/stall.py" "$CPORT" 256 24 3 >"$WORK/stall.out" 2>&1 & STALLPID=$!
# Mid-stall, after at least one sweep: the figures an operator would read.
sleep 2
MID=$("$BIN" daemon stats 2>&1 || true)
SCRAPE=$(python3 -c "import sys,urllib.request;print(urllib.request.urlopen('http://127.0.0.1:%s/metrics' % sys.argv[1], timeout=5).read().decode())" "$MPORT" 2>&1 || true)
wait "$STALLPID" || true
R=$(cat "$WORK/stall.out")
read -r PK IO CO <<<"$R"; PKV=${PK#peak_mib=}
if awk "BEGIN{exit !($PKV <= 6)}" && [ "$IO" = in_order=1 ] && [ "$CO" = complete=1 ]; then pass
else fail "per-pair bound" "a stalled reader stays near the 4 MiB ceiling and resumes in order" "probe: $R (peak<=6, in_order, complete)"; fi

if grep -q '^fast_lo:all$' <<<"$MID" && [ "$(figure fast_lo_entered "$MID")" -ge 2 ] &&
   [ "$(figure fast_lo_tainted_bound "$MID")" -ge 1 ] && [ "$(figure fast_lo_sockets_tcp "$MID")" -ge 1 ] &&
   [ "$(figure fast_lo_held_bytes "$MID")" -ge 3145728 ]; then pass
else fail "stats: stalled" "daemon stats shows the stalled pair entered, tainted for its bound, on TCP, and ~4 MiB held" \
    "$(tr '\n' ' ' <<<"$MID")"; fi
if grep -q 'socketley_fast_lo_info{mode="all"} 1' <<<"$SCRAPE" &&
   grep -qE 'socketley_fast_lo_tainted_total\{reason="bound"\} [1-9]' <<<"$SCRAPE" &&
   grep -qE 'socketley_fast_lo_sockets\{path="tcp"\} [1-9]' <<<"$SCRAPE"; then pass
else fail "metrics: stalled" "the metrics endpoint carries the mode, the bound taint and the socket on TCP" \
    "$(grep fast_lo <<<"$SCRAPE" | grep -v '^#' | tr '\n' ' ')"; fi

# ─── (c) red: with the ceiling raised the same reader holds far more ─────────
restart "$CAPBIN" --fast-lo all --fast-lo-limit 512,1024
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null; wait_port "$CPORT" || true
R=$(python3 "$WORK/stall.py" "$CPORT" 256 60 3)
read -r PK IO CO <<<"$R"; PKV=${PK#peak_mib=}
if awk "BEGIN{exit !($PKV > 6)}"; then pass
else fail "per-pair red" "a 512 MiB ceiling must let the backlog exceed 6 MiB (else the bound is untested)" "probe: $R"; fi

# ─── (d) global budget caps the sum across many stalled pairs ───────────────
restart "$CAPBIN" --fast-lo all --fast-lo-limit 4,12
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null; wait_port "$CPORT" || true
BOUNDED=$(python3 "$WORK/stall_many.py" "$CPORT" 8 256 60 3); BV=${BOUNDED#sum_mib=}
AFTER=$("$BIN" daemon stats 2>&1 || true)
if [ "$(figure fast_lo_tainted_budget "$AFTER")" -ge 1 ]; then pass
else fail "stats: budget" "daemon stats counts the pairs the global budget tainted" "$(tr '\n' ' ' <<<"$AFTER")"; fi

restart "$CAPBIN" --fast-lo all --fast-lo-limit 4,4096
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null; wait_port "$CPORT" || true
OPEN=$(python3 "$WORK/stall_many.py" "$CPORT" 8 256 60 3); OV=${OPEN#sum_mib=}

if awk "BEGIN{exit !($BV <= 20 && $OV > $BV + 4)}"; then pass
else fail "global budget" "the summed backlog stays near the 12 MiB budget and grows without it" "bounded=$BV MiB open=$OV MiB (bounded<=20 and open>bounded+4)"; fi

# ─── (e) a fast pair whose reader keeps up is never tainted ─────────────────
# It moves far more than the per-pair bound in total while its unread backlog
# stays near 2 MiB, so a counter that is not corrected in time taints it.
restart "$CAPBIN" --fast-lo all
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null; wait_port "$CPORT" || true
R=$(python3 "$WORK/fast.py" "$CPORT")
read -r MV AK RC <<<"$R"
if [ "${MV#moved_mib=}" -gt 256 ] && [ "${AK#acked=}" -le 1 ] && [ "${RC#rcvd=}" = 0 ]; then pass
else fail "fast pair" "a reader that keeps up keeps its pair on the shortcut (nothing received by TCP)" "probe: $R (moved>256 MiB, acked<=1, rcvd=0)"; fi
AFTER=$("$BIN" daemon stats 2>&1 || true)
TAINTS=$(( $(figure fast_lo_tainted_bound "$AFTER") + $(figure fast_lo_tainted_unanswered "$AFTER") +
           $(figure fast_lo_tainted_budget "$AFTER") + $(figure fast_lo_tainted_peer_off "$AFTER") ))
if [ "$(figure fast_lo_entered "$AFTER")" -ge 2 ] && [ "$TAINTS" = 0 ]; then pass
else fail "stats: fast pair" "daemon stats shows the fast pair entered and no taint of any kind" "$(tr '\n' ' ' <<<"$AFTER")"; fi

# ─── (f) a proxy's pair to a stalled local backend of another process ───────
python3 "$WORK/sink.py" "$SINKPORT" >/dev/null 2>&1 & SINKPID=$!; disown
wait_port "$SINKPORT" || true
restart "$CAPBIN" --fast-lo all --fast-lo-limit 4,64
attached
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$SINKPORT" --protocol tcp -s >/dev/null
wait_port "$PXPORT" || true
BOUNDED=$(python3 "$WORK/push.py" "$PXPORT" "$SINKPORT"); BV=${BOUNDED#peak_mib=}

restart "$CAPBIN" --fast-lo all --fast-lo-limit 64,256
attached
"$BIN" create proxy px -p "$PXPORT" --backend "127.0.0.1:$SINKPORT" --protocol tcp -s >/dev/null
wait_port "$PXPORT" || true
OPEN=$(python3 "$WORK/push.py" "$PXPORT" "$SINKPORT"); OV=${OPEN#peak_mib=}

if awk "BEGIN{exit !($BV <= 6 && $OV > 12)}"; then pass
else fail "foreign backend bound" "a stalled backend of another process stays near the 4 MiB bound, and holds past TCP's buffer under 64" \
    "bounded=$BV MiB open=$OV MiB (bounded<=6 and open>12)"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ]
