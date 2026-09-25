#!/usr/bin/env bash
# Integration test: what a proxy holds when its clients upload faster than the
# backend takes it
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# handle_client_read declines the next read while the BACKEND's write queue is
# over the pacing point, which is the same decline handle_backend_read makes in
# the other direction -- and a multishot recv ignores it just the same, because
# it is already armed in the kernel and nothing asked it to stop.
#
# The two directions are not the same size.  A backend sends what it has; clients
# uploading through a TCP proxy on loopback are bounded by nothing.  Measured at
# 1,200 of them into a backend that accepts and never reads: 357 MB held on a
# single-shot arm against 5,032 MB with the arm pinned on, and 1,885 MB on the
# shipped rule before withdraw_armed_client_reads() existed.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the armed client reads not being taken back, which above
#     MULTISHOT_MIN_CLIENTS is the only thing that bounds the upload -- the rule
#     arms multishot on purpose at that count, so the rule is held to what a
#     single-shot arm holds, which declines at the bottom of every read
#   * a reference arm that is not single-shot, so the comparison is not one
#     configuration with itself
#   * more clients than the threshold, or the row is about the other arm
#   * and the one thing a megabyte figure cannot see: that withdrawing a read
#     mid-body does not LOSE any of it.  A cancelled multishot recv can have data
#     completions queued ahead of its -ECANCELED, and taking the cancellation as
#     the end of the read would drop them -- silently, in the middle of an upload
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

if ! command -v python3 >/dev/null 2>&1; then
    echo "=== Integration: an upload through a proxy is bounded by its backend ==="
    echo "  SKIP: python3 not available"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
BEPID=""
# `|| true` on every kill: the sink exits by itself once it has written its
# counts, and under set -e a kill of a process that is already gone ends the run
# three assertions early -- which it did.
cleanup(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }
not_asserted(){ TOTAL=$((TOTAL+1)); echo "  NOT ASSERTED [$1]: $2"; }

SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then SANITIZED="ASan"; fi

echo "=== Integration: an upload through a proxy is bounded by its backend ==="

MANY=1100              # above MULTISHOT_MIN_CLIENTS, or the rule arms single-shot
PER=1048576            # and what each of them sends, so the row is bounded by
                       # 1100 MiB rather than by how long it runs
FEW=8                  # the integrity row: few enough to check every byte
FEW_BYTES=4194304
# The reference is single-shot, which declines at the bottom of every read, and
# not multishot pinned on: since decline_armed_read() a pinned arm is bounded
# too, and the old ratio against it read 55-68% across a 60% line on one binary.
BPORT=$((SL_PORT_BASE + 1752))
PPORT=$((SL_PORT_BASE + 1751))

# A backend that accepts and does not read for `quiet` seconds, then drains
# everything and counts what arrived per connection.  Not reading is the whole
# point: it is what puts the proxy's write queue over the pacing point.
cat >"$WORK/sink.py" <<'PY'
import socket, sys, selectors, time
port, quiet = int(sys.argv[1]), float(sys.argv[2])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(4096); srv.setblocking(False)
sel = selectors.DefaultSelector()
sel.register(srv, selectors.EVENT_READ, None)
held, counts, t0 = [], {}, time.time()
draining, seen, live = False, 0, 0
while True:
    for key, _ in sel.select(timeout=0.2):
        if key.data is None:
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    break
                c.setblocking(False)
                held.append(c)
                counts[c.fileno()] = 0
                seen += 1
                if draining:
                    sel.register(c, selectors.EVENT_READ, c.fileno()); live += 1
        else:
            try:
                d = key.fileobj.recv(262144)
            except OSError:
                d = b""
            if d:
                counts[key.data] += len(d)
            else:
                sel.unregister(key.fileobj); key.fileobj.close(); live -= 1
    if not draining and time.time() - t0 > quiet:
        draining = True
        for c in held:
            try:
                sel.register(c, selectors.EVENT_READ, c.fileno()); live += 1
            except (KeyError, ValueError, OSError): pass
    # Ended by every upload reaching EOF, not by a stopwatch: the proxy is still
    # forwarding what it queued while this end was not reading, and a timer here
    # counts whatever happened to have arrived.
    if draining and seen > 0 and live <= 0:
        break
    if time.time() - t0 > quiet + 90:
        break
with open(sys.argv[3], "w") as f:
    for v in counts.values():
        f.write("%d\n" % v)
PY

# N connections that each push PER bytes and then sit there, in C because a
# Python uploader pushes too little to fill what the proxy would hold.
if ! gcc -O2 -pthread -o "$WORK/load" "$HERE/lib_hold_load.c" 2>"$WORK/cc.log"; then
    echo "  SKIP: no C compiler"; cat "$WORK/cc.log"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

start_backend(){   # quiet_seconds counts_file
    python3 "$WORK/sink.py" "$BPORT" "$1" "$2" >"$WORK/be.log" 2>&1 &
    BEPID=$!
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$BPORT " && break; sleep 0.1; done
    if ! ss -ltn 2>/dev/null | grep -q ":$BPORT "; then
        echo "  FATAL: the sink backend never bound $BPORT"
        echo "  Results: 0/0 passed (0 failed)"; exit 2
    fi
}
stop_backend(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; BEPID=""
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$BPORT " || break; sleep 0.1; done; }

HELD=0; WORKER=""; ARM_CARRIED=""; ARM_OPENED=0; ARM_SENT=0
run_arm(){   # tag clients per hold   (the pin is the caller's)
    local tag=$1 clients=$2 per=$3 hold=$4 base r i carried up
    daemon_isolate "upbound-$tag"
    daemon_start "$BIN"
    "$BIN" create proxy up -p "$PPORT" --backend "127.0.0.1:$BPORT" --protocol tcp -s >/dev/null 2>&1 || true
    for i in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$PPORT " && break; sleep 0.1; done
    if ! ss -ltn 2>/dev/null | grep -q ":$PPORT "; then
        echo "  FATAL: the proxy never bound $PPORT for arm $tag"
        echo "  Results: 0/0 passed (0 failed)"; exit 2
    fi
    WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$PPORT" '$4 ~ p"$" {
        if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
    if [ -z "${WORKER:-}" ]; then
        echo "  FATAL: no pid for the proxy listener"; echo "  Results: 0/0 passed (0 failed)"; exit 2
    fi
    carried=$(tr '\0' '\n' <"/proc/$WORKER/environ" 2>/dev/null |
              awk -F= '/^SOCKETLEY_RECV_MULTISHOT=/{print $2}')
    ARM_CARRIED="${carried:-absent}"
    base=$(awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo 0)
    "$WORK/load" up "$PPORT" "$clients" "$per" >"$WORK/up.$tag" 2>/dev/null &
    up=$!
    local peak=$base
    for i in $(seq 1 $(( (${hold%.*} + 8) * 10 )) ); do
        sleep 0.1
        kill -0 "$up" 2>/dev/null || break
        r=$(awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo "")
        [ -z "$r" ] && break
        [ "$r" -gt "$peak" ] && peak=$r
    done
    wait "$up" 2>/dev/null || true
    ARM_OPENED=$(sed -n 1p "$WORK/up.$tag" 2>/dev/null || echo 0)
    ARM_SENT=$(sed -n 2p "$WORK/up.$tag" 2>/dev/null || echo 0)
    HELD=$(( (peak - base) / 1024 ))
}

# ── 1. the rule, above the threshold, where it arms multishot on purpose ────
start_backend 30 "$WORK/counts.rule"
unset SOCKETLEY_RECV_MULTISHOT
run_arm rule "$MANY" "$PER" 12
HELD_RULE=$HELD; OPENED_RULE=$ARM_OPENED; CARRIED_RULE=$ARM_CARRIED
echo "  the rule:      $OPENED_RULE uploading clients, worker held ${HELD_RULE} MB (MULTISHOT=$CARRIED_RULE)"
daemon_stop; stop_backend
for i in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PPORT " || break; sleep 0.1; done

if [ "$CARRIED_RULE" = absent ]; then pass
else fail "the unpinned arm carries no pin" \
          "the worker for the rule arm carries MULTISHOT='$CARRIED_RULE'" \
          "-- the comparison below would be one pinned arm with another"; fi

# ── 2. the same storm on a single-shot arm ──────────────────────────────────
start_backend 30 "$WORK/counts.single"
export SOCKETLEY_RECV_MULTISHOT=0
run_arm single "$MANY" "$PER" 12
HELD_SINGLE=$HELD; OPENED_SINGLE=$ARM_OPENED; CARRIED_SINGLE=$ARM_CARRIED
echo "  single-shot:   $OPENED_SINGLE uploading clients, worker held ${HELD_SINGLE} MB (MULTISHOT=$CARRIED_SINGLE)"
daemon_stop; stop_backend
unset SOCKETLEY_RECV_MULTISHOT
for i in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PPORT " || break; sleep 0.1; done

if [ "$CARRIED_SINGLE" = 0 ]; then pass
else fail "the single-shot arm carries the pin" \
          "the worker for the single-shot arm carries MULTISHOT='$CARRIED_SINGLE', not 0"; fi

if [ "${OPENED_RULE:-0}" -gt 768 ] && [ "${OPENED_SINGLE:-0}" -gt 768 ]; then pass
else fail "both storms are above the threshold" \
          "opened $OPENED_RULE and $OPENED_SINGLE, and the threshold is 768" \
          "-- below it the rule arms single-shot and the row is about nothing"; fi

# ── 3. the rule holds what single-shot holds ────────────────────────────────
if [ -n "$SANITIZED" ]; then
    not_asserted "the rule bounds what an upload can make the proxy hold" \
        "held ${HELD_RULE} MB against ${HELD_SINGLE} MB; RSS under $SANITIZED measures the allocator's quarantine"
elif [ "${HELD_SINGLE:-0}" -le 0 ]; then
    fail "the rule bounds what an upload can make the proxy hold" \
         "the single-shot arm held ${HELD_SINGLE} MB, so there is nothing to compare with" \
         "-- the clients did not make the proxy hold anything, so the storm or the" \
         "   backend is wrong rather than the proxy"
elif [ "$HELD_RULE" -le $(( HELD_SINGLE * 3 / 2 )) ]; then pass
else fail "the rule bounds what an upload can make the proxy hold" \
          "the rule held ${HELD_RULE} MB against single-shot's ${HELD_SINGLE} MB" \
          "-- above MULTISHOT_MIN_CLIENTS the read is armed multishot on purpose," \
          "   so taking armed reads back is the only thing bounding this"; fi

# ── 4. and not one byte of it is lost on the way ────────────────────────────
# The withdrawal cancels a read that may already have data completions queued
# ahead of its -ECANCELED.  Treating the cancellation as the end of the read
# would drop them, in the middle of a body, with nothing to notice it.
start_backend 3 "$WORK/counts.few"
unset SOCKETLEY_RECV_MULTISHOT
export SOCKETLEY_RECV_MULTISHOT=1      # multishot for certain, at any count
run_arm few "$FEW" "$FEW_BYTES" 20
unset SOCKETLEY_RECV_MULTISHOT
FEW_OPENED=$ARM_OPENED; FEW_SENT=$ARM_SENT
# The proxy stays up until the backend has seen every upload end.  Stopping the
# daemon first throws away whatever is still queued for the backend -- which read
# as 4.5 MB of 32 arriving, and as a product defect.
for i in $(seq 1 400); do [ -s "$WORK/counts.few" ] && break; sleep 0.2; done
daemon_stop
stop_backend

GOT_TOTAL=$(awk '{s+=$1} END{print s+0}' "$WORK/counts.few" 2>/dev/null || echo 0)
GOT_FULL=$(awk -v w="$FEW_BYTES" '$1 >= w {n++} END{print n+0}' "$WORK/counts.few" 2>/dev/null || echo 0)
echo "  integrity: $FEW_OPENED uploads of $FEW_BYTES B, backend counted $GOT_TOTAL B in $GOT_FULL whole"
if [ "${FEW_OPENED:-0}" = "$FEW" ] && [ "${GOT_FULL:-0}" = "$FEW" ] &&
   [ "${GOT_TOTAL:-0}" = $(( FEW * FEW_BYTES )) ]; then pass
else fail "a withdrawn read loses none of the body it was in the middle of" \
          "$FEW_OPENED clients sent $FEW_SENT B, the backend counted $GOT_TOTAL B" \
          "of an expected $(( FEW * FEW_BYTES )), whole bodies $GOT_FULL of $FEW" \
          "-- a data completion queued ahead of the -ECANCELED is a piece of the" \
          "   upload; taking the cancellation as the end of the read drops it"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
