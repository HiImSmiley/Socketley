#!/usr/bin/env bash
# suite: quiet -- over a thousand connections and a rate compared across arms.
# Integration test: which recv arm a proxy uses, and what the choice is worth
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A multishot recv stays armed in the kernel, which is worth two opposite things.
# It saves the re-arm, and that is the whole cost at high connection counts.  And
# it cannot be declined, which is how every backpressure decision in this proxy is
# made -- so it reads ahead into a queue nothing drains.  Measured, median of the
# per-pass differences against a single-shot arm of the same binary at 8 KiB
# bodies: +7.7% for single-shot at 128 connections, +6.0% at 512, -15.0% at 768.
#
# So the arm is chosen once a turn, from the live client count AND from whether
# the runtime is over its pacing budget, and this file is about the half of that
# which is observable from outside.  Two mechanisms, at two connection counts:
# below the threshold the proxy picks single-shot and backpressure declines the
# read itself, and above it the proxy picks multishot on purpose, so the only
# thing that can bound the queue is withdraw_armed_backend_reads() taking the
# armed read back.  There is a row for each, and a build missing either one reads
# a ratio of 1.
#
# ─── WHY THE ASSERTION IS A RATIO AND NOT A CEILING ─────────────────────────
#
# Worker RSS in megabytes depends on the box, the body size and the allocator, so
# a fixed bound would be a number nobody can defend in a year.  Both arms run in
# THIS run instead, against the same clients and the same backend, and the
# assertion is the ratio between them -- which is also what makes the test fail
# on a build that has no rule: there both arms are multishot, so the ratio is 1.
#
# The body is 4 MiB for that pair and not the 1 MiB the throughput rows use,
# because the rule's arm is bounded by the pacing watermark and does NOT grow
# with the body while the pinned one does -- at 1 MiB the two came out 84 against
# 126 MB, a ratio of 1.5 with no room under a 1.5 threshold, which is a test that
# flakes rather than a test that measures.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the arm pinned on holding materially more than the rule does, which is the
#     rule doing its job and the only externally visible proof of it
#   * a pinned arm that is not actually pinned, so the ratio cannot be a
#     comparison of one configuration with itself
#   * the multishot path still serving correctly -- before the rule every proxy
#     test exercised it, and after the rule NOTHING in this suite reaches it
#     without the pin, which is coverage this change would otherwise have removed
#   * armed reads NOT being taken back above the threshold, which is the only
#     thing that bounds the queue there -- the rule arms multishot on purpose at
#     that count, so backpressure cannot decline anything and the ratio is the
#     whole proof that withdraw_armed_backend_reads() runs
#   * more connections than the threshold, so the switch itself is walked
#   * the proxy still serving after both storms
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

if ! command -v python3 >/dev/null 2>&1; then
    echo "=== Integration: a proxy's recv arm follows its client count ==="
    echo "  SKIP: python3 not available"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

PASS=0; FAIL=0; TOTAL=0; SKIP=0
WORK=$(mktemp -d)
BEPID=""
cleanup(){ [ -n "$BEPID" ] && kill -9 "$BEPID" 2>/dev/null; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }
not_asserted(){ TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1)); echo "  NOT ASSERTED [$1]: $2"; }

SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then SANITIZED="ASan"; fi

echo "=== Integration: a proxy's recv arm follows its client count ==="

BODY=4194304           # what the slow clients ask for: the pinned arm buffers it
BODY_MID=1048576       # what the above-threshold row asks for: big enough that
                       # the body takes many reads, which is the only shape a
                       # withdrawal can do anything about -- at 256 KiB both arms
                       # came out at exactly 383 MB, because the whole body is
                       # queued before the next turn can take the read back
BODY_SMALL=262144      # and what the correctness rows ask for, so they stay quick
SLOW_CLIENTS=128
MANY_CLIENTS=1100      # above MULTISHOT_MIN_CLIENTS, so the switch itself is walked
RATIO_MIN=20           # tenths: 2.0x
BIG_FRAC=88            # hundredths: above the threshold the rule must hold under
                       # 88% of the pinned arm.  In THIS file's shape the two
                       # builds read 100% (no withdrawal: 874 MB against 869) and
                       # 75% (with it: 648 against 869), so 88 sits between them
                       # with about equal room on each side.  The effect is
                       # larger than 25% off a C backend -- 449 MB against 1016
                       # at 1200 clients -- but a Python backend with 1100
                       # threads delivers the bodies in dribbles, so this row
                       # understates it on purpose rather than by accident.

# A backend that serves a 1 MiB body, thread per connection so 1100 at once do
# not queue behind each other and read as the proxy being slow.
cat >"$WORK/be.py" <<'PY'
import socket, sys, threading
port, big, mid, small = (int(sys.argv[1]), int(sys.argv[2]),
                         int(sys.argv[3]), int(sys.argv[4]))
def resp(size):
    return (("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
             "Content-Type: text/plain\r\n\r\n" % size).encode() + b"v" * size)
R = {big: resp(big), mid: resp(mid), small: resp(small)}
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(2048)
def handle(c):
    c.settimeout(30)
    try:
        while True:
            req = c.recv(65536)
            if not req: return
            line = req.split(b"\r\n")[0]
            c.sendall(R[small] if b"/small" in line else
                      R[mid] if b"/mid" in line else R[big])
    except OSError:
        pass
    finally:
        try: c.close()
        except OSError: pass
while True:
    try: cl, _ = srv.accept()
    except OSError: break
    threading.Thread(target=handle, args=(cl,), daemon=True).start()
PY

# N connections that ask and then stop reading, so the proxy is left owing the
# body to peers that never drain.  No threads: the sockets just sit there.
#
# Connected in one pass and asked in a second, because the arm is decided from
# the live client count: connect-then-ask per socket took eleven seconds for
# 1100 and the count was still under the threshold when most of the reads were
# armed, so every one of them got the single-shot arm and the row measured the
# ramp rather than the arm.
cat >"$WORK/slow.py" <<'PY'
import socket, sys, time
port, n, path, hold = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
req = ("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode()
socks = []
for _ in range(n):
    try:
        socks.append(socket.create_connection(("127.0.0.1", port), 5))
    except OSError:
        pass
for s in socks:
    try:
        s.sendall(req)          # and nothing is ever read back, on purpose
    except OSError:
        pass
print(len(socks), flush=True)
time.sleep(hold)
for s in socks:
    try: s.close()
    except OSError: pass
PY

# N concurrent clients that DO read their whole body, so a wrong byte count or a
# dropped connection is a failure rather than a slow row.
cat >"$WORK/many.py" <<'PY'
import socket, sys, selectors
port, n, path, want = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
req = ("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path).encode()
sel = selectors.DefaultSelector()
got, opened = {}, 0
for i in range(n):
    try:
        s = socket.create_connection(("127.0.0.1", port), 10)
        s.setblocking(False)
        s.sendall(req)
        sel.register(s, selectors.EVENT_READ, i)
        got[i] = 0
        opened += 1
    except OSError:
        pass
done = 0
import time
end = time.time() + 60
while done < opened and time.time() < end:
    for key, _ in sel.select(timeout=1.0):
        try:
            d = key.fileobj.recv(262144)
        except OSError:
            d = b""
        if d:
            got[key.data] += len(d)
        else:
            sel.unregister(key.fileobj)
            key.fileobj.close()
            done += 1
full = sum(1 for i in got if got[i] >= want)
print("%d %d %d" % (opened, done, full))
PY

python3 "$WORK/be.py" "$((SL_PORT_BASE + 1746))" "$BODY" "$BODY_MID" "$BODY_SMALL" >"$WORK/be.log" 2>&1 &
BEPID=$!
BPORT=$((SL_PORT_BASE + 1746))
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$BPORT " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$BPORT "; then
    echo "  FATAL: the body backend never bound $BPORT"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

PPORT=$((SL_PORT_BASE + 1745))
HELD=0; WORKER=""

# One arm: its own daemon, because the pin is an environment variable and the
# worker inherits it from the daemon it was forked by.
run_arm() {   # tag [clients] [path] [hold] [samples]   (the pin is the caller's)
    local tag=$1 clients=${2:-$SLOW_CLIENTS} path=${3:-/pa/} hold=${4:-6} samples=${5:-90}
    local base peak r i carried
    daemon_isolate "recvarm-$tag"
    daemon_start "$BIN"
    "$BIN" create proxy pa -p "$PPORT" --backend "127.0.0.1:$BPORT" -s >/dev/null 2>&1 || true
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
    # The pin has to be in the worker, or the ratio compares a configuration
    # with itself and reads as the rule not working.
    carried=$(tr '\0' '\n' <"/proc/$WORKER/environ" 2>/dev/null |
              awk -F= '/^SOCKETLEY_RECV_MULTISHOT=/{print $2}')
    ARM_CARRIED="${carried:-absent}"
    base=$(awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo 0)
    python3 "$WORK/slow.py" "$PPORT" "$clients" "$path" "$hold" >"$WORK/slow.$tag" 2>&1 &
    local sp=$!
    peak=$base
    # Two figures, because they answer different questions.  The peak includes
    # the ramp, which both arms pay alike.  The median of the samples taken
    # after the storm is up and before it closes is what the proxy HOLDS while
    # the clients sit there, and that is the only one a withdrawal moves: it
    # cannot un-queue what arrived before the turn that withdrew the read.
    local up=0
    : >"$WORK/rss.$tag"
    for i in $(seq 1 "$samples"); do
        sleep 0.1
        kill -0 "$sp" 2>/dev/null || break
        r=$(awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo "")
        [ -z "$r" ] && break
        [ "$r" -gt "$peak" ] && peak=$r
        # slow.py prints its count the moment every socket has asked, so a
        # non-empty file is the storm being up.
        [ "$up" = 0 ] && [ -s "$WORK/slow.$tag" ] && up=1
        [ "$up" = 1 ] && echo "$r" >>"$WORK/rss.$tag"
    done
    wait "$sp" 2>/dev/null || true
    ARM_OPENED=$(head -1 "$WORK/slow.$tag" 2>/dev/null || echo 0)
    HELD=$(( (peak - base) / 1024 ))
    ARM_SAMPLES=$(wc -l <"$WORK/rss.$tag" 2>/dev/null || echo 0)
    ARM_STEADY=$(sort -g "$WORK/rss.$tag" 2>/dev/null |
        awk -v b="$base" '{a[NR]=$1}
             END{ if (NR > 0) print int((a[int((NR+1)/2)] - b) / 1024); else print 0 }')
}

# ── 1. the rule, which below the threshold means single-shot ─────────────────
unset SOCKETLEY_RECV_MULTISHOT
run_arm rule
HELD_RULE=$HELD; OPENED_RULE=$ARM_OPENED; CARRIED_RULE=$ARM_CARRIED
echo "  the rule:       $OPENED_RULE slow clients, worker held ${HELD_RULE} MB (MULTISHOT=$CARRIED_RULE)"

# ── 2. and a check that a pinned arm is really pinned ────────────────────────
if [ "$CARRIED_RULE" = absent ]; then pass
else fail "the unpinned arm carries no pin" \
          "the worker for the rule arm carries MULTISHOT='$CARRIED_RULE'" \
          "-- the ratio below would compare one pinned arm with another"; fi

daemon_stop
for i in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PPORT " || break; sleep 0.1; done

# ── 3. the same clients with the arm pinned on ───────────────────────────────
export SOCKETLEY_RECV_MULTISHOT=1
run_arm pinned
HELD_PIN=$HELD; OPENED_PIN=$ARM_OPENED; CARRIED_PIN=$ARM_CARRIED
echo "  arm pinned on:  $OPENED_PIN slow clients, worker held ${HELD_PIN} MB (MULTISHOT=$CARRIED_PIN)"

if [ "$CARRIED_PIN" = 1 ]; then pass
else fail "the pinned arm carries the pin" \
          "the worker for the pinned arm carries MULTISHOT='$CARRIED_PIN', not 1"; fi

# Both storms have to have happened, or the megabytes below are about nothing.
if [ "${OPENED_RULE:-0}" -ge $((SLOW_CLIENTS / 2)) ] && [ "${OPENED_PIN:-0}" -ge $((SLOW_CLIENTS / 2)) ]; then
    pass
else fail "both storms reached the proxy" \
          "opened $OPENED_RULE and $OPENED_PIN of $SLOW_CLIENTS" \
          "-- a held figure from a storm that never arrived proves nothing"; fi

# ── 4. the ratio, which is the whole point ──────────────────────────────────
if [ -n "$SANITIZED" ]; then
    not_asserted "the pinned arm holds more than the rule does" \
        "held ${HELD_RULE} MB against ${HELD_PIN} MB; RSS under $SANITIZED measures the allocator's quarantine"
elif [ "${HELD_RULE:-0}" -le 0 ]; then
    fail "the pinned arm holds more than the rule does" \
         "the rule arm held ${HELD_RULE} MB, so there is no ratio to take" \
         "-- the clients did not make the proxy hold anything, so the body or the" \
         "   hold window is wrong rather than the proxy"
else
    RATIO_T=$(( HELD_PIN * 10 / HELD_RULE ))
    echo "  ratio: pinned/rule = ${RATIO_T}/10, threshold ${RATIO_MIN}/10"
    if [ "$RATIO_T" -ge "$RATIO_MIN" ]; then pass
    else fail "the pinned arm holds more than the rule does" \
              "pinned held ${HELD_PIN} MB against ${HELD_RULE} MB, ratio ${RATIO_T}/10" \
              "-- below the threshold the proxy is to pick single-shot, which is the" \
              "   only arm backpressure can decline; a ratio near 1 means both arms" \
              "   are multishot and the count is not deciding anything"; fi
fi

# ── 5. the multishot path still serves, on this same pinned daemon ──────────
MANY_PIN=$(timeout 90 python3 "$WORK/many.py" "$PPORT" 64 "/pa/small" "$BODY_SMALL" 2>/dev/null || echo "0 0 0")
read -r m_open m_done m_full <<<"$MANY_PIN"
if [ "${m_full:-0}" -ge 60 ] && [ "${m_open:-0}" -ge 60 ]; then
    echo "  pinned multishot served $m_full of $m_open bodies in full"
    pass
else fail "the multishot path still serves whole bodies" \
          "opened $m_open, finished $m_done, complete $m_full of 64 at $BODY_SMALL bytes" \
          "-- with the rule in place nothing else in this suite reaches the" \
          "   multishot arm, so this row is its only coverage"; fi

daemon_stop
unset SOCKETLEY_RECV_MULTISHOT
for i in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PPORT " || break; sleep 0.1; done

# ── 6. the same ratio ABOVE the threshold, where the arm is multishot ───────
# This is the row the withdrawal exists for.  Below the threshold the rule picks
# single-shot and backpressure declines the read itself; above it the rule picks
# multishot on purpose, so the only thing that can bound the queue is taking the
# armed read back -- and on a build that does not, this row reads 1.0 because
# both arms are the same arm.
#
# 1 MiB and not the 4 MiB above, because 1100 clients times 4 MiB is more than
# this box has and the row would be measuring the OOM killer -- and not the
# 256 KiB of the correctness rows either, because a body that fits in one turn is
# fully queued before any withdrawal can be submitted, which read as both arms
# holding exactly 383 MB.
unset SOCKETLEY_RECV_MULTISHOT
run_arm bigrule "$MANY_CLIENTS" /pa/mid 10 400
HELD_BR=$ARM_STEADY; OPENED_BR=$ARM_OPENED; SAMPLES_BR=$ARM_SAMPLES
echo "  above the threshold, the rule: $OPENED_BR slow clients, held ${HELD_BR} MB (peak ${HELD} MB)"
daemon_stop
for i in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PPORT " || break; sleep 0.1; done

export SOCKETLEY_RECV_MULTISHOT=1
run_arm bigpin "$MANY_CLIENTS" /pa/mid 10 400
HELD_BP=$ARM_STEADY; OPENED_BP=$ARM_OPENED
echo "  above the threshold, pinned:   $OPENED_BP slow clients, held ${HELD_BP} MB (peak ${HELD} MB)"
daemon_stop
unset SOCKETLEY_RECV_MULTISHOT
for i in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PPORT " || break; sleep 0.1; done

if [ -n "$SANITIZED" ]; then
    not_asserted "above the threshold the rule still bounds the queue" \
        "held ${HELD_BR} MB against ${HELD_BP} MB; RSS under $SANITIZED measures the allocator's quarantine"
elif [ "${OPENED_BR:-0}" -lt $((MANY_CLIENTS / 2)) ] || [ "${OPENED_BP:-0}" -lt $((MANY_CLIENTS / 2)) ]; then
    fail "above the threshold the rule still bounds the queue" \
         "opened $OPENED_BR and $OPENED_BP of $MANY_CLIENTS" \
         "-- neither storm arrived, so the megabytes are about nothing"
elif [ "${SAMPLES_BR:-0}" -le 0 ]; then
    fail "above the threshold the rule still bounds the queue" \
         "the rule arm took no RSS sample while its storm was up, so its ${HELD_BR} MB is no measurement"
elif [ "${HELD_BP:-0}" -le 0 ]; then
    fail "above the threshold the rule still bounds the queue" \
         "the pinned arm held ${HELD_BP} MB, so there is no ratio to take" \
         "-- the clients did not make the proxy hold anything, so the body or the" \
         "   hold window is wrong rather than the proxy"
else
    echo "  ratio: rule/pinned = $(( HELD_BR * 100 / HELD_BP ))%, must be under ${BIG_FRAC}%"
    if [ $(( HELD_BR * 100 )) -lt $(( HELD_BP * BIG_FRAC )) ]; then pass
    else fail "above the threshold the rule still bounds the queue" \
              "the rule held ${HELD_BR} MB against the pinned arm's ${HELD_BP} MB," \
              "which is $(( HELD_BR * 100 / HELD_BP ))% where it must be under ${BIG_FRAC}%" \
              "-- above MULTISHOT_MIN_CLIENTS the rule arms multishot deliberately," \
              "   so the bound comes from withdraw_armed_backend_reads() alone; a" \
              "   ratio near 1.0 means the armed reads are not being taken back"; fi
fi

# ── 7. and more clients than the threshold, so the switch itself is walked ──
daemon_isolate recvarm-many
daemon_start "$BIN"
"$BIN" create proxy pa -p "$PPORT" --backend "127.0.0.1:$BPORT" -s >/dev/null 2>&1 || true
for i in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$PPORT " && break; sleep 0.1; done
MANY=$(timeout 180 python3 "$WORK/many.py" "$PPORT" "$MANY_CLIENTS" "/pa/small" "$BODY_SMALL" 2>/dev/null || echo "0 0 0")
read -r n_open n_done n_full <<<"$MANY"
if [ "${n_open:-0}" -gt 768 ] && [ "${n_full:-0}" -ge $(( n_open * 95 / 100 )) ]; then
    echo "  past the threshold: $n_open clients, $n_full complete bodies"
    pass
else fail "more clients than the threshold are served correctly" \
          "opened $n_open of $MANY_CLIENTS, finished $n_done, complete $n_full" \
          "-- above MULTISHOT_MIN_CLIENTS the rule switches arm mid-flight, and a" \
          "   connection already armed keeps its own, so both arms are live at once"; fi

# ── 8. and the proxy is still there ─────────────────────────────────────────
LAST=$(timeout 30 python3 "$WORK/many.py" "$PPORT" 1 "/pa/small" "$BODY_SMALL" 2>/dev/null || echo "0 0 0")
read -r l_open l_done l_full <<<"$LAST"
if [ "${l_full:-0}" = 1 ]; then pass
else fail "the proxy still serves after both storms" \
          "a single request answered $l_full complete of 1 (opened $l_open)"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
