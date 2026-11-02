#!/usr/bin/env bash
# Integration test: the second concurrent download is not punished for being second.
#
# ─── ONE PIPE, ONE CONNECTION AT A TIME ─────────────────────────────────────
#
# The zero-copy path needed a pipe, and there was exactly one per runtime:
#
#     int  m_splice_pipe[2]{-1, -1};
#     bool m_splice_busy{false};
#
# so the acquire read `!m_splice_busy`, and every connection but the one holding
# it fell back to read+write -- which for a 4 MiB file was measured at 6087 us
# against splice's 975. Interleaved A/B of the two builds, seven passes,
# concurrent downloads of 4 MiB files:
#
#     conc   old        new       factor   spread(new)
#     1       2.9 ms     2.9 ms    0.98x        262%
#     2      11.9 ms     4.2 ms    2.80x         36%
#     4      26.1 ms     5.3 ms    4.97x         25%
#     8      55.8 ms    10.5 ms    5.33x         13%
#
# The count was 8 when that was measured, and a later benchmark showed 8 put the
# boundary at about ten concurrent requests -- past which the read path's
# per-request allocation of the whole file costs 13x the throughput and grows
# RSS with concurrency.  It is a 64 MB pipe budget now, so the count follows the
# pipe size; see the man page for the figures.
#
# The conc=1 row is the control and says the single case did not move; its 262%
# spread says it could not have said much anyway. The rest grow apart exactly
# as the mechanism predicts -- the old arm serialises onto one pipe and pays the
# read path for the remainder.
#
# ─── WHY A PIPE PER CONNECTION AND NOT A POOL OF THEM ───────────────────────
#
# A pool needs to know which slot a completion belongs to, and the case that
# decides it is a splice completing for a connection that is already gone: with
# one shared pipe, `m_splice_busy = false` covered it, and with N there is no
# way to learn the index from the CQE. Every fix for that is an accounting
# invariant -- a per-slot in-flight count, or a side table -- and a missed
# decrement strands a slot silently.
#
# Owned by the connection, there is no index to lose. The struct is released
# through pool_release(), which the retired list only reaches once
# conn_ops_pending() is false, so the pipe is never freed while the kernel is
# still splicing into it. It also deletes the drain loop that splice_cleanup()
# carried: that existed to stop one response's leftover bytes reaching the next
# user of the shared pipe, and there is no next user now.
#
# ─── WHAT THIS FILE ASSERTS, AND WHY THOSE ──────────────────────────────────
#
# Not the speed -- that is the A/B above, and a timing assertion here would be
# a flake. What it asserts is the two things the change can break:
#
#   Bytes. Eight connections each holding their own pipe is the first time this
#   server has had more than one splice in flight at once, so each stream
#   carrying its own file exactly is the property that was never exercised.
#
#   Descriptors. A pipe is two of them, and the counter that caps them is the
#   new invariant. A leak does not show as a wrong answer -- it shows as the
#   cap filling until nothing gets the fast path again, which is invisible from
#   outside. It is visible in /proc/<worker>/fd, so that is what is measured,
#   across sequential downloads, concurrent bursts, and aborts mid-transfer.
#
# ─── WHAT THE COUNTER-PROOF SAID ABOUT THE REDUNDANCY ───────────────────────
#
# Two places give the pipe back -- splice_cleanup() at the response's end, and
# the retire path beside the file descriptor -- and that redundancy is why
# removing either ONE of them changes nothing here: this file was green, at 13
# descriptors flat, with the release taken out of splice_cleanup(). Every
# connection in it closes, so the retire path covered it.
#
# Removing BOTH is caught, and the shape of the failure is worth recording:
#
#     base 15   concurrent 29   sequential 29   aborted 29
#
# It grows by fourteen and then stops. Seven pipes at two descriptors each, and
# then MAX_CONCURRENT_SPLICE refuses the eighth -- so a leak does not run away,
# it fills the cap and quietly turns the fast path off for the rest of the
# runtime's life. That is the failure this assertion exists for, and it is the
# reason the redundancy is not an accident: there is no state in which one site
# alone leaking produces a leak, because the other one frees it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate splicedl

P=$((SL_PORT_BASE+1966))
NAMES="sd_srv"
WWW="$SOCKETLEY_TMPD/www"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

mkdir -p "$WWW"
# Eight distinct 4 MiB files. Distinct so a stream carrying another stream's
# bytes is a wrong answer and not a coincidence; 4 MiB because that is where
# splice measurably beats the read path, so this is the size the change is about.
python3 - "$WWW" <<'PYEOF'
import sys, os
w = sys.argv[1]
for k in range(8):
    open(os.path.join(w, "f%d.bin" % k), "wb").write(
        bytes(((i * 7 + k * 13) % 251) for i in range(4 << 20)))
PYEOF

echo "=== Integration: many downloads at once, each its own bytes ==="
daemon_start "$BIN"

create_ok "a static file server" "$BIN" create server sd_srv -p "$P" --http "$WWW" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

# The worker and not the daemon: the pipes are the serving process's.
WPID=$("$BIN" stats sd_srv 2>/dev/null | awk -F: '/^pid:/ {gsub(/[^0-9]/,"",$2); print $2}' | head -1)
# Pipes and sockets: the files themselves are kept open between requests, one descriptor each, and counted apart.
fds() { find "/proc/$WPID/fd" -mindepth 1 -maxdepth 1 ! -lname "$WWW/*" 2>/dev/null | wc -l; }
kept() { find "/proc/$WPID/fd" -mindepth 1 -maxdepth 1 -lname "$WWW/*" 2>/dev/null | wc -l; }

if [ -n "${WPID:-}" ] && [ -d "/proc/$WPID/fd" ]; then ok; else
    bad "the worker's descriptors can be counted" \
        "stats gave pid='${WPID:-}' and /proc/\$pid/fd is not readable -- every" \
        "descriptor assertion below would measure nothing"; fi

run_downloads() {   # $1=concurrency  $2=rounds ; prints "ok" or the first mismatch
    timeout 180 python3 - "$P" "$WWW" "$1" "$2" <<'PYEOF' 2>&1
import os, socket, sys, threading
port, www, conc, rounds = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
want = [open(os.path.join(www, "f%d.bin" % k), "rb").read() for k in range(8)]
bad = []
lock = threading.Lock()

def one(k):
    try:
        s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(60)
        s.sendall(("GET /f%d.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % k).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(65536)
            if not c: raise RuntimeError("closed in headers")
            buf += c
        body = buf.split(b"\r\n\r\n", 1)[1]
        while True:
            c = s.recv(1 << 18)
            if not c: break
            body += c
        s.close()
        if body != want[k]:
            with lock:
                bad.append("f%d: %d bytes, %s" % (
                    k, len(body),
                    "wrong length" if len(body) != len(want[k]) else "wrong bytes"))
    except Exception as e:
        with lock:
            bad.append("f%d: %s" % (k, e))

for r in range(rounds):
    ts = [threading.Thread(target=one, args=(i % 8,)) for i in range(conc)]
    for t in ts: t.start()
    for t in ts: t.join()
print(bad[0] if bad else "ok")
PYEOF
}

# ─── 1. One at a time, which is the case that always had the pipe ───────────
check "a single download is byte-exact" "ok" "$(run_downloads 1 2)"

BASE=$(fds)

# ─── 2. Eight at once, which is the case that never could be ────────────────
# More than one splice in flight at a time is new, so each stream carrying its
# own file exactly is the property under test.
check "eight concurrent downloads are each byte-exact" "ok" "$(run_downloads 8 3)"

# ─── 3. And past the count, where the read path serves the remainder ────────
# The budget bounds how many pipes exist, not how many clients are served: the
# ones that do not get a pipe take the path every connection but one used to
# take, and must be just as correct.
#
# 96 and not 16, because the count is 64 now.  This case was written against a
# cap of 8 and said "sixteen at once", which stopped reaching the fallback the
# moment the measurement moved the cap -- an assertion still passing and no
# longer testing what it names.
check "ninety-six at once are still each byte-exact" "ok" "$(run_downloads 96 1)"

# ─── 4. The descriptors come back ───────────────────────────────────────────
# The new invariant. A leak is not a wrong answer -- it is the cap filling
# until nothing takes the fast path again, which nothing outside can see.
sleep 1.5
AFTER=$(fds)
if [ "$AFTER" -le $((BASE + 4)) ]; then ok; else
    bad "descriptors return after concurrent downloads" \
        "worker held $BASE before and $AFTER after 40 downloads; a pipe is two" \
        "descriptors, so this is about $(( (AFTER - BASE) / 2 )) of them stranded"; fi

# ─── 5. And they come back one at a time as well ────────────────────────────
# Sequentially is where a leak accumulates fastest per unit of time, and it is
# also the shape a keep-alive client has.
# The downloads are judged too: sixty that all failed would leave the descriptors low as well.
SEQ_OUT=$(run_downloads 1 60)
if [ "$SEQ_OUT" = ok ]; then ok; else
    bad "sixty sequential downloads arrive whole" "$SEQ_OUT"; fi
sleep 1.5
SEQ=$(fds)
if [ "$SEQ" -le $((BASE + 4)) ]; then ok; else
    bad "descriptors return after sequential downloads" \
        "worker held $BASE before and $SEQ after 60 more; every one of those" \
        "made a pipe and something is not closing them"; fi

# ─── 6. Including when the client walks away mid-transfer ───────────────────
# The path this change touches that no ordinary request reaches: the connection
# is retired with a splice still in the ring, so the pipe cannot be freed at
# once and has to be freed by the reap instead.
ABORTS=$(timeout 90 python3 - "$P" <<'PYEOF' 2>&1
import socket, sys, time
port = int(sys.argv[1])
started = 0
for _ in range(30):
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.sendall(b"GET /f0.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    # Just enough to have the transfer running, then gone.
    try:    started += len(s.recv(4096)) > 0
    except Exception: pass
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    s.close()
    time.sleep(0.02)
print(started)
PYEOF
)
# An abort counts only once the transfer was running, or the reap below is never reached.
if [ "$ABORTS" = 30 ]; then ok; else
    bad "thirty downloads are aborted mid-transfer" "driver: ${ABORTS:-no output}"; fi
sleep 2.5
ABORTED=$(fds)
if [ "$ABORTED" -le $((BASE + 4)) ]; then ok; else
    bad "descriptors return after aborts mid-transfer" \
        "worker held $BASE before and $ABORTED after 30 aborted downloads --" \
        "the retire path is where a pipe with an op still in the ring is freed"; fi

# ─── 7. And the fast path still works afterwards ────────────────────────────
# A build that leaked would answer everything above correctly and quietly stop
# using splice; this at least establishes it is still serving.
check "the server still serves after all of it" "ok" "$(run_downloads 4 1)"
check "and the runtime is up"                   "Up" \
      "$("$BIN" ps -a 2>/dev/null | awk '$2=="sd_srv" { print $7 }')"

KEPT=$(kept)
if [ "$KEPT" -le 8 ]; then ok; else
    bad "the files are kept open one descriptor each at most" "$KEPT descriptors on 8 files"; fi

echo "  measured: worker fds base=$BASE concurrent=$AFTER sequential=$SEQ aborted=$ABORTED, files kept $KEPT"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
