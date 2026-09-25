#!/usr/bin/env bash
# Integration test: a value too large is told so, and the bound is a knob.
#
# ─── THE ARGUMENT THIS TREE ALREADY MADE, AT ONE OF TWO SITES ───────────────
#
# resp_parser.h says it, eight lines above the constant:
#
#     "too_many_args is separated from error because the two need different
#      words: one says the stream is no longer framed, the other says this
#      command had more arguments than we accept and the next one would have
#      been fine. A client told "protocol error" for an over-long DEL
#      reconnects and sends it again."
#
# That reasoning produced a distinct parse_result for the ARRAY-SIZE cap. The
# BULK-LENGTH cap beside it was left on the error path, so a perfectly framed
# `SET key <600 KB>` was refused as a protocol error. Measured:
#
#     SET a hi                      -> +OK
#     SET b <600KB>                 -> -ERR protocol error
#     GET a  (same connection)      -> <closed>
#
# Both halves wrong for this cause. The length parsed cleanly; it was simply
# larger than this build accepts. And a client library reading "protocol error"
# concludes its own framing is broken, reconnects, and sends the same oversized
# value again -- the exact loop that comment describes, made certain here
# because the connection dies too.
#
# The connection still closes, which is what Redis does for a bulk length it
# will not take: the body was never read, so there is no framed position to
# continue from. What changes is that the client is told which wall it met.
#
# ─── AND THE NUMBER, WHICH WAS NOT ADJUSTABLE ───────────────────────────────
#
# The real ceiling was 512 KB -- RESP_MAX_BULK_LEN -- against Redis's default
# proto-max-bulk-len of 512 MB, a factor of 1024. MAX_PARTIAL_SIZE, the inbound
# accumulation bound, was 1 MiB, repeated as a constexpr in all four runtimes.
#
# Those two were already exactly 2:1, so --read-buffer names a halving that
# existed rather than introducing one: the accumulation bound is the buffer and
# the largest single value inside it is half, which leaves room for the framing
# around it. The default reproduces both old numbers exactly.
#
# ─── THE REFUSAL ARRIVES HOWEVER FAR PAST THE LIMIT ─────────────────────────
#
# The refusal used to be written and the connection closed at once, and a
# client still sending got an RST that Linux uses to discard the queued answer:
# read at 600 KB to 2 MB of overshoot, lost at 4 MB, and lost at 150 kB inside
# the suite once load moved the race.  The cache now sends its FIN behind the
# answer and reads the rest out of the way until the client's own EOF, the
# server's maybe_shutdown_write() -- so every case below expects the refusal,
# and RST is a failure.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate readbuffer

P_DEF=$((SL_PORT_BASE+1968))
P_BIG=$((SL_PORT_BASE+1970))
P_SRV=$((SL_PORT_BASE+1972))
NAMES="rb_def rb_big rb_srv"

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

echo "=== Integration: a value too large says so, and the bound is a knob ==="
daemon_start "$BIN"

f() { "$BIN" show "$1" 2>/dev/null | sed -n 's/^ *"read_buffer": *\([0-9]*\).*/\1/p' | head -1; }

# One RESP driver for every case, so the difference between them is the runtime.
resp() {   # $1=port $2=value-bytes ; prints the reply, or a named transport end
    timeout 60 python3 - "$1" "$2" <<'PYEOF' 2>/dev/null || true
import socket, sys
port, n = int(sys.argv[1]), int(sys.argv[2])
v = b"z" * n
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(20)
try:
    s.sendall(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n" + b"$" + str(len(v)).encode() + b"\r\n" + v + b"\r\n")
    r = s.recv(400)
    print(r.decode(errors="replace").strip() if r else "CLOSED")
except BrokenPipeError:
    print("RST")
except ConnectionResetError:
    print("RST")
except Exception as e:
    print("ERR:%s" % type(e).__name__)
finally:
    s.close()
PYEOF
}

create_ok "a cache with the default bound" "$BIN" create cache rb_def -p "$P_DEF" -s
create_ok "and one with a large one"       "$BIN" create cache rb_big -p "$P_BIG" \
    --read-buffer 8M -s
ready_tcp 127.0.0.1 "$P_DEF" >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_BIG" >/dev/null 2>&1 || true

# ─── 1. At the limit, and past it ───────────────────────────────────────────
check "a value at the limit is stored" "+OK" "$(resp "$P_DEF" 524288)"

# Eight times the limit, which lost the refusal to an RST every time.
RFAR=$(resp "$P_DEF" 4194304)
case "$RFAR" in
    *"larger than this cache accepts"*) ok ;;
    *) bad "a value eight times the limit still reads the refusal" "got '$RFAR'" \
           "-- RST is the close resetting the answer out of the client's queue" ;;
esac

R=$(resp "$P_DEF" 614400)
case "$R" in
    *"larger than this cache accepts"*) ok ;;
    *"protocol error"*)
        bad "a value past the limit names the limit" \
            "it said 'protocol error' for a perfectly framed command, which is" \
            "what makes a client reconnect and send the same value again" ;;
    *) bad "a value past the limit names the limit" "got '$R'" ;;
esac
# The number in it, because "too large" without one leaves the caller guessing
# what to send instead.
case "$R" in *524288*) ok ;;
    *) bad "and says what the limit is" "got '$R'" ;; esac

# ─── 2. And a genuinely broken frame still says so ──────────────────────────
# The split is the point. A build that renamed every refusal would pass case 1
# and lose the one word that means "the stream is gone".
BROKEN=$(timeout 30 python3 - "$P_DEF" <<'PYEOF' 2>/dev/null || true
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(10)
s.sendall(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$abc\r\nv\r\n")
try:    print(s.recv(300).decode(errors="replace").strip())
except Exception: print("CLOSED")
s.close()
PYEOF
)
case "$BROKEN" in *"protocol error"*) ok ;;
    *) bad "a malformed length is still a protocol error" \
           "got '$BROKEN' -- a length that does not parse really is broken framing" ;; esac

# ─── 3. The knob moves it ───────────────────────────────────────────────────
check "the large cache takes 600 KB"  "+OK" "$(resp "$P_BIG" 614400)"
check "and takes 3 MB"                "+OK" "$(resp "$P_BIG" 3145728)"

# ─── 4. And the derived limit is half the buffer ────────────────────────────
# 8 MiB in, so 4 MiB of value; the refusal has to name the runtime's own number
# and not the constant it used to be compiled with.
RB=$(resp "$P_BIG" 5242880)
case "$RB" in
    *4194304*) ok ;;
    *524288*) bad "the large cache names its own limit" \
                  "it named 524288, the old constant, so the refusal is not" \
                  "reading this runtime's bound" ;;
    *) bad "the large cache names its own limit" "got '$RB'" ;;
esac

# ─── 5. show, the floor, and a value that is not a size ─────────────────────
check "the configured bound is in show" "8388608" "$(f rb_big)"
if [ -z "$(f rb_def)" ]; then ok; else
    bad "and a default runtime's record is unchanged" \
        "show printed read_buffer=$(f rb_def) for a runtime nobody configured"; fi

"$BIN" edit rb_big --read-buffer 1K >/dev/null 2>&1 || true
check "a bound below one ordinary document is floored" "65536" "$(f rb_big)"

RC=0; OUT=$("$BIN" edit rb_big --read-buffer banana 2>&1) || RC=$?
check "a non-size value is refused" "1" "$RC"
case "$OUT" in *"K/M/G"*) ok ;;
    *) bad "and says what a size looks like" "got '$OUT'" ;; esac

# ─── 6. A live edit reaches the running cache ───────────────────────────────
# Nothing caches the derived limit -- it is asked at each parse -- so this must
# take without a restart.
"$BIN" edit rb_big --read-buffer 2M >/dev/null 2>&1 || true
check "the record moved" "2097152" "$(f rb_big)"
# 2 MiB in, so 1048576 of value. Both sides of that number, because the
# first draft of these two put 1.5 MB on the "inside" side and was told so:
# the code was right and the arithmetic here was not.
RL=$(resp "$P_BIG" 1000000)
check "a value inside the new bound is stored" "+OK" "$RL"
RL2=$(resp "$P_BIG" 1200000)
case "$RL2" in
    *"larger than this cache accepts"*1048576*) ok ;;
    *524288*|*4194304*)
        bad "and one past it is refused with the NEW number" \
            "got '$RL2' -- that is a limit from before the edit, so the derived" \
            "number is being cached instead of read at each parse" ;;
    *) bad "and one past it is refused with the NEW number" "got '$RL2'" ;;
esac

# ─── 7. show/import round trip ──────────────────────────────────────────────
"$BIN" show rb_big > "$SOCKETLEY_TMPD/rb.json" 2>/dev/null
"$BIN" import rb_big < "$SOCKETLEY_TMPD/rb.json" >/dev/null 2>&1 || true
check "a round trip through show/import keeps it" "2097152" "$(f rb_big)"

# ─── 8. The other runtimes share the knob ───────────────────────────────────
# It is not a cache setting: MAX_PARTIAL_SIZE was a constexpr in all four, so
# the bound it replaces governs an HTTP body as much as a RESP value.
create_ok "a server with a large bound" "$BIN" create server rb_srv -p "$P_SRV" \
    --read-buffer 4M --http "$SOCKETLEY_TMPD" -s
ready_tcp 127.0.0.1 "$P_SRV" >/dev/null 2>&1 || true
POST=$(timeout 60 python3 - "$P_SRV" <<'PYEOF' 2>/dev/null || true
import socket, sys
# 2 MB: past the old 1 MiB bound, inside the configured 4 MiB one.
body = b"p" * (2 * 1024 * 1024)
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(20)
try:
    s.sendall(("POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % len(body)).encode() + body)
    r = s.recv(200)
    print(r.split(b"\r\n")[0].decode(errors="replace") if r else "CLOSED")
except Exception as e:
    print("ERR:%s" % type(e).__name__)
finally:
    s.close()
PYEOF
)
case "$POST" in
    *413*) bad "a 2 MB body is inside a 4 MiB bound" \
               "answered 413, so the server is still comparing against the old" \
               "1 MiB constant rather than its configured bound" ;;
    "") bad "the server answered the post at all" "no reply" ;;
    *) ok ;;
esac

echo "  measured: default refusal=[$R] large=[$RB] post=[$POST]"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
