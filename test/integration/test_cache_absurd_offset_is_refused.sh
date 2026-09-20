#!/usr/bin/env bash
# Integration test: an offset no allocation can serve is refused, not thrown at
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# `SETRANGE k 9223372036854775807 x` computed its result length from the
# client's offset and handed it to std::string, which raises length_error above
# max_size().  Nothing between cache_store and main() catches, so the worker
# called std::terminate: one command, from any client that could reach the
# port, and every connection on that process went with it.  The cache has no
# password mechanism, so there was nothing in front of it either.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
# Two things, because only the pair distinguishes the fix from a quieter
# version of the same failure:
#   1. the command is ANSWERED, and with a reason rather than silence
#   2. the SAME connection still serves afterwards -- PING is the instrument,
#      because a dead worker cannot answer it and a live one cannot fail to
#   Asserting only (1) would pass on a worker that answered and then died; only
#   (2) would pass on one that dropped the command on the floor.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate absurdoffset
PORT=$((SL_PORT_BASE+171))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop ao 2>/dev/null || true
    "$BIN" remove ao 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

"$BIN" create cache ao -p "$PORT" >/dev/null
"$BIN" start ao >/dev/null
for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done

OUT=$(python3 - "$PORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(6)
def cmd(*a):
    # The send is inside the guard as well.  A worker that died on the PREVIOUS
    # command makes this one raise BrokenPipeError, and an uncaught one ends the
    # script with a traceback -- a test that goes red without naming what broke,
    # which is the same as a test that cannot be read.
    try:
        s.sendall(b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a))
        return s.recv(400).decode("latin1").strip()
    except Exception:
        return "<silence>"
cmd(b"SET", b"k", b"v")
# INT64_MAX: above max_size(), which is the constructor's own refusal point.
print("resp_answer=" + ("error" if cmd(b"SETRANGE", b"k", b"9223372036854775807", b"x").startswith("-") else "not-an-error"))
print("resp_alive="  + ("yes" if cmd(b"PING") == "+PONG" else "no"))
# 2^63: the same number one higher, which wraps offset+size() to a small value.
print("wrap_answer=" + ("error" if cmd(b"SETRANGE", b"k", b"18446744073709551615", b"xy").startswith("-") else "not-an-error"))
print("wrap_alive="  + ("yes" if cmd(b"PING") == "+PONG" else "no"))
# A modest offset must keep working -- the guard must refuse absurdity, not padding.
cmd(b"SETRANGE", b"k", b"10", b"tail")
print("sane_ok=" + ("yes" if cmd(b"GET", b"k").startswith("$14") else "no"))
PY
)
for k in resp_answer:error resp_alive:yes wrap_answer:error wrap_alive:yes sane_ok:yes; do
    want=${k#*:}; key=${k%%:*}
    ok "$(echo "$OUT" | sed -n "s/^$key=//p")" "$want" "$key"
done

# The text protocol reaches the same store through a different interpreter.
#
# `get` is the liveness probe and not `ping`, because the text interpreter has
# no ping -- it answers "failed: unknown command", which would have made this
# assertion fail for a reason that has nothing to do with the worker being up.
TXT=$(printf 'set a b\nsetrange tk 9223372036854775807 x\nget a\n' \
      | timeout 10 nc -q 2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' || true)
ok "$(echo "$TXT" | grep -c 'exceeds maximum allowed size')" "1" "text protocol says why"
ok "$(echo "$TXT" | tail -1)" "b" "text protocol still serves after it"
# The refusal must END the line.  It did not: the length was hand-counted one
# short, the newline was cut, and the next reply ran into the back of it --
# which is a parse error for every client that reads this protocol by line.
ok "$(echo "$TXT" | grep -c '^error: string exceeds maximum allowed size$')" "1" \
   "the refusal is a line of its own"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
