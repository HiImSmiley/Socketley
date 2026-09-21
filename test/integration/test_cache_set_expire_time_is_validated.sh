#!/usr/bin/env bash
# Integration test: SET .. EX 0 writes nothing and says so
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# `SET k v EX 0` parsed the zero, skipped the deadline because the write was
# guarded by `if (ex_sec > 0)` with no else, stored the key, and answered +OK.
# So the key was there WITHOUT a deadline and the caller had been told it
# worked -- a lock or a session whose TTL its owner computed down to zero
# became immortal, and nothing anywhere said so.  `EX -1` and `PX 0` were the
# same line.  Redis refuses all three and writes nothing.
#
# `SET k v EX abc` answered "syntax error", which names the wrong thing: the
# option was fine and its argument was not.  The parse failure left the number
# unconsumed, so the loop met it as an option on the next turn and refused THAT.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
# The refusal and its absence of effect, together: TTL -2 means the key is not
# there at all, which is the half that separates "refused" from "refused after
# writing".  And for an existing key, that the refusal did not overwrite it --
# the shape a lock refresh actually has.
#
# Only one interpreter can reach this: the line protocol's `set` takes a value
# and nothing else, so there is no EX to give it.  A check with the text
# protocol is here anyway, asserting exactly that -- if `set` ever grows
# options there, this assertion is what notices.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate setexpire
PORT=$((SL_PORT_BASE+186))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop se 2>/dev/null || true
    "$BIN" remove se 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

"$BIN" create cache se -p "$PORT" >/dev/null
"$BIN" start se >/dev/null
for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done

OUT=$(python3 - "$PORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(6)
def cmd(*a):
    try:
        s.sendall(b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a))
        return s.recv(4000).decode("latin1").strip()
    except Exception:
        return "<silence>"
def bad(r): return "yes" if r == "-ERR invalid expire time in 'set' command" else r

# Refused, and -- the half that matters -- nothing written.  TTL -2 is "no
# such key"; TTL -1 would be the defect exactly: stored, and immortal.
for n, (k, opt, val) in enumerate((("z1", b"EX", b"0"), ("z2", b"EX", b"-1"),
                                   ("z3", b"PX", b"0"), ("z4", b"PX", b"-1000"))):
    print("%s_said=%s" % (k, bad(cmd(b"SET", k.encode(), b"v", opt, val))))
    print("%s_ttl=%s"  % (k, cmd(b"TTL", k.encode())))

# An existing key is not overwritten by a refused write, which is the shape a
# lock refresh has: the old value and the old deadline both survive.
cmd(b"SET", b"lock", b"owner-a", b"EX", b"600")
print("lock_said="  + bad(cmd(b"SET", b"lock", b"owner-b", b"EX", b"0")))
print("lock_value=" + cmd(b"GET", b"lock").split("\r\n")[-1])
print("lock_ttl="   + ("yes" if cmd(b"TTL", b"lock") in (":600", ":599") else cmd(b"TTL", b"lock")))

# The argument that is not a number is refused as one.
r = cmd(b"SET", b"n1", b"v", b"EX", b"abc")
print("nan_said=" + ("yes" if r == "-ERR value is not an integer or out of range" else r))
print("nan_ttl="  + cmd(b"TTL", b"n1"))
# A missing argument is still a syntax error: the option itself is the problem.
r = cmd(b"SET", b"n2", b"v", b"EX")
print("bare_said=" + ("yes" if r == "-ERR syntax error" else r))

# The controls.  A positive deadline still arms, a plain SET still writes with
# none, and a deadline too large for the old `int` is now accepted as Redis
# accepts it instead of being called a syntax error.
print("ok_said="   + cmd(b"SET", b"g1", b"v", b"EX", b"600"))
print("ok_ttl="    + ("yes" if cmd(b"TTL", b"g1") in (":600", ":599") else cmd(b"TTL", b"g1")))
print("px_said="   + cmd(b"SET", b"g2", b"v", b"PX", b"600000"))
print("px_ttl="    + ("yes" if cmd(b"TTL", b"g2") in (":600", ":599") else cmd(b"TTL", b"g2")))
print("plain_said=" + cmd(b"SET", b"g3", b"v"))
print("plain_ttl="  + cmd(b"TTL", b"g3"))
print("huge_said="  + cmd(b"SET", b"g4", b"v", b"EX", b"9999999999"))
print("huge_ttl="   + ("yes" if int(cmd(b"TTL", b"g4").lstrip(":")) > 31536000 else "no"))
print("alive=" + ("yes" if cmd(b"PING") == "+PONG" else "no"))
PY
)
for k in z1_said:yes z1_ttl::-2 z2_said:yes z2_ttl::-2 z3_said:yes z3_ttl::-2 z4_said:yes z4_ttl::-2 \
         lock_said:yes lock_value:owner-a lock_ttl:yes \
         nan_said:yes nan_ttl::-2 bare_said:yes \
         ok_said:+OK ok_ttl:yes px_said:+OK px_ttl:yes plain_said:+OK plain_ttl::-1 \
         huge_said:+OK huge_ttl:yes alive:yes; do
    want=${k#*:}; key=${k%%:*}
    ok "$(echo "$OUT" | sed -n "s/^$key=//p")" "$want" "resp $key"
done

# The line protocol has no options on `set`, so "ex" and "0" are part of the
# VALUE.  Asserted rather than assumed: if that ever changes, the key below
# stops reading back as the whole line and this goes red.
TXT=$(printf 'set tk v ex 0\nget tk\nttl tk\n' | timeout 10 nc -q 2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | paste -sd'|' - || true)
ok "$TXT" "ok|v ex 0|-1" "text protocol: set takes no options, so ex 0 is value"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
