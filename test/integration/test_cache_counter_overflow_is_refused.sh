#!/usr/bin/env bash
# Integration test: a counter that leaves int64 is refused, not wrapped
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# `INCRBY k 9223372036854775807` twice answered `:-2`.  cache_store::incr and
# ::hincrby both did `val += delta` with nothing in front of it, so the sum ran
# off the end of int64 -- undefined behaviour, and what it produced was a
# number the client has no reason to doubt.  A counter is believed: a quota
# that wrapped negative grants everything, and a sequence that wrapped hands
# out an id that is already taken.
#
# `DECRBY k -9223372036854775808` is the same family one step earlier.  Both
# interpreters passed `-delta` to incr(), and INT64_MIN has no negation in
# int64 -- so the undefined operation happened BEFORE the store was reached and
# no guard inside it could have seen the argument.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
# For every refusal, the pair:
#   1. the command is ANSWERED, with the reason Redis gives
#   2. the value is the one that was there BEFORE -- a guard that refuses after
#      writing is a guard that did not work
# Plus a control on each protocol, because "refuse everything" passes 1 and 2.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate counteroverflow
PORT=$((SL_PORT_BASE+182))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop co 2>/dev/null || true
    "$BIN" remove co 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

"$BIN" create cache co -p "$PORT" >/dev/null
"$BIN" start co >/dev/null
for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done

OUT=$(python3 - "$PORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(6)
def cmd(*a):
    # The send is guarded too: a worker that died on the PREVIOUS command makes
    # this one raise, and an uncaught raise ends the script with a traceback
    # instead of a named failure.
    try:
        s.sendall(b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a))
        return s.recv(4000).decode("latin1").strip()
    except Exception:
        return "<silence>"
MAX = b"9223372036854775807"
MIN = b"-9223372036854775808"
def over(r): return "yes" if r.startswith("-ERR increment or decrement would overflow") else r

# INCR / INCRBY off the top.
cmd(b"SET", b"c", MAX)
print("incr_refused="  + over(cmd(b"INCR", b"c")))
print("incr_kept="     + cmd(b"GET", b"c").split("\r\n")[-1])
print("incrby_refused=" + over(cmd(b"INCRBY", b"c", b"1")))

# The two-step Redis spells out: INCRBY MAX from zero is fine, twice is not.
cmd(b"SET", b"d", b"0")
print("first_max="     + cmd(b"INCRBY", b"d", MAX))
print("second_refused=" + over(cmd(b"INCRBY", b"d", MAX)))
print("second_kept="   + cmd(b"GET", b"d").split("\r\n")[-1])

# DECR / DECRBY off the bottom.
cmd(b"SET", b"e", MIN)
print("decr_refused="  + over(cmd(b"DECR", b"e")))
print("decrby_refused=" + over(cmd(b"DECRBY", b"e", b"1")))
print("decr_kept="     + cmd(b"GET", b"e").split("\r\n")[-1])

# The negation that never reached the store.
cmd(b"SET", b"f", b"0")
r = cmd(b"DECRBY", b"f", MIN)
print("negate_refused=" + ("yes" if r.startswith("-ERR decrement would overflow") else r))
print("negate_kept="   + cmd(b"GET", b"f").split("\r\n")[-1])

# A hash field is the same arithmetic in another container.
cmd(b"HSET", b"h", b"fld", MAX)
print("hincrby_refused=" + over(cmd(b"HINCRBY", b"h", b"fld", b"1")))
print("hincrby_kept="  + cmd(b"HGET", b"h", b"fld").split("\r\n")[-1])

# The control: an ordinary counter still counts, so "refuse everything" cannot
# pass the assertions above.
cmd(b"SET", b"g", b"41")
print("control="       + cmd(b"INCR", b"g"))
print("control_h="     + cmd(b"HINCRBY", b"h", b"ok", b"7"))
print("alive="         + ("yes" if cmd(b"PING") == "+PONG" else "no"))
PY
)
for k in incr_refused:yes incr_kept:9223372036854775807 incrby_refused:yes \
         first_max::9223372036854775807 second_refused:yes second_kept:9223372036854775807 \
         decr_refused:yes decrby_refused:yes decr_kept:-9223372036854775808 \
         negate_refused:yes negate_kept:0 \
         hincrby_refused:yes hincrby_kept:9223372036854775807 \
         control::42 control_h::7 alive:yes; do
    want=${k#*:}; key=${k%%:*}
    ok "$(echo "$OUT" | sed -n "s/^$key=//p")" "$want" "resp $key"
done

# The text protocol reaches the same store through a different interpreter, so
# a guard put into only one of them is half a guard.
#
# `get` is the liveness probe and not `ping`: this interpreter has no ping and
# would answer "failed: unknown command", which is a red assertion about
# something other than the worker being up.
TXT=$(printf 'set alive yes\nset c 9223372036854775807\nincr c\nget c\nincrby c 1\nset e -9223372036854775808\ndecr e\nget e\nset f 0\ndecrby f -9223372036854775808\nget f\nhset h fld 9223372036854775807\nhincrby h fld 1\nhget h fld\nset g 41\nincr g\nget alive\n' \
      | timeout 10 nc -q 2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' || true)
ok "$(echo "$TXT" | grep -c '^error: increment or decrement would overflow$')" "4" \
   "text protocol refuses all four overflows, each on a line of its own"
ok "$(echo "$TXT" | grep -c '^error: decrement would overflow$')" "1" \
   "text protocol names the negation separately"
ok "$(echo "$TXT" | grep -c '^9223372036854775807$')" "2" \
   "text protocol kept the string and the hash field unchanged"
ok "$(echo "$TXT" | grep -c '^-9223372036854775808$')" "1" \
   "text protocol kept the value at the bottom unchanged"
ok "$(echo "$TXT" | grep -c '^42$')" "1" "text protocol still counts"
ok "$(echo "$TXT" | tail -1)" "yes" "text protocol still serves afterwards"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
