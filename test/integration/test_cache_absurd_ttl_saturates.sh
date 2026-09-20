#!/usr/bin/env bash
# Integration test: a deadline past the clock's range means "never", not "gone"
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# set_expiry and set_expiry_ms took the client's int64 straight into
# `now() + seconds(n)`.  steady_clock counts nanoseconds, so that multiplies by
# a billion (a million for the ms spelling) and every TTL past ~9.2e9 s or
# ~9.2e12 ms wrapped -- into the PAST.  The key a client had just asked to keep
# for as long as possible was deleted on its next touch:
#
#     SET t v ; PEXPIRE t 9223372036854775807  ->  :1
#     PTTL t                                   ->  :-1
#     GET t                                    ->  (nil)
#
# The -1 is the part worth naming: int64max milliseconds in nanoseconds is
# exactly -1000000 modulo 2^64, so the wrapped deadline read back through PTTL
# as the sentinel that means "this key has no expiry at all".
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
# For every spelling that can carry an int64 to the store -- PEXPIRE, PSETEX,
# SET .. PX, EXPIREAT, PEXPIREAT -- the triple:
#   1. the command is ACCEPTED, as Redis accepts it
#   2. the remaining TTL reads far in the future, not -1 and not a small number
#   3. the VALUE is still there after the store has had a chance to sweep it
# Plus a control on each protocol: an ordinary 100 ms TTL must still fire, or a
# build that broke expiry altogether would pass everything above.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate absurdttl
PORT=$((SL_PORT_BASE+183))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop at 2>/dev/null || true
    "$BIN" remove at 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

"$BIN" create cache at -p "$PORT" >/dev/null
"$BIN" start at >/dev/null
for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done

OUT=$(python3 - "$PORT" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(6)
def cmd(*a):
    try:
        s.sendall(b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a))
        return s.recv(4000).decode("latin1").strip()
    except Exception:
        return "<silence>"
MAX = b"9223372036854775807"
# "Far" is a year in the unit asked for, which no wrap can land on by accident
# and no honest clock can be below: -1 fails it, and so does a small positive.
def far(reply, floor):
    try: return "yes" if int(reply.lstrip(":")) > floor else reply
    except ValueError: return reply
YEAR_MS, YEAR_S = 31536000000, 31536000

for key, setter in ((b"a", (b"PEXPIRE", b"a", MAX)),
                    (b"b", (b"PEXPIREAT", b"b", MAX)),
                    (b"c", (b"EXPIREAT", b"c", MAX))):
    cmd(b"SET", key, b"v")
    print("%s_set=%s"   % (key.decode(), cmd(*setter)))
    print("%s_ttl=%s"   % (key.decode(), far(cmd(b"PTTL", key), YEAR_MS)))
    print("%s_value=%s" % (key.decode(), cmd(b"GET", key).split("\r\n")[-1]))

# The two write-with-deadline spellings, which reach the same store by a
# different door.
print("psetex_set="   + cmd(b"PSETEX", b"d", MAX, b"v"))
print("psetex_ttl="   + far(cmd(b"PTTL", b"d"), YEAR_MS))
print("psetex_value=" + cmd(b"GET", b"d").split("\r\n")[-1])
print("setpx_set="    + cmd(b"SET", b"e", b"v", b"PX", MAX))
print("setpx_ttl="    + far(cmd(b"PTTL", b"e"), YEAR_MS))
print("setpx_value="  + cmd(b"GET", b"e").split("\r\n")[-1])

# TTL and EXPIRETIME read the same saturated point through different
# arithmetic; EXPIRETIME adds it to the WALL clock, which is where narrowing to
# milliseconds first became necessary.
print("ttl_seconds=" + far(cmd(b"TTL", b"a"), YEAR_S))
print("expiretime="  + far(cmd(b"EXPIRETIME", b"a"), int(time.time())))

# The control: an ordinary deadline still fires, so a build that simply stopped
# expiring keys cannot pass the assertions above.
cmd(b"SET", b"ctl", b"v")
cmd(b"PEXPIRE", b"ctl", b"100")
time.sleep(0.4)
print("control_gone=" + ("yes" if cmd(b"GET", b"ctl") == "$-1" else cmd(b"GET", b"ctl")))
# And one that has NOT fired, so "expire everything immediately" fails too.
cmd(b"SET", b"ctl2", b"v")
cmd(b"EXPIRE", b"ctl2", b"600")
print("control_kept=" + cmd(b"GET", b"ctl2").split("\r\n")[-1])
print("alive=" + ("yes" if cmd(b"PING") == "+PONG" else "no"))
PY
)
for k in a_set::1 a_ttl:yes a_value:v b_set::1 b_ttl:yes b_value:v c_set::1 c_ttl:yes c_value:v \
         psetex_set:+OK psetex_ttl:yes psetex_value:v \
         setpx_set:+OK setpx_ttl:yes setpx_value:v \
         ttl_seconds:yes expiretime:yes \
         control_gone:yes control_kept:v alive:yes; do
    want=${k#*:}; key=${k%%:*}
    ok "$(echo "$OUT" | sed -n "s/^$key=//p")" "$want" "resp $key"
done

# The text protocol reaches the same store through a different interpreter.
# `get` is the liveness probe, not `ping`: this interpreter has no ping.
TXT=$(printf 'set alive yes\nset ta v\npexpire ta 9223372036854775807\npttl ta\nget ta\npsetex tb 9223372036854775807 v\npttl tb\nget tb\nset tc v\nexpireat tc 9223372036854775807\nttl tc\nget tc\nset tctl v\npexpire tctl 100\nget alive\n' \
      | timeout 10 nc -q 2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' || true)
# Two PTTLs and one TTL, each of which has to be a number past a year in its
# own unit.  -1 is what the wrap produced and is what this counts out.
ok "$(echo "$TXT" | awk '$0+0 > 31536000000' | wc -l)" "2" "text protocol: both pttl read far in the future"
ok "$(echo "$TXT" | awk '$0+0 > 31536000 && $0+0 < 31536000000' | wc -l)" "1" "text protocol: ttl reads far in the future"
ok "$(echo "$TXT" | grep -cE '^-[12]$')" "0" "text protocol: no deadline read back as 'none' or 'gone'"
ok "$(echo "$TXT" | grep -c '^v$')" "3" "text protocol: all three values survived"
sleep 0.4
CTL=$(printf 'get tctl\n' | timeout 10 nc -q 2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' || true)
ok "$CTL" "nil" "text protocol: an ordinary 100 ms deadline still fires"
ok "$(echo "$TXT" | tail -1)" "yes" "text protocol still serves afterwards"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
