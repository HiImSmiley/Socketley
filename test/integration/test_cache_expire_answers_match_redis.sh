#!/usr/bin/env bash
# Integration test: what EXPIRE answers about a key that is not there, and
# what it does with a deadline that has already passed
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# Two answers a client believes, in the four spellings of one command.
#
#   EXPIREAT/PEXPIREAT ANSWERED 1 FOR A KEY THAT WAS NEVER THERE.  The
#   already-past branch called m_store.del() and threw the return value away,
#   so `EXPIREAT ghost 1` reported success for a name the cache had never
#   heard, and replicated that to every follower and into the journal.  Redis
#   answers 0.  A caller using EXPIREAT as a compare-and-delete read 1 as "it
#   was mine and now it is gone".
#
#   EXPIRE key 0 AND EXPIRE key -1 WERE ERRORS.  Redis deletes the key and
#   answers 1.  Every TTL that is computed rather than typed eventually comes
#   out at zero -- a deadline reached, a clamp -- and this cache answered
#   "error: invalid seconds" and LEFT THE KEY, so the caller was told its
#   delete failed and the key stayed.
#
#   And one more found by reading the same lines: `EXPIREAT k
#   -9223372036854775808` overflowed `unix_s - now_s`, the wrap came out
#   POSITIVE, and the key a client asked to delete was given a deadline 292
#   years out instead.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
# Reply AND effect, every time: 1 with the key gone, or 0 with nothing
# touched.  Asserting only the reply passes on a cache that answers correctly
# and deletes nothing; asserting only the effect passes on one that deletes
# and lies about it.
#
# Plus the replication half, measured rather than read off the path: with a
# journal open, a refused EXPIREAT must not leave the ghost key's name in it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate expireanswers
PORT=$((SL_PORT_BASE+185))
WORK=$(mktemp -d)
DUMP="$WORK/e.rdb"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop ea 2>/dev/null || true
    "$BIN" remove ea 2>/dev/null || true
    rm -rf "$WORK"
    daemon_stop
}
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

"$BIN" create cache ea -p "$PORT" --persistent "$DUMP" --persistent-interval 1s >/dev/null
"$BIN" start ea >/dev/null
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
MIN = b"-9223372036854775808"

# ── a key that is not there, through all four spellings ──────────────────
print("ghost_expireat="   + cmd(b"EXPIREAT",  b"ghost1", b"1"))
print("ghost_pexpireat="  + cmd(b"PEXPIREAT", b"ghost2", b"1"))
print("ghost_expire0="    + cmd(b"EXPIRE",    b"ghost3", b"0"))
print("ghost_pexpire0="   + cmd(b"PEXPIRE",   b"ghost4", b"0"))
# The future branch was already right; it is here so the fix is not read as
# "EXPIREAT now always says 0".
print("ghost_future="     + cmd(b"EXPIREAT",  b"ghost5", b"99999999999"))

# ── a deadline already passed deletes, and says so ───────────────────────
for name, args in ((b"d1", (b"EXPIRE",    b"d1", b"0")),
                   (b"d2", (b"EXPIRE",    b"d2", b"-1")),
                   (b"d3", (b"PEXPIRE",   b"d3", b"0")),
                   (b"d4", (b"EXPIREAT",  b"d4", b"1")),
                   (b"d5", (b"PEXPIREAT", b"d5", b"1")),
                   (b"d6", (b"EXPIREAT",  b"d6", MIN)),
                   (b"d7", (b"PEXPIREAT", b"d7", MIN))):
    cmd(b"SET", name, b"v")
    n = name.decode()
    print("%s_said=%s" % (n, cmd(*args)))
    print("%s_gone=%s" % (n, cmd(b"EXISTS", name)))

# ── the control: an ordinary deadline is still a deadline ────────────────
cmd(b"SET", b"keep", b"v")
print("keep_said="  + cmd(b"EXPIRE", b"keep", b"600"))
print("keep_value=" + cmd(b"GET", b"keep").split("\r\n")[-1])
print("keep_ttl="   + ("yes" if cmd(b"TTL", b"keep") in (":600", ":599") else cmd(b"TTL", b"keep")))
cmd(b"SET", b"keep2", b"v")
print("keep2_said=" + cmd(b"EXPIREAT", b"keep2", b"99999999999"))
print("keep2_value=" + cmd(b"GET", b"keep2").split("\r\n")[-1])
print("alive=" + ("yes" if cmd(b"PING") == "+PONG" else "no"))
PY
)
for k in ghost_expireat::0 ghost_pexpireat::0 ghost_expire0::0 ghost_pexpire0::0 ghost_future::0 \
         d1_said::1 d1_gone::0 d2_said::1 d2_gone::0 d3_said::1 d3_gone::0 \
         d4_said::1 d4_gone::0 d5_said::1 d5_gone::0 d6_said::1 d6_gone::0 d7_said::1 d7_gone::0 \
         keep_said::1 keep_value:v keep_ttl:yes keep2_said::1 keep2_value:v alive:yes; do
    want=${k#*:}; key=${k%%:*}
    ok "$(echo "$OUT" | sed -n "s/^$key=//p")" "$want" "resp $key"
done

# ── the replication half, on disk ────────────────────────────────────────
# journal_mutation rewrites expire/pexpire to pexpireat but leaves the *at
# spellings verbatim, so both ghost names are searched for literally.  The
# journal is the same chokepoint the followers are fed from: what is not in
# here was not sent to them either.  -a because the records carry binary
# headers and -o because one "line" of this file is most of it.  -i because
# repl() joins the client's own argv and the RESP client above shouts.
sleep 1.6
jcount() { grep -aio "$1" "$DUMP.journal" 2>/dev/null | wc -l; }
ok "$(jcount 'expireat ghost1')"  "0" "a ghost EXPIREAT is not journalled"
ok "$(jcount 'pexpireat ghost2')" "0" "a ghost PEXPIREAT is not journalled"
# The control for the control: a real deletion IS journalled, so a build that
# simply stopped journalling would not pass the two above.
ok "$(jcount 'expireat d4')"      "1" "a real EXPIREAT deletion is journalled"

# ── the text protocol, same store, different interpreter ─────────────────
# The whole transcript rather than counted lines, because a count of "ok"s is
# the same number for several different wrong answers.  `get` is the liveness
# probe: this interpreter has no ping.
#
# expireat/pexpireat answer 1/0 here and expire answers ok/nil -- the man
# page's split between the two families, which is kept.
TXT=$(printf 'set alive yes\nexpireat tghost 1\npexpireat tghost2 1\nexpire tghost3 0\nset t1 v\nexpire t1 0\nget t1\nset t2 v\npexpire t2 0\nget t2\nset t3 v\nexpireat t3 1\nget t3\nset t4 v\nexpireat t4 -9223372036854775808\nget t4\nset t5 v\nexpire t5 600\nget t5\nget alive\n' \
      | timeout 10 nc -q 2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | paste -sd'|' - || true)
WANT='ok|0|0|nil|ok|ok|nil|ok|1|nil|ok|1|nil|ok|1|nil|ok|ok|v|yes'
ok "$TXT" "$WANT" "text protocol: the whole transcript, reply by reply"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
