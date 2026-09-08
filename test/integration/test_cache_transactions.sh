#!/usr/bin/env bash
# Integration test: MULTI / EXEC / DISCARD.
#
# What this buys is grouping, not rollback, and the difference is what the
# assertions here are shaped around.  Between MULTI and EXEC a command is text
# on a queue and nothing has happened; EXEC runs the queue back to back on an
# event loop that is single-threaded, so no other connection's command can land
# in the middle of it.  A command that fails inside EXEC fails alone -- the
# ones before it stay -- which is Redis's rule and is asserted here so nobody
# later reads "transaction" as "all or nothing".
#
# The interleaving case is the one worth having: a second connection writes
# between the MULTI and the EXEC, and its write must land BEFORE the queue,
# because the queue had not run yet.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate txn
PORT=$((SL_PORT_BASE+1420))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
eq()  { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', wanted '$3'"; fi; }

cleanup() { "$BIN" stop tc >/dev/null 2>&1; sleep 0.3
            "$BIN" remove tc >/dev/null 2>&1; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: MULTI/EXEC ==="
command -v nc >/dev/null 2>&1 || { echo "  SKIP: nc is required"; exit 0; }

daemon_start "$BIN"
"$BIN" create cache tc -p "$PORT" -s >/dev/null 2>&1

pt()  { printf '%s\n' "$1" | timeout 3 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | tr '\n' '|'; }
# One connection carrying several lines, which is the only way to test this:
# the queue lives on the connection and a second one has none.
conv() { printf '%b' "$1" | timeout 5 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | tr '\n' '|'; }

for i in $(seq 1 60); do [ -n "$(pt 'size')" ] && break; sleep 0.2; done
if [ -n "$(pt 'size')" ]; then ok; else
    bad "the cache answers" "nothing on $PORT"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi

eq "a queued command answers queued, then EXEC runs them" \
   "$(conv 'multi\nset a 1\nincrby a 5\nexec\n')" "ok|queued|queued|ok|6|end|"
eq "and the writes are there afterwards" "$(pt 'get a')" "6|"

eq "DISCARD answers ok"      "$(conv 'multi\nset d weg\ndiscard\n')" "ok|queued|ok|"
eq "and nothing was written" "$(pt 'get d')" "nil|"

eq "EXEC without MULTI is refused"    "$(conv 'exec\n')"          "error: EXEC without MULTI|"
eq "DISCARD without MULTI is refused" "$(conv 'discard\n')"       "error: DISCARD without MULTI|"
eq "MULTI inside MULTI is refused"    "$(conv 'multi\nmulti\n')"  "ok|error: MULTI nested|"

# Nothing happens until EXEC: the queue is checked from a SECOND connection,
# which is the only observer that cannot be fooled by the first one's buffer.
printf 'multi\nset later yes\n' | timeout 3 nc -q1 127.0.0.1 "$PORT" >/dev/null 2>&1
eq "a queued write has not happened" "$(pt 'get later')" "nil|"

# A failing command inside EXEC fails alone -- stated, because "transaction"
# invites the other reading.
eq "one bad command does not undo the good ones" \
   "$(conv 'multi\nset t1 a\nquatsch\nset t2 b\nexec\n')" \
   "ok|queued|queued|queued|ok|failed: unknown command|ok|end|"
eq "the write before it stayed" "$(pt 'get t1')" "a|"
eq "and the write after it ran" "$(pt 'get t2')" "b|"

# A connection that dies mid-transaction takes its queue with it.
printf 'multi\nset ghost yes\n' | timeout 2 nc -q1 127.0.0.1 "$PORT" >/dev/null 2>&1
sleep 0.3
eq "a dropped connection runs nothing" "$(pt 'get ghost')" "nil|"

# ── RESP ────────────────────────────────────────────────────────────────────
if command -v redis-cli >/dev/null 2>&1; then
    OUT=$(printf 'MULTI\nSET r1 x\nINCRBY n 3\nEXEC\n' | redis-cli -p "$PORT" 2>&1 | tr '\n' '|')
    eq "RESP: OK, QUEUED, QUEUED, then the replies" "$OUT" "OK|QUEUED|QUEUED|OK|3|"
    eq "RESP: the write landed" "$(redis-cli -p "$PORT" GET r1 2>&1 | tr '\n' '|')" "x|"

    # The array header is the part a client parses, so it is asserted on the
    # wire rather than through redis-cli's rendering of it.
    RAW=$(printf '*1\r\n$5\r\nMULTI\r\n*3\r\n$3\r\nSET\r\n$2\r\nrw\r\n$1\r\nv\r\n*2\r\n$3\r\nGET\r\n$2\r\nrw\r\n*1\r\n$4\r\nEXEC\r\n' \
          | timeout 3 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | tr '\n' '|')
    eq "RESP: EXEC answers one array of two" "$RAW" "+OK|+QUEUED|+QUEUED|*2|+OK|\$1|v|"

    OUT=$(printf 'MULTI\nDISCARD\nEXEC\n' | redis-cli -p "$PORT" 2>&1 | tr '\n' '|')
    case "$OUT" in "OK|OK|"*"without MULTI"*) ok ;; *) bad "RESP: DISCARD then EXEC" "got '$OUT'" ;; esac

    # ── RESET, which is why a pooling client can reuse a socket ──────────────
    #
    # RESET has to run INSIDE a transaction, where every other command is
    # queued.  That is the whole point of it: a client returning a connection
    # to its pool sends RESET precisely because it does not know what state the
    # connection is in, and if a stray MULTI is that state then queueing the
    # one command meant to clear it files it behind the mess.  Checked on the
    # wire because the ORDER of the replies is the assertion -- +RESET has to
    # arrive before EXEC is refused, not after it.
    RAW=$(printf '*1\r\n$5\r\nMULTI\r\n*3\r\n$3\r\nSET\r\n$2\r\nrq\r\n$1\r\n1\r\n*1\r\n$5\r\nRESET\r\n*1\r\n$4\r\nEXEC\r\n' \
          | timeout 3 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | tr '\n' '|')
    case "$RAW" in "+OK|+QUEUED|+RESET|-ERR"*) ok ;;
        *) bad "RESP: RESET runs inside MULTI and discards it" "got '$RAW'" ;; esac
    eq "RESP: and the queued write never happened" \
       "$(redis-cli -p "$PORT" GET rq 2>&1 | tr '\n' '|')" "|"

    # A subscription is session state too, and a connection still holding one
    # is not a fresh one.
    RAW=$(printf '*2\r\n$9\r\nSUBSCRIBE\r\n$2\r\nch\r\n*1\r\n$5\r\nRESET\r\n*2\r\n$3\r\nGET\r\n$2\r\nrq\r\n' \
          | timeout 3 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | tr '\n' '|')
    case "$RAW" in *"+RESET|"*'$-1'*) ok ;;
        *) bad "RESP: RESET leaves subscribe mode" "got '$RAW'" ;; esac

    # QUIT is what every client library sends when it drops a connection, and
    # it was answered "unknown command".  The +OK has to reach the wire BEFORE
    # the close -- a connection marked closing has its buffer dropped, which is
    # the shape that silenced every protocol error.
    RAW=$(printf '*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nQUIT\r\n' \
          | timeout 3 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | tr '\n' '|')
    eq "RESP: QUIT is answered and then closes" "$RAW" "+PONG|+OK|"
else
    echo "  (redis-cli absent — the RESP arm did not run)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
