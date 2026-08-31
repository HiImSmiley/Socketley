#!/usr/bin/env bash
# Integration test: `socketley <cache> <verb>` runs where the cache is.
#
# Every verb under `<name> <verb>` was a direct call on the instance the daemon
# holds.  That was right while a runtime could live in the daemon and has been
# wrong since 7144417e moved every one of them into a worker: the object left
# in the daemon is a placeholder, so
#
#   socketley c set k v      wrote a store no client can read
#   socketley c get k        read that store back and agreed with itself
#   socketley c flush        saved it OVER the dump the real keys were in
#
# Two wrong answers that match, which is why no test caught it: a file that
# writes and reads through the CLI alone is consistent and empty.  So every
# assertion here crosses the two routes -- write on one, read on the other.
#
# The flush case is the one with teeth.  Measured on the parent commit: a
# 101-byte dump holding five keys became 4 bytes, and the keys lived on only in
# the worker's memory until the next crash.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cliworker
PORT=$((SL_PORT_BASE+1400))
DUMP="$SOCKETLEY_TMPD/c.rdb"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
eq()  { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', wanted '$3'"; fi; }

cleanup() { "$BIN" stop cw >/dev/null 2>&1; sleep 0.3
            "$BIN" remove cw >/dev/null 2>&1; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a CLI cache command runs where the cache is ==="

command -v nc >/dev/null 2>&1 || { echo "  SKIP: nc is required"; exit 0; }

daemon_start "$BIN"
"$BIN" create cache cw -p "$PORT" --persistent "$DUMP" --mode admin -s >/dev/null 2>&1

port() { printf '%s\n' "$1" | timeout 3 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | head -1; }

for i in $(seq 1 60); do [ "$(port "size")" != "" ] && break; sleep 0.2; done
if [ -n "$(port "size")" ]; then ok; else
    bad "the cache answers on its port" "no reply to size on $PORT"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi

# ── The crossing, both ways ─────────────────────────────────────────────────
"$BIN" cw set viacli cv >/dev/null 2>&1
eq "a CLI write is visible on the port" "$(port 'get viacli')" "cv"

port 'set viaport pv' >/dev/null
eq "a port write is visible from the CLI" "$("$BIN" cw get viaport | tr -d '\r\n')" "pv"

# Every family, because the twenty verbs were twenty separate calls and a fix
# that funnelled only the string ones would pass the two assertions above.
"$BIN" cw lpush L x  >/dev/null 2>&1
"$BIN" cw sadd  S m  >/dev/null 2>&1
"$BIN" cw hset  H f v >/dev/null 2>&1
"$BIN" cw zadd  Z 5 q >/dev/null 2>&1
eq "a CLI list write is on the port"   "$(port 'llen L')"     "1"
eq "a CLI set write is on the port"    "$(port 'scard S')"    "1"
eq "a CLI hash write is on the port"   "$(port 'hget H f')"   "v"
eq "a CLI zset write is on the port"   "$(port 'zscore Z q')" "5"

# ── Success is still silent ─────────────────────────────────────────────────
# The port answers `ok` to a mutation and this CLI does not print that, so the
# reply has to be mapped rather than passed through.
OUT=$("$BIN" cw set quiet 1 2>&1)
if [ -z "$OUT" ]; then ok; else bad "a successful CLI mutation prints nothing" "printed '$OUT'"; fi

RC=0; OUT=$("$BIN" cw quatsch k 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && printf '%s' "$OUT" | grep -q "unknown action: quatsch"; then ok; else
    bad "an unknown verb still names itself" "exit $RC, said '$OUT'"
fi

RC=0; OUT=$("$BIN" cw set 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && printf '%s' "$OUT" | grep -q "usage:"; then ok; else
    bad "a missing argument is refused" "exit $RC, said '$OUT'"
fi

# `memory` is half configuration the daemon holds and half a figure only the
# worker has, so it is the one verb finished on both sides.
MEM=$("$BIN" cw memory 2>&1 | tr -d '\r\n')
if printf '%s' "$MEM" | grep -qE '^[0-9]+ [0-9]+$'; then ok; else
    bad "memory keeps its two-number form" "got '$MEM'"
fi

# ── flush, the one that destroyed data ──────────────────────────────────────
# Content and not size: with the CLI writing into the placeholder the dump is
# not empty, it is full of the WRONG keys -- the ones typed at the CLI -- so a
# size check passes against the defect.  These five exist only in the worker.
for k in a b c d e; do port "set $k onlyport$k" >/dev/null; done
"$BIN" cw flush >/dev/null 2>&1
sleep 0.4
if grep -qa "onlyportd" "$DUMP" 2>/dev/null; then ok; else
    bad "a CLI flush saves the worker's keys" \
        "the dump ($(stat -c%s "$DUMP" 2>/dev/null || echo 0) bytes) does not hold a key only the worker has"
fi

# And read back, after a kill rather than a stop: a clean stop makes the worker
# write its own dump, which would repair the file this case is about.
PIDS=$("$BIN" stats cw 2>/dev/null | grep -oP 'pid[s]?:\s*\K[0-9 ,]+' | tr ',' ' ')
for p in $PIDS; do
    grep -qa 'socketley' "/proc/$p/cmdline" 2>/dev/null && kill -9 "$p" 2>/dev/null
done
sleep 1
"$BIN" stop cw >/dev/null 2>&1; sleep 0.5
"$BIN" start cw >/dev/null 2>&1
for i in $(seq 1 60); do [ "$(port "size")" != "" ] && break; sleep 0.2; done
eq "the flushed dump comes back with the worker's keys" "$(port 'get c')" "onlyportc"

# ── An unknown first word ───────────────────────────────────────────────────
# `socketley stpo cw` answered "runtime not found: stpo" and sent the reader
# looking for a runtime nobody meant.
RC=0; OUT=$("$BIN" stpo cw 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && printf '%s' "$OUT" | grep -q "unknown command: stpo"; then ok; else
    bad "a mistyped command names itself" "exit $RC, said '$(printf '%s' "$OUT" | head -1)'"
fi
if printf '%s' "$OUT" | grep -q "is a runtime"; then ok; else
    bad "the message names the other reading too" "said '$(printf '%s' "$OUT" | head -2)'"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
