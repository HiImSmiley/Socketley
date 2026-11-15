#!/usr/bin/env bash
# Integration test: a reply longer than stdio's buffer leaves the CLI in one write
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The CLI printed a daemon's reply with `std::cout << data`, and stdio hands a
# pipe anything past its 4 KiB buffer in pieces: an `ls` of 14,282 bytes went
# out as write(12288) and write(1994).  A reader that has what it wanted and
# leaves -- `grep -q`, `head -1`, `awk '... { exit }'` -- killed the CLI with
# SIGPIPE between the two, and under `set -o pipefail` the pipeline's status
# was 141: `socketley ls | grep -q name` read as a list without the name, and
# `! socketley ls | grep -q name` as one without it precisely when it was there.
# Every script that asks a long list about one line is that caller.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The reply has to be longer than 4096 bytes or the old build passes too, so
# that is checked first.  The writes are counted with strace on the CLI itself
# (a child, which needs no permission to trace), because a reader cannot tell
# one write from two that arrived before it read.  And the bytes through the
# pipe are compared with the bytes into a file, so one write that dropped the
# tail would not pass.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate onewrite

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a reply longer than stdio's buffer leaves the CLI in one write ==="
daemon_start "$BIN"

# Sixty runtimes, created and not started: nothing binds, and `ls` lists them all.
for i in $(seq 1 60); do
    "$BIN" create server "onewrite_runtime_$i" -p $((SL_PORT_BASE + i)) >/dev/null 2>&1
done

"$BIN" ls >"$SOCKETLEY_TMPD/ls.file" 2>/dev/null
SIZE=$(wc -c <"$SOCKETLEY_TMPD/ls.file")
if [ "$SIZE" -gt 4096 ]; then pass; else
    fail "the list is longer than stdio's 4 KiB buffer" "it is $SIZE bytes, and a shorter one went out in one write before too"
fi

if command -v strace >/dev/null 2>&1; then
    for verb in "ls" "ps -a"; do
        # shellcheck disable=SC2086
        strace -qq -e trace=write,writev -e signal=none -o "$SOCKETLEY_TMPD/st" "$BIN" $verb 2>/dev/null \
            | cat >"$SOCKETLEY_TMPD/ls.pipe"
        WRITES=$(grep -cE '^(write|writev)\(1,' "$SOCKETLEY_TMPD/st")
        if [ "$WRITES" -eq 1 ]; then pass; else
            fail "\`$verb\` reaches a pipe in one write" \
                "it took $WRITES, of $(grep -E '^(write|writev)\(1,' "$SOCKETLEY_TMPD/st" | grep -oE '[0-9]+$' | tr '\n' ' ')bytes"
        fi
    done
else
    echo "  SKIP: no strace, so the writes are not counted"
fi

"$BIN" ls 2>/dev/null | cat >"$SOCKETLEY_TMPD/ls.pipe"
# The CREATED column ages between the two calls ("9 seconds ago" to "1 minute ago" under a sanitizer), so the ages and
# the padding they set are left out of the comparison; a lost tail or line still shows.
age='s/[0-9]+ (second|minute|hour|day)s? ago/AGE/g; s/ +/ /g'
same_list() { cmp -s <(sed -E "$age" "$1") <(sed -E "$age" "$2"); }
if same_list "$SOCKETLEY_TMPD/ls.file" "$SOCKETLEY_TMPD/ls.pipe"; then pass; else
    fail "the list through a pipe is the list into a file" \
        "$(wc -c <"$SOCKETLEY_TMPD/ls.pipe") bytes through the pipe, $SIZE into the file"
fi

# The caller this is for: a reader that leaves at the first runtime's line.
MISSED=0
for _ in $(seq 1 50); do
    "$BIN" ls 2>/dev/null | grep -q "onewrite_runtime_1 " || MISSED=$((MISSED+1))
done
if [ "$MISSED" -eq 0 ]; then pass; else
    fail "ls | grep -q under pipefail finds the first runtime every time" "it missed $MISSED of 50"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
