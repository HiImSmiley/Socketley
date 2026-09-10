#!/usr/bin/env bash
# Integration test: -w file actually receives the messages.
#
# man socketley.1 promised "Write every received message to file". Measured
# before this fix, on a private daemon:
#
#     create server s -p P -w /tmp/rx.log   -> exit 0, nothing printed
#     show s                                -> "write_file": "/tmp/rx.log"
#     three messages through P              -> the file does not exist
#
# The whole life of the value was:
#
#     set_write_file()  <- four flag doors (create and edit, twice each),
#                          plus import and the boot restore
#     get_write_file()  <- state_persistence.cpp, twice, to write it back
#                          into the JSON
#
# Nothing anywhere opened it. The path was parsed, validated for presence,
# carried to the worker in the config frame, persisted across reboots and
# echoed by `show` -- and the man page's own troubleshooting recipe was
#
#     socketley create server api -p 9000 --log /tmp/api.log -s
#     tail -f /tmp/api.log
#
# a tail on a file that would never be created.
#
# ─── WHY IMPLEMENT RATHER THAN REFUSE ───────────────────────────────────────
#
# Both readings were on the table. Refusing the flag would break `create`
# commands that succeed today, including the one in this project's own help
# text; and nobody can be depending on the current behaviour, because there is
# none. The documented sentence is specific enough to be a specification, and
# its stdout sibling -b was already implemented at exactly the point where
# every received message is counted -- so the file half is the same call, one
# line below.
#
# ─── WHAT THE FIRST MEASUREMENT AFTER THE FIX FOUND ─────────────────────────
#
# `edit s -w second.log` was stored, reported by `show`, and the next message
# still went to the FIRST file: write_file was not in apply_live_config, so the
# frame reached the worker and the worker ignored that field. It is in the live
# set now, unconditionally, for the reason backend_timeout is -- the one caller
# parses a whole document, so a guarded form would make -w the one setting that
# could be turned on and never off.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate writefile

P_SRV=$((SL_PORT_BASE+1820))
P_SHD=$((SL_PORT_BASE+1822))
NAMES="wf_srv wf_shd"

W1="$SOCKETLEY_TMPD/rx.log"
W2="$SOCKETLEY_TMPD/rx2.log"
WS="$SOCKETLEY_TMPD/rx_shards.log"

PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

check() {   # label expected actual
    if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi
}

say() {   # port message
    printf '%s\n' "$2" | timeout 3 nc -q0 127.0.0.1 "$1" >/dev/null 2>&1 || true
}

# The file is written by the worker on its own turn, so the assertion waits for
# the line rather than sleeping a guess and calling it absent.
await_lines() {   # file count
    local i
    for i in $(seq 1 60); do
        [ -f "$1" ] && [ "$(wc -l < "$1")" -ge "$2" ] && return 0
        sleep 0.1
    done
    return 1
}

echo "=== Integration: -w writes the messages it was given a file for ==="
daemon_start "$BIN"

# ─── 1. Nothing before the first message ────────────────────────────────────
create_ok "a server with -w" "$BIN" create server wf_srv -p "$P_SRV" -w "$W1"
"$BIN" start wf_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV" >/dev/null 2>&1 || true

if [ -e "$W1" ]; then
    bad "no file before a message" "$W1 exists already"
else
    ok
fi

# ─── 2. The messages arrive, in order, one per line ─────────────────────────
for m in alpha beta gamma; do say "$P_SRV" "$m"; done
if await_lines "$W1" 3; then ok; else
    bad "three messages reach the file" \
        "after 6s the file holds: $(cat "$W1" 2>/dev/null | tr '\n' '|')"; fi

check "one line per message"  "3"                "$(wc -l < "$W1" 2>/dev/null || echo 0)"
check "and in the order sent" "alpha|beta|gamma" "$(tr '\n' '|' < "$W1" | sed 's/|$//')"

# The file is the operator's, not the world's.
check "mode 0600" "600" "$(stat -c %a "$W1")"

# ─── 3. It follows an edit on a running runtime ─────────────────────────────
# This is the half the first measurement after the fix got wrong: stored,
# reported by `show`, and the worker still writing to the old path.
OUT=$("$BIN" edit wf_srv -w "$W2" 2>&1) || true
if [ -z "$OUT" ]; then ok; else bad "edit -w is accepted" "got '$OUT'"; fi

say "$P_SRV" delta
if await_lines "$W2" 1; then ok; else
    bad "the next message goes to the new file" "$W2 holds nothing after 6s"; fi
check "the new file has only what came after" "delta" "$(tr -d '\n' < "$W2")"
check "and the old file was not touched again" "3" "$(wc -l < "$W1")"

# ─── 4. Append, not truncate ────────────────────────────────────────────────
# A restart adds to the file, because a runtime that loses its record on every
# restart is not a record.
"$BIN" restart wf_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV" >/dev/null 2>&1 || true
say "$P_SRV" epsilon
if await_lines "$W2" 2; then ok; else
    bad "a restart appends" "$W2: $(tr '\n' '|' < "$W2")"; fi
check "both lines are there" "delta|epsilon" "$(tr '\n' '|' < "$W2" | sed 's/|$//')"

# ─── 5. An unwritable path is one complaint, not one per message ────────────
# `grep -c` prints 0 AND exits 1 when it matches nothing, so an `|| echo 0`
# here appends a SECOND zero and the arithmetic below reads "0\n0".
BEFORE=$(grep -c "could not be opened" "$SOCKETLEY_DLOG" 2>/dev/null || true)
"$BIN" edit wf_srv -w /proc/definitely-not-a-directory/rx.log >/dev/null 2>&1 || true
for m in e1 e2 e3 e4 e5; do say "$P_SRV" "$m"; done
sleep 1
AFTER=$(grep -c "could not be opened" "$SOCKETLEY_DLOG" 2>/dev/null || true)
check "five messages, one complaint" "1" "$((AFTER - BEFORE))"

# And the runtime is still serving: a file it cannot write is not a reason to
# stop carrying traffic.
STATE=$("$BIN" ps -a 2>/dev/null | awk '$2=="wf_srv" { print $7 }')
check "the runtime keeps serving" "Up" "$STATE"

# ─── 6. Every shard writes into the one path ────────────────────────────────
# N workers, one file, and the interesting number is the total: an append this
# size is atomic, so nothing should be lost or torn.
create_ok "a 3-shard server with -w" "$BIN" create server wf_shd \
    -p "$P_SHD" --shards 3 -w "$WS"
"$BIN" start wf_shd >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SHD" >/dev/null 2>&1 || true
for i in $(seq 1 15); do say "$P_SHD" "shard-msg-$i"; done
if await_lines "$WS" 15; then ok; else
    bad "all 15 reach the shared file" "got $(wc -l < "$WS" 2>/dev/null || echo 0) of 15"; fi
check "and none of them tore" "15" \
    "$(grep -c '^shard-msg-[0-9]\+$' "$WS" 2>/dev/null || true)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
