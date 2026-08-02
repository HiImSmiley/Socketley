#!/usr/bin/env bash
# Integration test: `ps -s` and `ls -s` print what they are documented to print.
#
# The man page says of both, in the same words:
#
#     With --silent or -s, prints only runtime names (one per line).
#
# and the interactive help repeats it.  Neither does.  `-s` suppresses the
# header and prints the whole eight-column table underneath it, so the operator
# who reads the documentation and writes
#
#     for n in $(socketley ps -s); do ...
#
# iterates over ids, ports, connection counts and the words "Up" and "seconds".
# The names-only form exists — it is `-s --name` — but nothing says so, and the
# flag that is documented to produce it produces a table.
#
# ─── WHAT IS NOT CHANGED ────────────────────────────────────────────────────
#
# `-s` with columns named explicitly keeps meaning "no header": `ps -s --id
# --name` is two tab-separated fields and stays two tab-separated fields.  A
# column list is a request for those columns, and honouring the documented
# default there would throw away what the caller asked for.  The default table
# is untouched, header and all.
#
# The assertions are therefore paired.  "Bare `ps` still prints its header" and
# "`-s --id --name` still prints two fields" are green on the build this was
# written against — stated alone they would stay green if `-s` were deleted
# outright.  Each is there to hold down the half that must survive the half that
# changes.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate silentnames

PORT_A=19875
PORT_B=19876

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   sn_up sn_made 2>/dev/null || true
    sleep 0.2
    "$BIN" remove sn_up sn_made 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: --silent prints the names it is documented to print ==="

daemon_start "$BIN"

# One running, one merely created.  The second is what separates `ps` from `ls`
# below: `ps` must not name it, `ls` must.
"$BIN" create server sn_up   -p "$PORT_A" -s >/dev/null 2>&1 || true
"$BIN" create server sn_made -p "$PORT_B"    >/dev/null 2>&1 || true
sleep 0.3

# The premise.  Every assertion below is about these two runtimes being in these
# two states; without this the file proves nothing about either command.
LS_FULL=$("$BIN" ls 2>&1 || true)
if printf '%s\n' "$LS_FULL" | awk '$2 == "sn_up" && /Up /   { a=1 }
                                   $2 == "sn_made" && /Created/ { b=1 }
                                   END { exit !(a && b) }'; then
    ok
else
    bad "the premise: one runtime up, one only created" \
        "ls does not show that state" "$LS_FULL"
fi

# ─── ps -s ──────────────────────────────────────────────────────────────────

PS_S=$("$BIN" ps -s 2>&1 || true)

# One field per line is the whole claim: "only runtime names (one per line)".
WIDE=$(printf '%s\n' "$PS_S" | awk 'NF != 1 { print; exit }')
if [ -z "$WIDE" ]; then
    ok
else
    bad "ps -s prints one field per line" "a line carries more than a name" "$WIDE"
fi

if [ "$(printf '%s\n' "$PS_S" | sort | tr '\n' ' ')" = "sn_up " ]; then
    ok
else
    bad "ps -s names the running runtime and nothing else" \
        "expected exactly 'sn_up'" "got: $(printf '%s' "$PS_S" | tr '\n' '|')"
fi

# Paired with the two above: -s has always suppressed the header, and must go on
# doing so.  Green on the build this was written against.
if ! printf '%s\n' "$PS_S" | grep -q "OWNED BY"; then
    ok
else
    bad "ps -s prints no header" "the header is still there" "$PS_S"
fi

# ─── ls -s ──────────────────────────────────────────────────────────────────

LS_S=$("$BIN" ls -s 2>&1 || true)

WIDE=$(printf '%s\n' "$LS_S" | awk 'NF != 1 { print; exit }')
if [ -z "$WIDE" ]; then
    ok
else
    bad "ls -s prints one field per line" "a line carries more than a name" "$WIDE"
fi

# ls is the whole inventory, so the runtime that was never started is named here
# and was not named above.  This is also what proves the two commands did not
# quietly become the same command.
if [ "$(printf '%s\n' "$LS_S" | sort | tr '\n' ' ')" = "sn_made sn_up " ]; then
    ok
else
    bad "ls -s names every runtime, running or not" \
        "expected 'sn_made sn_up'" "got: $(printf '%s' "$LS_S" | tr '\n' '|')"
fi

# ─── ps -a -s ───────────────────────────────────────────────────────────────

PS_AS=$("$BIN" ps -a -s 2>&1 || true)
if [ "$(printf '%s\n' "$PS_AS" | sort | tr '\n' ' ')" = "sn_made sn_up " ]; then
    ok
else
    bad "ps -a -s names the runtimes -a adds" \
        "expected 'sn_made sn_up'" "got: $(printf '%s' "$PS_AS" | tr '\n' '|')"
fi

# ─── what must not move ─────────────────────────────────────────────────────

# An explicit column list is a request for those columns.  Two fields, tab
# separated, no header — before and after.
PS_COLS=$("$BIN" ps -s --id --name 2>&1 || true)
if printf '%s\n' "$PS_COLS" | awk -F'\t' 'NF != 2 { bad=1 } END { exit bad }' \
   && printf '%s\n' "$PS_COLS" | grep -q "sn_up" \
   && ! printf '%s\n' "$PS_COLS" | grep -q "NAME"; then
    ok
else
    bad "ps -s --id --name is still two fields and no header" \
        "column selection changed shape" "$(printf '%s' "$PS_COLS" | tr '\n' '|')"
fi

# The default table, header and all.  Twenty-odd files in this directory awk a
# column out of this.
PS_PLAIN=$("$BIN" ps 2>&1 || true)
if printf '%s\n' "$PS_PLAIN" | grep -q "OWNED BY" \
   && printf '%s\n' "$PS_PLAIN" | awk '$2 == "sn_up" && /Up / { found=1 } END { exit !found }'; then
    ok
else
    bad "bare ps still prints the table it always printed" \
        "the default output moved" "$PS_PLAIN"
fi

# ─── and the documentation that promised it ─────────────────────────────────

MAN="$HERE/../../man/socketley.1"
HELP="$HERE/../../man/socketley-help.sh"

if [ "$(grep -c "prints only runtime names (one per line)" "$MAN")" = "2" ]; then
    ok
else
    bad "the man page still documents both listings as names-only" \
        "expected the sentence under ls and under ps" \
        "found $(grep -c "prints only runtime names (one per line)" "$MAN")"
fi

if [ "$(grep -c "Print only runtime names (one per line)" "$HELP")" = "2" ]; then
    ok
else
    bad "the interactive help still documents both listings as names-only" \
        "expected the sentence under ls and under ps" \
        "found $(grep -c "Print only runtime names (one per line)" "$HELP")"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
