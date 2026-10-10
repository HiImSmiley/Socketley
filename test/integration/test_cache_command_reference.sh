#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# The cache's command reference in man/socketley.1 is one list serving two
# protocols, and seven of its entries are RESP only -- the line protocol
# answers "failed: unknown command" to them.  Only `hello` said so, in its own
# prose.  `smismember` in particular reads like every other set command beside
# it and is refused, and nothing in the page told a reader that.
#
# Found by sending every command in that section to a cache, which is what this
# file now does on every run.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Both directions, so the note cannot rot either way:
#
#   * every documented command the note does NOT except is accepted by the line
#     protocol -- a wrong argument count is fine, "unknown command" is not
#   * every command the note DOES except is refused by it, so the list cannot
#     quietly grow past what is true
#
# A fresh connection per command, because `multi`, `subscribe` and `replicate`
# change what the connection does next and would otherwise decide the answers
# of everything sent after them.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
MAN="$HERE/../../man/socketley.1"
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate cmdref
PASS=0; FAIL=0; TOTAL=0
cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: the cache command reference matches the line protocol ==="

# ─── What the page says ─────────────────────────────────────────────────────
S=$(grep -n "Connect via TCP and send commands" "$MAN" | head -1 | cut -d: -f1 || true)
[ -n "$S" ] || { echo "  FAIL: the page has no cache command section to read"; exit 1; }
E=$(awk -v s="$S" 'NR>s && /^\.SS /{print NR; exit}' "$MAN")
[ -n "$E" ] || { echo "  FAIL: the command section has no end"; exit 1; }

# A command entry is a .TP/.TQ followed by .BI "<name> ", which is what keeps
# reply words like "ok" and "true" -- marked up the same way inline -- out.
DOCUMENTED=$(awk -v s="$S" -v e="$E" 'NR>s && NR<e{
        if ($0 ~ /^\.T[PQ]$/) { tp=1; next }
        if (tp && $0 ~ /^\.BI "[a-z]+ /) { split($0, a, "\""); split(a[2], b, " "); print b[1] }
        tp=0
    }' "$MAN" | sort -u)

# The note's own list, which ends at the paragraph break so the sentence that
# explains it cannot be read as part of it.
# `|| true` on the pipeline as well as on the count: a page with no note at all
# makes grep -o find nothing, and pipefail would end the run at the assignment
# instead of at the assertion written to report it.
EXCEPTED=$(awk -v s="$S" 'NR>s && /are RESP only/{f=1} f{print} f && /^\.PP$/{exit}' "$MAN" \
    | { grep -oE '^\.BR? "?[a-z]+' || true; } | sed 's/^\.BR\? "\?//' | sort -u)

# `|| true`, because grep -c on nothing exits 1 and under set -e that ends the
# run before the assertion that was going to report it -- which is exactly the
# failure this file is meant to describe, so it must survive it.
DOC_N=$(printf '%s\n' "$DOCUMENTED" | grep -c . || true)
EXC_N=$(printf '%s\n' "$EXCEPTED" | grep -c . || true)
echo "  the page documents $DOC_N commands and excepts $EXC_N of them"
if [ "$DOC_N" -gt 60 ] && [ "$EXC_N" -gt 0 ]; then pass
else fail "the page still reads as a command reference" \
          "documented=$DOC_N excepted=$EXC_N -- the extraction found almost nothing," \
          "which means the page moved and this file is measuring its own regex."; fi

daemon_start "$BIN"
PORT=$((SL_PORT_BASE + 880))
"$BIN" create cache cmdref -p "$PORT" -s >/dev/null 2>&1 || true
sleep 0.5

# One connection per command, and the first line of the answer.  /dev/tcp
# rather than nc, because nc -q1 lingers a second per command and there are
# more than a hundred of them.
ask() {
    local reply=""
    exec 3<>"/dev/tcp/127.0.0.1/$PORT" 2>/dev/null || { printf '<no connection>'; return; }
    printf '%s\n' "$1" >&3
    IFS= read -r -t 2 reply <&3 || reply=""
    exec 3<&- 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    printf '%s' "${reply%$'\r'}"
}

# The control first: a command that is certainly there, and one that certainly
# is not, so a run where every answer looks the same cannot pass.
[ "$(ask 'get')" != "failed: unknown command" ] && pass \
    || fail "the probe can tell a known command" "`get` alone read as unknown"
[ "$(ask 'definitelynotacommand')" = "failed: unknown command" ] && pass \
    || fail "the probe can tell an unknown command" \
            "a command nobody implements did not read as unknown"

# ─── Documented and not excepted: the line protocol has to take it ──────────
MISSING=""
for cmd in $DOCUMENTED; do
    printf '%s\n' "$EXCEPTED" | grep -qx "$cmd" && continue
    [ "$(ask "$cmd")" = "failed: unknown command" ] && MISSING="$MISSING $cmd"
done
if [ -z "$MISSING" ]; then pass
else fail "every documented command is accepted" \
          "the page documents these and the line protocol refuses them:$MISSING" \
          "either the command is missing or the RESP-only note is."; fi

# ─── Excepted: it has to actually be refused ────────────────────────────────
WRONG=""
for cmd in $EXCEPTED; do
    [ "$(ask "$cmd")" = "failed: unknown command" ] || WRONG="$WRONG $cmd"
done
if [ -z "$WRONG" ]; then pass
else fail "every excepted command is refused" \
          "the note calls these RESP only and the line protocol takes them:$WRONG" \
          "an exception that is not true reads as a missing feature."; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
