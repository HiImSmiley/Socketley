#!/usr/bin/env bash
# Integration test: a relative path on the command line names the file the
# caller meant, not one relative to wherever the daemon happens to run.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The CLI forwarded `--lua example.lua` as typed and the daemon opened it
# against its own working directory, which is "/" under systemd -- so the
# README's own Quick Start loaded /example.lua and failed, and a relative
# --log or --persistent wrote somewhere nobody would look.  The CLI now makes
# a relative path in a flag the daemon opens absolute against the caller's
# directory before sending it.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The daemon is started from "/" and the command run from a scratch directory,
# so the two working directories differ the way they do in production; the
# script must actually run (it writes a file), the log must land beside it,
# and an absolute path must come through unchanged.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate clirel

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { cd /; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a relative path means the caller's directory ==="
P=$((SL_PORT_BASE + 1840))
WORKDIR="$SOCKETLEY_TMPD/work"
mkdir -p "$WORKDIR"
cat > "$WORKDIR/hello.lua" <<EOF
local f = io.open("$WORKDIR/ran.txt", "w")
f:write("ran")
f:close()
EOF

(cd / && daemon_start "$BIN")
cd "$WORKDIR"
"$BIN" create server rel -p "$P" --lua hello.lua --log rel.log -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ -s "$WORKDIR/ran.txt" ] && break; sleep 0.1; done

ok "$(cat "$WORKDIR/ran.txt" 2>/dev/null)" "ran" "a relative --lua is the script beside the caller"
ok "$("$BIN" show rel 2>/dev/null | sed -n 's/.*"lua_script": "\([^"]*\)".*/\1/p' | head -1)" \
   "$WORKDIR/hello.lua" "and it is stored as that absolute path"
ok "$("$BIN" show rel 2>/dev/null | sed -n 's/.*"log_file": "\([^"]*\)".*/\1/p' | head -1)" \
   "$WORKDIR/rel.log" "a relative --log is resolved the same way"

# Every flag the schema calls a path, not a list the CLI kept beside it, which had none of these.
: > targets.txt; : > tiers.txt; : > repl.txt
"$BIN" create storage relst -p $((P + 2)) --dir data --anonymous --notify-targets targets.txt --tiers tiers.txt \
    --replication-targets repl.txt >/dev/null 2>&1
field() { "$BIN" show relst 2>/dev/null | sed -n "s/.*\"$1\": \"\([^\"]*\)\".*/\1/p" | head -1; }
ok "$(field notify_targets) $(field tiers) $(field replication_targets)" \
   "$WORKDIR/targets.txt $WORKDIR/tiers.txt $WORKDIR/repl.txt" "a storage's relative target and tier files are the caller's"

"$BIN" create server abs -p $((P + 1)) --log /dev/null >/dev/null 2>&1
ok "$("$BIN" show abs 2>/dev/null | sed -n 's/.*"log_file": "\([^"]*\)".*/\1/p' | head -1)" \
   "/dev/null" "an absolute path comes through unchanged"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
