#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a FIFO under a web runtime's --root named like a Lua page, or included or rendered by one, is a
# missing file, not a stalled runtime.
#
# ─── THE DEFECT (round 8b, R8-3; this test round 8c) ────────────────────────
#
# The page loader opened `<name>.lua` (and include()'s and render()'s files) beneath the root with O_RDONLY and checked
# S_ISREG only after the open.  open(2) of a FIFO with no writer blocks, and the loader runs on the runtime's loop:
# one GET of /x.lua where x.lua is a FIFO -- placed by anyone who may write under the root -- and the runtime answered
# nothing more, to anybody, until something wrote to it.  Fixed in dadb1fb5b (O_NONBLOCK, as the runtime's own file
# cache already opened); on dadb1fb5b^ every case below after the first FIFO times out (000).
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate luafifo
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1981))
W="$T/www"
# Let a stalled open go, so a red run ends without a hung runtime.
release() { for f in "$W/x.lua" "$W/_lib/inc.lua" "$W/_views/v.tpl"; do [ -p "$f" ] && { ( exec 3>"$f" ) & sleep 0.3; kill $! 2>/dev/null; }; done; }
trap 'release; "$BIN" stop lp >/dev/null 2>&1; "$BIN" remove lp >/dev/null 2>&1; daemon_stop' EXIT

echo "=== Integration: a FIFO named like a Lua page, include or template is not found and stalls nothing ==="
command -v mkfifo >/dev/null 2>&1 || { echo "  SKIP: mkfifo is required"; exit 0; }
daemon_start "$BIN"
mkdir -p "$W/_lib" "$W/_views"
echo 'echo("ok")' > "$W/index.lua"
mkfifo "$W/x.lua"
mkfifo "$W/_lib/inc.lua"
mkfifo "$W/_views/v.tpl"
cat > "$W/inc.lua" <<'EOF'
local ok = pcall(include, "_lib/inc.lua")
echo(ok and "included" or "not included")
EOF
cat > "$W/tpl.lua" <<'EOF'
local ok = pcall(render, "_views/v.tpl", {})
echo(ok and "rendered" or "not rendered")
EOF
"$BIN" create web lp -p "$P" --root "$W" --lua-pages -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/index.lua" && break; sleep 0.1; done
code() { curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/$1"; }
body() { curl -s -m 3 "http://127.0.0.1:$P/$1"; }

expect "a page is run" "$(body index.lua)" "ok"
expect "a FIFO named like a page is not found, at once" "$(code x.lua)" 404
expect "and the runtime still answers after it" "$(body index.lua)" "ok"
expect "the page's address without .lua is not found either" "$(code x)" 404
expect "a FIFO a page includes is no file to include" "$(body inc.lua)" "not included"
expect "a FIFO a page renders is no template" "$(body tpl.lua)" "not rendered"
expect "and nothing stalled" "$(body index.lua)" "ok"

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
