#!/usr/bin/env bash
# Integration test: on an --anonymous storage one visitor's watch positions are not shown to the next.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * every anonymous visitor keeping positions in one file, named for the word
#     "anonymous", so whoever came next read which films the last one watched,
#     how far and when
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

daemon_isolate anonprog
P=$((SL_PORT_BASE+1964))
U="http://127.0.0.1:$P"
trap 'daemon_stop' EXIT

echo "=== Integration: anonymous visitors keep no positions for each other ==="

daemon_start "$BIN"
"$BIN" create storage an -p "$P" --dir "$SOCKETLEY_TMPD/an" --anonymous -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done
curl -s -o /dev/null -X PUT "$U/films"
printf 'frames' | curl -s -o /dev/null -T - "$U/films/night.mp4"
expect "the film is there" "$(curl -s "$U/films/night.mp4")" "frames"

ui() { curl -s -m 5 -H 'X-Socketley-UI: 1' "$@"; }
ui -o /dev/null -X POST -d '{"bucket":"films","key":"night.mp4","t":1200,"d":5400}' "$U/~ui/progress"
expect "the next visitor is shown nothing the last one watched" "$(ui "$U/~ui/progress")" "[]"
expect "and nothing about it is kept on disk" "$(ls "$SOCKETLEY_TMPD/an/.ui/progress" 2>/dev/null | wc -l)" 0

# The page's one script is let run by its hash and no other inline script is, so text that reached the page unescaped
# could not run.
curl -s -D "$SOCKETLEY_TMPD/h" -o "$SOCKETLEY_TMPD/b" "$U/~ui"
expect "the interface's script runs by its hash and nothing else inline does" "$(python3 - "$SOCKETLEY_TMPD/h" "$SOCKETLEY_TMPD/b" <<'PY'
import sys, re, hashlib, base64
h = open(sys.argv[1]).read(); b = open(sys.argv[2], 'rb').read()
csp = next((l for l in h.splitlines() if l.lower().startswith('content-security-policy')), '')
src = re.search(r"script-src ([^;]*)", csp)
s = b.index(b'<script>') + 8; e = b.index(b'</script>')
want = "'self' 'sha256-%s'" % base64.b64encode(hashlib.sha256(b[s:e]).digest()).decode()
print('yes' if src and src.group(1).strip() == want else 'script-src is %r' % (src.group(1) if src else None))
PY
)" "yes"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
