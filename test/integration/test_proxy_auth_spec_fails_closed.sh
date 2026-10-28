#!/usr/bin/env bash
# Integration test: an --auth no door has judged refuses everybody, and the import door judges it.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The flag refuses an --auth that is not bearer:, basic: or idp:, but saved
# state, a restored archive and `import` (which `edit` sends its buffer
# through) hand the value to the proxy unjudged, and the proxy read any other
# prefix as no --auth at all: "Bearer:/etc/tokens", one capital letter, let
# every request through while `show` still printed it.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The proxy answers 401 to a request with no token before anything is changed
# and 200 to one with the token, so a 401 after the state is edited is the
# changed spec refusing and not a proxy that refuses everything for some other
# reason; and an import of the right spelling still lands.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxauthspec
T="$SOCKETLEY_TMPD"

BE=$((SL_PORT_BASE+1840))
PX=$((SL_PORT_BASE+1841))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: an --auth that is none of the three refuses everybody ==="

cat > "$T/be.py" <<'PYEOF'
import socket, sys, threading
port = int(sys.argv[1])
def serve(c):
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                b = c.recv(65536)
                if not b: return
                buf += b
            _, buf = buf.split(b"\r\n\r\n", 1)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
    finally:
        c.close()
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(16)
sys.stderr.write("be up\n"); sys.stderr.flush()
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF
python3 "$T/be.py" "$BE" 2>"$T/be.log" & BEPID=$!
for _ in $(seq 1 50); do grep -q "be up" "$T/be.log" 2>/dev/null && break; sleep 0.1; done

daemon_start "$BIN"
STATE_DIR=$(grep -a "state directory: " "$SOCKETLEY_DLOG" | tail -1 | sed 's/.*state directory: //' || true)
if [ -z "$STATE_DIR" ] || [ ! -d "$STATE_DIR" ]; then
    echo "  FATAL: the daemon did not say which state directory it is using"
    exit 2
fi

printf 'tok-one\n' > "$T/tokens"
"$BIN" create proxy pa -p "$PX" --backend "127.0.0.1:$BE" --protocol http --auth "bearer:$T/tokens" -s \
    >/dev/null 2>&1
tc() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" "http://127.0.0.1:$PX/pa/"; }
for _ in $(seq 1 50); do [ "$(tc)" = 401 ] && break; sleep 0.1; done
ok "$(tc)$(tc -H 'Authorization: Bearer tok-one')" "401200" "the proxy refuses no token and passes the right one"

"$BIN" show pa > "$T/pa.json"
sed 's|"auth": "bearer:|"auth": "Bearer:|' "$T/pa.json" > "$T/typo.json"
out=$("$BIN" import pa < "$T/typo.json" 2>&1); rc=$?
ok "$rc:$(grep -c -- '--auth takes bearer:' <<<"$out")" "1:1" "an import of an --auth that is none of the three is refused, saying why"
"$BIN" import pa < "$T/pa.json" >/dev/null 2>&1; rc=$?
ok "$rc" "0" "and the same document spelled right is taken"
"$BIN" start pa >/dev/null 2>&1 || true
for _ in $(seq 1 50); do [ "$(tc)" = 401 ] && break; sleep 0.1; done

# The state file edited behind the daemon's back, as a restored archive or a hand edit leaves it.
kill "$SOCKETLEY_DPID" 2>/dev/null
for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
for _ in $(seq 1 50); do [ "$(tc)" = 000 ] && break; sleep 0.1; done
sed -i 's|"auth": "bearer:|"auth": "Bearer:|' "$STATE_DIR/pa.json"
ok "$(grep -c '"auth": "Bearer:' "$STATE_DIR/pa.json")" "1" "the saved state now carries the misspelt --auth"
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"
"$BIN" start pa >/dev/null 2>&1 || true
got=000
for _ in $(seq 1 50); do got=$(tc); [ "$got" != 000 ] && break; sleep 0.1; done
ok "$got$(tc -H 'Authorization: Bearer tok-one')" "401401" \
   "restored from that state the proxy refuses every request rather than none"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
