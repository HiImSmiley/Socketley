#!/usr/bin/env bash
# Integration test: a header a script hands the server, or hands socketley.http, never ends its line early.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a value with CR LF in it, in an answer from on_http_request, writing a
#     header the client chose -- a script's header is often made of what the
#     request said -- and the same through respond_stream
#   * a name with a space or a colon in it written as given
#   * a header with neither still sent, which a fix that dropped all of them
#     would stop
#   * socketley.http sending a request line or a header with a line break in
#     it to whoever it calls, rather than refusing the call
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate scripthdr
T="$SOCKETLEY_TMPD"
SP=$((SL_PORT_BASE+1966))
SINK=$((SL_PORT_BASE+1967))
SINK_PID=""
trap '[ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null; daemon_stop' EXIT

echo "=== Integration: a script's headers carry no line break ==="

# Whoever socketley.http calls: writes down every request line and header it is sent.
python3 - "$SINK" "$T/sink.log" <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(8)
while True:
    c, _ = s.accept()
    c.settimeout(3)
    d = b""
    try:
        while b"\r\n\r\n" not in d:
            b = c.recv(4096)
            if not b: break
            d += b
    except Exception:
        pass
    open(sys.argv[2], "ab").write(d.split(b"\r\n\r\n")[0] + b"\n--\n")
    c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
    c.close()
PY
SINK_PID=$!

cat > "$T/s.lua" <<EOF
local POISON = { ["X-Good"] = "fine", ["X-Bad"] = "a\r\nSet-Cookie: evil=1", ["Bad Name"] = "x" }
function on_http_request(req)
    if req.path == "/full" then
        return { status = 200, body = "b", headers = POISON }
    end
    if req.path == "/stream" then
        self.respond_stream(req.client_id, 200, POISON)
        self.send_chunk(req.client_id, "b")
        self.end_response(req.client_id)
        return
    end
    if req.path == "/out-bad" then
        local r = socketley.http({ url = "http://127.0.0.1:$SINK/x", timeout_ms = 3000,
                                   headers = { ["X-Bad"] = "a\r\nInjected: 1" } })
        return { status = 200, body = r.ok and "sent" or tostring(r.error) }
    end
    if req.path == "/out-good" then
        local r = socketley.http({ url = "http://127.0.0.1:$SINK/y", timeout_ms = 3000,
                                   headers = { ["X-Ok"] = "1" } })
        return { status = 200, body = r.ok and "sent" or tostring(r.error) }
    end
    return { status = 404, body = "no" }
end
EOF
daemon_start "$BIN"
"$BIN" create server sh -p "$SP" --lua "$T/s.lua" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$SP/full" && break; sleep 0.1; done

for path in full stream; do
    h=$(curl -s -m 5 -D - -o /dev/null "http://127.0.0.1:$SP/$path" | tr -d '\r')
    expect "a value with a line break writes no header of its own ($path)" "$(grep -ci '^set-cookie' <<<"$h")" 0
    expect "a name that is no token is not written ($path)" "$(grep -c '^Bad Name' <<<"$h")" 0
    expect "and a sound header is still sent ($path)" "$(grep -c '^X-Good: fine' <<<"$h")" 1
done

said=$(curl -s -m 10 "http://127.0.0.1:$SP/out-bad")
expect "socketley.http refuses a header with a line break, saying so" "$(grep -c 'cannot go out' <<<"$said")" 1
expect "and sends nothing of it" "$(grep -c '^Injected' "$T/sink.log" 2>/dev/null)" 0
expect "a sound header is sent" "$(curl -s -m 10 "http://127.0.0.1:$SP/out-good") $(grep -c '^X-Ok: 1' "$T/sink.log" 2>/dev/null)" "sent 1"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
