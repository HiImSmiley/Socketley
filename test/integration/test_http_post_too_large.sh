#!/usr/bin/env bash
# Integration test: a body the server will not take is refused with a 413.
#
# ─── THE DEFECT ─────────────────────────────────────────────────────────────
#
# parse_partial framed a POST by its Content-Length and then waited for the
# body, whatever the length said.  A body above server_connection's 1 MiB
# partial cap therefore arrived, filled `partial` past the cap, and handle_read
# closed the connection -- no status, no reason, after the client had sent a
# megabyte.  Measured on debc162c against a server with on_http_request:
#
#     head -c 2000000 /dev/zero | curl --data-binary @- ...   000, exit 52
#     head -c 1100000 /dev/zero | curl --data-binary @- ...   000, exit 52
#     head -c 1048000 /dev/zero | curl --data-binary @- ...   200
#     headers declaring Content-Length: 2000000, no body     nothing, ever
#
# ─── WHAT EACH ROW CATCHES ──────────────────────────────────────────────────
#
#   500 KB POST answered 200 with its length   a build that refuses every
#                                              body, and the harness's own
#                                              ability to see a 200
#   1,048,000 B POST answered 200              a limit set below the cap
#   2,000,000 B POST answered 413              the defect (000 on the old build)
#   headers alone answered 413 within 2 s      the refusal is decided from the
#                                              declared length, before a byte
#                                              of body has been sent -- the
#                                              old build waits for the body
#   the 413 is followed by EOF                 the connection is closed rather
#                                              than the body read as requests
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate httppost
PASS=0; FAIL=0; TOTAL=0
trap daemon_stop EXIT

LUA_PORT=$((SL_PORT_BASE+490))
DISK_PORT=$((SL_PORT_BASE+491))

WWW="$SOCKETLEY_TMPD/www"
mkdir -p "$WWW"
printf 'ROOT\n' > "$WWW/index.html"
LUA="$SOCKETLEY_TMPD/post.lua"
cat > "$LUA" <<'LUAEOF'
function on_http_request(req)
    return { status = 200, body = "got " .. #req.body .. " bytes" }
end
LUAEOF

echo "=== Integration: a POST body over the partial cap is a 413, not a close ==="

daemon_start "$BIN"
create_ok "lua server created"  "$BIN" create server hp_lua  -p "$LUA_PORT"  --lua "$LUA" -s
create_ok "disk server created" "$BIN" create server hp_disk -p "$DISK_PORT" --http "$WWW" -s
ready_http 127.0.0.1 "$LUA_PORT"  /           10 || echo "  NOTE: lua server never answered"
ready_http 127.0.0.1 "$DISK_PORT" /index.html 10 || echo "  NOTE: disk server never answered"

# post PORT BYTES -> "<status> <body>" as curl saw it, 000 for no answer.
post() {
    head -c "$2" /dev/zero | curl -s --max-time 10 -w ' %{http_code}' \
        --data-binary @- "http://127.0.0.1:$1/" 2>/dev/null || true
}

# Headers only, declaring a body that never comes, and what arrives in 2 s.
cat > "$SOCKETLEY_TMPD/hdr.py" <<'PYEOF'
import socket, sys
port, length = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % length).encode())
s.settimeout(2)
buf = b""
try:
    while True:
        d = s.recv(4096)
        if not d:
            print("status=%s eof=yes" % (buf.split(b" ")[1].decode() if buf.startswith(b"HTTP/1.1 ") else "none"))
            raise SystemExit(0)
        buf += d
except socket.timeout:
    print("status=%s eof=no" % (buf.split(b" ")[1].decode() if buf.startswith(b"HTTP/1.1 ") else "none"))
PYEOF

check() {   # check LABEL GOT WANT
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '  PASS [%-36s] %s\n' "$1" "$2"
    else
        FAIL=$((FAIL+1)); printf '  FAIL [%-36s] %s   (expected %s)\n' "$1" "$2" "$3"
    fi
}

echo "--- bodies the server takes ---"
check "lua 500,000 B POST"           "$(post "$LUA_PORT" 500000)"  "got 500000 bytes 200"
check "lua 1,048,000 B POST"         "$(post "$LUA_PORT" 1048000)" "got 1048000 bytes 200"

echo "--- a body over the cap ---"
got=$(post "$LUA_PORT" 2000000)
check "lua 2,000,000 B POST status"  "${got##* }" 413
got=$(post "$DISK_PORT" 2000000)
check "disk 2,000,000 B POST status" "${got##* }" 413

echo "--- refused on the declared length, before any body ---"
check "lua headers only, CL=2000000"  "$(python3 "$SOCKETLEY_TMPD/hdr.py" "$LUA_PORT"  2000000 2>/dev/null || echo ERR)" "status=413 eof=yes"
check "disk headers only, CL=2000000" "$(python3 "$SOCKETLEY_TMPD/hdr.py" "$DISK_PORT" 2000000 2>/dev/null || echo ERR)" "status=413 eof=yes"
# And the same probe under the cap is still waiting for its body, which is the
# control that the row above measures the refusal and not a server that
# answers every POST at once.
check "lua headers only, CL=1000"     "$(python3 "$SOCKETLEY_TMPD/hdr.py" "$LUA_PORT"  1000 2>/dev/null || echo ERR)" "status=none eof=no"

echo
echo "Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
