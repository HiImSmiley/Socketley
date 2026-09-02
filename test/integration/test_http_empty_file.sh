#!/usr/bin/env bash
# Integration test: an empty file is served, in disk mode as in --http-cache.
#
# ─── THE DEFECT ─────────────────────────────────────────────────────────────
#
# serve_http's disk path used the file's size as its existence check:
# `st_size <= 0` answered 404, and had it got past that, handle_file_read
# answered 404 to the `cqe->res == 0` a zero-length read completes with.
# rebuild_http_cache read the same file and built a 200 with Content-Length:
# 0.  Measured on d8394e9b, the same directory behind two servers:
#
#     path          disk        --http-cache
#     /empty.txt    404 (13)    200 (0)
#     /empty.html   404 (13)    200 (110)      the injected script alone
#     /empty.bin    404 (13)    200 (0)
#
# ─── WHAT EACH ROW CATCHES ──────────────────────────────────────────────────
#
#   /index.html 200 with a body      the harness sees bodies and statuses
#   /missing 404 on both             a build that answers 200 to everything,
#                                    which would turn every row below green
#   empty file: disk == cache        the subject; on the old build the disk
#                                    column reads 404
#   empty file: body == CL           the response is framed, so that
#   keep-alive GET empty, GET index  the next response on the connection is
#                                    read from where this one said it ends
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate httpempty
PASS=0; FAIL=0; TOTAL=0
trap daemon_stop EXIT

DISK_PORT=$((SL_PORT_BASE+485))
CACHE_PORT=$((SL_PORT_BASE+486))

WWW="$SOCKETLEY_TMPD/www"
mkdir -p "$WWW"
printf '<html><body>ROOT</body></html>\n' > "$WWW/index.html"
: > "$WWW/empty.txt"
: > "$WWW/empty.html"
: > "$WWW/empty.bin"

echo "=== Integration: an empty file is a 200 in disk mode as in --http-cache ==="

daemon_start "$BIN"
create_ok "disk server created"  "$BIN" create server he_disk  -p "$DISK_PORT"  --http "$WWW" -s
create_ok "cache server created" "$BIN" create server he_cache -p "$CACHE_PORT" --http "$WWW" --http-cache -s
ready_http 127.0.0.1 "$DISK_PORT"  /index.html 10 || echo "  NOTE: disk server never answered"
ready_http 127.0.0.1 "$CACHE_PORT" /index.html 10 || echo "  NOTE: cache server never answered"

# status, declared length and bytes after the header block, read to EOF on a
# raw socket so the body is counted by this file and not by curl.
cat > "$SOCKETLEY_TMPD/one.py" <<'PYEOF'
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path).encode())
except OSError as e:
    print("ERR:%s" % e); raise SystemExit(0)
buf = b""; s.settimeout(3)
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
except socket.timeout:
    pass
s.close()
i = buf.find(b"\r\n\r\n")
if i < 0:
    print("status=none cl=none body=%d" % len(buf)); raise SystemExit(0)
head = buf[:i].decode("latin-1").split("\r\n")
status = head[0].split(" ")[1] if " " in head[0] else "none"
cl = "none"
for line in head[1:]:
    k, _, v = line.partition(":")
    if k.strip().lower() == "content-length":
        cl = v.strip()
print("status=%s cl=%s body=%d" % (status, cl, len(buf) - i - 4))
PYEOF

# Two GETs on one connection, the empty file first, parsed by Content-Length.
cat > "$SOCKETLEY_TMPD/ka.py" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"GET /empty.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    time.sleep(0.3)
    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
except OSError as e:
    print("ERR:%s" % e); raise SystemExit(0)
buf = b""; s.settimeout(3)
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
except socket.timeout:
    pass
s.close()
statuses = []
while buf.startswith(b"HTTP/1.1 "):
    i = buf.find(b"\r\n\r\n")
    if i < 0:
        break
    cl = 0
    for line in buf[:i].split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            cl = int(v.strip())
    statuses.append(buf[:i].split(b" ")[1].decode())
    buf = buf[i + 4 + cl:]
print("statuses=%s leftover=%d" % (",".join(statuses), len(buf)))
PYEOF

one() { python3 "$SOCKETLEY_TMPD/one.py" "$@" 2>/dev/null || echo ERR; }
field() { local v=${2#*$1=}; printf '%s' "${v%% *}"; }

check() {   # check LABEL GOT WANT
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '  PASS [%-32s] %s\n' "$1" "$2"
    else
        FAIL=$((FAIL+1)); printf '  FAIL [%-32s] %s   (expected %s)\n' "$1" "$2" "$3"
    fi
}

echo "--- controls ---"
d=$(one "$DISK_PORT" /index.html)
check "disk /index.html status"  "$(field status "$d")" 200
check "disk /index.html body>0"  "$([ "$(field body "$d")" -gt 0 ] && echo yes || echo no)" yes
check "disk /missing"            "$(field status "$(one "$DISK_PORT" /missing)")"  404
check "cache /missing"           "$(field status "$(one "$CACHE_PORT" /missing)")" 404

echo "--- an empty file, disk against --http-cache ---"
for f in /empty.txt /empty.html /empty.bin; do
    d=$(one "$DISK_PORT" "$f"); c=$(one "$CACHE_PORT" "$f")
    check "cache $f status"        "$(field status "$c")" 200
    check "disk  $f status"        "$(field status "$d")" 200
    check "disk  $f CL == cache"   "$(field cl "$d")"     "$(field cl "$c")"
    check "disk  $f body == CL"    "$(field body "$d")"   "$(field cl "$d")"
done

echo "--- keep-alive: the empty response frames the next one ---"
check "disk  GET empty, GET index"  "$(python3 "$SOCKETLEY_TMPD/ka.py" "$DISK_PORT"  2>/dev/null || echo ERR)" "statuses=200,200 leftover=0"
check "cache GET empty, GET index"  "$(python3 "$SOCKETLEY_TMPD/ka.py" "$CACHE_PORT" 2>/dev/null || echo ERR)" "statuses=200,200 leftover=0"

echo
echo "Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
