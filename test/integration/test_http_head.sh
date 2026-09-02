#!/usr/bin/env bash
# Integration test: a HEAD gets the headers a GET would get, and no body.
#
# ─── THE DEFECT ─────────────────────────────────────────────────────────────
#
# parse_partial read the method into hreq.method and nothing read it again, so
# every emitter -- 404, --http-cache hit, revalidated hit, disk read, splice,
# Lua table, Lua 500, 400, 501 -- answered HEAD with the bytes a GET gets.
# Measured on 5c30f6c4: HEAD /index.html carried 148 body bytes, HEAD /nope
# carried the 13 of the 404 text, and HEAD /blob.bin spliced all 5000.  Under
# keep-alive a client that trusts Content-Length reads those bytes as the start
# of its next response and is desynchronised from then on.
#
# ─── WHAT EACH ROW CATCHES ──────────────────────────────────────────────────
#
#   GET body == Content-Length > 0    a harness that cannot see a body; without
#                                     it every "HEAD body=0" below is
#                                     unfalsifiable
#   HEAD body == 0                    the defect
#   HEAD Content-Length == GET's      a build that answers HEAD with the length
#                                     of nothing, or for HTML with st_size
#                                     instead of the injected body's length
#   HEAD status == GET's              a build that decides HEAD before it
#                                     decides whether the file exists
#   keep-alive HEAD then GET == 2     the consequence: the second response is
#                                     parsed from where the first said it ends
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate httphead
PASS=0; FAIL=0; TOTAL=0
trap daemon_stop EXIT

DISK_PORT=$((SL_PORT_BASE+480))
CACHE_PORT=$((SL_PORT_BASE+481))
LUA_PORT=$((SL_PORT_BASE+482))

WWW="$SOCKETLEY_TMPD/www"
mkdir -p "$WWW"
# An HTML file takes the read path and its body is the injected one, so its
# Content-Length is not st_size; a binary above nothing takes the splice path;
# a small text file takes the read path without injection.
printf '<html><head></head><body>hello world</body></html>\n' > "$WWW/index.html"
head -c 5000 /dev/urandom > "$WWW/blob.bin"
printf 'twelve bytes' > "$WWW/small.txt"

LUA="$SOCKETLEY_TMPD/head.lua"
cat > "$LUA" <<'LUAEOF'
function on_http_request(req)
    if req.path == "/boom" then
        error("the handler exploded")
    end
    -- Not a function of req.method, because the row below compares the
    -- HEAD's Content-Length with the GET's.
    return { status = 200, body = "served by lua" }
end
LUAEOF

echo "=== Integration: HEAD carries the headers of a GET and no body ==="

daemon_start "$BIN"

create_ok "disk server created"  "$BIN" create server hd_disk  -p "$DISK_PORT"  --http "$WWW" -s
create_ok "cache server created" "$BIN" create server hd_cache -p "$CACHE_PORT" --http "$WWW" --http-cache -s
create_ok "lua server created"   "$BIN" create server hd_lua   -p "$LUA_PORT"   --lua "$LUA" -s

ready_http 127.0.0.1 "$DISK_PORT"  /index.html 10 || echo "  NOTE: disk server never answered"
ready_http 127.0.0.1 "$CACHE_PORT" /index.html 10 || echo "  NOTE: cache server never answered"
ready_http 127.0.0.1 "$LUA_PORT"   /lua        10 || echo "  NOTE: lua server never answered"

# One request on a fresh connection with Connection: close, read to EOF, and
# report status, declared length and the bytes that followed the header block
# -- a raw socket rather than curl, because curl's -I stops reading at the
# header block and would report 0 body bytes against every build.
cat > "$SOCKETLEY_TMPD/one.py" <<'PYEOF'
import socket, sys
port, method, path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
extra = sys.argv[4] if len(sys.argv) > 4 else ""
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(("%s %s HTTP/1.1\r\nHost: x\r\n%sConnection: close\r\n\r\n"
               % (method, path, extra)).encode())
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
head = buf[:i].decode("latin-1")
status = head.split("\r\n")[0].split(" ")[1] if " " in head else "none"
cl = "none"
for line in head.split("\r\n")[1:]:
    k, _, v = line.partition(":")
    if k.strip().lower() == "content-length":
        cl = v.strip()
print("status=%s cl=%s body=%d" % (status, cl, len(buf) - i - 4))
PYEOF

# HEAD then GET on one keep-alive connection, parsed the way a client that
# believes Content-Length parses: the first response ends at its header block,
# the second at its header block plus its declared length.  Reports how many
# responses that yields and whether the second's body is exactly its length.
cat > "$SOCKETLEY_TMPD/ka.py" <<'PYEOF'
import socket, sys, time
port, path = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(("HEAD %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
    time.sleep(0.3)
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
def parse(b, is_head):
    i = b.find(b"\r\n\r\n")
    if i < 0 or not b.startswith(b"HTTP/1.1 "):
        return None, b
    cl = 0
    for line in b[:i].split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            cl = int(v.strip())
    end = i + 4 + (0 if is_head else cl)
    return (b[:i].split(b"\r\n")[0], cl, b[i+4:end]), b[end:]
first, rest = parse(buf, True)
second, rest = parse(rest, False)
n = (first is not None) + (second is not None)
ok = second is not None and len(second[2]) == second[1] and second[1] > 0 and not rest
print("responses=%d second_ok=%s" % (n, "yes" if ok else "no"))
PYEOF

one() { python3 "$SOCKETLEY_TMPD/one.py" "$@" 2>/dev/null || echo ERR; }

check() {   # check LABEL GOT WANT
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '  PASS [%-34s] %s\n' "$1" "$2"
    else
        FAIL=$((FAIL+1)); printf '  FAIL [%-34s] %s   (expected %s)\n' "$1" "$2" "$3"
    fi
}

# pair LABEL PORT PATH [EXTRA]: GET and HEAD of the same path, the GET is the
# control and the HEAD is judged against it.
pair() {
    local label="$1" port="$2" path="$3" extra="${4:-}" g h gs gc gb hs hc hb
    g=$(one "$port" GET  "$path" "$extra")
    h=$(one "$port" HEAD "$path" "$extra")
    gs=${g#status=}; gs=${gs%% *}; gc=${g#*cl=}; gc=${gc%% *}; gb=${g##*body=}
    hs=${h#status=}; hs=${hs%% *}; hc=${h#*cl=}; hc=${hc%% *}; hb=${h##*body=}
    check "$label GET body==CL>0"       "$gb" "$gc"
    TOTAL=$((TOTAL+1))
    if [ "$gc" != "none" ] && [ "$gc" -gt 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "  FAIL [$label GET has a body]: $g"; fi
    check "$label HEAD status==GET"     "$hs" "$gs"
    check "$label HEAD CL==GET"         "$hc" "$gc"
    check "$label HEAD body"            "$hb" "0"
}

echo "--- disk mode: read, splice, small read, 404 ---"
pair "disk html"   "$DISK_PORT" /index.html
pair "disk splice" "$DISK_PORT" /blob.bin
pair "disk small"  "$DISK_PORT" /small.txt
pair "disk 404"    "$DISK_PORT" /nope
# The second request for a small file is the revalidated hit.
pair "disk reval"  "$DISK_PORT" /small.txt

echo "--- --http-cache mode ---"
pair "cache html"  "$CACHE_PORT" /index.html
pair "cache 404"   "$CACHE_PORT" /nope

echo "--- Lua on_http_request: table, 500 ---"
pair "lua table"   "$LUA_PORT" /lua
pair "lua 500"     "$LUA_PORT" /boom

echo "--- a refusal is bodiless too ---"
pair "400 refusal" "$DISK_PORT" /index.html $'X-Bad : 1\r\n'

echo "--- keep-alive: HEAD then GET on one connection ---"
for port in "$DISK_PORT" "$CACHE_PORT" "$LUA_PORT"; do
    got=$(python3 "$SOCKETLEY_TMPD/ka.py" "$port" /index.html 2>/dev/null || echo ERR)
    check "keep-alive HEAD,GET :$port" "$got" "responses=2 second_ok=yes"
done
got=$(python3 "$SOCKETLEY_TMPD/ka.py" "$DISK_PORT" /blob.bin 2>/dev/null || echo ERR)
check "keep-alive HEAD,GET splice" "$got" "responses=2 second_ok=yes"

echo
echo "Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
