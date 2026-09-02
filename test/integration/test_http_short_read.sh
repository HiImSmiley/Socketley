#!/usr/bin/env bash
# Integration test: a file the read path could not read whole is not a 200.
#
# ─── THE DEFECT ─────────────────────────────────────────────────────────────
#
# serve_http's read path -- every .html, every file under --tls, and every
# file while another client holds the instance's one splice -- issued a single
# read whose length was cut to 32 bits and which the kernel caps at
# MAX_RW_COUNT (2,147,479,552).  handle_file_read then built a 200 out of
# whatever came back, with a Content-Length to match, so the client saw a
# complete, well-framed file that was not the file.  Measured on d77e2d4d:
#
#     truncate -s 2200M big.bin, two concurrent GETs
#         first  (splice)   size=2306867200  200
#         second (read)     size=2147479552  200      the kernel's cap, as a 200
#
# ─── WHY THE FIXTURE IS 4 GiB + 4 KiB, SPARSE, AND .html ────────────────────
#
# A file of 2200 MiB proves the kernel cap but costs the box 4 GB of resident
# memory and a second client to hold the splice.  A file of 4 GiB + 4 KiB
# proves the other half of the same defect -- the 32-bit cut -- for the price
# of one page: the length becomes 4096, the read returns 4096, and on the old
# build the client gets a 200 declaring 4,206 bytes (with the injected
# script) for a 4,294,971,392-byte file.  The buffer is malloc'd at the full
# size but only the read's bytes are touched; the file is sparse and holds
# no blocks.  .html because that extension always takes the read path.
#
# ─── WHAT EACH ROW CATCHES ──────────────────────────────────────────────────
#
#   small.html 200, body == CL         the read path serves, and the harness
#                                      counts bodies; a build that 500s every
#                                      read fails here
#   huge.html status                   the defect: 200 on the old build
#   huge.html not 200 below its size   the invariant itself, stated so that a
#                                      future build answering 200 with the
#                                      right length passes and one answering
#                                      200 with any other length fails
#   huge.html then EOF                 the refusal closes rather than leaving
#                                      the client to send its next request
#                                      into a response that was cut short
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate httpshort
PASS=0; FAIL=0; TOTAL=0
trap daemon_stop EXIT

PORT=$((SL_PORT_BASE+495))
HUGE=$((4 * 1024 * 1024 * 1024 + 4096))

WWW="$SOCKETLEY_TMPD/www"
mkdir -p "$WWW"
printf '<html><body>small</body></html>\n' > "$WWW/small.html"
truncate -s "$HUGE" "$WWW/huge.html"

echo "=== Integration: a short read of a static file is not a 200 ==="

daemon_start "$BIN"
create_ok "server created" "$BIN" create server hs -p "$PORT" --http "$WWW" -s
ready_http 127.0.0.1 "$PORT" /small.html 10 || echo "  NOTE: server never answered"

# status, declared length, bytes after the header block and whether the peer
# closed, read to EOF or 5 s of silence on a raw socket.
cat > "$SOCKETLEY_TMPD/one.py" <<'PYEOF'
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
except OSError as e:
    print("ERR:%s" % e); raise SystemExit(0)
buf = b""; s.settimeout(5); eof = "no"
try:
    while True:
        d = s.recv(1 << 20)
        if not d:
            eof = "yes"; break
        buf += d
except socket.timeout:
    pass
s.close()
i = buf.find(b"\r\n\r\n")
if i < 0:
    print("status=none cl=none body=%d eof=%s" % (len(buf), eof)); raise SystemExit(0)
head = buf[:i].decode("latin-1").split("\r\n")
status = head[0].split(" ")[1] if " " in head[0] else "none"
cl = "none"
for line in head[1:]:
    k, _, v = line.partition(":")
    if k.strip().lower() == "content-length":
        cl = v.strip()
print("status=%s cl=%s body=%d eof=%s" % (status, cl, len(buf) - i - 4, eof))
PYEOF

one() { python3 "$SOCKETLEY_TMPD/one.py" "$@" 2>/dev/null || echo ERR; }
field() { local v=${2#*$1=}; printf '%s' "${v%% *}"; }

check() {   # check LABEL GOT WANT
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '  PASS [%-34s] %s\n' "$1" "$2"
    else
        FAIL=$((FAIL+1)); printf '  FAIL [%-34s] %s   (expected %s)\n' "$1" "$2" "$3"
    fi
}

echo "--- control: the read path serves a file it can read whole ---"
r=$(one "$PORT" /small.html)
check "small.html status"       "$(field status "$r")" 200
check "small.html body == CL"   "$(field body "$r")" "$(field cl "$r")"

echo "--- a file the one read cannot cover ---"
r=$(one "$PORT" /huge.html)
echo "  huge.html answered: $r"
check "huge.html status"        "$(field status "$r")" 500
st=$(field status "$r"); cl=$(field cl "$r")
TOTAL=$((TOTAL+1))
if [ "$st" = "200" ] && [ "$cl" != "none" ] && [ "$cl" -lt "$HUGE" ]; then
    FAIL=$((FAIL+1)); echo "  FAIL [huge.html 200 below its size       ] cl=$cl for a $HUGE-byte file"
else
    PASS=$((PASS+1)); echo "  PASS [huge.html not a 200 below its size ] status=$st cl=$cl"
fi
check "huge.html closed after"  "$(field eof "$r")" yes

echo
echo "Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
