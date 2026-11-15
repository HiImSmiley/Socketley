#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a FIFO under a FastCGI proxy's --root, in the place of a static file, is a missing file and not a
# stalled runtime.
#
# ─── THE DEFECT (round 8b, R8-3; this test round 8c) ────────────────────────
#
# A static file under --root is looked at with an O_PATH open (which a FIFO does not hold) and then opened O_RDONLY
# to be sent.  That second open checked S_ISREG only after it returned, and open(2) of a FIFO with no writer blocks, on
# the proxy's loop.  Anyone who may write under --root (an upload folder, a second account) who swaps a file for a
# FIFO between the two opens -- renameat2(RENAME_EXCHANGE) in a loop wins the race within a few hundred requests --
# stalls the proxy for every client until something writes to the FIFO.  Fixed in dadb1fb5b (O_NONBLOCK until the
# descriptor is a regular file).  On dadb1fb5b^ the race below stalls a request within seconds; the same holds for
# the --compress copy, which is opened the same way after a statx.
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

daemon_isolate fcgififo
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1984))
W="$T/www"
SWAP_PID=""
# Let a stalled open go, so a red run ends without a hung runtime.
release() {
    [ -n "$SWAP_PID" ] && kill "$SWAP_PID" 2>/dev/null && wait "$SWAP_PID" 2>/dev/null
    SWAP_PID=""
    for f in "$W/s.css" "$W/swap" "$W/f.css"; do [ -p "$f" ] && { ( exec 3>"$f" ) & sleep 0.3; kill $! 2>/dev/null; }; done
}
trap 'release; "$BIN" stop site >/dev/null 2>&1; "$BIN" remove site >/dev/null 2>&1; daemon_stop' EXIT

echo "=== Integration: a FIFO in place of a FastCGI proxy's static file is not found and stalls nothing ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_start "$BIN"
mkdir -p "$W"
printf 'body{}\n' > "$W/ok.css"
printf 'body{}\n' > "$W/s.css"
mkfifo "$W/swap"
mkfifo "$W/f.css"
# No index.php: an address with no file behind it is 404 here, never the FastCGI server's, which is not running.
out=$("$BIN" create proxy site -p "$P" --domain site --backend "fastcgi://unix:$T/none.sock" --root "$W" -s 2>&1) || echo "  create: $out"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/ok.css" && break; sleep 0.1; done
code() { curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/$1"; }

expect "a static file is served" "$(code ok.css)" 200
expect "a FIFO is not found, at once" "$(code f.css)" 404
expect "and the proxy still answers after it" "$(code ok.css)" 200

# s.css and the FIFO beside it change places as fast as the kernel takes it, while s.css is asked for over and over.
cat > "$T/swap.py" <<'EOF'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD, RENAME_EXCHANGE = -100, 2
a, b = sys.argv[1].encode(), sys.argv[2].encode()
while True:
    if libc.renameat2(AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE) != 0:
        sys.exit("renameat2: " + os.strerror(ctypes.get_errno()))
EOF
cat > "$T/ask.py" <<'EOF'
import socket, sys, time
port, secs = int(sys.argv[1]), float(sys.argv[2])
req = b"GET /s.css HTTP/1.1\r\nHost: x\r\n\r\n"
end, n, seen = time.time() + secs, 0, {}
while time.time() < end:
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        s.sendall(req)
        head = s.recv(4096)
    except socket.timeout:
        print("stalled after %d requests" % n); sys.exit(0)
    finally:
        s.close()
    code = head[9:12].decode(errors="replace")
    seen[code] = seen.get(code, 0) + 1
    n += 1
print("answered all %d (%s)" % (n, " ".join("%s:%d" % kv for kv in sorted(seen.items()))))
EOF
python3 "$T/swap.py" "$W/s.css" "$W/swap" &
SWAP_PID=$!
sleep 0.2
out=$(python3 "$T/ask.py" "$P" 8)
echo "  $out"
expect "a file swapped for a FIFO between the look and the open stalls no request" "${out%% *}" "answered"
release
expect "and the proxy still answers after the swapping" "$(code ok.css)" 200

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
