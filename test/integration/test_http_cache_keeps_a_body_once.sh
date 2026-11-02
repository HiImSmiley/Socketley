#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, files and port window, so it runs beside the others
# Integration test: a server's content cache keeps each file's body once, and answers a client that asks to close
# with the close header over that body.
#
# What each part would catch:
#   * a keep-alive and a close response built whole for every file: --http-cache held each body twice, 80 MB of
#     memory for 40 MB of files, and the disk mode's 64 MiB map took half the files it could
#   * a close answer that is the keep-alive one: a client that asked to close told to keep alive
#   * a close answer whose body is cut, shifted or followed by anything, from either cache or either send path
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: the content cache keeps a body once ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate bodyonce
T=$SOCKETLEY_TMPD
PM=$((SL_PORT_BASE + 1958)); PD=$((SL_PORT_BASE + 1959))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
mkdir -p "$T/www"
python3 - "$T/www" <<'PY'
import os, sys
for i in range(20):
    open(os.path.join(sys.argv[1], "f%02d.bin" % i), "wb").write(bytes((i * 7 + k) & 255 for k in range(256)) * 8192)
# Small enough for the disk mode's map as well.
for i in range(10):
    open(os.path.join(sys.argv[1], "s%02d.bin" % i), "wb").write(bytes((i * 3 + k) & 255 for k in range(256)) * 192)
PY
daemon_start "$BIN"
"$BIN" create server mem -p "$PM" --http "$T/www" --http-cache -s >/dev/null 2>&1
"$BIN" create server disk -p "$PD" --http "$T/www" -s >/dev/null 2>&1
for p in "$PM" "$PD"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/f00.bin")" = 200 ] && break; sleep 0.1; done
done
rss_of() { local pid; pid=$(ss -ltnpH "sport = :$1" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2); awk '/^VmRSS/ {print int($2 / 1024)}' "/proc/$pid/status"; }

# Every file asked twice of each, keep-alive and close, and each answer checked byte for byte.
out=$(timeout 120 python3 - "$T/www" "$PM" "$PD" <<'PY'
import os, socket, sys
d, ports = sys.argv[1], [int(p) for p in sys.argv[2:]]
bad = []
def ask(port, name, close, head=False):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    req = "%s /%s HTTP/1.1\r\nHost: x\r\n%s\r\n" % ("HEAD" if head else "GET", name, "Connection: close\r\n" if close else "")
    s.sendall(req.encode())
    buf = b""
    while True:
        if not close:
            if b"\r\n\r\n" in buf:
                h = buf.split(b"\r\n\r\n", 1)[0]
                n = 0 if head else int([l.split(b":")[1] for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
                if len(buf) >= len(h) + 4 + n: break
        d_ = s.recv(1 << 20)
        if not d_: break
        buf += d_
    s.close()
    h, body = buf.split(b"\r\n\r\n", 1)
    return h.decode("latin1"), body
for port in ports:
    for rnd in range(2):
        for name in ["f%02d.bin" % i for i in range(20)] + ["s%02d.bin" % i for i in range(10)]:
            want = open(os.path.join(d, name), "rb").read()
            for close in (False, True):
                h, body = ask(port, name, close)
                conn = [l for l in h.split("\r\n") if l.lower().startswith("connection:")]
                if body != want: bad.append("%d %s close=%s body %d bytes" % (port, name, close, len(body)))
                if conn != ["Connection: " + ("close" if close else "keep-alive")]: bad.append("%d %s %s" % (port, name, conn))
    h, body = ask(port, "f03.bin", True, head=True)
    if body or "Connection: close" not in h or "Content-Length: 2097152" not in h: bad.append("%d HEAD %r %d" % (port, h[-60:], len(body)))
print(len(bad), "; ".join(bad[:4]))
PY
)
echo "  every file, of 2 MiB and 48 KiB, asked twice of both caches, keep-alive and close: ${out:-nothing} wrong"
case "$out" in "0 "*) ok ;; *) bad "every answer is the file, with the Connection asked for" "$out" ;; esac
rss=$(rss_of "$PM")
echo "  the in-memory cache's worker holds ${rss} MiB for 40 MiB of files"
if [ "$sanitized" = 1 ]; then echo "  SKIP [memory]: a resident size measures the sanitizer's quarantine, not the cache"
elif [ "${rss:-999}" -lt 70 ]; then ok
else bad "a body is kept once in memory" "${rss} MiB"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
