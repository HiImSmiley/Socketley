#!/usr/bin/env bash
# Integration test: a server answering HTTP ends a client that asked to close
# on that client's own FIN, and still ends one that never sends it
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# After the answer to a Connection: close request the connection, its FIN out,
# had only its armed read left, so it was finished at once: the read was
# cancelled and the descriptor handed to orderly_close, which shut the write
# side a second time, asked TCP_INFO and polled the socket on a timer until the
# client had closed -- a cancel, a timeout and four syscalls per connection.
# The read now stays armed behind our FIN, as a refused request's drain does,
# and takes the client's FIN itself; the descriptor is then closed at once.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a client that asked to close and then keeps its end open, silent, is
#     closed by the server within seconds -- the drain this rides on left
#     without its deadline, or with only the idle sweep's thirty seconds
#   * fifty clients that ask to close and close get every byte of a cached
#     answer and of one read from disk -- a close taken for the client's FIN
#     while bytes of the answer were unsent
#   * the same connections, kept alive, are untouched: three requests on one
#
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a server answering HTTP ends a closing client on its own FIN ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 1637)); PD=$((P + 1))

# Every body is a pattern that names its own offset, so a short or shifted answer cannot pass for a whole one.
mkdir -p "$WORK/site"
python3 - "$WORK/site" <<'PY'
import sys
for name, n in (("small.bin", 1000), ("big.bin", 300000)):
    open(sys.argv[1] + "/" + name, "wb").write(bytes((i * 7 + i // 251) & 0xff for i in range(n)))
PY

daemon_isolate "srvclosefin"
daemon_start "$BIN"
"$BIN" create server hc -p "$P" --bind 127.0.0.1 --http "$WORK/site" --http-cache -s >/dev/null 2>&1 || true
"$BIN" create server hd -p "$PD" --bind 127.0.0.1 --http "$WORK/site" -s >/dev/null 2>&1 || true
for port in "$P" "$PD"; do
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$port " && break; sleep 0.1; done
done

cat > "$WORK/close.py" <<'PY'
import socket, sys, time
port, path, n, mode = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
want = bytes((i * 7 + i // 251) & 0xff for i in range(n))
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(10)
conn = b"keep-alive" if mode == "alive" else b"close"
def ask():
    s.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: x\r\nConnection: " + conn + b"\r\n\r\n")
buf = b""
def answer():
    global buf
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: return None
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    while len(rest) < n:
        d = s.recv(65536)
        if not d: break
        rest += d
    buf = rest[n:]
    return rest[:n]
if mode == "alive":
    for k in range(3):
        ask()
        b = answer()
        if b != want:
            print("request %d: %s" % (k, "nothing" if b is None else "%d bytes, %s" % (len(b), "intact" if b == want[:len(b)] else "corrupt")))
            sys.exit()
    print("ok"); sys.exit()
ask()
try: b = answer()
except OSError as e: print("%s while reading" % type(e).__name__); sys.exit()
if b != want:
    print("short or corrupt: %s" % ("nothing" if b is None else "%d bytes" % len(b))); sys.exit()
if mode == "go":
    s.close(); print("ok"); sys.exit()
# Silent for 4 s, which a closed end then answers with a reset: the server's FIN came with the answer, and its close
# of a silent socket sends nothing more.
time.sleep(4)
try:
    for x in (b"x", b"y", b"z"):
        s.sendall(x); time.sleep(0.3)
    print("still open after 4 s")
except OSError:
    print("closed")
PY

# ── a client that asked to close and keeps its end open ─────────────────────
GOT=$(timeout 30 python3 "$WORK/close.py" "$P" /small.bin 1000 keep 2>&1) || true
case "$GOT" in closed) pass ;; *) fail "a closing client that keeps its end open is closed by the server" "$GOT" ;; esac

# ── clients that ask to close and close ─────────────────────────────────────
for spec in "$P /small.bin 1000 cached" "$P /big.bin 300000 cached" "$PD /small.bin 1000 disk" "$PD /big.bin 300000 disk"; do
    set -- $spec
    OK=0; LAST=""
    for _ in $(seq 1 50); do
        GOT=$(timeout 10 python3 "$WORK/close.py" "$1" "$2" "$3" go 2>&1) || true
        if [ "$GOT" = ok ]; then OK=$((OK+1)); else LAST=$GOT; fi
    done
    if [ "$OK" = 50 ]; then pass
    else fail "50 closing clients get their whole answer ($4, $3 bytes)" "$OK of 50" "$LAST"; fi
done

# ── and a kept-alive one is untouched ───────────────────────────────────────
GOT=$(timeout 10 python3 "$WORK/close.py" "$P" /small.bin 1000 alive 2>&1) || true
case "$GOT" in ok) pass ;; *) fail "three requests on one kept-alive connection" "$GOT" ;; esac

daemon_stop

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
