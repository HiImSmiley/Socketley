#!/usr/bin/env bash
# Integration test: a request refused while its body is still arriving gets
# the refusal, not a reset
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# An --http server answers a body past its bound with 413 and closes.  It sent
# its FIN with the read still armed, but the reachability rule counts an armed
# read on a closing connection as owed to nobody, so the next completion closed
# the socket with the rest of the body unread -- and a close with unread data
# is a reset, which the client's kernel delivers ahead of the 413 it had not
# read yet.  test_http_body_streams_to_the_script.sh saw it only under the
# suite's load, as a lost 413.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * any of 64 concurrent 2 MB uploads cut off while still sending, or not
#     reading its 413 status line
#   * the server still serving afterwards
#   * and a refused peer that keeps its connection being drained for a while
#     and then cut off, so a drain cannot hold a slot as long as it likes
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

echo "=== Integration: a refusal mid-body reaches the client ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 135))
mkdir -p "$WORK/www"; echo ok > "$WORK/www/index.html"
daemon_isolate refusalbody
daemon_start "$BIN"
"$BIN" create server rb -p "$P" --http "$WORK/www" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

OUT=$(timeout 120 python3 - "$P" "${UPLOADS:-64}" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
body = b"u" * (2 * 1024 * 1024)
head = ("POST /upload HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\n\r\n" % len(body)).encode()
res = {}
N = int(sys.argv[2]) if len(sys.argv) > 2 else 64
def one(i):
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(20)
    got = b""
    try:
        # A send refused is the failure itself: a client library stops there
        # and never reads the answer that was waiting for it.
        s.sendall(head)
        s.sendall(body)
        while b"\r\n" not in got:
            c = s.recv(65536)
            if not c: break
            got += c
        res[i] = got.split(b"\r\n", 1)[0].decode(errors="replace")
    except OSError as e:
        res[i] = "ERR:" + type(e).__name__
    finally:
        s.close()
ts = [threading.Thread(target=one, args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()
ok = sum(1 for v in res.values() if v.startswith("HTTP/1.1 413"))
other = sorted(set(v for v in res.values() if not v.startswith("HTTP/1.1 413")))
print("%d %s" % (ok, ";".join(other) or "-"))
PY
) || OUT="0 python-failed"
read -r GOT OTHER <<<"$OUT"
N=${UPLOADS:-64}
echo "  $N uploads of 2 MB: $GOT sent whole and read their 413; other outcomes: $OTHER"

# ── 1. every refusal is read ────────────────────────────────────────────────
if [ "$GOT" = "$N" ]; then pass
else fail "every client sends its body and reads its 413" "$GOT of $N" "others: $OTHER" \
          "-- closed with the body unread, the reset overtook the answer"; fi

# ── 2. and the server still answers ─────────────────────────────────────────
AFTER=$(timeout 10 python3 - "$P" <<'PY' 2>/dev/null || true
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(5)
s.sendall(b"GET /index.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
d = b""
while True:
    c = s.recv(4096)
    if not c: break
    d += c
print(d.split(b"\r\n", 1)[0].decode())
PY
)
if [ "$AFTER" = "HTTP/1.1 200 OK" ]; then pass
else fail "the server still serves after the refusals" "got '$AFTER'"; fi

# ── 3. a refused peer that keeps the connection is let go ──────────────────
# Our FIN is the EOF it reads; after that the drain reads what it sends until
# the sweep ends it, ten seconds on and at most one 30-second tick later, and
# the next byte it sends then meets a reset.
LINGER=$(timeout 90 python3 - "$P" <<'PY' 2>/dev/null || true
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.sendall(b"POST /upload HTTP/1.1\r\nHost: t\r\nContent-Length: 2097152\r\n\r\n" + b"u" * 65536)
s.settimeout(5)
got = b""
while True:
    c = s.recv(65536)
    if not c: break
    got += c
status = got.split(b"\r\n", 1)[0].decode().replace(" ", "_")
t0 = time.time()
try:
    while time.time() - t0 < 80:
        s.sendall(b"u")
        time.sleep(1)
    print("%s never" % status)
except OSError:
    print("%s %d" % (status, time.time() - t0))
PY
)
read -r LSTATUS LSECS <<<"${LINGER:-none never}"
echo "  a refused peer that keeps sending: '$LSTATUS', cut off after ${LSECS}s"
if [ "$LSTATUS" = "HTTP/1.1_413_Content_Too_Large" ] && [ "$LSECS" != never ] &&
   [ "$LSECS" -ge 5 ] && [ "$LSECS" -le 45 ]; then pass
else fail "a refused peer is drained for a while and then cut off" "'$LSTATUS' after ${LSECS}s" \
          "-- under 5s is no drain at all; never is a drain with no deadline"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
