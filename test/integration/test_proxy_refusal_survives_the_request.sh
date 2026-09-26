#!/usr/bin/env bash
# Integration test: a request the proxy refuses while it is still arriving gets
# the refusal, not a reset
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The proxy answers a header block past its bound with 431 and closes, and
# closed its read side at once: shutdown(SHUT_RD) in queue_final_response, so
# the multishot recv would end.  What the client was still sending then sat
# unread, and the close that followed was a reset -- 62 of 64 clients sending
# a 2 MB header got EPIPE on their send and never read the 431.  The server
# runtime had the same hole; see test_http_refusal_survives_the_body.sh.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * any of 64 concurrent 2 MB header blocks cut off while still sending, or
#     not reading its 431 status line
#   * the proxy still relaying afterwards
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

echo "=== Integration: a proxy refusal mid-request reaches the client ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 137)); BP=$((P + 1))
mkdir -p "$WORK/www"; echo ok > "$WORK/www/index.html"
daemon_isolate proxyrefusal
daemon_start "$BIN"
"$BIN" create server rbe -p "$BP" --http "$WORK/www" -s >/dev/null 2>&1 || true
"$BIN" create proxy rp -p "$P" --backend "127.0.0.1:$BP" --protocol http -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

OUT=$(timeout 120 python3 - "$P" "${UPLOADS:-64}" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
head = b"GET /rp/index.html HTTP/1.1\r\nHost: t\r\nX-Big: "
body = b"a" * (2 * 1024 * 1024) + b"\r\n\r\n"
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
ok = sum(1 for v in res.values() if v.startswith("HTTP/1.1 431"))
other = sorted(set(v for v in res.values() if not v.startswith("HTTP/1.1 431")))
print("%d %s" % (ok, ";".join(other) or "-"))
PY
) || OUT="0 python-failed"
read -r GOT OTHER <<<"$OUT"
N=${UPLOADS:-64}
echo "  $N header blocks of 2 MB: $GOT sent whole and read their 431; other outcomes: $OTHER"

# ── 1. every refusal is read ────────────────────────────────────────────────
if [ "$GOT" = "$N" ]; then pass
else fail "every client sends its header block and reads its 431" "$GOT of $N" "others: $OTHER" \
          "-- closed with the body unread, the reset overtook the answer"; fi

# ── 2. and the proxy still relays ───────────────────────────────────────────
AFTER=$(timeout 10 python3 - "$P" <<'PY' 2>/dev/null || true
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(5)
s.sendall(b"GET /rp/index.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
d = b""
while True:
    c = s.recv(4096)
    if not c: break
    d += c
print(d.split(b"\r\n", 1)[0].decode())
PY
)
if [ "$AFTER" = "HTTP/1.1 200 OK" ]; then pass
else fail "the proxy still relays after the refusals" "got '$AFTER'"; fi

# ── 3. a refused peer that keeps the connection is let go ──────────────────
# Our FIN is the EOF it reads; after that the drain reads what it sends until
# the one-second sweep ends it ten seconds on, and the next byte it sends then
# meets a reset.
LINGER=$(timeout 90 python3 - "$P" <<'PY' 2>/dev/null || true
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.sendall(b"GET /rp/ HTTP/1.1\r\nHost: t\r\nX-Big: " + b"a" * (2 * 1024 * 1024))
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
if [ "$LSTATUS" = "HTTP/1.1_431_Request_Header_Fields_Too_Large" ] && [ "$LSECS" != never ] &&
   [ "$LSECS" -ge 5 ] && [ "$LSECS" -le 20 ]; then pass
else fail "a refused peer is drained for a while and then cut off" "'$LSTATUS' after ${LSECS}s" \
          "-- under 5s is no drain at all; never is a drain with no deadline"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
