#!/usr/bin/env bash
# Integration test: an HTTP proxy performs the ACTIVE close on Connection: close
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# test_http_active_close.sh is the same fact for --http.  The proxy was never
# made to hold it: a client that asked to close got its answer, the proxy sent
# its FIN only once the write's completion came round again, and by then the
# client had read the answer and closed too.  Measured on 200 sequential
# connection-per-request exchanges through the proxy, the kernel held TIME-WAIT
# on BOTH ends of every connection -- a simultaneous close -- so the client's
# ephemeral port paid for each one; at 32 concurrent clients 80% of them were
# the client's alone.  The client's port pool, not either side's CPU, then sets
# the rate: 17.4k requests/s against 53.9k once the FIN leaves with the data.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the TIME-WAIT rows land on the proxy's fixed port and not on the clients'
#     ephemeral ones -- the defect, read off the kernel rather than our logs
#   * every body arrives whole, because a FIN sent ahead of the last bytes would
#     pass the first assertion and truncate the answer
#   * the same for a body far larger than a socket takes in one send, which is
#     the path where the bytes are queued and the FIN has to wait for them
#   * a keep-alive client is not closed -- without it the first assertion passes
#     against a proxy that closes every connection it answers
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate proxyclose
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: an HTTP proxy performs the active close ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1597))
BP=$((P + 1))
mkdir -p "$WORK/www"
head -c 600 /dev/zero | tr '\0' s > "$WORK/www/small.txt"
head -c 4194304 /dev/zero | tr '\0' L > "$WORK/www/large.txt"
"$BIN" create server pcbe -p "$BP" --http "$WORK/www" --http-cache -s >/dev/null 2>&1 || true
"$BIN" create proxy pc -p "$P" --backend "127.0.0.1:$BP" --protocol http -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do
    ss -ltn 2>/dev/null | grep -q ":$P " && ss -ltn 2>/dev/null | grep -q ":$BP " && break
    sleep 0.1
done
if ! ss -ltn 2>/dev/null | grep -q ":$P "; then
    echo "  FATAL: the proxy never bound $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

# C and not Python, because the defect is a race the client wins by closing as
# soon as it has the body: a Python client reads and closes slowly enough that
# the late FIN still arrives first, and the assertion passed on the tree it was
# written against.
if ! gcc -O2 -o "$WORK/close" "$HERE/lib_close_race.c" 2>"$WORK/cc.log"; then
    echo "  SKIP: no C compiler"; cat "$WORK/cc.log"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

cat > "$WORK/keep.py" <<'PY'
# Two requests on one connection; prints how many were answered.
import socket, sys
port, path, want = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
req = ("GET %s HTTP/1.1\r\nHost: t\r\n\r\n" % path).encode()
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
answered = 0
buf = b""
for _ in range(2):
    s.sendall(req)
    while True:
        head, sep, rest = buf.partition(b"\r\n\r\n")
        if sep and len(rest) >= want:
            buf = rest[want:]; answered += 1; break
        b = s.recv(65536)
        if not b: break
        buf += b
print(answered)
PY

# Counted per 4-tuple, from the client's own port numbers, because a count of
# rows on the proxy's port also holds whatever an earlier run left behind for
# sixty seconds, and those expire in the middle of this one.
tw_sides(){   # ports-file -> "proxy_side client_side"
    ss -tan state time-wait 2>/dev/null | awk -v p="$P" -v f="$1" '
        BEGIN { while ((getline l < f) > 0) mine[l] = 1 }
        NR > 1 { n = split($3, a, ":"); lp = a[n]; n = split($4, b, ":"); rp = b[n]
                 if (lp == p && (rp in mine)) srv++
                 if (rp == p && (lp in mine)) cli++ }
        END { printf "%d %d\n", srv, cli }'
}

N=200
WHOLE=$(timeout 120 "$WORK/close" "$P" /pc/small.txt "$N" 600 2>"$WORK/ports" || echo 0)
sleep 0.5
read -r srv cli < <(tw_sides "$WORK/ports")
echo "  $N close exchanges: TIME-WAIT on the proxy's port $srv, on the clients' $cli"

# ── 1. the rows are the proxy's ─────────────────────────────────────────────
if [ "$srv" -ge $((N * 9 / 10)) ] && [ "$cli" -le $((N / 10)) ]; then pass
else fail "the proxy holds TIME-WAIT, not the client" \
          "proxy-side rows $srv, client-side rows $cli for $N exchanges" \
          "-- a proxy that sends its FIN a turn late closes together with the" \
          "client, and the client's ephemeral port pays for every connection"; fi

# ── 2. and every answer was whole ───────────────────────────────────────────
if [ "$WHOLE" = "$N" ]; then pass
else fail "a FIN never overtakes the answer" "$WHOLE of $N bodies arrived whole"; fi

# ── 3. a body larger than one send is whole too ─────────────────────────────
BIG=$(timeout 120 "$WORK/close" "$P" /pc/large.txt 5 4194304 2>/dev/null || echo 0)
if [ "$BIG" = "5" ]; then pass
else fail "a 4 MiB answer is whole before the FIN" "$BIG of 5 arrived whole" \
          "-- the direct send takes what the socket holds and the rest is queued;" \
          "a FIN sent before the queue drained cuts it"; fi

# ── 4. the control: keep-alive is not closed ────────────────────────────────
KEPT=$(timeout 30 python3 "$WORK/keep.py" "$P" /pc/small.txt 600 || echo 0)
if [ "$KEPT" = "2" ]; then pass
else fail "a keep-alive connection is kept" "$KEPT of 2 requests on one connection answered"; fi

# ── 5. and the answer says so ───────────────────────────────────────────────
# RFC 9112 9.6: the side that closes says close.  The pooled backend answers
# keep-alive, which the proxy passed through to a client it was about to close;
# a keep-alive client must still be told keep-alive.
conn_hdr() {   # Connection value to send, or "" -> the response's Connection value
    python3 - "$P" "$1" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(5)
extra = ("Connection: %s\r\n" % sys.argv[2]) if sys.argv[2] else ""
s.sendall(("GET /pc/small.txt HTTP/1.1\r\nHost: t\r\n%s\r\n" % extra).encode())
d = b""
while b"\r\n\r\n" not in d:
    b = s.recv(65536)
    if not b: break
    d += b
v = [l.split(b":", 1)[1].strip().decode().lower() for l in d.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]
     if l.lower().startswith(b"connection:")]
print(",".join(v) or "none")
PY
}
H=$(conn_hdr close || echo error)
if [ "$H" = "close" ]; then pass
else fail "a client that asked to close is told close" "the response said Connection: $H"; fi
H=$(conn_hdr "" || echo error)
if [ "$H" = "keep-alive" ]; then pass
else fail "a keep-alive client is still told keep-alive" "the response said Connection: $H"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
