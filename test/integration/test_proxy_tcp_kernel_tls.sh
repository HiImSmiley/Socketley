#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a --protocol tcp --tls proxy splices what its backend streams to a client through kernel TLS.
#
# What each part would catch:
#   * the splice into a TLS socket the kernel does not encrypt yet, or past what OpenSSL still holds: a stream the
#     client cannot decrypt, or one out of order
#   * the messages after the switch, both ways, lost or reordered: what the client sends is still decrypted here
#   * a client that only exchanges small messages moved at all
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a TLS TCP proxy splices a backend's stream to its client through kernel TLS ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
[ -r /proc/net/tls_stat ] || { echo "  SKIP: the kernel has no TLS layer here (modprobe tls)"; exit 0; }
daemon_isolate tcpktls
T=$SOCKETLEY_TMPD
PB=$((SL_PORT_BASE + 1949)); PT=$((SL_PORT_BASE + 1951))
unset SOCKETLEY_CONFIG
BE_PID=""
trap '[ -n "$BE_PID" ] && kill "$BE_PID" 2>/dev/null; daemon_stop' EXIT

# "bulk N SEED\n" is answered with N bytes of a pattern of its seed, "ping X\n" with "pong X\n".
cat > "$T/be.py" <<'PY'
import socket, sys, threading
def pattern(n, seed):
    block = bytes((i * 31 + seed) % 251 for i in range(65536))
    out = bytearray()
    while len(out) < n:
        out += block
    return bytes(out[:n])
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(64)
def serve(c):
    f = c.makefile("rb")
    with c:
        for line in f:
            w = line.split()
            if w and w[0] == b"bulk":
                c.sendall(pattern(int(w[1]), int(w[2])))
            elif w and w[0] == b"ping":
                c.sendall(b"pong " + w[1] + b"\n")
while True:
    c, _ = l.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
python3 "$T/be.py" "$PB" & BE_PID=$!
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -keyout "$T/k.pem" -out "$T/c.pem" >/dev/null 2>&1
daemon_start "$BIN"
"$BIN" create proxy tp -p "$PT" --protocol tcp --backend "127.0.0.1:$PB" --tls --cert "$T/c.pem" --key "$T/k.pem" -s \
    >/dev/null 2>&1
for p in "$PB" "$PT"; do for _ in $(seq 1 50); do ss -ltnH "( sport = :$p )" | grep -q . && break; sleep 0.1; done; done
tx() { awk '$1=="TlsTxSw" {print $2}' /proc/net/tls_stat; }

cat > "$T/cl.py" <<'PY'
import socket, ssl, sys
port, plan = int(sys.argv[1]), sys.argv[2]
def pattern(n, seed):
    block = bytes((i * 31 + seed) % 251 for i in range(65536))
    out = bytearray()
    while len(out) < n:
        out += block
    return bytes(out[:n])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=20))
def take(n):
    got = bytearray()
    while len(got) < n:
        d = s.recv(min(1 << 20, n - len(got)))
        if not d:
            break
        got += d
    return bytes(got)
fails = []
for i, step in enumerate(plan.split(",")):
    kind, n = step.split(":")
    if kind == "bulk":
        s.sendall(b"bulk %d %d\n" % (int(n), i))
        if take(int(n)) != pattern(int(n), i):
            fails.append("bulk %d" % i)
    else:
        for k in range(int(n)):
            s.sendall(b"ping %d-%d\n" % (i, k))
            want = b"pong %d-%d\n" % (i, k)
            if take(len(want)) != want:
                fails.append("ping %d-%d" % (i, k)); break
s.close()
print("ok" if not fails else " ".join(fails[:3]))
PY

t0=$(tx)
got=$(timeout 60 python3 "$T/cl.py" "$PT" "ping:50")
if [ "$got" = ok ] && [ "$(tx)" = "$t0" ]; then ok
else bad "a client of small messages only stays in user space" "$got, kernel TLS sockets $t0 -> $(tx)"; fi

t0=$(tx)
got=$(timeout 120 python3 "$T/cl.py" "$PT" "bulk:8388608,ping:20,bulk:3000000,ping:5,bulk:65536,bulk:20000000,ping:3")
if [ "$got" = ok ] && [ "$(tx)" = $((t0 + 1)) ]; then ok
else bad "a stream moves its client, and every stream and message after it, both ways, arrives in order" \
    "$got, kernel TLS sockets $t0 -> $(tx)"; fi

pids=(); for i in $(seq 1 6); do timeout 120 python3 "$T/cl.py" "$PT" "bulk:6000000,ping:2,bulk:2000000" > "$T/p$i" & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
n=$(cat "$T"/p* | grep -c '^ok$')
if [ "$n" = 6 ]; then ok; else bad "six moved clients at once each get their own streams" "$n of 6"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
