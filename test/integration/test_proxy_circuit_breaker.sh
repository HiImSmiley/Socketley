#!/usr/bin/env bash
# Integration test: what the circuit breaker counts as a backend failure.
#
# Both directions matter and are checked here, because a breaker that never
# opens is as wrong as one that opens on healthy traffic:
#
#   a backend that answers and then closes its own connection is healthy —
#   that is HTTP/1.0, Connection: close, and every keep-alive idle timeout
#
#   a backend that closes without answering has failed, and the breaker must
#   still take it out of rotation
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
OK_BE=19901; OK_PROXY=19900
BAD_BE=19911; BAD_PROXY=19910
PASS=0; FAIL=0; TOTAL=0
DAEMON_PID=""; BE_PIDS=()

cleanup() {
    "$BIN" stop cb_ok   2>/dev/null || true
    "$BIN" stop cb_bad  2>/dev/null || true
    sleep 0.3
    "$BIN" remove cb_ok  2>/dev/null || true
    "$BIN" remove cb_bad 2>/dev/null || true
    for p in "${BE_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

echo "=== Integration: proxy circuit breaker ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    echo "  SKIP: python3 and curl are both required"
    exit 0
fi

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"; cleanup' EXIT

# Healthy: answers, then closes. Failing: closes without answering.
cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading
mode, port = sys.argv[1], int(sys.argv[2])
body = b"backend-ok"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)

def serve(c):
    try:
        c.recv(65536)
        if mode == "healthy":
            c.sendall(resp)
    except OSError:
        pass
    finally:
        c.close()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(64)
print("ready", flush=True)
while True:
    try:
        c, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

start_backend() {   # mode, port
    python3 "$TMPD/be.py" "$1" "$2" >"$TMPD/be_$2.log" 2>&1 &
    BE_PIDS+=("$!")
    for _ in $(seq 1 50); do grep -q ready "$TMPD/be_$2.log" 2>/dev/null && return 0; sleep 0.1; done
    return 1
}

count_codes() {     # proxy port, name, requests -> "<n200> <n503>"
    local n200=0 n503=0 code
    for _ in $(seq 1 "$3"); do
        code=$(timeout 4 curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/$2/" 2>/dev/null || true)
        [ "$code" = "200" ] && n200=$((n200+1))
        [ "$code" = "503" ] && n503=$((n503+1))
        sleep 0.15
    done
    echo "$n200 $n503"
}

"$BIN" daemon >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 0.5

start_backend healthy "$OK_BE"  || { echo "  SKIP: healthy backend did not start"; exit 0; }
start_backend failing "$BAD_BE" || { echo "  SKIP: failing backend did not start"; exit 0; }

"$BIN" create proxy cb_ok  -p "$OK_PROXY"  --backend "127.0.0.1:$OK_BE"  -s 2>&1 || true
"$BIN" create proxy cb_bad -p "$BAD_PROXY" --backend "127.0.0.1:$BAD_BE" -s 2>&1 || true
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$OK_PROXY" 2>/dev/null && break; sleep 0.1; done
sleep 0.5

# circuit_threshold defaults to 5, so twelve requests are well past it.
read ok200 ok503 <<< "$(count_codes "$OK_PROXY" cb_ok 12)"
assert_eq "$ok200" "12" "healthy backend stays in rotation despite closing connections"
assert_eq "$ok503" "0"  "healthy backend is never circuit-broken"

read bad200 bad503 <<< "$(count_codes "$BAD_PROXY" cb_bad 10)"
TOTAL=$((TOTAL+1))
if [ "$bad503" -gt 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [failing backend is circuit-broken]: never returned 503 in 10 requests"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
