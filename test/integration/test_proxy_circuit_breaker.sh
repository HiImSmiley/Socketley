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
#
#   a backend that writes a fragment of a header block and then half-closes has
#   failed too, and this is the one the breaker could not see.  "The backend
#   answered" was read off the first byte to arrive on the socket, so a peer
#   that stops in the middle of its headers was recorded as a success and kept
#   its whole share of the rotation, handing every client after it the same
#   truncated fragment.  The loss to the client that hits it is unavoidable —
#   those bytes are already on its wire and no status line can be written behind
#   them — but the next client's is not.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate breaker
OK_BE=19901; OK_PROXY=19900
BAD_BE=19911; BAD_PROXY=19910
CUT_BE=19921; CUT_PROXY=19920
PASS=0; FAIL=0; TOTAL=0
BE_PIDS=()

cleanup() {
    "$BIN" stop cb_ok   2>/dev/null || true
    "$BIN" stop cb_bad  2>/dev/null || true
    "$BIN" stop cb_cut  2>/dev/null || true
    sleep 0.3
    "$BIN" remove cb_ok  2>/dev/null || true
    "$BIN" remove cb_bad 2>/dev/null || true
    "$BIN" remove cb_cut 2>/dev/null || true
    for p in "${BE_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    daemon_stop
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

# Healthy: answers, then closes.  Failing: closes without answering.
# Truncated: writes part of a header block — no terminating blank line anywhere
# in it — and half-closes.  One small write, so the proxy reads the whole
# fragment in one completion; that is the state its response scan calls "the
# rest of this header block is still coming", and it never comes.
cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading
mode, port = sys.argv[1], int(sys.argv[2])
body = b"backend-ok"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)
fragment = b"HTTP/1.1 200 OK\r\nX-Partial: yes"

def serve(c):
    try:
        c.recv(65536)
        if mode == "healthy":
            c.sendall(resp)
        elif mode == "truncated":
            c.sendall(fragment)
            c.shutdown(socket.SHUT_WR)
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

daemon_start "$BIN"

start_backend healthy   "$OK_BE"  || { echo "  SKIP: healthy backend did not start"; exit 0; }
start_backend failing   "$BAD_BE" || { echo "  SKIP: failing backend did not start"; exit 0; }
start_backend truncated "$CUT_BE" || { echo "  SKIP: truncating backend did not start"; exit 0; }

create_ok "proxy for the healthy backend created" \
    "$BIN" create proxy cb_ok  -p "$OK_PROXY"  --backend "127.0.0.1:$OK_BE"  -s
create_ok "proxy for the failing backend created" \
    "$BIN" create proxy cb_bad -p "$BAD_PROXY" --backend "127.0.0.1:$BAD_BE" -s
create_ok "proxy for the truncating backend created" \
    "$BIN" create proxy cb_cut -p "$CUT_PROXY" --backend "127.0.0.1:$CUT_BE" -s
# The healthy proxy has to answer before the breaker cases mean anything.
ready_http 127.0.0.1 "$OK_PROXY" "/cb_ok/ready" 20 || true

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

# The truncating backend.  Twelve requests against a threshold of five.
#
# What the client on one of those first requests gets is worth stating, because
# it is worse than a dropped connection and it is not fixable here: the fragment
# is a status line and one header, and a header block ended by the connection
# closing is a complete response by RFC 9112 Section 6.3, so curl reports 200.
# A backend that stopped in the middle of its answer is presented to the client
# as a success with no body.  Those bytes are already on the wire by the time
# the half-close arrives; nothing can be written behind them.
#
# What is fixable is how many clients it happens to.  Five failures open the
# breaker and the proxy answers 503 from there on without dialling the backend
# again.  Before the fix that never happened at any number of requests — the
# first byte of the fragment was recorded as the backend answering, so every one
# of the twelve was a 200 and the breaker's error count never moved.
read cut200 cut503 <<< "$(count_codes "$CUT_PROXY" cb_cut 12)"
TOTAL=$((TOTAL+1))
if [ "$cut503" -gt 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [backend that stops mid-header-block is circuit-broken]:" \
         "never returned 503 in 12 requests"
fi
TOTAL=$((TOTAL+1))
if [ "$cut200" -le 5 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [it is out of rotation within circuit_threshold requests]:" \
         "$cut200 of 12 were served by it, expected at most 5"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
