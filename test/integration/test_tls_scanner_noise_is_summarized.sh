#!/usr/bin/env bash
# Integration test: handshakes strangers fail are summed up, not logged one by one.
#
# Anyone may open a TLS port, and the scanners that do send HTTP, nothing, or a
# protocol of their own: each failed handshake wrote one or more untagged lines,
# so the log of an exposed runtime was mostly theirs.  They are counted now and
# said as one line a minute, with the reasons that came most often, while a
# connection this side begins and fails is still said at once.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate tlsnoise
PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: strangers' failed handshakes are summed up ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
T="$SOCKETLEY_TMPD"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1

# Two seconds instead of a minute, so the summary can be waited for.
export SOCKETLEY_TLS_FAILURE_REPORT_SECS=2
P=$((SL_PORT_BASE + 1061))
daemon_start "$BIN"
"$BIN" create server noisy -p "$P" --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$P") 2>/dev/null && break; sleep 0.1; done

# What a scanner sends: plain HTTP, a few bytes of nothing in particular, and a connection closed at once.
python3 - "$P" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
def once(payload):
    s = socket.create_connection(("127.0.0.1", port), 3)
    s.settimeout(3)
    if payload:
        s.sendall(payload)
        try:
            s.recv(100)
        except Exception:
            pass
    s.close()
for _ in range(12):
    once(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
for _ in range(6):
    once(b"\x00\x01\x02\x03SSH-2.0-scan\r\n")
for _ in range(4):
    once(b"")
PY

# The summary is said once its window has passed, at the latest at the worker's next turn.
SUM=""
for _ in $(seq 1 60); do
    SUM=$(grep -E "inbound handshakes? failed in the last" "$SOCKETLEY_DLOG" 2>/dev/null || true)
    [ -n "$SUM" ] && [ "$(grep -oE '[0-9]+ inbound handshakes? failed' <<<"$SUM" | awk '{s+=$1} END{print s+0}')" -ge 18 ] && break
    sleep 0.2
done
COUNTED=$(grep -oE '[0-9]+ inbound handshakes? failed' <<<"$SUM" | awk '{s+=$1} END{print s+0}')
LINES=$(grep -cE "inbound handshakes? failed in the last" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$COUNTED" -ge 18 ] && [ "$LINES" -le 3 ]; then pass
else fail "failed handshakes are counted into a summary" "counted $COUNTED in $LINES line(s): $SUM"; fi

if grep -q "http request\|wrong version number\|packet length too long\|unknown protocol" <<<"$SUM"; then pass
else fail "the summary names the reasons" "$SUM"; fi

# None of them on a line of its own at the default level.
EACH=$(grep -cE "handshake failed" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$EACH" -eq 0 ]; then pass
else fail "no failed handshake has a line of its own" "$EACH lines: $(grep -m1 'handshake failed' "$SOCKETLEY_DLOG")"; fi

# A client that speaks TLS is served as before.
if echo | timeout 5 openssl s_client -connect "127.0.0.1:$P" -servername localhost </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then pass
else fail "a TLS client still completes its handshake" "openssl s_client got no certificate"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
