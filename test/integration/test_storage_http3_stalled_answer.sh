#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: an HTTP/3 answer the storage gives up on is reset, and nothing of it is sent afterwards.
#
# What it would catch:
#   * a stream let go by the write stall while QUIC still holds its answer's bytes for sending: the client that had
#     held the answer back by its window was then sent whatever lay in that memory by the time it opened the window
#     again (another request's bytes among them), or the worker died reading it
#   * the storage's stall not following SOCKETLEY_WRITE_STALL_SECS, which is what lets this run in seconds
#
# Skipped when the binary was built without HTTP/3 or the python aioquic library is missing.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgh3stall
P1=$((SL_PORT_BASE+1880))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
skip() { echo "  SKIP: $1"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
trap daemon_stop EXIT

echo "=== Integration: an HTTP/3 answer given up on is reset ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || skip "$tool is not available"
done
python3 -c 'import aioquic, sys; sys.exit(int(aioquic.__version__.split(".")[0]) < 1)' 2>/dev/null \
    || skip "the python aioquic library 1.0 or later is not installed (pip install aioquic)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/key.pem" -out "$T/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# The daemon hands its environment to the runtimes it starts: a client takes nothing of its answer for three seconds.
SOCKETLEY_WRITE_STALL_SECS=3 daemon_start "$BIN"
"$BIN" create storage stall -p "$P1" --dir "$T/data" --anonymous --tls --cert "$T/cert.pem" --key "$T/key.pem" -s \
    >/dev/null 2>&1 || bad "create" "the TLS runtime was not created"
U="https://localhost:$P1"
for _ in $(seq 1 100); do [ "$(curl -s -m 5 --cacert "$T/cert.pem" -o /dev/null -w '%{http_code}' "$U/")" = 200 ] && break; sleep 0.1; done
stat_of() { "$BIN" stats stall 2>/dev/null | awk -F: -v k="$1" '$1==k {s+=$2} END {print s+0}'; }
for _ in $(seq 1 50); do [ "$(stat_of h3)" -ge 1 ] && break; sleep 0.1; done
[ "$(stat_of h3)" -ge 1 ] || skip "this build has no HTTP/3 (scripts/build-thirdparty.sh http3, then rebuild)"

curl -s -m 10 --cacert "$T/cert.pem" -X PUT "$U/stall" >/dev/null
head -c 200000 /dev/urandom > "$T/obj"
expect "the object is put" "$(curl -s -m 20 --cacert "$T/cert.pem" -T "$T/obj" -o /dev/null -w '%{http_code}' "$U/stall/obj")" 200

# The client lets 2 KiB of the answer through and no more for ten seconds, keeps the connection alive, puts and
# reads other objects meanwhile, then opens its window.
got=$(timeout 120 python3 "$HERE/lib_storage_http3_edge.py" stalled "$P1" "$T/cert.pem" /stall/obj 10 2>&1 | tail -1)
expect "an answer held back past the write stall is reset, and none of it follows" "$got" "reset"
expect "and the runtime still serves" \
    "$(curl -s -m 20 --cacert "$T/cert.pem" "$U/stall/obj" | cmp -s - "$T/obj" && echo same || echo differs)" same
[ "$(stat_of timeouts)" -ge 1 ] && ok "stats counts the stream it gave up" || bad "timeouts" "$(stat_of timeouts)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
