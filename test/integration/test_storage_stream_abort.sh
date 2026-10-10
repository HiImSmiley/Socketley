#!/usr/bin/env bash
# Integration test: a streamed GET whose client goes away mid-read leaves the
# storage runtime whole.
#
# A body too large to send at once is read from its file a chunk at a time into
# a buffer the connection owns, and the client can leave while such a read is
# in flight.  The read then completes into a connection that is being torn
# down, which only the sanitizer sees directly; outside it the runtime has to
# go on serving, in the same process, with every byte of the next read right.
# Over TLS and over HTTP/2 because those are the paths that read rather than
# splice.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgabort
P1=$((SL_PORT_BASE+1885))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

cleanup() {
    "$BIN" stop stgabort >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgabort >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a streamed GET abandoned mid-read ==="
for tool in openssl curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  SKIP: $tool is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
done
if ! curl -V | grep -q HTTP2; then echo "  SKIP: curl has no HTTP/2"; echo "  Results: 0/0 passed (0 failed)"; exit 0; fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/key.pem" -out "$T/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

daemon_start "$BIN"
"$BIN" create storage stgabort -p "$P1" --dir "$T/data" --anonymous --tls --cert "$T/cert.pem" --key "$T/key.pem" -s \
    >/dev/null 2>&1 || bad "create" "the TLS runtime was not created"
U="https://localhost:$P1"
tc() { curl -s --cacert "$T/cert.pem" "$@"; }
for _ in $(seq 1 100); do [ "$(tc -m 5 -o /dev/null -w '%{http_code}' "$U/")" = 200 ] && break; sleep 0.1; done

head -c 33554432 /dev/urandom > "$T/big"
expect "a bucket is made" "$(tc -m 30 -o /dev/null -w '%{http_code}' -X PUT "$U/abrt")" 200
expect "32 MiB is put" "$(tc -m 60 -o /dev/null -w '%{http_code}' -T "$T/big" "$U/abrt/big")" 200

PID0=$("$BIN" stats stgabort 2>/dev/null | sed -n 's/^pid://p')

# Each reader takes a little and leaves, which is a close in the middle of the body with a file read likely out.
# Waited for by pid, since the daemon is a job of this shell too.
for round in 1 2 3 4; do
    PIDS=()
    for _ in $(seq 1 6); do
        tc -m 10 --http1.1 "$U/abrt/big" 2>/dev/null | head -c 70000 >/dev/null & PIDS+=($!)
        tc -m 10 --http2 "$U/abrt/big" 2>/dev/null | head -c 70000 >/dev/null & PIDS+=($!)
        tc --http2 --limit-rate 2M -m 0.4 -o /dev/null "$U/abrt/big" 2>/dev/null & PIDS+=($!)
    done
    # Several streams on one HTTP/2 connection, all cut together when the transfer is timed out.
    tc --http2 --parallel --parallel-immediate -m 0.5 -o /dev/null -o /dev/null -o /dev/null -o /dev/null \
        "$U/abrt/big" "$U/abrt/big" "$U/abrt/big" "$U/abrt/big" 2>/dev/null & PIDS+=($!)
    wait "${PIDS[@]}" 2>/dev/null
    [ "$round" -lt 4 ] && sleep 0.2
done

PID1=$("$BIN" stats stgabort 2>/dev/null | sed -n 's/^pid://p')
if [ -n "$PID0" ] && [ "$PID0" = "$PID1" ]; then ok "the runtime is the same process after every reader left"
else bad "the runtime is the same process after every reader left" "pid before '${PID0:-none}', after '${PID1:-none}'"; fi

expect "and reads the object back byte for byte over HTTP/1.1" \
    "$(tc -m 60 --http1.1 "$U/abrt/big" | cmp -s - "$T/big" && echo same)" same
expect "and over HTTP/2" "$(tc -m 60 --http2 "$U/abrt/big" | cmp -s - "$T/big" && echo same)" same

if ! grep -qiE "AddressSanitizer|SEGV|SUMMARY: .*Sanitizer|runtime error:" "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "nothing in the log says memory went wrong"
else
    bad "nothing in the log says memory went wrong" \
        "$(grep -iE 'AddressSanitizer|SEGV|Sanitizer|runtime error:' "$SOCKETLEY_DLOG" | head -1)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
