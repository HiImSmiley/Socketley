#!/usr/bin/env bash
# Integration test: a sync carries to a storage over https, by its host's name, without holding a file in memory.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an https target never reached: the certificate not checked against the
#     host's name, or the name never resolved
#   * a body over TLS sent only once the whole of it had been read: the record
#     layer held every byte, so a sync's worker grew by the size of each file
#     it carried and a large one could take the machine's memory
#   * the bytes arriving other than they are here
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate synctls
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1962))
trap 'daemon_stop' EXIT

echo "=== Integration: a sync over https ==="

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext "subjectAltName=DNS:localhost" \
    -keyout "$T/k.pem" -out "$T/c.pem" 2>/dev/null
# The worker trusts what the daemon was started trusting, and this certificate is its own authority.
export SSL_CERT_FILE="$T/c.pem"
daemon_start "$BIN"
KEY=AKIASYNCOVERTLS00000
SEC=syncovertlssecretsyncovertls0000
"$BIN" create storage box -p "$P" --dir "$T/stg" --tls --cert "$T/c.pem" --key "$T/k.pem" \
    --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
S() { curl -s -m 30 --cacert "$T/c.pem" --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
for _ in $(seq 1 50); do S -o /dev/null "https://localhost:$P/" && break; sleep 0.1; done
S -o /dev/null -X PUT "https://localhost:$P/far"
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"

mkdir -p "$T/src"
head -c $((200*1024*1024)) /dev/urandom > "$T/src/big.bin"
"$BIN" create sync s --dir "$T/src" --storage "https://localhost:$P/far" --credentials "$T/creds" --every never -s \
    >/dev/null 2>&1
st() { "$BIN" stats s 2>/dev/null | sed -n "s/^$1://p"; }
for _ in $(seq 1 240); do [ "$(st carried)" = 1 ] && break; [ -n "$(st last_error)" ] && break; sleep 0.5; done
expect "a file is carried to an https target named by its host" "$(st carried) $(st failures)" "1 0"
[ -n "$(st last_error)" ] && echo "    last_error: $(st last_error)"
expect "and arrives as it is here" \
    "$(S "https://localhost:$P/far/big.bin" | cmp -s - "$T/src/big.bin" && echo same)" same

# The worker's high-water mark, against the 200 MiB the file is: held whole it is all of it and more.
pid=$(st pid)
hwm=$(awk '/^VmHWM:/{print int($2/1024)}' "/proc/$pid/status" 2>/dev/null)
if [ -z "$hwm" ]; then
    bad "the worker's memory can be read" "no /proc/$pid/status"
elif [ "${SOCKETLEY_CONFIG:-}" = Sanitize ] || nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then
    echo "  SKIP: memory under a sanitizer build keeps every freed piece (high-water ${hwm} MiB)"
else
    if [ "$hwm" -lt 100 ]; then ok "the worker never held the file (high-water ${hwm} MiB of a 200 MiB file)"
    else bad "the body is sent as it is read" "the worker's high-water mark is ${hwm} MiB carrying a 200 MiB file"; fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
