#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories and port window, so it runs beside the others
# Integration test: a sync runtime brings a file larger than one range from a storage, whole and with its bytes.
#
# What it would catch: a range asked for in 8 MiB and read by a client that refused any answer over 1 MiB, so every
# file past about a megabyte was never brought, its fetch failing and retried for ever.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a sync runtime brings a large file from a storage ==="
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }
daemon_isolate syncbig
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1964))
DST="$T/dst"; mkdir -p "$DST"
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
KEY=AKIASYNCBIG000000000; SEC=syncbigsecretsyncbigsecret000000
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/media"
MIB=${MIB:-40}
head -c $((MIB << 20)) /dev/urandom > "$T/big.bin"
head -c 3000 /dev/urandom > "$T/small.bin"
S -o /dev/null -T "$T/big.bin" "http://127.0.0.1:$P/media/big.bin"
S -o /dev/null -T "$T/small.bin" "http://127.0.0.1:$P/media/small.bin"
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"; chmod 600 "$T/creds"

t0=$(mono_ns)
"$BIN" create sync down --dir "$DST" --storage "http://127.0.0.1:$P/media" --credentials "$T/creds" --mode in \
    --every 60s -s >/dev/null 2>&1
for _ in $(seq 1 600); do cmp -s "$DST/big.bin" "$T/big.bin" && break; sleep 0.05; done
ms=$(( ($(mono_ns) - t0) / 1000000 ))
cmp -s "$DST/small.bin" "$T/small.bin" && ok || bad "a small file is brought" "$(ls -la "$DST" | tail -3)"
if cmp -s "$DST/big.bin" "$T/big.bin"; then
    ok
    echo "  $MIB MiB brought in $ms ms, $(( MIB * 1000 / (ms > 0 ? ms : 1) )) MiB/s"
else
    bad "a $MIB MiB file is brought whole" "$(ls -la "$DST" | tail -3); $("$BIN" stats down 2>&1 | grep -iE 'fail|error|note' | head -3)"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
