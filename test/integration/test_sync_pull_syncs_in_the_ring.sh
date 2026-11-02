#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories and port window, so it runs beside the others
# Integration test: a sync runtime bringing many files from a storage syncs each through the ring, so its lanes go on
# while the disk takes the files before.
#
# What each part would catch:
#   * an fsync of every file brought, on the loop, after its last byte: every lane waited for every other's disk, and a
#     thousand files of 4 KiB took five to fifteen seconds to an ext4 disk
#   * a file put at its name before its sync ended, or never: one missing, or one whose bytes are not the storage's
#   * a pull called over while files are still being synced: the temporary files left behind
# The directory brought into is on a disk, not on the tmpfs a test's files usually are, where a sync costs nothing.
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

echo "=== Integration: a sync runtime syncs the files it brings through the ring ==="
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate syncring
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1962))
N=1000
DST=$(mktemp -d /var/tmp/socketley-syncring-XXXXXX)
on_disk=1
[ "$(stat -f -c %T "$DST" 2>/dev/null)" = tmpfs ] && on_disk=0
unset SOCKETLEY_CONFIG
trap 'daemon_stop; rm -rf "$DST"' EXIT
daemon_start "$BIN"
KEY=AKIASYNCRING00000000; SEC=syncringsecretsyncringsecret0000
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/media"
for i in $(seq 1 20); do head -c 4096 /dev/urandom > "$T/blob$i"; done
for i in $(seq 1 "$N"); do
    printf 'url = "http://127.0.0.1:%s/media/d%s/f%s.bin"\nupload-file = "%s/blob%s"\noutput = /dev/null\n' \
        "$P" $((i % 20)) "$i" "$T" $((i % 20 + 1))
done > "$T/cfg"
S -K "$T/cfg" --parallel --parallel-max 16 >/dev/null 2>&1
have=$(S "http://127.0.0.1:$P/media?list-type=2&max-keys=5000" | grep -o '<Key>' | wc -l)
[ "$have" = "$N" ] || { bad "the storage holds the files" "$have of $N"; echo "=== Results: $PASS passed, $FAIL failed ==="; exit 1; }
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"; chmod 600 "$T/creds"

t0=$(mono_ns)
"$BIN" create sync down --dir "$DST" --storage "http://127.0.0.1:$P/media" --credentials "$T/creds" --mode in \
    --every 60s -s >/dev/null 2>&1
for _ in $(seq 1 1200); do [ "$(find "$DST" -name '*.bin' | wc -l)" -ge "$N" ] && break; sleep 0.05; done
ms=$(( ($(mono_ns) - t0) / 1000000 ))
got=$(find "$DST" -name '*.bin' | wc -l)
echo "  $got of $N files of 4 KiB brought to $(stat -f -c %T "$DST") in $ms ms"
[ "$got" = "$N" ] && ok || bad "every file is brought" "$got of $N"
wrong=0
for i in 1 7 333 999 1000; do cmp -s "$DST/d$((i % 20))/f$i.bin" "$T/blob$((i % 20 + 1))" || wrong=$((wrong + 1)); done
[ "$wrong" = 0 ] && ok || bad "each with the storage's bytes" "$wrong of 5 differ"
for _ in $(seq 1 50); do [ -z "$(ls -A "$DST/.socketley-sync" 2>/dev/null)" ] && break; sleep 0.1; done
[ -z "$(ls -A "$DST/.socketley-sync" 2>/dev/null)" ] && ok || bad "no file is left half way" "$(ls "$DST/.socketley-sync" | head -3)"
if [ "$on_disk" = 0 ]; then echo "  SKIP [time]: /var/tmp is a tmpfs, where a sync costs nothing"
elif [ "$sanitized" = 1 ]; then echo "  SKIP [time]: milliseconds measure the sanitizer, not the disk"
elif [ "$ms" -lt 2500 ]; then ok
else bad "the lanes do not wait for each other's syncs" "$ms ms"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
