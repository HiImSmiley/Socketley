#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: --http keeps a large file's descriptor between requests, and answers with the file under the name.
#
# What each part would catch:
#   * a kept descriptor served after the file was changed in place, replaced by a rename, deleted, or swapped for a
#     symlink out of the root: the old bytes, or bytes from outside, where the name now says otherwise
#   * a kept descriptor shared by downloads whose windows come out of the page cache, read at the file's position:
#     one download moving it under another, so ranges of one cold file asked at once come back with the wrong bytes
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: --http keeps a large file's descriptor, and the file under the name is what is sent ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate httpkept
P=$((SL_PORT_BASE + 1952))
unset SOCKETLEY_CONFIG
# On a disk, not a tmpfs, so a file's pages can be put out of the page cache.
W=$(mktemp -d /var/tmp/socketley-kept-XXXXXX)
trap 'daemon_stop; rm -rf "$W"' EXIT
mkdir -p "$W/www" "$W/got"
head -c 300000 /dev/urandom > "$W/www/f.bin"
head -c 300000 /dev/urandom > "$W/outside.bin"
daemon_start "$BIN"
"$BIN" create server kept -p "$P" --http "$W/www" -s >/dev/null 2>&1
for _ in $(seq 1 50); do ss -ltnH "( sport = :$P )" | grep -q . && break; sleep 0.1; done
U="http://127.0.0.1:$P/f.bin"
same() { curl -s -m 10 -o "$W/got/x" "$U" && cmp -s "$W/got/x" "$1"; }

same "$W/www/f.bin" && same "$W/www/f.bin" && ok || bad "the file is sent, and again from the kept descriptor" "bytes differ"

# The same size and inode, other bytes and another time: the bytes are the inode's either way, the validator is not.
etag() { curl -s -m 10 -o /dev/null -D - "$U" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}'; }
was=$(etag)
head -c 300000 /dev/urandom > "$W/new"
dd if="$W/new" of="$W/www/f.bin" bs=300000 count=1 conv=notrunc status=none
touch -d '2001-01-01 00:00:00' "$W/www/f.bin"
now=$(etag)
if same "$W/www/f.bin" && [ -n "$now" ] && [ "$now" != "$was" ]; then ok
else bad "a file changed in place is sent under a validator of its own" "ETag '$was' then '$now'"; fi

head -c 300000 /dev/urandom > "$W/www/f.bin.new"; mv "$W/www/f.bin.new" "$W/www/f.bin"
same "$W/www/f.bin" && ok || bad "a file replaced by a rename is the new one" "bytes differ"

rm "$W/www/f.bin"
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$U")
if [ "$code" = 404 ]; then ok; else bad "a deleted file is gone" "got $code"; fi

ln -s "$W/outside.bin" "$W/www/f.bin"
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$U")
if [ "$code" = 404 ]; then ok; else bad "a symlink out of the root put under a kept name is refused" "got $code"; fi
rm "$W/www/f.bin"

# Ranges of one cold file at once: each one's windows come out of the disk through the pipe, from one kept descriptor.
head -c $((32 << 20)) /dev/urandom > "$W/www/big.bin"
curl -s -m 30 -o /dev/null "http://127.0.0.1:$P/big.bin"
sync
python3 - "$W/www/big.bin" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY); os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED); os.close(fd)
PY
pids=()
for i in $(seq 0 7); do
    a=$((i * (4 << 20) + 12345)); b=$((a + (3 << 20)))
    curl -s -m 60 --limit-rate 8M -r "$a-$b" -o "$W/got/r$i" "http://127.0.0.1:$P/big.bin" & pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
whole=0
for i in $(seq 0 7); do
    a=$((i * (4 << 20) + 12345)); n=$(((3 << 20) + 1))
    [ "$(stat -c %s "$W/got/r$i" 2>/dev/null)" = "$n" ] && cmp -s -i "$a:0" -n "$n" "$W/www/big.bin" "$W/got/r$i" &&
        whole=$((whole + 1))
done
if [ "$whole" = 8 ]; then ok; else bad "eight ranges of one cold file asked at once are each their own bytes" "$whole of 8"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
