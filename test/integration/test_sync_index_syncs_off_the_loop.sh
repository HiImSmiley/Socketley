#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories, port window and device-mapper device, so it runs beside the others
# Integration test: a sync job's index is synced through the ring, so a disk that takes a second over each sync does
# not hold up the job's own loop: what inotify names is carried while the index is synced.
#
# A sync job runs in a worker of its own, one loop for its walks, its listings, its exchanges, its inotify and the
# daemon's link to it. It syncs its index at the end of each walk and each listing, and that fdatasync was made on
# the loop: on a busy disk it took 15 to 1,900 ms, and a file written meanwhile waited that long to be carried.
#
# What each part would catch:
#   * an fdatasync of the index on the loop: a file written here while the index is synced is carried only after it
#   * a listing that never ends, or records lost on the way to the index: a restart that brings the files again
#   * a rewrite of the index left beside it
# The index's directory is a device-mapper `delay` device whose flushes each wait DELAY_MS, mounted here with sudo -n
# and taken down by this test's own trap; the job's directory and the storage live on tmpfs where there is one, so
# the only slow disk is the index's. Skipped, not failed, where sudo -n or the delay target is missing.
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

echo "=== Integration: a sync job's index is synced off the loop ==="
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }
if ! sudo -n dmsetup targets 2>/dev/null | grep -q '^delay'; then
    sudo -n modprobe dm-delay 2>/dev/null
    sudo -n dmsetup targets 2>/dev/null | grep -q '^delay' ||
        { echo "  SKIP: no sudo -n dmsetup with the delay target, so no slow disk can be made"; exit 0; }
fi
command -v mkfs.ext4 >/dev/null 2>&1 || { echo "  SKIP: mkfs.ext4 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1

daemon_isolate syncslow
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1005))
DELAY_MS=1000
DM="socketley-syncslow-$$"
IMG="$T/slow.img"
LOOPDEV=""; DMUP=0; MNT=""
unset SOCKETLEY_CONFIG

cleanup() {
    # The daemon goes first, since it holds the index open, and the device is unmounted before daemon_stop removes the
    # state directory, which would otherwise reach into it.
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        kill "$SOCKETLEY_DPID" 2>/dev/null
        for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    fi
    # Only what this test made, by the names it chose.
    [ -n "$MNT" ] && { sudo -n umount "$MNT" 2>/dev/null || sudo -n umount -l "$MNT" 2>/dev/null || echo "  WARN: could not unmount $MNT"; }
    [ "$DMUP" = 1 ] && { sudo -n dmsetup remove "$DM" 2>/dev/null || sudo -n dmsetup remove --force "$DM" 2>/dev/null || echo "  WARN: could not remove $DM"; }
    [ -n "$LOOPDEV" ] && { sudo -n losetup -d "$LOOPDEV" 2>/dev/null || echo "  WARN: could not detach $LOOPDEV"; }
    rm -f "$IMG"
    [ -n "${F:-}" ] && [ "$F" != "$T" ] && rm -rf "$F"
    daemon_stop
}
trap cleanup EXIT

truncate -s 64M "$IMG"
LOOPDEV=$(sudo -n losetup -f --show "$IMG" 2>/dev/null) || { LOOPDEV=""; echo "  SKIP: no loop device"; exit 0; }
SECTORS=$(sudo -n blockdev --getsz "$LOOPDEV")
# Reads and writes at once, every flush -- what an fdatasync waits for -- DELAY_MS later.
if ! sudo -n dmsetup create "$DM" --table "0 $SECTORS delay $LOOPDEV 0 0 $LOOPDEV 0 0 $LOOPDEV 0 $DELAY_MS" 2>/dev/null; then
    echo "  SKIP: this kernel's delay target takes no flush delay"; exit 0
fi
DMUP=1
sudo -n mkfs.ext4 -q -F -E nodiscard "/dev/mapper/$DM" >/dev/null 2>&1 || { bad "mkfs" "the slow device takes no ext4"; exit 1; }

daemon_start "$BIN"
# The state directory of this daemon's socket, named for it beside the default one.
STATE=$(ls -d "$HOME"/.local/share/socketley/runtimes.* 2>/dev/null | head -1)
[ -n "$STATE" ] || STATE=$(ls -d "$HOME"/.local/share/socketley/runtimes 2>/dev/null)
[ -n "$STATE" ] || { bad "state" "the daemon made no state directory under $HOME"; exit 1; }
mkdir -p "$STATE/sync"
sudo -n mount -t ext4 "/dev/mapper/$DM" "$STATE/sync" || { bad "mount" "the slow device could not be mounted"; exit 1; }
MNT="$STATE/sync"
sudo -n chown "$(id -u):$(id -g)" "$MNT"
chmod 700 "$MNT"

# The device is what the test says it is: one synced write takes the flush delay.
t0=$(mono_ms)
dd if=/dev/zero of="$MNT/probe" bs=4k count=1 oflag=dsync status=none
slow=$(( $(mono_ms) - t0 ))
rm -f "$MNT/probe"
echo "  one synced 4 KiB write to the index's disk: $slow ms"
[ "$slow" -ge $((DELAY_MS * 8 / 10)) ] && ok || { bad "the disk is slow" "$slow ms, not ~$DELAY_MS"; exit 1; }

# Where the files of both sides go: tmpfs when the box has one.
F=$T
if [ "$(stat -f -c %T /dev/shm 2>/dev/null)" = tmpfs ] && [ -w /dev/shm ]; then F=$(mktemp -d /dev/shm/socketley-syncslow-XXXXXX); fi
[ "$F" = "$T" ] && echo "  note: no tmpfs, so the gaps below take in the disk's own syncs"
KEY=AKIASYNCSLOW00000000; SEC=syncslowsecretsyncslowsecret0000
"$BIN" create storage box -p "$P" --dir "$F/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/media"
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"; chmod 600 "$T/creds"
# Half the files one folder down, so a folder below --dir is synced as well as --dir itself.
mkdir -p "$F/src/sub" "$F/dst"

# Walked every second, so the index is synced every second while files come.
"$BIN" create sync up --dir "$F/src" --storage "http://127.0.0.1:$P/media" --credentials "$T/creds" --mode out \
    --every 1s -s >/dev/null 2>&1
sleep 1.5
N=40
name() { [ $(($1 % 2)) = 0 ] && echo "sub/f$1.txt" || echo "f$1.txt"; }
for i in $(seq 1 "$N"); do printf 'file %s' "$i" > "$F/src/$(name "$i")"; sleep 0.15; done
# An object is <dir>/<bucket>/data/<2 hex>/<sha256 of its key>, renamed in once whole: its change time is when it
# was carried, and the file's own is when it was written -- the gap is the job's, not this test's polling.
objs=()
for i in $(seq 1 "$N"); do h=$(name "$i" | tr -d '\n' | sha256sum | cut -c1-64); objs+=("$F/stg/media/data/${h:0:2}/$h"); done
for _ in $(seq 1 150); do stat "${objs[@]}" >/dev/null 2>&1 && break; sleep 0.1; done
if stat "${objs[@]}" >/dev/null 2>&1; then
    ok
    worst=0; over=0
    for i in $(seq 1 "$N"); do
        gap=$(awk -v w="$(stat -c %.9Z "$F/src/$(name "$i")")" -v c="$(stat -c %.9Z "${objs[$((i - 1))]}")" 'BEGIN { printf "%d", (c - w) * 1000 }')
        [ "$gap" -gt "$worst" ] && worst=$gap
        [ "$gap" -gt $((DELAY_MS / 2)) ] && over=$((over + 1))
    done
    echo "  $N files written 150 ms apart beside an index synced every second: the slowest carried $worst ms after it was written, $over over $((DELAY_MS / 2)) ms"
    if [ "$sanitized" = 1 ]; then echo "  SKIP [loop held]: milliseconds measure the sanitizer, not the loop"
    elif [ "$over" = 0 ]; then ok
    else bad "the job's loop is not held by its index's sync" "$over of $N files waited over $((DELAY_MS / 2)) ms, the worst $worst"; fi
else
    bad "every file is carried" "$(ls "$F/stg/media/data" 2>/dev/null | wc -l) folders of objects"
fi
for _ in $(seq 1 30); do stats=$("$BIN" stats up 2>/dev/null); echo "$stats" | grep -q "^indexed:$N\$" && break; sleep 0.1; done
echo "$stats" | grep -q "^indexed:$N\$" && ok || bad "the index holds every file carried" "$(echo "$stats" | grep -E '^(indexed|carried|last_error):' | tr '\n' ' ')"
[ -s "$MNT/up.index" ] && ok || bad "the index is on the slow disk" "$(ls -la "$MNT")"

# The other way: brought, each recorded once its folder is synced, and the listing over for all that.
"$BIN" create sync down --dir "$F/dst" --storage "http://127.0.0.1:$P/media" --credentials "$T/creds" --mode in \
    --every 1s -s >/dev/null 2>&1
got() { find "$F/dst" -name 'f*.txt' | wc -l; }
for _ in $(seq 1 100); do [ "$(got)" -ge "$N" ] && break; sleep 0.1; done
[ "$(got)" = "$N" ] && ok || bad "the listing brings every file" "$(got) of $N"
for _ in $(seq 1 30); do stats=$("$BIN" stats down 2>/dev/null); echo "$stats" | grep -q "^indexed:$N\$" && break; sleep 0.1; done
echo "$stats" | grep -q "^indexed:$N\$" && echo "$stats" | grep -q '^failures:0$' && ok ||
    bad "the index holds every file brought, each recorded once its folder is synced" "$(echo "$stats" | grep -E '^(indexed|brought|failures|last_error):' | tr '\n' ' ')"
# Removed from the storage: removed here, and recorded gone once its folder is synced.
S -o /dev/null -X DELETE "http://127.0.0.1:$P/media/f1.txt"
S -o /dev/null -X DELETE "http://127.0.0.1:$P/media/sub/f2.txt"
for _ in $(seq 1 60); do [ ! -e "$F/dst/f1.txt" ] && "$BIN" stats down 2>/dev/null | grep -q "^indexed:$((N - 2))\$" && break; sleep 0.1; done
[ ! -e "$F/dst/f1.txt" ] && [ ! -e "$F/dst/sub/f2.txt" ] && "$BIN" stats down 2>/dev/null | grep -q "^indexed:$((N - 2))\$" &&
    "$BIN" stats down 2>/dev/null | grep -q '^failures:0$' && ok ||
    bad "a file the storage removed is removed here and forgotten" "$("$BIN" stats down | grep -E '^(indexed|removed_here|failures|last_error):' | tr '\n' ' ')"

# Stopped while a sync may be in the ring, and started again: what was recorded is read back, nothing is brought a
# second time and nothing is kept twice.
"$BIN" stop down >/dev/null 2>&1
"$BIN" start down >/dev/null 2>&1
sleep 3
stats=$("$BIN" stats down 2>/dev/null)
echo "$stats" | grep -q '^brought:0$' && echo "$stats" | grep -q "^indexed:$((N - 2))\$" && ok ||
    bad "a restart reads what was recorded" "$(echo "$stats" | grep -E '^(indexed|brought|conflicts|last_error):' | tr '\n' ' ')"
[ -z "$(find "$F/dst" -name '*conflict*')" ] && ok || bad "nothing is kept twice" "$(find "$F/dst" -name '*conflict*' | head -3)"
[ -z "$(ls "$MNT" | grep '\.new$')" ] && ok || bad "no rewrite is left beside the index" "$(ls "$MNT")"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
