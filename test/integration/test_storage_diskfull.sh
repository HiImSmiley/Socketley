#!/usr/bin/env bash
# Integration test: a storage runtime whose disk fills answers an S3 error, keeps
# what it holds and serves again when room comes back.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# On a small tmpfs and on a small ext4 in a loop file, each mounted here with
# sudo -n and unmounted by this test's own trap: an upload larger than the room
# left is answered StorageFull (507) with an S3 document, leaving no object and no
# temporary file; eight more do the same without leaking a descriptor; on a disk
# full to the last block a PUT, a CopyObject, a DELETE and a CreateBucket are
# each answered and the earlier objects are served intact; with the room back the
# same runtime stores again without a restart; eight uploads racing for what is
# left end with whole objects and refusals and nothing between; and a restart sees
# the same keys with the same bytes.
#
# Skipped, not failed, where `sudo -n` cannot mount.  The assertions live in
# lib_storage_diskfull.py.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgfull

PORT1=$((SL_PORT_BASE+1631))
PORT2=$((SL_PORT_BASE+1632))
MNT_TMPFS="$SOCKETLEY_TMPD/tmpfs"
MNT_EXT4="$SOCKETLEY_TMPD/ext4"
IMG="$SOCKETLEY_TMPD/ext4.img"
MOUNTED=()

cleanup() {
    "$BIN" stop stgt >/dev/null 2>&1 || true
    "$BIN" stop stge >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgt >/dev/null 2>&1 || true
    "$BIN" remove stge >/dev/null 2>&1 || true
    # Only what this test mounted, by the paths it chose; a mount in use is left for the next line of the log.
    for m in ${MOUNTED[@]+"${MOUNTED[@]}"}; do
        sudo -n umount "$m" 2>/dev/null || sudo -n umount -l "$m" 2>/dev/null || echo "  WARN: could not unmount $m"
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a full disk under the storage runtime ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
if ! sudo -n true 2>/dev/null; then
    echo "  SKIP: sudo -n is not available, so nothing can be mounted"
    exit 0
fi

mkdir -p "$MNT_TMPFS" "$MNT_EXT4"
if sudo -n mount -t tmpfs -o size=12m,uid="$(id -u)",gid="$(id -g)",mode=0755 tmpfs "$MNT_TMPFS" 2>/dev/null; then
    MOUNTED+=("$MNT_TMPFS")
else
    echo "  SKIP: cannot mount a tmpfs"
    exit 0
fi
HAVE_EXT4=0
if command -v mkfs.ext4 >/dev/null 2>&1 && truncate -s 16M "$IMG" && mkfs.ext4 -q -F "$IMG" >/dev/null 2>&1 &&
   sudo -n mount -t ext4 -o loop "$IMG" "$MNT_EXT4" 2>/dev/null; then
    MOUNTED+=("$MNT_EXT4")
    sudo -n chown "$(id -u):$(id -g)" "$MNT_EXT4"
    HAVE_EXT4=1
else
    echo "  NOTE: no ext4 loop mount here; the tmpfs alone is run"
fi

daemon_start "$BIN"
mkdir -p "$MNT_TMPFS/objects"
if ! "$BIN" create storage stgt -p "$PORT1" --dir "$MNT_TMPFS/objects" --anonymous -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT1/" 2>/dev/null && break
    sleep 0.1
done

rc=0
python3 "$HERE/lib_storage_diskfull.py" tmpfs "$PORT1" "$MNT_TMPFS/objects" "$MNT_TMPFS" stgt || rc=$?

if [ "$HAVE_EXT4" = 1 ]; then
    mkdir -p "$MNT_EXT4/objects"
    if ! "$BIN" create storage stge -p "$PORT2" --dir "$MNT_EXT4/objects" --anonymous -s >/dev/null 2>&1; then
        echo "  FAIL [create]: the ext4 runtime was not created"
        exit 1
    fi
    for _ in $(seq 1 100); do
        curl -s -o /dev/null "http://127.0.0.1:$PORT2/" 2>/dev/null && break
        sleep 0.1
    done
    python3 "$HERE/lib_storage_diskfull.py" ext4 "$PORT2" "$MNT_EXT4/objects" "$MNT_EXT4" stge || rc=$((rc + $?))
fi

if [ "$rc" -ne 0 ]; then
    echo "  FAILED"
    exit "$rc"
fi
echo "  PASSED"
exit 0
