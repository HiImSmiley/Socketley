#!/usr/bin/env bash
# Integration test: a listing page and a new version cost what they show and write, not what the bucket holds.
#
# ListMultipartUploads copied and sorted every upload of the bucket for each page, ListObjectVersions read every
# version of a key to find a page's marker, and each new version of a key moved every older one; the assertions,
# which compare each cost at 2,000 and at 20,000, live in lib_storage_listing_cost.py.
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stglistcost

P1=$((SL_PORT_BASE+1591))

cleanup() {
    "$BIN" stop lcost >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove lcost >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage listing and version cost ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

if ! "$BIN" create storage lcost -p "$P1" --dir "$SOCKETLEY_TMPD/objects" --anonymous --fsync never -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P1/")" != 000 ] && break
    sleep 0.1
done

python3 "$HERE/lib_storage_listing_cost.py" "$P1"
exit $?
