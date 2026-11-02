#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories and port window, so it runs beside the others
# Integration test: a node of a storage cluster takes another node's counts of a share link off its loop.
#
# What each part would catch:
#   * every count another node told written and synced twice under the link's lock on the loop: beside a hundred
#     counted downloads a second at one node, each request at the other waited for the disk
#   * a count told and not kept, or kept short: the other node's link not at the downloads made
# The nodes' files are on a disk, not on the tmpfs a test's files usually are, where a sync costs nothing.
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

echo "=== Integration: a cluster node takes another's share link counts off its loop ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate clshare
T=$SOCKETLEY_TMPD
D=$(mktemp -d /var/tmp/socketley-clshare-XXXXXX)
on_disk=1
[ "$(stat -f -c %T "$D" 2>/dev/null)" = tmpfs ] && on_disk=0
PA=$((SL_PORT_BASE + 1970)); PB=$((SL_PORT_BASE + 1971))
unset SOCKETLEY_CONFIG
trap 'daemon_stop; rm -rf "$D"' EXIT
cat > "$T/creds" <<EOF
[admin]
AKIACLSHAREADMIN0000:clshareadminsecretclshareadminsecret0000
admin = true
[ann]
AKIACLSHAREANN000000:clshareannsecretclshareannsecretclshare0
EOF
A="AKIACLSHAREANN000000:clshareannsecretclshareannsecretclshare0"
for n in cla clb; do
    printf 'self %s\nnode cla http://127.0.0.1:%s\nnode clb http://127.0.0.1:%s\nkey AKIACLSHARENODES000 clsharenodessecretclsharenodessecret00\n' \
        "$n" "$PA" "$PB" > "$T/$n.cluster"
done
daemon_start "$BIN"
"$BIN" create storage cla -p "$PA" --dir "$D/a" --credentials "$T/creds" --nodes "$T/cla.cluster" -s >/dev/null 2>&1
"$BIN" create storage clb -p "$PB" --dir "$D/b" --credentials "$T/creds" --nodes "$T/clb.cluster" -s >/dev/null 2>&1
for p in "$PA" "$PB"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/")" != 000 ] && break; sleep 0.1; done
done
curl -s -u "$A" -X MKCOL -o /dev/null "http://127.0.0.1:$PA/~dav/ann/"
printf 'x' | curl -s -u "$A" -T - -o /dev/null "http://127.0.0.1:$PA/~dav/ann/f.txt"
mk() { curl -s -u "$A" -X POST -d "$1" "http://127.0.0.1:$PA/~share" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null; }
many=$(mk '{"bucket":"ann","key":"f.txt","max_downloads":100000}')
free=$(mk '{"bucket":"ann","key":"f.txt"}')
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PB/~share/$free?download")" = 200 ] && break; sleep 0.1; done

out=$(timeout 90 python3 - "$PA" "$PB" "$many" "$free" <<'PY'
import socket, sys, threading, time
pa, pb, many, free = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
def get(s, path):
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(65536)
    h, rest = buf.split(b"\r\n\r\n", 1)
    n = int([l.split(b":")[1] for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
    while len(rest) < n: rest += s.recv(65536)
    return int(h.split(b" ")[1])
stop, counted = [False], [0]
def hammer():
    s = socket.create_connection(("127.0.0.1", pa), timeout=30)
    while not stop[0]:
        if get(s, "/~share/%s?download" % many) == 200: counted[0] += 1
th = threading.Thread(target=hammer); th.start()
s = socket.create_connection(("127.0.0.1", pb), timeout=30)
lat, end = [], time.time() + 6
while time.time() < end:
    t = time.perf_counter(); get(s, "/~share/%s?download" % free); lat.append((time.perf_counter() - t) * 1000)
    time.sleep(0.002)
stop[0] = True; th.join()
lat.sort()
print("%.2f %.2f %d" % (lat[len(lat) // 2], lat[-1], counted[0]))
PY
)
read -r p50 worst counted <<<"$out"
echo "  ${counted:-?} downloads counted at one node; a request at the other beside them: ${p50:-?} ms at the median, ${worst:-?} ms at worst"
# The other node's link is at every download made, once what was told has arrived.
seen=0
for _ in $(seq 1 100); do
    seen=$(curl -s -u "$A" "http://127.0.0.1:$PB/~share" | python3 -c 'import json,sys; print(sum(x.get("downloads",0) for x in json.load(sys.stdin) if x.get("id")==sys.argv[1]))' "$many" 2>/dev/null)
    [ "${seen:-0}" = "${counted:-x}" ] && break; sleep 0.1
done
echo "  the other node's link says ${seen:-?} downloads"
[ "${seen:-0}" = "${counted:-x}" ] && [ "${counted:-0}" -gt 0 ] && ok || bad "every count told is kept" "${seen:-?} of ${counted:-?}"
if [ "$on_disk" = 0 ]; then echo "  SKIP [wait]: /var/tmp is a tmpfs, where a sync costs nothing"
elif [ "$sanitized" = 1 ]; then echo "  SKIP [wait]: milliseconds measure the sanitizer, not the disk"
elif awk -v m="${p50:-99}" 'BEGIN{exit !(m < 2)}'; then ok
else bad "a request at the other node does not wait for the counts' syncs" "$out"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
