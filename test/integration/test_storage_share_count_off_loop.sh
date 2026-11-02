#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories and port window, so it runs beside the others
# Integration test: a share link's download is counted off the loop, so the other requests do not wait for the disk.
#
# What each part would catch:
#   * the count written and synced twice under the link's lock on the loop: beside a hundred counted downloads a
#     second, every other request of the runtime waited 7 ms at the median and up to 150 ms
#   * a count taken off the loop that lets more downloads through than the link allows, or fewer
# The storage's files are on a disk, not on the tmpfs a test's files usually are, where a sync costs nothing.
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

echo "=== Integration: a share link's download is counted off the loop ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate sharecount
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1963)); U="http://127.0.0.1:$P"
D=$(mktemp -d /var/tmp/socketley-sharecount-XXXXXX)
on_disk=1
[ "$(stat -f -c %T "$D" 2>/dev/null)" = tmpfs ] && on_disk=0
unset SOCKETLEY_CONFIG
trap 'daemon_stop; rm -rf "$D"' EXIT
daemon_start "$BIN"
cat > "$T/creds" <<EOF
AKIASHARECOUNTOPS000:sharecountopssecretsharecountopssecret00
[ann]
AKIASHARECOUNTANN000:sharecountannsecretsharecountannsecret00
EOF
A="AKIASHARECOUNTANN000:sharecountannsecretsharecountannsecret00"
"$BIN" create storage st -p "$P" --dir "$D/d" --credentials "$T/creds" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done
curl -s -u "$A" -X MKCOL -o /dev/null "$U/~dav/ann/"
printf 'x' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/f.txt"
mk() { curl -s -u "$A" -X POST -d "$1" "$U/~share" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
five=$(mk '{"bucket":"ann","key":"f.txt","max_downloads":5}')
many=$(mk '{"bucket":"ann","key":"f.txt","max_downloads":100000}')
free=$(mk '{"bucket":"ann","key":"f.txt"}')

# Eight at once on a link that allows five.
pids=()
for _ in $(seq 1 8); do curl -s -m 30 -o /dev/null -w '%{http_code}\n' "$U/~share/$five?download" >> "$T/codes" & pids+=($!); done
wait "${pids[@]}"
codes=$(cat "$T/codes")
got=$(sort <<<"$codes" | uniq -c | awk '{printf "%s×%s ", $1, $2}')
echo "  eight downloads at once of a link that allows five: $got"
[ "$(grep -c '^200$' <<<"$codes")" = 5 ] && [ "$(grep -c '^410$' <<<"$codes")" = 3 ] && ok \
    || bad "the link allows exactly five" "$got"
[ "$(curl -s "$U/~share/$five?download" -o /dev/null -w '%{http_code}')" = 410 ] && ok || bad "and none after" "more"

out=$(timeout 60 python3 - "$P" "$many" "$free" <<'PY'
import socket, sys, threading, time
port, many, free = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def get(s, path):
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(65536)
    h, rest = buf.split(b"\r\n\r\n", 1)
    n = int([l.split(b":")[1] for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
    while len(rest) < n: rest += s.recv(65536)
stop, counted = [False], [0]
def hammer():
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    while not stop[0]:
        get(s, "/~share/%s?download" % many); counted[0] += 1
th = threading.Thread(target=hammer); th.start()
s = socket.create_connection(("127.0.0.1", port), timeout=30)
lat, end = [], time.time() + 6
while time.time() < end:
    t = time.perf_counter(); get(s, "/~share/%s?download" % free); lat.append((time.perf_counter() - t) * 1000)
    time.sleep(0.002)
stop[0] = True; th.join()
lat.sort()
print("%.2f %.2f %d" % (lat[len(lat) // 2], lat[-1], counted[0] // 6))
PY
)
read -r p50 worst rate <<<"$out"
echo "  beside ${rate:-?} counted downloads a second: another request ${p50:-?} ms at the median, ${worst:-?} ms at worst"
if [ "$on_disk" = 0 ]; then echo "  SKIP [wait]: /var/tmp is a tmpfs, where a sync costs nothing"
elif [ "$sanitized" = 1 ]; then echo "  SKIP [wait]: milliseconds measure the sanitizer, not the disk"
elif awk -v m="${p50:-99}" 'BEGIN{exit !(m < 2)}'; then ok
else bad "another request does not wait for a count's syncs" "$out"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
