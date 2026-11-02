#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, data directory and port window, so it runs beside the others
# Integration test: a storage with many share links looks over the ones that burn, and lists a user's own, without
# reading every link it keeps.
#
# What each part would catch:
#   * every link file read and parsed every five seconds on the loop while any connection was open, burning or not:
#     at 30,000 links each look held every request for tens of milliseconds
#   * a link that burns made by a build before the marks, which a look over the marks alone never finds: its file
#     outlives its expiry
#   * a mark whose link is gone that is never let go of
#   * a user's list of links read from every link kept, anyone's: 30,000 of others' made each listing a pass over them
#   * a link made before the marks missing from its maker's list
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

echo "=== Integration: a storage looks over the share links that burn, and lists a user's, not every link ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate burnmarks
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1954)); U="http://127.0.0.1:$P"
N=30000
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
cat > "$T/creds" <<EOF
AKIABURNMARKSOPS0000:burnmarksopssecretburnmarksopssecret0000
[ann]
AKIABURNMARKSANN0000:burnmarksannsecretburnmarksannsecret0000
EOF
A="AKIABURNMARKSANN0000:burnmarksannsecretburnmarksannsecret0000"
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
"$BIN" create storage st -p "$P" --dir "$T/d" --credentials "$T/creds" -s >/dev/null 2>&1
up || bad "the runtime serves" "no answer on $P"
mk() { curl -s -m 30 -u "$A" -X POST -d "$1" "$U/~share" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null; }
curl -s -u "$A" -X MKCOL -o /dev/null "$U/~dav/ann/"
for f in r old new; do printf '%s' "$f" | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/$f.txt"; done
plain=$(mk '{"bucket":"ann","key":"r.txt"}')
new=$(mk '{"bucket":"ann","key":"new.txt","burn":true,"expires_in":3600}')
old=$(mk '{"bucket":"ann","key":"old.txt","burn":true,"expires_in":3600}')
S="$T/d/.shares"
[ -e "$S/burn/$new" ] && ok || bad "a link that burns is marked" "$(ls "$S" | head -5 | tr '\n' ' ')"
[ ! -e "$S/burn/$plain" ] && ok || bad "and one that does not is not" "$plain"

# As a build before the marks left them: one link that burns, past its expiry and with no mark, many that do not, and
# a mark whose link is gone.
"$BIN" stop st >/dev/null 2>&1
python3 - "$S" "$plain" "$old" "$N" <<'PY'
import json, os, sys
d, plain, old, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
mine = json.load(open(os.path.join(d, plain + ".json")))
for i in range(n + 1):
    nid = "%s%06d" % (plain[:16], i)
    o = dict(mine, id=nid)
    # The last one ann's, the rest someone else's.
    if i < n: o["owner"] = "someone-else"
    open(os.path.join(d, nid + ".json"), "w").write(json.dumps(o))
o = json.load(open(os.path.join(d, old + ".json")))
o["expires"] = 1000
for k in list(o):
    if k.startswith("expires") and isinstance(o[k], int): o[k] = 1000
open(os.path.join(d, old + ".json"), "w").write(json.dumps(o))
os.unlink(os.path.join(d, "burn", old))
open(os.path.join(d, "burn", "gonegonegonegonegone00"), "w").close()
PY
touch -d '5 minutes ago' "$S/burn/gonegonegonegonegone00"
"$BIN" start st >/dev/null 2>&1
up || bad "the runtime serves again" "no answer on $P"
for _ in $(seq 1 150); do [ ! -e "$S/$old.json" ] && [ ! -e "$S/$old.burning" ] && break; sleep 0.1; done
[ ! -e "$S/$old.json" ] && [ ! -e "$S/$old.burning" ] && ok || bad "a link that burns with no mark is found and ends" "$(ls "$S" | grep "$old")"
for _ in $(seq 1 100); do [ "$(curl -s -u "$A" -o /dev/null -w '%{http_code}' "$U/~dav/ann/old.txt")" = 404 ] && break; sleep 0.1; done
[ "$(curl -s -u "$A" -o /dev/null -w '%{http_code}' "$U/~dav/ann/old.txt")" = 404 ] && ok || bad "and takes its file with it" "still there"
[ ! -e "$S/burn/gonegonegonegonegone00" ] && ok || bad "a mark whose link is gone goes" "still there"
[ -e "$S/burn/$new" ] && [ "$(curl -s "$U/~share/$new?download")" = new ] && ok || bad "a link that burns later is left to its end" "$(ls "$S/burn")"
legacy="${plain:0:16}$(printf '%06d' "$N")"
for _ in $(seq 1 100); do [ -e "$S/owner" ] && [ -n "$(find "$S/owner" -name "$legacy")" ] && break; sleep 0.1; done
mine=$(curl -s -u "$A" "$U/~share" | python3 -c 'import json,sys; print(" ".join(sorted(x["id"] for x in json.load(sys.stdin))))')
want=$(printf '%s\n' "$plain" "$new" "$legacy" | sort | tr '\n' ' ' | sed 's/ $//')
[ "$mine" = "$want" ] && ok || bad "a user lists their own links, the one made before the marks among them" "got '$mine', want '$want'"
t0=$(mono_ns)
for _ in 1 2 3 4 5; do curl -s -u "$A" -o /dev/null "$U/~share"; done
list_ms=$(( ($(mono_ns) - t0) / 5000000 ))
echo "  a user's list beside $N links of someone else's: $list_ms ms"
if [ "$sanitized" = 1 ]; then echo "  SKIP [list]: milliseconds measure the sanitizer, not the list"
elif [ "$list_ms" -lt 20 ]; then ok
else bad "a user's list is not a pass over every link" "$list_ms ms"; fi

# Requests all along, across three looks, beside N links that do not burn.
out=$(timeout 60 python3 - "$P" "$plain" <<'PY'
import socket, sys, time
port, lid = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=30)
lat = []
end = time.time() + 16
while time.time() < end:
    t = time.perf_counter()
    s.sendall(("GET /~share/%s HTTP/1.1\r\nHost: x\r\n\r\n" % lid).encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(65536)
    h, rest = buf.split(b"\r\n\r\n", 1)
    n = int([l.split(b":")[1] for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
    while len(rest) < n: rest += s.recv(65536)
    lat.append((time.perf_counter() - t) * 1000)
    time.sleep(0.002)
lat.sort()
print("%.1f %.2f %d" % (lat[-1], lat[len(lat) // 2], len(lat)))
PY
)
read -r worst p50 count <<<"$out"
echo "  beside $N links that do not burn: the worst request of ${count:-?} over 16 s ${worst:-?} ms, the median ${p50:-?} ms"
if [ "$sanitized" = 1 ]; then echo "  SKIP [stall]: milliseconds measure the sanitizer, not the look"
elif awk -v w="${worst:-9999}" 'BEGIN{exit !(w < 25)}'; then ok
else bad "a look does not hold the loop for every link" "$out"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
