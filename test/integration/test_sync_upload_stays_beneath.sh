#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a sync runtime uploads only files below --dir, even while a folder in it is swapped for a link.
#
# ─── THE DEFECT (round 8b) ──────────────────────────────────────────────────
#
# carry() checked a file with realpath() and then opened the resolved path by name.  O_NOFOLLOW guards only the last
# name, so a folder on the way swapped for a link between the two calls sent the open outside --dir.  Whoever may
# write in --dir (a shared folder, a second account) so had the daemon upload any file its user can read -- keys,
# state, other users' data -- to the bucket, which a two-way sync then brings back into the folder.  Measured on dev
# 3b7db9690 with this file's setup: the bucket held the outside file after 11 s and 38 s in two runs (folder d/ with
# 150 levels below it, flipped to a link to a copy of that tree outside); with four such folders it was red in 3 of 3
# runs, after 6-7 s.  The fix walks the resolved path again
# beneath the folder's descriptor with openat2(RESOLVE_BENEATH), where the kernel refuses any way out.
#
# Red on the old code only by winning the race, so the budget is generous; green always runs it out.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate syncbeneath
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1975))
RP=""
trap 'for p in $RP; do kill $p 2>/dev/null; done; daemon_stop' EXIT
N=${SYNC_RACE_FOLDERS:-4}
SECS=${SYNC_RACE_SECS:-45}

echo "=== Integration: a sync upload stays below --dir while a folder in it is swapped for a link ==="

daemon_start "$BIN"
DEEP=$(python3 -c 'print("/".join(["x"] * 150))')
mkdir -p "$T/stg" "$T/outside/$DEEP" "$T/src/in"
for k in $(seq 1 "$N"); do mkdir -p "$T/src/d$k/$DEEP"; printf 'inside\n' > "$T/src/d$k/$DEEP/secret"; done
KEY=AKIASYNCBENEATH00000; SEC=syncsecretbeneathsyncsecretbenea
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/photos"
# Every upload is kept, so one that read the outside file is found even after a later one replaced it.
S -o /dev/null -X PUT "http://127.0.0.1:$P/photos?versioning" \
  --data '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>'
printf 'OUTSIDE-THE-SYNCED-FOLDER\n' > "$T/outside/$DEEP/secret"
printf 'linked-inside\n' > "$T/src/in/target"
ln -s ../in/target "$T/src/d1/link"
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"; chmod 600 "$T/creds"
"$BIN" create sync up --dir "$T/src" --storage "box/photos" --credentials "$T/creds" --mode out --every 1s -s >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$(S "http://127.0.0.1:$P/photos/d1/link")" = linked-inside ] && break; sleep 1; done
if [ "$(S "http://127.0.0.1:$P/photos/d1/link")" = linked-inside ]; then ok "a link to a file inside --dir is carried as before"
else bad "a link to a file inside --dir is carried as before" "$(S "http://127.0.0.1:$P/photos/d1/link" | head -c 80)"; fi

# One flipper per folder, so the uploads that can lose the race come N at a time.
for k in $(seq 1 "$N"); do
python3 - "$T/src" "$T/outside" "$SECS" "$DEEP" "d$k" <<'PY' &
import os, sys, time
src, out, secs, deep, name = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4], sys.argv[5]
d, real, link = os.path.join(src, name), os.path.join(src, "." + name + ".real"), os.path.join(src, "." + name + ".link")
os.rename(d, real); os.symlink(out, link)
end = time.time() + secs; n = 0
while time.time() < end:
    os.rename(real, d)
    if n % 2000 == 0:
        with open(os.path.join(d, deep, "secret"), "a") as f:
            f.write("x")
    os.rename(d, real); os.rename(link, d); os.rename(d, link)
    n += 1
os.rename(real, d)
PY
RP="$RP $!"
done
leaked=""
for i in $(seq 1 "$SECS"); do
    if grep -rlq OUTSIDE-THE-SYNCED-FOLDER "$T/stg" 2>/dev/null; then leaked="after ${i}s"; break; fi
    sleep 1
done
for p in $RP; do kill $p 2>/dev/null; wait $p 2>/dev/null; done; RP=""
carried=$("$BIN" stats up 2>/dev/null | sed -n 's/^carried://p')
if [ -z "$leaked" ]; then ok "no upload read the file outside --dir ($carried uploads while the folder flipped)"
else bad "no upload read the file outside --dir" "the bucket holds it $leaked"; fi
if [ "${carried:-0}" -gt 20 ]; then ok "the race was run: the file was carried again and again"
else bad "the race was run" "only ${carried:-0} uploads"; fi

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
