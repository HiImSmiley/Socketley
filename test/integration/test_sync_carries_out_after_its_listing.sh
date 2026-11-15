#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories and port window, so it runs beside the others
# Integration test: both ways, a sync runtime starts carrying this side's files as soon as it has brought the
# storage's, rather than at the next wake that happens to come.
#
# What it would catch: the walk after a listing asking the loop for a turn soon while the one-second tick the
# listing had left armed was still waiting, which dropped the ask, so the carrying out began only when something
# else woke the loop -- 150 to 250 ms later in most runs here.
#
# The gap is read from the files' own change times, which the job and the storage set as they rename each into
# place, so it is not the test's polling: a loop of ls, curl and date measured itself at 30 to 60 ms of the gap on a
# loaded box.  And both sides live on tmpfs where there is one, since between the last file brought and the first
# carried the job syncs its index to disk, and a disk shared with builds took 15 to 1,900 ms for an fdatasync: what
# the test is about is the turn the loop takes, not the disk.  So measured, with 8 busy loops on the test's CPUs, the
# first carried came 7-49 ms after the last brought in all but 3 of 72 rounds (the worst 106), and with the dropped
# turn put back 17-286 ms, over 50 in 41 of 48.
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

echo "=== Integration: both ways, a sync runtime carries out right after it has brought in ==="
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }
daemon_isolate syncsoon
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1965))
unset SOCKETLEY_CONFIG
# Where the files of both sides go: tmpfs when the box has one, else the test's own directory on whatever disk.
F=$T
if [ "$(stat -f -c %T /dev/shm 2>/dev/null)" = tmpfs ] && [ -w /dev/shm ]; then F=$(mktemp -d /dev/shm/socketley-syncsoon-XXXXXX); fi
trap 'daemon_stop; [ "$F" != "$T" ] && rm -rf "$F"' EXIT
[ "$F" = "$T" ] && echo "  note: no tmpfs, so the gaps below take in the disk's syncs"
daemon_start "$BIN"
KEY=AKIASYNCSOON00000000; SEC=syncsoonsecretsyncsoonsecret0000
"$BIN" create storage box -p "$P" --dir "$F/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"; chmod 600 "$T/creds"
now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

# Files of a megabyte to bring, so the last fetches outlast the short tick the loop is turned by while it brings.
N=16
head -c $((1 << 20)) /dev/urandom > "$T/mib.bin"
ROUNDS=${ROUNDS:-6}
slow=0; worst=0
for r in $(seq 1 "$ROUNDS"); do
    b="round$r"
    S -o /dev/null -X PUT "http://127.0.0.1:$P/$b"
    for i in $(seq 1 "$N"); do S -o /dev/null -T "$T/mib.bin" "http://127.0.0.1:$P/$b/in/f$i.txt"; done
    mkdir -p "$F/d$r/out"
    for i in $(seq 1 "$N"); do printf 'here %s' "$i" > "$F/d$r/out/f$i.txt"; done
    "$BIN" create sync "j$r" --dir "$F/d$r" --storage "box/$b" --credentials "$T/creds" --mode inout --every never -s \
        >/dev/null 2>&1
    # Every file both ways, then when each was renamed into place: the last of the storage's here, the first of this
    # side's there (an object is <dir>/<bucket>/data/<2 hex>/<sha256 of its key>, renamed in once whole).  Waited for
    # on the files alone: a request to the daemon meanwhile wakes its loop, which is what the job used to wait for.
    objs=()
    for i in $(seq 1 "$N"); do h=$(printf 'out/f%s.txt' "$i" | sha256sum | cut -c1-64); objs+=("$F/stg/$b/data/${h:0:2}/$h"); done
    done_=0
    end=$(( $(now_ms) + 30000 ))
    while [ "$(now_ms)" -lt "$end" ]; do
        if [ "$(ls "$F/d$r/in" 2>/dev/null | wc -l)" = "$N" ] && stat "${objs[@]}" >/dev/null 2>&1; then done_=1; break; fi
        sleep 0.05
    done
    if [ "$done_" = 0 ]; then
        c=$(S "http://127.0.0.1:$P/$b?list-type=2&prefix=out/" | grep -o '<Key>' | wc -l)
        bad "round $r" "the job did not bring the storage's $N files and carry this side's out ($c listed, or not where the layout says)"
        continue
    fi
    brought=$(stat -c %.9Z "$F/d$r/in/"* | sort -n | tail -1)
    carried=$(stat -c %.9Z "${objs[@]}" | sort -n | head -1)
    gap=$(awk -v b="$brought" -v c="$carried" 'BEGIN { printf "%d", (c - b) * 1000 }')
    echo "  round $r: the first of this side's carried $gap ms after the last of the storage's was brought"
    [ "$gap" -gt "$worst" ] && worst=$gap
    [ "$gap" -gt 50 ] && slow=$((slow + 1))
    "$BIN" remove "j$r" >/dev/null 2>&1
done
# Half the rounds and not one, so a round slowed by a loaded box is not taken for the job waiting.
if [ $((slow * 2)) -lt "$ROUNDS" ]; then ok; else bad "carried out after its listing" "$slow of $ROUNDS rounds waited over 50 ms between the last file brought and the first carried, the worst $worst ms"; fi

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
