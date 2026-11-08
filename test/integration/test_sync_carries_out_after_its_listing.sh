#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories and port window, so it runs beside the others
# Integration test: both ways, a sync runtime starts carrying this side's files as soon as it has brought the
# storage's, rather than at the next wake that happens to come.
#
# What it would catch: the walk after a listing asking the loop for a turn soon while the one-second tick the
# listing had left armed was still waiting, which dropped the ask, so the carrying out began only when something
# else woke the loop -- 150 to 250 ms later in most runs here.
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
trap 'daemon_stop' EXIT
daemon_start "$BIN"
KEY=AKIASYNCSOON00000000; SEC=syncsoonsecretsyncsoonsecret0000
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
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
    mkdir -p "$T/d$r/out"
    for i in $(seq 1 "$N"); do printf 'here %s' "$i" > "$T/d$r/out/f$i.txt"; done
    "$BIN" create sync "j$r" --dir "$T/d$r" --storage "box/$b" --credentials "$T/creds" --mode inout --every never -s \
        >/dev/null 2>&1
    # The moment the last of the storage's files is here, then the moment the last of this side's is there.
    brought=0; carried=0
    end=$(( $(now_ms) + 30000 ))
    while [ "$(now_ms)" -lt "$end" ]; do
        if [ "$brought" = 0 ] && [ -e "$T/d$r/in/f$N.txt" ] && [ "$(ls "$T/d$r/in" | wc -l)" = "$N" ]; then brought=$(now_ms); fi
        if [ "$brought" != 0 ]; then
            c=$(S "http://127.0.0.1:$P/$b?list-type=2&prefix=out/" | grep -o '<Key>' | wc -l)
            if [ "$c" = "$N" ]; then carried=$(now_ms); break; fi
        fi
    done
    if [ "$carried" = 0 ]; then bad "round $r" "the job did not carry this side's $N files out"; continue; fi
    gap=$((carried - brought))
    [ "$gap" -gt "$worst" ] && worst=$gap
    [ "$gap" -gt 100 ] && slow=$((slow + 1))
    "$BIN" remove "j$r" >/dev/null 2>&1
done
# Half the rounds and not one, so a round slowed by a loaded box is not taken for the job waiting.
if [ $((slow * 2)) -lt "$ROUNDS" ]; then ok; else bad "carried out after its listing" "$slow of $ROUNDS rounds waited over 100 ms between the last file brought and the last carried, the worst $worst ms"; fi

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
