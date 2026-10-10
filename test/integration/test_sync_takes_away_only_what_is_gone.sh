#!/usr/bin/env bash
# Integration test: what a sync runtime takes away from a storage, what it sees between walks, and what it says when
# it cannot carry.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a directory that is empty -- a disk that is not mounted -- emptying the
#     bucket, which no later run can fill again
#   * a file below a directory the walk may not enter taken off the far side
#   * a file deleted here, or replaced by a link to nothing, left on it
#   * a link to a file outside --dir carried, which sends whatever whoever may
#     write in --dir points it at
#   * a target named by a host never resolved, which only an address hides
#   * a file above one request's 5 GiB never arriving, which needs parts --
#     and a part out of place, which the marks at their edges would show
#   * with --every never: a file written, changed or deleted after the first
#     walk never reaching the far side, which is a sync without inotify
#   * a file in a directory made after the start not carried, since no watch
#     names it until a walk does
#   * a --storage that can never work accepted at create: a URL with no bucket,
#     a path before the bucket, a bucket S3 would refuse, a target twice
#   * a runtime named that is no storage carrying nowhere in silence, and a
#     --dir that holds the storage's own data, which would carry forever
#   * a --dir with a slash at its end cutting a letter off every name
#   * a storage serving TLS itself named by its runtime, which would be
#     spoken to in plain HTTP
#   * an index kept after `remove`, or kept across a change of --prefix, so a
#     job made again believes the far side holds what it never sent there
#   * a sync that cannot carry raising no alert, or one that recovers not
#     clearing it; credentials put right in their file not used until a
#     restart
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate sync2
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1975))
M=$((SL_PORT_BASE+1976))
C=$((SL_PORT_BASE+1977))
trap 'chmod -R u+rwx "$T" 2>/dev/null; daemon_stop' EXIT

echo "=== Integration: a sync takes away only what is gone ==="

ADMIN="AKIASYNCALERTADMIN00:syncalertadminsecretsyncalertadmin0000"
printf '[admin]\nadmin = true\n%s\n' "$ADMIN" > "$T/dash.creds"
printf 'daemon = { metrics_port = %d, dashboard_credentials = "%s" }\n' "$M" "$T/dash.creds" > "$T/daemon.lua"
export SOCKETLEY_CONFIG="$T/daemon.lua"
daemon_start "$BIN"
mkdir -p "$T/stg" "$T/src/sub" "$T/src/locked"
KEY=AKIASYNCGONE00000000
SEC=syncgonesecretsyncgonesecret0000
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/photos"
keys() { S "http://127.0.0.1:$P/${1:-photos}" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'; }
st() { "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2://p"; }
# Waits up to $1 seconds for the keys of bucket $2 to be $3.
until_keys() { local i; for i in $(seq 1 "$1"); do [ "$(keys "$2")" = "$3" ] && return 0; sleep 0.5; done; return 1; }
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"

printf 'a\n' > "$T/src/a.txt"
printf 'b\n' > "$T/src/sub/b.txt"
printf 'c\n' > "$T/src/locked/c.txt"
printf 'l\n' > "$T/src/target.txt"
ln -s target.txt "$T/src/link.txt"
# A link out of --dir, which whoever may write there could point at anything the daemon may read.
printf 'not yours\n' > "$T/outside.txt"
ln -s "$T/outside.txt" "$T/src/escape.txt"

# ─── what create refuses ────────────────────────────────────────────────────
refused() { "$BIN" create sync bad --dir "$T/src" --storage "$1" --credentials "$T/creds" 2>&1 | grep -c -- "$2"; }
expect "a URL with no bucket is refused" "$(refused "https://s3.example.com" 'names no bucket')" 1
expect "and one with a path before the bucket" "$(refused "https://s3.example.com/a/photos" 'path between')" 1
expect "and a bucket S3 would refuse" "$(refused "box/Bad_Bucket" 'not a bucket name')" 1
expect "and a target named twice" "$(refused "box/photos,box/photos" 'twice')" 1
expect "and a name that is neither a runtime nor an address" "$(refused "a b/photos" 'neither')" 1
expect "and a directory the target storage keeps its own data in" \
    "$("$BIN" create sync bad --dir "$T/stg" --storage box/photos --credentials "$T/creds" 2>&1 | grep -c 'one in the other')" 1
if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -keyout "$T/k.pem" -out "$T/c.pem" 2>/dev/null
    "$BIN" create storage tlsbox -p $((P+3)) --dir "$T/tstg" --tls --cert "$T/c.pem" --key "$T/k.pem" \
        --access-key "$KEY" --secret-key "$SEC" >/dev/null 2>&1
    expect "and a storage that serves TLS itself, named rather than given by its URL" \
        "$("$BIN" create sync bad --dir "$T/src" --storage tlsbox/photos --credentials "$T/creds" 2>&1 | grep -c 'serves TLS itself')" 1
    "$BIN" remove tlsbox >/dev/null 2>&1
fi
expect "none of them was made" "$("$BIN" ls 2>/dev/null | grep -c ' bad ')" 0

# ─── watched rather than walked ─────────────────────────────────────────────
"$BIN" create sync s --dir "$T/src" --storage box/photos --credentials "$T/creds" --every never -s >/dev/null 2>&1
until_keys 30 photos "a.txt link.txt locked/c.txt sub/b.txt target.txt"
expect "the first walk carries everything, a link as what it points at, and no link out of --dir" "$(keys)" "a.txt link.txt locked/c.txt sub/b.txt target.txt"
# The figures arrive once the worker has published them, which a sanitizer build does later.
for _ in $(seq 1 20); do [ "$(st s watched)" = 3 ] && break; sleep 0.5; done
expect "and inotify watches every directory" "$(st s watched)" 3
printf 'new\n' > "$T/src/new.txt"
until_keys 15 photos "a.txt link.txt locked/c.txt new.txt sub/b.txt target.txt"
expect "with --every never, a file written after the walk is carried" "$(keys)" "a.txt link.txt locked/c.txt new.txt sub/b.txt target.txt"
printf 'A\n' > "$T/src/a.txt"
for _ in $(seq 1 30); do [ "$(S "http://127.0.0.1:$P/photos/a.txt")" = A ] && break; sleep 0.5; done
expect "a file changed is carried again" "$(S "http://127.0.0.1:$P/photos/a.txt")" A
rm "$T/src/new.txt"
until_keys 15 photos "a.txt link.txt locked/c.txt sub/b.txt target.txt"
expect "a file deleted is taken away" "$(keys)" "a.txt link.txt locked/c.txt sub/b.txt target.txt"
mkdir -p "$T/src/later/deeper"
printf 'd\n' > "$T/src/later/deeper/d.txt"
until_keys 15 photos "a.txt later/deeper/d.txt link.txt locked/c.txt sub/b.txt target.txt"
expect "a file in a directory made since is carried" "$(keys)" "a.txt later/deeper/d.txt link.txt locked/c.txt sub/b.txt target.txt"
rm "$T/src/target.txt"
until_keys 15 photos "a.txt later/deeper/d.txt link.txt locked/c.txt sub/b.txt"
# No event names the link, which did not change; the next walk finds it pointing at nothing.
"$BIN" stop s >/dev/null 2>&1; "$BIN" start s >/dev/null 2>&1
until_keys 15 photos "a.txt later/deeper/d.txt locked/c.txt sub/b.txt"
expect "a link left pointing at nothing is taken away at the next walk" "$(keys)" "a.txt later/deeper/d.txt locked/c.txt sub/b.txt"

# ─── what is not gone ───────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    chmod 000 "$T/src/locked"
    "$BIN" stop s >/dev/null 2>&1; "$BIN" start s >/dev/null 2>&1
    sleep 3
    expect "a file below a directory the walk may not enter stays" "$(keys)" "a.txt later/deeper/d.txt locked/c.txt sub/b.txt"
    chmod 755 "$T/src/locked"
else
    echo "  SKIP: running as root, which enters every directory"
fi
"$BIN" stop s >/dev/null 2>&1
mv "$T/src" "$T/src.away"; mkdir "$T/src"
"$BIN" start s >/dev/null 2>&1
for _ in $(seq 1 20); do [ -n "$(st s last_error)" ] && break; sleep 0.5; done
sleep 2
expect "a directory that is suddenly empty takes nothing away" "$(keys)" "a.txt later/deeper/d.txt locked/c.txt sub/b.txt"
expect "and says why" "$(st s last_error | grep -c 'is empty')" 1
"$BIN" stop s >/dev/null 2>&1
rmdir "$T/src"; mv "$T/src.away" "$T/src"

# ─── the index ──────────────────────────────────────────────────────────────
idx=$(find "$HOME" -name s.index -path '*/sync/*' | head -1)
expect "the index is kept while the job is" "$([ -f "$idx" ] && echo yes)" yes
"$BIN" remove s >/dev/null 2>&1
expect "and removed with it" "$([ -e "$idx" ] && echo kept || echo gone)" gone
"$BIN" create sync s --dir "$T/src" --storage box/photos --credentials "$T/creds" --prefix laptop --every never -s >/dev/null 2>&1
until_keys 30 photos "a.txt laptop/a.txt laptop/later/deeper/d.txt laptop/locked/c.txt laptop/sub/b.txt later/deeper/d.txt locked/c.txt sub/b.txt"
expect "a job made again under another prefix carries everything there" \
    "$(keys)" "a.txt laptop/a.txt laptop/later/deeper/d.txt laptop/locked/c.txt laptop/sub/b.txt later/deeper/d.txt locked/c.txt sub/b.txt"
"$BIN" stop s >/dev/null 2>&1
"$BIN" show s 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); d["prefix"]="desk"; print(json.dumps(d))' > "$T/s.json"
"$BIN" import s < "$T/s.json" >/dev/null 2>&1
"$BIN" start s >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$(keys | grep -o 'desk/' | wc -l)" -ge 4 ] && break; sleep 0.5; done
expect "and a prefix changed by import begins the index again rather than believing it" "$(keys | grep -o 'desk/' | wc -l)" 4
"$BIN" remove s >/dev/null 2>&1
# A --dir written with a slash at its end cuts the same paths as one without.
"$BIN" create sync sl --dir "$T/src/" --storage box/photos --credentials "$T/creds" --prefix sl --every never -s >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$(keys | grep -o 'sl/' | wc -l)" -ge 4 ] && break; sleep 0.5; done
expect "a --dir ending in a slash keeps every name whole" "$(keys | tr ' ' '\n' | grep '^sl/' | tr '\n' ' ' | sed 's/ $//')" \
    "sl/a.txt sl/later/deeper/d.txt sl/locked/c.txt sl/sub/b.txt"
"$BIN" remove sl >/dev/null 2>&1

# ─── a host given by name ───────────────────────────────────────────────────
# Resolved on the resolver's own thread, whose answer has to wake the run's loop: an address alone never asks.
S -o /dev/null -X PUT "http://127.0.0.1:$P/named"
"$BIN" create sync named --dir "$T/src" --storage "http://localhost:$P/named" --credentials "$T/creds" -s >/dev/null 2>&1
# The worker's figures follow its work, so the failure count is waited for beside the keys.
for _ in $(seq 1 30); do [ "$(keys named | wc -w)" = 4 ] && [ -n "$(st named failures)" ] && break; sleep 0.5; done
expect "a target named by a host is resolved and carried to" "$(keys named | wc -w) $(st named failures)" "4 0"
"$BIN" remove named >/dev/null 2>&1

# ─── a file too large for one request ───────────────────────────────────────
# 600 MiB, sparse, with a mark at the end of the first part, at the start of the second and at the end of the file:
# one PUT carries at most 5 GiB, so a file above that never arrives unless it goes in parts.
mkdir -p "$T/big"
truncate -s 600M "$T/big/v.img"
mark() { printf '%s' "$2" | dd of="$T/big/v.img" bs=1 seek="$1" conv=notrunc status=none; }
mark $((64*1024*1024-4)) "END1"; mark $((64*1024*1024)) "BEG2"; mark $((600*1024*1024-4)) "LAST"
S -o /dev/null -X PUT "http://127.0.0.1:$P/big"
"$BIN" create sync big --dir "$T/big" --storage box/big --credentials "$T/creds" --every never -s >/dev/null 2>&1
for _ in $(seq 1 120); do [ "$(st big carried)" = 1 ] && break; sleep 0.5; done
expect "a file above the part size is carried" "$(st big carried) $(st big failures)" "1 0"
expect "in parts, as its etag says" "$(S -I "http://127.0.0.1:$P/big/v.img" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: .*-\([0-9]*\)"$/\1/p')" 10
expect "at its whole length" "$(S -I "http://127.0.0.1:$P/big/v.img" | tr -d '\r' | sed -n 's/^[Cc]ontent-[Ll]ength: //p')" 629145600
expect "with every part where it belongs" \
    "$(S -r $((64*1024*1024-4))-$((64*1024*1024+3)) "http://127.0.0.1:$P/big/v.img") $(S -r -4 "http://127.0.0.1:$P/big/v.img")" "END1BEG2 LAST"
"$BIN" remove big >/dev/null 2>&1
S -o /dev/null -X DELETE "http://127.0.0.1:$P/big/v.img"; rm -rf "$T/big"

# ─── a target that is no storage, and one that refuses ──────────────────────
"$BIN" create cache cc -p "$C" -s >/dev/null 2>&1
"$BIN" create sync nostore --dir "$T/src" --storage cc/photos --credentials "$T/creds" -s >/dev/null 2>&1
for _ in $(seq 1 20); do [ -n "$(st nostore last_error)" ] && break; sleep 0.5; done
expect "a runtime named that is no storage is said" "$(st nostore last_error | grep -c 'is a cache runtime, not a storage')" 1
"$BIN" remove nostore >/dev/null 2>&1

# A target with no runtime behind it yet holds up nothing of the others: its queue could not shrink, and while it
# held anything no walk ran -- and a link whose target goes is seen by a walk alone.
mkdir -p "$T/two"; printf 't\n' > "$T/two/t.txt"; ln -s t.txt "$T/two/l.txt"; printf 's\n' > "$T/two/stay.txt"
S -o /dev/null -X PUT "http://127.0.0.1:$P/two"
"$BIN" create sync pair --dir "$T/two" --storage "box/two,nobody/two" --credentials "$T/creds" --every 2s -s >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$(keys two)" = "l.txt stay.txt t.txt" ] && break; sleep 0.5; done
rm "$T/two/t.txt"
for _ in $(seq 1 30); do [ "$(keys two)" = "stay.txt" ] && break; sleep 0.5; done
expect "a target that is not there yet holds up no walk of the others" "$(keys two) $(st pair waiting)" "stay.txt 0"
"$BIN" remove pair >/dev/null 2>&1

U="http://127.0.0.1:$M"
curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null
al() { curl -s -m 10 -b "$T/jar" "$U/api/alerts" | python3 -c "import json,sys; d=json.load(sys.stdin); print(any(a['id'] == 'sync:late' for a in d['active']))"; }
"$BIN" create sync late --dir "$T/src" --storage box/later --credentials "$T/creds" -s >/dev/null 2>&1
for _ in $(seq 1 60); do [ "$(al)" = True ] && break; sleep 1; done
expect "a sync whose bucket is not there raises an alert" "$(al)" True
"$BIN" stop late >/dev/null 2>&1
for _ in $(seq 1 60); do [ "$(al)" = False ] && break; sleep 1; done
expect "a sync stopped owes nothing, and its alert clears" "$(al)" False
"$BIN" start late >/dev/null 2>&1
for _ in $(seq 1 60); do [ "$(al)" = True ] && break; sleep 1; done
expect "and started again still failing raises it again" "$(al)" True
S -o /dev/null -X PUT "http://127.0.0.1:$P/later"
for _ in $(seq 1 90); do [ "$(al)" = False ] && break; sleep 1; done
expect "and once the bucket is there it carries, and the alert clears" "$(al) $(keys later | wc -w)" "False 4"

# Credentials put right in their file are used at the next walk, which the refusal itself asks for.
printf 'access_key = %s\nsecret_key = wrongwrongwrongwrongwrongwrong00\n' "$KEY" > "$T/rot.creds"
"$BIN" create sync rot --dir "$T/src" --storage box/rot --credentials "$T/rot.creds" -s >/dev/null 2>&1
S -o /dev/null -X PUT "http://127.0.0.1:$P/rot"
for _ in $(seq 1 30); do [ -n "$(st rot last_error)" ] && break; sleep 0.5; done
expect "credentials the storage refuses are said, with S3's reason" "$(st rot last_error | grep -c '403 SignatureDoesNotMatch')" 1
cp "$T/creds" "$T/rot.creds"
for _ in $(seq 1 90); do [ "$(keys rot | wc -w)" = 4 ] && break; sleep 1; done
expect "and once put right in the file they are used, with no restart" "$(keys rot | wc -w)" 4

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
