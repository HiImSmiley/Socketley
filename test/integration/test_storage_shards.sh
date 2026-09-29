#!/usr/bin/env bash
# Integration test: a storage runtime split over N shards behaves as one.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# The shards share one directory and a key's owner, CRC16("bucket/key") mapped
# to a shard the way a cache maps a slot, is the only shard that renames its
# body into place and writes its journal.  A runtime made with --listen unix:
# has a node per shard, so each check here says which shard a request lands on
# and what has to cross:
#
#   crossings    a put through the owner crosses nothing and a put through any
#                other shard crosses once, to the shard a client computed
#   one winner   one key put at once through every shard, over and over, is
#                never torn and every shard then serves the same object
#   listing      a listing through any shard is the listing of one shard over
#                the same files, page for page, across prefixes, delimiters and
#                page sizes
#   buckets      made through any shard they are on all of them, and dropped
#                from all of them
#   resharding   stop, edit --shards, start: every key is served whole by every
#                shard of the new split and listed, going 4 -> 2 -> 1 -> 3 -> 4
#   no traffic   at one shard nothing crosses at all
#   tcp          behind one port (SO_REUSEPORT) connections land where the
#                kernel puts them and the answers are the same
#   stats        per-shard figures, and every crossing sent is a crossing served
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgshards

PT=$((SL_PORT_BASE+1570))
D="$SOCKETLEY_TMPD"
DATA="$D/objects"
DATA1="$D/objects-one"
DATAT="$D/objects-tcp"
SOCK="$D/stg.sock"
SOCK1="$D/one.sock"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() {   # name got want
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi
}

cleanup() {
    for r in stg stg1 stgt; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in stg stg1 stgt; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# The nodes of an n-shard runtime made with --listen unix:$SOCK.
nodes() {
    local n=$1 i
    if [ "$n" -le 1 ]; then echo "$SOCK"; return; fi
    for i in $(seq 0 $((n-1))); do echo "$D/stg#$i.sock"; done
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_nodes() {   # node...
    local node t
    for node in "$@"; do
        for t in $(seq 1 150); do
            [ "$(code --unix-socket "$node" http://x/)" = 200 ] && continue 2
            sleep 0.1
        done
        return 1
    done
}
run_py() {   # a mode of the library, whose lines are the test's
    local out rc
    out=$(python3 "$HERE/lib_storage_shards.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL)' | while IFS= read -r line; do
        case "$line" in
            "  PASS:"*) echo "$line" ;;
            *) echo "$line" ;;
        esac
    done
    local p f
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
        bad "the library ran" "exit $rc: $out"
    fi
}

echo "=== Integration: a sharded storage runtime ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

# ── four shards ─────────────────────────────────────────────────────────────
"$BIN" create storage stg --listen "unix:$SOCK" --dir "$DATA" --anonymous --shards 4 -s >/dev/null 2>&1
expect "a sharded storage runtime is accepted and started" "$?" 0
N4=($(nodes 4))
wait_nodes "${N4[@]}" && ok "every shard has a node that answers" || bad "nodes" "no answer from ${N4[*]}"

echo "== buckets =="
expect "a bucket is made through shard 2" "$(code --unix-socket "${N4[2]}" -X PUT http://x/shared)" 200
for i in 0 1 2 3; do
    expect "shard $i has the bucket" "$(code --unix-socket "${N4[$i]}" -I http://x/shared)" 200
done
expect "making it again through shard 3 is refused as it is" "$(code --unix-socket "${N4[3]}" -X PUT http://x/shared)" 409
curl -s --unix-socket "${N4[1]}" -X PUT --data-binary held http://x/shared/held -o /dev/null
expect "a bucket holding an object is not dropped, whichever shard is asked" \
    "$(code --unix-socket "${N4[0]}" -X DELETE http://x/shared)" 409
expect "and is still whole afterwards" "$(curl -s --unix-socket "${N4[3]}" http://x/shared/held)" held
expect "the object is deleted through another shard" "$(code --unix-socket "${N4[2]}" -X DELETE http://x/shared/held)" 204
expect "the empty bucket is dropped through shard 1" "$(code --unix-socket "${N4[1]}" -X DELETE http://x/shared)" 204
for i in 0 1 2 3; do
    expect "shard $i no longer has it" "$(code --unix-socket "${N4[$i]}" -I http://x/shared)" 404
done
expect "and it can be made again through shard 0" "$(code --unix-socket "${N4[0]}" -X PUT http://x/shared)" 200
expect "with an object put through shard 3" "$(code --unix-socket "${N4[3]}" -X PUT --data-binary again http://x/shared/again)" 200
expect "read through shard 1" "$(curl -s --unix-socket "${N4[1]}" http://x/shared/again)" again

echo "== one key put through every shard at once =="
run_py storm "$BIN" "${N4[@]}"

echo "== what crosses =="
run_py cross "$BIN" "${N4[@]}"

echo "== the same listing through every shard =="
run_py populate "${N4[@]}"
run_py verify 0 "${N4[@]}"
cp -r "$DATA" "$DATA1"
"$BIN" create storage stg1 --listen "unix:$SOCK1" --dir "$DATA1" --anonymous -s >/dev/null 2>&1
expect "a one-shard runtime on a copy of the files is made" "$?" 0
wait_nodes "$SOCK1" && ok "and answers" || bad "one-shard node" "no answer"
run_py equiv -- "${N4[@]}" -- "$SOCK1"

echo "== one shard crosses nothing =="
for i in $(seq 1 12); do
    curl -s --unix-socket "$SOCK1" -X PUT --data-binary "v$i" "http://x/pop/one$i" -o /dev/null
done
curl -s --unix-socket "$SOCK1" -X PUT http://x/onebucket -o /dev/null
curl -s --unix-socket "$SOCK1" "http://x/pop?list-type=2" -o /dev/null
curl -s --unix-socket "$SOCK1" -X DELETE http://x/pop/one1 -o /dev/null
curl -s --unix-socket "$SOCK1" -X DELETE http://x/onebucket -o /dev/null
st1=$("$BIN" stats stg1 2>&1)
has "$st1" "mesh_direct:0" && has "$st1" "mesh_relayed:0" && ! has "$st1" "shard_commits_sent" \
    && ok "puts, deletes, listings and bucket changes at one shard cross nothing" \
    || bad "one shard crossed" "$st1"
"$BIN" stop stg1 >/dev/null 2>&1

echo "== stats =="
st4=$("$BIN" stats stg 2>&1)
n_sections=$(echo "$st4" | grep -c '^\[shard ')
expect "stats has a section per shard" "$n_sections" 4
n_objs=$(echo "$st4" | grep -c '^objects:')
expect "each shard reports its own objects" "$n_objs" 4
has "$st4" "shard_commits_sent:" && has "$st4" "shard_list_fanouts:" \
    && ok "and what crossed" || bad "crossing figures" "$st4"

echo "== a different shard count on the same directory =="
# The check above put later0 already.
prior=1
for n in 2 1 3 4; do
    "$BIN" stop stg >/dev/null 2>&1
    sleep 0.5
    out=$("$BIN" edit stg --shards "$n" 2>&1); rc=$?
    expect "the shard count is edited to $n" "$rc" 0
    "$BIN" start stg >/dev/null 2>&1
    NN=($(nodes "$n"))
    wait_nodes "${NN[@]}" && ok "$n shard(s) answer" || { bad "$n nodes" "no answer from ${NN[*]}"; continue; }
    run_py verify "$prior" "${NN[@]}"
    prior=$((prior+1))
done

echo "== behind one port =="
"$BIN" create storage stgt -p "$PT" --dir "$DATAT" --anonymous --shards 4 -s >/dev/null 2>&1
expect "a sharded runtime on a TCP port is made" "$?" 0
for t in $(seq 1 100); do [ "$(code "http://127.0.0.1:$PT/")" = 200 ] && break; sleep 0.1; done
expect "a bucket is made" "$(code -X PUT "http://127.0.0.1:$PT/tcp")" 200
bad_put=0; bad_get=0
for i in $(seq 1 40); do
    [ "$(code -X PUT --data-binary "value-$i" "http://127.0.0.1:$PT/tcp/key$i")" = 200 ] || bad_put=$((bad_put+1))
done
for i in $(seq 1 40); do
    [ "$(curl -s "http://127.0.0.1:$PT/tcp/key$i")" = "value-$i" ] || bad_get=$((bad_get+1))
done
expect "forty puts over separate connections all land" "$bad_put" 0
expect "and all read back" "$bad_get" 0
keycount=$(curl -s "http://127.0.0.1:$PT/tcp?list-type=2" | grep -o '<Key>' | wc -l)
expect "the listing has all forty" "$keycount" 40
stt=$("$BIN" stats stgt 2>&1)
sent=$(echo "$stt" | awk -F: '/^shard_commits_sent:/ {s+=$2} END {print s+0}')
served=$(echo "$stt" | awk -F: '/^shard_commits_served:/ {s+=$2} END {print s+0}')
landed=$(echo "$stt" | awk -F: '/^shard_total_connections:/ {if ($2>0) c++} END {print c+0}')
[ "$sent" -gt 0 ] && ok "some puts crossed between shards ($sent)" || bad "no put crossed" "$stt"
expect "every crossing was served" "$served" "$sent"
[ "$landed" -ge 2 ] && ok "connections landed on $landed shards" || bad "all connections on one shard" "$landed"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
