#!/usr/bin/env bash
# Integration test: a storage bucket's CORS rules, and what a browser hears.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   config      PutBucketCors / GetBucketCors / DeleteBucketCors as S3 answers
#               them, MalformedXML and InvalidRequest for what S3 refuses, and a
#               refusal leaves the rules that were there
#   preflight   OPTIONS is answered from the first rule that allows the origin,
#               method and headers, 403 CORSResponse otherwise, and needs no
#               signature on a runtime that wants one
#   actual      every answer to an allowed origin carries the rule, errors and
#               refusals included, and an answer to anyone else carries nothing
#   restart     the rules are on disk with the bucket and come back with it
#   shards      set through a shard that is not 0, every shard has them before
#               the answer, and a restart into a different split keeps them
#
# The assertions live in lib_storage_cors.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgcors

PT=$((SL_PORT_BASE+1591))
D="$SOCKETLEY_TMPD"
SOCK="$D/one.sock"
SOCK2="$D/two.sock"
AK="AKIACORSTESTKEY00001"
SK="cors/test/secret+key"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

cleanup() {
    for r in one two sig; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in one two sig; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

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
    local out rc p f
    out=$(python3 "$HERE/lib_storage_cors.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL|SKIP)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
        bad "the library ran" "exit $rc: $out"
    fi
}
restart() {   # runtime
    "$BIN" stop "$1" >/dev/null 2>&1
    sleep 0.3
    "$BIN" start "$1" >/dev/null 2>&1
}

echo "=== Integration: storage bucket CORS ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

# ── one shard ───────────────────────────────────────────────────────────────
"$BIN" create storage one --listen "unix:$SOCK" --dir "$D/one" --anonymous -s >/dev/null 2>&1
expect "a storage runtime is made" "$?" 0
wait_nodes "$SOCK" && ok "and answers" || bad "node" "no answer from $SOCK"

echo "== the rules, the preflight and the actual requests =="
run_py basic "$SOCK"
[ -s "$D/one/web/cors" ] && ok "the rules are a file in the bucket's directory" || bad "cors file" "$(ls -la "$D/one/web")"

echo "== a restart =="
restart one
wait_nodes "$SOCK" && ok "the runtime is back" || bad "restart" "no answer"
run_py persist "$SOCK"

echo "== the same directory split in two =="
"$BIN" stop one >/dev/null 2>&1
sleep 0.3
"$BIN" edit one --shards 2 >/dev/null 2>&1
expect "the runtime is split in two" "$?" 0
"$BIN" start one >/dev/null 2>&1
wait_nodes "$D/one#0.sock" "$D/one#1.sock" && ok "both shards answer" || bad "split" "no answer"
run_py persist "$D/one#0.sock" "$D/one#1.sock"
"$BIN" stop one >/dev/null 2>&1

# ── two shards ──────────────────────────────────────────────────────────────
echo "== two shards =="
"$BIN" create storage two --listen "unix:$SOCK2" --dir "$D/two" --anonymous --shards 2 -s >/dev/null 2>&1
expect "a runtime of two shards is made" "$?" 0
N=("$D/two#0.sock" "$D/two#1.sock")
wait_nodes "${N[@]}" && ok "both shards answer" || bad "nodes" "no answer from ${N[*]}"
run_py shards "${N[@]}"
restart two
wait_nodes "${N[@]}" && ok "both shards are back after a restart" || bad "restart" "no answer"
run_py persist "${N[@]}"

# ── signatures ──────────────────────────────────────────────────────────────
echo "== a runtime that wants signatures =="
if python3 -c "import boto3" 2>/dev/null; then
    "$BIN" create storage sig -p "$PT" --dir "$D/sig" --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1
    expect "a signed runtime is made" "$?" 0
    for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$PT/")" != 000 ] && break; sleep 0.1; done
    run_py signed "$PT" "$AK" "$SK"
else
    echo "  SKIP: boto3 is not installed"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
