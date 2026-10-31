#!/usr/bin/env bash
# Integration test: --scrub reads every version back and finds what the disk changed, and a node of a cluster has
# another node send it again.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a pass that skips versions, or calls a whole one corrupt: a plain, a
#     multipart, an SSE-S3 object and a noncurrent version
#   * a changed byte not found in any of them
#   * a corrupt copy not replaced from another node, replaced under another id,
#     or replaced by removing it on the node that held it whole
#   * --scrub taking what is no duration
# suite: isolated
set -uo pipefail
# Clients as before botocore 1.36, which sent and checked checksums only where S3 required them: it reads objects it damaged on purpose, which a client checking every answer's checksum refuses to hand over.
# An older botocore ignores these and already is that client.
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgscrub

P1=$((SL_PORT_BASE+1971))
PA=$((SL_PORT_BASE+1973))
PB=$((SL_PORT_BASE+1975))
export ADMIN_AK="AKIASCRUBADMIN000001"
export ADMIN_SK="scrub/admin/secret"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in sc1 sca scb scx; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in sc1 sca scb scx; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0; sleep 0.1; done
    return 1
}
run_lib() {
    local label=$1 out rc p f; shift
    out=$(python3 "$HERE/lib_storage_scrub.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL)'
    p=$(echo "$out" | grep -c '^  PASS'); f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    [ "$rc" -ne 0 ] && [ "$f" -eq 0 ] && bad "$label" "exit $rc: $out"
}

echo "=== Integration: storage scrub ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"
printf '[admin]\n%s:%s\nadmin = true\n' "$ADMIN_AK" "$ADMIN_SK" > "$T/creds"
head -c 32 /dev/urandom > "$T/master.key"; chmod 600 "$T/master.key"

out=$("$BIN" create storage scx -p "$P1" --dir "$T/x" --credentials "$T/creds" --scrub soon 2>&1)
[ $? -eq 1 ] && echo "$out" | grep -q "duration" && ok "--scrub refuses what is no duration" \
    || bad "--scrub refuses what is no duration" "$out"
"$BIN" remove scx >/dev/null 2>&1

# ── one runtime ─────────────────────────────────────────────────────────────
"$BIN" create storage sc1 -p "$P1" --dir "$T/one" --credentials "$T/creds" --sse-key-file "$T/master.key" \
    --scrub 2s -s >/dev/null 2>&1 || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
shown=$("$BIN" show sc1 2>&1)
echo "$shown" | grep -q '"scrub": 2' && ok "show names the scrub's period" || bad "show names the scrub's period" "$shown"
run_lib "the alone half ran" alone "sc1:$P1" "$T/one"
told=$(grep -c "does not hold the bytes its header names; restore it from a copy" "$SOCKETLEY_DLOG")
[ "$told" = 4 ] && ok "each corrupt copy is logged once, saying what to do, however many passes find it" \
    || bad "each corrupt copy is logged once, saying what to do, however many passes find it" "$told lines for 4"

# ── two nodes ───────────────────────────────────────────────────────────────
for n in sca scb; do
    printf 'self %s\nnode sca http://127.0.0.1:%s\nnode scb http://127.0.0.1:%s\nkey AKIASCRUBNODES000001 nodes/secret\n' \
        "$n" "$PA" "$PB" > "$T/$n.nodes"
done
"$BIN" create storage sca -p "$PA" --dir "$T/a" --credentials "$T/creds" --nodes "$T/sca.nodes" --scrub 2s \
    -s >/dev/null 2>&1 &&
"$BIN" create storage scb -p "$PB" --dir "$T/b" --credentials "$T/creds" --nodes "$T/scb.nodes" -s >/dev/null 2>&1 \
    || { echo "  FAIL [create]: the nodes were not created"; exit 1; }
wait_up "$PA" && wait_up "$PB" || bad "the nodes come up" "no answer on $PA or $PB"
run_lib "the heal half ran" heal "sca:$PA" "$T/a" "scb:$PB"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
