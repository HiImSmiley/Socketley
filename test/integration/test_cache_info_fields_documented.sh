#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# The `info` entry in man/socketley.1 enumerates the fields a monitor reads
# back, and it stopped at the ones that existed when it was written.  Two
# commits added master_host, master_port, master_link_status, connected_slaves
# and master_sync_in_progress to the document, and the page named none of them.
#
# Nothing checked, which is why it drifted: the command list beside it IS
# checked against the behaviour on every run, and did not drift.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Both directions, against a live leader AND a live follower, because the
# replication section is the one that differs by role:
#
#   * every replication field either document answers is named on the page --
#     the direction that would have caught the drift above
#   * every field the page names appears in one of the two documents, so the
#     page cannot keep a field the code dropped
#   * the split itself, which the page states: a follower answers the master_*
#     fields and not connected_slaves, a leader the reverse
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
MAN="$HERE/../../man/socketley.1"
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate infofields
PASS=0; FAIL=0; TOTAL=0
cleanup() {
    "$BIN" stop  inf_follower inf_leader >/dev/null 2>&1 || true
    "$BIN" remove inf_follower >/dev/null 2>&1 || true
    "$BIN" remove inf_leader   >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
send_to() { echo "$2" | nc -q 1 127.0.0.1 "$1" 2>/dev/null | tr -d '\r'; }

echo "=== Integration: the info entry names the fields info answers ==="

# ─── What the page says, from the roff source ───────────────────────────────
#
# Read from the source rather than from a rendered page, the way the command
# reference beside it does, so this needs no man(1) on the box.
ENTRY=$(awk '/^\.B info$/{f=1} f&&/^\.TP$/&&NR>1{if(seen){exit}} f{print; if(/^\.TP$/)seen=1}' \
        "$MAN" 2>/dev/null || true)
[ -z "$ENTRY" ] && ENTRY=$(sed -n '/^\.B info$/,/^\.BI "config get /p' "$MAN")
DOCUMENTED=$(grep -oE '\b(master_[a-z_]+|connected_slaves|role)\b' <<<"$ENTRY" \
             | sort -u || true)
DOC_N=$(printf '%s\n' "$DOCUMENTED" | grep -c . || true)

if [ "${DOC_N:-0}" -ge 5 ]; then pass
else fail "the page's info entry names replication fields at all" \
          "found ${DOC_N:-0} in the entry, expected at least 5" \
          "entry was $(printf '%s' "$ENTRY" | wc -l) lines"; fi

# ─── A live pair ────────────────────────────────────────────────────────────
# An offset nothing else in the directory claims: +930 is also
# test_state_dir_asymmetric's and test_command_diagnostics'.
P=$((SL_PORT_BASE + 1021))
daemon_start "$BIN"
RC=0
timeout 20 "$BIN" create cache inf_leader -p "$P" -s >/dev/null 2>&1 || RC=$?
sleep 0.6
send_to "$P" 'set infoseed v' >/dev/null
timeout 20 "$BIN" create cache inf_follower -p $((P + 1)) \
    --replicate "127.0.0.1:$P" -s >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "the pair is created" "a create exited $RC"; fi

GOT=""
for _ in $(seq 1 10); do
    GOT=$(send_to $((P + 1)) 'get infoseed')
    [ "$GOT" = "v" ] && break
    sleep 0.5
done
if [ "$GOT" = "v" ]; then pass
else fail "the follower is synced before its fields are read" "got: '$GOT'"; fi

INFO_L=$(send_to "$P" 'info')
INFO_F=$(send_to $((P + 1)) 'info')

answered() {  # -> every replication field name either document answers
    printf '%s\n%s\n' "$INFO_L" "$INFO_F" \
        | grep -oE '^(master_[a-z_]+|connected_slaves|role):' \
        | tr -d ':' | sort -u || true
}
ANSWERED=$(answered)
ANS_N=$(printf '%s\n' "$ANSWERED" | grep -c . || true)
if [ "${ANS_N:-0}" -ge 5 ]; then pass
else fail "the two documents answer replication fields at all" \
          "found ${ANS_N:-0}: $(printf '%s' "$ANSWERED" | tr '\n' ' ')"; fi

# ─── Direction one: nothing answered is unnamed ─────────────────────────────
UNDOCUMENTED=$(comm -23 <(printf '%s\n' "$ANSWERED") <(printf '%s\n' "$DOCUMENTED") || true)
if [ -z "$UNDOCUMENTED" ]; then pass
else fail "every replication field info answers is named on the page" \
          "the page does not name: $(printf '%s' "$UNDOCUMENTED" | tr '\n' ' ')" \
          "this is the drift the file exists to catch"; fi

# ─── Direction two: nothing named is gone ───────────────────────────────────
STALE=$(comm -13 <(printf '%s\n' "$ANSWERED") <(printf '%s\n' "$DOCUMENTED") || true)
if [ -z "$STALE" ]; then pass
else fail "every field the page names is still answered" \
          "the page names, and no document has: $(printf '%s' "$STALE" | tr '\n' ' ')"; fi

# ─── The split the page states ──────────────────────────────────────────────
for f in master_host master_port master_link_status master_sync_in_progress; do
    if grep -q "^$f:" <<<"$INFO_F"; then pass
    else fail "a follower answers $f" "not in its document"; fi
    if ! grep -q "^$f:" <<<"$INFO_L"; then pass
    else fail "a leader does not answer $f" \
              "got: $(grep -m1 "^$f:" <<<"$INFO_L")"; fi
done
if grep -q "^connected_slaves:" <<<"$INFO_L"; then pass
else fail "a leader answers connected_slaves" "not in its document"; fi
if ! grep -q "^connected_slaves:" <<<"$INFO_F"; then pass
else fail "a follower does not answer connected_slaves" \
          "got: $(grep -m1 '^connected_slaves:' <<<"$INFO_F")"; fi
if grep -q "^role:slave" <<<"$INFO_F" && grep -q "^role:master" <<<"$INFO_L"; then pass
else fail "each side names its own role" \
          "follower: $(grep -m1 '^role:' <<<"$INFO_F")" \
          "leader:   $(grep -m1 '^role:' <<<"$INFO_L")"; fi

echo "  the page names $DOC_N replication fields and the pair answers $ANS_N"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
