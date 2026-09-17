#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
#     --replicate 1.2.3.4:abc      --replicate 1.2.3.4      --replicate :6379
#
# The flag's own message says it wants host:port and it took whatever it was
# given.  set_replicate_target() then made the cache a follower, start() called
# connect_to_master() once, threw the return away, and the cache came up.  It
# stayed up, `ls` showed it running, and it followed nobody -- with no line in
# the log, no retry and nothing in `info` that distinguishes it from a follower
# whose master is healthy.  The symptom is a write on the master that never
# arrives, which is the longest possible distance from a typo in `create`.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# The refusal and its reason, that the address a follower dials is still said
# out loud when the dial fails for a reason a flag cannot see (a well-formed
# address with nothing behind it), and -- paired, because a build that refused
# every target would pass all of that -- that an ordinary leader/follower pair
# is still created AND still replicates.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate replicate_target
PASS=0; FAIL=0; TOTAL=0
cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
send_to() { echo "$2" | nc -q 1 127.0.0.1 "$1" 2>/dev/null | tr -d '\r'; }

echo "=== Integration: a replication target that cannot work is refused ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 890))

# ─── The spellings the flag asked for and did not check ─────────────────────
i=0
for bad in "1.2.3.4:abc" "1.2.3.4:" "1.2.3.4:99999" "1.2.3.4:0" "1.2.3.4" ":6379"; do
    i=$((i + 1))
    "$BIN" remove rep_bad >/dev/null 2>&1 || true
    RC=0
    OUT=$(timeout 20 "$BIN" create cache rep_bad -p $((P + i)) --replicate "$bad" -s 2>&1) || RC=$?
    if [ "$RC" -ne 0 ]; then pass
    else fail "--replicate $bad is refused" \
              "create exited 0 for an address no follower can dial" \
              "said: ${OUT:-<nothing>}"; fi
done

# The reason has to name the part that is wrong, and the two wrong parts differ.
"$BIN" remove rep_bad >/dev/null 2>&1 || true
OUT=$(timeout 20 "$BIN" create cache rep_bad -p $((P + 10)) --replicate "1.2.3.4:abc" -s 2>&1 || true)
if grep -q "the port is not a number" <<<"$OUT"; then pass
else fail "the reason names the port" "said: ${OUT:-<nothing>}"; fi
"$BIN" remove rep_bad >/dev/null 2>&1 || true
OUT=$(timeout 20 "$BIN" create cache rep_bad -p $((P + 11)) --replicate "1.2.3.4" -s 2>&1 || true)
if grep -q "needs a port" <<<"$OUT"; then pass
else fail "the reason names the missing port" "said: ${OUT:-<nothing>}"; fi

# ─── The half a flag cannot see: well formed, and nothing behind it ─────────
#
# The flag has no way to know whether anything is listening, so this is the
# assertion for the discarded return: the cache may still come up, and the log
# has to say the dial did not happen.
"$BIN" remove rep_bad >/dev/null 2>&1 || true
DEAD=$((P + 12))
timeout 20 "$BIN" create cache rep_dead -p $((P + 13)) --replicate "127.0.0.1:$DEAD" -s >/dev/null 2>&1 || true
sleep 0.6
if grep -q "could not dial master" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
else fail "a dial that did not happen is said out loud" \
          "nothing in the daemon log mentions the master it could not reach" \
          "a follower that follows nobody is invisible until a write goes missing."; fi

# ─── And the state is visible, which is the other half of the same gap ──────
#
# rep_dead is up, follows nobody, and answers every read out of an empty
# dataset.  Before this, INFO derived role: from whether the cache was
# read-only, so it called itself a master, and neither INFO nor stats said
# anything about the link at all.
INFO_DEAD=$(send_to $((P + 13)) 'info')
if grep -q "role:slave" <<<"$INFO_DEAD"; then pass
else fail "a follower calls itself a follower" \
          "INFO says role:master on a cache configured with --replicate" \
          "got: $(grep -m1 '^role:' <<<"$INFO_DEAD" || echo '<no role line>')"; fi
if grep -q "master_link_status:down" <<<"$INFO_DEAD"; then pass
else fail "a link that is not standing reads as down" \
          "INFO does not say the link is down on a follower that never dialled" \
          "got: $(grep -m1 'master_link_status' <<<"$INFO_DEAD" || echo '<no line>')"; fi
if [ "$("$BIN" stats rep_dead 2>/dev/null | grep -m1 '^master_link:' | cut -d: -f2)" = "0" ]; then pass
else fail "stats says the same thing" \
          "stats reports repl_role but nothing about the link"; fi

# ─── Control: an ordinary pair is created and replicates ────────────────────
#
# Load-bearing: everything above passes on a build that refuses every target.
"$BIN" remove rep_dead >/dev/null 2>&1 || true
LEADER=$((P + 14)); FOLLOWER=$((P + 15))
RC=0
timeout 20 "$BIN" create cache rep_leader -p "$LEADER" -s >/dev/null 2>&1 || RC=$?
sleep 0.4
send_to "$LEADER" 'set replok beforeattach' >/dev/null
RC2=0
OUT=$(timeout 20 "$BIN" create cache rep_follower -p "$FOLLOWER" \
        --replicate "127.0.0.1:$LEADER" -s 2>&1) || RC2=$?
if [ "$RC" -eq 0 ] && [ "$RC2" -eq 0 ]; then pass
else fail "an ordinary pair is still created" \
          "leader exited $RC, follower exited $RC2" \
          "said: ${OUT:-<nothing>}"; fi

sleep 1.2
if [ "$(send_to "$FOLLOWER" 'get replok')" = "beforeattach" ]; then pass
else fail "the ordinary pair still replicates" \
          "the follower does not have the key the leader had at attach time" \
          "got: '$(send_to "$FOLLOWER" 'get replok')'"; fi

send_to "$LEADER" 'set repllive afterattach' >/dev/null
sleep 0.8
if [ "$(send_to "$FOLLOWER" 'get repllive')" = "afterattach" ]; then pass
else fail "a live write still reaches the follower" \
          "got: '$(send_to "$FOLLOWER" 'get repllive')'"; fi

# ─── A leader named rather than spelled in dotted quads ─────────────────────
#
# The manual offers "--replicate host:port" and connect_to_master() asked
# inet_pton, which takes literals only, so `--replicate localhost:6379` refused
# every time and said nothing.  Forced to AF_INET, so this resolves to
# 127.0.0.1 and not ::1.
RC=0
timeout 20 "$BIN" create cache rep_named -p $((P + 16)) \
    --replicate "localhost:$LEADER" -s >/dev/null 2>&1 || RC=$?
sleep 1.2
if [ "$RC" -eq 0 ] && [ "$(send_to $((P + 16)) 'get replok')" = "beforeattach" ]; then pass
else fail "a leader named rather than spelled is followed too" \
          "create exited $RC and the follower does not have the leader's key" \
          "got: '$(send_to $((P + 16)) 'get replok')'"; fi

# The same three questions on a pair that IS connected, which is what separates
# the lines above from a build that always says "down".
INFO_LIVE=$(send_to "$FOLLOWER" 'info')
if grep -q "master_link_status:up" <<<"$INFO_LIVE"; then pass
else fail "a standing link reads as up" \
          "got: $(grep -m1 'master_link_status' <<<"$INFO_LIVE" || echo '<no line>')"; fi
if grep -q "master_port:$LEADER" <<<"$INFO_LIVE"; then pass
else fail "the follower names the port it follows" \
          "got: $(grep -m1 'master_port' <<<"$INFO_LIVE" || echo '<no line>')"; fi
INFO_LEADER=$(send_to "$LEADER" 'info')
if grep -qE "connected_slaves:[1-9]" <<<"$INFO_LEADER"; then pass
else fail "the leader counts its followers" \
          "got: $(grep -m1 'connected_slaves' <<<"$INFO_LEADER" || echo '<no line>')"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
