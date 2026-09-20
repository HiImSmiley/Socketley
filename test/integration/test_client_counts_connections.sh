#!/usr/bin/env bash
# Integration test: a client's total_connections counts connections, not dials.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE COUNTER WAS INCREMENTED AT THE DIAL.  try_connect() reaches its
#   `connected:` label whenever connect() answers 0 *or* EINPROGRESS, and a
#   non-blocking connect to anything that is not already there answers
#   EINPROGRESS -- the refusal arrives later, as -ECONNREFUSED on a CQE.  So a
#   client pointed at a port nobody holds reported, measured on 2dfdc3ad over
#   twenty-two seconds:
#
#       connections:0   total_connections:2 3 4 5
#
#   -- five connections and none of them at the same time.  Every other runtime
#   counts something that happened: the server at accept(), the cache at
#   accept(), the proxy after on_auth admits a client.  The client counted an
#   intention, and the daemon's own socketley_connections_total, whose HELP
#   text reads "Total connections accepted", summed it in with the rest.
#
# ─── WHY IT IS SIX ASSERTIONS AND NOT ONE ───────────────────────────────────
#
# "total_connections stays 0 against a dead target" is also true of a build
# whose client never dials, and of one where the counter was simply deleted.
# So the dead-target arm is paired with dial_attempts, which says the client
# really did keep trying, and with a live arm that has to count its connection.
#
# The live client is SILENT -- no script, no traffic in either direction.  That
# is the arm that fails a fix which counts at the first byte instead of at the
# dial: a `--mode in` client waiting on a server that pushes once an hour is
# connected for that hour, and has to be counted for it.
#
# Seen red with the increment put back where it was, on this tree: these two,
#
#   FAIL [a dial that never connected is not counted]: total_connections is '4'
#   FAIL [the two counters are two numbers]: live dials=2 connections=2, ...
#
# and the other seven green, which is what says the file is about the change.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate client_counts

# lib_ports.sh's `exec 9>lockfile 2>/dev/null` applies both redirections to
# this shell, so stderr is put back before anything can need it.
exec 2>&1

S_LIVE=$((SL_PORT_BASE+811))    # a server that is really there
P_DEAD=$((SL_PORT_BASE+812))    # a port nobody holds, and nobody may hold

PASS=0; FAIL=0; TOTAL=0      # TOTAL is lib_create.sh's convention
ok()  { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in c_live c_dead s_live; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in c_live c_dead s_live; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# One field of one runtime's `stats`, empty when the daemon did not answer or
# the build does not report it -- which the assertions below tell apart.
stat_of() { "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\([0-9][0-9]*\)$/\1/p" | head -1; }

# Poll a field to a value, to a deadline, because the backoff this client runs
# on starts at a second: the honest assertion is that it converges and the
# honest failure is that it did not within a stated bound.
wait_stat() {  # name field want deadline_s
    local i=0
    while [ "$i" -lt "$4" ]; do
        [ "$(stat_of "$1" "$2")" = "$3" ] && return 0
        sleep 1; i=$((i+1))
    done
    return 1
}

# The same, for the assertions whose claim is "at least": an empty field --
# which is what a build with no such counter answers -- is never enough.
wait_stat_min() {  # name field least deadline_s
    local i=0 v
    while [ "$i" -lt "$4" ]; do
        v=$(stat_of "$1" "$2")
        [ -n "$v" ] && [ "$v" -ge "$3" ] && return 0
        sleep 1; i=$((i+1))
    done
    return 1
}

echo "=== Integration: a client counts connections, not dials ==="

daemon_start "$BIN"

# The dead port has to be dead before anything is read from it.  A listener
# that outlived another file would make this whole arm a statement about a
# stranger, and a server sets SO_REUSEPORT, so it would not even collide.
HELD=$(ss -ltnH 2>/dev/null | awk -v p="$P_DEAD" '{n=split($4,a,":"); if(a[n]==p) print p}')
if [ -z "$HELD" ]; then ok
else bad "the dead port is dead" \
         "something is listening on $P_DEAD, so the arm below would be measuring it"; fi

create_ok "server for the live client" "$BIN" create server s_live -p "$S_LIVE" --mode inout -s
create_ok "client, a target that is there"  "$BIN" create client c_live -t "127.0.0.1:$S_LIVE" --reconnect -s
create_ok "client, a target that is not"    "$BIN" create client c_dead -t "127.0.0.1:$P_DEAD" --reconnect -s

# ── A connection that is there, and says nothing ────────────────────────────
if wait_stat c_live connections 1 10; then ok
else bad "control: the live client connects at all" \
         "never reported a connection; nothing below it can be read"; fi

if wait_stat_min c_live total_connections 1 10; then ok
else bad "a silent connection is counted" \
         "total_connections is '$(stat_of c_live total_connections)', wanted 1 -- this client is connected and has sent and received nothing, which is what a --mode in client does all day"; fi

# ── A target that is not there ──────────────────────────────────────────────
#
# Four dials is roughly eight seconds of backoff (1, 2, 4), and the deadline is
# generous because what is being asserted is that they happened at all.
if wait_stat_min c_dead dial_attempts 4 20; then ok
else bad "control: the dead client keeps dialling" \
         "dial_attempts is '$(stat_of c_dead dial_attempts)', wanted 4 -- an empty value means this build does not report the field, and a small one means the client stopped trying, and the assertion below proves nothing in either case"; fi

DC=$(stat_of c_dead total_connections)
if [ "$DC" = "0" ]; then ok
else bad "a dial that never connected is not counted" \
         "total_connections is '$DC' after four dials to a port nobody holds; connections is '$(stat_of c_dead connections)'"; fi

# ── And the two do come apart ───────────────────────────────────────────────
#
# The one assertion that fails on a build where dial_attempts is a second name
# for the same number.
LD=$(stat_of c_live dial_attempts); DD=$(stat_of c_dead dial_attempts)
LC=$(stat_of c_live total_connections)
if [ "$LD" = "$LC" ] && [ "$DD" != "$DC" ]; then ok
else bad "the two counters are two numbers" \
         "live dials=$LD connections=$LC, dead dials=$DD connections=$DC -- wanted the live pair equal and the dead pair not"; fi

echo ""
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ]
