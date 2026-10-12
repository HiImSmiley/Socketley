#!/usr/bin/env bash
# suite: isolated
# Integration test: a runtime is restarted through itself, and lives.
#
# A dashboard is reached through an entrance proxy, so the commands that change
# that proxy travel through it.  As a stop, an import and a start they are three
# round trips, and the first one cuts the other two off: measured on a live box,
# the entrance stopped with its configuration unchanged, and every site behind
# it with it.  The daemon now does all three, so what becomes of the caller's
# connection decides nothing.
#
# The shard count is the setting under test because it is one a running runtime
# refuses outright -- the case that needs the stop at all -- and because the
# listeners on the port count the shards, so the change is visible from outside.
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: a runtime restarted through itself ==="
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate rtself
trap 'daemon_stop' EXIT
T="$SOCKETLEY_TMPD"
mkdir -p "$T/www"; printf 'behind\n' > "$T/www/i.txt"
daemon_start "$BIN"

BE=$((SL_PORT_BASE + 1770)); EN=$((SL_PORT_BASE + 1771))
"$BIN" create server be -p "$BE" --bind 127.0.0.1 --http "$T/www" -s >/dev/null
# The entrance: everything below is asked for through it, as a dashboard is.
"$BIN" create proxy ent -p "$EN" --bind 127.0.0.1 --backend "127.0.0.1:$BE" --shards 4 -s >/dev/null
for _ in $(seq 1 150); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$EN/ent/i.txt")" = 200 ] && break
    sleep 0.1
done

state() { "$BIN" ls 2>/dev/null | awk -v n=" ent " '$0 ~ n {print $7}'; }
# show leaves out a field at its default, and one shard is the default, so a missing line reads as the 1 it is.
shards() { local v; v=$("$BIN" show ent 2>/dev/null | sed -n 's/.*"shards": \([0-9]*\).*/\1/p'); echo "${v:-1}"; }
# One line per listening worker, which is the shard count from outside the daemon.
workers() { ss -ltn "sport = :$EN" 2>/dev/null | grep -c ":$EN "; }
# What a caller reached through the entrance sees; empty when it is not listening.
through() { curl -s -m 5 "http://127.0.0.1:$EN/ent/i.txt" 2>/dev/null; }

check "the entrance serves what is behind it" "$(through)" behind
check "on four shards" "$(workers)" 4

# ── the change a running runtime refuses ────────────────────────────────────
OUT=$("$BIN" edit ent --shards 1 2>&1); RC=$?
check "a shard count does not change while it runs" "$RC $(grep -c 'while running' <<<"$OUT")" "1 1"
check "and the runtime is untouched by the refusal" "$(state) $(shards)" "Up 4"

# ── the same change, carried across a restart ───────────────────────────────
"$BIN" restart ent --shards 1 >/dev/null 2>&1
RC=$?
for _ in $(seq 1 150); do [ "$(through)" = behind ] && break; sleep 0.1; done
check "restart with the flag is taken" "$RC" 0
check "the runtime is running again" "$(state)" Up
check "on one shard" "$(workers)" 1
check "and still serves what is behind it" "$(through)" behind

# ── a refused flag leaves it running ────────────────────────────────────────
OUT=$("$BIN" restart ent --shards 999 2>&1); RC=$?
check "a value the runtime refuses is refused" "$RC $(grep -c 'between 1 and 64' <<<"$OUT")" "1 1"
check "and leaves it running" "$(state) $(through)" "Up behind"

# ── restart with nothing to change ──────────────────────────────────────────
"$BIN" restart ent >/dev/null 2>&1
for _ in $(seq 1 150); do [ "$(through)" = behind ] && break; sleep 0.1; done
check "a restart with no flags keeps the configuration" "$(shards)" 1
check "and ends running" "$(state) $(through)" "Up behind"

# A stopped runtime is started by restart, as it was before this was one command.
"$BIN" stop ent >/dev/null 2>&1
"$BIN" restart ent >/dev/null 2>&1
for _ in $(seq 1 150); do [ "$(through)" = behind ] && break; sleep 0.1; done
check "a stopped runtime is started by restart" "$(state)" Up

# ── the document door, which is the one the dashboard uses ──────────────────
"$BIN" import ent --restart '{"shards":2}' >/dev/null 2>&1
for _ in $(seq 1 150); do [ "$(through)" = behind ] && break; sleep 0.1; done
check "import takes the flag too" "$(shards) $(state)" "2 Up"
check "on two shards" "$(workers)" 2

# The flag is the caller's own, so it is not part of the document whichever side of it it stands on.
"$BIN" import ent '{"shards":4}' --restart >/dev/null 2>&1
for _ in $(seq 1 150); do [ "$(through)" = behind ] && break; sleep 0.1; done
check "the flag after the document is not imported as part of it" "$(shards) $(state)" "4 Up"

# ── and a configuration command does not start what was stopped ─────────────
"$BIN" stop ent >/dev/null 2>&1
"$BIN" edit ent --shards 3 --restart >/dev/null 2>&1
check "edit --restart leaves a stopped runtime stopped" "$(state) $(shards)" "Stopped 3"

# restart is the lifecycle verb and means one thing with flags and without: it ends with the runtime running.
"$BIN" restart ent --shards 2 >/dev/null 2>&1
for _ in $(seq 1 150); do [ "$(through)" = behind ] && break; sleep 0.1; done
check "restart with flags starts a stopped runtime too" "$(state) $(shards)" "Up 2"
check "and the flags were applied" "$(workers)" 2

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
