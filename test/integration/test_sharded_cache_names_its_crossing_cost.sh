#!/usr/bin/env bash
# Integration test: a cache sharded behind ONE address says so, once.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# `--shards N` is two different bargains. On a server the shards are
# interchangeable -- every one answers every request -- and the flag buys
# throughput. On a cache a key belongs to exactly one shard, SO_REUSEPORT hands
# out whole connections without knowing the key, and the shard that accepted a
# foreign key relays it to the owner.
#
# Measured on this tree: two shards behind one address serve 0.89x of what ONE
# shard serves, for 1.9 cores instead of 1.0 -- a crossing costs about 13 us of
# server CPU where answering a local key costs 5.8. The flag is a regression in
# that arrangement and reads like a scaling feature, so the runtime now names
# the cost at start.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   exactly 1 on --shards 3         a build that dropped the line entirely, and
#                                   one that dropped `m_shard_i == 0` and says
#                                   it once per shard
#   0 with --cluster                a build that dropped `!m_cluster_forced`,
#                                   warning about the arrangement that is the
#                                   remedy
#   0 at --shards 1                 a build that dropped `m_shard_n > 1`
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate shardwarn

P_ONE=$((SL_PORT_BASE+1940))
P_REL=$((SL_PORT_BASE+1950))
P_CLU=$((SL_PORT_BASE+1960))     # braucht base+1..base+3 dazu
NAMES="sw_one sw_rel sw_clu"

PASS=0; FAIL=0; TOTAL=0
ok()    { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()   { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop   "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a single-address sharded cache names its crossing cost ==="
daemon_start "$BIN"

# Zaehlt die Zeile fuer EINEN Cache, nicht fuer irgendeinen: die Meldung fuehrt
# den Namen, sonst zaehlte dieser Test drei Arme als einen.
said_for() { grep -c "cache \"$1\": .* shards share one address" "$SOCKETLEY_DLOG" 2>/dev/null || true; }
state()    { "$BIN" ps -a 2>/dev/null | awk -v n="$1" '$2==n { print $7 }'; }

# ─── 1. Drei Shards hinter einer Adresse ────────────────────────────────────
create_ok "a cache at three shards, one address" "$BIN" create cache sw_rel -p "$P_REL" --shards 3
"$BIN" start sw_rel >/dev/null 2>&1 || true
ready_resp 127.0.0.1 "$P_REL" 15 || true
sleep 0.5
check "it is up"                       "Up" "$(state sw_rel)"
check "and it said so exactly once"    "1"  "$(said_for sw_rel)"

# ─── 2. Dieselben drei Shards mit --cluster ─────────────────────────────────
create_ok "the same three under --cluster" "$BIN" create cache sw_clu -p "$P_CLU" --shards 3 --cluster
"$BIN" start sw_clu >/dev/null 2>&1 || true
ready_resp 127.0.0.1 "$P_CLU" 15 || true
sleep 0.5
check "it is up"                       "Up" "$(state sw_clu)"
check "and says nothing: that IS the remedy" "0" "$(said_for sw_clu)"

# ─── 3. Ein Shard ───────────────────────────────────────────────────────────
create_ok "an unsharded cache" "$BIN" create cache sw_one -p "$P_ONE"
"$BIN" start sw_one >/dev/null 2>&1 || true
ready_resp 127.0.0.1 "$P_ONE" 15 || true
sleep 0.5
check "it is up"                       "Up" "$(state sw_one)"
check "and has nothing to warn about"  "0"  "$(said_for sw_one)"

# ─── 4. Die Anordnung, vor der gewarnt wird, bedient trotzdem ───────────────
# Eine Warnung ueber etwas, das nicht mehr funktioniert, waere ein Fehler und
# keine Warnung.  Drei Keys, die nach CLUSTER KEYSLOT auf drei Besitzer fallen,
# ueber EINE Verbindung -- also Ueberquerungen, genau der Weg, den die Meldung
# benennt.
round_trip=$(python3 - 127.0.0.1 "$P_REL" <<'PYX'
import socket, sys
def enc(*a):
    out = b"*%d\r\n" % len(a)
    for x in a: out += b"$%d\r\n%s\r\n" % (len(x), x)
    return out
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), 5); s.settimeout(5)
keys = [b"a", b"b", b"c"]        # Slots 15495 / 3300 / 7365
for k in keys: s.sendall(enc(b"SET", k, b"v" + k))
for k in keys: s.sendall(enc(b"GET", k))
buf = b""
try:
    while not all((b"v" + k) in buf for k in keys):
        d = s.recv(4096)
        if not d: break
        buf += d
except socket.timeout:
    pass
print("ok" if all((b"v" + k) in buf for k in keys) else "missing:" + repr(buf[:160]))
PYX
) || round_trip="python-failed"
check "and the warned-about cache still serves across shards" "ok" "$round_trip"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
