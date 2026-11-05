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
# Measured on this tree: two shards behind one address take 1.91 cores and
# return 1.05x of what ONE shard returns, four take 3.95 and return 1.75x, while
# the same four slot-routed return 2.80x. Per-operation cost roughly doubles,
# 4.16 us at one shard against 7.60 at two. The flag reads like a scaling
# feature and in that arrangement is mostly not one, so the runtime names the
# cost at start.
#
# The size of it depends on how well the crossings batch, and the CLIENT decides
# that: the same 192 connections as 12x16 give 0.90x where 8x24 give 1.05x. That
# is why the line names the mechanism and not a ratio.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   exactly 1 on --shards 3         a build that dropped the line entirely, and
#   --no-cluster                    one that dropped `m_shard_i == 0` and says
#                                   it once per shard
#   0 with no flag, and with        a build that dropped `!m_cluster_on`,
#   --cluster                       warning about the arrangement that is the
#                                   remedy, and one whose default stayed off
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
P_DEF=$((SL_PORT_BASE+1970))     # ebenso, ohne Flag
NAMES="sw_one sw_rel sw_clu sw_def"

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
create_ok "a cache at three shards, one address" "$BIN" create cache sw_rel -p "$P_REL" --shards 3 --no-cluster
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

# ─── 2b. Dieselben drei ohne Flag, im Cluster-Modus als Vorgabe ─────────────
create_ok "the same three with no flag" "$BIN" create cache sw_def -p "$P_DEF" --shards 3
"$BIN" start sw_def >/dev/null 2>&1 || true
ready_resp 127.0.0.1 "$P_DEF" 15 || true
sleep 0.5
check "it is up"                       "Up" "$(state sw_def)"
check "and says nothing: the remedy is the default" "0" "$(said_for sw_def)"

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
