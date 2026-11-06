#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a change the rest of socketley tells a dns runtime of reaches the zones it falls in, and no other.
#
# What each part would catch:
#   * every zone read, signed and given a new serial again for a name published in one of them: a secondary of
#     every other zone transferring it for nothing, and every shard signing every zone again
#   * the zone the name falls in left as it was: its serial or its SOA signature unmoved, so no secondary sees it
#   * a name relative to every zone reaching only one of them
#   * a serial that a restart, or another shard, gives otherwise than the one served before it
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { [ "$2" = "$3" ] && ok "$1" || bad "$1" "got '$2', want '$3'"; }

command -v dig >/dev/null 2>&1 || { echo "  SKIP: dig is required"; exit 0; }

daemon_isolate dns_feed_zones
T="$SOCKETLEY_TMPD"
NS=$((SL_PORT_BASE+1750))
trap daemon_stop EXIT

echo "=== Integration: a feed change reaches the zones it falls in ==="

for z in a b; do
    cat > "$T/$z.zone" <<EOF
\$ORIGIN $z.test.
\$TTL 3600
@         IN SOA ns1 hostmaster ( 2026110601 1h 15m 1w 300 )
          IN NS  ns1
ns1       IN A   192.0.2.53
EOF
done

daemon_start "$BIN"
"$BIN" create dns ns -p "$NS" --bind 127.0.0.1 --zone "$T/a.zone,$T/b.zone" --publish 192.0.2.10 --dnssec --rrl 0 \
    --shards 2 --proxy none -s >/dev/null 2>&1
q() { dig +time=2 +tries=1 -p "$NS" @127.0.0.1 "$@" 2>/dev/null; }
for _ in $(seq 1 50); do q +short b.test SOA | grep -q . && break; sleep 0.1; done
serial() { q +short "$1" SOA | awk '{print $3}'; }
# The SOA's signature, which a zone signed again makes anew with the serial it carries.
soa_sig() { q +dnssec +noall +answer "$1" SOA | awk '$4 == "RRSIG" { print $NF }'; }
# The serial each of several queries is answered with, from ports the kernel spreads over the shards.
serials() { for _ in $(seq 1 12); do serial "$1"; done | sort -u | tr '\n' ' '; }

# Something published first, so both zones are past whatever the runtime's start wrote to the feed.
"$BIN" create server first -p $((SL_PORT_BASE+1751)) --domain first.a.test >/dev/null 2>&1
for _ in $(seq 1 50); do [ -n "$(q +short first.a.test A)" ] && break; sleep 0.2; done
sleep 1.5
a1=$(serial a.test); b1=$(serial b.test)
as1=$(soa_sig a.test); bs1=$(soa_sig b.test)
[ -n "$a1" ] && [ -n "$bs1" ] && ok "both zones are served signed ($a1, $b1)" || bad "both zones are served signed" "'$a1' '$bs1'"

"$BIN" create server web -p $((SL_PORT_BASE+1752)) --domain www.a.test >/dev/null 2>&1
for _ in $(seq 1 50); do [ -n "$(q +short www.a.test A)" ] && break; sleep 0.2; done
expect "a name published in one zone is served there" "$(q +short www.a.test A)" "192.0.2.10"
sleep 1.5
a2=$(serial a.test); b2=$(serial b.test)
if [ "${a2:-0}" -gt "${a1:-0}" ] 2>/dev/null; then ok "and its zone's serial grows ($a1 -> $a2)"
else bad "the serial of the zone the name is in" "$a1 -> $a2"; fi
[ "$(soa_sig a.test)" != "$as1" ] && ok "and its SOA is signed anew" || bad "the SOA signature of the zone the name is in" "unchanged"
expect "the other zone's serial is the one it had" "$b2" "$b1"
expect "and so is its SOA's signature" "$(soa_sig b.test)" "$bs1"

"$BIN" remove web >/dev/null 2>&1
for _ in $(seq 1 50); do [ -z "$(q +short www.a.test A)" ] && break; sleep 0.2; done
expect "a name gone is gone from its zone" "$(q +short www.a.test A)" ""
sleep 1.5
a3=$(serial a.test)
if [ "${a3:-0}" -gt "${a2:-0}" ] 2>/dev/null; then ok "and its serial grows again ($a2 -> $a3)"
else bad "the serial after the name went" "$a2 -> $a3"; fi
expect "the other zone's still the one it had" "$(serial b.test)" "$b1"

# Relative, so under every apex.
"$BIN" create server chat -p $((SL_PORT_BASE+1753)) --domain chat >/dev/null 2>&1
for _ in $(seq 1 50); do [ -n "$(q +short chat.b.test A)" ] && break; sleep 0.2; done
sleep 1.5
a4=$(serial a.test); b4=$(serial b.test)
if [ "${a4:-0}" -gt "${a3:-0}" ] 2>/dev/null && [ "${b4:-0}" -gt "${b1:-0}" ] 2>/dev/null; then
    ok "a name relative to every zone reaches every zone ($a3 -> $a4, $b1 -> $b4)"
else bad "a relative name's serials" "$a3 -> $a4, $b1 -> $b4"; fi
expect "every shard serves one serial for each zone" "$(serials a.test)/$(serials b.test)" "$a4 /$b4 "

"$BIN" stop ns >/dev/null 2>&1
"$BIN" start ns >/dev/null 2>&1
for _ in $(seq 1 50); do q +short b.test SOA | grep -q . && break; sleep 0.1; done
expect "a restart serves the serials served before it" "$(serials a.test)/$(serials b.test)" "$a4 /$b4 "

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
