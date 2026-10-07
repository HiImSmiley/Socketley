#!/usr/bin/env bash
# Integration test: names runtimes are reached by, and the entrance that routes requests by them.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   ownership    a name belongs to one runtime: a second one is refused at
#                create, edit and import, whatever its case or trailing dot,
#                and across types; the runtimes of one group share a name; the
#                entrance, a proxy without --backend, has none of its own
#   publishing   a dns runtime with --proxy answers every runtime's name with
#                this machine's public address, or --publish's; a cache's name
#                too, though only HTTP runtimes are routed
#   the table    the entrance's routes: each HTTP runtime's names, a short name
#                under each zone, a storage runtime's buckets beneath it, the
#                runtimes of a group together, nothing for a cache
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate edge
P=$((SL_PORT_BASE+1740))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: names and the entrance ==="
daemon_start "$BIN"

# ── ownership ───────────────────────────────────────────────────────────────
expect "a runtime takes a name" "$("$BIN" create server a -p "$P" --domain chat 2>&1)" ""
has "a second runtime is refused it, whatever its case and trailing dot" \
    "$("$BIN" create server b -p $((P+1)) --domain Chat. 2>&1)" "chat is already the name of runtime 'a'"
has "and so is a runtime of another type" \
    "$("$BIN" create storage s -p $((P+2)) --dir "$T/s" --anonymous --domain chat 2>&1)" "already the name of runtime 'a'"
expect "the runtimes of one group share a name" \
    "$("$BIN" create server g1 -p $((P+3)) -g web --domain www 2>&1)$("$BIN" create server g2 -p $((P+4)) -g web --domain www 2>&1)" ""
has "edit cannot take another's name" "$("$BIN" edit g1 --domain chat 2>&1)" "already the name of runtime 'a'"
has "nor import" "$("$BIN" import a '{"name":"a","domain":"www"}' 2>&1)" "already the name of runtime"
has "and the refused import left the runtime as it was" "$("$BIN" show a 2>&1)" '"domain": "chat"'
has "the entrance has no name of its own" "$("$BIN" create proxy e -p $((P+5)) --domain x 2>&1)" "has no name of its own"
expect "and nothing refused was made" "$("$BIN" ls 2>/dev/null | awk 'NR>1 {print $2}' | sort | tr '\n' ' ')" "a g1 g2 "
for r in a g1 g2; do "$BIN" remove "$r" >/dev/null 2>&1; done

# ── publishing, through the entrance ────────────────────────────────────────
command -v dig >/dev/null 2>&1 || { echo "  SKIP: dig is not installed, so names are not asked for"; echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"; }
cat > "$T/z.zone" <<'EOF'
$ORIGIN example.com.
$TTL 300
@    SOA ns1 hostmaster 1 1h 15m 1w 60
     NS  ns1
ns1  A   192.0.2.53
mail A   192.0.2.25
EOF
DNS=$((P+10))
"$BIN" create dns ns -p "$DNS" --zone "$T/z.zone" --proxy web --rrl 0 -s >/dev/null 2>&1
"$BIN" create proxy web -p $((P+11)) >/dev/null 2>&1
"$BIN" create storage ui -p $((P+12)) --dir "$T/ui" --anonymous --domain ui >/dev/null 2>&1
"$BIN" create cache mycache -p $((P+13)) --domain mycache >/dev/null 2>&1
qd() { dig @127.0.0.1 -p "$DNS" +time=2 +tries=1 +short "$@" 2>&1; }
got=""
for _ in $(seq 1 40); do got=$(qd ui.example.com A); [ -n "$got" ] && break; sleep 0.2; done
mine=$(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -n "$got" ]; then
    case " $(echo $mine) " in *" $got "*) ok "with --proxy and no --publish, a name is answered with this machine's address ($got)" ;;
        *) bad "this machine's address" "answered $got; this machine has: $(echo $mine)" ;; esac
else
    echo "  SKIP: this machine has no public address on its interfaces, so --proxy publishes nothing by itself"
fi
"$BIN" stop ns >/dev/null 2>&1; "$BIN" remove ns >/dev/null 2>&1
"$BIN" create dns ns -p "$DNS" --zone "$T/z.zone" --proxy web --publish 198.51.100.7 --rrl 0 -s >/dev/null 2>&1
for _ in $(seq 1 40); do got=$(qd ui.example.com A); [ "$got" = 198.51.100.7 ] && break; sleep 0.2; done
expect "--publish names the address instead" "$got" "198.51.100.7"
expect "a storage runtime's buckets under its short name" "$(qd photos.ui.example.com A)" "198.51.100.7"
expect "a cache's name is published too" "$(qd mycache.example.com A)" "198.51.100.7"
expect "a name the zone file gives an address keeps it" "$(qd mail.example.com A)" "192.0.2.25"

# ── the table the entrance routes by ────────────────────────────────────────
"$BIN" create server chat1 -p $((P+14)) -g chat --domain chat >/dev/null 2>&1
"$BIN" create server chat2 -p $((P+15)) -g chat --domain chat >/dev/null 2>&1
want="zone example.com
route *.ui.example.com 127.0.0.1:$((P+12))
route chat.example.com 127.0.0.1:$((P+14)) 127.0.0.1:$((P+15))
route ui.example.com 127.0.0.1:$((P+12))"
table=""
for _ in $(seq 1 40); do table=$(cat "$(find "$T" -name routes-web | head -1)" 2>/dev/null); [ "$table" = "$want" ] && break; sleep 0.2; done
expect "the entrance's table: each HTTP runtime's names, a group together, no cache" "$table" "$want"
"$BIN" remove chat2 >/dev/null 2>&1
for _ in $(seq 1 40); do grep -q "$((P+15))" "$(find "$T" -name routes-web | head -1)" || break; sleep 0.2; done
has "a runtime removed leaves the table" "$(cat "$(find "$T" -name routes-web | head -1)")" "route chat.example.com 127.0.0.1:$((P+14))
"
"$BIN" remove web >/dev/null 2>&1
for _ in $(seq 1 40); do [ -z "$(find "$T" -name routes-web)" ] && break; sleep 0.2; done
expect "and an entrance removed, its table" "$(find "$T" -name routes-web | wc -l)" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
