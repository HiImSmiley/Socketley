#!/usr/bin/env bash
# Integration test: --bind and -p address:port bind a runtime's port on one IPv4 address alone
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a server, cache, proxy or storage runtime (a sharded one included) that
#     still binds every address when it was given one
#   * an address that is no address taken, or one the host does not have
#     leaving the runtime up on every address instead
#   * the address lost by a stop, a daemon restart or an import, or changed
#     under a running runtime
#   * 0.0.0.0 not giving every address back
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate bindaddr

P_SRV=$((SL_PORT_BASE+1951))
P_CACHE=$((SL_PORT_BASE+1957))
P_PROXY=$((SL_PORT_BASE+1959))
P_STG=$((SL_PORT_BASE+1969))
P_BAD=$((SL_PORT_BASE+1979))
P_UDP=$((SL_PORT_BASE+1989))
NAMES="ba_srv ba_cache ba_proxy ba_stg ba_bad ba_udp"

PASS=0; FAIL=0; TOTAL=0
check() { TOTAL=$((TOTAL+1)); if [ "$2" = "$3" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "  FAIL [$1]: got '$2', want '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1; done
    daemon_stop
}
trap cleanup EXIT

# The local address every listener on `port` has, sorted, one per line.
bound() { ss -Hltn "sport = :$1" 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ' '; }
bound_udp() { ss -Hlun "sport = :$1" 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ' '; }
wait_bound() { for _ in $(seq 1 100); do [ -n "$(bound "$1")" ] && return 0; sleep 0.05; done; return 1; }

echo "=== Integration: a runtime's port bound on one address ==="
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"

"$BIN" create server ba_srv -p "127.0.0.1:$P_SRV" -s >/dev/null 2>&1
"$BIN" create cache ba_cache -p "$P_CACHE" --bind 127.0.0.1 -s >/dev/null 2>&1
"$BIN" create proxy ba_proxy -p "127.0.0.1:$P_PROXY" --backend "127.0.0.1:$P_SRV" -s >/dev/null 2>&1
printf '[admin]\nAKIABINDADDRESS00001:bind-address-secret-bind-address-secr\nadmin = true\n' > "$T/creds"
"$BIN" create storage ba_stg -p "127.0.0.1:$P_STG" --dir "$T/stg" --credentials "$T/creds" --shards 2 -s >/dev/null 2>&1
for p in $P_SRV $P_CACHE $P_PROXY $P_STG; do wait_bound "$p"; done
check "a server given -p address:port binds that address alone" "$(bound "$P_SRV")" "127.0.0.1:$P_SRV "
check "a cache given --bind" "$(bound "$P_CACHE")" "127.0.0.1:$P_CACHE "
check "a proxy" "$(bound "$P_PROXY")" "127.0.0.1:$P_PROXY "
check "and a storage runtime's every shard" "$(ss -Hltn "sport = :$P_STG" | awk '{print $4}' | sort | uniq -c | awk '{print $1, $2}')" \
    "2 127.0.0.1:$P_STG"
check "which serves there" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P_STG/")" 403
check "ls --json names the address" "$("$BIN" ls --json | grep -o '"name":"ba_srv"[^}]*"bind":"[^"]*"' | grep -o '"bind":"[^"]*"')" \
    '"bind":"127.0.0.1"'

# A UDP server's socket takes the address too.
"$BIN" create server ba_udp -p "127.0.0.1:$P_UDP" --udp -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ -n "$(bound_udp "$P_UDP")" ] && break; sleep 0.05; done
check "a UDP server binds the address alone" "$(bound_udp "$P_UDP")" "127.0.0.1:$P_UDP "

# Refusals.
out=$("$BIN" create server ba_bad -p "999.1.1.1:$P_BAD" 2>&1); rc=$?
check "an address that is no address is refused" "$rc:$(grep -c 'invalid listen address' <<<"$out")" "1:1"
out=$("$BIN" create server ba_bad -p "$P_BAD" --bind localhost 2>&1); rc=$?
check "and a name is no address" "$rc" 1
# A listing that names the server is one that could have named ba_bad.
L=$("$BIN" ls --json)
check "and nothing was made" "$(grep -q '"name":"ba_srv"' <<<"$L" && grep -c '"name":"ba_bad"' <<<"$L")" 0
out=$("$BIN" edit ba_cache --bind 0.0.0.0 2>&1); rc=$?
check "the address of a running runtime is not changed" "$rc:$(grep -c 'while running' <<<"$out")" "1:1"
"$BIN" show ba_cache > "$T/cache.json"
sed -i 's/"bind": "127.0.0.1"/"bind": "127.0.0.2"/' "$T/cache.json"
check "the imported document asks for another address" "$(grep -c '"bind": "127.0.0.2"' "$T/cache.json")" 1
out=$("$BIN" import ba_cache < "$T/cache.json" 2>&1); rc=$?
check "nor by an import" "$rc:$(grep -c 'while running' <<<"$out")" "1:1"

# An address the host does not have fails the start, rather than binding every address.
"$BIN" create server ba_bad -p "192.0.2.1:$P_BAD" >/dev/null 2>&1
"$BIN" start ba_bad >/dev/null 2>&1
sleep 0.3
check "an address the host does not have binds nothing" "$(bound "$P_BAD")" ""

# Kept across a stop, a daemon restart and an import.
"$BIN" stop ba_cache >/dev/null 2>&1
"$BIN" start ba_cache >/dev/null 2>&1; wait_bound "$P_CACHE"
check "kept across a stop" "$(bound "$P_CACHE")" "127.0.0.1:$P_CACHE "
kill "$SOCKETLEY_DPID" 2>/dev/null
for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
for p in $P_SRV $P_CACHE $P_PROXY $P_STG; do for _ in $(seq 1 50); do [ -z "$(bound "$p")" ] && break; sleep 0.1; done; done
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"
for p in $P_SRV $P_CACHE $P_PROXY $P_STG; do wait_bound "$p"; done
check "and a daemon restart" "$(bound "$P_CACHE") $(bound "$P_STG")" "127.0.0.1:$P_CACHE  127.0.0.1:$P_STG "
"$BIN" stop ba_cache >/dev/null 2>&1
"$BIN" show ba_cache > "$T/cache.json"
sed -i 's/"bind": "127.0.0.1"/"bind": "nope"/' "$T/cache.json"
out=$("$BIN" import ba_cache < "$T/cache.json" 2>&1); rc=$?
check "an import of an address that is no address is refused" "$rc:$(grep -c 'not an IPv4 address' <<<"$out")" "1:1"
sed -i 's/"bind": "nope"/"bind": "127.0.0.2"/' "$T/cache.json"
"$BIN" import ba_cache < "$T/cache.json" >/dev/null 2>&1
"$BIN" start ba_cache >/dev/null 2>&1; wait_bound "$P_CACHE"
check "an import moves it" "$(bound "$P_CACHE")" "127.0.0.2:$P_CACHE "

# 0.0.0.0 is every address again.
"$BIN" stop ba_cache >/dev/null 2>&1
"$BIN" edit ba_cache --bind 0.0.0.0 >/dev/null 2>&1
"$BIN" start ba_cache >/dev/null 2>&1; wait_bound "$P_CACHE"
check "--bind 0.0.0.0 binds every address" "$(bound "$P_CACHE")" "0.0.0.0:$P_CACHE "
S=$("$BIN" show ba_cache)
check "and is no address in the state" "$([ -n "$S" ] && grep -c '"bind"' <<<"$S")" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
