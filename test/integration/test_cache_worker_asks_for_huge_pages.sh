#!/usr/bin/env bash
# Integration test: a cache's worker is exec'd with the glibc tunable that
# turns its heap into huge pages, and no other runtime is.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# Profiled at pipeline depth 100, 61.67% of a cache worker's time sits in one
# symbol -- _Hashtable::_M_find_before_node_tr -- plus 5.13% in the memcmp it
# calls and 2.67% in the hash.  Nearly seven tenths of a pipelined operation is
# one lookup over a keyspace far larger than the TLB covers.  glibc hands a
# process huge pages only when asked, and it reads the tunable at startup, so
# the process can never ask for itself: whoever spawns it must.
#
# Measured, cache holding ~173k keys, GET at -P 100, seven interleaved passes
# with the order rotated: 4,510,440 -> 5,211,085 a second, 6 of 6 passes, the
# spread [1.106, 1.185] clear of 1.00.  At depth 1 the same change is +4.5% on
# 7 of 8 passes with a spread that contains 1.00, so it is not claimed there.
#
# A server serving a cached file measured 0.9994 with them, spread
# [0.971, 1.077] -- nothing -- for 0.8 to 3.7 MB of RSS, which is why the cache
# is the only type that asks.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   cache worker has it        the spawn path reverted to execl(), which
#                              inherits the daemon's environment and asks for
#                              nothing
#   server/proxy do NOT        a build that passed `true` unconditionally and
#                              charged every runtime the RSS
#   daemon does not            a build that set it globally with setenv()
#   SOCKETLEY_HUGEPAGE=0       the operator's veto stopped being read
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate hugepage

P_CACHE=$((SL_PORT_BASE+1900))
P_SRV=$((SL_PORT_BASE+1910))
P_PRX=$((SL_PORT_BASE+1920))
NAMES="hp_cache hp_srv hp_prx"

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

echo "=== Integration: only a cache's worker asks for huge pages ==="
daemon_start "$BIN"

# The worker behind a port, not "some socketley": three runtimes are up and
# picking the wrong one is how this test would pass for the wrong reason.
worker_on_port() {
    local port=$1 p
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        [ "$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null)" = "$SOCKETLEY_DPID" ] || continue
        if ls -l "/proc/$p/fd" 2>/dev/null | grep -q "socket:" &&
           ss -ltnpH "sport = :$port" 2>/dev/null | grep -q "pid=$p,"; then
            echo "$p"; return 0
        fi
    done
    echo ""
}
tunable_count() {
    local p=$1
    [ -n "$p" ] || { echo "no-worker"; return; }
    tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -c '^GLIBC_TUNABLES=.*hugetlb=1' || true
}

create_ok "a cache"  "$BIN" create cache  hp_cache -p "$P_CACHE"
create_ok "a server" "$BIN" create server hp_srv   -p "$P_SRV"
create_ok "a proxy"  "$BIN" create proxy  hp_prx   -p "$P_PRX" --backend "127.0.0.1:$P_SRV"
for n in $NAMES; do "$BIN" start "$n" >/dev/null 2>&1 || true; done
ready_resp 127.0.0.1 "$P_CACHE" 15 || true
ready_tcp  127.0.0.1 "$P_SRV"   15 || true
sleep 1

WC=$(worker_on_port "$P_CACHE")
WS=$(worker_on_port "$P_SRV")
WP=$(worker_on_port "$P_PRX")
if [ -n "$WC" ] && [ -n "$WS" ] && [ -n "$WP" ]; then ok
else bad "all three workers were found" "cache='$WC' server='$WS' proxy='$WP'"; fi

check "the cache's worker asks for huge pages"  "1" "$(tunable_count "$WC")"
check "the server's worker does not"            "0" "$(tunable_count "$WS")"
check "the proxy's worker does not"             "0" "$(tunable_count "$WP")"
check "and the daemon itself does not"          "0" "$(tunable_count "$SOCKETLEY_DPID")"

# The cache still serves; a tunable that broke the exec would show up here and
# nowhere else in this file.
redis_reply=$(printf '*1\r\n$4\r\nPING\r\n' | timeout 3 nc -q0 127.0.0.1 "$P_CACHE" 2>/dev/null | tr -d '\r\n' || true)
check "and the cache still answers" "+PONG" "$redis_reply"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
