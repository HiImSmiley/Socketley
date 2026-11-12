#!/usr/bin/env bash
# suite: isolated -- its own network and mount namespace, daemons, sockets and port window, so it runs beside the others
# Integration test: a proxy follows a group member whose host name moved to another address.
#
# A member on another daemon is reached by the name that daemon advertises, and the proxy carried the address it
# resolved for as long as the member stayed in the group, so a node back on a new address under its old name -- a
# container restarted, a pod rescheduled -- was dialled at the old one until it left the group, with the resolver's
# thirty-second cache handing the old address back to a lookup that came too soon. The container cluster test saw
# it: api2 restarted at 10.4.1.13 instead of 10.4.1.12 and never took traffic again.
#
# What each part would catch:
#   * the name, the group and this namespace's hosts file not working here: the member answers at its first address
#   * an address carried over, or looked up again out of the resolver's cache: the member, still running and still
#     in the group, answers after its name moved to a second address and the first one went away
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rnm true 2>/dev/null; then
        echo "=== Integration: a proxy follows a group member whose host name moved ==="
        echo "  SKIP: no unprivileged network and mount namespace here"
        exit 0
    fi
    exec unshare -rnm env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a proxy follows a group member whose host name moved ==="
ip link set lo up
daemon_isolate grpmoved
T=$SOCKETLEY_TMPD
NAME=$(hostname)

# The member's daemon advertises this machine's name, which this namespace's hosts file sends to the first address.
# The rest of 10.9.0.0/24 goes into a dummy device, which drops it: an address that moved away goes silent, as a
# container's does, rather than refusing at once.
ip addr add 10.9.0.2/32 dev lo
ip link add slmv0 type dummy && ip link set slmv0 up && ip route add 10.9.0.0/24 dev slmv0 \
    || { echo "  SKIP: no dummy device in this namespace"; exit 0; }
printf '127.0.0.1 localhost\n10.9.0.2 %s\n' "$NAME" > "$T/hosts"
mount --bind "$T/hosts" /etc/hosts || { echo "  SKIP: /etc/hosts cannot be replaced here"; exit 0; }

PR=$((SL_PORT_BASE + 1961)); PM=$((SL_PORT_BASE + 1962))
SOCK2="$T/two.sock"; HOME2="$T/home2"; CDIR="$T/cluster"; WWW="$T/www"
mkdir -p "$HOME2" "$CDIR" "$WWW"
printf 'here\n' > "$WWW/where.txt"
two() { HOME="$HOME2" SOCKETLEY_SOCKET="$SOCK2" "$BIN" "$@"; }
D2PID=""
trap '[ -n "$D2PID" ] && kill "$D2PID" 2>/dev/null; daemon_sweep "$SOCK2"; daemon_stop' EXIT

daemon_start "$BIN"
HOME="$HOME2" SOCKETLEY_SOCKET="$SOCK2" "$BIN" daemon >>"$T/two.log" 2>&1 &
D2PID=$!
for _ in $(seq 1 100); do grep -q "daemon started" "$T/two.log" 2>/dev/null && break; sleep 0.1; done
"$BIN" daemon --name gw --cluster "$CDIR" >/dev/null 2>&1
two daemon --name member --cluster "$CDIR" >/dev/null 2>&1
two create server gm_r -p "$PR" --group gm_g --http "$WWW" -s >/dev/null 2>&1
# The breaker kept shut, so what is measured is the address and not how long an open circuit waits.
"$BIN" create proxy gm_p -p "$PM" --backend @gm_g --circuit-threshold 1000 -s >/dev/null 2>&1

answered_within() {   # seconds -> 0 and the seconds it took once the member answers through the proxy
    local t0 n; t0=$(date +%s%N)
    for n in $(seq 1 $(( $1 * 5 ))); do
        # Under the proxy's own prefix, which it strips.
        if [ "$(curl -s -m 1 "http://127.0.0.1:$PM/gm_p/where.txt" 2>/dev/null)" = here ]; then
            TOOK=$(( ($(date +%s%N) - t0) / 1000000 )); return 0
        fi
        sleep 0.2
    done
    TOOK=""; return 1
}

if answered_within 15; then ok "the member answers through the proxy at its first address (${TOOK} ms)"
else bad "the member answers through the proxy at its first address" "cluster group gm_g: $("$BIN" cluster group gm_g 2>&1 | tr '\n' ' ')"; fi

# The same member, running and in the group throughout, now only at a second address its name resolves to; the
# first one now leads nowhere.
ip addr del 10.9.0.2/32 dev lo
ip addr add 10.9.0.3/32 dev lo
printf '127.0.0.1 localhost\n10.9.0.3 %s\n' "$NAME" > "$T/hosts"

if answered_within 20; then ok "after its name moved, the member answers again (${TOOK} ms)"
else bad "after its name moved, the member answers again" "no answer in 20 s; it is still in the group: $("$BIN" cluster group gm_g 2>&1 | grep -c "$PR") entry"; fi

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
