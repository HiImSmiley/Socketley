#!/usr/bin/env bash
# Integration test: an on_route that raises must not end the process.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
# Both call sites invoked on_route as an unprotected sol::function with nothing
# between them and main(), so one request took the whole process out through
# sol2's panic handler -- and it needed no unusual script, because on a TCP
# proxy the callback is handed no arguments and the ordinary `return hash(path)
# % n` raises on the first request.
# ─── THE TWO PATHS ──────────────────────────────────────────────────────────
# Both call sites are exercised -- the indexed path and the group path --
# because the group one builds its pool per connection with a different
# fallback, so a fix applied to one site would leave this file half red.
# ─── THE CONTROL ────────────────────────────────────────────────────────────
# "The daemon is still alive" also passes where on_route is never consulted, so
# the file opens with a proxy whose on_route works and pins a fixed index --
# which fails on any build that stops calling the callback.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaroute

# One base so a second run can move the whole block, because a collision here
# looks exactly like a proxy that will not forward.
PORT_BASE=$((SL_PORT_BASE+970))
OK_BE0=$((PORT_BASE+1))
OK_BE1=$((PORT_BASE+2))
OK_PROXY=$((PORT_BASE+3))
IDX_BE0=$((PORT_BASE+4))
IDX_BE1=$((PORT_BASE+5))
IDX_PROXY=$((PORT_BASE+6))
GRP_BE0=$((PORT_BASE+7))
GRP_BE1=$((PORT_BASE+8))
GRP_PROXY=$((PORT_BASE+9))

GROUP="luaroute_grp_$$"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop route_ok route_idx route_grp ok_be0 ok_be1 idx_be0 idx_be1 \
        grp_be0 grp_be1 2>/dev/null || true
    "$BIN" remove route_ok route_idx route_grp ok_be0 ok_be1 idx_be0 idx_be1 \
        grp_be0 grp_be1 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: proxy --strategy lua, on_route that raises ==="

daemon_start "$BIN"

SCRIPTS="$SOCKETLEY_TMPD"

# Answers, always backend 1, so which backend got the bytes is the oracle for
# whether the callback was consulted and its answer used.
cat >"$SCRIPTS/good.lua" <<'LUA'
function on_route(method, path)
    return 1
end
LUA

# Raises, and not contrived: this is the shape every on_route example has,
# running on a TCP proxy where the callback is handed no arguments.
cat >"$SCRIPTS/bad.lua" <<'LUA'
function on_route(method, path)
    return #path % 2
end
LUA

# total_connections rather than bytes_in, because the empty string means "could
# not read" while 0 is a legitimate reading, and substituting one for the other
# makes a backend that was never created read as one nothing reached.
conns() {
    local v
    v=$("$BIN" stats "$1" 2>/dev/null | sed -n 's/^total_connections:\([0-9][0-9]*\)$/\1/p' | head -1) || v=""
    printf '%s' "$v"
}

# hit PORT — one TCP connection carrying one line, whatever comes back.
hit() { printf 'route-me\n' | timeout 4 nc -q1 127.0.0.1 "$1" >/dev/null 2>&1 || true; }

# ─── CONTROL: on_route is consulted, and its answer is used ─────────────────

create_ok "ok_be0 created"  "$BIN" create server ok_be0 -p "$OK_BE0" -s
create_ok "ok_be1 created"  "$BIN" create server ok_be1 -p "$OK_BE1" -s
create_ok "route_ok created" "$BIN" create proxy route_ok -p "$OK_PROXY" \
    --backend "127.0.0.1:$OK_BE0,127.0.0.1:$OK_BE1" --protocol tcp \
    --strategy lua --lua "$SCRIPTS/good.lua" -s
ready_tcp 127.0.0.1 "$OK_PROXY" 10 || true

for _ in 1 2 3; do hit "$OK_PROXY"; done
sleep 0.4

C0=$(conns ok_be0); C1=$(conns ok_be1)
if [ -n "$C1" ] && [ "$C1" -gt 0 ]; then ok
else bad "on_route consulted" "backend 1 saw '$C1' connections, expected more than 0" \
    "a build that never calls on_route satisfies every crash assertion below"; fi
if [ "$C0" = "0" ]; then ok
else bad "on_route answer used" "backend 0 saw '$C0' connections, expected 0" \
    "on_route returned 1 for every request, so backend 0 must see none"; fi

# ─── THE INDEXED PATH ───────────────────────────────────────────────────────

create_ok "idx_be0 created" "$BIN" create server idx_be0 -p "$IDX_BE0" -s
create_ok "idx_be1 created" "$BIN" create server idx_be1 -p "$IDX_BE1" -s
create_ok "route_idx created" "$BIN" create proxy route_idx -p "$IDX_PROXY" \
    --backend "127.0.0.1:$IDX_BE0,127.0.0.1:$IDX_BE1" --protocol tcp \
    --strategy lua --lua "$SCRIPTS/bad.lua" -s
ready_tcp 127.0.0.1 "$IDX_PROXY" 10 || true

hit "$IDX_PROXY"
sleep 0.4

if daemon_alive "$SOCKETLEY_SOCKET"; then ok
else
    bad "daemon survives a raising on_route (indexed backends)" \
        "the daemon is gone after one request" \
        "$(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
    daemon_bail "raising on_route (indexed backends)" \
        "the daemon this test is measuring aborted on one request" \
        "everything below would be measuring a dead socket, so it is not run"
fi

# The request is still routed, because the fallback for an unusable index is
# the ordinary selection and surviving without forwarding would be a different
# bug wearing this fix's clothes.
I0=$(conns idx_be0); I1=$(conns idx_be1)
if [ -n "$I0" ] && [ -n "$I1" ] && [ $((I0 + I1)) -gt 0 ]; then ok
else bad "request still forwarded (indexed)" "backends saw '$I0' and '$I1' connections" \
    "a raising on_route falls back to the ordinary selection, it does not drop"; fi

# The operator is told which callback failed and why, because a crash that is
# merely swallowed is not a fix.
if grep -q "on_route error" "$SOCKETLEY_DLOG" 2>/dev/null; then ok
else bad "the error is reported" "no 'on_route error' line in the daemon log" \
    "$(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"; fi

# Blast radius, which is the assertion the crash actually violated: the two
# backends and the control proxy went down with the daemon and none of them had
# anything to do with the script.
PS=$("$BIN" ps 2>&1) || daemon_required "ps after indexed on_route error"
for rt in ok_be0 ok_be1 route_ok idx_be0 idx_be1; do
    if grep -q "$rt" <<<"$PS"; then ok
    else bad "$rt survives" "gone from ps after an unrelated proxy's script raised"; fi
done

# ─── THE GROUP PATH ─────────────────────────────────────────────────────────
# Two members, because on_route is only asked once the resolved pool has more
# than one entry and a one-member group would take the fast path.

create_ok "grp_be0 created" "$BIN" create server grp_be0 -p "$GRP_BE0" -g "$GROUP" -s
create_ok "grp_be1 created" "$BIN" create server grp_be1 -p "$GRP_BE1" -g "$GROUP" -s
create_ok "route_grp created" "$BIN" create proxy route_grp -p "$GRP_PROXY" \
    --backend "@$GROUP" --protocol tcp \
    --strategy lua --lua "$SCRIPTS/bad.lua" -s
ready_tcp 127.0.0.1 "$GRP_PROXY" 10 || true

hit "$GRP_PROXY"
sleep 0.4

if daemon_alive "$SOCKETLEY_SOCKET"; then ok
else
    bad "daemon survives a raising on_route (@group backend)" \
        "the daemon is gone after one request through the group path" \
        "$(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
    daemon_bail "raising on_route (@group backend)" \
        "the daemon this test is measuring aborted on one request" \
        "everything below would be measuring a dead socket, so it is not run"
fi

G0=$(conns grp_be0); G1=$(conns grp_be1)
if [ -n "$G0" ] && [ -n "$G1" ] && [ $((G0 + G1)) -gt 0 ]; then ok
else bad "request still forwarded (@group)" "members saw '$G0' and '$G1' connections" \
    "a raising on_route falls back to the pool's first member, it does not drop"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
