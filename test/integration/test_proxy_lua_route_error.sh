#!/usr/bin/env bash
# Integration test: an on_route that raises must not end the process.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# `--strategy lua` asks the script's on_route() where each request goes.  Both
# call sites invoked it as a plain sol::function — an UNPROTECTED call — and
# nothing between them and main() catches anything: not select_and_resolve_backend,
# not on_cqe, not event_loop::run(), not daemon_start().  A Lua error therefore
# left through sol2's panic handler, and what the daemon printed was
#
#     terminate called after throwing an instance of 'sol::error'
#       what():  lua: error: route.lua:2: attempt to get length of local 'path' (a nil value)
#     Aborted (core dumped)
#
# One request.  With --daemon-process that is the whole daemon and every runtime
# in it — measured here at three: two backends and the proxy, all gone together.
#
# It needed no unusual script to reach.  on_route(method, path) receives its two
# arguments only on `--protocol http`; on a TCP proxy it is called with none, so
# the ordinary `return hash(path) % n` raises on the FIRST request.  A working
# HTTP config, copied onto a TCP proxy, is a crash on first contact.
#
# ─── THE TWO PATHS ──────────────────────────────────────────────────────────
#
# select_and_resolve_backend asks on_route in two places and both were
# unprotected, so both are exercised here:
#
#   * the indexed path, for `--backend host:port,host:port`
#   * the group path, for `--backend @group` with more than one member
#
# The indexed one is not a proxy for the other: the group path builds its pool
# per connection and has a different fallback, and a fix applied to one site
# only would leave this file half red.
#
# ─── THE CONTROL ────────────────────────────────────────────────────────────
#
# "The daemon is still alive" also passes on a build where on_route is never
# consulted at all — including one where `--strategy lua` silently degrades to
# round-robin.  So the file opens with a proxy whose on_route WORKS and pins a
# fixed index: every connection must land on backend 1 and none on backend 0.
# That assertion fails on any build that stops calling the callback, which is
# the way a crash fix could otherwise be faked.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaroute

# One base so a second run — or a run beside another agent's — can move the
# whole block.  A collision here looks exactly like a proxy that will not
# forward, which is the diagnosis this file must never invite.
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

# Answers.  Always backend 1, so "which backend got the bytes" is the oracle for
# "was the callback consulted and was its answer used".
cat >"$SCRIPTS/good.lua" <<'LUA'
function on_route(method, path)
    return 1
end
LUA

# Raises.  Not contrived: this is the shape every on_route example in examples/
# has, running on a TCP proxy, where the callback is handed no arguments.
cat >"$SCRIPTS/bad.lua" <<'LUA'
function on_route(method, path)
    return #path % 2
end
LUA

# total_connections and not bytes_in: the empty string means "could not read",
# and 0 is a legitimate reading of every counter here.  Substituting one for the
# other is how the assertions below would go back to passing for the wrong
# reason — a backend that was never created reads as a backend nothing reached.
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

# The request is still routed.  The fallback for an on_route that produced no
# usable index is the ordinary selection, so one of the two backends must have
# seen the connection — surviving without forwarding would be a different bug
# wearing this fix's clothes.
I0=$(conns idx_be0); I1=$(conns idx_be1)
if [ -n "$I0" ] && [ -n "$I1" ] && [ $((I0 + I1)) -gt 0 ]; then ok
else bad "request still forwarded (indexed)" "backends saw '$I0' and '$I1' connections" \
    "a raising on_route falls back to the ordinary selection, it does not drop"; fi

# The operator is told which callback failed and why.  A crash that is merely
# swallowed is not a fix.
if grep -q "on_route error" "$SOCKETLEY_DLOG" 2>/dev/null; then ok
else bad "the error is reported" "no 'on_route error' line in the daemon log" \
    "$(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"; fi

# Blast radius: the runtimes that share the process are untouched.  This is the
# assertion the crash actually violated — the two backends and the control proxy
# went down with the daemon, and none of them had anything to do with the script.
PS=$("$BIN" ps 2>&1) || daemon_required "ps after indexed on_route error"
for rt in ok_be0 ok_be1 route_ok idx_be0 idx_be1; do
    if grep -q "$rt" <<<"$PS"; then ok
    else bad "$rt survives" "gone from ps after an unrelated proxy's script raised"; fi
done

# ─── THE GROUP PATH ─────────────────────────────────────────────────────────
#
# Two members, because select_and_resolve_backend only asks on_route once the
# resolved pool has more than one entry.  A one-member group would take the
# fast path and this section would pass against the unfixed build.

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
