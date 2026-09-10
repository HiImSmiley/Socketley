#!/usr/bin/env bash
# Integration test: ls, ps, stats and the metrics endpoint report the port a
# runtime actually binds.
#
# Measured before this fix, on a private daemon:
#
#     create server nop        # no -p at all
#     start nop
#     ss -ltn                  -> 0.0.0.0:8000, LISTEN
#     nc 127.0.0.1 8000        -> connected, served
#     ps -a                    -> PORT "-"
#     ps --json                -> "port":0
#     stats nop                -> port:0
#
# The default is documented -- "Default port: 8000" -- so the runtime did the
# right thing. What lied was every surface that reports it: no socketley
# command would tell an operator which port their runtime was answering on, and
# two runtimes both left at the default both went to 8000, which is the other
# half of this (see test_one_address_one_runtime.sh).
#
# ─── WHERE THE NUMBER COMES FROM ────────────────────────────────────────────
#
# runtime_instance::effective_port(), which is also what listen_addresses() is
# built from -- so the port `ps` prints and the port the manager refuses a
# collision on cannot drift apart. Nine reporting sites read it now: six in the
# listing code, stats_prefix(), and the metrics endpoint's two.
#
# `show` is deliberately NOT one of them, and that is asserted below. Its output
# is the state document and it goes back in through `import`, so writing 8000
# into it would pin a runtime that had been left to take whichever default its
# type has.
#
# ─── WHY 8000 IS NOT BOUND HERE ─────────────────────────────────────────────
#
# Every other file in this directory stays inside the window lib_ports.sh
# claimed, precisely so a suite cannot collide with whatever else is on the
# machine -- and 8000 is the most likely port on a developer's box to be busy.
# So the default is asserted through a runtime type whose default this test can
# reach safely instead: a cache defaults to 9000 and a proxy to 8080, and the
# assertion that matters is "the reported number is the bound number", which
# does not care which number it is. The configured-port cases below carry the
# rest.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate reportedport

P_SRV=$((SL_PORT_BASE+1880))
P_CLI=$((SL_PORT_BASE+1882))
NAMES="rp_srv rp_cli rp_unix rp_own"
UPATH="$SOCKETLEY_TMPD/rp.sock"

PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

check() {   # label expected actual
    if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi
}

ps_port()   { "$BIN" ps -a 2>/dev/null | awk -v n="$1" '$2==n {print $4}'; }
json_port() { "$BIN" ps --json 2>/dev/null \
                | sed -n "s/.*\"name\":\"$1\"[^}]*\"port\":\([0-9]*\).*/\1/p"; }
stats_port(){ "$BIN" stats "$1" 2>/dev/null | sed -n 's/^port:\(.*\)$/\1/p'; }
show_port() { "$BIN" show "$1" 2>/dev/null \
                | sed -n 's/^ *"port": *\([0-9]*\).*$/\1/p'; }

echo "=== Integration: the reported port is the bound port ==="
daemon_start "$BIN"

# ─── 1. A configured port reads back everywhere ─────────────────────────────
# The easy half, and the control: if these disagree the rest means nothing.
create_ok "a server on a port of its own" "$BIN" create server rp_srv -p "$P_SRV"
"$BIN" start rp_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV" >/dev/null 2>&1 || true

check "ps"        "$P_SRV" "$(ps_port    rp_srv)"
check "ps --json" "$P_SRV" "$(json_port  rp_srv)"
check "stats"     "$P_SRV" "$(stats_port rp_srv)"
check "show"      "$P_SRV" "$(show_port  rp_srv)"

# ─── 2. An unset port reads back as the one it binds ────────────────────────
# A cache with no -p takes 9000; what is asserted is that the four surfaces
# agree with each other and with the kernel, not the number itself.
CACHE_DEFAULT=9000
if ss -ltnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' | grep -qx "$CACHE_DEFAULT"; then
    echo "  (port $CACHE_DEFAULT is already in use on this machine -- the default-port"
    echo "   cases are skipped rather than measured against somebody else's listener)"
else
    create_ok "a cache with no -p" "$BIN" create cache rp_cli
    "$BIN" start rp_cli >/dev/null 2>&1 || true
    ready_tcp 127.0.0.1 "$CACHE_DEFAULT" >/dev/null 2>&1 || true

    # It really is listening there, which is the fact the reporting has to match.
    BOUND=$(ss -ltnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' \
            | grep -cx "$CACHE_DEFAULT" || true)
    if [ "${BOUND:-0}" -ge 1 ]; then ok; else
        bad "the cache is really on its default port" \
            "nothing is listening on $CACHE_DEFAULT"; fi

    check "ps reports the bound port"        "$CACHE_DEFAULT" "$(ps_port    rp_cli)"
    check "ps --json reports the bound port" "$CACHE_DEFAULT" "$(json_port  rp_cli)"
    check "stats reports the bound port"     "$CACHE_DEFAULT" "$(stats_port rp_cli)"

    # And the document does NOT, because it goes back in through import and a
    # runtime left to its default must stay left to it.
    check "show keeps the configured zero" "0" "$(show_port rp_cli)"

    "$BIN" stop rp_cli >/dev/null 2>&1 || true
fi

# ─── 3. A runtime that binds no port reports zero ───────────────────────────
# Not "the default it would have taken": there is no port here at all.
create_ok "a server on a unix path" "$BIN" create server rp_unix \
    --listen "unix:$UPATH"
"$BIN" start rp_unix >/dev/null 2>&1 || true
sleep 0.5
check "a --listen runtime reports no port" "0" "$(json_port rp_unix)"
if [ -S "$UPATH" ]; then ok; else
    bad "and it really is on the path instead" "$UPATH is not a socket node"; fi

# ─── 4. The reported number is the one a collision is refused on ────────────
# The whole reason effective_port() and listen_addresses() share a source: a
# second runtime put on the number `ps` prints must be refused by that number.
REPORTED=$(ps_port rp_srv)
create_ok "a second runtime on the reported port" "$BIN" create server rp_own \
    -p "$REPORTED"
OUT=$("$BIN" start rp_own 2>&1) || true
if [[ "$OUT" == *"$REPORTED"* && "$OUT" == *"rp_srv"* ]]; then ok; else
    bad "the refusal names the port ps printed" \
        "start said '${OUT:-<nothing>}'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
