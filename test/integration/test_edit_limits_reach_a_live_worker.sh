#!/usr/bin/env bash
# Integration test: which half of `edit` reaches a runtime that is already
# serving, and which half waits for its next start.
#
# ─── WHERE THE LINE IS, AND WHY IT IS THERE ────────────────────────────────
#
# A runtime lives in its own process and the object `edit` changes is the
# daemon's placeholder.  The worker used to drop a second config frame with a
# warning, so `socketley edit api --max-connections 1` wrote the placeholder,
# answered 0, made `show` report 1 --- and the process holding the port went on
# enforcing 10.  Measured that way, four connections against 10 edited to 1:
#
#     before the edit            4 of 4 stayed open
#     after  edit ... 1, rc 0    4 of 4 stayed open   <- show already said 1
#     after  restart             1 of 4 stayed open
#
# The frame is now sent and taken, but only for what a live runtime can take:
# the limits it reads at the moment it uses them --- connections per accept,
# rate per message, idle per sweep.  Everything else is refused by arithmetic
# rather than by policy.  A port is a bound socket.  TLS is a context the open
# handshakes already used.  Backends are open connections.  A server's --http
# directory decides what a request in flight is being answered from.  None of
# those can change under a connection that exists, so they keep waiting, and
# man/socketley.1 and `edit --help` say which is which.
#
# ─── SO THIS FILE PINS THE LINE, FROM BOTH SIDES ───────────────────────────
#
# One assertion that a limit reaches the live worker, one that a directory does
# not, and one that the directory arrives on restart.  Widening the live set is
# an improvement and this file is where it gets written down; the third
# assertion is what stops the second from also passing for an edit that was
# never stored at all.
#
# ─── THE PROXY HALF, AND ONE WIDENING ──────────────────────────────────────
#
# The four above are limits every runtime type reads per use.  A proxy has nine
# more of the same kind --- routing and mesh POLICY, read when a backend is
# picked, a request is armed or a failure is counted, with nothing built from
# them --- and they used to wait for a restart along with the port and the TLS
# context, for no reason except that apply_live_config() did not mention them.
# Measured against a backend that accepts and never answers:
#
#     created with --backend-timeout 1     client waited 1.02s
#     edit --backend-timeout 6, rc 0       client waited 1.01s   <- show said 6
#     after a restart                      client waited 6.02s
#
# So `show` reported six while the process holding the port cut the client off
# at one, and the only way to find out was to time it.  They are live now, and
# the assertions below time it rather than reading a rc or a `show`, because a
# green rc is exactly what the defect produced.
#
# --health-check is deliberately NOT among the nine and the last assertion pins
# that: it arms a sweep timer at setup, so turning it on has no timer to arm.
# It is stored and applies at the next start, like the server's --http above.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: edit delivers limits live and defers the rest ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1492))

WWW_A=$(mktemp -d); WWW_B=$(mktemp -d)
echo "served-from-A" > "$WWW_A/index.txt"
echo "served-from-B" > "$WWW_B/index.txt"
cleanup() { rm -rf "$WWW_A" "$WWW_B"; daemon_stop 2>/dev/null || true; }

daemon_isolate edittiming
trap cleanup EXIT
daemon_start "$BIN"

"$BIN" create server et -p "$P" --max-connections 10 --http "$WWW_A" -s >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.5

# How many of four simultaneous connections the runtime keeps.  A refused one
# is closed at once, so a read that returns b'' is the refusal; a timeout means
# the connection is open and the server simply has nothing to say, which is the
# normal state for a server with no script.
open_count() {
python3 -c "
import socket, time
kept, held = 0, []
for _ in range(4):
    try:
        s = socket.create_connection(('127.0.0.1', $P), timeout=2)
        s.settimeout(0.6)
        s.sendall(b'x\n')
        try:    d = s.recv(16)
        except socket.timeout: d = b'-'
        if d != b'': kept += 1
        held.append(s)
    except Exception:
        pass
    time.sleep(0.1)
print(kept)
for s in held: s.close()
" 2>/dev/null
}

served() { curl -s --max-time 3 "http://127.0.0.1:$P/index.txt" 2>/dev/null | tr -d '\n'; }

BEFORE=$(open_count)
BEFORE_BODY=$(served)
if [ "${BEFORE:-0}" -eq 4 ] && [ "$BEFORE_BODY" = "served-from-A" ]; then
    ok "the runtime starts where its flags put it (4 of 4 kept, serving A)"
else
    bad "the starting state has to be the flags' state" \
        "kept ${BEFORE:-<none>} of 4 and served '${BEFORE_BODY:-<nothing>}';" \
        "nothing below distinguishes anything if the limit or the directory" \
        "is already something else"
fi

# ── the half that waits ────────────────────────────────────────────────────
"$BIN" edit et --http "$WWW_B" >/dev/null 2>&1
EDIT_HTTP_RC=$?
SHOWN_DIR=$("$BIN" show et 2>/dev/null | grep -o "\"http_dir\": *\"[^\"]*\"" | head -1)
AFTER_HTTP=$(served)
if [ "$EDIT_HTTP_RC" -eq 0 ] && [ "$AFTER_HTTP" = "served-from-A" ]; then
    ok "a new --http directory is stored and the live worker keeps serving the old one"
else
    bad "a directory cannot change under a request in flight" \
        "edit rc $EDIT_HTTP_RC, show: ${SHOWN_DIR:-<none>}, served '${AFTER_HTTP:-<nothing>}';" \
        "if --http now reaches a live worker that is an improvement, not a" \
        "regression --- but man/socketley.1 and man/socketley-help.sh name the" \
        "live set, and they have to change in the same commit as this line"
fi

# ── the half that arrives ──────────────────────────────────────────────────
"$BIN" edit et --max-connections 1 >/dev/null 2>&1
EDIT_LIMIT_RC=$?
sleep 0.5
AFTER_LIMIT=$(open_count)
if [ "$EDIT_LIMIT_RC" -eq 0 ] && [ "${AFTER_LIMIT:-0}" -eq 1 ]; then
    ok "--max-connections reaches the running worker ($AFTER_LIMIT of 4 kept)"
else
    bad "a limit read per accept reaches a runtime that is already accepting" \
        "edit rc $EDIT_LIMIT_RC, the worker kept ${AFTER_LIMIT:-<none>} of 4 where it kept $BEFORE before;" \
        "4 means the config frame did not arrive, or arrived and set a field" \
        "the accept path does not read --- the hot paths hold a cached copy," \
        "and refresh_cached_limits() is what makes the setter true"
fi

# ── and the deferred half arrives on restart ───────────────────────────────
"$BIN" restart et >/dev/null 2>&1
sleep 2
RESTARTED_BODY=$(served)
if [ "$RESTARTED_BODY" = "served-from-B" ]; then
    ok "and a restart applies the directory (serving B)"
else
    bad "the stored directory takes effect at the next start" \
        "after a restart the runtime served '${RESTARTED_BODY:-<nothing>}', expected served-from-B;" \
        "without this line the assertion above would also pass for an edit that" \
        "was never stored at all"
fi

# ── the proxy's nine, timed rather than reported ───────────────────────────
#
# A backend that accepts and never answers, so the only thing that ends the
# request is the proxy's own response deadline -- which makes the wait the
# measurement.  Held connections are kept in a list so the backend does not
# close them and end the wait for the wrong reason.
PX=$((SL_PORT_BASE+1494)); BE=$((SL_PORT_BASE+1495))
python3 - "$BE" <<'PYEOF' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64)
held = []
while True:
    c, _ = s.accept(); held.append(c)
PYEOF
BE_PID=$!
cleanup() {
    # `wait` inside the redirect too, or the shell prints its own "Killed"
    # job notice on stderr after the results line.
    [ -n "${BE_PID:-}" ] && { kill -9 "$BE_PID"; wait "$BE_PID"; } 2>/dev/null
    rm -rf "$WWW_A" "$WWW_B"
    daemon_stop 2>/dev/null || true
}
sleep 0.5

"$BIN" create proxy ep -p "$PX" --backend "127.0.0.1:$BE" --protocol http \
    --backend-timeout 1 -s >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PX" 2>/dev/null && break; sleep 0.1; done
sleep 0.6

# Seconds the proxy made the client wait, to two decimals.
waited() {
    local t0 t1
    t0=$(date +%s.%N)
    curl -s -o /dev/null --max-time 20 "http://127.0.0.1:$PX/ep/" 2>/dev/null || true
    t1=$(date +%s.%N)
    awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}'
}

W_BEFORE=$(waited)
if awk -v w="$W_BEFORE" 'BEGIN{exit !(w > 0.7 && w < 2.5)}'; then
    ok "the proxy starts on the deadline its flag gave it (${W_BEFORE}s)"
else
    bad "the starting deadline has to be the flag's deadline" \
        "the client waited ${W_BEFORE}s where --backend-timeout 1 was asked for;" \
        "nothing below distinguishes anything if the deadline is already something else"
fi

"$BIN" edit ep --backend-timeout 6 >/dev/null 2>&1
EDIT_BT_RC=$?
sleep 0.3
W_AFTER=$(waited)
if [ "$EDIT_BT_RC" -eq 0 ] && awk -v w="$W_AFTER" 'BEGIN{exit !(w > 4.5 && w < 9.0)}'; then
    ok "--backend-timeout reaches the running proxy (${W_BEFORE}s -> ${W_AFTER}s, no restart)"
else
    bad "mesh policy read per request reaches a proxy that is already serving" \
        "edit rc $EDIT_BT_RC, the client waited ${W_AFTER}s where it waited ${W_BEFORE}s before;" \
        "a wait unchanged near ${W_BEFORE}s means the config frame arrived and set a" \
        "field the request path does not read, or apply_live_config() does not" \
        "mention it --- \`show\` will report 6 either way, which is why this is timed"
fi

# And the one that is not live, pinned from the other side so the paragraph in
# man/socketley.1 has an assertion behind it.
"$BIN" edit ep --health-check tcp >/dev/null 2>&1
EDIT_HC_RC=$?
SHOWN_HC=$("$BIN" show ep 2>/dev/null | grep -o "\"health_check\": *[0-9]*" | head -1)
if [ "$EDIT_HC_RC" -eq 0 ] && [ -n "$SHOWN_HC" ]; then
    ok "--health-check is stored and waits for the next start ($SHOWN_HC)"
else
    bad "--health-check is stored rather than refused" \
        "edit rc $EDIT_HC_RC, show: ${SHOWN_HC:-<none>};" \
        "it arms a sweep timer at setup, so it cannot go live --- but it is" \
        "stored like every other deferred flag, and man/socketley.1 says so"
fi

"$BIN" stop ep >/dev/null 2>&1; "$BIN" remove ep >/dev/null 2>&1
{ kill -9 "$BE_PID"; wait "$BE_PID"; } 2>/dev/null; BE_PID=""

"$BIN" stop et >/dev/null 2>&1; "$BIN" remove et >/dev/null 2>&1
daemon_stop
trap - EXIT
rm -rf "$WWW_A" "$WWW_B"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
