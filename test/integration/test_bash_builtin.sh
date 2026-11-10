#!/usr/bin/env bash
# Integration test: `enable -f socketley-bash.so socketley` makes `socketley send` a request from the shell itself
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The builtin sends a line to the daemon over one connection it keeps for the
# shell, and hands every other command to the socketley program on PATH.  What
# would be wrong and quiet: a line lost or reordered, a script's exported
# SOCKETLEY_SOCKET not reaching it, a daemon that restarted leaving the kept
# connection dead, or a refusal whose exit code is not the one the program gives.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate bashbuiltin

SO="$(cd "$(dirname "$BIN")" && pwd)/socketley-bash.so"
P=$((SL_PORT_BASE+1966))
NAMES="bb_cli"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

echo "=== Integration: socketley as a bash builtin ==="
if [ ! -f "$SO" ]; then
    echo "  SKIP: no $SO in this build"
    exit 0
fi

LPID=""
cleanup() {
    if [ -n "$LPID" ]; then
        { kill -9 "$LPID" && wait "$LPID"; } 2>/dev/null || true
    fi
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# A peer that writes every line it reads to a file, one connection after another.
cat > "$SOCKETLEY_TMPD/peer.py" <<'PYEOF'
import socket, sys
port, out = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
with open(out, "ab", buffering=0) as f:
    while True:
        c, _ = srv.accept()
        while True:
            b = c.recv(65536)
            if not b:
                break
            f.write(b)
PYEOF
GOT="$SOCKETLEY_TMPD/got"
: > "$GOT"
python3 "$SOCKETLEY_TMPD/peer.py" "$P" "$GOT" > /dev/null 2>&1 &
LPID=$!
for _ in $(seq 1 200); do
    ss -ltn 2>/dev/null | grep -q ":$P " && break
    sleep 0.05
done

daemon_start "$BIN"
create_ok "a client to the peer" "$BIN" create client bb_cli -t "127.0.0.1:$P" -s
for _ in $(seq 1 50); do
    "$BIN" ls 2>/dev/null | grep -q "bb_cli.*Up" && break
    sleep 0.1
done

# The program for every other command is the one next to the builtin.
SHELLPATH="$(cd "$(dirname "$BIN")" && pwd):$PATH"
run() { PATH="$SHELLPATH" bash -c "enable -f '$SO' socketley; $1" 2>&1; }

check "the builtin is what the name runs" "socketley is a shell builtin" "$(run 'type socketley | head -1')"

OUT=$(run 'for i in $(seq 1 500); do socketley send bb_cli "line $i" || exit 9; done; socketley send bb_cli -- -dash; socketley send bb_cli two  words')
check "500 sends answered as the program answers them" "" "$OUT"
for _ in $(seq 1 50); do
    [ "$(grep -c . "$GOT")" -ge 502 ] && break
    sleep 0.1
done
check "every line reached the peer, in order" "$(for i in $(seq 1 500); do echo "line $i"; done; echo -dash; echo two words)" "$(cat "$GOT")"

check "a runtime that does not exist is refused with the program's code" "runtime not found: nosuch|1" \
    "$(run 'socketley send nosuch x; echo "|$?"' | tr -d '\n')"
check "an empty message is refused" "empty message|1" "$(run 'socketley send bb_cli ""; echo "|$?"' | tr -d '\n')"
check "any other command runs the program" "1" "$(run 'socketley ls' | grep -c 'bb_cli')"
check "a socket the script exports is the one asked" "2" \
    "$(run "export SOCKETLEY_SOCKET=$SOCKETLEY_TMPD/none.sock; socketley send bb_cli x >/dev/null 2>&1; echo \$?")"

# The kept connection outlives the daemon it was made to, and the next send makes a new one.
: > "$GOT"
GO="$SOCKETLEY_TMPD/go"
PATH="$SHELLPATH" bash -c "enable -f '$SO' socketley; socketley send bb_cli before
    while [ ! -e '$GO' ]; do sleep 0.05; done
    socketley send bb_cli after; echo \$? > '$GO.rc'" > "$SOCKETLEY_TMPD/later.out" 2>&1 &
LATER=$!
for _ in $(seq 1 50); do
    grep -q before "$GOT" && break
    sleep 0.1
done
kill "$SOCKETLEY_DPID" 2>/dev/null || true
wait "$SOCKETLEY_DPID" 2>/dev/null || true
daemon_start "$BIN"
for _ in $(seq 1 80); do
    "$BIN" ls 2>/dev/null | grep -q "bb_cli.*Up" && break
    sleep 0.1
done
touch "$GO"
wait "$LATER" || true
for _ in $(seq 1 50); do
    grep -q after "$GOT" && break
    sleep 0.1
done
check "a send after the daemon restarted goes on a new connection" "before|after|0" \
    "$(paste -sd'|' "$GOT")|$(cat "$GO.rc" 2>/dev/null)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
