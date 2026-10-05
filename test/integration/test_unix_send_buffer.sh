#!/usr/bin/env bash
# Integration test: every data-path unix stream socket carries socketley's send
# buffer, accepted or dialed, read off the kernel with `ss -xm`.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# Unix stream backpressure is the SENDER's sk_sndbuf alone, and an accepted
# unix socket inherits nothing from its listener, so each accept and each
# connect has to set it -- and a site that forgets still answers every
# request correctly, just with 208 KB in flight instead of 1 MiB.  Nothing but
# the kernel's own number can tell the two apart.
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
# One row per call site of unix_sock::tune_stream: the cache, server and proxy
# accept paths off --listen unix:, the server and cache accept off a companion
# node, the proxy's backend connect to that node, and the client's -t unix:
# connect.  A build that drops any one of them reads the default there.  The
# control row reads python's own untuned socket, so an instrument that returned
# the expected value for everything would fail it.

set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate unixsndbuf
PASS=0; FAIL=0; TOTAL=0

HOLDERS=()
cleanup() {
    local p
    for p in "${HOLDERS[@]}"; do kill "$p" 2>/dev/null || true; done
    for p in "${HOLDERS[@]}"; do wait "$p" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: unix stream send buffer ==="

# setsockopt caps the request at wmem_max and the kernel doubles it.
WMAX=$(cat /proc/sys/net/core/wmem_max)
WDEF=$(cat /proc/sys/net/core/wmem_default)
REQ=$((512 * 1024))
[ "$WMAX" -lt "$REQ" ] && REQ=$WMAX
WANT=$((REQ * 2))
if [ "$WANT" -eq "$WDEF" ]; then
    echo "  SKIP: wmem_default is $WDEF, the value this build asks for -- the two cannot be told apart here"
    exit 0
fi

daemon_start "$BIN"
D="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE + 1790))
RTDIR="$SOCKETLEY_SOCKET.rt"

# Connects to a unix path, has one exchange so the connection is surely
# accepted, and holds it open until killed; a server with no handler answers
# nothing, so the reply is waited for briefly and hold() waits well past that.
cat > "$D/hold.py" <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
s.sendall(sys.argv[2].encode().decode("unicode_escape").encode("latin1"))
s.settimeout(1)
try: s.recv(4096)
except OSError: pass
print("held", flush=True)
time.sleep(600)
EOF

# For every established socket bound to PATH: "<its tb> <its peer's tb>".
cat > "$D/tb.py" <<'EOF'
import re, subprocess, sys
rows = {}
for line in subprocess.run(["ss", "-xmaH"], capture_output=True, text=True).stdout.splitlines():
    f = line.split()
    m = re.search(r"\btb(\d+)", line)
    if len(f) < 8 or f[0] != "u_str" or not m:
        continue
    rows[f[5]] = (f[1], f[4], f[7], int(m.group(1)))
for ino, (state, local, peer, tb) in rows.items():
    if state == "ESTAB" and local == sys.argv[1]:
        print(tb, rows.get(peer, ("", "", "", -1))[3])
EOF

hold() {   # hold <path> <payload>
    local out="$D/hold.$RANDOM"
    python3 "$D/hold.py" "$1" "$2" >"$out" 2>&1 &
    HOLDERS+=($!)
    local i
    for i in $(seq 1 150); do grep -q held "$out" 2>/dev/null && return 0; sleep 0.1; done
    return 1
}

# Waits for the first row at PATH and prints it.
tb_at() {
    local i r
    for i in $(seq 1 50); do
        r=$(python3 "$D/tb.py" "$1" | head -1)
        [ -n "$r" ] && { echo "$r"; return 0; }
        sleep 0.1
    done
    echo "none none"
}

check() {   # check <name> <got>
    if [ "$2" = "$WANT" ]; then ok "$1 ($2)"
    else bad "$1" "tb=$2, expected $WANT (the default is $WDEF)"; fi
}

# ── 1. cache --listen unix:, and a client runtime dialing one ───────────────
"$BIN" create cache usb_c  --listen "unix:$D/c.sock"  -s >/dev/null
"$BIN" create cache usb_ct --listen "unix:$D/ct.sock" -s >/dev/null
"$BIN" create client usb_cl -t "unix:$D/ct.sock" -s >/dev/null
hold "$D/c.sock" 'PING\r\n' || bad "cache holder" "no reply over $D/c.sock"
read -r ACC PEER <<< "$(tb_at "$D/c.sock")"
check "cache: a socket accepted off --listen unix:" "$ACC"
if [ "$PEER" = "$WDEF" ]; then ok "control: python's own socket reads the default ($PEER)"
else bad "control" "python's untuned socket read tb=$PEER, expected $WDEF -- the instrument is not reading what it names"; fi
read -r ACC PEER <<< "$(tb_at "$D/ct.sock")"
check "client: the socket -t unix: dials" "$PEER"

# ── 2. server --listen unix:, and a server's companion node ─────────────────
"$BIN" create server usb_s  --listen "unix:$D/s.sock" -s >/dev/null
"$BIN" create server usb_sp -p "$P" -s >/dev/null
hold "$D/s.sock" 'hi\n' || bad "server holder" "no connection over $D/s.sock"
read -r ACC PEER <<< "$(tb_at "$D/s.sock")"
check "server: a socket accepted off --listen unix:" "$ACC"
for i in $(seq 1 30); do [ -S "$RTDIR/usb_sp.sock" ] && break; sleep 0.1; done
hold "$RTDIR/usb_sp.sock" 'hi\n' || bad "node holder" "no connection over $RTDIR/usb_sp.sock"
read -r ACC PEER <<< "$(tb_at "$RTDIR/usb_sp.sock")"
check "server: a socket accepted off its companion node" "$ACC"

# ── 3. proxy --listen unix: in front of a cache it reaches over its node ────
"$BIN" create cache usb_kv -p "$((P + 1))" -s >/dev/null
"$BIN" create proxy usb_px --listen "unix:$D/px.sock" --backend usb_kv --protocol tcp -s >/dev/null
hold "$D/px.sock" 'PING\r\n' || bad "proxy holder" "no reply over $D/px.sock"
read -r ACC PEER <<< "$(tb_at "$D/px.sock")"
check "proxy: a socket accepted off --listen unix:" "$ACC"
read -r ACC PEER <<< "$(tb_at "$RTDIR/usb_kv.sock")"
check "cache: a socket accepted off its companion node" "$ACC"
check "proxy: the backend socket it dials to that node" "$PEER"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
