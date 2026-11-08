#!/usr/bin/env bash
# Integration test: the answers to one read of pipelined lines leave the server
# in one send.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# A read carrying sixteen lines was answered in two or three sends: the first
# answer was flushed the moment it was queued -- by sendmsg() when the loop
# had only this connection, through the ring otherwise -- and the other
# fifteen waited behind it for its completion and went in a send of their own.
# A Go server writes once per read.  The server-app suite's pipelined echo
# (64 connections, 16 lines in flight) read 0.71x Go with a profile that was
# all kernel.
#
# ─── THE INSTRUMENT ────────────────────────────────────────────────────────
#
# The client's own TCP_INFO: tcpi_data_segs_in counts the segments that
# carried data to it.  On loopback a send of a few hundred bytes is one
# segment, so segments per read is sends per read, read off the receiving
# socket with no tracing of the server at all.
#
# ─── THE ASSERTIONS ────────────────────────────────────────────────────────
#
# For the built-in echo (--send-to sender) and a script answering with
# self.send (under --mode in, so nothing else is relayed), with one connection (where the first answer went by sendmsg)
# and with eight (where it went by the ring): every answer arrives intact and
# in order, and the answers to one read arrive in at most 1.2 segments on
# average.  The defect reads 3.00 with one connection and 2.00 with eight.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: the answers to one read leave in one send ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PB=$((SL_PORT_BASE+1858))
PL=$((SL_PORT_BASE+1859))

daemon_isolate pipeonesend
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/echo.lua" <<'LUAEOF'
function on_client_message(id, msg)
    self.send(id, msg)
end
LUAEOF
"$BIN" create server pob -p "$PB" --send-to sender -s >/dev/null 2>&1
"$BIN" create server pol -p "$PL" --mode in --lua "$SOCKETLEY_TMPD/echo.lua" -s >/dev/null 2>&1
sleep 1.5

cat > "$SOCKETLEY_TMPD/segs.py" <<'PYEOF'
import socket, struct, sys, time
port, conns, rounds = int(sys.argv[1]), int(sys.argv[2]), 30
def segs(s):
    # tcpi_data_segs_in, at its offset in struct tcp_info since Linux 4.6
    return struct.unpack_from('I', s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232), 152)[0]
ss = [socket.create_connection(('127.0.0.1', port), 5) for _ in range(conns)]
time.sleep(0.2)
for s in ss:
    s.sendall(b'w\n'); s.recv(10)
base = [segs(s) for s in ss]
batch = b''.join(b'line%02d\n' % i for i in range(16))
intact = True
for r in range(rounds):
    for s in ss:
        s.sendall(batch)
    for s in ss:
        got = b''
        while len(got) < len(batch):
            d = s.recv(65536)
            if not d: break
            got += d
        intact = intact and got == batch
print('%s %.2f' % ('intact' if intact else 'damaged', sum(segs(s) - b for s, b in zip(ss, base)) / (conns * rounds)))
PYEOF

for arm in "built-in:$PB" "lua:$PL"; do
    name=${arm%%:*}; port=${arm#*:}
    for c in 1 8; do
        read -r state per <<<"$(python3 "$SOCKETLEY_TMPD/segs.py" "$port" "$c" 2>/dev/null)"
        if [ "${state:-}" != "intact" ]; then
            bad "$name, $c connection(s): every answer arrives in order" "the client read '${state:-<nothing>}'"
            continue
        fi
        if awk -v p="$per" 'BEGIN{exit !(p <= 1.2)}'; then
            ok "$name, $c connection(s): $per segments per 16-line read"
        else
            bad "$name, $c connection(s): one send per read" \
                "$per segments per 16-line read, wanted at most 1.2;" \
                "3.00 (one connection) or 2.00 (eight) is the first answer flushed alone"
        fi
    done
done

for r in pob pol; do "$BIN" stop $r >/dev/null 2>&1; "$BIN" remove $r >/dev/null 2>&1; done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
