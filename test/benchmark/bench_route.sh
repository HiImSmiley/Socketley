#!/usr/bin/env bash
# What a routed connection costs in the daemon, end to end.
#
# bench_conn_transfer measures the transports on their own, with no Lua, no
# write queue and no io_uring, because that is the only way to see the
# difference between them.  This measures the opposite thing: the whole path a
# routed message actually travels today — client, parent server's read, the
# route lookup, the sub-server's Lua, owner_send back through the parent, and
# out.  It is the denominator the transport numbers should be read against.
#
# Point it at two binaries to compare them:
#   BIN=/path/to/old  bash test/benchmark/bench_route.sh
#
# Runs its own daemon on its own socket and state directory and kills it by the
# pid it started, never by name.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
ROUNDS="${ROUNDS:-20000}"
REPEATS="${REPEATS:-5}"

WORK=$(mktemp -d /tmp/socketley-benchroute-XXXXXX)
export SOCKETLEY_SOCKET="$WORK/s.sock"
export HOME="$WORK/home"
mkdir -p "$HOME"

PARENT_PORT="${PARENT_PORT:-19781}"
SUB_PORT="${SUB_PORT:-19782}"
DPID=""

cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    sleep 0.3
    rm -rf "$WORK"
}
trap cleanup EXIT

# ─── Machine state ──────────────────────────────────────────────────────────
# A run started on the previous run's debris measures the debris.  This kernel
# holds 16384 TIME_WAIT sockets and a run that reaches the ceiling is measuring
# a machine it broke itself.
TW=$(ss -tan state time-wait 2>/dev/null | wc -l)
LOAD=$(cut -d' ' -f1 /proc/loadavg)
echo "machine: load $LOAD, $TW sockets in TIME_WAIT, $(nproc) CPUs"
if [ "$TW" -gt 2000 ]; then
    echo "REFUSING: too many TIME_WAIT sockets to measure anything"
    exit 1
fi
if [ "${LOAD%%.*}" -ge 1 ]; then
    echo "WARNING: load is $LOAD before the run started; these numbers are not comparable"
fi

cat > "$WORK/sub.lua" <<'EOLUA'
-- The sub-server answers through the runtime that owns the connection, which
-- is the whole of the routed round trip.
function on_client_message(client_id, msg)
    self.owner_send(client_id, msg)
end
EOLUA

cat > "$WORK/parent.lua" <<EOLUA
function on_client_message(client_id, msg)
    if msg == "spawn" then
        socketley.create("server", "bench_sub", { port = $SUB_PORT, config = "$WORK/sub.lua" })
        socketley.start("bench_sub")
        self.send(client_id, "ready")
        return
    end
    if msg == "join" then
        self.route(client_id, "bench_sub")
        return
    end
    self.send(client_id, msg)
end
EOLUA

"$BIN" daemon >"$WORK/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do
    [ -S "$SOCKETLEY_SOCKET" ] && "$BIN" ls >/dev/null 2>&1 && break
    sleep 0.1
done
"$BIN" ls >/dev/null 2>&1 || { echo "daemon did not come up"; exit 1; }

"$BIN" create server bench_par -p "$PARENT_PORT" --lua "$WORK/parent.lua" -s >/dev/null 2>&1
sleep 0.5

python3 - "$PARENT_PORT" "$ROUNDS" "$REPEATS" <<'PY'
import socket, statistics, sys, time

PORT    = int(sys.argv[1])
ROUNDS  = int(sys.argv[2])
REPEATS = int(sys.argv[3])
MSG     = b"x" * 64 + b"\n"

def dial():
    s = socket.create_connection(("127.0.0.1", PORT))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(10)
    return s

def pingpong(sock, n):
    """n request/response exchanges, returning seconds."""
    want = len(MSG)
    t0 = time.perf_counter()
    for _ in range(n):
        sock.sendall(MSG)
        got = 0
        while got < want:
            chunk = sock.recv(4096)
            if not chunk:
                return -1
            got += len(chunk)
    return time.perf_counter() - t0

# Bring the sub-server up.
b = dial(); b.sendall(b"spawn\n"); b.recv(4096); b.close(); time.sleep(0.8)

def run(routed):
    s = dial()
    if routed:
        s.sendall(b"join\n"); time.sleep(0.3)
    pingpong(s, 2000)                       # warm-up, discarded
    out = []
    for _ in range(REPEATS):
        out.append(pingpong(s, ROUNDS))
    s.close()
    return out

direct = run(False)
routed = run(True)

def report(name, runs):
    if any(r < 0 for r in runs):
        print("  %-22s FAILED (a round trip never came back)" % name)
        return None
    med = statistics.median(runs)
    print("  %-22s %8.2f us/round  %9.1f rounds/s   (n=%d, spread %.1f%%)"
          % (name, med / ROUNDS * 1e6, ROUNDS / med, len(runs),
             (max(runs) - min(runs)) / med * 100.0))
    return med

print("\nrounds=%d repeats=%d, 65-byte messages, TCP_NODELAY" % (ROUNDS, REPEATS))
d = report("straight to parent", direct)
r = report("routed to sub-server", routed)
if d and r:
    print("  routing costs %.2fx a message the parent answers itself" % (r / d))
PY
