#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a table of the cache that held much and holds little is walked and drawn from as what it holds.
#
# A key table grew at three quarters full and never shrank, so a set that held 1,000,000 members and holds one kept
# its 2,097,152 slots: SRANDMEMBER drew 256 empty slots and then walked to the next live one, a million on average,
# and RANDOMKEY did the same over a keyspace emptied by DEL. The tables are rebuilt for what they hold once seven
# eighths of their slots stand empty, between commands.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate cacheshrink
trap daemon_stop EXIT

echo "=== Integration: a cache's tables follow what they hold ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1660))
"$BIN" create cache shr -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 100); do redis-cli -p "$P" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done

python3 - "$P" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port))
s.settimeout(120)
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print("  PASS: " + name)
    else: failed += 1; print("  FAIL [%s]: %s" % (name, detail))
def cmd(*a):
    return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a)
def run(cmds, replies):
    buf = b"".join(cmds); s.sendall(buf)
    got = b""
    while got.count(b"\r\n") < replies:
        got += s.recv(1 << 20)
    return got
N = 1000000
for k in range(0, N, 10000):
    run([cmd(b"SADD", b"big", b"m%07d" % i) for i in range(k, k + 10000)], 10000)
for k in range(1, N, 10000):
    run([cmd(b"SREM", b"big", b"m%07d" % i) for i in range(k, min(k + 10000, N))], min(10000, N - k))
for k in range(0, N, 10000):
    run([cmd(b"SET", b"k%07d" % i, b"v") for i in range(k, k + 10000)], 10000)
for k in range(1, N, 10000):
    run([cmd(b"DEL", b"k%07d" % i) for i in range(k, min(k + 10000, N))], min(10000, N - k))
t0 = time.monotonic()
got = run([cmd(b"SRANDMEMBER", b"big")] * 2000, 4000)
srand = time.monotonic() - t0
check("SRANDMEMBER answers the one member left", got.count(b"m0000000") == 2000, got[:60])
t0 = time.monotonic()
got = run([cmd(b"RANDOMKEY")] * 2000, 4000)
rk = time.monotonic() - t0
print("    2000 SRANDMEMBER of a set that held 1,000,000: %.3f s; 2000 RANDOMKEY: %.3f s" % (srand, rk))
check("2000 SRANDMEMBER of a set emptied to one member take under 0.5 s", srand < 0.5, "%.3f s" % srand)
check("2000 RANDOMKEY of a keyspace emptied to two keys take under 0.5 s", rk < 0.5, "%.3f s" % rk)
got = run([cmd(b"SMEMBERS", b"big"), cmd(b"SCARD", b"big"), cmd(b"DBSIZE")], 5)
check("the set and the keyspace still hold what is left", b"m0000000" in got and b":1\r\n" in got and b":2\r\n" in got, got)
print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
PY
