#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: DEL of a value of many elements frees it off the loop, as FLUSHALL frees a store.
#
# DEL, UNLINK and an expiry freed a set of 2,000,000 members on the loop, every other client waiting; a value of 4,096
# elements or more is handed to the reaper thread FLUSHALL already frees on.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate cachelazydel
trap daemon_stop EXIT

echo "=== Integration: DEL of a large value frees it off the loop ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
daemon_start "$BIN"
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
P=$((SL_PORT_BASE + 1670))
"$BIN" create cache ldel -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 100); do redis-cli -p "$P" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done

python3 - "$P" "$sanitized" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
def conn():
    c = socket.create_connection(("127.0.0.1", port)); c.settimeout(120); return c
s, o = conn(), conn()
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print("  PASS: " + name)
    else: failed += 1; print("  FAIL [%s]: %s" % (name, detail))
def cmd(*a):
    return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a)
def run(c, cmds, replies):
    c.sendall(b"".join(cmds)); got = b""
    while got.count(b"\r\n") < replies:
        got += c.recv(1 << 20)
    return got
N = 2000000
for big, add in ((b"set", b"SADD"), (b"hash", b"HSET"), (b"zset", b"ZADD")):
    for k in range(0, N if big == b"set" else N // 2, 10000):
        if add == b"SADD":
            cmds = [cmd(add, big, b"m%07d" % i) for i in range(k, k + 10000)]
        elif add == b"HSET":
            cmds = [cmd(add, big, b"f%07d" % i, b"v") for i in range(k, k + 10000)]
        else:
            cmds = [cmd(add, big, b"%d" % i, b"m%07d" % i) for i in range(k, k + 10000)]
        run(s, cmds, 10000)
worst = 0.0
for big in (b"set", b"hash", b"zset"):
    s.sendall(cmd(b"DEL", big))
    # A moment for the DEL to be read first, so the PING waits behind it if it holds the loop.
    time.sleep(0.005)
    t0 = time.monotonic()
    run(o, [cmd(b"PING")], 1)
    worst = max(worst, time.monotonic() - t0)
    got = b""
    while b"\r\n" not in got:
        got += s.recv(100)
    check("DEL of the %s answers 1" % big.decode(), got == b":1\r\n", got)
print("    a PING behind DEL of a set of 2,000,000 and a hash and a sorted set of 1,000,000: worst %.1f ms" % (worst * 1000))
if sys.argv[2] == "1":
    print("  SKIP [stall]: milliseconds measure the sanitizer, not the reaper")
else:
    check("a PING behind DEL of a value of a million elements waits under 100 ms", worst < 0.1, "%.1f ms" % (worst * 1000))
check("the keys are gone", run(s, [cmd(b"DBSIZE")], 1) == b":0\r\n")
print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
PY
