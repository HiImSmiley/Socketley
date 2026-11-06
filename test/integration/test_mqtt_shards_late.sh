#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An mqtt runtime of several shards when one shard hears late of what another did.
#
# What each part would catch:
#   * a SUBACK sent before the other shards know of its new filter, so a QoS 1 message published on another shard
#     right after it never reaches the subscriber, with the mesh and with the daemon carrying the shards' words
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$HERE/lib_verdicts.sh"

echo "=== Integration: an mqtt runtime of several shards when one hears late ==="
P=$((SL_PORT_BASE + 1960))

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$P" "$BIN" 2>&1 <<'PY'
import os, re, signal, subprocess, sys, time
from lib_mqtt import *
phase, port, binary = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def owner(c):
    lport = c.sock.getsockname()[1]
    out = subprocess.run(["ss", "-tnpH", "sport = :%d and dport = :%d" % (port, lport)],
                         capture_output=True, timeout=10).stdout.decode()
    m = re.search(r"pid=(\d+)", out)
    return int(m.group(1)) if m else None

def stat(name, least=1):
    # A shard's figures reach the daemon a moment after they change.
    for _ in range(50):
        out = subprocess.run([binary, "stats", "sh"], capture_output=True, timeout=30).stdout.decode()
        n = sum(int(v) for k, _, v in (l.partition(":") for l in out.splitlines()) if k == name)
        if n >= least:
            break
        time.sleep(0.2)
    return n

def elsewhere(name, home):
    for i in range(60):
        c = connected(port, "%s-%d" % (name, i))
        if owner(c) not in (home, None):
            return c
        c.disconnect()
    return None

if phase in ("suback", "suback_relayed"):
    def suback():
        pub = connected(port, "pub")
        sub = elsewhere("sub", owner(pub))
        truth("a subscriber lands on another shard than its publisher", sub is not None)
        if sub is None:
            return
        # Each filter new to every shard, published to at once from the other one.
        got = 0
        for i in range(40):
            sub.subscribe(("fresh/%d" % i, 1))
            pub.publish("fresh/%d" % i, b"m%d" % i, qos=1)
            m = sub.message(3)
            got += m is not None and m.payload == b"m%d" % i
        check("every QoS 1 message published on another shard right after the SUBACK arrives (%s)" % phase, got, 40)
        held = stat("subacks_held")
        truth("stats count the SUBACKs that waited", held >= 1, held)
        # One the other shards know already is answered at once.
        again = connected(port, "again")
        t = time.time()
        again.subscribe(("fresh/0", 1))
        truth("a SUBACK for a filter every shard knows is not held", time.time() - t < 0.5, time.time() - t)
        pub.disconnect(); sub.disconnect(); again.disconnect()
    guarded("suback", suback)

PY
}

for mode in mesh relayed; do
    daemon_isolate "mqttlate$mode"
    trap 'daemon_stop' EXIT
    if [ "$mode" = relayed ]; then export SOCKETLEY_NO_SHARD_MESH=1; else unset SOCKETLEY_NO_SHARD_MESH; fi
    daemon_start "$BIN"
    "$BIN" create mqtt sh -p "$P" --anonymous --shards 3 -s >/dev/null 2>&1 \
        && ok || bad "a broker of three shards is made ($mode)" "$(tail -3 "$SOCKETLEY_DLOG")"
    ready_tcp 127.0.0.1 "$P" || bad "it listens ($mode)" "$(tail -5 "$SOCKETLEY_DLOG")"
    for _ in $(seq 1 50); do
        [ "$("$BIN" stats sh 2>/dev/null | awk -F: '$1=="shard_peers_known"{s+=$2} END{print s+0}')" -ge 6 ] && break
        sleep 0.2
    done
    if [ "$mode" = relayed ]; then tally < <(run suback_relayed); else tally < <(run suback); fi
    daemon_stop
done
unset SOCKETLEY_NO_SHARD_MESH

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
