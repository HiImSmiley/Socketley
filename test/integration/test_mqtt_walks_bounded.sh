#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# What a SUBSCRIBE and a PUBLISH cost the loop, whatever the retained messages and the sessions moved between shards.
#
# What each part would catch:
#   * a SUBSCRIBE of 1,024 distinct filters that each match all of 20,000 retained messages walked them 1,024 times
#     in one turn of the loop; the filters of one SUBSCRIBE now walk the retained tree at most four times over
#   * every PUBLISH tested its topic against every filter of every session moved to another shard in the last ten
#     seconds, 20 sessions of 10,000 filters 200,000 times; the filters of the sessions moved are one tree now
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

echo "=== Integration: a SUBSCRIBE and a PUBLISH cost what they reach ==="
daemon_isolate mqttwalks
P=$((SL_PORT_BASE + 1760))
PS=$((SL_PORT_BASE + 1761))
trap 'daemon_stop' EXIT
daemon_start "$BIN"
sanitized=0
build_sanitized && sanitized=1

"$BIN" create mqtt wk -p "$P" --anonymous -s >/dev/null 2>&1 \
    && ok || bad "a broker is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create mqtt wks -p "$PS" --anonymous --shards 2 -s >/dev/null 2>&1 \
    && ok || bad "a broker of two shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
ready_tcp 127.0.0.1 "$P" || bad "it listens" "$(tail -5 "$SOCKETLEY_DLOG")"
ready_tcp 127.0.0.1 "$PS" || bad "the sharded one listens" "$(tail -5 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do
    [ "$("$BIN" stats wks 2>/dev/null | awk -F: '$1=="shard_peers_known"{s+=$2} END{print s+0}')" -ge 2 ] && break
    sleep 0.2
done

run() {
    SANITIZED=$sanitized PYTHONPATH="$HERE" python3 - "$1" "$2" "$BIN" 2>&1 <<'PY'
import itertools, json, os, subprocess, sys, time
from lib_mqtt import *
phase, port, binary = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def ping_ms(c):
    t0 = time.monotonic()
    c.ping()
    return (time.monotonic() - t0) * 1000

if phase == "retained":
    def retained():
        levels = ["l%d" % i for i in range(10)]
        pub = connected(port, "r-pub", timeout=30)
        for i in range(20000):
            pub.publish("/".join(levels) + "/%d" % i, b"x", qos=0, retain=True, wait=False)
        pub.ping()
        filters = ["/".join(c) + "/+" for c in itertools.product(*[(l, "+") for l in levels])]
        sub = connected(port, "r-sub", timeout=30)
        other = connected(port, "r-other", timeout=30)
        base = min(ping_ms(other) for _ in range(5))
        sub.send(SUBSCRIBE, 2, struct.pack(">H", 1) + prop_bytes(None) + b"".join(s(f) + b"\x00" for f in filters))
        held = ping_ms(other)
        print("    a ping behind a SUBSCRIBE of %d filters over 20,000 retained: %.1f ms (alone %.1f ms)" %
              (len(filters), held, base))
        if os.environ.get("SANITIZED") == "1":
            print("  SKIP [stall]: a loop held in milliseconds measures the sanitizer, not the walk")
        else:
            truth("a SUBSCRIBE of 1,024 filters each matching 20,000 retained messages holds the loop under 300 ms",
                  held < 300, "%.1f ms" % held)
        n = len(sub.messages(100, 3))
        truth("the subscriber is sent retained messages", n > 0, n)
    guarded("retained", retained)

if phase == "moved":
    def sessions():
        return json.loads(subprocess.run([binary, "mqtt-sessions", "wks"], capture_output=True, timeout=10).stdout)

    def shard_of(cid):
        for x in sessions():
            if x["client"] == cid and x["connected"]:
                return x["shard"]
        return None

    def on_shard(cid, want, **kw):
        """A connection of `cid` on shard `want`, or on whichever when None."""
        for _ in range(60):
            c = Client(port, timeout=30)
            c.connect(cid, **kw)
            if want is None or shard_of(cid) == want:
                return c
            c.disconnect()
        raise Closed("never landed on shard %r" % want)

    def moved():
        pub = on_shard("m-pub", None)
        home = shard_of("m-pub")
        filters = [("f/%d/x" % j, 1) for j in range(10000)]
        for i in range(20):
            cid = "mv-%d" % i
            c = on_shard(cid, home, clean=True, props={SESSION_EXPIRY: 600})
            c.subscribe(*filters, timeout=30)
            c.disconnect()
            for _ in range(60):
                c = Client(port, timeout=30)
                c.connect(cid, clean=False, props={SESSION_EXPIRY: 600})
                if shard_of(cid) not in (home, None):
                    break
                c.disconnect()
            c.disconnect()
        t0 = time.monotonic()
        for k in range(200):
            pub.publish("nobody/%d" % k, b"x", qos=1)
        took = time.monotonic() - t0
        moved_n = sum(1 for x in sessions() if x["client"].startswith("mv-") and x["shard"] != home)
        print("    200 PUBLISHes at QoS 1 beside %d sessions of 10,000 filters moved away: %.3f s" % (moved_n, took))
        truth("the sessions moved to the other shard", moved_n == 20, moved_n)
        truth("200 PUBLISHes beside 20 moved sessions of 10,000 filters take under 1 s", took < 1.0, "%.3f s" % took)
    guarded("moved", moved)
PY
}

tally < <(run retained "$P")
# The figures are gathered at an interval, so the count is waited for.
for _ in $(seq 1 30); do
    cut=$("$BIN" stats wk 2>&1 | awk -F: '$1=="retained_cut"{s+=$2} END{print s+0}')
    [ "$cut" -ge 1 ] && break
    sleep 0.2
done
[ "$cut" -ge 1 ] && ok || bad "the SUBSCRIBE past four walks of the retained tree is counted" "retained_cut $cut"
tally < <(run moved "$PS")

echo "  Results: $PASS passed, $FAIL failed"
exit "$FAIL"
