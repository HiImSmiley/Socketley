#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A Raft port's inbound links are held to their hello: one that says nothing, or opens with a frame no hello is,
# goes, and a table full of such links makes room for the next connection rather than refusing it.
#
# What each part would catch:
#   * a connection that never says hello kept forever, so 256 of them refuse every member's connection
#   * a first frame announced at 16 MiB buffered before anything judged who sent it
#   * a full table closing the newcomer, a member among them, instead of a link that has said nothing
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_raft.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"

T=$(mktemp -d /tmp/socketley-raftadmit-XXXXXX)
daemon_watch "$T"
PR=$((SL_PORT_BASE + 1794))
NODES=()
cleanup() {
    set +e
    local n
    for n in "${NODES[@]}"; do
        kill -9 "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        daemon_sweep "$(sock "$n")"
    done
    rm -rf "$T"
}
trap cleanup EXIT

echo "=== Integration: a Raft port's inbound links are held to their hello ==="
node_start a --raft-listen 127.0.0.1:$PR --raft-init --raft-insecure --raft-name a
wait_for 15 '[ "$(role a)" = leader ]' && ok || bad "the node founds its cluster" "$(status a)"

tally < <(python3 - "$PR" 2>&1 <<'PY'
import sys, socket, struct, time
port = int(sys.argv[1])
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
def dial():
    return socket.create_connection(("127.0.0.1", port), 5)
def closed_within(s, secs):
    """Whether the node closes the connection within `secs`."""
    s.settimeout(secs)
    try:
        return s.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:
        return True

s = dial()
check("a connection that says nothing is closed once 3 s pass", closed_within(s, 6), True)
s.close()

s = dial()
s.sendall(b"\0" + struct.pack("<I", 16 * 1024 * 1024 - 1) + b"x" * 4096)
check("one whose first frame is longer than any hello is closed at once", closed_within(s, 2), True)
s.close()

idle = [dial() for _ in range(256)]
time.sleep(0.5)
late = dial()
check("a table full of links that said nothing takes the next connection", closed_within(late, 0.5), False)
check("and closes the oldest of them to make room", closed_within(idle[0], 1), True)
for x in idle + [late]:
    x.close()
PY
)
wait_for 5 '[ "$(role a)" = leader ]' && ok || bad "the node leads its cluster still" "$(status a)"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
