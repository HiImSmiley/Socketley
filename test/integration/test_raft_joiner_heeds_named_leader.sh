#!/usr/bin/env bash
# suite: isolated -- its own daemons, sockets, state directories and port window, so it runs beside the others
# A Raft node waiting to be admitted takes the cluster's word -- a refusal, a message -- only from the leader the node
# it dialled (--raft-join) named on that connection, not from any peer that finished a hello.
#
# ─── THE DEFECT (round 8b, noted; fixed round 8c) ───────────────────────────
#
# Before admission a joiner stepped messages from, and stopped for good on a refusal from, any peer that had said
# hello: a peer that holds a certificate of the cluster's CA (or anyone, under --raft-insecure) could stop every node
# while it joined, or feed it a log of its own.  Now the node it dialled answers each join on the joiner's own
# connection with the leader it knows (id and name, kind::leader), and until admitted the joiner hears that peer alone.
# A node of an older version answers nothing; after three joins on an open connection the joiner says so and takes
# everyone's word, as before.
#
# The seed here is a stand-in that speaks the wire format, so which leader it names is the test's to choose.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_raft.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if eval "$2"; then ok "$1"; else bad "$1" "${3:-}"; fi; }

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
T=$(mktemp -d /tmp/socketley-raftjoin-XXXXXX)
daemon_watch "$T"
PS=$((SL_PORT_BASE + 1795)); PJ=$((SL_PORT_BASE + 1796)); PM=$((SL_PORT_BASE + 1797)); PK=$((SL_PORT_BASE + 1798))
NODES=()
SEED_PIDS=()
cleanup() {
    set +e
    local n p
    for p in "${SEED_PIDS[@]}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
    for n in "${NODES[@]}"; do
        kill -9 "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        daemon_sweep "$(sock "$n")"
    done
    rm -rf "$T"
}
trap cleanup EXIT

# The frames: marker, u32 length, version 1, kind, fields little-endian, strings as u32 length and bytes.
cat > "$T/wire.py" <<'PY'
import struct
def s(b): return struct.pack("<I", len(b)) + b
def frame(kind, body): p = bytes([1, kind]) + body; return b"\0" + struct.pack("<I", len(p)) + p
def hello(i, name, addr): return frame(2, struct.pack("<Q", i) + s(name.encode()) + s(addr.encode()))
def leader(i, name, addr): return frame(8, struct.pack("<Q", i) + s(name.encode()) + s(addr.encode()))
def refuse(why): return frame(7, s(why.encode()))
def frames(buf):
    out = []
    while len(buf) >= 5:
        n = struct.unpack("<I", buf[1:5])[0]
        if len(buf) < 5 + n: break
        out.append(buf[5:5 + n]); buf = buf[5 + n:]
    return out, buf
PY
# seed.py <port> <modefile> <log>: answers each join with the leader <modefile> names ("none", "mute", or "<id> <name>").
cat > "$T/seed.py" <<'PY'
import socket, sys, threading
sys.path.insert(0, sys.argv[0].rsplit("/", 1)[0])
import wire
port, modefile, log = int(sys.argv[1]), sys.argv[2], sys.argv[3]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
def serve(c):
    buf = b""
    while True:
        d = c.recv(65536)
        if not d: return
        got, buf = wire.frames(buf + d)
        for p in got:
            if p[1] != 3: continue
            mode = open(modefile).read().split()
            with open(log, "a") as f: f.write("join %s\n" % mode[0])
            if mode[0] == "mute": continue
            c.sendall(wire.leader(0, "", "") if mode[0] == "none" else wire.leader(int(mode[0], 16), mode[1], "127.0.0.1:1"))
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
# rogue.py <port> <id> <name> <why>: says hello as <id>/<name> and refuses.
cat > "$T/rogue.py" <<'PY'
import socket, sys, time
sys.path.insert(0, sys.argv[0].rsplit("/", 1)[0])
import wire
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
c.sendall(wire.hello(int(sys.argv[2], 16), sys.argv[3], "127.0.0.1:9") + wire.refuse(sys.argv[4]))
time.sleep(1)
PY
joins() { grep -c "^join" "$T/$1.seedlog" 2>/dev/null || echo 0; }
# Waits for the joiner to have sent the seed one more join than it had, so the leader it names now has been read.
next_join() { local n; n=$(joins "$1"); wait_for 10 "[ \$(joins $1) -gt $n ]"; sleep 0.3; }

echo "=== Integration: a joiner heeds only the leader the node it dialled names ==="
echo none > "$T/s.mode"
python3 "$T/seed.py" "$PS" "$T/s.mode" "$T/s.seedlog" & SEED_PIDS+=($!)
sleep 0.3
node_start j --raft-listen 127.0.0.1:$PJ --raft-join 127.0.0.1:$PS --raft-insecure --raft-name j
check "the joiner asks the seed to be admitted" 'wait_for 10 "[ \$(joins s) -ge 1 ]"' "the seed saw no join"
next_join s

python3 "$T/rogue.py" "$PJ" 7777777777777777 rogue "rogue says stop" 2>/dev/null
sleep 1.5
check "a refusal from a peer while the seed names no leader does not stop the joiner" '[ "$(role j)" != stopped ]' \
    "$(status j | head -5)"
check "and the joiner says it ignored it" 'grep -q "ignored a refusal from 7777777777777777 (rogue)" "$T/j.log"' \
    "$(tail -3 "$T/j.log")"

echo "1111111111111111 a" > "$T/s.mode"
next_join s
python3 "$T/rogue.py" "$PJ" 7777777777777777 rogue "rogue says stop" 2>/dev/null
sleep 1.5
check "nor one from a peer that is not the leader the seed names" '[ "$(role j)" != stopped ]' "$(status j | head -5)"
python3 "$T/rogue.py" "$PJ" 1111111111111111 b "the right id, another name" 2>/dev/null
sleep 1.5
check "nor one from a peer that gives the named leader's id under another name" '[ "$(role j)" != stopped ]' \
    "$(status j | head -5)"

echo "7777777777777777 rogue" > "$T/s.mode"
next_join s
python3 "$T/rogue.py" "$PJ" 7777777777777777 rogue "the named leader says no" 2>/dev/null
check "the leader the seed names is heeded: its refusal stops the joiner" \
    'wait_for 10 "[ \"\$(role j)\" = stopped ]"' "$(status j | head -5)"
check "with the leader's words" 'grep -q "the named leader says no" "$T/j.log"' "$(tail -3 "$T/j.log")"

# A seed of an older version, which answers no join: after three, everyone's word, as before this change.
echo mute > "$T/m.mode"
python3 "$T/seed.py" "$PM" "$T/m.mode" "$T/m.seedlog" & SEED_PIDS+=($!)
sleep 0.3
node_start k --raft-listen 127.0.0.1:$PK --raft-join 127.0.0.1:$PM --raft-insecure --raft-name k
check "a joiner whose seed names no leader at all says so after three joins" \
    'wait_for 15 "grep -q \"without naming the leader\" $T/k.log"' "$(tail -3 "$T/k.log")"
python3 "$T/rogue.py" "$PK" 7777777777777777 rogue "anyone, as before" 2>/dev/null
check "and then takes a refusal from any peer, as it did before" 'wait_for 10 "[ \"\$(role k)\" = stopped ]"' \
    "$(status k | head -5)"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
