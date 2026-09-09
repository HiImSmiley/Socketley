#!/usr/bin/env bash
# Integration test: --send-to, and who a server with no script answers.
#
# --mode names a direction and never said who receives a message.  With no
# script, `inout` repeated every message to the OTHER connections -- so a single
# client talking to a server heard nothing back, which reads exactly like a
# broken runtime.  Two of the three things it could have done had no spelling at
# all: echoing to the sender needed Lua, and everyone-including-the-sender was
# not reachable from the message path.
#
# It also came apart by transport.  Measured against the pre-flag binary: over
# UDP the sender DID receive its own datagram and over TCP it did not, from two
# code paths meant to agree -- the UDP one passed `nullptr` where an exclusion
# was supposed to go, under a comment claiming the caller had handled it.  The
# UDP row below is the guard on that.
#
# The recipients are a SET, and a DISJOINT one: `others` is everyone else who is
# not the master, so `others,master` is not a second spelling of `others`.  There
# is no `all` for the same reason -- `sender,others` says it.
#
# --master-forward was one recipient carrying its own flag and is now
# `--send-to master`, prefix and all.  The master rows are what make that
# replacement checkable rather than merely plausible.
#
# Every case uses two clients, because one client cannot tell `others` from a
# server that answers nobody -- which is the whole reason this was invisible.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate sendto
P_OTHERS=$((SL_PORT_BASE+1940))
P_SENDER=$((SL_PORT_BASE+1941))
P_BOTH=$((SL_PORT_BASE+1942))
P_UDP=$((SL_PORT_BASE+1943))
P_REFUSE=$((SL_PORT_BASE+1944))
P_MFWD=$((SL_PORT_BASE+1945))
P_MSET=$((SL_PORT_BASE+1946))
P_MMOD=$((SL_PORT_BASE+1947))
MPW=hunter2
PASS=0; FAIL=0; TOTAL=0
NAMES="st_others st_sender st_both st_udp st_mfwd st_mset st_mmod"

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" 2>/dev/null || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

check() {   # label expected actual
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$1]: expected '$2', got '$3'"
    fi
}

refused() {   # label needle -- everything after is the command
    local label=$1 needle=$2; shift 2
    local out
    out=$("$@" 2>&1) || true
    TOTAL=$((TOTAL+1))
    if grep -q "$needle" <<<"$out"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: expected a refusal naming '$needle', got '$out'"
    fi
}

# Two TCP clients, A sends, and the answer says who heard it.  Not `nc`: a
# reader that exits when stdin ends reports silence for a server that answered.
probe_tcp() {
    python3 - "$1" <<'PYEOF' 2>/dev/null || echo "PROBE-FAILED"
import socket, sys, time
port = int(sys.argv[1])
a = socket.create_connection(("127.0.0.1", port), 5); a.settimeout(1.5)
b = socket.create_connection(("127.0.0.1", port), 5); b.settimeout(1.5)
time.sleep(0.3)
a.sendall(b"hello\n")
def hear(s):
    try:    return s.recv(256).decode().strip()
    except Exception: return ""
print("%s/%s" % (hear(a) or "-", hear(b) or "-"))
PYEOF
}

# The same shape over UDP, where a peer exists only once it has spoken.
probe_udp() {
    python3 - "$1" <<'PYEOF' 2>/dev/null || echo "PROBE-FAILED"
import socket, sys, time
port = int(sys.argv[1]); dst = ("127.0.0.1", port)
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); a.settimeout(1.2)
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b.settimeout(1.2)
b.sendto(b"register-b\n", dst)
time.sleep(0.3)
for s in (a, b):
    try: s.recvfrom(256)
    except Exception: pass
a.sendto(b"hello\n", dst)
def hear(s):
    try:    return s.recvfrom(256)[0].decode().strip()
    except Exception: return ""
print("%s/%s" % (hear(a) or "-", hear(b) or "-"))
PYEOF
}

# A master and two ordinary clients: an ordinary one sends, and the answer says
# who heard it.  The master's copy carries the sender's descriptor in front of
# it and a descriptor is not predictable, so it is reported as `fwd` by shape
# rather than compared by value.
probe_master() {
    python3 - "$1" "$MPW" <<'PYEOF' 2>/dev/null || echo "PROBE-FAILED"
import socket, sys, time
port, pw = int(sys.argv[1]), sys.argv[2]
m = socket.create_connection(("127.0.0.1", port), 5); m.settimeout(1.2)
m.sendall(("master %s\n" % pw).encode())
time.sleep(0.4)
try: m.recv(256)
except Exception: pass
c = socket.create_connection(("127.0.0.1", port), 5); c.settimeout(1.2)
o = socket.create_connection(("127.0.0.1", port), 5); o.settimeout(1.2)
time.sleep(0.3)
c.sendall(b"hello\n")
def hear(s):
    out = ""
    try:
        while True:
            d = s.recv(256)
            if not d: break
            out += d.decode()
    except Exception: pass
    return out.strip().replace("\n", "|") or "-"
mh = hear(m)
print("%s/%s/%s" % ("fwd" if mh.startswith("[") and mh.endswith(" hello") else mh,
                    hear(c), hear(o)))
PYEOF
}

echo "=== Integration: server --send-to ==="

daemon_start "$BIN"

create_ok "default server"          "$BIN" create server st_others -p "$P_OTHERS" -s
create_ok "--send-to sender"        "$BIN" create server st_sender -p "$P_SENDER" --send-to sender -s
create_ok "--send-to sender,others" "$BIN" create server st_both   -p "$P_BOTH"   --send-to sender,others -s
create_ok "--send-to over UDP"      "$BIN" create server st_udp    -p "$P_UDP"    --udp -s
create_ok "master, master"          "$BIN" create server st_mfwd   -p "$P_MFWD" \
    --mode master --master-pw "$MPW" --send-to master -s
create_ok "master, sender,master"   "$BIN" create server st_mset   -p "$P_MSET" \
    --mode master --master-pw "$MPW" --send-to sender,master -s
create_ok "master, others,master"   "$BIN" create server st_mmod   -p "$P_MMOD" \
    --mode master --master-pw "$MPW" --send-to others,master -s

for p in "$P_OTHERS" "$P_SENDER" "$P_BOTH" "$P_MFWD" "$P_MSET" "$P_MMOD"; do
    ready_tcp 127.0.0.1 "$p" || echo "  WARN: nothing listening on $p"
done
sleep 0.4

# sender_heard/other_heard
check "unset is others"        "-/hello"     "$(probe_tcp "$P_OTHERS")"
check "sender echoes back"     "hello/-"     "$(probe_tcp "$P_SENDER")"
check "sender,others is both"  "hello/hello" "$(probe_tcp "$P_BOTH")"

# The transport divergence: this read hello/hello before the flag existed.
check "UDP unset matches TCP"  "-/hello"     "$(probe_udp "$P_UDP")"

# master_heard/sender_heard/other_heard.  `fwd` is "[<fd>] hello", which is byte
# for byte what --master-forward produced -- that flag is gone and this is what
# replaced it.  The other two rows are shapes that had no spelling before.
check "master mode: master"        "fwd/-/-"     "$(probe_master "$P_MFWD")"
check "master mode: sender,master" "fwd/hello/-" "$(probe_master "$P_MSET")"
check "master mode: others,master" "fwd/-/hello" "$(probe_master "$P_MMOD")"

# --master-forward is answered with a pointer rather than "unknown flag": it is
# a spelling that worked yesterday and the recipient it named still exists.
refused "--master-forward points at its replacement" "now --send-to master" \
    "$BIN" create server st_bad0 -p "$P_REFUSE" --mode master --master-pw x --master-forward

# Refused rather than accepted and ignored, and the check must survive --mode
# being typed on either side of --send-to.
refused "--mode in refused" "needs --mode inout or master" \
    "$BIN" create server st_bad1 -p "$P_REFUSE" --mode in --send-to sender

refused "master outside master mode, reversed order" "needs --mode master" \
    "$BIN" create server st_bad2 -p "$P_REFUSE" --send-to master --mode inout

refused "unknown recipient refused" "unknown --send-to" \
    "$BIN" create server st_bad3 -p "$P_REFUSE" --send-to nobody

refused "a trailing comma is a typo, not an empty recipient" "unknown --send-to" \
    "$BIN" create server st_bad4 -p "$P_REFUSE" --send-to sender,

# The refusal is per RECIPIENT and not per flag: a blanket "inout only" rule
# would have rejected this one, and it is exactly the case the set model buys.
OUT=$("$BIN" create server st_bad5 -p "$P_REFUSE" --mode master --master-pw x --send-to sender 2>&1) || true
TOTAL=$((TOTAL+1))
if [ -z "$OUT" ]; then
    PASS=$((PASS+1)); "$BIN" remove st_bad5 >/dev/null 2>&1 || true
else
    FAIL=$((FAIL+1)); echo "  FAIL [sender is allowed in master mode]: got '$OUT'"
fi

# On record and readable back: a flag that only lives in the running process is
# lost on the restart the daemon performs for itself.  Written in the spelling
# that was typed, so a state file can be checked by eye.
SF=$(find "${HOME}/.local/share/socketley" -name 'st_mset.json' 2>/dev/null | head -1)
TOTAL=$((TOTAL+1))
if [ -n "$SF" ] && grep -q '"send_to": "sender,master"' "$SF"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo "  FAIL [the set persists in its own spelling]: not in ${SF:-<no state file>}"
fi

# Unset is not written, like every other optional field here, so a state file
# from before this flag keeps meaning what it meant.
DF=$(find "${HOME}/.local/share/socketley" -name 'st_others.json' 2>/dev/null | head -1)
TOTAL=$((TOTAL+1))
if [ -n "$DF" ] && ! grep -q 'send_to' "$DF"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo "  FAIL [unset not persisted]: send_to written into ${DF:-<no state file>}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
