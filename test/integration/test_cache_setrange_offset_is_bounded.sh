#!/usr/bin/env bash
# Integration test: one SETRANGE cannot ask the allocator for more than the
# machine has.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# SETRANGE is the only command whose result length is computed from a number
# the client sends rather than from the bytes it sends.  `SETRANGE k <offset>
# x` builds a string of offset+1 bytes out of a request a few dozen bytes long.
#
# The guard on it refused two things: the size_t wrap, and anything above
# std::string::max_size(), which is about 4.6e18.  Every length in between --
# which is every length that matters -- was accepted, and cache_store then
# either constructs or resizes to it.  A failed allocation raises std::bad_alloc,
# and there are exactly three catch blocks in this tree (CLI flag parsing, a
# state-file default helper, and JavaScript in the dashboard), none of them
# anywhere near the command path.  So the worker terminates, taking every
# connection on that process with it.
#
# No authentication is involved: this cache has no such mechanism.
#
# ─── WHY 1e15 AND NOT 1e12 ──────────────────────────────────────────────────
#
# 1e12 is a terabyte, which Linux overcommit may well hand out -- and then the
# construction memsets it and the OOM killer arrives, which is slow and takes
# neighbours with it.  1e15 is past the user address space on x86-64, so the
# mapping is refused outright: the same defect, reached in milliseconds and
# without putting the machine under memory pressure.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   the huge offset is refused   the guard accepting a length no process holds
#   the cache still answers      the worker dying, which is the actual damage:
#                                every other connection goes with it
#   an ordinary SETRANGE works   a cap set so low it broke the command
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate setrange

P=$((SL_PORT_BASE+1696))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() { "$BIN" stop sr >/dev/null 2>&1 || true; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: one SETRANGE cannot ask for more than the machine has ==="

daemon_start "$BIN"
"$BIN" create cache sr -p "$P" --resp -s >/dev/null 2>&1
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

OUT=$(timeout 60 python3 - "$P" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])

def talk(sock, *parts):
    out = b"*%d\r\n" % len(parts)
    for p in parts:
        b = p.encode() if isinstance(p, str) else p
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    sock.sendall(out)

def reply(sock):
    sock.settimeout(20)
    buf = b""
    while b"\r\n" not in buf:
        d = sock.recv(65536)
        if not d:
            return "<closed>"
        buf += d
    return buf.split(b"\r\n")[0].decode("latin1", "replace")

def conn():
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.settimeout(20)
    return s

# Past the user address space on x86-64: the mapping is refused at once.
HUGE = "1000000000000000"
try:
    s = conn()
    talk(s, "PING"); print("ping_before=%s" % reply(s))
    talk(s, "SETRANGE", "bigk", HUGE, "x")
    print("huge_answer=%s" % reply(s))
    s.close()
except Exception as e:
    print("huge_answer=<%s: %s>" % (type(e).__name__, e))

# A fresh connection, because the one above may legitimately have been closed
# after a refusal -- what matters is whether the WORKER is still there.
time.sleep(0.5)
try:
    s2 = conn()
    talk(s2, "PING"); print("ping_after=%s" % reply(s2))
    talk(s2, "SETRANGE", "okk", "5", "abc"); print("small_setrange=%s" % reply(s2))
    talk(s2, "GET", "okk"); r = reply(s2); print("small_get_header=%s" % r)
    s2.close()
except Exception as e:
    print("ping_after=<%s: %s>" % (type(e).__name__, e))
PYEOF
)
echo "$OUT" | sed 's/^/  /'

case "$OUT" in
    *"huge_answer=-ERR"*) ok ;;
    *) bad "a SETRANGE past what a process can hold is refused with an error" \
           "got: $(echo "$OUT" | grep huge_answer || echo '<no line>')" \
           "a closed connection here is the allocation being attempted and the" \
           "worker dying on the std::bad_alloc nothing in this tree catches" ;;
esac

case "$OUT" in
    *"ping_after=+PONG"*) ok ;;
    *) bad "the cache is still serving afterwards" \
           "got: $(echo "$OUT" | grep ping_after || echo '<no line>')" \
           "this is the damage: one command from one client ends the worker" \
           "and every other connection on it"; ;;
esac

case "$OUT" in
    *"small_setrange=:8"*) ok ;;
    *) bad "an ordinary SETRANGE still works" \
           "got: $(echo "$OUT" | grep small_setrange || echo '<no line>')" \
           "offset 5 plus three bytes is a string of 8"; ;;
esac

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
