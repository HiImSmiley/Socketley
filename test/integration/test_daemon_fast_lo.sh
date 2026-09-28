#!/usr/bin/env bash
# Integration test: `daemon --fast-lo` puts loopback pairs on the kernel shortcut
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# With --fast-lo a send on a 127.0.0.1 pair is placed straight into the peer's
# receive queue, so the bytes never pass through TCP: the sender's
# tcpi_bytes_acked stays at the 1 its SYN took.  That counter is how this file
# tells a pair on the shortcut from one off it.  The proxy's splice path and
# kernel relay read the TCP receive queue, which a socket on the shortcut does
# not fill, so a pair with a leg on it must stay on the copy path.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a mode other than own or all accepted, or --fast-lo taken by the cli
#     together with --name, where it would configure nothing
#   * a daemon without the capabilities refusing to serve, rather than saying
#     so once and serving on the ordinary path
#   * all: a local client of another process not put on the shortcut (acked
#     counts the whole exchange), or its pipelined replies out of order
#   * all: a runtime of another daemon -- same binary, same cgroup, no
#     --fast-lo -- taken for one of this daemon's
#   * own: that same client put on it anyway -- own is for pairs whose both ends
#     are this daemon's runtimes -- or a client runtime's pair to a server
#     runtime not put on it
#   * splice or the kernel relay taking a pair with a leg on the shortcut, which
#     loses the bytes and hangs the exchange
#
# The last three need CAP_BPF and CAP_NET_ADMIN, given to a copy of the binary
# with `sudo -n setcap`; without sudo they are skipped.
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: daemon --fast-lo ==="
if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }
not_asserted(){ TOTAL=$((TOTAL+1)); echo "  NOT ASSERTED [$1]: $2"; }

daemon_isolate fastlo
# The probes and the capped copy outlive each daemon's TMPD, which daemon_stop deletes.
WORK=$(mktemp -d /tmp/socketley-fastlo-work-XXXXXX)
daemon_watch "$WORK"
ECHOPID=""
cleanup(){ [ -n "$ECHOPID" ] && { kill -9 "$ECHOPID" 2>/dev/null || true; }; daemon_stop; rm -rf "$WORK"; }
trap cleanup EXIT

CPORT=$((SL_PORT_BASE + 1811))
PXSPLICE=$((SL_PORT_BASE + 1812))
PXRELAY=$((SL_PORT_BASE + 1813))
EPORT=$((SL_PORT_BASE + 1814))
SPORT=$((SL_PORT_BASE + 1815))

# A foreign client: pipelined SETs and GETs of 300 KB values, then the
# sender's tcpi_bytes_acked (offset 120 of struct tcp_info).
cat >"$WORK/cache_probe.py" <<'PY'
import socket, struct, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
v = b"v" * 300000
cmds = b"".join(b"*3\r\n$3\r\nSET\r\n$2\r\nk%d\r\n$%d\r\n%s\r\n" % (i, len(v), v) for i in range(10))
cmds += b"".join(b"*2\r\n$3\r\nGET\r\n$2\r\nk%d\r\n" % i for i in range(10))
s.sendall(cmds)
want = b"+OK\r\n" * 10 + (b"$300000\r\n" + v + b"\r\n") * 10
got = b""
try:
    while len(got) < len(want):
        d = s.recv(1 << 20)
        if not d: break
        got += d
except socket.timeout:
    pass
acked = struct.unpack_from("Q", s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256), 120)[0]
print("ok" if got == want else "bad got=%d want=%d" % (len(got), len(want)), acked)
PY

# 4 MB of distinct bytes through a port and back.
cat >"$WORK/echo_probe.py" <<'PY'
import os, socket, sys, threading
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
data = os.urandom(4 << 20)
threading.Thread(target=s.sendall, args=(data,), daemon=True).start()
got = b""
try:
    while len(got) < len(data):
        d = s.recv(1 << 20)
        if not d: break
        got += d
except socket.timeout:
    pass
print("ok" if got == data else "bad got=%d want=%d" % (len(got), len(data)))
PY

cat >"$WORK/echo_server.py" <<'PY'
import socket, sys, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(16)
def serve(c):
    while True:
        d = c.recv(1 << 16)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

wait_port(){ local i; for i in $(seq 1 50); do python3 -c "import socket,sys;socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=1)" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

restart(){ daemon_stop; daemon_isolate fastlo; daemon_start "$@"; }

# ─── (a) the flag's value and its place on the command line ─────────────────
OUT=$("$BIN" daemon --fast-lo bogus 2>&1) && RC=0 || RC=$?
if [ "$RC" = 1 ] && grep -q 'invalid --fast-lo value' <<<"$OUT"; then pass
else fail "bad mode" "daemon --fast-lo bogus should exit 1 naming the value" "rc=$RC out: $OUT"; fi

OUT=$("$BIN" daemon --name x --fast-lo 2>&1) && RC=0 || RC=$?
if [ "$RC" = 1 ] && grep -q 'cannot be combined' <<<"$OUT"; then pass
else fail "with --name" "--fast-lo beside --name configures nothing and must be refused" "rc=$RC out: $OUT"; fi

# ─── (b) without the capabilities: said once, and served ────────────────────
if [ "$(id -u)" = 0 ]; then
    not_asserted "uncapped" "running as root, where the shortcut attaches"
else
    daemon_start "$BIN" --fast-lo
    "$BIN" create cache c -p "$CPORT" -s >/dev/null
    wait_port "$CPORT" || true
    R=$(python3 "$WORK/cache_probe.py" "$CPORT" 2>&1 || true)
    if grep -q 'fast-lo: unavailable, serving without it' "$SOCKETLEY_DLOG" && [ "${R%% *}" = ok ]; then pass
    else fail "uncapped" "a daemon that cannot attach says so and serves" "probe: $R" "$(grep -i fast-lo "$SOCKETLEY_DLOG" || echo 'no fast-lo line in the log')"; fi
fi

# ─── the capped copy ────────────────────────────────────────────────────────
CAPBIN="$WORK/socketley-fastlo"
cp "$BIN" "$CAPBIN"
if ! sudo -n setcap cap_bpf,cap_net_admin+ep "$CAPBIN" 2>/dev/null; then
    echo "  SKIP: the shortcut itself (no sudo -n setcap for CAP_BPF/CAP_NET_ADMIN)"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    [ "$FAIL" = 0 ] && exit 0 || exit 1
fi

attached(){
    if grep -q 'fast-lo: unavailable' "$SOCKETLEY_DLOG"; then
        echo "  SKIP: the shortcut did not attach here: $(grep 'fast-lo' "$SOCKETLEY_DLOG")"
        echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
        [ "$FAIL" = 0 ] && exit 0 || exit 1
    fi
}

# ─── (c) all: a local client of another process ─────────────────────────────
restart "$CAPBIN" --fast-lo
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null
wait_port "$CPORT" || true
R=$(python3 "$WORK/cache_probe.py" "$CPORT" 2>&1 || true)
read -r VERDICT ACKED <<<"$R"
if [ "$VERDICT" = ok ] && [ "${ACKED:-0}" -le 1 ]; then pass
else fail "all: foreign client" "pipelined replies intact and the client's bytes off TCP" "probe: $R (acked <= 1 is the shortcut)"; fi

# Another daemon of the same binary in the same cgroup is not this daemon.
OTHERSOCK="$WORK/other.sock"
OTHERPORT=$((SL_PORT_BASE + 1816))
SOCKETLEY_SOCKET="$OTHERSOCK" HOME="$WORK" "$CAPBIN" daemon >"$WORK/other.log" 2>&1 & OTHERPID=$!
for _ in $(seq 1 50); do [ -S "$OTHERSOCK" ] && break; sleep 0.1; done
SOCKETLEY_SOCKET="$OTHERSOCK" HOME="$WORK" "$BIN" create cache oc -p "$OTHERPORT" -s >/dev/null 2>&1 || true
wait_port "$OTHERPORT" || true
R=$(python3 "$WORK/cache_probe.py" "$OTHERPORT" 2>&1 || true)
{ kill -9 "$OTHERPID"; wait "$OTHERPID"; } 2>/dev/null || true
read -r VERDICT ACKED <<<"$R"
if [ "$VERDICT" = ok ] && [ "${ACKED:-0}" -gt 1000 ]; then pass
else fail "all: another daemon" "a daemon without --fast-lo, same binary, same cgroup, stays on TCP" "probe: $R (acked > 1000 is TCP)"; fi

# ─── (d) splice and the kernel relay stay off a pair on the shortcut ───────
python3 "$WORK/echo_server.py" "$EPORT" >/dev/null 2>&1 & ECHOPID=$!; disown
wait_port "$EPORT" || true

export SOCKETLEY_PROXY_SPLICE=1
restart "$CAPBIN" --fast-lo
unset SOCKETLEY_PROXY_SPLICE
attached
"$BIN" create proxy ps -p "$PXSPLICE" --backend "127.0.0.1:$EPORT" --protocol tcp -s >/dev/null
wait_port "$PXSPLICE" || true
R=$(timeout 20 python3 "$WORK/echo_probe.py" "$PXSPLICE" 2>&1 || echo "hung")
if [ "$R" = ok ]; then pass
else fail "splice" "a proxied pair with a leg on the shortcut stays on the copy path" "probe: $R"; fi

export SOCKETLEY_PROXY_SOCKMAP=1
restart "$CAPBIN" --fast-lo
unset SOCKETLEY_PROXY_SOCKMAP
attached
"$BIN" create proxy pr -p "$PXRELAY" --backend "127.0.0.1:$EPORT" --protocol tcp -s >/dev/null
wait_port "$PXRELAY" || true
R=$(timeout 20 python3 "$WORK/echo_probe.py" "$PXRELAY" 2>&1 || echo "hung")
if [ "$R" = ok ]; then pass
else fail "kernel relay" "a proxied pair with a leg on the shortcut stays out of the relay" "probe: $R"; fi

# ─── (e) own: this daemon's runtimes only ───────────────────────────────────
restart "$CAPBIN" --fast-lo own
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null
wait_port "$CPORT" || true
R=$(python3 "$WORK/cache_probe.py" "$CPORT" 2>&1 || true)
read -r VERDICT ACKED <<<"$R"
if [ "$VERDICT" = ok ] && [ "${ACKED:-0}" -gt 1000 ]; then pass
else fail "own: foreign client" "a client of another process stays on TCP under own" "probe: $R (acked > 1000 is TCP)"; fi

if command -v ss >/dev/null 2>&1; then
    "$BIN" create server s -p "$SPORT" -s >/dev/null
    wait_port "$SPORT" || true
    "$BIN" create client cl -t "127.0.0.1:$SPORT" -s >/dev/null
    for i in $(seq 1 20); do "$BIN" send cl "message $i" >/dev/null 2>&1 || true; done
    sleep 0.3
    # The client runtime's socket: local port any, peer the server's port.
    LINE=$(ss -tinH "( dport = :$SPORT )" 2>/dev/null | tr '\n' ' ')
    ACKED=$(grep -oE 'bytes_acked:[0-9]+' <<<"$LINE" | head -1 | cut -d: -f2)
    if [ -n "$ACKED" ] && [ "$ACKED" -le 1 ]; then pass
    else fail "own: runtime pair" "a client runtime's pair to a server runtime is on the shortcut" "ss: ${LINE:-no connection to :$SPORT}"; fi
else
    not_asserted "own: runtime pair" "ss not available"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ]
