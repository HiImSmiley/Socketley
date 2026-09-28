#!/usr/bin/env bash
# Integration test: `daemon --fast-lo` puts loopback pairs on the kernel shortcut
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# With --fast-lo a send on a 127.0.0.1 pair is placed straight into the peer's
# receive queue, so the bytes never pass through TCP: the sender's
# tcpi_bytes_acked stays at the 1 its SYN took.  That counter is how this file
# tells a pair on the shortcut from one off it.  The proxy's splice path reads
# the TCP receive queue, which a socket on the shortcut does not fill, so a
# pair with a leg on it must stay on the copy path.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a mode other than own or all accepted, or --fast-lo taken by the cli
#     together with --name, where it would configure nothing
#   * a daemon without the capabilities refusing to serve, rather than saying
#     so once and serving on the ordinary path; `daemon stats` not saying it
#     is unavailable and why, or not saying off when it was never asked for
#   * all: a local client of another process not put on the shortcut (acked
#     counts the whole exchange), or its pipelined replies out of order
#   * all: a runtime of another daemon -- same binary, same cgroup, no
#     --fast-lo -- taken for one of this daemon's
#   * all: a proxy's pair to a local backend of another process (the sidecar
#     case) left on TCP -- the backend's own socket acks the echo -- or the
#     echo corrupted on the way
#   * own: that backend pair put on the shortcut
#   * all: a pair in another netns with our tuple entering (a container's
#     127.0.0.1 pair overwriting our socket's entry) -- red without the guard
#   * all: a runtime's Lua HTTP call to a local service on ::1 left on TCP --
#     the service's socket acks the 1 MiB body -- or the body corrupted; and a
#     dual-stack service reached at 127.0.0.1 (both ends IPv4-mapped on its
#     side) lost from the shortcut when the keys learned IPv6
#   * own: that same client put on it anyway -- own is for pairs whose both ends
#     are this daemon's runtimes -- or a client runtime's pair to a server
#     runtime not put on it
#   * splice taking a pair with a leg on the shortcut, which loses the bytes and
#     hangs the exchange
#
# Everything past the uncapped case needs CAP_BPF and CAP_NET_ADMIN, given to a
# copy of the binary with `sudo -n setcap`; without sudo it is skipped.
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
ECHOPID=""; ORIGINPID=""; HCPID=""; NSPID=""
cleanup(){ [ -n "$NSPID" ] && sudo -n kill -9 "$NSPID" 2>/dev/null || true
    for p in "$ECHOPID" "$ORIGINPID" "$HCPID"; do [ -n "$p" ] && { kill -9 "$p" 2>/dev/null || true; }; done
    daemon_stop; rm -rf "$WORK"; }
trap cleanup EXIT

CPORT=$((SL_PORT_BASE + 1811))
PXSPLICE=$((SL_PORT_BASE + 1812))
EPORT=$((SL_PORT_BASE + 1814))
SPORT=$((SL_PORT_BASE + 1815))
PXFOREIGN=$((SL_PORT_BASE + 1817))
ORIGIN6=$((SL_PORT_BASE + 1818))
CALLER6=$((SL_PORT_BASE + 1819))
NSA=$((SL_PORT_BASE + 1822))

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

# 1 MB echoed through a proxy while the connection is held, then the
# tcpi_bytes_acked of both ends of the proxy's pair to the backend: the
# backend's accepted socket (source port EPORT) and the proxy's connect to it.
cat >"$WORK/backend_probe.py" <<'PY'
import os, re, socket, subprocess, sys, threading
port, ep = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
data = os.urandom(1 << 20)
threading.Thread(target=s.sendall, args=(data,), daemon=True).start()
got = b""
try:
    while len(got) < len(data):
        d = s.recv(1 << 20)
        if not d: break
        got += d
except socket.timeout:
    pass
out = subprocess.run(["ss", "-tinH", "( sport = :%d or dport = :%d )" % (ep, ep)],
                     capture_output=True, text=True).stdout.splitlines()
acked = {}
for i, ln in enumerate(out):
    if not ln.startswith("ESTAB"): continue
    side = "backend" if ln.split()[3].endswith(":%d" % ep) else "proxy"
    m = re.search(r"bytes_acked:(\d+)", out[i + 1] if i + 1 < len(out) else "")
    acked[side] = int(m.group(1)) if m else 0   # ss leaves a zero out
print("ok" if got == data else "bad got=%d want=%d" % (len(got), len(data)),
      acked.get("backend", -1), acked.get("proxy", -1))
PY

# A local HTTP service on an IPv6 socket that answers each request with a 1 MiB
# body, waits for the client to close, and appends its own socket's
# tcpi_bytes_acked to OUT; bound to ::1, or to :: dual-stack.
cat >"$WORK/origin6.py" <<'PY'
import socket, struct, sys
host, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
body = bytes(range(256)) * 4096
l = socket.socket(socket.AF_INET6); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
l.bind((host, port)); l.listen(8)
open(out, "a").close()
while True:
    c, _ = l.accept(); c.settimeout(10); req = b""
    try:
        while b"\r\n\r\n" not in req:
            d = c.recv(4096)
            if not d: break
            req += d
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        while c.recv(4096): pass
        acked = struct.unpack_from("Q", c.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256), 120)[0]
        with open(out, "a") as f: f.write("%d\n" % acked)
    except Exception as e:
        with open(out, "a") as f: f.write("error %s\n" % e)
    c.close()
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
    OUT=$("$BIN" daemon stats 2>&1 || true)
    if grep -q '^fast_lo:unavailable$' <<<"$OUT" && grep -q '^fast_lo_reason:.' <<<"$OUT"; then pass
    else fail "uncapped stats" "daemon stats says the shortcut is unavailable, and why" "out: $OUT"; fi
    restart "$BIN"
    OUT=$("$BIN" daemon stats 2>&1 || true)
    if [ "$OUT" = "fast_lo:off" ]; then pass
    else fail "off stats" "daemon stats says the shortcut is off when it was not asked for" "out: $OUT"; fi
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

# ─── (d) splice stays off a pair on the shortcut ────────────────────────────
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

# ─── (e) all: a proxy's pair to a local backend of another process ──────────
# The backend is the python echo server, not a runtime, so its port is in no
# map: the pair enters because the proxy's connect is this daemon's.
if command -v ss >/dev/null 2>&1; then
    restart "$CAPBIN" --fast-lo
    attached
    "$BIN" create proxy pf -p "$PXFOREIGN" --backend "127.0.0.1:$EPORT" --protocol tcp -s >/dev/null
    wait_port "$PXFOREIGN" || true
    R=$(timeout 20 python3 "$WORK/backend_probe.py" "$PXFOREIGN" "$EPORT" 2>&1 || echo "hung")
    read -r VERDICT BACKEND PROXY <<<"$R"
    if [ "$VERDICT" = ok ] && [ "${BACKEND:--1}" -ge 0 ] && [ "${BACKEND:--1}" -le 1 ] &&
       [ "${PROXY:--1}" -ge 0 ] && [ "${PROXY:--1}" -le 1 ]; then pass
    else fail "all: foreign backend" "a proxy's pair to a local backend of another process is on the shortcut, echo intact" \
        "probe: $R (verdict, backend acked, proxy acked; 0..1 is the shortcut, -1 no connection)"; fi
else
    not_asserted "all: foreign backend" "ss not available"
fi

# ─── (f) all: a runtime's Lua HTTP call to a local IPv6 service ─────────────
# The call is the runtime's connect, so its pair enters like the proxy's above;
# ::1 is the address, and a dual-stack service reached at 127.0.0.1 is the
# regression guard for IPv4-mapped keys on the service's side.
v6_call(){  # $1 tag, $2 bind address, $3 url host; the verdict in R, not a subshell, so cleanup sees ORIGINPID
    local out="$WORK/origin6-$1.out" i
    python3 "$WORK/origin6.py" "$2" "$ORIGIN6" "$out" >/dev/null 2>&1 & ORIGINPID=$!; disown
    for i in $(seq 1 50); do [ -f "$out" ] && break; sleep 0.1; done
    cat >"$WORK/call6-$1.lua" <<LUA
function on_start()
    local t = {}
    for i = 0, 255 do t[#t + 1] = string.char(i) end
    local want = string.rep(table.concat(t), 4096)
    local r = socketley.http({ url = "http://$3:$ORIGIN6/", timeout_ms = 5000 })
    socketley.log("FASTLO6 $1 ok=" .. tostring(r.ok) .. " same=" .. tostring(r.body == want))
end
LUA
    "$BIN" create server "c6$1" -p "$CALLER6" --lua "$WORK/call6-$1.lua" -s >/dev/null 2>&1 || true
    for i in $(seq 1 50); do grep -q "FASTLO6 $1 " "$SOCKETLEY_DLOG" 2>/dev/null && [ -s "$out" ] && break; sleep 0.1; done
    "$BIN" remove "c6$1" >/dev/null 2>&1 || true
    kill -9 "$ORIGINPID" 2>/dev/null || true; ORIGINPID=""
    R="$({ grep -oE "FASTLO6 $1 .*" "$SOCKETLEY_DLOG" || true; } | tail -1) acked=$(tail -1 "$out" 2>/dev/null || true)"
}
if python3 -c "import socket; s=socket.socket(socket.AF_INET6); s.bind(('::1', 0))" 2>/dev/null; then
    restart "$CAPBIN" --fast-lo
    attached
    v6_call lo6 "::1" "[::1]"
    if grep -q "ok=true same=true acked=[01]$" <<<"$R"; then pass
    else fail "all: ::1" "a runtime's HTTP call to a local service on ::1 is on the shortcut, body intact" \
        "got: $R (acked 0..1 is the shortcut)"; fi
    v6_call map "::" "127.0.0.1"
    if grep -q "ok=true same=true acked=[01]$" <<<"$R"; then pass
    else fail "all: v4-mapped" "a dual-stack service reached at 127.0.0.1 stays on the shortcut" \
        "got: $R (acked 0..1 is the shortcut)"; fi
else
    not_asserted "all: ::1" "no IPv6 loopback here"
    not_asserted "all: v4-mapped" "no IPv6 loopback here"
fi

# ─── (g) own: this daemon's runtimes only ───────────────────────────────────
restart "$CAPBIN" --fast-lo own
attached
"$BIN" create cache c -p "$CPORT" -s >/dev/null
wait_port "$CPORT" || true
R=$(python3 "$WORK/cache_probe.py" "$CPORT" 2>&1 || true)
read -r VERDICT ACKED <<<"$R"
if [ "$VERDICT" = ok ] && [ "${ACKED:-0}" -gt 1000 ]; then pass
else fail "own: foreign client" "a client of another process stays on TCP under own" "probe: $R (acked > 1000 is TCP)"; fi

if command -v ss >/dev/null 2>&1; then
    "$BIN" create proxy pf -p "$PXFOREIGN" --backend "127.0.0.1:$EPORT" --protocol tcp -s >/dev/null
    wait_port "$PXFOREIGN" || true
    R=$(timeout 20 python3 "$WORK/backend_probe.py" "$PXFOREIGN" "$EPORT" 2>&1 || echo "hung")
    read -r VERDICT BACKEND PROXY <<<"$R"
    if [ "$VERDICT" = ok ] && [ "${BACKEND:-0}" -gt 1000 ]; then pass
    else fail "own: foreign backend" "under own a proxy's pair to a backend of another process stays on TCP" \
        "probe: $R (backend acked > 1000 is TCP)"; fi
else
    not_asserted "own: foreign backend" "ss not available"
fi

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

# ─── all: a pair in another netns with our tuple must not enter ─────────────
# At the root cgroup the sockops program fires for containers too.  A pair in
# another netns whose ports match a host pair on our cache's port shares our
# tuple space; without the netns guard it enters, bumping the entered counter
# and able to overwrite our socket's map entry.  The guard bakes the daemon's
# netns cookie into the program and rejects any other.
if command -v ss >/dev/null 2>&1 && sudo -n unshare -n true 2>/dev/null; then
    cat >"$WORK/nspair.py" <<'PY'
import socket, sys, time
cp, a = int(sys.argv[1]), int(sys.argv[2])
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind(("127.0.0.1", cp)); l.listen(1)
c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); c.bind(("127.0.0.1", a)); c.connect(("127.0.0.1", cp))
s, _ = l.accept()
print("ready", flush=True)
c.sendall(b"x" * 1000)
time.sleep(1.5)
PY
    cat >"$WORK/hostcli.py" <<'PY'
import socket, sys, time, os
cp, a, ready = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(a))); s.connect(("127.0.0.1", cp))
s.sendall(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nhello\r\n"); assert s.recv(100).startswith(b"+OK")
while not os.path.exists(ready): time.sleep(0.05)
s.settimeout(3); s.sendall(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")
try: print("host", "ok" if s.recv(100) == b"$5\r\nhello\r\n" else "bad", flush=True)
except socket.timeout: print("host noreply", flush=True)
PY
    restart "$CAPBIN" --fast-lo
    attached
    "$BIN" create cache c -p "$CPORT" -s >/dev/null
    wait_port "$CPORT" || true
    python3 "$WORK/hostcli.py" "$CPORT" "$NSA" "$WORK/nsready" >"$WORK/host.out" 2>&1 & HCPID=$!
    sleep 0.5
    E1=$("$BIN" daemon stats | grep -oE '^fast_lo_entered:[0-9]+' | cut -d: -f2)
    sudo -n timeout 15 unshare -n sh -c "ip link set lo up && exec python3 $WORK/nspair.py $CPORT $NSA" >"$WORK/ns.out" 2>&1 & NSPID=$!
    for _ in $(seq 1 50); do grep -q ready "$WORK/ns.out" 2>/dev/null && break; sleep 0.1; done
    sleep 0.5
    E2=$("$BIN" daemon stats | grep -oE '^fast_lo_entered:[0-9]+' | cut -d: -f2)
    touch "$WORK/nsready"
    wait "$HCPID" 2>/dev/null || true; HCPID=""
    HOST=$(cat "$WORK/host.out" 2>/dev/null)
    if [ "$HOST" = "host ok" ] && [ "${E1:-0}" = "${E2:-1}" ]; then pass
    else fail "netns guard" "a pair in another netns with our tuple must not enter, and the host pair is intact" \
        "host: $HOST  entered before ns: ${E1:-?}  after: ${E2:-?} (must be equal)"; fi
else
    not_asserted "netns guard" "no ss, or no sudo -n unshare -n"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ]
