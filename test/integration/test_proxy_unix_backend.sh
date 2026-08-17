#!/usr/bin/env bash
# Integration test: --backend unix:/path/to.sock
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A sidecar proxy and the process it fronts are on one host, and until this flag
# existed the only way to join them was loopback TCP — a full stack, sequence
# numbers, checksums and windows, for a connection that never sees a wire.
# Measured as a strict 64-byte ping-pong between two processes, unpinned:
# TCP 17.93us against UNIX 9.83us.
#
# ─── WHAT THESE ASSERTIONS ARE FOR ──────────────────────────────────────────
#
# Every payload check here compares against the OTHER address family rather than
# against a status.  A proxy that answered "200" with an empty body, or that
# forwarded the first read and dropped the rest, passes a status check and fails
# this one — and the TCP arm is the control, so a bug that breaks both arms
# equally is visible as both of them differing from the payload that was sent.
#
# The negatives are the other half, and they are the reason the flag is not just
# a memcpy into a sockaddr_un.  sun_path is 108 bytes and the kernel truncates
# silently: a 120-byte path would bind to whatever its first 107 bytes reach,
# which can be a real socket belonging to somebody else.  So the truncation
# assertion does not merely check for a refusal, it puts a listening socket at
# exactly the truncation point and proves nothing ever reached it.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
# lib_ports.sh opens its lock with `exec 9>`; an exec with no command applies
# its redirections to this shell for good, so stderr is restored here rather
# than trusted.  Debugging this file blind cost an hour once already.
exec 2>&1
daemon_isolate unixbe
PASS=0; FAIL=0; TOTAL=0

BE_PIDS=()
cleanup() {
    local p
    for p in "${BE_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: proxy over a unix-socket backend ==="

HELPER="$HERE/lib_unix_backend.py"
if [ ! -f "$HELPER" ]; then
    echo "  SKIP: $HELPER not present"
    exit 0
fi

daemon_start "$BIN"

P=$((SL_PORT_BASE + 1400))
D="$SOCKETLEY_TMPD"

# start_backend KIND ADDR PROTO COUNTFILE
#
# Waits for the helper's "ready" line rather than sleeping: a race here would
# make a real failure and a slow machine indistinguishable.
start_backend() {
    local kind=$1 addr=$2 proto=$3 countf=$4 fifo
    fifo="$D/ready-$(basename "$countf")"
    rm -f "$fifo"; mkfifo "$fifo"
    python3 "$HELPER" "$kind" "$addr" "$proto" "$countf" >"$fifo" 2>>"$D/backend.err" &
    BE_PIDS+=("$!")
    local line=""
    read -r -t 10 line <"$fifo" || true
    rm -f "$fifo"
    [ "$line" = "ready" ]
}

# ─── The backends: one per family per protocol, same program ────────────────
ECHO_SOCK="$D/echo.sock"
HTTP_SOCK="$D/http.sock"
ECHO_PORT=$((P + 1))
HTTP_PORT=$((P + 2))

if start_backend unix "$ECHO_SOCK" echo "$D/c-echo-unix" &&
   start_backend tcp  "$ECHO_PORT" echo "$D/c-echo-tcp" &&
   start_backend unix "$HTTP_SOCK" http "$D/c-http-unix" &&
   start_backend tcp  "$HTTP_PORT" http "$D/c-http-tcp"; then pass
else
    fail "the four backends came up" "one of them never reported ready"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    echo "  FAILED"
    exit 1
fi

"$BIN" create proxy ub_tcp_unix  -p $((P + 10)) --backend "unix:$ECHO_SOCK"      --protocol tcp -s >/dev/null 2>&1 || true
"$BIN" create proxy ub_tcp_inet  -p $((P + 11)) --backend "127.0.0.1:$ECHO_PORT" --protocol tcp -s >/dev/null 2>&1 || true
"$BIN" create proxy ub_http_unix -p $((P + 12)) --backend "unix:$HTTP_SOCK"      -s >/dev/null 2>&1 || true
"$BIN" create proxy ub_http_inet -p $((P + 13)) --backend "127.0.0.1:$HTTP_PORT" -s >/dev/null 2>&1 || true
sleep 1

# ─── 1. TCP mode: the bytes back are the bytes sent, both families ──────────
#
# 8 KiB, which is more than one read buffer's worth of anything on the path, so
# a proxy that forwards the first completion and loses the rest fails here.  The
# payload is deterministic rather than random: a failure has to be reproducible
# from the file that reported it.
relay_probe() {
    local port=$1
    timeout 15 python3 -c "
import socket, sys
payload = bytes(range(256)) * 32          # 8192 bytes
s = socket.create_connection(('127.0.0.1', $port), timeout=10)
s.settimeout(10)
s.sendall(payload)
got = b''
while len(got) < len(payload):
    chunk = s.recv(65536)
    if not chunk: break
    got += chunk
s.close()
sys.stdout.write('%d:%s' % (len(got), 'same' if got == payload else 'differs'))
" 2>/dev/null || echo "0:error"
}

UNIX_RELAY=$(relay_probe $((P + 10)))
INET_RELAY=$(relay_probe $((P + 11)))

if [ "$UNIX_RELAY" = "8192:same" ]; then pass
else fail "tcp mode over a unix backend returns the payload unchanged" \
          "got '$UNIX_RELAY', expected '8192:same'"; fi

# The control.  Without it a build where both families are broken the same way
# would leave only a one-armed failure to read, and the natural conclusion —
# "the unix path is wrong" — would be the wrong one.
if [ "$INET_RELAY" = "8192:same" ]; then pass
else fail "the tcp-backend control returns the payload unchanged" \
          "got '$INET_RELAY' — both arms are affected, so this is not about the address family"; fi

# ─── 2. HTTP mode: same body over both families ─────────────────────────────
http_probe() {
    local port=$1 name=$2 n=$3
    timeout 20 python3 -c "
import socket, sys
s = socket.create_connection(('127.0.0.1', $port), timeout=10)
s.settimeout(10)
bodies = []
buf = b''
for i in range($n):
    s.sendall(b'GET /$name/ HTTP/1.1\r\nHost: probe\r\nConnection: keep-alive\r\n\r\n')
    while b'\r\n\r\n' not in buf:
        chunk = s.recv(65536)
        if not chunk: break
        buf += chunk
    if b'\r\n\r\n' not in buf:
        break
    head, buf = buf.split(b'\r\n\r\n', 1)
    n_body = 0
    for line in head.split(b'\r\n'):
        if line.lower().startswith(b'content-length:'):
            n_body = int(line.split(b':', 1)[1])
    while len(buf) < n_body:
        chunk = s.recv(65536)
        if not chunk: break
        buf += chunk
    bodies.append(buf[:n_body].decode('latin1'))
    buf = buf[n_body:]
s.close()
sys.stdout.write(('|'.join(bodies)) if bodies else 'NOTHING')
" 2>/dev/null || echo "ERROR"
}

UNIX_BODY=$(http_probe $((P + 12)) ub_http_unix 1)
INET_BODY=$(http_probe $((P + 13)) ub_http_inet 1)

if [ "$UNIX_BODY" = "unix-backend-body" ]; then pass
else fail "http over a unix backend returns the backend's body" \
          "got '${UNIX_BODY:-<nothing>}', expected 'unix-backend-body'"; fi

if [ "$UNIX_BODY" = "$INET_BODY" ]; then pass
else fail "the two families return the same body" \
          "unix said '${UNIX_BODY:-<nothing>}', tcp said '${INET_BODY:-<nothing>}'"; fi

# ─── 3. The connection pool files a unix backend too ────────────────────────
#
# The pool keys on (host, port), and a unix backend has no port.  Left at the
# old rule, every request through one paid for a fresh connect — most of what
# this address family was adopted to save.  A body check cannot see that: both
# answer correctly.  The accept counter can.
POOL_N=10
UNIX_BODIES=$(http_probe $((P + 12)) ub_http_unix "$POOL_N")
INET_BODIES=$(http_probe $((P + 13)) ub_http_inet "$POOL_N")
sleep 0.4
UNIX_ACC=$(cat "$D/c-http-unix" 2>/dev/null || echo "?")
INET_ACC=$(cat "$D/c-http-tcp" 2>/dev/null || echo "?")

# One earlier request each, from assertion 2, so a perfect pool is 2 accepts.
EXPECT_BODIES=$(python3 -c "print('|'.join(['unix-backend-body'] * $POOL_N))")
if [ "$UNIX_BODIES" = "$EXPECT_BODIES" ]; then pass
else fail "$POOL_N keep-alive requests over a unix backend all answer" \
          "got '${UNIX_BODIES:0:120}...'"; fi

if [ "$UNIX_ACC" -le 3 ] 2>/dev/null; then pass
else fail "a unix backend's sockets are pooled" \
          "the backend accepted $UNIX_ACC connections for $((POOL_N + 1)) requests" \
          "the tcp-backend control accepted $INET_ACC for the same load" \
          "an unpooled unix backend accepts one per request"; fi

# The control again: if the TCP arm also failed to pool, the pool is broken for
# everyone and this test should not be read as being about unix sockets.
if [ "$INET_ACC" -le 3 ] 2>/dev/null; then pass
else fail "the tcp-backend control is pooled" \
          "accepted $INET_ACC connections for $((POOL_N + 1)) requests — the pool is broken for both families"; fi

# ─── 4. A path that is not there, and a stale node left by a previous run ───
#
# Both are the backend's answer rather than ours, so both must reach the client
# as 502 — the same thing a dead TCP backend gets — rather than a hang or a
# closed connection with nothing in it.
STALE="$D/stale.sock"
python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('$STALE'); s.listen(1); s.close()"   # node left behind, nobody listening

"$BIN" create proxy ub_missing -p $((P + 20)) --backend "unix:$D/not-there.sock" -s >/dev/null 2>&1 || true
"$BIN" create proxy ub_stale   -p $((P + 21)) --backend "unix:$STALE"            -s >/dev/null 2>&1 || true
"$BIN" create proxy ub_deadtcp -p $((P + 22)) --backend "127.0.0.1:$((P + 900))" -s >/dev/null 2>&1 || true
sleep 0.8

status_probe() {
    timeout 15 python3 -c "
import socket, sys
try:
    s = socket.create_connection(('127.0.0.1', $1), timeout=10)
    s.settimeout(10)
    s.sendall(b'GET /$2/ HTTP/1.1\r\nHost: probe\r\n\r\n')
    d = s.recv(4096)
    s.close()
    sys.stdout.write(d.split(b'\r\n')[0].decode('latin1') if d else 'NOTHING')
except Exception as e:
    sys.stdout.write('EXC:%s' % type(e).__name__)
" 2>/dev/null || echo "TIMEOUT"
}

MISSING=$(status_probe $((P + 20)) ub_missing)
STALE_ST=$(status_probe $((P + 21)) ub_stale)
DEADTCP=$(status_probe $((P + 22)) ub_deadtcp)

if [[ "$MISSING" == *"502"* ]]; then pass
else fail "a unix path that does not exist answers 502" "got '${MISSING:-<nothing>}'"; fi

if [[ "$STALE_ST" == *"502"* ]]; then pass
else fail "a stale socket node answers 502" \
          "got '${STALE_ST:-<nothing>}' — a node with nobody behind it refuses the connect"; fi

if [ "$MISSING" = "$DEADTCP" ]; then pass
else fail "an unreachable unix backend answers as an unreachable tcp one does" \
          "unix said '$MISSING', tcp said '$DEADTCP'"; fi

# ─── 5. Truncation is refused, and the truncated path is never touched ──────
#
# sun_path holds 107 bytes and a terminator, and the kernel truncates without
# saying so.  The socket below sits at exactly the truncation point of the path
# configured after it, so a build that trimmed instead of refusing would connect
# to it — and its accept counter is what says whether that happened.  A refusal
# alone would not: a proxy that failed to start for some unrelated reason also
# never connects.
TRUNC="$D/$(python3 -c "print('t' * (107 - len('$D') - 1))")"
LONGP="${TRUNC}xxxxxxxxxxxxx"
if [ "${#TRUNC}" -eq 107 ] && [ "${#LONGP}" -eq 120 ]; then pass
else fail "the truncation fixture is the length it claims" \
          "the decoy is ${#TRUNC} bytes and the configured path ${#LONGP}; the test below proves nothing"; fi

if start_backend unix "$TRUNC" echo "$D/c-trunc"; then pass
else fail "a backend listens at the truncation point" "it never reported ready"; fi

set +e
"$BIN" create proxy ub_toolong -p $((P + 23)) --backend "unix:$LONGP" --protocol tcp -s >/dev/null 2>&1
LONG_RC=$?
set -e
if [ "$LONG_RC" -ne 0 ]; then pass
else fail "a path longer than sun_path is refused" \
          "create -s exited 0 — the proxy came up on an address the kernel would trim"; fi

if grep -q "would be truncated to a different socket" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
else fail "the refusal says why" \
          "nothing in the daemon log names the truncation"; fi

# Give a build that did trim time to have connected.
sleep 0.5
TRUNC_ACC=$(cat "$D/c-trunc" 2>/dev/null || echo "?")
if [ "$TRUNC_ACC" = "0" ]; then pass
else fail "nothing connected to the truncated path" \
          "the decoy socket accepted $TRUNC_ACC connections" \
          "a trimmed path reaches a different socket, and this is what that looks like"; fi

# ─── 6. The other refusals, each at configuration time ──────────────────────
refuse_case() {
    local name=$1 port=$2 needle=$3; shift 3
    local before after
    before=$(wc -c <"$SOCKETLEY_DLOG")
    set +e
    "$BIN" create proxy "$name" -p "$port" "$@" -s >/dev/null 2>&1
    local rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        fail "$name is refused" "create -s exited 0"
        return
    fi
    after=$(tail -c "+$((before + 1))" "$SOCKETLEY_DLOG")
    if grep -qF "$needle" <<<"$after"; then pass
    else fail "$name is refused for the stated reason" \
              "exited $rc, but the log does not say \"$needle\"" \
              "${after:0:200}"; fi
}

refuse_case ub_relative $((P + 30)) "must be absolute"          --backend "unix:relative.sock" --protocol tcp
refuse_case ub_empty    $((P + 31)) "no socket path"            --backend "unix:"             --protocol tcp
refuse_case ub_tls      $((P + 32)) "no TLS to a unix socket"   --backend "unix:$ECHO_SOCK" \
                                                                --ca /etc/ssl/certs/ca-certificates.crt --protocol tcp

# And the refusals leave the runtime unable to serve rather than half-up.
BAD_STATUS=$("$BIN" ls 2>/dev/null | awk '$2 == "ub_relative" { print $7 }')
if [ "$BAD_STATUS" = "Failed" ]; then pass
else fail "a refused proxy is not left running" "ls reports '${BAD_STATUS:-<nothing>}'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
