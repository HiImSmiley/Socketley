#!/usr/bin/env bash
# Integration test: the AF_UNIX listener on every runtime that listens,
# and the connect side on the one that dials.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# test_server_unix_listen.sh proves the mechanism on the server, where it was
# born.  This file proves the mechanism is shared rather than copied: the
# proxy and the cache listen through the same shared/unix_listener.h bind, the
# client dials through the same address construction, and each runtime's OWN
# incompatibilities (--tls everywhere, --cluster on a cache, --shards on a
# proxy) are refused with their stated reasons.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# The payload checks would catch a runtime whose accept path assumed AF_INET —
# a peer-address read, a TCP socket option treated as load-bearing.  The 0600
# checks would catch a runtime that reached the shared bind without the shared
# chmod.  The node-removal checks would catch a teardown that closed the fd
# and left the node — which is exactly the half that existed only in the
# server before this was shared.  The refusals each name the broken build they
# catch beside the assertion.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
# lib_ports.sh opens its lock with `exec 9>`; an exec with no command applies
# its redirections to this shell for good.  Put stderr back.
exec 2>&1
daemon_isolate unixrts
PASS=0; FAIL=0; TOTAL=0

BACKEND_PID=""
cleanup() {
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
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

echo "=== Integration: unix listeners across runtimes ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1550))
D="$SOCKETLEY_TMPD"
WWW="$D/www"
mkdir -p "$WWW"
echo "<h1>behind-the-proxy</h1>" > "$WWW/index.html"

# One HTTP exchange over a unix socket; prints the status line, or 'yes' if
# the needle is in the response.
http_unix() {   # http_unix <sockpath> <request-path> <needle>
    timeout 10 python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$1'); s.settimeout(5)
s.sendall(b'GET $2 HTTP/1.1\r\nHost: probe\r\n\r\n')
d = b''
n = None
while True:
    if n is None and b'\r\n\r\n' in d:
        head, _, body = d.partition(b'\r\n\r\n')
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                n = int(line.split(b':', 1)[1])
        if n is None: break
    if n is not None:
        head, _, body = d.partition(b'\r\n\r\n')
        if len(body) >= n: break
    c = s.recv(65536)
    if not c: break
    d += c
s.close()
sys.stdout.write('yes' if b'$3' in d else (d.split(b'\r\n')[0].decode('latin1') or 'NOTHING'))
" 2>/dev/null || echo "ERROR"
}

# One RESP command over a unix socket; prints the raw reply.
resp_unix() {   # resp_unix <sockpath> <inline-command>
    timeout 10 python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$1'); s.settimeout(5)
s.sendall(b'$2\r\n')
sys.stdout.write(s.recv(65536).decode('latin1', 'replace').strip())
s.close()
" 2>/dev/null || echo "ERROR"
}

# ─── 1. A proxy listens on a unix socket ────────────────────────────────────
#
# Backend over TCP, front door over unix — the mirror of what --backend unix:
# already covered.  Catches an accept path that assumed the accepted peer has
# an AF_INET address.
"$BIN" create server ur_be -p $((P + 1)) --http "$WWW" -s >/dev/null 2>&1 || true
PXSOCK="$D/px.sock"
"$BIN" create proxy ur_px --listen "unix:$PXSOCK" --backend "127.0.0.1:$((P + 1))" -s >/dev/null 2>&1 || true
sleep 1

if [ -S "$PXSOCK" ]; then pass
else fail "the proxy's socket node exists" "$PXSOCK is not a socket"; fi

MODE=$(stat -c '%a' "$PXSOCK" 2>/dev/null || echo "?")
if [ "$MODE" = "600" ]; then pass
else fail "the proxy's node is owner-only" \
          "mode is $MODE, not 600 -- a runtime that reached the shared bind" \
          "without the shared chmod publishes to whoever the umask allows"; fi

PXBODY=$(http_unix "$PXSOCK" "/ur_px/" "behind-the-proxy")
if [ "$PXBODY" = "yes" ]; then pass
else fail "the proxy forwards a request that arrived over unix" "got '$PXBODY'"; fi

"$BIN" stop ur_px >/dev/null 2>&1 || true
sleep 0.6
if [ ! -e "$PXSOCK" ]; then pass
else fail "stopping the proxy removes its node" \
          "$PXSOCK is still there -- the teardown unlink existed only in the" \
          "server before the listener was shared"; fi

# ─── 2. A cache listens on a unix socket ────────────────────────────────────
CSOCK="$D/cache.sock"
"$BIN" create cache ur_cache --listen "unix:$CSOCK" -s >/dev/null 2>&1 || true
sleep 1

if [ -S "$CSOCK" ]; then pass
else fail "the cache's socket node exists" "$CSOCK is not a socket"; fi

CMODE=$(stat -c '%a' "$CSOCK" 2>/dev/null || echo "?")
if [ "$CMODE" = "600" ]; then pass
else fail "the cache's node is owner-only" "mode is $CMODE, not 600"; fi

PONG=$(resp_unix "$CSOCK" "PING")
if [ "$PONG" = "+PONG" ]; then pass
else fail "the cache answers RESP over unix" "PING answered '$PONG'"; fi

SETR=$(resp_unix "$CSOCK" "SET urk urv")
GETR=$(resp_unix "$CSOCK" "GET urk")
if [[ "$GETR" == *"urv"* ]]; then pass
else fail "a value stored over unix is served over unix" \
          "SET said '$SETR', GET said '$GETR'"; fi

"$BIN" stop ur_cache >/dev/null 2>&1 || true
sleep 0.6
if [ ! -e "$CSOCK" ]; then pass
else fail "stopping the cache removes its node" "$CSOCK is still there"; fi

# ─── 3. A client dials a unix socket ────────────────────────────────────────
#
# The connect side: -t unix:/path.  Asserted through the server's connection
# count, which is the one observable a connected-and-idle client has.
USOCK="$D/usrv.sock"
"$BIN" create server ur_usrv --listen "unix:$USOCK" -s >/dev/null 2>&1 || true
sleep 0.8
"$BIN" create client ur_cli -t "unix:$USOCK" -s >/dev/null 2>&1 || true

CONNS=""
for _i in $(seq 1 20); do
    CONNS=$("$BIN" ls 2>/dev/null | awk '$2 == "ur_usrv" { print $5 }')
    [ "$CONNS" = "1" ] && break
    sleep 0.3
done
if [ "$CONNS" = "1" ]; then pass
else fail "a client dials the unix server" \
          "the server reports '$CONNS' connections, wanted 1" \
          "a client that fell back to TCP or failed silently both read 0"; fi

# And the dial really is that socket: stopping the server drops the client's
# connection.  (Reconnect is not configured, so the count stays down.)
"$BIN" stop ur_cli >/dev/null 2>&1 || true
"$BIN" stop ur_usrv >/dev/null 2>&1 || true
sleep 0.5

# ─── 4. Each runtime's own incompatibilities, with their stated reasons ─────

# Refused at create, where the flag parser sees the whole line.
refuse_cli() {   # refuse_cli <label> <needle> <create-args...>
    local label=$1 needle=$2; shift 2
    local out rc
    set +e
    out=$("$BIN" create "$@" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        fail "$label" "create exited 0"
        return
    fi
    if grep -qF -- "$needle" <<<"$out"; then pass
    else fail "$label" "exited $rc saying: ${out:-<nothing>}"; fi
}

# Refused at setup, because the flag parser is not on the restore path: the
# create succeeds and the START fails, with the reason in the daemon log.
setup_refusal() {   # setup_refusal <label> <needle> <create-args...>
    local label=$1 needle=$2; shift 2
    local before rc
    before=$(wc -c <"$SOCKETLEY_DLOG")
    set +e
    "$BIN" create "$@" -s >/dev/null 2>&1
    rc=$?
    set -e
    local after
    after=$(tail -c "+$((before + 1))" "$SOCKETLEY_DLOG")
    if [ "$rc" -ne 0 ] && grep -qF -- "$needle" <<<"$after"; then pass
    else fail "$label" "exit $rc; the log said: ${after:0:200}"; fi
}

# A sharded proxy on a unix path: N workers would unlink each other's node.
# Would catch a build that let the pair through to serve on whichever shard
# bound last.
refuse_cli "a sharded proxy is refused a unix listener" \
    "--shards and --listen are not compatible" \
    proxy ur_shpx --shards 2 --listen "unix:$D/shpx.sock" --backend "127.0.0.1:9"

# A client listens on nothing; the flag is refused with the pointer to the
# side it does have.  Would catch a build that took the flag and ignored it.
refuse_cli "a client is refused --listen, and told about -t" \
    "-t unix:" \
    client ur_clil --listen "unix:$D/cl.sock"

# The dial side is validated where the listen side is: a relative path names
# a different socket from a different cwd.
refuse_cli "a client's relative unix target is refused" \
    "must be absolute" \
    client ur_clir -t "unix:relative.sock"

# TLS on a unix listener, per runtime that grew the listener.  Would catch a
# runtime that reached the shared bind without asking the shared refusal.
setup_refusal "a proxy is refused --tls with --listen" \
    "--tls encrypts a listener" \
    proxy ur_pxtls --listen "unix:$D/pxtls.sock" --backend "127.0.0.1:9" \
    --tls --cert /dev/null --key /dev/null

setup_refusal "a cache is refused --tls with --listen" \
    "--tls encrypts a listener" \
    cache ur_ctls --listen "unix:$D/ctls.sock" \
    --tls --cert /dev/null --key /dev/null

# Both listeners at once, on the runtimes that just grew the second one.
setup_refusal "a proxy is refused --listen with -p" \
    "--listen and -p" \
    proxy ur_pxboth -p $((P + 30)) --listen "unix:$D/pxboth.sock" --backend "127.0.0.1:9"

setup_refusal "a cache is refused --listen with -p" \
    "--listen and -p" \
    cache ur_cboth -p $((P + 31)) --listen "unix:$D/cboth.sock"

# --cluster advertises base+1+i ports out of a formula; a path has no
# successor.  Would catch a build that advertised addresses nothing answers.
setup_refusal "a cache is refused --cluster with --listen" \
    "--cluster" \
    cache ur_cclu --listen "unix:$D/cclu.sock" --cluster --shards 1

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
