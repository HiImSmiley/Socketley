#!/usr/bin/env bash
# suite: quiet -- fails under a parallel group run and passes alone, most
# likely inspecting the fd table before the worker has bound. A proxy worker
# inherits exactly four descriptors and no others, because SOCK_CLOEXEC was set
# at one socket() call in the tree and the io_uring accepts passed a trailing 0
# where the flags go -- with the two consequences asserted as well as the
# table, since either could be fixed alone: a worker holding the daemon's IPC
# listener makes daemon_pids answer yes with no daemon in existence, and a
# worker holding another runtime's listening socket keeps that port bound after
# a daemon that was killed never reached teardown's shutdown.
# ─── AND WHY THE WORKER IS MADE TO SERVE ────────────────────────────────────
# The opposite mistake is the expensive one, so the last assertion is an
# end-to-end request through the worker: its own listener is opened after the
# exec from the port in its config frame, and that claim is worth nothing
# unless something has gone through it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate wfd

BE_PORT=$((SL_PORT_BASE+694))       # a plain backend, so the worker has something to answer with
SRV_PORT=$((SL_PORT_BASE+690))      # an unrelated server runtime — the port that must not leak
PX_PORT=$((SL_PORT_BASE+692))       # the worker's own port
SRV_NAME=wfd_srv
PX_NAME=wfd_px
PASS=0; FAIL=0; TOTAL=0
BEPID=""
WPID=""

cleanup() {
    # `|| true` on both, because a worker can no longer outlive its daemon and
    # under pipefail a failing command in an EXIT trap replaces the script's
    # exit status -- printing 12/12 passed and exiting 1, which is invisible
    # from the log.
    [ -n "$WPID" ] && kill -CONT "$WPID" 2>/dev/null || true
    [ -n "$WPID" ] && kill -9 "$WPID" 2>/dev/null || true
    for n in "$PX_NAME" "$SRV_NAME"; do
        "$BIN" stop "$n" 2>/dev/null || true
        "$BIN" remove "$n" 2>/dev/null || true
    done
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    [ -n "${TMPD:-}" ] && rm -rf "$TMPD"
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    [ -n "${3:-}" ] && echo "        $3"
    return 0
}

echo "=== Integration: an out-of-process worker inherits nothing it was not given ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

TMPD=$(mktemp -d)

cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(64)
def serve(c):
    try:
        c.settimeout(10)
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = c.recv(4096)
            if not chunk: return
            req += chunk
        body = b"worker-served"
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                  str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    try: conn, _ = srv.accept()
    except Exception: break
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY

python3 "$TMPD/be.py" "$BE_PORT" >/dev/null 2>&1 &
BEPID=$!
ready_tcp 127.0.0.1 "$BE_PORT" 15 || { echo "  SKIP: backend did not start"; exit 0; }

daemon_start "$BIN"
DPID=$SOCKETLEY_DPID

# The unrelated runtime is started first so its listener is already open in the
# daemon when the worker is forked, since a listener opened after the fork
# could not be inherited however the flags are set.
create_ok "unrelated server created" "$BIN" create server "$SRV_NAME" -p "$SRV_PORT" -s
ready_tcp 127.0.0.1 "$SRV_PORT" 15 || fail "setup" "the unrelated server never listened"

create_ok "out-of-process proxy created" \
    "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" --backend "127.0.0.1:$BE_PORT" \
    --protocol http -s

# Found by executable identity rather than by name, because agents copy the
# binary into their worktrees, and `proxy-worker` is the daemon's own argv for
# the child rather than a user-typed string, so matching it cannot hit a shell.
find_worker() {
    local d p r=""
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "$p" = "$DPID" ] && continue
        [ "/proc/$p/exe" -ef "$BIN" ] || continue
        { tr '\0' '\n' < "/proc/$p/cmdline"; } 2>/dev/null \
            | grep -x 'proxy-worker' >/dev/null || continue
        r=$p
    done
    printf '%s' "$r"
}
for _ in $(seq 1 60); do WPID=$(find_worker); [ -n "$WPID" ] && break; sleep 0.25; done

TOTAL=$((TOTAL+1))
if [ -n "$WPID" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [worker forked]: no proxy-worker process for $PX_NAME"
    echo "        nothing below is measuring anything; the rest is skipped"
    echo "  --- $PASS/$TOTAL passed, $FAIL failed ---"
    exit 1
fi

# An http proxy routes on a "/<name>/" prefix and 404s anything else, so both
# the readiness probe and the request below carry it.
ready_http 127.0.0.1 "$PX_PORT" "/$PX_NAME/ready" 20 || true

# ── 1. THE FD TABLE ─────────────────────────────────────────────────────────
# Classified from /proc/net rather than from the number, because the numbers
# move and what is asserted is what each descriptor is -- one assertion per
# leak, so a failure says which one came back.
DSOCK=$SOCKETLEY_SOCKET
hex_port() { printf '%04X' "$1"; }
SRV_HEX=$(hex_port "$SRV_PORT")
PX_HEX=$(hex_port "$PX_PORT")

# What the worker holds, one line per descriptor, already classified.
classify() {
    local f n t ino
    for f in /proc/"$WPID"/fd/*; do
        n=${f##*/}
        t=$({ readlink "$f"; } 2>/dev/null) || continue
        [ -n "$t" ] || continue
        case "$t" in
            socket:*)
                ino=${t#socket:[}; ino=${ino%]}
                # A TCP row first; a UNIX row if it is not TCP.
                awk -v i="$ino" -v n="$n" 'NR>1 && $10==i {print n" tcp "$2" "$4; f=1}
                                           END{if(!f) print ""}' /proc/net/tcp \
                    | grep -v '^$' && continue
                awk -v i="$ino" -v n="$n" '$7==i {print n" unix "$8" "$4}' /proc/net/unix
                ;;
            *) echo "$n other $t" ;;
        esac
    done
}
FDS=$(classify)
echo "  worker $WPID fd table:"
printf '%s\n' "$FDS" | sed 's/^/    /'

# (a) the daemon's IPC listener — a UNIX socket on the daemon's path with
#     SO_ACCEPTCON (00010000) set.
if printf '%s\n' "$FDS" | awk -v s="$DSOCK" '$2=="unix" && $3==s && $4=="00010000"{f=1}
                                             END{exit !f}'; then
    fail "the daemon's IPC listener does not cross the exec" \
         "the worker holds an SO_ACCEPTCON socket on $DSOCK" \
         "daemon_alive() will report a live daemon for as long as this worker lives"
else
    pass
fi

# An accepted connection on the daemon's IPC socket -- same path, no
# SO_ACCEPTCON -- which is one CLI process's private channel.
if printf '%s\n' "$FDS" | awk -v s="$DSOCK" '$2=="unix" && $3==s && $4!="00010000"{f=1}
                                             END{exit !f}'; then
    fail "an accepted CLI connection does not cross the exec" \
         "the worker holds a non-listening socket on $DSOCK"
else
    pass
fi

# Any LISTEN socket that is not the worker's own port, stated this way so a
# fourth listener nobody thought of is caught by the same line.
STRAY=$(printf '%s\n' "$FDS" \
        | awk -v px=":$PX_HEX" '$2=="tcp" && $4=="0A" && $3 !~ px" *$" {print $1" -> "$3}')
if [ -n "$STRAY" ]; then
    fail "no listening socket but its own crosses the exec" \
         "the worker holds: $(printf '%s' "$STRAY" | tr '\n' ' ')" \
         "port $SRV_PORT belongs to $SRV_NAME, which this process knows nothing about"
else
    pass
fi

# The positive half, without which the assertion above passes on a worker that
# never bound anything at all.
if printf '%s\n' "$FDS" | awk -v px=":$PX_HEX" '$2=="tcp" && $4=="0A" && $3 ~ px" *$"{f=1}
                                                END{exit !f}'; then
    pass
else
    fail "the worker has its own listener" \
         "no LISTEN socket on $PX_PORT in the worker's fd table" \
         "the three assertions above are satisfied by a worker that bound nothing"
fi

# ── 2. THE WORKER STILL SERVES ──────────────────────────────────────────────
#
# Before the destructive half below, because that half stops the daemon.
BODY=$(python3 - "$PX_PORT" "/$PX_NAME/" <<'PY'
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 10); s.settimeout(10)
    s.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
               % sys.argv[2]).encode())
    d = b""
    while True:
        c = s.recv(4096)
        if not c: break
        d += c
    sys.stdout.write(d.split(b"\r\n\r\n", 1)[1].decode() if b"\r\n\r\n" in d else "<no body>")
except Exception as e:
    sys.stdout.write("<error: %s>" % e)
PY
)
if [ "$BODY" = "worker-served" ]; then
    pass
else
    fail "the worker proxies a request end to end" \
         "got '$BODY', wanted 'worker-served'" \
         "SOCK_CLOEXEC has been set on something the worker needed"
fi

# ── 3. THE TWO CONSEQUENCES ─────────────────────────────────────────────────
#
# ─── WHY THIS SECTION CHANGED SHAPE ─────────────────────────────────────────
# A worker cannot outlive its daemon any more -- it asks for
# PR_SET_PDEATHSIG(SIGKILL) first thing, because SO_REUSEPORT lets a survivor
# go on serving from a build nobody believes is running -- so what stood here
# is replaced by the assertion that the new guarantee holds: freeze the worker,
# kill the daemon, and require the worker to be gone anyway.
kill -STOP "$WPID" 2>/dev/null || true
kill -9 "$DPID" 2>/dev/null || true
SOCKETLEY_DPID=""
for _ in $(seq 1 40); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done

TOTAL=$((TOTAL+1))
if kill -0 "$DPID" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the daemon survived kill -9; the two assertions below are void"
else
    PASS=$((PASS+1))
fi

# A frozen worker cannot act on the EOF its control socket just got, so only
# the kernel can end it and this asserts that it did.
for _ in $(seq 1 60); do kill -0 "$WPID" 2>/dev/null || break; sleep 0.25; done
TOTAL=$((TOTAL+1))
if kill -0 "$WPID" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL: a SIGSTOPped worker outlived its daemon (pid $WPID)"
    echo "        PR_SET_PDEATHSIG is not set, or is set to a signal a stopped"
    echo "        process can ignore; it is holding $PX_PORT for as long as it lives"
else
    PASS=$((PASS+1))
fi

# Weaker than it was and deliberately kept: it can no longer fail by the route
# it was written for, but a killed daemon leaving nothing behind claiming to
# serve its socket is still worth asking and costs one connect.
if daemon_alive "$DSOCK"; then
    fail "nothing is left claiming to serve the dead daemon's socket" \
         "daemon_alive says a daemon is serving $DSOCK after kill -9 on $DPID" \
         "this is the false report 81dcf4a removed, arriving by a second route"
else
    pass
fi

# The unrelated runtime's port comes back, and since the daemon was killed a
# leaked duplicate is the only thing that could still be holding it.
BINDMSG=$(python3 - "$SRV_PORT" <<'PY'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(1); sys.stdout.write("free")
except OSError as e:
    sys.stdout.write(e.strerror or "bind failed")
PY
)
if [ "$BINDMSG" = "free" ]; then
    pass
else
    fail "a stopped runtime's port is not held by an unrelated worker" \
         "binding $SRV_PORT said '$BINDMSG'" \
         "$SRV_NAME is gone with its daemon; something is still holding its port"
fi

kill -CONT "$WPID" 2>/dev/null || true

echo "  --- $PASS/$TOTAL passed, $FAIL failed ---"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
