#!/usr/bin/env bash
# Integration test: an out-of-process proxy worker inherits four descriptors and
# no others.
#
# The daemon forks and execs itself for every proxy created with
#.  Four descriptors are meant to cross that exec — /dev/null
# on stdin, the daemon's stdout and stderr so a worker's log lines land where
# the operator is already looking, and the control socket on fd 3.  Everything
# else the daemon holds was inheritable as well, because SOCK_CLOEXEC was set at
# exactly one socket() call in the tree and the io_uring accepts passed a
# trailing 0 where the flags argument goes.
#
# Read out of a live worker on the broken build:
#
#     fd 5 -> unix .../daemon.sock  SO_ACCEPTCON   the daemon's IPC listener
#     fd 6 -> tcp 0.0.0.0:4CEA      LISTEN         a DIFFERENT runtime's port
#     fd 8 -> unix .../daemon.sock                 an accepted CLI connection
#     fd 9 -> tcp 0.0.0.0:4CEC      LISTEN         19692, its own — legitimate
#
# ─── WHY THE CONSEQUENCES ARE ASSERTED AND NOT JUST THE FD TABLE ────────────
#
# An fd table is a fact about a process; what it costs is two facts about the
# operator, and both are asserted here because either could be fixed on its own
# by a change that left the other in place.
#
#   THE SOCKET.  A worker holding the daemon's IPC listener answers "is a daemon
#   serving this socket" in the affirmative.  That question is asked by inode in
#   lib_daemon.sh's daemon_pids, which c1875e3 rewrote precisely so that a
#   renamed binary copy could not make it say no; this made it say yes with no
#   daemon in existence, which is the same false report arriving by the other
#   door.  Measured on the broken build with both processes up, daemon_pids
#   returned two pids for one serving process.
#
#   THE PORT.  A worker holding another runtime's listening socket keeps that
#   port bound after the runtime is gone.  On the ordinary stop path this is
#   invisible: teardown() calls shutdown() on the listener, which unhashes the
#   socket for every duplicate of it at once.  A daemon that is killed rather
#   than stopped never reaches that line — and then the port is held by a
#   process with no runtime and no daemon to account for it, and the next
#   `create` on it fails with an address in use that nothing on the machine
#   explains.
#
# ─── AND WHY THE WORKER IS MADE TO SERVE ────────────────────────────────────
#
# The opposite mistake is the expensive one.  SOCK_CLOEXEC on something the
# worker genuinely needs would break the split silently — the daemon would fork,
# the child would exec, and the runtime would be gone with the fd table looking
# tidier than ever.  So the last assertion is an end-to-end request through the
# worker to a backend, after the change: the worker's own listener is not
# inherited, it is opened after the exec from the port in its config frame, and
# that claim is worth nothing unless something has gone through it.
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
    # `|| true` on both, like every other line in this function.
    #
    # It was not needed while the worker was guaranteed to still be there: the
    # test SIGSTOPped it precisely so that it would outlive its daemon, so both
    # kills found a live process and returned 0.  A worker cannot outlive its
    # daemon any more, so both now fail -- and under `set -euo pipefail` a
    # failing command in an EXIT trap replaces the script's exit status.
    #
    # The symptom was a test that printed "12/12 passed, 0 failed" and exited 1,
    # which the runner counts as a failure and the report denies.  Worth the
    # comment because that shape is invisible from the log: every assertion the
    # file makes was green.
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

# The unrelated runtime, started FIRST so that its listener is already open in
# the daemon when the worker is forked.  That ordering is the whole point: a
# listener opened after the fork could not be inherited however the flags are
# set, so a test that creates it second would pass on the broken build.
create_ok "unrelated server created" "$BIN" create server "$SRV_NAME" -p "$SRV_PORT" -s
ready_tcp 127.0.0.1 "$SRV_PORT" 15 || fail "setup" "the unrelated server never listened"

create_ok "out-of-process proxy created" \
    "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" --backend "127.0.0.1:$BE_PORT" \
    --protocol http -s

# The worker, found by executable identity rather than by name: agents copy the
# binary into their worktrees under other names, and lib_daemon.sh documents at
# length why nothing here may match on one.  `proxy-worker` in the command line
# is the daemon's own argv for the child, not a user-typed string, so matching
# it cannot hit a shell.
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
#
# Classified from /proc/net rather than from the number, because the numbers
# move: with the leak closed the worker's own listener is fd 6, and on the
# broken build fd 6 was another runtime's.  What is asserted is what each
# descriptor IS.
#
# The daemon's socket path and the two ports are all known here, so each of the
# three leaks has its own assertion and a failure says which one came back.
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

# (b) an accepted connection on the daemon's IPC socket — same path, no
#     SO_ACCEPTCON.  This is one CLI process's private channel to the daemon.
if printf '%s\n' "$FDS" | awk -v s="$DSOCK" '$2=="unix" && $3==s && $4!="00010000"{f=1}
                                             END{exit !f}'; then
    fail "an accepted CLI connection does not cross the exec" \
         "the worker holds a non-listening socket on $DSOCK"
else
    pass
fi

# (c) any LISTEN socket that is not the worker's own port.  Stated this way
#     rather than as "not $SRV_PORT" so that a fourth listener nobody thought
#     of is caught by the same line.
STRAY=$(printf '%s\n' "$FDS" \
        | awk -v px=":$PX_HEX" '$2=="tcp" && $4=="0A" && $3 !~ px" *$" {print $1" -> "$3}')
if [ -n "$STRAY" ]; then
    fail "no listening socket but its own crosses the exec" \
         "the worker holds: $(printf '%s' "$STRAY" | tr '\n' ' ')" \
         "port $SRV_PORT belongs to $SRV_NAME, which this process knows nothing about"
else
    pass
fi

# (d) and the positive half of (c): its own listener IS there.  Without this,
#     (c) passes on a worker that never bound anything at all — an identity
#     assertion that a no-op satisfies.
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
#
# It used to freeze the worker with SIGSTOP so that it OUTLIVED the kill -9 on
# its daemon, and then read the two consequences off the survivor: a survivor
# holding the daemon's listener is one that answers "yes, a daemon is here", and
# a survivor holding an unrelated runtime's port is one that keeps that port
# bound.  The setup guard below insisted the survivor existed, and said so
# plainly: without it "nothing below discriminates".
#
# A worker cannot outlive its daemon any more.  It asks the kernel for
# PR_SET_PDEATHSIG(SIGKILL) before it does anything else, precisely because
# SO_REUSEPORT lets a survivor go on serving its share of a port from a build
# nobody believes is running — see the note above claim_current_daemon() in
# proxy_worker.cpp.  SIGKILL and not SIGTERM for the reason this test's own
# SIGSTOP demonstrates: a stopped process runs no handler.
#
# So the survivor is gone, and with it the discriminating power of (e) and (f).
# That is not a loss of coverage, because it is not where the coverage was: the
# fd table in section 1 asserts each of the three leaks DIRECTLY, on a live
# worker, by what each descriptor is — and those assertions are untouched and
# still fail on a broken build.  (e) and (f) were always the consequences of
# what (a)-(d) measure.
#
# What replaces the old setup guard is the assertion that the new guarantee
# holds, which is the one thing here that a regression could now break: freeze
# the worker, kill the daemon, and require the worker to be gone anyway.
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

# A frozen worker cannot act on the EOF its control socket just got, so nothing
# it could DO would end it.  Only the kernel can, and this asserts that it did.
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

# (e) no daemon exists, so nothing may claim to be serving its socket.
#
# Weaker than it was, and deliberately kept: with the worker killed alongside
# its daemon this can no longer fail by the route it was written for, and (a)
# above is what catches that leak now.  It still answers a question worth
# asking — that a killed daemon leaves nothing behind claiming to serve its
# socket — and it costs one connect().
if daemon_alive "$DSOCK"; then
    fail "nothing is left claiming to serve the dead daemon's socket" \
         "daemon_alive says a daemon is serving $DSOCK after kill -9 on $DPID" \
         "this is the false report c1875e3 removed, arriving by a second route"
else
    pass
fi

# (f) the unrelated runtime's port comes back.  The daemon was killed, so
#     nothing ran teardown()'s shutdown() — a leaked duplicate is the only thing
#     that can still be holding this.  Same caveat as (e): (c)/(d) above are
#     what discriminate now, and this is the consequence they imply.
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
