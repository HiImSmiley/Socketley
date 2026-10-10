#!/usr/bin/env bash
# Integration test: --listen unix:/path/to.sock on a server
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The other half of --backend unix:, so socketley can proxy to socketley
# without a loopback TCP stack between them.  A unix listener is not a port
# with a different spelling: it is a filesystem node, which outlives the
# process that made it, carries permissions, and cannot be reached by anything
# that only knows how to dial an address.  Each of those is an assertion here.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# The payload checks are paired against the same server on a TCP port, so a
# build that breaks both reads as both differing rather than as a unix bug.
# The permission check is not decoration: connecting to a unix socket needs
# write permission on the node, so a build that let the umask decide would
# publish a listener anybody on the machine can talk to under `umask 0` --
# which is the defect this tree already has recorded against its 0644 state
# files.  The stale-node and live-node cases are the two halves of one
# decision, and only asserting one of them would pass on a build that always
# unlinked (stealing a live socket) or never did (never starting twice).

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
# lib_ports.sh opens its lock with `exec 9>`; an exec with no command applies
# its redirections to this shell for good.  Put stderr back.
exec 2>&1
daemon_isolate unixlisten
PASS=0; FAIL=0; TOTAL=0

SQUATTER=""
cleanup() {
    [ -n "$SQUATTER" ] && kill "$SQUATTER" 2>/dev/null || true
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

echo "=== Integration: a server listening on a unix socket ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1450))
D="$SOCKETLEY_TMPD"
SOCK="$D/srv.sock"
WWW="$D/www"
mkdir -p "$WWW"
echo "<h1>over-unix</h1>" > "$WWW/index.html"

# ─── 1. It binds, and the node is the server's alone ────────────────────────
"$BIN" create server ul_srv --listen "unix:$SOCK" --http "$WWW" -s >/dev/null 2>&1 || true
"$BIN" create server ul_tcp -p $((P + 1))        --http "$WWW" -s >/dev/null 2>&1 || true
sleep 1

if [ -S "$SOCK" ]; then pass
else fail "the socket node exists" "$SOCK is not a socket"; fi

MODE=$(stat -c '%a' "$SOCK" 2>/dev/null || echo "?")
if [ "$MODE" = "600" ]; then pass
else fail "the socket node is owner-only" \
          "mode is $MODE, not 600" \
          "connecting to a unix socket needs write permission on the node," \
          "so anything wider is who may talk to this server"; fi

# ─── 2. It serves the same bytes as the same server on a port ───────────────
http_over_unix() {
    timeout 10 python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$1'); s.settimeout(5)
s.sendall(b'GET / HTTP/1.1\r\nHost: probe\r\n\r\n')
d = b''
while b'\r\n\r\n' not in d:
    c = s.recv(65536)
    if not c: break
    d += c
s.close()
head, _, body = d.partition(b'\r\n\r\n')
sys.stdout.write(head.split(b'\r\n')[0].decode('latin1'))
" 2>/dev/null || echo "ERROR"
}
http_over_tcp() {
    timeout 10 python3 -c "
import socket, sys
s = socket.create_connection(('127.0.0.1', $1), timeout=5); s.settimeout(5)
s.sendall(b'GET / HTTP/1.1\r\nHost: probe\r\n\r\n')
d = b''
while b'\r\n\r\n' not in d:
    c = s.recv(65536)
    if not c: break
    d += c
s.close()
sys.stdout.write(d.split(b'\r\n')[0].decode('latin1'))
" 2>/dev/null || echo "ERROR"
}

UNIX_LINE=$(http_over_unix "$SOCK")
TCP_LINE=$(http_over_tcp $((P + 1)))

if [[ "$UNIX_LINE" == *"200 OK"* ]]; then pass
else fail "the unix listener answers" "status line was '${UNIX_LINE:-<nothing>}'"; fi

if [ "$UNIX_LINE" = "$TCP_LINE" ]; then pass
else fail "it answers as the same server on a port does" \
          "unix '${UNIX_LINE:-<nothing>}' vs tcp '${TCP_LINE:-<nothing>}'"; fi

# The whole body, not only the status.  A listener that forwarded the header
# and dropped the rest passes everything above this line.
read_http() {   # read_http <python-connect-expr>
    timeout 10 python3 -c "
import socket, sys
$1
s.settimeout(5)
s.sendall(b'$2')
d = b''
n = None
# Read to the declared Content-Length rather than to EOF: this server answers
# keep-alive, so waiting for EOF would time out on a perfectly good response
# and report it as a failure.
while True:
    if n is None and b'\r\n\r\n' in d:
        head, _, body = d.partition(b'\r\n\r\n')
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                n = int(line.split(b':', 1)[1])
        if n is None: break
        d = head + b'\r\n\r\n' + body
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

BODY_U=$(read_http "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect('$SOCK')" \
                   "GET / HTTP/1.1\r\nHost: probe\r\n\r\n" "over-unix")
if [ "$BODY_U" = "yes" ]; then pass
else fail "the file's contents come back over the unix socket" "got '$BODY_U'"; fi

# ─── 3. A proxy reaches it, by path and by runtime name ─────────────────────
"$BIN" create proxy ul_px_path -p $((P + 10)) --backend "unix:$SOCK" -s >/dev/null 2>&1 || true
"$BIN" create proxy ul_px_name -p $((P + 11)) --backend ul_srv       -s >/dev/null 2>&1 || true
sleep 1

proxied() {
    read_http "s = socket.create_connection(('127.0.0.1', $1), timeout=5)" \
              "GET /$2/ HTTP/1.1\r\nHost: probe\r\n\r\n" "over-unix"
}
BY_PATH=$(proxied $((P + 10)) ul_px_path)
BY_NAME=$(proxied $((P + 11)) ul_px_name)

if [ "$BY_PATH" = "yes" ]; then pass
else fail "a proxy reaches it by unix: path" "got '$BY_PATH'"; fi

# The runtime-name form has to work too, or `--backend <name>` silently means
# "this runtime does not exist" for every server that listens this way.
if [ "$BY_NAME" = "yes" ]; then pass
else fail "a proxy reaches it by runtime name" \
          "got '$BY_NAME' -- the endpoint table publishes a port, and a unix" \
          "server has none, so it has to publish the path instead"; fi

# ─── 4. Stop removes the node ───────────────────────────────────────────────
"$BIN" stop ul_srv >/dev/null 2>&1 || true
sleep 0.6
if [ ! -e "$SOCK" ]; then pass
else fail "stopping removes the socket node" \
          "$SOCK is still there; closing the descriptor does not unlink the path"; fi

# ─── 5. A stale node is taken over; a live one is not ───────────────────────
#
# Two halves of one decision.  A build that always unlinked would pass the
# first and fail the second by stealing a live socket; one that never unlinked
# would pass the second and never start twice.
python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind('$SOCK'); s.listen(1); s.close()"
if [ -S "$SOCK" ]; then pass
else fail "the stale-node fixture is a socket node" "nothing to take over"; fi

"$BIN" start ul_srv >/dev/null 2>&1 || true
sleep 0.8
AFTER_STALE=$(http_over_unix "$SOCK")
if [[ "$AFTER_STALE" == *"200 OK"* ]]; then pass
else fail "a stale node left by a previous run is taken over" \
          "the server did not come back up on it: '${AFTER_STALE:-<nothing>}'"; fi

# Now the live one: a second runtime asking for the same path must be refused,
# and the first must still be serving afterwards.
#
# The requirement is "refused", and it is checked as that rather than as the
# state a particular mechanism happens to leave behind.  It used to read
# `Failed`, because the second runtime forked a worker that discovered the
# collision at the bind and the supervisor marked the placeholder.  The daemon
# now refuses before the fork -- it can see both runtimes and the kernel
# cannot -- so nothing is built and the runtime is left `Created`, which is
# what it is.  Both spellings satisfy the sentence above; neither is `Up`.
SQUAT_OUT=$("$BIN" create server ul_squat --listen "unix:$SOCK" -s 2>&1) || true
sleep 0.8
SQUAT_STATUS=$("$BIN" ls 2>/dev/null | awk '$2 == "ul_squat" { print $7 }')
if [ "$SQUAT_STATUS" != "Up" ] && [ -n "$SQUAT_STATUS" ]; then pass
else fail "a second server on a live socket is refused" \
          "ls reports '${SQUAT_STATUS:-<nothing>}' for the second one"; fi

# And the operator is told which runtime holds the path, on the terminal rather
# than in a log they have to be told to go and read.
if [[ "$SQUAT_OUT" == *"ul_srv"* && "$SQUAT_OUT" == *"already serving"* ]]; then pass
else fail "the refusal names the runtime holding the path" \
          "create said '${SQUAT_OUT:-<nothing>}'"; fi

STILL=$(http_over_unix "$SOCK")
if [[ "$STILL" == *"200 OK"* ]]; then pass
else fail "the server that owns the socket still has it" \
          "it answers '${STILL:-<nothing>}' after the refused start" \
          "a build that unlinks unconditionally takes the path away here"; fi

# A file that is no socket is the operator's: the probe's ECONNREFUSED is the same for it as for a leftover node, and
# reading it as one deleted whatever the path named.
NOTES="$D/notes.txt"
echo "keep me" > "$NOTES"
"$BIN" create server ul_file --listen "unix:$NOTES" -s >/dev/null 2>&1 || true
sleep 0.8
if [ "$(cat "$NOTES" 2>/dev/null)" = "keep me" ]; then pass
else fail "a regular file at the --listen path is left alone" \
          "it now holds '$(cat "$NOTES" 2>/dev/null || echo '<gone>')'"; fi
"$BIN" remove ul_file >/dev/null 2>&1 || true

# ─── 6. The restore path applies the whole common list ──────────────────────
#
# Both of these ride on the same line of daemon.cpp: the restore used to carry
# its own copy of apply_common_config's field list, and the copy was short.
# --listen would have been the next field to go missing; --shards already had.
"$BIN" create server ul_be -p $((P + 20)) -s >/dev/null 2>&1 || true
"$BIN" create proxy ul_sh -p $((P + 21)) --backend "127.0.0.1:$((P + 20))" \
    --shards 4 -s >/dev/null 2>&1 || true
sleep 1

daemon_stop_and_restart() {
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    local i
    for i in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    wait "$SOCKETLEY_DPID" 2>/dev/null || true
    : > "$SOCKETLEY_DLOG"
    "$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
    SOCKETLEY_DPID=$!
    for i in $(seq 1 100); do
        grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
        sleep 0.1
    done
    sleep 1.5
}
daemon_stop_and_restart

# Polled rather than slept on: this daemon has six runtimes and four shards to
# bring up, and a fixed sleep here would make a slow machine and a broken
# restore report the same thing.
RESTORED=""
for _i in $(seq 1 20); do
    RESTORED=$(http_over_unix "$SOCK")
    [[ "$RESTORED" == *"200 OK"* ]] && break
    sleep 0.5
done
if [[ "$RESTORED" == *"200 OK"* ]]; then pass
else fail "a restored server rebinds its unix socket" \
          "it answers '${RESTORED:-<nothing>}' after a daemon restart" \
          "ls will still say Up: nothing checks that a listener exists"; fi

SHARDS=$("$BIN" show ul_sh 2>/dev/null | grep -c '"shards": 4' || true)
if [ "$SHARDS" = "1" ]; then pass
else fail "a restored proxy keeps its shard count" \
          "show no longer reports 4 shards after a daemon restart" \
          "measured before the fix: 4 workers became 1, reported Up throughout"; fi

# ─── 6b. show | import round-trips the listener, and a bad one is refused ───
#
# `show name | socketley import name` is a documented round trip, and the field
# has to survive it -- an import that dropped `listen` would move a server off
# its socket and onto a TCP port, silently.  And the value has to be judged on
# the way in: parse_json_string strips the `unix:` prefix and cannot report a
# value that never had one, so a document saying `"listen": "/run/x.sock"` would
# otherwise import as "no unix listener at all".
"$BIN" stop ul_srv >/dev/null 2>&1 || true
sleep 0.4
DOC=$("$BIN" show ul_srv 2>/dev/null)
if grep -q '"listen": "unix:' <<<"$DOC"; then pass
else fail "show reports the listen socket" "the document has no listen field"; fi

set +e
"$BIN" import ul_srv "$DOC" >/dev/null 2>&1
IMP_RC=$?
set -e
AFTER_IMPORT=$("$BIN" show ul_srv 2>/dev/null | grep '"listen"' || true)
if [ "$IMP_RC" -eq 0 ] && grep -q "unix:$SOCK" <<<"$AFTER_IMPORT"; then pass
else fail "the listen socket survives show | import" \
          "import exited $IMP_RC and show now says '${AFTER_IMPORT:-<nothing>}'"; fi

BAD_DOC=$(python3 -c "
import sys
d = sys.stdin.read()
sys.stdout.write(d.replace('\"unix:$SOCK\"', '\"$SOCK\"'))
" <<<"$DOC")
set +e
IMP_OUT=$("$BIN" import ul_srv "$BAD_DOC" 2>&1)
BAD_RC=$?
set -e
if [ "$BAD_RC" -ne 0 ] && grep -q "unix:" <<<"$IMP_OUT"; then pass
else fail "import refuses a listen value with no unix: prefix" \
          "exit $BAD_RC saying: ${IMP_OUT:-<nothing>}" \
          "accepted, it would move the server onto a TCP port and say nothing"; fi

"$BIN" start ul_srv >/dev/null 2>&1 || true
sleep 0.8

# ─── 7. The refusals, each at the point the flag is read ────────────────────
refuse_cli() {
    local name=$1 needle=$2; shift 2
    local out rc
    set +e
    out=$("$BIN" create server "$name" "$@" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        fail "$name is refused" "create exited 0"
        return
    fi
    if grep -qF -- "$needle" <<<"$out"; then pass
    else fail "$name is refused for the stated reason" \
              "exited $rc saying: ${out:-<nothing>}"; fi
}

LONG="/tmp/$(python3 -c "print('z' * 120)").sock"
# A relative path is the caller's, resolved by the CLI against the directory
# the command was typed in -- so it binds there, and is not refused.
REL_DIR="$(mktemp -d)"
ABS_BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
(cd "$REL_DIR" && "$ABS_BIN" create server ul_rel --listen "unix:relative.sock" -s >/dev/null 2>&1)
for _ in $(seq 1 50); do [ -S "$REL_DIR/relative.sock" ] && break; sleep 0.1; done
if [ -S "$REL_DIR/relative.sock" ]; then pass
else fail "a relative unix: path binds beside the caller" \
          "no socket at $REL_DIR/relative.sock"; fi
"$BIN" remove ul_rel >/dev/null 2>&1 || true
rm -rf "$REL_DIR"
refuse_cli ul_empty "no socket path"        --listen "unix:"
refuse_cli ul_tcp2  "a TCP port is -p"      --listen "127.0.0.1:9000"
refuse_cli ul_long  "would be truncated"    --listen "unix:$LONG"

# These two are decided in setup(), not in the flag parser, because the flag
# parser is not on the restore or import path.  So they cost a failed start
# rather than a refused create, and the reason is in the daemon log.
setup_refusal() {
    local name=$1 needle=$2; shift 2
    local before rc
    before=$(wc -c <"$SOCKETLEY_DLOG")
    set +e
    "$BIN" create server "$name" "$@" -s >/dev/null 2>&1
    rc=$?
    set -e
    local after
    after=$(tail -c "+$((before + 1))" "$SOCKETLEY_DLOG")
    if [ "$rc" -ne 0 ] && grep -qF -- "$needle" <<<"$after"; then pass
    else fail "$name is refused at start" \
              "exit $rc; the log said: ${after:0:200}"; fi
}

setup_refusal ul_both "--listen and -p"  -p $((P + 30)) --listen "unix:$D/both.sock"
setup_refusal ul_udp  "--udp asks for"   --listen "unix:$D/udp.sock" --udp

# --listen stopped being a server's flag alone when the listener moved to
# shared/unix_listener.h: a proxy given one is accepted at parse now.  This
# inverts the refusal that used to sit here.  What it catches is the flag
# falling back out of the common parser and becoming per-type again — the
# behaviour behind it is proved in test_unix_listener_runtimes.sh, not here.
set +e
OUT=$("$BIN" create proxy ul_pxl --backend 127.0.0.1:9 --listen "unix:$D/x.sock" 2>&1)
RC=$?
set -e
if [ "$RC" -eq 0 ]; then pass
else fail "--listen on a proxy parses" "exit $RC saying: ${OUT:-<nothing>}"; fi
"$BIN" remove ul_pxl >/dev/null 2>&1 || true

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
