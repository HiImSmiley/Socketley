#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: the proxy reads `close` as a TOKEN in the Connection list,
# not as the first two letters of the field value.
#
# rewrite_http_request decided whether the client had asked to close with
#
#     if (val.size() >= 5 && (val[0] | 0x20) == 'c' && (val[1] | 0x20) == 'l')
#
# — a two-character prefix test, wrong in both directions:
#
#   * "Connection: keep-alive, close" starts "ke", so the close was never seen
#     and the proxy kept a connection the client had asked it to end.  That is
#     an ordinary spelling, not a corner case; it is the one http_list_has_token
#     exists for, and RFC 9110 Section 7.6.1 makes Connection a list header.
#
#   * "Connection: clientinfo" starts "cl" and is five bytes, so the proxy set
#     client_conn_close on a connection nobody had asked to close — and a
#     request pipelined behind it was then DROPPED (see the comment at the
#     `client_answer_owed` detach).  A well-formed request, silently unanswered.
#
# Twenty-nine lines above that test, the same function reads the `Upgrade`
# token out of the same header with http_list_has_token() and cites the RFC for
# doing so.  The correct helper was already in scope; this site predates it by
# five months (cb0c76c 2026-03-02 against 443c5fc 2026-07-31) and was never
# revisited, which is what an invariant kept at the call site does.
#
# ─── WHY FOUR CASES AND NOT TWO ─────────────────────────────────────────────
#
# The two controls are what make the two real assertions mean anything.  A
# harness that cannot see a second answer reports "1" for every case and looks
# like a passing close-honoured test; a harness whose socket dies early reports
# the same.  So `keep-alive` must produce 2 and `close` must produce 1 on the
# same socket, in the same run, before the other two are worth reading:
#
#     keep-alive          2   catches a build that closes on everything
#     close               1   catches a build that never closes
#     keep-alive, close   1   catches the prefix test -- it sees "ke"
#     clientinfo          2   catches the prefix test -- it sees "cl"
#
# Both directions are asserted on purpose.  A fix tested only on
# "keep-alive, close" passes if `close` is matched anywhere in the value, which
# would still fire on "clientinfo".
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

TMPDIR_T=$(mktemp -d /tmp/socketley-conntok-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""

BE_PORT=$((SL_PORT_BASE+460))
PX_PORT=$((SL_PORT_BASE+461))
SV_PORT=$((SL_PORT_BASE+462))
PX_NAME=ctok_px
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Exact process name plus this run's own SOCKETLEY_SOCKET, never a
    # command-line pattern: `pgrep -f` matches the shell that merely carries the
    # string, including this one.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: Connection: close is a token, not a prefix ==="

mkdir -p "$TMPDIR_T/www"
printf 'ROOT\n' > "$TMPDIR_T/www/index.html"

"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done

# --http-cache off on purpose: disk mode is the default path and the one the
# proxy sits in front of in the other proxy tests.
create_ok "backend created" "$BIN" create server ctok_be -p "$BE_PORT" \
    --http "$TMPDIR_T/www" -s
create_ok "proxy created"   "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s
# The server is the CONTROL implementation, not scenery: it answers the same
# four values through http_request_keep_alive(), which already reads the list
# correctly.  Running both in one file means a red proxy row cannot be blamed
# on the client, the wire or the box -- the server row was produced by the same
# harness in the same second.
create_ok "control server created" "$BIN" create server ctok_sv -p "$SV_PORT" \
    --http "$TMPDIR_T/www" -s

ready_tcp 127.0.0.1 "$BE_PORT" 10 || true
ready_tcp 127.0.0.1 "$PX_PORT" 10 || true
ready_tcp 127.0.0.1 "$SV_PORT" 10 || true

# Two pipelined requests in ONE write, then read until the peer closes or the
# socket goes quiet.  stdin is never closed: `nc -q` sends FIN after writing,
# and a proxy that reads client EOF as an abort then answers nothing at all --
# which is what made the first attempt at this test report 0 for every case.
cat > "$TMPDIR_T/pipe.py" <<'PYEOF'
import socket, sys
port = int(sys.argv[1]); connval = sys.argv[2]; path = sys.argv[3]
req = ("GET %s HTTP/1.1\r\nHost: x\r\nConnection: %s\r\n\r\n"
       "GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % (path, connval, path)).encode()
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(req)
except OSError as e:
    print("ERR:%s" % e); raise SystemExit(0)
buf = b""
s.settimeout(2.5)
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
except socket.timeout:
    pass
s.close()
print(buf.count(b"HTTP/1.1 200"))
PYEOF

# answers LABEL PORT CONNVALUE PATH EXPECTED
answers() {
    local label="$1" port="$2" val="$3" path="$4" want="$5" got
    got=$(python3 "$TMPDIR_T/pipe.py" "$port" "$val" "$path" 2>/dev/null || echo ERR)
    TOTAL=$((TOTAL+1))
    if [ "$got" = "$want" ]; then
        PASS=$((PASS+1))
        printf '  PASS [%s]: Connection: %-18s -> %s answer(s)\n' "$label" "$val" "$got"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL [%s]: Connection: %-18s -> %s answer(s), expected %s\n' \
            "$label" "$val" "$got" "$want"
    fi
}

echo "--- proxy (the subject) ---"
answers proxy   "$PX_PORT" "keep-alive"        "/$PX_NAME/index.html" 2
answers proxy   "$PX_PORT" "close"             "/$PX_NAME/index.html" 1
answers proxy   "$PX_PORT" "keep-alive, close" "/$PX_NAME/index.html" 1
answers proxy   "$PX_PORT" "clientinfo"        "/$PX_NAME/index.html" 2

echo "--- server (the control: already reads the list correctly) ---"
answers server  "$SV_PORT" "keep-alive"        "/index.html" 2
answers server  "$SV_PORT" "close"             "/index.html" 1
answers server  "$SV_PORT" "keep-alive, close" "/index.html" 1
answers server  "$SV_PORT" "clientinfo"        "/index.html" 2

echo
echo "Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
