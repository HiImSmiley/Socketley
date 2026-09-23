#!/usr/bin/env bash
# Integration test: HEAD is a property of one request, not of the connection.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# queue_http_response() is the one place an HTTP response enters the write
# queue, and it cuts a response to its header block when conn->http_head is
# set -- which is right, and is why the flag exists.  The flag was written in
# exactly two places, both inside the proto_http arm of parse_partial(): down
# at the top of a parsed head, up if the method is HEAD.
#
# Two kinds of response are produced without ever reaching those lines:
#
#   the WebSocket upgrade refusals -- 426 for a version that is not 13, and
#   400 for a handshake with no Sec-WebSocket-Key.  An upgrade is always a GET,
#   so the flag there is never this request's; it is the previous request's.
#
#   the 408 the idle sweep answers for a head that stopped half-arrived.  The
#   request line was never parsed, so nothing cleared the flag.
#
# In both cases the body was dropped while the Content-Length that promises it
# stayed, so a client reading the declared number of bytes waits for bytes that
# will never come and then sees the close.  The 426 exists to tell a client
# which version to speak; a 426 with no body tells it nothing.
#
# ─── WHAT WOULD MAKE THIS VACUOUS ───────────────────────────────────────────
#
# Asserting the status line.  Both refusals answer 426/400/408 with and without
# the defect -- the existing test_http_head_deadline.sh checks exactly that and
# is green on the defective tree.  What is measured here is the BODY LENGTH,
# against the Content-Length in the same response, with a fresh-connection
# control for every row so "this build cannot answer 426 at all" cannot pass.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_create.sh"
. "$HERE/lib_ready.sh"
daemon_isolate headstale

P=$((SL_PORT_BASE+1760))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() { "$BIN" stop hs >/dev/null 2>&1 || true; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a HEAD does not cut the next request's body off ==="

WWW=$SOCKETLEY_TMPD/www
mkdir -p "$WWW"
printf 'twelve bytes' > "$WWW/small.txt"

daemon_start "$BIN"
create_ok "a static server" "$BIN" create server hs -p "$P" --http "$WWW" -s
ready_http 127.0.0.1 "$P" /small.txt 10 >/dev/null 2>&1 || true

# One connection, one or two requests, reporting the LAST response's status,
# its declared Content-Length and the bytes that actually followed the header
# block.  The first response is consumed by reading its own header block and
# then exactly as many body bytes as it declares, which is correct for a HEAD
# (none) and for a 200 alike.
probe() {  # probe FIRST_OR_EMPTY SECOND [nobody]
    python3 - "$P" "$1" "$2" "${3:-}" <<'PYEOF'
import socket, sys
port, first, second, nobody = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
s = socket.create_connection(("127.0.0.1", port), 10)
s.settimeout(45)
f = s.makefile("rb")

def one(expect_body):
    head = b""
    while b"\r\n\r\n" not in head:
        c = f.read(1)
        if not c:
            return None, -1, b""
        head += c
    cl = -1
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":", 1)[1].strip())
    body = b""
    if expect_body and cl > 0:
        body = f.read(cl)
    return head, cl, body

if first:
    s.sendall(first.encode("latin1"))
    # A HEAD's own response carries a Content-Length and no body, which is the
    # behaviour this file must not disturb; read the head only.
    one(False)

s.sendall(second.encode("latin1"))
# `nobody` says the last response is itself a HEAD's, so reading Content-Length
# bytes after it would block on the next request's answer instead.
head, cl, body = one(not nobody)
if head is None:
    print("status=<nothing> cl=-1 body=0 text=")
    raise SystemExit(0)
print("status=%s" % head.split(b"\r\n")[0].decode("latin1"))
print("cl=%d" % cl)
print("body=%d" % len(body))
print("text=%s" % body.decode("latin1", "replace").strip())
PYEOF
}

HEAD_REQ=$'HEAD /small.txt HTTP/1.1\r\nHost: x\r\n\r\n'
GET_REQ=$'GET /small.txt HTTP/1.1\r\nHost: x\r\n\r\n'
UP8=$'GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n'
NOKEY=$'GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n'

g() { printf '%s\n' "$2" | sed -n "s/^$1=//p"; }

# ─── 1. The controls: the refusals carry a body on a fresh connection ───────
R=$(probe "" "$UP8")
CL_FRESH=$(g cl "$R")
check "a 426 on a fresh connection has a body" "$CL_FRESH" "$(g body "$R")"
if [ "${CL_FRESH:-0}" -gt 0 ]; then ok; else
    bad "the 426 declares a body at all" "Content-Length: ${CL_FRESH:-<none>}" \
        "with nothing declared, every length comparison below is 0 = 0"; fi

R=$(probe "$GET_REQ" "$UP8")
check "and after a GET on the same connection" "$(g cl "$R")" "$(g body "$R")"

# ─── 2. The defect: the same refusal behind a HEAD ──────────────────────────
R=$(probe "$HEAD_REQ" "$UP8")
check "a 426 behind a HEAD still has its body" "$(g cl "$R")" "$(g body "$R")"
case "$(g text "$R")" in
    *"version 13"*) ok ;;
    *) bad "and the body is the sentence that names the version" \
           "got '$(g text "$R")'" \
           "a 426 with no body tells the client nothing, which is the whole" \
           "reason this status is sent instead of a close" ;;
esac

R=$(probe "$HEAD_REQ" "$NOKEY")
check "a 400 for a missing nonce behind a HEAD still has its body" \
      "$(g cl "$R")" "$(g body "$R")"

# ─── 3. The other site: the 408 for a head that stopped ─────────────────────
# Slow -- the deadline is ten seconds and the sweep that reads it runs on its
# own clock -- so it is one probe, with the fresh-connection control beside it.
R=$(probe "" $'POST /x HTTP/1.1\r\nHost: x\r\n')
check "a 408 on a fresh connection has a body" "$(g cl "$R")" "$(g body "$R")"
CL408=$(g cl "$R")

R=$(probe "$HEAD_REQ" $'POST /x HTTP/1.1\r\nHost: x\r\n')
check "a 408 behind a HEAD still has its body" "$CL408" "$(g body "$R")"

# ─── 4. And the behaviour that must not change ──────────────────────────────
R=$(probe "" "$HEAD_REQ" nobody)
check "a HEAD is still answered with its header block alone" "0" "$(g body "$R")"
if [ "$(g cl "$R")" = "12" ]; then ok; else
    bad "and the HEAD still declares the length it would have sent" \
        "Content-Length: $(g cl "$R"), expected 12"; fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
