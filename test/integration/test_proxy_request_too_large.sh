#!/usr/bin/env bash
# Integration test: what a client gets when it buffers more than the proxy holds.
#
# handle_client_read caps what it will hold for one exchange at MAX_PARTIAL_SIZE
# — one megabyte.  Everything the client has sent past the point the request in
# flight accounts for lands there: the body beyond its declared length, and the
# requests pipelined behind it.  Nothing drains any of it until the response that
# precedes it is finished, so a client that writes faster than the backend
# answers fills it on a perfectly well-formed connection.  It is not the
# malformed-request path and not slowloris; both of those are answered.  This one
# used to close in silence.
#
# TWO CASES, AND ONLY ONE OF THEM MAY BE ANSWERED.  That is the whole shape of
# this file, and it is why the second half is here at all:
#
#   the backend is still holding its response, so nothing of it has reached the
#   client — a status line then starts at a message boundary, and 413 is what
#   this client is owed
#
#   the backend has already begun streaming and part of its response is on the
#   client's wire — a 413 written behind those bytes would be read as their
#   continuation, at an offset the proxy has itself established is not a message
#   boundary.  The truncated response is left truncated: the client can see that
#   it is truncated, and cannot see a status line spliced into the middle of one.
#
# The two flood sizes are not decoration either.  A run that only floods over
# the cap cannot tell "the proxy answered 413" from "the proxy answers 413 to
# everything": the 512 KiB pass is the control, and it must complete normally in
# both cases or the number being measured is not the cap.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate toobig

HOLD_BE=$((SL_PORT_BASE+731)); HOLD_PX=$((SL_PORT_BASE+730))
STREAM_BE=$((SL_PORT_BASE+741)); STREAM_PX=$((SL_PORT_BASE+740))
PASS=0; FAIL=0; TOTAL=0
BE_PIDS=()
TMPD=$(mktemp -d)

cleanup() {
    "$BIN" stop  px_hold   >/dev/null 2>&1 || true
    "$BIN" stop  px_stream >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove px_hold   >/dev/null 2>&1 || true
    "$BIN" remove px_stream >/dev/null 2>&1 || true
    for p in "${BE_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    rm -rf "$TMPD"
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

echo "=== Integration: proxy 413 when a client buffers past the cap ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

# ---- backends -------------------------------------------------------------
#
# "hold" answers only after the client has long finished flooding, so nothing of
# its response is ever on the client's wire while the cap is crossed.
# "stream" writes its status line and the first four bytes of its body at once
# and finishes much later, so response_started is true for the whole flood.
cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading, time
mode, port = sys.argv[1], int(sys.argv[2])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)
print("ready", flush=True)

HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n"

def serve(c):
    try:
        c.recv(65536)
        if mode == "hold":
            time.sleep(5.0)
            c.sendall(HEAD + b"AAAABBBBCCCCDDDDEEEE")
        elif mode == "stream":
            c.sendall(HEAD + b"AAAA")
            time.sleep(5.0)
            c.sendall(b"BBBBCCCCDDDDEEEE")
    except OSError:
        pass
    finally:
        try: c.close()
        except OSError: pass

while True:
    try:
        c, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

# ---- the client -----------------------------------------------------------
#
# One request, then silence long enough for the proxy to have parsed and
# forwarded it — the flood must arrive with a request already in flight, or the
# 16 KiB header cap catches it first and the 431 path is what gets measured
# instead.  Reading runs on its own thread throughout, because the proxy's
# answer can arrive while this side is still writing.
cat > "$TMPD/flood.py" <<'PY'
import socket, sys, threading, time
port, path, mode, total = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
s = socket.create_connection(("127.0.0.1", port), timeout=30)
got = bytearray()

def reader():
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            got.extend(b)
    except OSError:
        pass

t = threading.Thread(target=reader, daemon=True)
t.start()

req = ("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode()
s.sendall(req)
time.sleep(0.4)

if mode == "after":
    # The flood must not start until part of the backend's answer is on this
    # wire, or the case being measured is the other one.
    deadline = time.time() + 8
    while not got and time.time() < deadline:
        time.sleep(0.02)
    if not got:
        print("NO-FIRST-BYTES")
        sys.exit(3)

chunk = req * 64
sent = 0
try:
    while sent < total:
        s.sendall(chunk)
        sent += len(chunk)
except OSError:
    pass
try:
    s.shutdown(socket.SHUT_WR)
except OSError:
    pass
t.join(timeout=15)
out = bytes(got)

status = "none"
if out.startswith(b"HTTP/1.1 "):
    status = out.split(b"\r\n", 1)[0].decode("latin1")[9:]
print("status=%s" % status)
print("bytes=%d" % len(out))
print("has413=%s" % ("yes" if b"413" in out else "no"))
print("body=%s" % out.split(b"\r\n\r\n", 1)[1].decode("latin1") if b"\r\n\r\n" in out else "body=")
PY

python3 "$TMPD/be.py" hold   "$HOLD_BE"   >"$TMPD/hold.log"   2>&1 & BE_PIDS+=($!)
python3 "$TMPD/be.py" stream "$STREAM_BE" >"$TMPD/stream.log" 2>&1 & BE_PIDS+=($!)
# The backends are this test's own, so one that never listens is a failure rather than a skip.
ready_tcp 127.0.0.1 "$HOLD_BE" 8   || { echo "  FAIL [the holding backend listens]: $(tail -2 "$TMPD/hold.log")"; exit 1; }
ready_tcp 127.0.0.1 "$STREAM_BE" 8 || { echo "  FAIL [the streaming backend listens]: $(tail -2 "$TMPD/stream.log")"; exit 1; }

daemon_start "$BIN"

# --backend-timeout well above the backends' five-second hold, because both of
# them are exactly what the default two seconds is documented to notice: "a
# backend which accepts connections and then stops answering".  The flood is
# made of pipelined requests, and while the header deadline masked the response
# one a run at the default reached the cap; unmasked it is answered 504 at two
# seconds and the number measured is the deadline rather than the cap.
create_ok "hold proxy created" "$BIN" create proxy px_hold \
    -p "$HOLD_PX" --backend "127.0.0.1:$HOLD_BE" --protocol http \
    --backend-timeout 30
create_ok "stream proxy created" "$BIN" create proxy px_stream \
    -p "$STREAM_PX" --backend "127.0.0.1:$STREAM_BE" --protocol http \
    --backend-timeout 30
"$BIN" start px_hold   >/dev/null 2>&1 || true
"$BIN" start px_stream >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$HOLD_PX" 8   || echo "  note: px_hold never listened"
ready_tcp 127.0.0.1 "$STREAM_PX" 8 || echo "  note: px_stream never listened"

run() {   # run PORT PATH MODE TOTAL -> sets R_STATUS R_BYTES R_413 R_BODY
    local out
    out=$(python3 "$TMPD/flood.py" "$1" "$2" "$3" "$4" 2>&1) || true
    R_STATUS=$(printf '%s\n' "$out" | sed -n 's/^status=//p')
    R_BYTES=$(printf '%s\n' "$out" | sed -n 's/^bytes=//p')
    R_413=$(printf '%s\n' "$out" | sed -n 's/^has413=//p')
    R_BODY=$(printf '%s\n' "$out" | sed -n 's/^body=//p')
    : "${R_STATUS:=<no-output>}" "${R_BYTES:=0}" "${R_413:=<no-output>}"
}

# ── the control: under the cap, nothing changes ────────────────────────────
echo "--- 512 KiB behind the request, which is under the cap ---"
run "$HOLD_PX" /px_hold/ now 524288
assert_eq "$R_STATUS" "200 OK" "under the cap, backend holding: the response arrives"
assert_eq "$R_BODY"   "AAAABBBBCCCCDDDDEEEE" "under the cap, backend holding: whole body"

run "$STREAM_PX" /px_stream/ after 524288
assert_eq "$R_STATUS" "200 OK" "under the cap, backend streaming: the response arrives"
assert_eq "$R_BODY"   "AAAABBBBCCCCDDDDEEEE" "under the cap, backend streaming: whole body"

# ── over the cap, nothing of the response on the wire yet: 413 ─────────────
echo "--- 3 MiB behind the request, backend still holding its response ---"
run "$HOLD_PX" /px_hold/ now 3145728
assert_eq "$R_STATUS" "413 Request Entity Too Large" \
          "over the cap with a silent backend: 413, not silence"

# ── over the cap with the response already started: silence ────────────────
#
# The one assertion here that must never turn green by a status line appearing:
# what is on this wire is a prefix of the backend's own response and nothing
# else.  A 413 written behind it would be read as part of that response.
echo "--- 3 MiB behind the request, backend already streaming ---"
run "$STREAM_PX" /px_stream/ after 3145728
assert_eq "$R_STATUS" "200 OK" \
          "over the cap after the response started: the backend's status stands"
assert_eq "$R_413" "no" \
          "over the cap after the response started: no status line behind the response"
assert_eq "$R_BODY" "AAAA" \
          "over the cap after the response started: truncated, and only truncated"

echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ]
