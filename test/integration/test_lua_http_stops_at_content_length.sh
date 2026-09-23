#!/usr/bin/env bash
# Integration test: socketley.http() ends a response where its length says,
# not where the peer happens to close.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The only end-of-response signal was the peer closing the socket.  Against a
# server that keeps the connection open -- which a great many do despite
# `Connection: close`, and which nothing in the protocol forbids -- a body that
# arrived in full was answered `ok=false, error=response timed out`, after
# spending the whole deadline waiting for a FIN that was never coming.
#
# ─── WHAT IT ASSERTS, AND WHAT STAYS ON THE OLD RULE ────────────────────────
#
#   a length and no close    answered from the length, and quickly
#   chunked                  read until close, because this does not frame
#                            chunked and a Content-Length beside it is a lie
#   no length at all         read until close, which is the only framing an
#                            HTTP/1.0 response without one has
#   HEAD                     ends at the headers, because the length it quotes
#                            is the body a GET would have had
#   a length and a short     an error, because the length is a promise and this
#   body                     one was broken -- the only truncation a reader can
#                            be certain of, since every other framing here ends
#                            at the close and has no number to fall short of
#
# The last is the one a careless fix breaks: a HEAD reply says
# Content-Length: 4096 and sends nothing, so waiting for 4096 bytes waits for
# the deadline -- which is the defect this file exists to prevent, arriving
# from the other side.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate clen

ORIGIN=$((SL_PORT_BASE+1780))
CALLER=$((SL_PORT_BASE+1781))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   clen_caller >/dev/null 2>&1 || true
    "$BIN" remove clen_caller >/dev/null 2>&1 || true
    [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: socketley.http() ends a response where its length says ==="

# Four framings from one origin, so the four answers below differ in the
# framing alone.
cat > "$SOCKETLEY_TMPD/origin.py" <<'PYEOF'
import socket, sys, threading, time

port = int(sys.argv[1])
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(16)
ls.settimeout(0.3)
sys.stderr.write("origin up\n"); sys.stderr.flush()

BODY = b"LENGTH-FRAMED-BODY"

def serve(c):
    try:
        c.settimeout(3)
        req = c.recv(8192).decode("latin1")
        line = req.split("\r\n", 1)[0]
        parts = line.split(" ")
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        if method == "HEAD":
            # A length with no body behind it, and the socket stays open: the
            # shape that hangs a reader which waits for the number.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
            time.sleep(20)
            return

        if path.startswith("/chunked"):
            c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                      b"5\r\nCHUNK\r\n0\r\n\r\n")
            return                      # closes: chunked is read until close here

        if path.startswith("/twolengths"):
            # RFC 9112 Section 6.3: two Content-Lengths that disagree make the
            # message unrecoverable.  The socket stays open, so a reader that
            # framed on either number would answer from it and a reader that
            # refuses to frame waits -- which is the difference this endpoint
            # is here to show.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                      b"Content-Length: 99\r\n\r\nAAAAABBBBBCCCCCDDDDD")
            time.sleep(20)
            return

        if path.startswith("/short"):
            # Forty declared, ten sent, then a close: the shape a reader that
            # stops at the close and never looks at what it was promised
            # reports as a complete two-hundred.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nSHORT-BODY")
            return

        if path.startswith("/nolength"):
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nNO-LENGTH-BODY")
            return                      # closes, which is its only framing

        # The default: complete, correctly framed, and the socket is NOT
        # closed -- which is the whole point of this file.
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(BODY), BODY))
        time.sleep(20)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

deadline = time.time() + 180
while time.time() < deadline:
    try:
        c, _ = ls.accept()
    except socket.timeout:
        continue
    except Exception:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF

python3 "$SOCKETLEY_TMPD/origin.py" "$ORIGIN" >"$SOCKETLEY_TMPD/origin.out" 2>"$SOCKETLEY_TMPD/origin.log" &
ORIGIN_PID=$!
for i in $(seq 1 60); do
    grep -q "origin up" "$SOCKETLEY_TMPD/origin.log" 2>/dev/null && break
    sleep 0.1
done
if ! grep -q "origin up" "$SOCKETLEY_TMPD/origin.log" 2>/dev/null; then
    bad "the origin came up" "$(tail -3 "$SOCKETLEY_TMPD/origin.log" 2>/dev/null | tr '\n' ' ')"
    echo "  $PASS/$TOTAL passed"; exit 1
fi

daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/probe.lua" <<LUAEOF
-- CR and LF replaced before logging, because a chunked body carries both and
-- a log line that wraps is one a grep reads half of -- which is how the
-- chunked assertion in this file first failed against correct behaviour.
local function say(tag, r)
    local b = tostring(r.body):gsub("[\r\n]", ".")
    socketley.log("CLEN " .. tag
        .. " ok=" .. tostring(r.ok)
        .. " status=" .. tostring(r.status)
        .. " body=[" .. b .. "]"
        .. " err=" .. tostring(r.error))
end
function on_start()
    say("LEN",   socketley.http({ url = "http://127.0.0.1:$ORIGIN/keepopen", timeout_ms = 4000 }))
    say("CHUNK", socketley.http({ url = "http://127.0.0.1:$ORIGIN/chunked",  timeout_ms = 4000 }))
    say("NOLEN", socketley.http({ url = "http://127.0.0.1:$ORIGIN/nolength", timeout_ms = 4000 }))
    say("SHORT", socketley.http({ url = "http://127.0.0.1:$ORIGIN/short",    timeout_ms = 4000 }))
    say("HEAD",  socketley.http({ url = "http://127.0.0.1:$ORIGIN/keepopen", timeout_ms = 4000,
                                  method = "HEAD" }))
    -- Shorter, because the right answer here is to wait: it is the one call in
    -- this file that must NOT be framed.
    say("TWOLEN", socketley.http({ url = "http://127.0.0.1:$ORIGIN/twolengths", timeout_ms = 1200 }))
    socketley.log("CLEN DONE")
end
LUAEOF

# Timed from outside: five calls that each waited out a 4s deadline would take
# twenty seconds, and five that stop at their framing take almost none.  The
# assertion is on the answers; this is what makes a regression legible.
T0=$(date +%s%N)
"$BIN" create server clen_caller -p "$CALLER" --lua "$SOCKETLEY_TMPD/probe.lua" >/dev/null 2>&1
"$BIN" start clen_caller >/dev/null 2>&1
for i in $(seq 1 250); do
    grep -q "CLEN DONE" "$SOCKETLEY_DLOG" 2>/dev/null && break
    sleep 0.1
done
T1=$(date +%s%N)
ELAPSED_MS=$(( (T1 - T0) / 1000000 ))

line_for() { grep -oE "CLEN $1 .*" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1; }

L_LEN=$(line_for LEN); L_CHUNK=$(line_for CHUNK)
L_NOLEN=$(line_for NOLEN); L_HEAD=$(line_for HEAD)
L_TWOLEN=$(line_for TWOLEN); L_SHORT=$(line_for SHORT)

echo "  ${ELAPSED_MS} ms for five calls with a 4000 ms deadline each"
for l in "$L_LEN" "$L_CHUNK" "$L_NOLEN" "$L_HEAD" "$L_TWOLEN" "$L_SHORT"; do echo "    ${l:-<nothing logged>}"; done

if grep -q "CLEN DONE" "$SOCKETLEY_DLOG" 2>/dev/null; then ok
else bad "the script ran all six calls" "no DONE line in the daemon log" \
         "every assertion below is void"; fi

case "$L_LEN" in
    *"ok=true"*"body=[LENGTH-FRAMED-BODY]"*) ok ;;
    *) bad "a length-framed body is answered without waiting for a close" \
           "${L_LEN:-nothing logged}" \
           "the peer holds the socket open on purpose here" ;;
esac

case "$L_CHUNK" in
    *"ok=true"*CHUNK*) ok ;;
    *) bad "a chunked response still arrives by the old rule" "${L_CHUNK:-nothing logged}" \
           "chunked is not framed here, so it must read until close" ;;
esac

case "$L_NOLEN" in
    *"ok=true"*"body=[NO-LENGTH-BODY]"*) ok ;;
    *) bad "a response with no length still arrives by the old rule" \
           "${L_NOLEN:-nothing logged}" ;;
esac

case "$L_HEAD" in
    *"ok=true"*"body=[]"*) ok ;;
    *) bad "a HEAD ends at its headers" "${L_HEAD:-nothing logged}" \
           "it quotes the length a GET would have had and sends no body," \
           "so waiting for that many bytes waits for the whole deadline" ;;
esac

# Two lengths that disagree are not a length.  A reader that picked either
# would answer 5 bytes or wait for 99 of 20; the only safe answer is that this
# message cannot be framed, which leaves reading until a close that is not
# coming -- so the deadline is the right outcome here and an early body is not.
case "$L_TWOLEN" in
    *"ok=false"*) ok ;;
    *) bad "two disagreeing Content-Lengths are not framed" "${L_TWOLEN:-nothing logged}" \
           "an answer here means one of the two numbers was picked, and RFC 9112" \
           "Section 6.3 says the message is unrecoverable rather than ambiguous" ;;
esac

# The one truncation this can be sure of: the peer named a length and closed
# before reaching it.  A short body handed back under ok=true is worse than an
# error, because the script has no second signal to check -- the close that
# ended it is the same close that ends a correctly framed HTTP/1.0 response,
# and over TLS the close_notify that would have told them apart is one
# SSL_OP_IGNORE_UNEXPECTED_EOF accepts the absence of on purpose.
case "$L_SHORT" in
    *"ok=false"*"short of its Content-Length"*) ok ;;
    *) bad "a body that stops short of its Content-Length is an error" \
           "${L_SHORT:-nothing logged}" \
           "the origin declared 40 bytes, sent 10, and closed; ok=true here" \
           "hands the script ten bytes with nothing to distinguish them from forty" ;;
esac

# One deadline's worth of slack: four calls that stopped at their framing plus
# one that is meant to wait 1200 ms cannot have spent four deadlines.
if [ "$ELAPSED_MS" -lt 8000 ]; then ok
else bad "the framed calls did not each wait out their deadline" \
         "${ELAPSED_MS} ms for five calls of 4000 ms and one of 1200 ms" \
         "at least two of them are waiting for a close that is not coming"; fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
