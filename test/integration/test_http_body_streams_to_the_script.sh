#!/usr/bin/env bash
# Integration test: a request body larger than memory reaches the script.
#
# ─── THE ASYMMETRY, AGAIN IN THE SAME DIRECTION ─────────────────────────────
#
# The proxy has streamed request bodies all along, and the mechanism is four
# lines in forward_client_body():
#
#     const size_t n = conn->body_unbounded
#         ? conn->partial.size()
#         : std::min(conn->body_remaining, conn->partial.size());
#     forward_to_backend(conn, std::string_view(conn->partial.data(), n));
#     conn->body_remaining -= n;
#     conn->partial.erase(0, n);          <- consumed, not accumulated
#
# The server did the opposite: it waited for the whole body to be in `partial`
# and refused past the bound --
#
#     size_t total_expected = hdr_end + 4 + content_length;
#     if (conn->partial.size() < total_expected) return;
#
# so a 2 MB POST was 413 while the same body through a proxy was fine. Same
# shape as write_queue_backpressure_bytes, read in five places in the proxy and
# none in the server: the reference implementation was in the sibling runtime.
#
# ─── WHAT IT COSTS NOW, WHICH IS THE POINT ──────────────────────────────────
#
# Worker RSS, one connection at a time, measured:
#
#     start              19,796 kB
#     after 50 MB  #1    37,344 kB
#     after 50 MB  #2    37,344 kB      unchanged
#     after 50 MB  #3    37,344 kB      unchanged
#     after 200 MB       37,428 kB      +84 kB
#     after 500 MB       37,444 kB      +16 kB
#
# The first upload costs 17.5 MB once -- the provided-buffer ring is 1024 x
# 16 KB and gets faulted in -- and every one after that costs nothing. Half a
# gigabyte received inside 37 MB of resident memory. That independence is the
# assertion below, and it is the only one that distinguishes streaming from a
# larger buffer.
#
# ─── WHY THERE IS NO FLAG FOR IT ────────────────────────────────────────────
#
# Defining on_http_body IS the opt-in, which is the same shape on_writable has:
# the runtime asks wants_on_http_body() before the headers are finished, and a
# script without it gets exactly today's behaviour including the 413. Nothing
# to configure, and no way to turn on streaming and then not read the stream.
#
# ─── AND THE ONE PIECE THAT IS NOT THE PROXY'S ──────────────────────────────
#
# The proxy forwards the body to a socket; a server hands it to a script, and
# then still has to answer the request whose headers are long gone from
# `partial`. So the connection owns the head as a string, and the request's
# views are REBASED onto that copy rather than parsed a second time -- the
# saved head is a byte-for-byte prefix, so each view keeps its offset and only
# its base moves. One parse, which is what keeps a streamed request and a
# gathered one from disagreeing about the same bytes.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate httpbody

P_S=$((SL_PORT_BASE+1974))
P_N=$((SL_PORT_BASE+1976))
NAMES="hb_stream hb_plain"
LUA="$SOCKETLEY_TMPD/hb.lua"
WWW="$SOCKETLEY_TMPD/www"

PASS=0; FAIL=0; SKIP=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

# ─── The one assertion a sanitized build cannot answer ───────────────────────
# Measured, Sanitize, this test's own script and one connection at a time:
#
#     start          122,836 kB
#     after 50 MB    142,860 kB    +20,024 kB   (the buffer ring, once)
#     after 200 MB   143,148 kB       +288 kB
#     after 500 MB   142,972 kB       -176 kB
#     after 500 MB   143,052 kB        +80 kB
#
# So the property holds under ASan too. What does not hold is MEASURING it from
# inside the suite: there the worker began at 221,848 kB -- 100 MB above a fresh
# ASan worker -- and the 200 MB body read as +242 MB. ASan's allocator does not
# hand pages back under pressure, and by then the box has plenty, so the reading
# is of the machine and not of this code.
#
# Declined rather than loosened, because a bound wide enough to pass there would
# not catch an accumulation in Release either, and counted in its own column so
# a nightly is not red for something nobody can act on -- which is exactly what
# test_abrupt_client_abort.sh does with its own RSS bound, for the same reason.
SANITIZED=""
# grep and not grep -q, deliberately.  -q exits at the first match, nm gets
# SIGPIPE, and under `set -o pipefail` the pipeline reports 141 -- so the test
# read "not sanitized" precisely when it WAS, and the two RSS assertions below
# stayed armed under ASan.  test_abrupt_client_abort.sh spells it this way for
# the same reason, and this tree's notes record the same trap three times over.
if nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then SANITIZED="ASan"; fi
not_asserted() {
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo "  NOT ASSERTED [$1]: $2"
    echo "        sanitized build ($SANITIZED) — its allocator's residency is what this would measure"
}

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

mkdir -p "$WWW"
cat > "$LUA" <<'LUAEOF'
-- Keyed by connection, which is the pattern rather than a detail: the first
-- draft of this file counted into globals and was caught by its own assertions
-- when the abandoned upload in case 6 left 4096 bytes in the counter for the
-- next request to inherit.  A body that never completes never reaches
-- on_http_request, so nothing there can be the reset.
local st = {}

function on_http_body(id, chunk, remaining)
    local e = st[id]
    if not e then e = { got = 0, chunks = 0, ends = 0 }; st[id] = e end
    e.got = e.got + #chunk
    e.chunks = e.chunks + 1
    -- remaining is what is still owed AFTER this chunk, so it reaches zero
    -- exactly once per body; counting that is how a build that fired the last
    -- call twice, or never, is caught.
    if remaining == 0 then e.ends = e.ends + 1 end
end

-- The other half of the contract: an upload that is abandoned is reported
-- here, with whatever arrived, so a script writing to a temp file knows to
-- remove it.  Nothing else would tell it.
function on_disconnect(id)
    local e = st[id]
    if e and e.got > 0 and e.ends == 0 then
        socketley.log("HB abandoned id=" .. id .. " partial=" .. e.got)
    end
    st[id] = nil
end

function on_http_request(req)
    local e = st[req.client_id] or { got = 0, chunks = 0, ends = 0 }
    st[req.client_id] = nil
    -- req.body is deliberately empty: the bytes were handed over as they
    -- arrived, and carrying them again is the memory this exists to avoid.
    -- Header names keep the case the client sent, so this asks for "Host".
    return { status = 200, body =
        "bytes=" .. e.got .. " chunks=" .. e.chunks .. " ends=" .. e.ends
        .. " reqbody=" .. #(req.body or "")
        .. " method=" .. tostring(req.method)
        .. " path=" .. tostring(req.path)
        .. " host=" .. tostring(req.headers and req.headers["Host"] or "?") }
end
LUAEOF

echo "=== Integration: a body bigger than memory reaches the script ==="
daemon_start "$BIN"

create_ok "a server that streams bodies" "$BIN" create server hb_stream -p "$P_S" \
    --lua "$LUA" --http "$WWW" -s
create_ok "and one that does not"        "$BIN" create server hb_plain  -p "$P_N" \
    --http "$WWW" -s
ready_tcp 127.0.0.1 "$P_S" >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_N" >/dev/null 2>&1 || true

WPID=$("$BIN" stats hb_stream 2>/dev/null | awk -F: '/^pid:/ {gsub(/[^0-9]/,"",$2); print $2}' | head -1)
rss() { awk '/VmRSS/{print $2}' "/proc/$WPID/status" 2>/dev/null || echo 0; }

post() {   # $1=port $2=megabytes ; prints "<status>|<body>"
    timeout 180 python3 - "$1" "$2" <<'PYEOF' 2>/dev/null || true
import socket, sys
port, mb = int(sys.argv[1]), int(sys.argv[2])
body = b"u" * (mb * 1024 * 1024)
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(120)
try:
    s.sendall(("POST /upload HTTP/1.1\r\nHost: h.example\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % len(body)).encode())
    s.sendall(body)
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(65536)
        if not c: break
        buf += c
    head, rest = (buf.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in buf else (buf, b""))
    s.settimeout(8)
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            rest += c
    except Exception:
        pass
    print("%s|%s" % (head.split(b"\r\n")[0].decode(errors="replace"),
                     rest.decode(errors="replace").strip()))
except Exception as e:
    print("ERR:%s|" % type(e).__name__)
finally:
    s.close()
PYEOF
}

# ─── 1. A body far past the old bound is accepted, whole ─────────────────────
A=$(post "$P_S" 50)
check "a 50 MB body is answered 200"  "HTTP/1.1 200 OK" "${A%%|*}"
AB="${A#*|}"
check "and every byte reached the script" "bytes=52428800" \
      "$(printf '%s\n' "$AB" | grep -oE 'bytes=[0-9]+')"
# The end of the body is signalled once. A build that never reached zero would
# leave a producer waiting, and one that reached it twice would answer twice.
check "the end is signalled exactly once" "ends=1" \
      "$(printf '%s\n' "$AB" | grep -oE 'ends=[0-9]+')"
check "and req.body carries none of it"   "reqbody=0" \
      "$(printf '%s\n' "$AB" | grep -oE 'reqbody=[0-9]+')"

# ─── 2. The head survives the body it was erased ahead of ───────────────────
# The views are rebased onto a copy the connection owns; a build that left them
# pointing into `partial` would read whatever the body overwrote.
check "the method is still the method" "method=POST"         "$(printf '%s\n' "$AB" | grep -oE 'method=[A-Z]+')"
check "the path survived"              "path=/upload"        "$(printf '%s\n' "$AB" | grep -oE 'path=[^ ]+')"
check "and so did a header value"      "host=h.example"      "$(printf '%s\n' "$AB" | grep -oE 'host=[^ ]+')"

# ─── 3. The assertion that distinguishes streaming from a bigger buffer ─────
# Not the size that is accepted -- a larger bound would do that -- but that the
# cost does not follow it.
BASE=$(rss)
post "$P_S" 50  >/dev/null
AFTER50=$(rss)
post "$P_S" 200 >/dev/null
AFTER200=$(rss)
GROWTH=$(( AFTER200 - AFTER50 ))
if [ -n "$SANITIZED" ]; then
    not_asserted "memory does not follow the body's size" \
        "RSS ${AFTER50}kB -> ${AFTER200}kB, growth ${GROWTH}kB"
    not_asserted "and stays inside a bound unrelated to it" \
        "RSS ${AFTER200}kB against a start of ${BASE}kB"
elif [ "$GROWTH" -lt 20480 ]; then
    ok
    if [ "$AFTER200" -lt $(( BASE + 61440 )) ]; then ok; else
        bad "and stays inside a bound unrelated to it" \
            "RSS ${AFTER200}kB against a start of ${BASE}kB; 200 MB was received"; fi
else
    bad "memory does not follow the body's size" \
        "RSS was ${AFTER50}kB after 50 MB and ${AFTER200}kB after 200 MB, a growth" \
        "of ${GROWTH}kB -- four times the body for barely more memory is the claim"
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
fi

# ─── 4. A script without the callback is unchanged, including its refusal ────
# The opt-in is the definition, so this is the control: same server, same POST,
# no on_http_body.
N=$(post "$P_N" 2)
check "without the callback a 2 MB body is still 413" "HTTP/1.1 413 Content Too Large" "${N%%|*}"

# ─── 5. A request pipelined behind a streamed body is still served ───────────
# The body path ends by going back to the top of parse_partial, and what is
# left in `partial` is the next request. A build that cleared instead of
# consuming would drop it.
PIPE=$(timeout 90 python3 - "$P_S" <<'PYEOF' 2>/dev/null || true
import socket, sys
port = int(sys.argv[1])
body = b"v" * (3 * 1024 * 1024)
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(60)
s.sendall(("POST /one HTTP/1.1\r\nHost: h.example\r\nContent-Length: %d\r\n"
           "Connection: keep-alive\r\n\r\n" % len(body)).encode())
s.sendall(body)
# The second request goes out immediately behind the first one's last byte.
s.sendall(b"GET /two HTTP/1.1\r\nHost: h.example\r\nConnection: close\r\n\r\n")
data = b""
try:
    while True:
        c = s.recv(65536)
        if not c: break
        data += c
except Exception:
    pass
s.close()
print("STATUSES=%d" % data.count(b"HTTP/1.1 "))
PYEOF
)
check "two answers come back for two requests" "STATUSES=2" "$PIPE"

# ─── 6. A client that promises more than it sends ────────────────────────────
# The body never completes, so the request is never dispatched; what must not
# happen is a hang or a runtime that stops serving.
timeout 40 python3 - "$P_S" <<'PYEOF' >/dev/null 2>&1 || true
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(5)
s.sendall(b"POST /short HTTP/1.1\r\nHost: h\r\nContent-Length: 10485760\r\n"
          b"Connection: close\r\n\r\n" + b"x" * 4096)
s.close()
PYEOF
sleep 2.5

# The script IS told, through on_disconnect, with what arrived -- which is the
# only signal an upload that never finished produces, and what a script writing
# to a temp file needs in order to remove it.
AB=$(grep -o 'HB abandoned id=[0-9]* partial=[0-9]*' "$SOCKETLEY_DLOG" | tail -1) || true
check "an abandoned upload is reported with what arrived" "partial=4096" \
      "$(printf '%s\n' "$AB" | grep -oE 'partial=[0-9]+')"

# ─── 7. And it is still serving afterwards ──────────────────────────────────
Z=$(post "$P_S" 1)
check "the runtime serves after all of it" "HTTP/1.1 200 OK" "${Z%%|*}"
check "and counts correctly again"         "bytes=1048576" \
      "$(printf '%s\n' "${Z#*|}" | grep -oE 'bytes=[0-9]+')"
check "the runtime is up"                  "Up" \
      "$("$BIN" ps -a 2>/dev/null | awk '$2=="hb_stream" { print $7 }')"

echo "  measured: rss base=${BASE}kB after50=${AFTER50}kB after200=${AFTER200}kB growth=${GROWTH}kB"
if [ "$SKIP" -gt 0 ]; then
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $SKIP not asserted under $SANITIZED)"
else
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
fi
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "    first: $A"; echo "  FAILED"; fi
[ "$FAIL" -eq 0 ]
