#!/usr/bin/env bash
# Integration test: a generated response larger than memory.
#
# ─── THE LAST SIDE OF THE SAME BOUND ────────────────────────────────────────
#
# Four cases, and three of them were already answered by this point:
#
#                  known length                unknown length
#   inbound        on_http_body                on_http_body + chunked decode
#   outbound       splice + Range (files)      <- this one
#
# A FILE of any size was served by the splice path and a Range of it by the 206
# path. A GENERATED body of any size was not expressible at all, because
# on_http_request has to RETURN the body -- so "transcode a video", "assemble an
# export from the cache", "stream a CSV of ten million rows" all required the
# whole answer in memory first.
#
# self.respond_stream / self.send_chunk / self.end_response put the script on
# the same side of the bound its reads already have, and they pace through
# self.pending()/on_writable exactly as any other producer does. That
# composition is the point: a stream without backpressure is only a slower way
# to run out of memory, which is the sentence this session started from.
#
# ─── THREE DECISIONS THAT ARE REFUSALS ──────────────────────────────────────
#
# Content-Length, Transfer-Encoding and Connection are dropped from the script's
# own header table. A Content-Length beside a chunked body is a message carrying
# two answers to how long it is -- the exact framing hole this server refuses
# with a 400 on the way IN, so producing it on the way out would be absurd.
#
# send_chunk on a HEAD answers false rather than dropping the bytes. A HEAD asked
# for the headers and nothing else; a script that thinks it is sending a body to
# one has a bug, and this refusal is the only report of it.
#
# An empty chunk is swallowed as true rather than sent, because "0\r\n\r\n" is
# the terminator's spelling: passing it through as payload would end the response
# while the script was still writing it.
#
# ─── AND ONE THAT IS A DEFERRAL ─────────────────────────────────────────────
#
# end_response is reached from inside a Lua callback, and a request pipelined
# behind the streamed one is already buffered with its client waiting. Parsing it
# from there is re-entering the function that is running, so the connection's
# serial waits for the next loop turn -- the same mechanism on_writable uses, for
# the same reason. Case 7 is two requests on one socket, which is the only shape
# that reaches it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate streamresp

P=$((SL_PORT_BASE+1982))
NAMES="sr_srv"
LUA="$SOCKETLEY_TMPD/sr.lua"
WWW="$SOCKETLEY_TMPD/www"

PASS=0; FAIL=0; SKIP=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

# grep and not grep -q: -q exits at the first match, nm takes SIGPIPE, and under
# `set -o pipefail` that is 141 -- a check that reads "not sanitized" exactly
# when it is.  Written this way from the start here because the two files before
# it learned it the other way, one of them twice.
SANITIZED=""
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
-- A generated body, paced.  The row is deterministic so the client can check the
-- bytes and not only their number, and the pacing is the composition this file
-- exists to show: self.pending() against self.watermark(), resumed by
-- on_writable, which is how a body larger than memory leaves this process.
local ROW = string.rep("r", 4096)
local jobs = {}

local function pump(id)
    local j = jobs[id]
    if not j then return end
    while j.left > 0 do
        if (self.pending(id) or 0) >= self.watermark() then return end
        local okay, why = self.send_chunk(id, ROW)
        if not okay then
            socketley.log("SR refused id=" .. id .. " left=" .. j.left
                .. " why=[" .. tostring(why) .. "]")
            jobs[id] = nil
            return
        end
        j.left = j.left - 1
        j.sent = j.sent + 1
    end
    socketley.log("SR done id=" .. id .. " want=" .. j.want
        .. " rows=" .. j.sent .. " resumed=" .. j.resumed)
    self.end_response(id)
    jobs[id] = nil
end

function on_writable(id)
    local j = jobs[id]
    if j then j.resumed = j.resumed + 1 end
    pump(id)
end

function on_disconnect(id) jobs[id] = nil end

function on_http_request(req)
    local p = req.path or "/"

    if p == "/twice" then
        -- Starting a response twice is a script bug and has to be named.
        local a = self.respond_stream(req.client_id, 200, {})
        local b, why = self.respond_stream(req.client_id, 200, {})
        socketley.log("SR twice first=" .. tostring(a) .. " second=" .. tostring(b)
            .. " why=[" .. tostring(why) .. "]")
        self.send_chunk(req.client_id, "one-only")
        self.end_response(req.client_id)
        return

    elseif p == "/nostart" then
        -- A chunk with no response open: refused, and the reason says so.
        local okay, why = self.send_chunk(req.client_id, "nope")
        socketley.log("SR nostart ok=" .. tostring(okay) .. " why=[" .. tostring(why) .. "]")
        return { status = 200, body = "fell-back-to-a-normal-answer" }

    elseif p == "/head" then
        self.respond_stream(req.client_id, 200, {["Content-Type"] = "text/plain"})
        local okay, why = self.send_chunk(req.client_id, "body")
        socketley.log("SR head ok=" .. tostring(okay) .. " why=[" .. tostring(why) .. "]")
        self.end_response(req.client_id)
        return

    elseif p == "/lie" then
        -- The headers this owns are dropped from the script's table rather than
        -- emitted beside the ones it sets.
        self.respond_stream(req.client_id, 201, {
            ["Content-Type"]   = "text/plain",
            ["Content-Length"] = "999999",
            ["Transfer-Encoding"] = "gzip",
            ["X-Kept"]         = "yes",
        })
        self.send_chunk(req.client_id, "short")
        self.end_response(req.client_id)
        return
    end

    -- /rows/<n>
    local n = tonumber(p:match("^/rows/(%d+)$") or "") or 4
    jobs[req.client_id] = { left = n, want = n, sent = 0, resumed = 0 }
    if not self.respond_stream(req.client_id, 200, {["Content-Type"] = "text/plain"}) then
        jobs[req.client_id] = nil
        return { status = 500, body = "could not start\n" }
    end
    pump(req.client_id)
end
LUAEOF

echo "=== Integration: a generated response larger than memory ==="
daemon_start "$BIN"

create_ok "a streaming server" "$BIN" create server sr_srv -p "$P" \
    --lua "$LUA" --http "$WWW" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

WPID=$("$BIN" stats sr_srv 2>/dev/null | awk -F: '/^pid:/ {gsub(/[^0-9]/,"",$2); print $2}' | head -1)
rss() { awk '/VmRSS/{print $2}' "/proc/$WPID/status" 2>/dev/null || echo 0; }

# One client for every case; it decodes the chunked framing itself, so a build
# that wrote a malformed size line is caught here rather than believed.
get() {   # $1=path $2=method $3=keepalive("1"/"") ; prints "status|te|cl|bytes|sha|extra"
    timeout 300 python3 - "$P" "$1" "${2:-GET}" "${3:-}" <<'PYEOF' 2>/dev/null || true
import hashlib, socket, sys
port, path, method, keep = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
# 300 and not 120: under suite load a 200 MB body takes longer than a quiet box
# suggests, and a timeout is the harness giving up rather than an answer.
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(300)
req = ("%s %s HTTP/1.1\r\nHost: h\r\nConnection: %s\r\n\r\n"
       % (method, path, "keep-alive" if keep else "close")).encode()
s.sendall(req)
if keep:
    # Pipelined immediately behind it: its answer can only come from the deferred
    # re-parse, because nothing else will read this socket again.
    s.sendall(b"GET /rows/2 HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")

buf = b""
while b"\r\n\r\n" not in buf:
    c = s.recv(65536)
    if not c: break
    buf += c
head, rest = (buf.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in buf else (buf, b""))
hd = head.decode(errors="replace")

def field(k):
    for line in hd.split("\r\n"):
        if line.lower().startswith(k + ":"):
            return line.split(":", 1)[1].strip()
    return ""

# Decoded as it arrives, with a bounded buffer: `raw += c` over 200 MB in 64 KB
# pieces is quadratic, and the first draft of this driver came back empty for
# exactly that reason -- a harness that could not read what the server sent.
chunked = field("transfer-encoding").lower() == "chunked"
h = hashlib.sha256()
total = 0
# `rest` too, and not only `head` and the later reads: the first read stops at
# the header terminator but can carry far past it, so a pipelined second
# response's status line may already be in there.  Counting only `head` made
# this case pass or fail depending on where the kernel split the reads.
statuses = head.count(b"HTTP/1.1 ") + rest.count(b"HTTP/1.1 ")
buf = bytearray(rest)
ok = True
want = 0          # bytes of the current chunk still to take
done = False

def pump():
    global buf, want, total, ok, done, statuses
    while True:
        if want == -1:
            # A payload that ended exactly at a read boundary owes its trailing
            # CRLF, and that is a state of its own.  Without it the next pump()
            # saw want == 0, read the CRLF as a chunk header and int(b'', 16)
            # threw -- reported as a body truncated at a random point, about one
            # run in five on the 200 MB case and never on a short one, because
            # the odds are per chunk and this case has 51,200 of them.  Captured
            # at 41,758,720 bytes with the buffer starting b'\r\n1000\r\nrrrr'.
            if len(buf) < 2: return
            if buf[0] != 13 or buf[1] != 10: ok = False; done = True; return
            del buf[:2]; want = 0
            continue
        if want > 0:
            take = min(want, len(buf))
            if take == 0: return
            h.update(memoryview(buf)[:take]); total += take
            del buf[:take]; want -= take
            if want == 0:
                if len(buf) < 2:
                    want = -1
                    return
                if buf[0] != 13 or buf[1] != 10: ok = False; done = True; return
                del buf[:2]
            continue
        if not chunked:
            if not buf: return
            h.update(buf); total += len(buf); del buf[:]
            continue
        # buf.find on the bytearray itself: bytes(buf) copied the WHOLE buffer
        # once per chunk, which over 200 MB of 4 KB rows is 51,200 copies of up
        # to 256 KB -- the driver, not the server, and it made a working server
        # look like it stalled at 85%.
        nl = buf.find(b"\r\n")
        if nl < 0:
            if len(buf) > 512: ok = False; done = True
            return
        try:    n = int(bytes(buf[:nl]).split(b";")[0], 16)
        except Exception: ok = False; done = True; return
        del buf[:nl + 2]
        if n == 0: done = True; return
        want = n

pump()
try:
    while not done:
        c = s.recv(1 << 18)
        if not c: break
        statuses += c.count(b"HTTP/1.1 ")
        buf += c
        pump()
    # The first body has ended.  With a request pipelined behind it the socket
    # still owes a second answer, and stopping at the terminator is why the
    # first draft of this driver saw one status line for two requests -- a
    # harness closing the connection before the thing it was asserting arrived.
    if keep:
        s.settimeout(10)
        while True:
            c = s.recv(1 << 18)
            if not c: break
            statuses += c.count(b"HTTP/1.1 ")
except Exception:
    pass
s.close()

print("%s|%s|%s|%d|%s|framed=%d statuses=%d" % (
    hd.split("\r\n")[0], field("transfer-encoding"), field("content-length"),
    total, h.hexdigest()[:16], 1 if ok else 0, statuses))
PYEOF
}

f() { printf '%s\n' "$2" | cut -d'|' -f"$1"; }
# The digest the client prints for a body of $1 rows, so a body of the right length and the wrong bytes fails.
rows_sha() { python3 -c 'import hashlib, sys
h = hashlib.sha256(); r = b"r" * 4096
for _ in range(int(sys.argv[1])): h.update(r)
print(h.hexdigest()[:16])' "$1"; }

# ─── 1. A streamed answer is chunked, complete and correctly framed ─────────
A=$(get /rows/4)
check "a streamed response is a 200"      "HTTP/1.1 200 OK" "$(f 1 "$A")"
check "declared chunked"                  "chunked"         "$(f 2 "$A")"
# Content-Length beside it is the framing hole this server refuses on the way in.
check "and carries no Content-Length"     ""                "$(f 3 "$A")"
check "the body is every row"             "16384"           "$(f 4 "$A")"
check "and every row's bytes"             "$(rows_sha 4)"   "$(f 5 "$A")"
case "$(f 6 "$A")" in *framed=1*) ok ;;
    *) bad "the chunk framing decodes" "got '$(f 6 "$A")' -- a size line the client could not read" ;; esac

# ─── 2. Larger than memory, paced by on_writable ────────────────────────────
# 200 MB of generated rows through a bound of 8 MiB: it can only arrive if the
# producer stopped at the watermark and was called back.
BASE=$(rss)
B=$(get /rows/51200)
check "200 MB of generated body arrives" "209715200" "$(f 4 "$B")"
check "and it is the generated bytes"    "$(rows_sha 51200)" "$(f 5 "$B")"
# want=51200 in the pattern, so this cannot read another case's line -- the
# first draft grepped the last "SR done" of any case and reported resumed=0 from
# a four-row one when the big case had not finished at all.
RES=$(grep -o 'SR done id=[0-9]* want=51200 rows=[0-9]* resumed=[0-9]*' "$SOCKETLEY_DLOG" | tail -1) || true
R=$(printf '%s\n' "$RES" | grep -oE 'resumed=[0-9]+' | cut -d= -f2)
if [ "${R:-0}" -gt 0 ]; then ok; else
    bad "and on_writable is what let it continue" \
        "resumed=${R:-0} -- 200 MB through an 8 MiB queue cannot happen without" \
        "the producer being called back, so this arrived some other way"; fi
AFTER=$(rss)
GROWTH=$(( AFTER - BASE ))
if [ -n "$SANITIZED" ]; then
    not_asserted "and memory does not follow the body" \
        "RSS ${BASE}kB -> ${AFTER}kB, growth ${GROWTH}kB"
elif [ "${BASE:-0}" -le 0 ] || [ "${AFTER:-0}" -le 0 ]; then
    # A worker whose RSS could not be read reads as 0kB, which is no growth and no measurement.
    bad "and memory does not follow the body" \
        "worker pid '${WPID}' gave RSS ${BASE:-?}kB -> ${AFTER:-?}kB -- nothing was measured"
elif [ "$GROWTH" -lt 30720 ]; then
    ok
else
    bad "and memory does not follow the body" \
        "RSS ${BASE}kB -> ${AFTER}kB, a growth of ${GROWTH}kB for 200 MB of body" \
        "that is supposed to leave as it is generated"
fi

# ─── 3. The headers this owns are not the script's to set ───────────────────
L=$(get /lie)
check "a 201 is a 201"                    "HTTP/1.1 201 Created" "$(f 1 "$L")"
check "its Content-Length is dropped"     ""         "$(f 3 "$L")"
check "its Transfer-Encoding is ours"     "chunked"  "$(f 2 "$L")"
check "and its own headers survive"       "5"        "$(f 4 "$L")"

# ─── 4. A HEAD gets the headers and no body, and is told so ─────────────────
H=$(get /head HEAD)
check "a HEAD is answered"            "HTTP/1.1 200 OK" "$(f 1 "$H")"
check "with no body at all"           "0"               "$(f 4 "$H")"
HL=$(grep -o 'SR head .*' "$SOCKETLEY_DLOG" | tail -1) || true
case "$HL" in
    *"ok=false"*) ok ;;
    *) bad "and send_chunk says so rather than dropping it" \
           "got '${HL:-<nothing>}' -- a script sending a body to a HEAD has a bug" \
           "and this refusal is its only report" ;;
esac
case "$HL" in *HEAD*) ok ;;
    *) bad "naming the reason" "got '${HL:-<nothing>}'" ;; esac

# ─── 5. Starting twice is refused, and once still works ────────────────────
T=$(get /twice)
check "a second respond_stream does not answer twice" "HTTP/1.1 200 OK" "$(f 1 "$T")"
check "the body is the one response"      "8" "$(f 4 "$T")"
TL=$(grep -o 'SR twice .*' "$SOCKETLEY_DLOG" | tail -1) || true
case "$TL" in *"first=true"*"second=false"*) ok ;;
    *) bad "the second start is refused" "got '${TL:-<nothing>}'" ;; esac

# ─── 6. A chunk with no response open is refused, and the fallback still runs ─
# The guard must stop a SECOND answer, not the first one: a script that only
# tried to send a chunk has not answered at all, so the ordinary return applies.
NS=$(get /nostart)
check "a normal answer still follows a refused chunk" "HTTP/1.1 200 OK" "$(f 1 "$NS")"
check "and it is that answer"  "28" "$(f 4 "$NS")"
NL=$(grep -o 'SR nostart .*' "$SOCKETLEY_DLOG" | tail -1) || true
case "$NL" in *"ok=false"*) ok ;;
    *) bad "the chunk was refused" "got '${NL:-<nothing>}'" ;; esac

# ─── 7. And a request pipelined behind a streamed one is served ─────────────
# The only case that reaches the deferred re-parse: end_response runs inside a
# Lua callback, so the buffered next request cannot be parsed from there.
K=$(get /rows/3 GET 1)
check "the first answer arrives"  "HTTP/1.1 200 OK" "$(f 1 "$K")"
ST=$(printf '%s\n' "$(f 6 "$K")" | grep -oE 'statuses=[0-9]+' | cut -d= -f2)
if [ "${ST:-0}" -ge 2 ]; then ok; else
    bad "and so does the one pipelined behind it" \
        "saw ${ST:-0} status lines on the socket -- the buffered second request" \
        "was never parsed, so its client waits for ever"; fi

# ─── 8. Still serving ───────────────────────────────────────────────────────
Z=$(get /rows/2)
check "the runtime serves after all of it" "8192" "$(f 4 "$Z")"
check "with the right bytes" "$(rows_sha 2)" "$(f 5 "$Z")"
check "and is up" "Up" "$("$BIN" ps -a 2>/dev/null | awk '$2=="sr_srv" { print $7 }')"

echo "  measured: 200MB=[$RES] rss ${BASE}kB->${AFTER}kB (+${GROWTH}kB)"
if [ "$SKIP" -gt 0 ]; then
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $SKIP not asserted under $SANITIZED)"
else
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
fi
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "    first: $A"; echo "  FAILED"; }
[ "$FAIL" -eq 0 ]
