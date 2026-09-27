#!/usr/bin/env bash
# Integration test: the request headers a script reads are the bytes that
# arrived, and they outlive the buffer they were parsed out of.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# `http_request::headers` is a vector of `pair<string_view, string_view>` whose
# views point into `conn->partial` — the connection's own read buffer, which
# `handle_http_request` erases under them the moment the answer is queued.  The
# Lua table used to be filled with `lua_headers[std::string(k)] = std::string(v)`
# and is now filled from the views directly, which is correct only because sol2
# pushes the bytes into the Lua heap itself.  Two things could be untrue of that
# and neither shows up as a compile error:
#
#   * the LENGTH.  A `string_view` over a parsed header is not NUL-terminated:
#     the name stops at the colon and the value stops before the CRLF, with the
#     rest of the request sitting immediately after.  Anything that reads
#     `.data()` as a C string runs past the end and picks up the next header.
#     That is why every assertion below carries the length the script measured
#     and not only the text — a value read as a C string is still a PREFIX
#     match, so `case $v in "wanted"*)` would have passed the broken build.
#
#   * the LIFETIME.  If the bytes were referenced rather than copied, a header
#     kept in a Lua global would read as whatever landed in that buffer next.
#     Assertion 7 stores one and reads it back on a later connection.
#
# ─── WHY THE SPECIAL CHARACTERS ─────────────────────────────────────────────
#
# A header value is opaque bytes.  The set below is chosen so that each class
# of mishandling has somewhere to show: a colon and a semicolon for anything
# that re-splits the line, an equals and a comma for anything that parses the
# value, a UTF-8 sequence for anything that assumes ASCII, an embedded tab for
# anything that trims more than the leading and trailing OWS it is supposed to,
# and an EMPTY value — which is the sharpest of them, because a C-string read
# of an empty value returns the whole rest of the request rather than "".
#
# Both sides of libstdc++'s 15-byte small-string boundary are represented on
# purpose: the copies this change removes were only ever allocations for the
# strings above 15 bytes, so a test made only of long ones would not have
# covered the path that was already allocation-free.
#
# ─── WHY DUPLICATES ─────────────────────────────────────────────────────────
#
# A table has one slot per key, so a header sent twice can only be one of them,
# and the vector keeps both.  Last-wins is what the table assignment has always
# produced and this file pins it, because it is a property of the FILL and the
# fill is what changed.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luahttphdr

PORT=$((SL_PORT_BASE+1322))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   hdrs >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove hdrs >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the headers a script reads are the bytes that arrived ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/hdrs.lua"
cat > "$LUA" <<'LUAEOF'
-- One header per line as `name<TAB>bytelength<TAB>value`, sorted, so the shell
-- can assert a length as well as a text and a truncation cannot hide behind a
-- prefix match.
local kept = nil

function on_http_request(req)
    if req.path == "/keep" then
        -- Held past the return, which is where the buffer these views point
        -- into is erased.
        kept = req.headers["X-Keep"]
        return { status = 200, body = "stored" }
    end
    if req.path == "/kept" then
        if kept == nil then return { status = 200, body = "KEPT\tnil" } end
        return { status = 200, body = "KEPT\t" .. #kept .. "\t" .. kept }
    end

    local names = {}
    for k in pairs(req.headers) do names[#names + 1] = k end
    table.sort(names)
    local out = { "COUNT\t" .. #names }
    for _, k in ipairs(names) do
        local v = req.headers[k]
        out[#out + 1] = k .. "\t" .. #v .. "\t" .. v
    end
    return { status = 200, body = table.concat(out, "\n") }
end
LUAEOF

create_ok "server with a header-reading handler created" "$BIN" create server hdrs \
    -p "$PORT" --lua "$LUA" -s
ready_tcp 127.0.0.1 "$PORT" 10 || echo "  NOTE: the runtime never accepted"

# ─── The client ─────────────────────────────────────────────────────────────
#
# Raw sockets rather than curl: this file has to send a header twice, send an
# empty value, send bytes curl would normalise, and send two requests down one
# connection.  Each invocation prints the bodies of the responses it read,
# separated by a line of ---.
PYC="$SOCKETLEY_TMPD/send.py"
cat > "$PYC" <<'PYEOF'
import socket, sys, os
port = int(os.environ["PORT"])
# argv: one "METHOD PATH" + raw header lines per request, requests split by "--"
groups, cur = [], []
for a in sys.argv[1:]:
    if a == "--":
        groups.append(cur); cur = []
    else:
        cur.append(a)
if cur: groups.append(cur)

raw = b""
for g in groups:
    line = g[0]
    head = line.encode("utf-8", "surrogateescape") + b"\r\n"
    for h in g[1:]:
        head += h.encode("utf-8", "surrogateescape") + b"\r\n"
    raw += head + b"\r\n"

s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(raw)
buf = b""
try:
    while True:
        d = s.recv(65536)
        if not d: break
        buf += d
        if buf.count(b"\r\n\r\n") >= len(groups):
            # Every response here is Content-Length'd; stop once each has a
            # head and its whole body.
            done, off = 0, 0
            while True:
                he = buf.find(b"\r\n\r\n", off)
                if he < 0: break
                head = buf[off:he].decode("latin-1")
                cl = 0
                for ln in head.split("\r\n"):
                    if ln.lower().startswith("content-length:"):
                        cl = int(ln.split(":", 1)[1])
                if len(buf) < he + 4 + cl: break
                done += 1; off = he + 4 + cl
            if done >= len(groups): break
except socket.timeout:
    pass
s.close()

off, out = 0, []
while off < len(buf):
    he = buf.find(b"\r\n\r\n", off)
    if he < 0: break
    head = buf[off:he].decode("latin-1")
    cl = 0
    for ln in head.split("\r\n"):
        if ln.lower().startswith("content-length:"):
            cl = int(ln.split(":", 1)[1])
    out.append(buf[he + 4: he + 4 + cl].decode("utf-8", "surrogateescape"))
    off = he + 4 + cl
sys.stdout.write("\n---\n".join(out))
PYEOF

export PORT
send() { python3 "$PYC" "$@" 2>/dev/null || true; }

# ─── The header set ─────────────────────────────────────────────────────────
#
# name:length:value, with the length written out rather than computed so that a
# typo in the fixture is a failure here and not a silently weakened assertion.
H_HOST="Host: 127.0.0.1:$PORT"
V_UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'      # 50, over SSO
V_SHORT='abc'                                                   # 3,  under SSO
V_EXACT15='0123456789abcde'                                     # 15, the boundary
V_16='0123456789abcdef'                                         # 16, one past it
V_PUNCT='a:b;c=d,e"f'"'"'g\h/i?j&k%l{m}n[o]p'                   # 31
V_UTF8='grüße-日本-✓'
V_TAB=$'in\tside'                                               # 7, tab kept and OWS trimmed
V_SPACED='  leading and trailing  '                             # OWS trimmed both ends

BODY=$(send "GET /echo HTTP/1.1" "$H_HOST" \
            "User-Agent: $V_UA" \
            "X-Short: $V_SHORT" \
            "X-Exact15: $V_EXACT15" \
            "X-Sixteen: $V_16" \
            "X-Punct: $V_PUNCT" \
            "X-Utf8: $V_UTF8" \
            "X-Tab: $V_TAB" \
            "X-Spaced: $V_SPACED" \
            "X-Empty:" \
            "X-MiXeD-CaSe: KeptAsSent" \
            "X-Dup: first" \
            "X-Dup: second" \
            "Connection: close")

# field NAME -> the "length<TAB>value" the script reported, or empty
field() { awk -F'\t' -v n="$1" '$1==n { sub(/^[^\t]*\t/, ""); print; exit }' <<<"$BODY"; }

# Control: the handler answered at all, before any assertion reads its output.
if [ -n "$BODY" ] && grep -q '^COUNT' <<<"$BODY"; then pass; else
    fail "control: the handler answered" \
         "the body was '${BODY:-<nothing>}'" \
         "every assertion below reads this body, so an empty one would make" \
         "each of them vacuously pass on a server that answered nothing"
fi

# ─── Name and value arrive whole ────────────────────────────────────────────
#
# The length is the half that matters: a value read as a C string runs to the
# end of the request and still starts with the right characters.
check() {
    local name=$1 want_len=$2 want_val=$3
    local got; got=$(field "$name")
    if [ "$got" = "$want_len"$'\t'"$want_val" ]; then pass; else
        fail "header $name arrives whole" \
             "script saw [${got}], wanted [${want_len}	${want_val}]" \
             "the views are not NUL-terminated: the name stops at the colon and" \
             "the value before the CRLF, with the next header immediately after"
    fi
}

check "User-Agent"   50 "$V_UA"
check "X-Short"       3 "$V_SHORT"
check "X-Exact15"    15 "$V_EXACT15"
check "X-Sixteen"    16 "$V_16"
check "X-Punct"      31 "$V_PUNCT"
check "X-Tab"         7 "$V_TAB"
check "X-MiXeD-CaSe" 10 "KeptAsSent"

# UTF-8 by bytes, because # in Lua counts bytes and that is the right unit for
# a header value: 'grüße-日本-✓' is 18 bytes and 11 codepoints.
check "X-Utf8"       18 "$V_UTF8"

# The OWS rule, both ways: the spaces around the value go, the tab inside stays.
check "X-Spaced"     20 "leading and trailing"

# The empty value is the sharpest NUL-terminator probe in the file: read as a C
# string it is not "" but the whole remainder of the request.
check "X-Empty"       0 ""

# ─── A header sent twice is one entry, and it is the last one ───────────────
DUP=$(field "X-Dup")
if [ "$DUP" = $'6\tsecond' ]; then pass; else
    fail "a header sent twice is the last one" \
         "script saw [$DUP], wanted [6	second]" \
         "the vector keeps both; the table has one slot, and which one wins is" \
         "a property of the fill loop that this change rewrote"
fi

# And it really is ONE entry: the count pins that the duplicate did not become
# two keys and that no header was dropped on the way in.
#   Host + User-Agent + 8 X-* probes + MiXeD + Dup + Connection = 13
COUNT=$(awk -F'\t' '$1=="COUNT" { print $2; exit }' <<<"$BODY")
if [ "$COUNT" = "13" ]; then pass; else
    fail "every header is present, exactly once" \
         "the script counted $COUNT keys, wanted 13" \
         "12 distinct names were sent plus one repeat; a count of 14 would mean" \
         "the repeat made a second key and a lower one means headers were lost"
fi

# ─── The bytes outlive the buffer they were parsed from ─────────────────────
#
# `conn->partial` is erased inside the same call that filled this table, and
# this connection is then closed and its struct returned to the pool.  A value
# that was referenced rather than copied reads as whatever lands there next.
KEEPV='keep-me-0123456789-and-this-half-is-past-the-small-string-boundary'
send "GET /keep HTTP/1.1" "$H_HOST" "X-Keep: $KEEPV" "Connection: close" >/dev/null

# Traffic between the store and the read, so the buffer has been written over
# by the time the global is read back.
for _ in 1 2 3; do
    send "GET /echo HTTP/1.1" "$H_HOST" "X-Noise: $V_UA$V_UA$V_UA" "Connection: close" >/dev/null
done

KEPT=$(send "GET /kept HTTP/1.1" "$H_HOST" "Connection: close")
if [ "$KEPT" = "KEPT"$'\t'"${#KEEPV}"$'\t'"$KEEPV" ]; then pass; else
    fail "a header held in a global is still its own bytes" \
         "the script read back [$KEPT], wanted [KEPT	${#KEEPV}	$KEEPV]" \
         "sol2 has to copy into the Lua heap; if it referenced the view instead," \
         "this reads as whatever the pooled connection buffer holds now"
fi

# ─── Two requests on one connection each see their own ──────────────────────
#
# Pipelined, so the second request's bytes are already in `partial` while the
# first is being answered — which is where a shared buffer and a stale view
# would show as the first request seeing the second's header.
PIPE=$(send "GET /echo HTTP/1.1" "$H_HOST" "X-Req: one" \
       -- "GET /echo HTTP/1.1" "$H_HOST" "X-Req: two-is-longer-than-fifteen" "Connection: close")
FIRST=${PIPE%%$'\n---\n'*}
SECOND=${PIPE##*$'\n---\n'}
G1=$(awk -F'\t' -v n="X-Req" '$1==n { sub(/^[^\t]*\t/, ""); print; exit }' <<<"$FIRST")
G2=$(awk -F'\t' -v n="X-Req" '$1==n { sub(/^[^\t]*\t/, ""); print; exit }' <<<"$SECOND")
if [ "$G1" = $'3\tone' ] && [ "$G2" = $'26\ttwo-is-longer-than-fifteen' ]; then pass; else
    fail "pipelined requests each see their own header" \
         "first saw [$G1] (wanted [3	one]), second saw [$G2] (wanted [26	two-is-longer-than-fifteen])" \
         "both requests are in one buffer at once, so a view that outlived its" \
         "request would show here as the first reading the second's value"
fi

# ─── ...and none of the one before it ───────────────────────────────────────
#
# The list the fields are collected into is kept by the connection between
# requests, so a list handed on without being emptied gives the second request
# the first one's entries -- views at offsets that now hold the second
# request's bytes.  Last-wins hides that for a name both requests send, which
# is why these names are sent only by the first and the COUNT is asserted.
PIPE=$(send "GET /echo HTTP/1.1" "$H_HOST" "X-Only-First: 1" "X-Also-First: 22" \
       -- "GET /echo HTTP/1.1" "$H_HOST" "Connection: close")
FIRST=${PIPE%%$'\n---\n'*}
SECOND=${PIPE##*$'\n---\n'}
C1=$(head -1 <<<"$FIRST")
C2=$(head -1 <<<"$SECOND")
N2=$(awk -F'\t' 'NR > 1 { printf "%s,", $1 }' <<<"$SECOND")
if [ "$C1" = $'COUNT\t3' ] && [ "$C2" = $'COUNT\t2' ] && [ "$N2" = "Connection,Host," ]; then pass; else
    fail "a pipelined request sees none of the headers of the request before it" \
         "first said [$C1] (wanted [COUNT	3]), second said [$C2] with names [$N2]" \
         "(wanted [COUNT	2] with names [Connection,Host,])" \
         "the header list is reused across requests on a connection; one handed" \
         "on without being cleared adds the first request's fields to the second"
fi

# ─── The daemon survived it ─────────────────────────────────────────────────
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive the header probes"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
