#!/usr/bin/env bash
# Integration test: on_read hands a client's read to the script as a view of
# the buffer, with no string made of it.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# A view reads memory the script does not own, so what it must never do is
# read outside the call's bytes or after the call: every method is bounded by
# the bytes of the call that is running and checks the generation it was made
# for.  The peer cuts its bytes so each cut is its own read, pacing on the
# script's answers, which walks the in-place framing, the joined first line and
# the copying path the way test_lua_batch_lines.sh walks them for on_messages.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
#   the bytes            one call per read, the same bytes on_messages gets:
#                          a split line joined, many lines in one view, CRLF
#                          and blank lines as sent
#   the methods          byte, sub, eq and find answer what string.byte,
#                          string.sub, == and string.find(plain) answer on
#                          the same bytes, for every index in and around them
#   lines()              the lines on_message would be handed, \r cut and
#                          blank ones skipped
#   END                  found with v:eq, after 2014 lines counted with v:find
#   v:sub                a copy that is still right after the call
#   a stale view         every method, and a kept iterator, raise the
#                          documented error from a timer and in a later call,
#                          and the runtime goes on reading
#   unreachable          no debug, no ffi, no jit.util, no metatable table,
#                          no pairs, rawget or fields but gen; gen is read-only
#   observers            -w and total_messages see each line as on_message,
#                          and total_messages without -w as well
#   precedence           on_messages and on_message are never called
#   a stop in on_read    the rest of the view still reads in that call, and
#                          nothing of that read or a later one is delivered
#   --connections        each connection's own id
#   --udp                a datagram is a view of one line with its \n
#   an error             reported naming on_read, as on_messages' are
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate onreadview

CPORT=$((SL_PORT_BASE+1745))
MPORT=$((SL_PORT_BASE+1746))
UPORT=$((SL_PORT_BASE+1747))
NPORT=$((SL_PORT_BASE+1748))
STATUS="$SOCKETLEY_TMPD/peer.status"
GO_STOP="$SOCKETLEY_TMPD/go.stop"
WOUT="$SOCKETLEY_TMPD/written.txt"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected [$2], got [$3]"; fi; }

cleanup() {
    for r in rv_cli rv_multi rv_count rv_udp; do
        "$BIN" stop   "$r" >/dev/null 2>&1 || true
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    for p in ${PEER_PID:-} ${MPEER_PID:-} ${NPEER_PID:-} ${UPEER_PID:-}; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

status_has() {
    local what=$1 deadline=$(( $(date +%s) + ${2:-20} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qxF "$what" "$STATUS" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# The script's lines with one tag, in order, from the daemon's log.
calls() { grep -a "$1 " "$SOCKETLEY_DLOG" 2>/dev/null | sed "s/.*$1 /$1 /"; }

listening() {
    for _ in $(seq 1 60); do
        ss -ltnH "sport = :$1" 2>/dev/null | grep -q . && return 0
        sleep 0.1
    done
}

echo "=== Integration: on_read hands a read over as a view ==="
daemon_start "$BIN"

# ─── One connection, every method ───────────────────────────────────────────
python3 - "$CPORT" "$STATUS" "$GO_STOP" <<'PY' >"$SOCKETLEY_TMPD/peer.log" 2>&1 &
import os, socket, sys, time
port, status_path, go_stop = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def say(s):
    with open(status_path, "a") as f:
        f.write(s + "\n")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
srv.settimeout(40)
c = srv.accept()[0]
c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
buf, lines = b"", 0
def acked(n, t=10):
    global buf, lines
    deadline = time.time() + t
    while lines < n:
        left = deadline - time.time()
        if left <= 0:
            return False
        c.settimeout(left)
        try:
            d = c.recv(65536)
        except socket.timeout:
            return False
        if not d:
            return False
        buf += d
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            w = line.split()
            if w[0] == b"ACK":
                lines += int(w[1])
            else:
                say("got " + line.decode())
    return True
time.sleep(0.3)
steps = [
    ((b"hel", b"lo wor", b"ld\n"), 1),
    ((b"one\ntwo\nthree\n",), 4),
    ((b"four\nfiv", b"e\nsix\nsev", b"en\n"), 8),
    ((b"crlf1\r\ncrlf2\r\n",), 10),
    ((b"blank1\n\n\r\nblank2\n",), 14),
    ((b"".join(b"bulk%d\n" % i for i in range(2000)) + b"END\n",), 2015),
]
for parts, want in steps:
    for i, p in enumerate(parts):
        if i:
            time.sleep(0.25)
        c.sendall(p)
    if not acked(want):
        say("stalled at %d lines, wanted %d" % (lines, want))
        sys.exit(1)
say("client delivered")
for _ in range(300):
    if os.path.exists(go_stop):
        break
    time.sleep(0.1)
c.sendall(b"STOP\nafter-stop\npart")
time.sleep(0.5)
try:
    c.sendall(b"ial\nlater\n")
except OSError:
    pass
say("stop sent")
time.sleep(3)
PY
PEER_PID=$!
listening "$CPORT"

cat > "$SOCKETLEY_TMPD/client.lua" <<'LUAEOF'
local function show(s) return (s:gsub("\r", "<CR>"):gsub("\n", "<LF>")) end
local calls, kept, kept_lines, copy, total = 0, nil, nil, nil, 0

-- What each method answers against what the string functions answer on the
-- same bytes, for every index in and around them.
local function compare(v, s)
    local n, bad, first = #s, 0, nil
    local function diff(what, a, b)
        if a ~= b then
            bad = bad + 1
            first = first or (what .. " view=" .. tostring(a) .. " string=" .. tostring(b))
        end
    end
    if v:len() ~= n then diff("len", v:len(), n) end
    diff("byte()", v:byte(), s:byte())
    for i = -n - 3, n + 3 do
        diff("byte(" .. i .. ")", v:byte(i), s:byte(i))
        diff("sub(" .. i .. ")", v:sub(i), s:sub(i))
        for j = -n - 3, n + 3 do
            local want = s:sub(i, j)
            diff("sub(" .. i .. "," .. j .. ")", v:sub(i, j), want)
            diff("eq(" .. i .. "," .. j .. ")", v:eq(i, j, want), true)
            diff("eq+(" .. i .. "," .. j .. ")", v:eq(i, j, want .. "x"), false)
            if #want > 0 then
                diff("eq-(" .. i .. "," .. j .. ")", v:eq(i, j, want:sub(1, -2) .. "\0"), false)
            end
        end
    end
    local needles = { "\n", "l", "lo", "", "zz", "\r\n", s, s .. "x", s:sub(2) }
    for _, nd in ipairs(needles) do
        local a1, a2 = v:find(nd)
        local b1, b2 = s:find(nd, 1, true)
        diff("find(" .. show(nd) .. ")", tostring(a1) .. "," .. tostring(a2), tostring(b1) .. "," .. tostring(b2))
        for _, init in ipairs({ -n - 3, -n, -2, -1, 0, 1, 2, 2.5, -1.5, n, n + 1, n + 2, n + 3 }) do
            a1, a2 = v:find(nd, init)
            b1, b2 = s:find(nd, init, true)
            diff("find(" .. show(nd) .. "," .. init .. ")", tostring(a1) .. "," .. tostring(a2),
                 tostring(b1) .. "," .. tostring(b2))
        end
    end
    -- lines() against the lines on_message would be handed.
    local want, got = {}, {}
    for line in s:gmatch("([^\n]*)\n") do
        line = line:gsub("\r$", "")
        if line ~= "" then want[#want + 1] = line end
    end
    for i, j in v:lines() do got[#got + 1] = v:sub(i, j) end
    diff("lines", table.concat(got, "|"), table.concat(want, "|"))
    return bad, first
end

local function seal(v)
    local out = {}
    local function put(k, val) out[#out + 1] = k .. "=" .. tostring(val) end
    put("debug", type(debug))
    put("ffi", (pcall(require, "ffi")))
    put("loaded.ffi", type(package.loaded.ffi))
    put("jit.util", (pcall(require, "jit.util")))
    put("mt", type(getmetatable(v)))
    put("pairs", (pcall(pairs, v)))
    put("rawget", (pcall(rawget, v, "p")))
    put("tostring", tostring(v))
    put("p", (pcall(function() return v.p end)) and tostring(v.p) or "raises")
    put("n", (pcall(function() return v.n end)) and tostring(v.n) or "raises")
    put("gen", type(v.gen))
    put("setgen", (pcall(function() v.gen = 1 end)))
    put("index", (pcall(function() return v[0] end)))
    put("notaview", (select(2, pcall(v.len, {})) or ""):match("not on a view") ~= nil)
    socketley.log("SEAL " .. table.concat(out, " "))
end

local function stale(v, it)
    local out = {}
    local function try(name, f)
        local ok, err = pcall(f)
        out[#out + 1] = name .. "=" .. (ok and "read" or
            (tostring(err):find("a view is valid only inside the on_read call it was given to; " ..
                                "copy what you keep with view:sub", 1, true) and "stale" or tostring(err)))
    end
    try("len", function() return v:len() end)
    try("byte", function() return v:byte(1) end)
    try("sub", function() return v:sub(1, 3) end)
    try("eq", function() return v:eq(1, 3, "hel") end)
    try("find", function() return v:find("l") end)
    try("lines", function() return v:lines() end)
    try("iterator", function() return it() end)
    return table.concat(out, " ")
end

function on_read(v, id)
    calls = calls + 1
    local s = v:sub(1, -1)
    local nl, i, ended = 0, 1, nil
    while true do
        local j = v:find("\n", i)
        if not j then break end
        if v:eq(i, j - 1, "END") then
            ended = total
        elseif v:eq(i, j - 1, "STOP") then
            socketley.log("RSTOP [" .. show(s) .. "]")
            socketley.stop(self.name)
            -- Still this call's bytes, read after the stop.
            socketley.log("RAFTERSTOP " .. v:len() .. " [" .. show(v:sub(i)) .. "]")
            return
        else
            total = total + 1
        end
        nl, i = nl + 1, j + 1
    end
    if nl > 20 then
        socketley.log("RCALL id=" .. id .. " lines=" .. nl .. " last=" .. show(s:sub(-9)))
    else
        socketley.log("RCALL id=" .. id .. " [" .. show(s) .. "]")
    end
    if #s <= 40 then
        local bad, first = compare(v, s)
        socketley.log("RCMP " .. bad .. (first and (" " .. first) or ""))
    end
    if calls == 1 then
        seal(v)
        kept, kept_lines, copy = v, v:lines(), v:sub(1, 5)
        socketley.set_timeout(50, function()
            socketley.log("RSTALE timer " .. stale(kept, kept_lines))
            socketley.log("RCOPY [" .. copy .. "]")
            -- Unprotected, so the timer raises, and the runtime has to go on reading.
            kept:len()
        end)
    elseif calls == 2 then
        socketley.log("RSTALE call " .. stale(kept, kept_lines))
    end
    if ended then self.send("done " .. ended) end
    self.send("ACK " .. nl)
end
function on_messages(chunk) socketley.log("RBATCH [" .. chunk .. "]") end
function on_message(msg) socketley.log("RPERLINE [" .. msg .. "]") end
LUAEOF

"$BIN" create client rv_cli -t "127.0.0.1:$CPORT" --lua "$SOCKETLEY_TMPD/client.lua" \
    -w "$WOUT" >/dev/null 2>&1
"$BIN" start rv_cli >/dev/null 2>&1

if status_has "client delivered" 30; then ok; else
    bad "every cut is delivered and answered" "peer says: $(tr '\n' ';' < "$STATUS" 2>/dev/null)"
fi
sleep 0.3

got=$(calls RCALL | head -7 | tr '\n' '|')
check "one call per read, the bytes as on_messages gets them" \
    "RCALL id=1 [hello world<LF>]|RCALL id=1 [one<LF>two<LF>three<LF>]|RCALL id=1 [four<LF>]|RCALL id=1 [five<LF>six<LF>]|RCALL id=1 [seven<LF>]|RCALL id=1 [crlf1<CR><LF>crlf2<CR><LF>]|RCALL id=1 [blank1<LF><LF><CR><LF>blank2<LF>]|" \
    "$got"
check "byte, sub, eq, find and lines answer as the string functions on every small read" \
    "RCMP 0|RCMP 0|RCMP 0|RCMP 0|RCMP 0|RCMP 0|RCMP 0|" "$(calls RCMP | head -7 | tr '\n' '|')"
bulk=$(calls RCALL | tail -n +8)
bulk_lines=0
while read -r line; do
    case "$line" in
        *lines=*) n=${line#*lines=}; bulk_lines=$((bulk_lines + ${n%% *})) ;;
        *) n=$(printf '%s' "$line" | grep -o '<LF>' | wc -l); bulk_lines=$((bulk_lines + n)) ;;
    esac
done <<< "$bulk"
check "2000 lines and END in one write are all in views" "2001" "$bulk_lines"
bulk_calls=$(printf '%s\n' "$bulk" | grep -c .)
if [ "$bulk_calls" -ge 1 ] && [ "$bulk_calls" -le 50 ]; then ok; else
    bad "2001 lines take far fewer than 2001 calls" "calls: $bulk_calls"
fi
check "END is found with v:eq after 2014 lines counted with v:find" "got done 2014" "$(grep -x 'got done.*' "$STATUS" | head -1)"
check "the script cannot reach ffi, the pointer or the view's insides" \
    "SEAL debug=nil ffi=false loaded.ffi=nil jit.util=false mt=string pairs=false rawget=false tostring=view p=raises n=raises gen=number setgen=false index=false notaview=true" \
    "$(calls SEAL | head -1)"
check "a view kept for a timer raises the documented error from every method" \
    "RSTALE timer len=stale byte=stale sub=stale eq=stale find=stale lines=stale iterator=stale" \
    "$(calls 'RSTALE timer' | head -1)"
check "a view kept for the next call raises it there too" \
    "RSTALE call len=stale byte=stale sub=stale eq=stale find=stale lines=stale iterator=stale" \
    "$(calls 'RSTALE call' | head -1)"
check "what v:sub copied is still right after the call" "RCOPY [hello]" "$(calls RCOPY | head -1)"
if grep -qa "a view is valid only inside the on_read call" "$SOCKETLEY_DLOG"; then ok; else
    bad "the timer's unprotected use is reported" "$(grep -a 'timer\|error' "$SOCKETLEY_DLOG" | tail -3)"
fi
check "on_messages and on_message are not called when on_read is defined" "" "$(calls RBATCH; calls RPERLINE)"

msgs=""
for _ in $(seq 1 30); do
    msgs=$({ "$BIN" stats rv_cli 2>/dev/null || true; } | awk -F: '$1 == "total_messages" { print $2; exit }')
    [ "$msgs" = 2013 ] && break
    sleep 0.1
done
check "total_messages counts the lines on_message would have had" "2013" "$msgs"

# ─── A stop inside on_read ──────────────────────────────────────────────────
before=$(calls RCALL | wc -l)
: > "$GO_STOP"
status_has "stop sent" 20 || bad "the peer sends its last reads" "peer says: $(tr '\n' ';' < "$STATUS")"
sleep 0.5
check "the call that stopped saw its read" "RSTOP [STOP<LF>after-stop<LF>]" "$(calls RSTOP | head -1)"
check "the rest of its view still reads after the stop, inside the call" \
    "RAFTERSTOP 16 [STOP<LF>after-stop<LF>]" "$(calls RAFTERSTOP | head -1)"
check "nothing of that read or a later one is delivered after the stop" "$before" "$(calls RCALL | wc -l)"

expect_w=$(printf '%s\n' "hello world" one two three four five six seven crlf1 crlf2 blank1 blank2
           for i in $(seq 0 1999); do echo "bulk$i"; done; printf '%s\n' END STOP after-stop)
if [ "$(cat "$WOUT" 2>/dev/null)" = "$expect_w" ]; then ok; else
    bad "-w writes every line as the per-line path does" \
        "first lines: $(head -12 "$WOUT" 2>/dev/null | tr '\n' '|')" "last: $(tail -3 "$WOUT" 2>/dev/null | tr '\n' '|')" \
        "lines: $(wc -l < "$WOUT" 2>/dev/null)"
fi

# ─── Two connections, each with its own id ──────────────────────────────────
python3 - "$MPORT" <<'PY' >"$SOCKETLEY_TMPD/mpeer.log" 2>&1 &
import socket, sys, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(4)
srv.settimeout(20)
conns = []
for _ in range(2):
    c = srv.accept()[0]
    c.settimeout(10)
    hello = b""
    while not hello.endswith(b"\n"):
        hello += c.recv(100)
    conns.append((c, hello.split()[1].decode()))
for c, hid in conns:
    c.sendall(b"ping " + hid.encode() + b"\n")
for c, hid in conns:
    got = b""
    while not got.endswith(b"\n"):
        got += c.recv(100)
    print("conn hello=%s answer=%s" % (hid, got.decode().strip()), flush=True)
time.sleep(1)
PY
MPEER_PID=$!
listening "$MPORT"
cat > "$SOCKETLEY_TMPD/multi.lua" <<'LUAEOF'
function on_connect(fd, id) self.send("hello " .. id) end
function on_read(v, id)
    for i, j in v:lines() do self.send("pong " .. id .. " " .. v:sub(i, j)) end
end
LUAEOF
"$BIN" create client rv_multi -t "127.0.0.1:$MPORT" --connections 2 --lua "$SOCKETLEY_TMPD/multi.lua" >/dev/null 2>&1
"$BIN" start rv_multi >/dev/null 2>&1
wait "$MPEER_PID" 2>/dev/null
got=$(sort "$SOCKETLEY_TMPD/mpeer.log" | tr '\n' '|')
check "each connection's on_read is handed its own id" \
    "conn hello=1 answer=pong 1 ping 1|conn hello=2 answer=pong 2 ping 2|" "$got"

# ─── Counted without an observer ────────────────────────────────────────────
# Without -w the count comes from the index the view walks, a path of its own.
python3 - "$NPORT" <<'PY' >/dev/null 2>&1 &
import socket, sys, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(1)
srv.settimeout(20)
c = srv.accept()[0]
time.sleep(0.3)
c.sendall(b"a\n\n\r\nb\r\n\r\r\n" + b"".join(b"l%d\n" % i for i in range(1000)) + b"\n\n")
time.sleep(3)
PY
NPEER_PID=$!
listening "$NPORT"
cat > "$SOCKETLEY_TMPD/count.lua" <<'LUAEOF'
local n = 0
function on_read(v)
    for i, j in v:lines() do
        n = n + 1
        if v:eq(i, j, "l999") then socketley.log("RCOUNT " .. n) end
    end
end
LUAEOF
"$BIN" create client rv_count -t "127.0.0.1:$NPORT" --lua "$SOCKETLEY_TMPD/count.lua" >/dev/null 2>&1
"$BIN" start rv_count >/dev/null 2>&1
for _ in $(seq 1 50); do calls RCOUNT | grep -q . && break; sleep 0.1; done
check "lines() walks the lines on_message would have had" "RCOUNT 1003" "$(calls RCOUNT | head -1)"
msgs=""
for _ in $(seq 1 30); do
    msgs=$({ "$BIN" stats rv_count 2>/dev/null || true; } | awk -F: '$1 == "total_messages" { print $2; exit }')
    [ "$msgs" = 1003 ] && break
    sleep 0.1
done
check "total_messages counts them without an observer too" "1003" "$msgs"

# ─── A datagram ─────────────────────────────────────────────────────────────
python3 - "$UPORT" <<'PY' >/dev/null 2>&1 &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.settimeout(20)
d, a = s.recvfrom(2048)
s.sendto(b"dgram\r\n", a)
PY
UPEER_PID=$!
sleep 0.3
cat > "$SOCKETLEY_TMPD/udp.lua" <<'LUAEOF'
function on_connect() self.send("hi") end
function on_read(v, id)
    socketley.log("RUDP id=" .. id .. " len=" .. v:len() .. " [" .. v:sub(1, -1):gsub("\n", "<LF>") .. "]")
    error("boom from on_read")
end
LUAEOF
"$BIN" create client rv_udp --udp -t "127.0.0.1:$UPORT" --lua "$SOCKETLEY_TMPD/udp.lua" >/dev/null 2>&1
"$BIN" start rv_udp >/dev/null 2>&1
for _ in $(seq 1 50); do calls RUDP | grep -q . && break; sleep 0.1; done
check "a datagram is a view of one line with its newline" "RUDP id=1 len=6 [dgram<LF>]" "$(calls RUDP | head -1)"
if grep -a "boom from on_read" "$SOCKETLEY_DLOG" | grep -q "on_read error"; then ok; else
    bad "an error in on_read is reported naming the callback" "$(grep -a 'boom' "$SOCKETLEY_DLOG" | head -2)"
fi

if grep -qaE 'AddressSanitizer|runtime error:|killed by signal|Segmentation' "$SOCKETLEY_DLOG" 2>/dev/null; then
    bad "no worker crashed" "$(grep -aE 'AddressSanitizer|runtime error:|killed by signal|Segmentation' "$SOCKETLEY_DLOG" | head -3)"
else
    ok
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
