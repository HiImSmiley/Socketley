#!/usr/bin/env bash
# Integration test: on_messages and on_client_messages take a read's complete
# lines as one string.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# A script that defines the batch callback is handed everything up to the last
# newline of each read in one call, and keeps the unfinished tail for the next
# read -- which is a different path through the client's in-place framing, its
# copying framing and the server's TCP arm.  The peer cuts its bytes so each
# cut is its own read, pacing on the script's answers.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
#   client, on_messages and on_message both defined:
#     a line split over three reads          one call, the line whole with its \n
#     three lines in one read                one call with all three
#     a read that ends a line, holds one     one call: the joined line and the
#       more and leaves a tail                 whole one; the tail next time
#     CRLF                                   the bytes as sent, \r kept
#     blank lines                            in the chunk, but not counted as
#                                              messages, as on_message has none
#     2000 lines in one write                every line, in far fewer calls
#     on_message                             never called
#     -w                                     every line, as on_message's runtime
#                                              writes them
#   server, on_client_messages and on_client_message both defined:
#     three lines in one read                one call with the sender's id
#     a line split across reads              joined, as on the client
#     returning true                         nothing relayed to the other client
#     returning false                        each line relayed as before
#     a UDP datagram                         a chunk of one line with its \n
#     on_client_message                      never called
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate batchlines

CPORT=$((SL_PORT_BASE+1777))
SPORT=$((SL_PORT_BASE+1778))
UPORT=$((SL_PORT_BASE+1779))
STATUS="$SOCKETLEY_TMPD/peer.status"
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
    for r in bl_cli bl_srv bl_udp; do
        "$BIN" stop   "$r" >/dev/null 2>&1 || true
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    [ -n "${PEER_PID:-}" ] && kill "$PEER_PID" 2>/dev/null
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

# The script's calls, in order, from the daemon's log.
calls() { grep -a "$1 " "$SOCKETLEY_DLOG" 2>/dev/null | sed "s/.*$1 /$1 /"; }

echo "=== Integration: a read's lines as one string ==="
daemon_start "$BIN"

# ─── The client ─────────────────────────────────────────────────────────────
python3 - "$CPORT" "$STATUS" <<'PY' >"$SOCKETLEY_TMPD/peer.log" 2>&1 &
import socket, sys, time
port, status_path = int(sys.argv[1]), sys.argv[2]
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
            lines += int(line.split()[1])
    return True
time.sleep(0.3)
steps = [
    ((b"hel", b"lo wor", b"ld\n"), 1),
    ((b"one\ntwo\nthree\n",), 4),
    ((b"four\nfiv", b"e\nsix\nsev", b"en\n"), 8),
    ((b"crlf1\r\ncrlf2\r\n",), 10),
    ((b"blank1\n\n\r\nblank2\n",), 14),
    ((b"".join(b"bulk%d\n" % i for i in range(2000)),), 2014),
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
time.sleep(5)
PY
PEER_PID=$!
for i in $(seq 1 60); do
    ss -ltnH "sport = :$CPORT" 2>/dev/null | grep -q . && break
    sleep 0.1
done

cat > "$SOCKETLEY_TMPD/client.lua" <<'LUAEOF'
-- Each call logged with its bytes made visible and its line count, the count
-- found with string.find as the manual's example does, and answered with it.
local function show(s) return (s:gsub("\r", "<CR>"):gsub("\n", "<LF>")) end
function on_messages(chunk)
    local n, i = 0, 1
    while true do
        local j = string.find(chunk, "\n", i, true)
        if not j then break end
        n, i = n + 1, j + 1
    end
    if n > 20 then
        socketley.log("CBATCH lines=" .. n .. " last=" .. show(chunk:sub(-9)))
    else
        socketley.log("CBATCH [" .. show(chunk) .. "]")
    end
    self.send("ACK " .. n)
end
function on_message(msg) socketley.log("CPERLINE [" .. msg .. "]") end
LUAEOF

"$BIN" create client bl_cli -t "127.0.0.1:$CPORT" --lua "$SOCKETLEY_TMPD/client.lua" \
    -w "$WOUT" >/dev/null 2>&1
"$BIN" start bl_cli >/dev/null 2>&1

if status_has "client delivered" 30; then ok; else
    bad "every cut is delivered and answered" "peer says: $(tr '\n' ';' < "$STATUS" 2>/dev/null)"
fi
sleep 0.3

got=$(calls CBATCH | head -7 | tr '\n' '|')
check "the client's calls, one per read, each line with its newline" \
    "CBATCH [hello world<LF>]|CBATCH [one<LF>two<LF>three<LF>]|CBATCH [four<LF>]|CBATCH [five<LF>six<LF>]|CBATCH [seven<LF>]|CBATCH [crlf1<CR><LF>crlf2<CR><LF>]|CBATCH [blank1<LF><LF><CR><LF>blank2<LF>]|" \
    "$got"

# 2000 lines, every one of them counted, in a handful of reads.
bulk=$(calls CBATCH | tail -n +8)
bulk_lines=0
while read -r line; do
    case "$line" in
        *lines=*) n=${line#*lines=}; bulk_lines=$((bulk_lines + ${n%% *})) ;;
        *) n=$(printf '%s' "$line" | grep -o '<LF>' | wc -l); bulk_lines=$((bulk_lines + n)) ;;
    esac
done <<< "$bulk"
check "2000 lines in one write all reach on_messages" "2000" "$bulk_lines"
bulk_calls=$(printf '%s\n' "$bulk" | grep -c .)
if [ "$bulk_calls" -ge 1 ] && [ "$bulk_calls" -le 50 ]; then ok; else
    bad "2000 lines in one write take far fewer than 2000 calls" "calls: $bulk_calls"
fi
check "the last bulk line ends the last call" "bulk1999<LF>" "$(calls CBATCH | tail -1 | grep -o 'bulk1999<LF>')"

check "on_message is not called when on_messages is defined" "" "$(calls CPERLINE | head -3)"

# Blank lines are no messages to on_message, so the batch path does not count them either.
msgs=""
for _ in $(seq 1 30); do
    msgs=$({ "$BIN" stats bl_cli 2>/dev/null || true; } | awk -F: '$1 == "total_messages" { print $2; exit }')
    [ "$msgs" = 2012 ] && break
    sleep 0.1
done
check "total_messages counts the lines on_message would have had, not the blank ones" "2012" "$msgs"

expect_w=$(printf '%s\n' "hello world" one two three four five six seven crlf1 crlf2 blank1 blank2; for i in $(seq 0 1999); do echo "bulk$i"; done)
if [ "$(cat "$WOUT" 2>/dev/null)" = "$expect_w" ]; then ok; else
    bad "-w writes every line as the per-line path does" \
        "first lines: $(head -12 "$WOUT" 2>/dev/null | tr '\n' '|')" "lines: $(wc -l < "$WOUT" 2>/dev/null)"
fi

# ─── The server ─────────────────────────────────────────────────────────────
cat > "$SOCKETLEY_TMPD/server.lua" <<'LUAEOF'
local function show(s) return (s:gsub("\n", "<LF>")) end
function on_client_messages(id, chunk)
    socketley.log("SBATCH " .. (id > 0 and "id" or "noid") .. " [" .. show(chunk) .. "]")
    if chunk:find("relay", 1, true) then return false end
    self.send(id, "GOT " .. show(chunk))
    return true
end
function on_client_message(id, msg) socketley.log("SPERLINE [" .. msg .. "]") end
LUAEOF

"$BIN" create server bl_srv -p "$SPORT" --bind 127.0.0.1 --lua "$SOCKETLEY_TMPD/server.lua" >/dev/null 2>&1
"$BIN" start bl_srv >/dev/null 2>&1
"$BIN" create server bl_udp -p "$UPORT" --bind 127.0.0.1 --udp --lua "$SOCKETLEY_TMPD/server.lua" >/dev/null 2>&1
"$BIN" start bl_udp >/dev/null 2>&1
for i in $(seq 1 60); do
    ss -ltnH "sport = :$SPORT" 2>/dev/null | grep -q . && break
    sleep 0.1
done

out=$(python3 - "$SPORT" "$UPORT" <<'PY'
import socket, sys, time
sport, uport = int(sys.argv[1]), int(sys.argv[2])
def conn():
    c = socket.create_connection(("127.0.0.1", sport), timeout=5)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return c
a, b = conn(), conn()
time.sleep(0.3)
def lines(c, n, t=3):
    got, buf, end = [], b"", time.time() + t
    while len(got) < n and time.time() < end:
        c.settimeout(max(end - time.time(), 0.01))
        try:
            d = c.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf += d
        while b"\n" in buf:
            l, buf = buf.split(b"\n", 1)
            got.append(l.decode())
    return got
b.sendall(b"hi\n")
print("B0", "|".join(lines(b, 1)))
a.sendall(b"x\ny\nz\n")
print("A1", "|".join(lines(a, 1)))
a.sendall(b"sp")
time.sleep(0.25)
a.sendall(b"lit\nw\n")
print("A2", "|".join(lines(a, 1)))
print("B1", "|".join(lines(b, 1, 1)) or "-")
a.sendall(b"relay1\nrelay2\n")
print("B2", "|".join(lines(b, 2)))
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(3)
u.sendto(b"dgram", ("127.0.0.1", uport))
try:
    print("U1", u.recv(65536).decode().rstrip("\n"))
except socket.timeout:
    print("U1 -")
PY
)

check "three lines in one read are one call" "A1 GOT x<LF>y<LF>z<LF>" "$(grep '^A1' <<< "$out")"
check "a line split across reads is joined with the rest of the read" "A2 GOT split<LF>w<LF>" "$(grep '^A2' <<< "$out")"
check "a chunk the script answered for is not relayed" "B1 -" "$(grep '^B1' <<< "$out")"
check "a chunk the script declined is relayed line by line" "B2 relay1|relay2" "$(grep '^B2' <<< "$out")"
check "the batch callback is told the sender" "SBATCH id [x<LF>y<LF>z<LF>]" "$(calls SBATCH | sed -n 2p)"
check "a datagram is a chunk of one line" "U1 GOT dgram<LF>" "$(grep '^U1' <<< "$out")"
check "on_client_message is not called when on_client_messages is defined" "" "$(calls SPERLINE | head -3)"

if grep -qE 'AddressSanitizer|runtime error:|killed by signal|messages error' "$SOCKETLEY_DLOG" 2>/dev/null; then
    bad "no worker crashed and no callback raised" \
        "$(grep -E 'AddressSanitizer|runtime error:|killed by signal|messages error' "$SOCKETLEY_DLOG" | head -3)"
else
    ok
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
