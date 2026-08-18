#!/usr/bin/env bash
# Integration test: a --http server performs the ACTIVE close on Connection: close
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Whoever performs the active close of a TCP connection holds TIME-WAIT for that
# 4-tuple for 60 s.  A server's sits on its fixed listening port and costs
# nothing scarce.  A client's sits on an ephemeral port, and this box has 28,231
# of them -- so at any sustained connection-per-request rate the client's port
# pool, not either side's CPU, is the binding constraint.
#
# This server was structurally the second side to close, every time.  Counted
# over 2,000 connection-per-request requests: 0 closes from us, 2,004 from the
# client, against haproxy's 1,976 from the server.  Two independent causes:
#
#   1. handle_http_request decided keep-alive from the request VERSION alone and
#      never looked at the client's `Connection` header, so `Connection: close`
#      was answered `Connection: keep-alive` and conn->closing was never set.
#   2. --http-cache stored ONE prebuilt response, built with keep_alive=true, so
#      even once (1) was fixed the cached bytes would still have said keep-alive.
#
# and then, with closing finally set, nothing sent the FIN: the multishot recv
# stays armed for the life of the connection, so conn_ops_pending() is true at
# the write completion and the close_conn() branch cannot fire.  It waited for
# the client's FIN -- which is the client closing first, which is the defect.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# The load-bearing assertion is the KERNEL's own view, not ours: after the
# exchange, a TIME-WAIT row must exist whose LOCAL port is the server's port.
# That row only exists if we sent FIN first.  It is asserted together with its
# negation -- that the mirror-image row, local=ephemeral peer=server, does NOT
# exist -- because "no row found" would otherwise pass against a build where the
# connection never happened at all.
#
# The keep-alive cases are the control.  Without them every assertion here would
# pass against a build that simply closed on every request, which would be a
# different and worse defect: assertion 3 (no FIN when keep-alive was asked for)
# is what makes assertion 1 mean "honours the request" rather than "always
# closes".  Both modes are covered because they are two different code paths:
# --http-cache serves a prebuilt string, disk mode builds one per request.

set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate httpclose
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: --http performs the active close ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1590))

mkdir -p "$WORK/www"
printf '<h1>hello</h1>' > "$WORK/www/index.html"

"$BIN" create server hcached -p $((P+1)) --http "$WORK/www" --http-cache -s >/dev/null 2>&1 || true
"$BIN" create server hdisk   -p $((P+2)) --http "$WORK/www"              -s >/dev/null 2>&1 || true
sleep 1.2

# One exchange, reported as machine-readable fields.  Python and not curl
# because the two facts under test -- who sent FIN, and which side the kernel
# put TIME-WAIT on -- both need the client's own ephemeral port number, and
# curl does not report it.
cat > "$WORK/probe.py" <<'PY'
import socket, subprocess, sys, time
port = int(sys.argv[1]); version = sys.argv[2]; conn_hdr = sys.argv[3]
req = f"GET /index.html HTTP/{version}\r\nHost: t\r\n".encode()
if conn_hdr != "none":
    req += f"Connection: {conn_hdr}\r\n".encode()
req += b"\r\n"

s = socket.create_connection(("127.0.0.1", port), 5)
local_port = s.getsockname()[1]
s.settimeout(5); s.sendall(req)

data = b""
while b"\r\n\r\n" not in data:
    chunk = s.recv(65536)
    if not chunk: break
    data += chunk
head, _, body = data.partition(b"\r\n\r\n")
clen = 0
for line in head.split(b"\r\n"):
    if line.lower().startswith(b"content-length:"):
        clen = int(line.split(b":", 1)[1])
while len(body) < clen:
    body += s.recv(65536)

status = head.split(b"\r\n")[0].decode(errors="replace")
conn_resp = "none"
for line in head.split(b"\r\n"):
    if line.lower().startswith(b"connection:"):
        conn_resp = line.split(b":", 1)[1].strip().decode().lower()

# Did the server close its write side on its own?  A read that returns EOF
# without us having closed anything is its FIN and nothing else.
s.settimeout(2.0)
fin = "no"
try:
    if s.recv(1) == b"": fin = "yes"
except socket.timeout:
    pass
s.close()

# Which side did the kernel put TIME-WAIT on?  Poll briefly: the row appears
# when the last ACK is processed, not when close() returns.
side = "none"
for _ in range(40):
    out = subprocess.run(["ss", "-tan", "state", "time-wait"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 4: continue
        lp = f[2].rsplit(":", 1)[-1]; rp = f[3].rsplit(":", 1)[-1]
        if lp == str(port) and rp == str(local_port): side = "server"; break
        if lp == str(local_port) and rp == str(port): side = "client"; break
    if side != "none": break
    time.sleep(0.05)

print(f"status={status}|conn={conn_resp}|fin={fin}|timewait={side}|lport={local_port}")
PY

probe(){ python3 "$WORK/probe.py" "$1" "$2" "$3"; }
field(){ printf '%s' "$1" | tr '|' '\n' | grep "^$2=" | cut -d= -f2-; }

for spec in "cached|$((P+1))" "disk|$((P+2))"; do
    mode=${spec%%|*}; port=${spec##*|}

    # ── the close case ───────────────────────────────────────────────────────
    r=$(probe "$port" 1.1 close)
    st=$(field "$r" status); ch=$(field "$r" conn); fn=$(field "$r" fin); tw=$(field "$r" timewait)

    # 1. the control: the request was actually served.  Everything below is
    #    meaningless against a build that answered nothing at all.
    if [ "${st#HTTP/1.1 200}" != "$st" ]; then pass
    else fail "$mode: Connection: close request is served" "status line was '$st'"; fi

    # 2. RFC 9112 s9.6 -- the response must echo the close it was asked for.
    #    Catches the --http-cache build that served one prebuilt keep-alive
    #    string for every request.
    if [ "$ch" = "close" ]; then pass
    else fail "$mode: response echoes Connection: close" "response said 'Connection: $ch'"; fi

    # 3. we send FIN without the client having closed anything.
    if [ "$fn" = "yes" ]; then pass
    else fail "$mode: server sends FIN first" \
              "the client waited 2 s after a complete response and got no FIN"; fi

    # 4. THE assertion: the kernel put TIME-WAIT on the server's fixed port.
    #    'client' is the pre-fix behaviour; 'none' means no connection was
    #    observed at all and is a failure too, not a pass by absence.
    if [ "$tw" = "server" ]; then pass
    else fail "$mode: TIME-WAIT is held by the server" \
              "the kernel put it on the '$tw' side (want 'server')" \
              "'client' = we closed second; 'none' = no TIME-WAIT row was found at all"; fi

    # ── the keep-alive control ───────────────────────────────────────────────
    # Without this every assertion above passes against a build that closes on
    # every request regardless of what was asked.
    r=$(probe "$port" 1.1 none)
    ch=$(field "$r" conn); fn=$(field "$r" fin)
    if [ "$ch" = "keep-alive" ]; then pass
    else fail "$mode: HTTP/1.1 with no Connection header stays keep-alive" "response said '$ch'"; fi
    if [ "$fn" = "no" ]; then pass
    else fail "$mode: no FIN when the client did not ask to close" \
              "the server closed a connection it was asked to keep"; fi

    # ── HTTP/1.0 ────────────────────────────────────────────────────────────
    # 1.0 defaults to close, and an explicit keep-alive overrides that default.
    # The second case is what --http-cache could not express at all: it held a
    # single prebuilt string, so it answered keep-alive to both.
    r=$(probe "$port" 1.0 none)
    if [ "$(field "$r" conn)" = "close" ]; then pass
    else fail "$mode: HTTP/1.0 with no Connection header closes" \
              "response said '$(field "$r" conn)'"; fi

    r=$(probe "$port" 1.0 keep-alive)
    if [ "$(field "$r" conn)" = "keep-alive" ]; then pass
    else fail "$mode: HTTP/1.0 with Connection: keep-alive is honoured" \
              "response said '$(field "$r" conn)'"; fi
done

# ─── THE FIN MUST NEVER OVERTAKE THE BODY ───────────────────────────────────
#
# The FIN is sent from the write COMPLETION, never from where the write is
# queued, because a ring submission is not a syscall: shutdown() issued with a
# write still in flight puts the FIN in front of the payload.  This assertion
# is what holds that ordering down.
#
# A truncated body followed by a well-formed EOF is the worst shape this defect
# has -- the status line is right, the framing looks finished, and only the
# byte count is wrong -- so the check is byte-exact and the reader is
# deliberately slow.  A fast reader drains the socket buffer, the send never has
# to block, and the case that catches this never arises.
#
# Watched red: a build that sent the FIN chained to the send instead of after
# its completion delivered 2,681,753 of 8,388,608 bytes and then closed
# cleanly.  That approach was measured and abandoned for unrelated reasons (it
# lost the very race it was meant to win), but the assertion it produced is the
# reason this file can tell a whole response from a plausible-looking stump.
LARGE="$WORK/www/large.bin"
python3 -c "
n = 8*1024*1024
open('$LARGE','wb').write(bytes((i*7+11)%251 for i in range(4096))*(n//4096))
"
"$BIN" create server hbig -p $((P+3)) --http "$WORK/www" --http-cache -s >/dev/null 2>&1 || true
sleep 1.2

# Its own probe rather than the shared one, because it has to read SLOWLY and
# the shared probe deliberately does not.
cat > "$WORK/slow.py" <<'PY'
import socket, sys, time, hashlib
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(20)
s.sendall(b"GET /large.bin HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
d = b""
while b"\r\n\r\n" not in d: d += s.recv(65536)
head, _, body = d.partition(b"\r\n\r\n")
clen = 0
for line in head.split(b"\r\n"):
    if line.lower().startswith(b"content-length:"):
        clen = int(line.split(b":", 1)[1])
first = True
while len(body) < clen:
    if first:
        time.sleep(1.0)      # let the socket buffer fill, so the send must block
        first = False
    c = s.recv(8192)
    if not c: break
    body += c
fin = "no"
try:
    if s.recv(1) == b"": fin = "yes"
except Exception: pass
s.close()
print(f"{clen}|{len(body)}|{hashlib.sha256(body).hexdigest()}|{fin}")
PY
want_sha=$(python3 -c "
import hashlib
print(hashlib.sha256(open('$LARGE','rb').read()).hexdigest())")
want_len=$(stat -c %s "$LARGE")
r=$(python3 "$WORK/slow.py" $((P+3)) 2>/dev/null || echo "0|0|none|no")
g_clen=$(printf '%s' "$r" | cut -d'|' -f1)
g_len=$(printf  '%s' "$r" | cut -d'|' -f2)
g_sha=$(printf  '%s' "$r" | cut -d'|' -f3)
g_fin=$(printf  '%s' "$r" | cut -d'|' -f4)

# The control: Content-Length must describe the file, or "we got that many
# bytes" below is a comparison against a number the server made up.
if [ "$g_clen" = "$want_len" ]; then pass
else fail "a large response declares the file's real length" \
          "Content-Length was $g_clen, the file is $want_len bytes"; fi

# THE assertion: every byte, not just the right number of them.
if [ "$g_sha" = "$want_sha" ] && [ "$g_len" = "$want_len" ]; then pass
else fail "a large response to a slow reader arrives whole" \
          "got $g_len of $want_len bytes, sha $g_sha" \
          "want sha $want_sha" \
          "a short body here means the linked FIN overtook the payload"; fi

# ...and it still closed, so the truncation cannot be hiding as a hang.
if [ "$g_fin" = "yes" ]; then pass
else fail "a large response is still closed by the server" \
          "no FIN after the body"; fi

# A list-valued header, which is how browsers actually send it.
r=$(probe $((P+1)) 1.1 "close, TE")
if [ "$(field "$r" conn)" = "close" ] && [ "$(field "$r" timewait)" = "server" ]; then pass
else fail "a comma-separated Connection list is parsed token-wise" \
          "'close, TE' gave conn='$(field "$r" conn)' timewait='$(field "$r" timewait)'"; fi

# Case-insensitive, per RFC 9110 s5.1 -- field names and these tokens both.
r=$(probe $((P+1)) 1.1 "CLOSE")
if [ "$(field "$r" conn)" = "close" ]; then pass
else fail "the close token is matched case-insensitively" \
          "'CLOSE' gave conn='$(field "$r" conn)'"; fi

echo
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ] || exit 1
