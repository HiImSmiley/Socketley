#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The tunnel runtime: an edge, an agent that dials out to it, and the agent's services served by the edge.
#
# What each part would catch:
#   * an invitation that joins twice, or an agent joining without one
#   * an HTTP service not served on its socket, or a TCP service not on its port
#   * bytes lost, reordered or held back under a large transfer, which is what the credit is for
#   * a half-closed connection whose answer is dropped
#   * an agent that does not come back after it or the edge restarts, or comes back by joining again
#   * a revoked agent still carried, or a service it never offered reached
#   * a service's name not beside the edge's, or another runtime given a name a service has
#   * an agent's offers that edit cannot change, or changes on a running agent that has not restarted
#   * a tunnel edit refused on a later flag that leaves an earlier one in effect after --restart
#   * the entrance's own address logged for who an agent or a person was
#   * a TCP service given an address opened on every one, or not carried
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"

echo "=== Integration: a tunnel edge serves the services of an agent that dialled out to it ==="
daemon_isolate tunnel
T=$SOCKETLEY_TMPD
PE=$((SL_PORT_BASE + 1970))
PT=$((SL_PORT_BASE + 1971))
PB=$((SL_PORT_BASE + 1972))
PX=$((SL_PORT_BASE + 1973))
python3 - "$PB" "$PX" <<'PY' &
import http.server, socketserver, sys, threading, os
pb, px = int(sys.argv[1]), int(sys.argv[2])
big = bytes(range(256)) * (5 * 1024 * 1024 // 256)
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        b = big if self.path == "/big" else ("hello from home %s" % self.path).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(65536)
            if not d:
                break
            self.request.sendall(d)
        self.request.shutdown(1)
class E(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
threading.Thread(target=S(("127.0.0.1", pb), H).serve_forever, daemon=True).start()
E(("127.0.0.1", px), Echo).serve_forever()
PY
BACKENDS=$!
trap 'kill $BACKENDS 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create tunnel t --mode edge -p "$PE" -s >/dev/null 2>&1 && ok || bad "an edge is made" "$(tail -3 "$SOCKETLEY_DLOG")"
out=$("$BIN" create tunnel t2 --mode edge 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "an edge without a port is refused" "rc $rc: $out"
out=$("$BIN" create tunnel a2 --mode agent --to https://x.example --offer web=127.0.0.1:1 2>&1); rc=$?
[ "$rc" -ne 0 ] && case "$out" in *"--join"*) true ;; *) false ;; esac && ok || bad "an agent with no invitation is refused" "rc $rc: $out"
out=$("$BIN" create tunnel a3 --mode agent --to https://x.example --join pi.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --offer web=example.com:80 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "an offer of a name, not an address, is refused" "rc $rc: $out"

INV=$("$BIN" tunnel t invite pi --http web --tcp "echo:$PT" 2>&1); rc=$?
case "$INV" in pi.*) ok ;; *) bad "an invitation is printed" "rc $rc: $INV" ;; esac
out=$("$BIN" tunnel t invite other --http web 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"already pi's"*) true ;; *) false ;; esac && ok || bad "a service of another agent cannot be taken" "rc $rc: $out"
[ "$("$BIN" tunnel t list)" = "$(printf 'pi\tinvited\tweb,echo:%s' "$PT")" ] && ok || bad "list shows the invitation" "$("$BIN" tunnel t list 2>&1)"
# Where the edge serves a service: beside its agents file, or under /tmp by a hash of that path when it is too deep.
sock_of() {
    local p; p=$(dirname "$(find "$HOME/.local/share" -path '*tunnel/t/agents' 2>/dev/null | head -1)")/$1.sock
    [ ${#p} -ge 100 ] && p="/tmp/skl-$(printf '%s' "$p" | sha256sum | cut -c1-16).sock"
    echo "$p"
}
for _ in $(seq 1 30); do WEB=$(sock_of web); [ -S "$WEB" ] && break; sleep 0.1; done
[ -S "$WEB" ] && ok || bad "the edge serves the invited HTTP service on its socket" "$(find "$HOME/.local/share" -path '*tunnel*' 2>&1)"

out=$(curl -s -m 3 --unix-socket "$WEB" http://web/x -o /dev/null -w '%{http_code}' 2>&1)
[ "$out" != 200 ] && ok || bad "with no agent connected nothing answers" "$out"

"$BIN" create tunnel home --mode agent --to "http://127.0.0.1:$PE" --join "$INV" \
    --offer "web=127.0.0.1:$PB,echo=127.0.0.1:$PX" -s >/dev/null 2>&1 && ok || bad "an agent is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do "$BIN" tunnel t list | grep -q joined && break; sleep 0.1; done
case "$("$BIN" tunnel t list)" in *joined*) ok ;; *) bad "the agent joins" "$("$BIN" tunnel t list) $(tail -5 "$SOCKETLEY_DLOG")" ;; esac
# The edge marks the agent joined before the agent has read the answer and kept the key it carries.
for _ in $(seq 1 50); do KEY=$(find "$HOME/.local/share" -path '*tunnel/home/key' 2>/dev/null | head -1); [ -s "$KEY" ] && break; sleep 0.1; done
[ "$(stat -c %a "$KEY" 2>/dev/null)" = 600 ] && ok || bad "and keeps its key, readable by its owner alone" "$KEY"

tally < <(python3 - "$WEB" "$PT" 2>&1 <<'PY' || echo "bad the transfer checks ran to their end"
import sys, socket, hashlib, threading, http.client
web, pt = sys.argv[1], int(sys.argv[2])
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("web", timeout=20); self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.settimeout(20); self.sock.connect(self.path)
def get(path, conn=None):
    c = conn or UnixConn(web)
    c.request("GET", path); r = c.getresponse(); b = r.read()
    return r.status, b
check("an HTTP request reaches the service at home", get("/x"), (200, b"hello from home /x"))
c = UnixConn(web)
check("one connection carries several requests", [get("/r%d" % i, c)[1] for i in range(5)],
      [("hello from home /r%d" % i).encode() for i in range(5)])
st, b = get("/big")
check("five megabytes come whole and in order", (st, len(b), hashlib.sha256(b).hexdigest()),
      (200, 5 * 1024 * 1024, hashlib.sha256(bytes(range(256)) * (5 * 1024 * 1024 // 256)).hexdigest()))
res = [None] * 16
def one(i):
    try:
        res[i] = get("/p%d" % i)[1]
    except Exception as e:
        res[i] = repr(e)
ts = [threading.Thread(target=one, args=(i,)) for i in range(16)]
[t.start() for t in ts]; [t.join() for t in ts]
check("sixteen connections at once each get their own answer", res, [("hello from home /p%d" % i).encode() for i in range(16)])
# TCP both ways, a lot of it, and the answer after the sender half-closes.
s = socket.create_connection(("127.0.0.1", pt), timeout=20)
data = bytes((i * 7) & 0xff for i in range(3 * 1024 * 1024))
def send():
    s.sendall(data); s.shutdown(socket.SHUT_WR)
t = threading.Thread(target=send); t.start()
got = bytearray()
while True:
    d = s.recv(65536)
    if not d:
        break
    got += d
t.join()
check("three megabytes over TCP come back whole after the sender half-closes", (len(got), bytes(got) == data), (len(data), True))
PY
)
"$BIN" stop home >/dev/null 2>&1; "$BIN" start home >/dev/null 2>&1
for _ in $(seq 1 60); do [ "$(curl -s -m 2 --unix-socket "$WEB" http://web/again)" = "hello from home /again" ] && break; sleep 0.1; done
[ "$(curl -s -m 2 --unix-socket "$WEB" http://web/again)" = "hello from home /again" ] && ok || bad "a restarted agent comes back with its key" "$(tail -5 "$SOCKETLEY_DLOG")"
[ "$(grep -c 'agent "pi" joined' "$SOCKETLEY_DLOG")" = 1 ] && ok || bad "and does not join again" "$(grep -c joined "$SOCKETLEY_DLOG")"

"$BIN" stop t >/dev/null 2>&1; "$BIN" start t >/dev/null 2>&1
for _ in $(seq 1 80); do [ "$(curl -s -m 2 --unix-socket "$WEB" http://web/back)" = "hello from home /back" ] && break; sleep 0.1; done
[ "$(curl -s -m 2 --unix-socket "$WEB" http://web/back)" = "hello from home /back" ] && ok || bad "after the edge restarts the agent dials again" "$(tail -5 "$SOCKETLEY_DLOG")"

# What a running agent offers is changed by edit through a restart, and edit says so when asked without one.
out=$("$BIN" edit home --offer "web=127.0.0.1:$PB" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"--offer changes a tunnel when it starts"*"--restart"*) true ;; *) false ;; esac && ok \
    || bad "edit of a running agent's offers asks for --restart" "rc $rc: $out"
"$BIN" edit home --offer "web=127.0.0.1:$PB,echo=127.0.0.1:$PX" --restart >/dev/null 2>&1 && ok || bad "edit --restart changes what an agent offers" "rc $?"
"$BIN" show home | grep -q "\"offer\": \"web=127.0.0.1:$PB,echo=127.0.0.1:$PX\"" && ok || bad "and the change is kept" "$("$BIN" show home | grep offer)"
for _ in $(seq 1 80); do [ "$(curl -s -m 2 --unix-socket "$WEB" http://web/edited)" = "hello from home /edited" ] && break; sleep 0.1; done
[ "$(curl -s -m 2 --unix-socket "$WEB" http://web/edited)" = "hello from home /edited" ] && ok || bad "with the agent back, its key kept" "$(tail -3 "$SOCKETLEY_DLOG")"

# A tunnel edit refused on a later flag leaves the earlier ones unapplied, through --restart as without it.
before=$("$BIN" show t)
out=$("$BIN" edit t --forward 10.0.0.9:22 --mode bogus --restart 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"--mode requires edge or agent"*) true ;; *) false ;; esac && ok \
    || bad "edit of an edge with a bad --mode is refused" "rc $rc: $out"
[ "$("$BIN" show t)" = "$before" ] && ok || bad "and the edge's --forward is as it was" "$("$BIN" show t | grep -E 'forward|mode')"
before=$("$BIN" show home)
out=$("$BIN" edit home --offer "web=127.0.0.1:1" --to ftp://nowhere --restart 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"--to requires"*) true ;; *) false ;; esac && ok \
    || bad "edit of an agent with a bad --to is refused" "rc $rc: $out"
[ "$("$BIN" show home)" = "$before" ] && ok || bad "and what the agent offers is as it was" "$("$BIN" show home | grep -E 'offer|\"to\"')"
for _ in $(seq 1 80); do [ "$(curl -s -m 2 --unix-socket "$WEB" http://web/refused)" = "hello from home /refused" ] && break; sleep 0.1; done
[ "$(curl -s -m 2 --unix-socket "$WEB" http://web/refused)" = "hello from home /refused" ] && ok || bad "and the agent, restarted unchanged, still carries web" "$(tail -3 "$SOCKETLEY_DLOG")"

# A second agent with the same invitation is refused, the first keeps its link.
"$BIN" create tunnel thief --mode agent --to "http://127.0.0.1:$PE" --join "$INV" --offer "web=127.0.0.1:$PB" -s >/dev/null 2>&1
for _ in $(seq 1 30); do grep -q "tunnel thief: the edge refused" "$SOCKETLEY_DLOG" && break; sleep 0.1; done
grep -q "tunnel thief: the edge refused: HTTP/1.1 401" "$SOCKETLEY_DLOG" && ok || bad "an invitation joins once" "$(grep thief "$SOCKETLEY_DLOG" | tail -2)"
"$BIN" remove thief >/dev/null 2>&1
# Behind the entrance the edge says who the entrance heard a refused agent from, not the entrance itself.
python3 - "$PE" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"GET /.tunnel HTTP/1.1\r\nHost: t\r\nUpgrade: socketley-tunnel/1\r\nConnection: Upgrade\r\n"
          b"X-Forwarded-For: 203.0.113.9\r\nAuthorization: Tunnel nobody.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n\r\n")
s.recv(4096)
PY
for _ in $(seq 1 20); do grep -q 'agent "nobody" refused from' "$SOCKETLEY_DLOG" && break; sleep 0.1; done
grep -q 'agent "nobody" refused from 203.0.113.9$' "$SOCKETLEY_DLOG" && ok \
    || bad "a refused agent is said with the address the entrance heard it from" "$(grep 'refused from' "$SOCKETLEY_DLOG" | tail -1)"

# ── Through the entrance, as on a machine with a zone ───────────────────────
if command -v dig >/dev/null 2>&1; then
    PW=$((SL_PORT_BASE + 1974)); DNS=$((SL_PORT_BASE + 1975))
    cat > "$T/z.zone" <<'ZONE'
$ORIGIN example.com.
$TTL 300
@    SOA ns1 hostmaster 1 1h 15m 1w 60
     NS  ns1
ns1  A   192.0.2.53
ZONE
    "$BIN" create proxy web -p "$PW" -s >/dev/null 2>&1
    "$BIN" create dns ns -p "$DNS" --zone "$T/z.zone" --proxy web --publish 198.51.100.7 --rrl 0 -s >/dev/null 2>&1
    "$BIN" edit t --domain t >/dev/null 2>&1
    for _ in $(seq 1 60); do [ "$(curl -s -m 2 -H 'Host: web.example.com' "http://127.0.0.1:$PW/e")" = "hello from home /e" ] && break; sleep 0.1; done
    [ "$(curl -s -m 2 -H 'Host: web.example.com' "http://127.0.0.1:$PW/e")" = "hello from home /e" ] && ok \
        || bad "the entrance routes a service's name, beside the edge's, to the agent at home" "$(cat "$HOME"/.local/share/socketley/runtimes*/.dns/routes-web 2>&1 | head -5)"
    # The zone is rebuilt at most once a second after the names change.
    for _ in $(seq 1 40); do got=$(dig +short @127.0.0.1 -p "$DNS" web.example.com A 2>/dev/null); [ -n "$got" ] && break; sleep 0.1; done
    [ "$got" = 198.51.100.7 ] && ok || bad "and the zone answers the name" "$got"
    out=$(curl -s -m 2 -H 'Host: t.example.com' "http://127.0.0.1:$PW/" 2>&1)
    case "$out" in *"socketley tunnel edge"*) ok ;; *) bad "the edge's own name reaches the edge, which says what it is" "$out" ;; esac
    out=$(curl -s -m 2 -o /dev/null -w '%{http_code}' -H 'Host: web.t.example.com' "http://127.0.0.1:$PW/e" 2>&1)
    [ "$out" != 200 ] && ok || bad "and no name below it is the edge's any more" "$out"
    out=$("$BIN" create server site -p $((SL_PORT_BASE + 1976)) --domain web 2>&1); rc=$?
    [ "$rc" -ne 0 ] && case "$out" in *"web is already the name of runtime 't'"*) true ;; *) false ;; esac && ok \
        || bad "a name a service has is not given to another runtime" "rc $rc: $out"
    "$BIN" remove site >/dev/null 2>&1
    # A second edge's service of the same name is no second route to it: the edge before it keeps the name.
    "$BIN" create tunnel t2 --mode edge -p $((SL_PORT_BASE + 1977)) --domain t2 -s >/dev/null 2>&1
    "$BIN" tunnel t2 invite other --http web >/dev/null 2>&1
    R="$(dirname "$(find "$HOME/.local/share" -name 'routes-web' 2>/dev/null | head -1)")/routes-web"
    sleep 2.5
    line=$(grep '^route web.example.com ' "$R")
    [ "$line" = "route web.example.com unix:$WEB" ] && ok || bad "two edges' services of one name are not one route" "$line"
    "$BIN" remove t2 >/dev/null 2>&1
    # A runtime's wildcard keeps the names under it: a service of the same name is no exact route past it.
    "$BIN" create server wild -p $((SL_PORT_BASE + 1978)) --domain '*.example.com' -s >/dev/null 2>&1
    sleep 2.5
    grep -q '^route web.example.com ' "$R" && bad "a runtime's wildcard keeps a service's name" "$(grep 'example.com' "$R")" || ok
    "$BIN" remove wild >/dev/null 2>&1
    # An agent's upgrade passes the entrance to the edge: the key it holds is taken there.
    up=$(python3 - "$PW" "$(cat "$KEY")" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(("GET /.tunnel HTTP/1.1\r\nHost: t.example.com\r\nUpgrade: socketley-tunnel/1\r\nConnection: Upgrade\r\n"
           "Authorization: Tunnel %s\r\n\r\n" % sys.argv[2].strip()).encode())
print(s.recv(4096).split(b"\r\n")[0].decode())
PY
)
    [ "$up" = "HTTP/1.1 101 Switching Protocols" ] && ok || bad "an agent upgrades through the entrance" "$up"
    sleep 0.5
fi

# A service the edge was told of and the agent does not offer is refused at the agent, its link kept.
"$BIN" tunnel t set pi --http web,ghost --tcp "echo:127.0.0.1:$PT" && ok || bad "set changes an agent's services" "rc $?"
sleep 1.5
# A TCP service given an address is opened on that one alone, and carried as before.
[ "$(ss -Hltn "sport = :$PT" | awk '{print $4}')" = "127.0.0.1:$PT" ] && ok \
    || bad "a TCP service given an address listens there alone" "$(ss -Hltn "sport = :$PT")"
"$BIN" tunnel t list | grep -q "echo:127.0.0.1:$PT" && ok || bad "and list says where" "$("$BIN" tunnel t list)"
# The entrance's upgrade above took the agent's link over, so it is waited for while it dials again.
bound() { python3 -c "
import socket, sys
s = socket.create_connection(('127.0.0.1', $PT), timeout=5); s.sendall(b'bound'); s.shutdown(1)
d = b''
while True:
    c = s.recv(100)
    if not c: break
    d += c
print(d.decode())" 2>&1; }
for _ in $(seq 1 80); do out=$(bound); [ "$out" = bound ] && break; sleep 0.1; done
[ "$out" = bound ] && ok || bad "and carried to the agent" "$out"
GHOST=$(sock_of ghost)
for _ in $(seq 1 30); do [ -S "$GHOST" ] && break; sleep 0.1; done
out=$(curl -s -m 3 --unix-socket "$GHOST" http://ghost/ -o /dev/null -w '%{http_code}' 2>&1)
[ -S "$GHOST" ] && [ "$out" != 200 ] && ok || bad "a service the agent does not offer is not reached" "$out"
# The upgrade through the entrance above took the agent's link over, so the agent has dialled again since.
for _ in $(seq 1 60); do [ "$(curl -s -m 2 --unix-socket "$WEB" http://web/kept)" = "hello from home /kept" ] && break; sleep 0.1; done
[ "$(curl -s -m 2 --unix-socket "$WEB" http://web/kept)" = "hello from home /kept" ] && ok \
    || bad "while the agent, its key kept, still carries what it offers" "$(tail -3 "$SOCKETLEY_DLOG")"

"$BIN" tunnel t revoke pi && ok || bad "an agent is revoked" "rc $?"
sleep 1.5
out=$(curl -s -m 3 --unix-socket "$WEB" http://web/after -w '%{http_code}' 2>&1)
case "$out" in *"hello from home"*) bad "a revoked agent is carried no more" "$out" ;; *) ok ;; esac
[ -S "$WEB" ] && bad "and its services are no longer served" "$WEB still there" || ok
for _ in $(seq 1 30); do [ "$("$BIN" stats t 2>/dev/null | sed -n 's/^links://p')" = 0 ] && break; sleep 0.2; done
[ "$("$BIN" stats t 2>/dev/null | sed -n 's/^links://p')" = 0 ] && ok || bad "and its link is cut" "$("$BIN" stats t 2>&1 | grep links)"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
