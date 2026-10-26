#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
# An entrance that terminates TLS speaks HTTP/2, which it has to read frame by
# frame rather than relay: a browser coalesces names onto one connection when
# the certificate and the address agree -- exactly an entrance's case -- so a
# connection routed once by its SNI would answer a request for one name out of
# another name's backend.  Each stream's own `:authority` is what gets routed.
#
#   negotiation  a client offering h2 by ALPN is given it, one that does not
#                keeps HTTP/1.1, and a non-entrance proxy offers neither
#   routing      a stream is routed by its own `:authority`, and two names reach
#                their two different runtimes, each over its own connection
#   bodies       a POST over a stream reaches the backend whole, with and
#                without a stated length
#   framing      an answer ends, so a client reads a complete body and a
#                second request on the same connection still works
#   the bound    more streams at once than the session allows are refused,
#                which a client retries elsewhere, rather than dropped
#   the tally    the entrance's stats count the connection and its streams
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate pxh2
P=$((SL_PORT_BASE+1840))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: the entrance speaks HTTP/2 and HTTP/3 ==="

if ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: openssl is not installed, so the entrance has no certificate to offer"
    echo ""
    echo "=== Results: 0/0 passed, 0 failed ==="
    exit 0
fi
if ! curl -V 2>/dev/null | grep -qi nghttp2; then
    echo "  SKIP: this curl has no HTTP/2, so nothing here can ask for it"
    echo ""
    echo "=== Results: 0/0 passed, 0 failed ==="
    exit 0
fi

daemon_start "$BIN"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=example.com \
    -addext "subjectAltName=DNS:*.example.com,DNS:example.com" \
    -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1

mkdir -p "$T/one" "$T/two"
echo "from-one" >"$T/one/who.txt"
echo "from-two" >"$T/two/who.txt"
# A body large enough to be several DATA frames and to cross a 16 KiB window.
head -c 200000 /dev/urandom | base64 | head -c 120000 >"$T/big.txt"

E=$((P+1))
"$BIN" create server one -p $((P+2)) --http "$T/one" --domain one.example.com -s >/dev/null 2>&1
"$BIN" create server two -p $((P+3)) --http "$T/two" --domain two.example.com -s >/dev/null 2>&1
"$BIN" create server three -p $((P+5)) --http "$T/two" --domain three.example.com -s >/dev/null 2>&1
cat >"$T/echo.lua" <<'LUA'
local got = {}
function on_http_body(id, chunk) got[id] = (got[id] or 0) + #chunk end
function on_http_request(req)
    local n = got[req.client_id] or #(req.body or ""); got[req.client_id] = nil
    return { status = 200, body = "len=" .. n }
end
function on_disconnect(id) got[id] = nil end
LUA
"$BIN" create server echo -p $((P+6)) --lua "$T/echo.lua" --domain echo.example.com -s >/dev/null 2>&1
"$BIN" create proxy ent -p "$E" --tls --cert "$T/e.pem" --key "$T/e.key" -s >/dev/null 2>&1

# Over the entrance, with the name resolved to it; -k because the certificate is its own.
hc() { local name=$1 path=$2; shift 2
       curl -sk --noproxy '*' -m 10 --resolve "$name:$E:127.0.0.1" "$@" "https://$name:$E$path"; }

# The table has to carry both names before anything can be routed by them.
routed() { local f; f=$(find "$T" -name 'routes-ent' | head -1); [ -n "$f" ] || return 1
           grep -q one.example.com "$f" && grep -q two.example.com "$f"; }
for _ in $(seq 1 60); do routed && break; sleep 0.2; done
if ! routed; then
    bad "the entrance learned both names" "its table never carried them"
    echo ""
    echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
    exit 1
fi
ok "the entrance learned both names"

# ── negotiation ─────────────────────────────────────────────────────────────
ver() { hc "$1" /who.txt -o /dev/null -w '%{http_version}'; }
got=""
for _ in $(seq 1 40); do got=$(ver one.example.com); [ "$got" = 2 ] && break; sleep 0.2; done
expect "a client offering h2 by ALPN is given it" "$got" "2"
expect "and the answer over that stream is the runtime's" "$(hc one.example.com /who.txt)" "from-one"
expect "a client that offers only HTTP/1.1 keeps it" \
    "$(hc one.example.com /who.txt --http1.1 -o /dev/null -w '%{http_version}')" "1.1"
expect "and still gets its answer" "$(hc one.example.com /who.txt --http1.1)" "from-one"

# ── routing, which is why the frames are read at all ────────────────────────
expect "a stream is routed by its own authority" "$(hc two.example.com /who.txt)" "from-two"
two_on_one=$(curl -sk --noproxy '*' -m 10 \
    --resolve "one.example.com:$E:127.0.0.1" --resolve "two.example.com:$E:127.0.0.1" \
    -w '|%{http_version}' \
    "https://one.example.com:$E/who.txt" "https://two.example.com:$E/who.txt" 2>&1 | tr -d '\n')
# Two names, each over its own connection because curl opens one per host: what this holds down is that each
# reaches its own runtime.  The coalesced case -- both names on ONE connection -- is in lib_proxy_http3.py, where
# the client can be made to do it, and there the second is refused 421.
has "two names, each routed to its own runtime" "$two_on_one" "from-one"
has "and the second name is not answered by the first's runtime" "$two_on_one" "from-two"
# The bodies and the versions interleave in curl's own output, so what is asked is that two answers came and both
# said 2 -- not where in the line they sit.
expect "both over HTTP/2" "$(printf '%s' "$two_on_one" | grep -o '|2' | wc -l)" "2"

# The check that makes reading the frames worth anything: a stream whose authority is not the name the handshake
# gave is refused.  A stream has no handshake of its own, so this asks that it is its session's that answers -- it
# was 200 until conn::tls() followed the parent, which is a connection opened for one name serving another's.
expect "a stream naming a name the handshake did not is refused" \
    "$(hc one.example.com /who.txt -H 'Host: two.example.com' -o /dev/null -w '%{http_code}/%{http_version}')" "421/2"

# ── a second request on the same connection ────────────────────────────────
twice=$(curl -sk --noproxy '*' -m 10 --resolve "one.example.com:$E:127.0.0.1" \
    "https://one.example.com:$E/who.txt" "https://one.example.com:$E/who.txt" | tr -d '\n')
expect "a stream ends, so the next request on the connection is answered too" "$twice" "from-onefrom-one"

# ── bodies ──────────────────────────────────────────────────────────────────
# The server runtime answers a POST to a path it does not serve with 404/405, which is enough: what is held down
# here is that the entrance carried the body's DATA frames and did not hang.
# The version is asked here too: without it this assertion is green over HTTP/1.1 as well and would not be about
# the frames at all, which is what the counter-proof with SOCKETLEY_PROXY_HTTP2=0 showed.
got=$(hc one.example.com /who.txt -X POST --data-binary @"$T/big.txt" -o /dev/null -w '%{http_code}/%{http_version}')
case "$got" in 2*/2|4*/2|5*/2) ok "a stated-length body over a stream reaches the backend and is answered ($got)" ;;
                *) bad "a stated-length body over a stream" "got '$got'" ;; esac
got=$(cat "$T/big.txt" | hc one.example.com /who.txt -X POST --data-binary @- -H 'Transfer-Encoding: chunked' \
       -o /dev/null -w '%{http_code}/%{http_version}')
case "$got" in 2*/2|4*/2|5*/2) ok "a body of no stated length too, framed as chunks for the parser ($got)" ;;
                *) bad "a body of no stated length" "got '$got'" ;; esac

# An empty DATA frame in the middle of a body of no stated length is nothing, and not the chunk that ends it.
for _ in $(seq 1 40); do [ "$(hc echo.example.com /x)" = "len=0" ] && break; sleep 0.2; done
got=$(python3 - "$E" <<'PY'
import socket, ssl, sys, h2.connection, h2.config, h2.events
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5), server_hostname="echo.example.com")
c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True)); c.initiate_connection()
c.send_headers(1, [(":method", "POST"), (":path", "/x"), (":scheme", "https"), (":authority", "echo.example.com")])
c.send_data(1, b"abc"); c.send_data(1, b""); c.send_data(1, b"def", end_stream=True)
s.sendall(c.data_to_send())
body, done = b"", False
s.settimeout(5)
while not done:
    d = s.recv(65536)
    if not d: break
    for e in c.receive_data(d):
        if isinstance(e, h2.events.DataReceived): body += e.data; c.acknowledge_received_data(len(e.data), e.stream_id)
        if isinstance(e, (h2.events.StreamEnded, h2.events.StreamReset)): done = True
    s.sendall(c.data_to_send())
print(body.decode(errors="replace"))
PY
)
expect "an empty DATA frame between two others leaves the body whole" "$got" "len=6"

# ── a complete body, byte for byte ─────────────────────────────────────────
cp "$T/big.txt" "$T/one/big.txt"
bigver=$(hc one.example.com /big.txt -o "$T/got.txt" -w '%{http_version}')
expect "a large answer arrives whole over a stream" \
    "$(cmp -s "$T/big.txt" "$T/got.txt" && echo "same/$bigver")" "same/2"

# ── the bound on streams at once ───────────────────────────────────────────
# Twenty at once against a session that allows eight: every one must be answered, the ones over the bound by being
# refused and retried on another stream, which is what REFUSED_STREAM means -- none may be lost or hang.
many=$(curl -sk --noproxy '*' -m 20 --parallel --parallel-immediate --parallel-max 20 \
    --resolve "one.example.com:$E:127.0.0.1" -o /dev/null -w '%{http_code}/%{http_version}\n' \
    "https://one.example.com:$E/who.txt?[1-20]" 2>/dev/null | sort | uniq -c | tr -s ' ' | tr '\n' ' ')
expect "twenty streams at once are all answered, over the bound of eight" "$many" " 20 200/2 "

# ── a session that opens no stream is bounded ──────────────────────────────
# A peer that negotiates h2 and then sends half a preface has said nothing this proxy can act on.  The HTTP/1.1
# path bounds the same thing with the head deadline; the frame path skips that code, so it arms it itself -- and
# without that this connection is held for ever on a listener with no --idle-timeout, which is this one.
half=$(python3 -I -c '
import socket, ssl, sys, time
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
try:
    raw = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
    w = ctx.wrap_socket(raw, server_hostname="one.example.com")
except Exception as e:
    print("no-tls:%s" % e); sys.exit(0)
if w.selected_alpn_protocol() != "h2":
    print("no-h2"); sys.exit(0)
w.sendall(b"PRI * HTTP/2.0\r\n")
t0 = time.time()
w.settimeout(25)
try:
    while w.recv(4096):
        pass
except Exception:
    print("held"); sys.exit(0)
print("closed" if time.time() - t0 < 20 else "held")
' "$E")
expect "a session that sends half a preface is closed, not held" "$half" "closed"

# ── the tally ──────────────────────────────────────────────────────────────
# Waited for, not asked once: an out-of-process runtime's counters reach the daemon in the worker's report, which
# lands on its own turn -- asking in the same breath as the last request read the report before it.
tally() { "$BIN" stats ent 2>/dev/null | sed -n 's/^h2_streams:\([0-9]*\)$/\1/p'; }
tally_of() { "$BIN" stats ent 2>/dev/null | sed -n "s/^$1:\\([0-9]*\\)$/\\1/p"; }
for _ in $(seq 1 60); do [ "$(tally || echo 0)" -ge 20 ] 2>/dev/null && break; sleep 0.2; done
has "the entrance counts the HTTP/2 connections it had" "$("$BIN" stats ent 2>&1)" "h2_conns:"
h2s=$(tally)
if [ "${h2s:-0}" -ge 20 ]; then ok "and the streams on them ($h2s)"; else bad "the stream tally" "got '${h2s:-}'"; fi

# ── a proxy that is not an entrance offers no h2 ───────────────────────────
"$BIN" create proxy fwd -p $((P+4)) --backend "127.0.0.1:$((P+2))" --tls --cert "$T/e.pem" --key "$T/e.key" -s \
    >/dev/null 2>&1
sleep 0.6
expect "a proxy with a backend of its own offers no h2, having no authority to route by" \
    "$(curl -sk --noproxy '*' -m 5 "https://127.0.0.1:$((P+4))/who.txt" -o /dev/null -w '%{http_version}')" "1.1"

# An answer that was framed whole ends with END_STREAM, not a reset: measured on the live entrance, every completed
# request left one h2_resets_out, which is a client being told its answer was cancelled after it was delivered.
# Waited on the stream count, which is the proof the request was counted at all, and only then are the resets
# read: waiting on the resets themselves would be waiting for the defect.
r0=$(tally_of h2_resets_out); s0=$(tally_of h2_streams)
case "$r0" in ''|*[!0-9]*) bad "the entrance reports h2_resets_out" "got '$r0'" ;; *) ok "the entrance reports h2_resets_out" ;; esac
hc one.example.com /who.txt >/dev/null
for _ in $(seq 1 60); do [ "$(tally_of h2_streams)" != "$s0" ] && break; sleep 0.2; done
expect "a completed answer leaves no reset behind" "$(tally_of h2_resets_out)" "$r0"

# ── HTTP/3 on the same port ────────────────────────────────────────────────
# A browser learns of it from Alt-Svc on a TCP answer and tries UDP next time; the streams on it are routed the same
# way, which is what lib_proxy_http3.py holds down.
alt=$(hc one.example.com /who.txt -o /dev/null -D - | tr -d '\r' | grep -i '^alt-svc:' | head -1)
case "$alt" in *h3=*) ok "an answer over TCP names the HTTP/3 port in Alt-Svc ($alt)" ;;
                  *) bad "Alt-Svc" "got '$alt'" ;; esac

cp "$T/big.txt" "$T/one/big.txt"
h3out=$(python3 "$HERE/lib_proxy_http3.py" "$E" "$T/e.pem" "$T/big.txt" 2>&1)
echo "$h3out" | sed -n 's/^  \(PASS\|FAIL\|SKIP\)/  \1/p'
h3p=$(echo "$h3out" | sed -n 's/^Results: \([0-9]*\) passed.*/\1/p')
h3f=$(echo "$h3out" | sed -n 's/^Results: [0-9]* passed, \([0-9]*\) failed/\1/p')
TOTAL=$((TOTAL + h3p + h3f)); PASS=$((PASS + h3p)); FAIL=$((FAIL + h3f))

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
