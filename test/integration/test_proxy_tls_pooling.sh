#!/usr/bin/env bash
# Integration test: a TLS backend connection is reused, and only ever by the
# request it belongs to.
#
# ─── WHAT CHANGED ───────────────────────────────────────────────────────────
#
# Until now a backend socket carrying a TLS session was never pooled, so every
# single request to an https:// backend paid for a full handshake: a TCP
# handshake, a certificate chain to verify, a key exchange, and then one
# request.  The stated reason was that the pool is keyed on a host and a port
# while a TLS connection carries a negotiated session, a peer verified against
# a name, a client certificate and a record layer part way through a stream.
#
# Three of those four are functions of that key -- start_backend_tls builds the
# session with create_ssl_client(host), where host is the same
# backend_endpoint_of() answer the pool files the socket under -- and the
# fourth belongs to the proxy's one backend tls_context.  The record layer is
# answered by pooling the session with the descriptor instead of the descriptor
# alone.
#
# ─── THE ORACLE ─────────────────────────────────────────────────────────────
#
# Counted at the backend, which is the end that does the work and the only one
# with no reason to flatter the proxy.  The Python backends below count two
# things per listener: a completed TLS handshake, and an HTTP request served.
# The saving is the ratio, and it is meaningless without both numbers -- a
# proxy that dropped requests would show a wonderful handshake count.
#
# The SNI name of every handshake is recorded with it.  That is what makes
# phase 2 an identity test rather than a load-balancing test: the two backends
# are configured under names that are different strings for the same machine,
# "localhost" and "127.0.0.1", so a pooled socket that crossed between them
# would be a socket whose peer was verified against one name serving a request
# routed to the other.  The names are visible at the backend because the proxy
# sends one as SNI and, for the address literal, deliberately sends none at all
# (RFC 6066 allows host names there only).
#
# ─── THE VACUITY GUARDS ─────────────────────────────────────────────────────
#
# "Few handshakes" passes trivially against a proxy that forwards nothing, and
# "no crossing" passes trivially against a proxy that only ever uses one
# backend.  So:
#
#   * every phase asserts the request count as well as the handshake count,
#     and every response body is checked to be the one that request asked for;
#   * phase 2 asserts that BOTH backends served requests, and that neither
#     served more than the round robin could have sent it;
#   * phase 3 asserts that a restart DOES handshake again -- the pool must not
#     survive the context that verified it -- which is the one place in this
#     file where a fresh handshake is the pass;
#   * phase 4 asserts a specific body, not merely a 200: the failure it is
#     written for produces a perfectly well-formed answer belonging to
#     somebody else.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_daemon.sh
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate proxy-tls-pool
TMPD="$SOCKETLEY_TMPD"

BE_A=$((SL_PORT_BASE+621)); BE_B=$((SL_PORT_BASE+622)); BE_C=$((SL_PORT_BASE+623))
PX_ONE=$((SL_PORT_BASE+625)); PX_TWO=$((SL_PORT_BASE+626)); PX_UNBID=$((SL_PORT_BASE+627))
REQS=${REQS:-40}
BEPIDS=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in tpool1 tpool2 tpoolu; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    for p in $BEPIDS; do kill "$p" 2>/dev/null || true; done
    for p in $BEPIDS; do wait "$p" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a TLS backend connection is pooled, and only for its own endpoint ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1 \
   || ! command -v curl >/dev/null 2>&1; then
    echo "  SKIP: python3, openssl and curl are all required"; exit 0
fi

# ── certificates ─────────────────────────────────────────────────────────────
#
# Two leaves under two different names for the same machine.  That is the whole
# point of the pair: the addresses differ only in how they are spelled, so
# nothing but the pool's own key can keep the two apart.
openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/ip.key" -out "$TMPD/ip.pem" \
    -days 2 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    >/dev/null 2>&1 || { echo "  SKIP: could not generate a certificate"; exit 0; }
openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/host.key" -out "$TMPD/host.pem" \
    -days 2 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
    >/dev/null 2>&1 || { echo "  SKIP: could not generate a certificate"; exit 0; }
# One trust store holding both, so --ca accepts either and the *name* is the
# only thing left that can reject a peer.
cat "$TMPD/ip.pem" "$TMPD/host.pem" > "$TMPD/both.pem"

# ── the backend ──────────────────────────────────────────────────────────────
#
# Counts handshakes and requests, records the SNI of every handshake, and can
# be asked to volunteer an extra answer on a socket after the exchange on it is
# over -- which is the shape phase 4 needs and the shape a pooled socket must
# never pass on.
cat > "$TMPD/be.py" <<'PYEOF'
import os, socket, ssl, sys, threading

port     = int(sys.argv[1])
cert     = sys.argv[2]
key      = sys.argv[3]
statef   = sys.argv[4]
unbidden = len(sys.argv) > 5 and sys.argv[5] == "unbidden"

lock       = threading.Lock()
handshakes = 0
requests   = 0
snis       = set()

def record():
    with lock:
        tmp = statef + ".tmp"
        with open(tmp, "w") as f:
            f.write("handshakes %d\nrequests %d\nsni %s\n"
                    % (handshakes, requests, ",".join(sorted(snis)) or "-"))
        os.replace(tmp, statef)

# CPython runs this for every handshake and passes None when the ClientHello
# carried no server_name extension at all, which is the case that matters here:
# create_ssl_client suppresses SNI for an address literal, because RFC 6066
# allows host names there only and some servers refuse the handshake outright
# when an address turns up in it.  So "-no-name-" is a real observation and not
# a default -- the set records every distinct name this listener was ever asked
# for, and an endpoint that only ever appears under one of them is an endpoint
# no pooled socket has crossed away from.
def sni_cb(sock, name, ctx_unused):
    with lock:
        snis.add(name if name else "-no-name-")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.sni_callback = sni_cb

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)
record()
print("ready", flush=True)


def serve(raw):
    global handshakes, requests
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        try: raw.close()
        except OSError: pass
        return
    with lock:
        handshakes += 1
    record()
    try:
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
            while b"\r\n\r\n" in buf:
                head, buf = buf.split(b"\r\n\r\n", 1)
                line = head.split(b"\r\n", 1)[0].split(b" ")
                if len(line) < 2:
                    break
                mark = line[1].lstrip(b"/")
                # The body names this backend AND the request, so a response
                # that reached the wrong client or came from the wrong peer is
                # visible in the body rather than only in a counter.
                body = b"%d:%s" % (port, mark)
                with lock:
                    requests += 1
                record()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                          b"Connection: keep-alive\r\n\r\n%s" % (len(body), body))
                if unbidden:
                    # An answer nobody asked for, written onto the socket after
                    # the exchange on it is finished.  Under TLS this is a
                    # record like any other -- indistinguishable from a session
                    # ticket until it has been decrypted -- which is exactly
                    # why the proxy's probe has to decrypt rather than peek.
                    extra = b"%d:VOLUNTEERED" % port
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                              b"Connection: keep-alive\r\n\r\n%s" % (len(extra), extra))
    except OSError:
        pass
    finally:
        try: c.close()
        except OSError: pass


while True:
    try:
        raw, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(raw,), daemon=True).start()
PYEOF

start_be() {   # $1 port  $2 cert  $3 key  $4 statefile  $5 log  [$6 unbidden]
    python3 "$TMPD/be.py" "$1" "$2" "$3" "$4" "${6:-plain}" >"$5" 2>&1 &
    BEPIDS="$BEPIDS $!"
    local i
    for i in $(seq 1 80); do grep -q ready "$5" 2>/dev/null && break; sleep 0.1; done
    grep -q ready "$5" 2>/dev/null
}

field() {   # $1 statefile  $2 key
    awk -v k="$2" '$1==k {print $2}' "$1" 2>/dev/null
}

wait_port() { local i; for i in $(seq 1 80); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
    sleep 0.1; done; return 1; }

daemon_start "$BIN"

# ─────────────────────────────────────────────────────────────────────────────
# 1. The saving, on one https:// backend.
# ─────────────────────────────────────────────────────────────────────────────
start_be "$BE_A" "$TMPD/ip.pem" "$TMPD/ip.key" "$TMPD/a.state" "$TMPD/a.log" \
    || { echo "  SKIP: backend would not start"; exit 0; }

"$BIN" create proxy tpool1 -p "$PX_ONE" --backend "https://127.0.0.1:$BE_A" \
    --protocol http --ca "$TMPD/both.pem" -s >/dev/null 2>&1
if ! wait_port "$PX_ONE"; then
    echo "  FATAL: the proxy never listened on $PX_ONE"
    tail -5 "$SOCKETLEY_DLOG" 2>/dev/null | sed 's/^/         /'
    exit 2
fi

BODIES_OK=1
for i in $(seq 1 "$REQS"); do
    got=$(timeout 8 curl -s -m 6 "http://127.0.0.1:$PX_ONE/tpool1/r$i" 2>/dev/null)
    [ "$got" = "$BE_A:r$i" ] || BODIES_OK=0
done

H1=$(field "$TMPD/a.state" handshakes); R1=$(field "$TMPD/a.state" requests)
H1=${H1:-0}; R1=${R1:-0}

echo "  phase 1: $REQS requests to one https:// backend -> $H1 TLS handshake(s), $R1 served"

if [ "$BODIES_OK" = "1" ] && [ "$R1" = "$REQS" ]; then ok
else bad "phase1-delivery" "expected $REQS correct bodies, served=$R1 bodies_ok=$BODIES_OK"; fi

# The headline.  A handshake per request is the old behaviour and is what this
# has to beat; the bound is generous on purpose -- curl opens a fresh client
# connection each time, and the proxy is free to keep more than one backend
# socket -- because the claim being made is "not one per request", not an exact
# count that would turn a scheduling wobble into a red build.
#
# The lower bound is not decoration: "$H1 -lt $REQS" is satisfied by zero, and
# zero is what a proxy that never reached the backend reports.  It has to have
# handshaked at least once and far fewer than once per request.
if [ "$H1" -ge 1 ] && [ "$H1" -lt "$REQS" ] && [ "$H1" -le 4 ]; then ok
else bad "phase1-handshakes" "expected between 1 and 4 handshakes for $REQS requests, got $H1"; fi

# And the name that was pinned to those handshakes.  An address literal must be
# checked against the certificate's iPAddress SAN with no SNI sent at all.
S1=$(field "$TMPD/a.state" sni)
if [ "$S1" = "-no-name-" ]; then ok
else bad "phase1-sni" "an https://127.0.0.1 backend must be asked for by no name at all, saw '$S1'"; fi

"$BIN" stop tpool1 >/dev/null 2>&1; "$BIN" remove tpool1 >/dev/null 2>&1

# ─────────────────────────────────────────────────────────────────────────────
# 2. Identity: two endpoints that differ only in how the same machine is named.
# ─────────────────────────────────────────────────────────────────────────────
start_be "$BE_B" "$TMPD/host.pem" "$TMPD/host.key" "$TMPD/b.state" "$TMPD/b.log" \
    || { echo "  SKIP: second backend would not start"; exit 0; }

"$BIN" create proxy tpool2 -p "$PX_TWO" \
    --backend "https://127.0.0.1:$BE_A" --backend "https://localhost:$BE_B" \
    --protocol http --ca "$TMPD/both.pem" -s >/dev/null 2>&1
if ! wait_port "$PX_TWO"; then
    echo "  FATAL: the two-backend proxy never listened on $PX_TWO"
    exit 2
fi

A_BEFORE=$(field "$TMPD/a.state" requests); A_BEFORE=${A_BEFORE:-0}
CROSSED=0; BAD2=0
for i in $(seq 1 "$REQS"); do
    got=$(timeout 8 curl -s -m 6 "http://127.0.0.1:$PX_TWO/tpool2/q$i" 2>/dev/null)
    case "$got" in
        "$BE_A:q$i"|"$BE_B:q$i") ;;                 # either backend, own marker
        "$BE_A:VOLUNTEERED"|"$BE_B:VOLUNTEERED") CROSSED=1 ;;
        *) BAD2=1 ;;
    esac
done

HA=$(field "$TMPD/a.state" handshakes); RA=$(field "$TMPD/a.state" requests)
HB=$(field "$TMPD/b.state" handshakes); RB=$(field "$TMPD/b.state" requests)
SA=$(field "$TMPD/a.state" sni);        SB=$(field "$TMPD/b.state" sni)
HA=${HA:-0}; RA=${RA:-0}; HB=${HB:-0}; RB=${RB:-0}
A_SHARE=$((RA - A_BEFORE))

echo "  phase 2: $REQS requests over two names -> 127.0.0.1 served $A_SHARE (sni '$SA'), localhost served $RB (sni '$SB')"

if [ "$BAD2" = "0" ] && [ "$CROSSED" = "0" ] \
   && [ "$((A_SHARE + RB))" = "$REQS" ]; then ok
else bad "phase2-delivery" "every response must be this request's own; crossed=$CROSSED bad=$BAD2 a=$A_SHARE b=$RB"; fi

# Both used, so "never crossed" is not true because one of them was idle.
if [ "$A_SHARE" -gt 0 ] && [ "$RB" -gt 0 ]; then ok
else bad "phase2-vacuity" "both backends must serve; 127.0.0.1=$A_SHARE localhost=$RB"; fi

# THE IDENTITY ASSERTION.  The proxy pins the endpoint's name to the session
# before the ClientHello, so a socket that ever crossed between these two would
# put the wrong name on the wire -- or, for the literal, put a name on the wire
# at all.  Each backend must have seen exactly one name, and its own.
if [ "$SA" = "-no-name-" ]; then ok
else bad "phase2-sni-ip" "the https://127.0.0.1 endpoint must send no SNI, and never localhost's name, saw '$SA'"; fi
if [ "$SB" = "localhost" ]; then ok
else bad "phase2-sni-host" "the https://localhost endpoint must send SNI 'localhost', saw '$SB'"; fi

# And still reusing: two endpoints, far fewer than $REQS handshakes between
# them, and at least one apiece — the same lower bound, for the same reason.
if [ "$HA" -ge 1 ] && [ "$HB" -ge 1 ] && [ "$((HA + HB))" -lt "$REQS" ]; then ok
else bad "phase2-handshakes" "expected reuse across both endpoints, got $HA + $HB for $REQS requests"; fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. A pooled session must not outlive the context that verified it.
#
# The one phase where a fresh handshake is the pass.  The proxy's backend
# tls_context -- the trust store it checks chains against and the client
# certificate it presents -- is built at start and thrown away at stop, so a
# pooled socket that survived a restart would be a connection verified by a
# configuration that is no longer in force.
# ─────────────────────────────────────────────────────────────────────────────
H_BEFORE=$((HA + HB))
"$BIN" stop tpool2 >/dev/null 2>&1
sleep 0.4
"$BIN" start tpool2 >/dev/null 2>&1
# Recorded rather than swallowed.  This file failed once inside a sweep under
# load and has not been reproduced since: 64 further runs, 58 of them under six
# or nine busy cores, all green.  Ruled out along the way -- test order (four
# orderings, no per-test disagreement), port exhaustion (peak 4,875 TIME_WAIT
# against ~28,000 ephemeral ports), and the stop-wait above, which was removed
# entirely and still passed 5 of 5.  The cause is unknown, so the useful change
# is not a guess at a fix but making the next occurrence explain itself:
# `served=0` on its own cannot tell "the port never came back" from "it came
# back and answered wrongly", and those two want different investigations.
PORT_BACK=1; wait_port "$PX_TWO" || PORT_BACK=0
got=$(timeout 8 curl -s -m 6 "http://127.0.0.1:$PX_TWO/tpool2/after-restart" 2>/dev/null)
HA2=$(field "$TMPD/a.state" handshakes); HB2=$(field "$TMPD/b.state" handshakes)
HA2=${HA2:-0}; HB2=${HB2:-0}
H_AFTER=$((HA2 + HB2))

echo "  phase 3: restart -> handshakes went $H_BEFORE -> $H_AFTER"

case "$got" in
    "$BE_A:after-restart"|"$BE_B:after-restart") SERVED=1 ;;
    *) SERVED=0 ;;
esac
if [ "$SERVED" = "1" ] && [ "$H_AFTER" -gt "$H_BEFORE" ]; then ok
else bad "phase3-restart" "the first request after a restart must handshake again and be served; served=$SERVED port_back=$PORT_BACK $H_BEFORE -> $H_AFTER"; fi

"$BIN" stop tpool2 >/dev/null 2>&1; "$BIN" remove tpool2 >/dev/null 2>&1

# ─────────────────────────────────────────────────────────────────────────────
# 4. A backend that speaks on an idle pooled socket.
#
# This is bbf4e9f's defect over an encrypted leg.  The backend answers, and then
# writes a second answer nobody asked for onto the same socket.  The proxy pools
# that socket; the next request borrows it.  What is waiting on it is a TLS
# record, and a record carrying application data looks exactly like a session
# ticket from outside -- so a probe that asks the kernel "are there bytes?" is
# answering the wrong question in both directions.  Nothing here may ever come
# back marked VOLUNTEERED.
# ─────────────────────────────────────────────────────────────────────────────
start_be "$BE_C" "$TMPD/ip.pem" "$TMPD/ip.key" "$TMPD/c.state" "$TMPD/c.log" \
    unbidden || { echo "  SKIP: unbidden backend would not start"; exit 0; }

"$BIN" create proxy tpoolu -p "$PX_UNBID" --backend "https://127.0.0.1:$BE_C" \
    --protocol http --ca "$TMPD/both.pem" -s >/dev/null 2>&1
if ! wait_port "$PX_UNBID"; then
    echo "  FATAL: the unbidden-backend proxy never listened on $PX_UNBID"
    exit 2
fi

VOL=0; MISS=0; N4=12
for i in $(seq 1 "$N4"); do
    got=$(timeout 8 curl -s -m 6 "http://127.0.0.1:$PX_UNBID/tpoolu/u$i" 2>/dev/null)
    case "$got" in
        "$BE_C:u$i")          ;;
        *VOLUNTEERED*) VOL=1 ;;
        *) MISS=$((MISS+1)) ;;
    esac
    sleep 0.05
done
RC=$(field "$TMPD/c.state" requests); RC=${RC:-0}

echo "  phase 4: $N4 requests to a backend that volunteers answers -> $MISS wrong, $VOL crossed"

# The confidentiality assertion.  Not "mostly right": one is a defect.
if [ "$VOL" = "0" ]; then ok
else bad "phase4-crosstalk" "a client received an answer the backend volunteered on a pooled socket"; fi

# The vacuity guard for it.  A proxy that answered nothing would also never
# hand over a volunteered answer, so the requests have to have been served.
if [ "$MISS" = "0" ] && [ "$RC" -ge "$N4" ]; then ok
else bad "phase4-delivery" "every request must still get its own answer; wrong=$MISS served=$RC"; fi

echo
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ] || echo "  failed: $FAIL"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
