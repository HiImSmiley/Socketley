#!/usr/bin/env bash
# Integration test: --health-check http against a TLS backend.
#
# It used to be refused at start, and the reason was honest: the probe wrote a
# plaintext GET straight at the backend socket, which a TLS backend answers with
# a handshake failure, so every backend would have been marked unhealthy while
# they were all fine.  What an operator was left with was --health-check tcp,
# which cannot tell a listening socket from a working server -- and telling
# those two apart is the whole reason a health check exists.
#
# The probe handshakes now, through the same memory BIO pair and the same
# io_uring submissions the data path uses, and against the same trust store.
# Three things have to be true at once for that to be worth having:
#
#   the proxy comes up at all with the two options together
#
#   the probe reaches the application and not merely the socket: a backend that
#   accepts, handshakes and serves ordinary requests, and answers the health
#   path 503, must be taken out of rotation.  The --health-check tcp case is run
#   side by side on the same pair of backends and must keep that backend in
#   rotation -- that is the documented limitation, stated as a measurement, and
#   it is also what makes the http result mean the probe rather than the machine
#
#   the probe is not a hole in the verification the data path insists on: a
#   backend whose certificate this proxy cannot verify must be marked unhealthy.
#   A probe that accepted any certificate would report a rotation full of
#   endpoints the data path is about to refuse to talk to
#
# EVERY PROXY HERE HAS TWO BACKENDS, and that is not padding.  With a single
# backend select_and_resolve_backend does not consult health at all -- there is
# nowhere for an unhealthy verdict to send the request instead -- so a one-
# backend test would report the same thing whether the probe worked or not.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate hctls

GOOD_BE=$((SL_PORT_BASE+771))     # trusted certificate, answers the health path 200
SICK_BE=$((SL_PORT_BASE+773))     # trusted certificate, answers the health path 503
UNTR_BE=$((SL_PORT_BASE+775))     # answers everything 200, signed by a CA we never hand over
HTTP_PX=$((SL_PORT_BASE+770))     # the two backends above, probed with --health-check http
TCP_PX=$((SL_PORT_BASE+772))      # the same two, probed with --health-check tcp (the control)
VER_PX=$((SL_PORT_BASE+774))      # good + untrusted, probed with --health-check http
REQS=12
PASS=0; FAIL=0; TOTAL=0
BE_PIDS=()
TMPD=$(mktemp -d)

cleanup() {
    for n in hc_http hc_tcp hc_ver; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.2
    for n in hc_http hc_tcp hc_ver; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    for p in "${BE_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    rm -rf "$TMPD"
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

echo "=== Integration: --health-check http against a TLS backend ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: python3 and openssl are both required"; exit 0
fi
if ! python3 -c "import ssl" >/dev/null 2>&1; then
    echo "  SKIP: python3 has no ssl module"; exit 0
fi

# Two independent self-signed certificates.  The second is never given to any
# proxy as a trust store, which is what makes the untrusted case untrusted
# rather than merely different.
for who in trusted other; do
    openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/$who.key" -out "$TMPD/$who.crt" \
        -days 2 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
        >/dev/null 2>&1 || { echo "  SKIP: could not generate a test certificate"; exit 0; }
done

# ---- the TLS backends -----------------------------------------------------
#
# Each answers an ordinary request with its own name, so which backend served a
# request is read off the body rather than guessed from a count.  "sick" is the
# shape a TCP check cannot see: listening, handshaking, serving -- and saying no
# on the health path alone.
cat > "$TMPD/be.py" <<'PY'
import socket, ssl, sys, threading

name, mode, port, crt, key = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)
print("ready", flush=True)

def answer(status, body):
    return ("HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (status, len(body), body)).encode()

def serve(raw):
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        try: raw.close()
        except OSError: pass
        return
    try:
        req = c.recv(65536).decode("latin1", "replace")
        line = req.split("\r\n", 1)[0]
        parts = line.split(" ")
        path = parts[1] if len(parts) > 1 else "/"
        if path.startswith("/healthz"):
            c.sendall(answer("503 Service Unavailable", "sick\n")
                      if mode == "sick" else answer("200 OK", "alive\n"))
        else:
            c.sendall(answer("200 OK", name))
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
PY

python3 "$TMPD/be.py" GOOD ok   "$GOOD_BE" "$TMPD/trusted.crt" "$TMPD/trusted.key" \
        >"$TMPD/good.log" 2>&1 & BE_PIDS+=($!)
python3 "$TMPD/be.py" SICK sick "$SICK_BE" "$TMPD/trusted.crt" "$TMPD/trusted.key" \
        >"$TMPD/sick.log" 2>&1 & BE_PIDS+=($!)
python3 "$TMPD/be.py" UNTR ok   "$UNTR_BE" "$TMPD/other.crt"   "$TMPD/other.key" \
        >"$TMPD/untr.log" 2>&1 & BE_PIDS+=($!)
for p in "$GOOD_BE" "$SICK_BE" "$UNTR_BE"; do
    ready_tcp 127.0.0.1 "$p" 8 || { echo "  SKIP: a TLS backend never listened"; exit 0; }
done

daemon_start "$BIN"

create_ok "http-probed proxy created" "$BIN" create proxy hc_http -p "$HTTP_PX" \
    --backend "https://127.0.0.1:$GOOD_BE,https://127.0.0.1:$SICK_BE" \
    --ca "$TMPD/trusted.crt" \
    --health-check http --health-path /healthz --health-interval 1 --health-threshold 1
create_ok "tcp-probed proxy created" "$BIN" create proxy hc_tcp -p "$TCP_PX" \
    --backend "https://127.0.0.1:$GOOD_BE,https://127.0.0.1:$SICK_BE" \
    --ca "$TMPD/trusted.crt" \
    --health-check tcp --health-interval 1 --health-threshold 1
create_ok "verification proxy created" "$BIN" create proxy hc_ver -p "$VER_PX" \
    --backend "https://127.0.0.1:$GOOD_BE,https://127.0.0.1:$UNTR_BE" \
    --ca "$TMPD/trusted.crt" \
    --health-check http --health-path /healthz --health-interval 1 --health-threshold 1

# ── the refusal is gone ────────────────────────────────────────────────────
#
# `start` exited 2 and left the runtime `failed` while the gate in
# proxy_instance::start() rejected --health-check http beside a TLS backend.
START_RC=0
"$BIN" start hc_http >"$TMPD/start.out" 2>&1 || START_RC=$?
assert_eq "$START_RC" "0" "--health-check http with a TLS backend is accepted at start"
# `ps` lists running runtimes only, with an "Up <n> seconds" status, so a row
# for this name is the state assertion: a proxy the gate refused never gets one.
STATE=$("$BIN" ps 2>/dev/null | awk '$2 == "hc_http" && /Up / { print "running" }' | head -1)
assert_eq "${STATE:-<not-listed>}" "running" "--health-check http with a TLS backend reaches running"

"$BIN" start hc_tcp >/dev/null 2>&1 || true
"$BIN" start hc_ver >/dev/null 2>&1 || true
for p in "$HTTP_PX" "$TCP_PX" "$VER_PX"; do
    ready_tcp 127.0.0.1 "$p" 8 || echo "  note: a proxy on $p never listened"
done

# Two sweeps at --health-interval 1, before a single request is sent.  Ordering
# matters: it keeps the circuit breaker out of the result entirely, so what
# takes a backend out of rotation below can only be the probe.
sleep 4

# hits PORT PREFIX -> "<GOODcount> <SICK-or-UNTR count> <non-200 count>"
hits() {
    python3 - "$1" "$2" "$REQS" <<'PY'
import socket, sys
port, prefix, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
good = other = bad = 0
for _ in range(n):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=8)
        s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % prefix).encode())
        buf = b""
        while len(buf) < 8192:
            b = s.recv(8192)
            if not b:
                break
            buf += b
        s.close()
    except OSError:
        bad += 1
        continue
    if not buf.startswith(b"HTTP/1.1 2"):
        bad += 1
    elif buf.endswith(b"GOOD"):
        good += 1
    else:
        other += 1
print(good, other, bad)
PY
}

# ── the probe reaches the application, not just the socket ────────────────
read -r G O B <<<"$(hits "$HTTP_PX" /hc_http/)"
assert_eq "$G" "$REQS" "http probe: every request lands on the backend whose health path is 200"
assert_eq "$O" "0"     "http probe: the backend answering /healthz 503 serves nothing"
assert_eq "$B" "0"     "http probe: no request failed"

# ── the control, and the documented limitation as a measurement ────────────
#
# The same two backends behind a TCP check.  A connect succeeds against the
# sick one, so it keeps its share -- that is what --health-check tcp cannot see,
# and if this ever reports 0 the http result above stops meaning anything.
read -r G2 O2 B2 <<<"$(hits "$TCP_PX" /hc_tcp/)"
TCP_SICK_SERVED=$([ "$O2" -gt 0 ] && echo yes || echo no)
assert_eq "$TCP_SICK_SERVED" "yes" \
          "tcp probe: the same backend still serves, which is what http now catches"
assert_eq "$B2" "0" "tcp probe: no request failed"

# ── the probe is not the hole in the verification ─────────────────────────
read -r G3 O3 B3 <<<"$(hits "$VER_PX" /hc_ver/)"
assert_eq "$G3" "$REQS" "http probe: an unverifiable TLS backend is out of rotation before any request"
assert_eq "$O3" "0"     "http probe: nothing was served by the unverifiable backend"
assert_eq "$B3" "0"     "http probe: no request reached the unverifiable backend and failed"

echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ]
