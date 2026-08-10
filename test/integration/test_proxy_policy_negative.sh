#!/usr/bin/env bash
# Integration test: the proxy's policy flags do NOTHING when they should do
# nothing, and something measurable when they should.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# --circuit-threshold already appeared in two test files before this one, and
# both of them asserted that the breaker OPENS.  Neither asserted that it stays
# SHUT, and two faults sat in that gap: a clean backend close after an answer,
# and a client aborting mid-exchange, each charged to the breaker as a backend
# failure.  Five of either took a perfectly healthy backend out of rotation and
# every later client was answered with an instant EOF.  A test that only watches
# a limiter fire cannot see a limiter that fires when nothing is wrong.
#
# So every refusal below is asserted next to a case that must keep working. That
# pairing is the whole design: "the breaker opened" passes on a build that
# refuses everything, and "the request was served" passes on a build with no
# breaker at all.  Only the two together say the policy is a policy.
#
# ─── WHAT IS PINNED HERE ────────────────────────────────────────────────────
#
#   1. the breaker stays shut for four things that are not backend failures,
#      and opens for the one that is
#   2. --retry replays idempotent methods and refuses non-idempotent ones, which
#      is a data-integrity question rather than an availability one: a POST that
#      reaches two backends because the first died after reading it is a
#      duplicate side effect nobody asked for
#   3. --retry-all replays them anyway, which is what it is for — pinned so that
#      it stays a deliberate decision and not an accident
#   4. --max-connections refuses past the limit and releases when connections go
#   5. --rate-limit and --global-rate-limit limit to the configured rate, are
#      measured rather than eyeballed, and let a compliant client through
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate policyneg

BE1=$((SL_PORT_BASE+940))
BE2=$((SL_PORT_BASE+941))
PX=$((SL_PORT_BASE+942))
PASS=0; FAIL=0; TOTAL=0
BEPIDS=""

cleanup() {
    for r in pn_px; do "$BIN" stop "$r" 2>/dev/null || true; done
    sleep 0.2
    for r in pn_px; do "$BIN" remove "$r" 2>/dev/null || true; done
    for p in $BEPIDS; do kill "$p" 2>/dev/null || true; done
    [ -n "${TMPD:-}" ] && rm -rf "$TMPD"
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

# For the rate limiters, where the answer is a number in a range rather than a
# value.  The range is stated at each call site with why it is that wide.
assert_range() {
    TOTAL=$((TOTAL+1))
    local got="$1" lo="$2" hi="$3" label="$4"
    if [ -n "$got" ] && [ "$got" -ge "$lo" ] && [ "$got" -le "$hi" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', wanted $lo..$hi"
    fi
}

echo "=== Integration: proxy policy flags refuse only what they should ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

TMPD=$(mktemp -d)

# ── the backend ─────────────────────────────────────────────────────────────
#
# One script, several behaviours, because the scenarios differ only in what the
# backend does after it has read the request.  It counts what it received and
# writes that to a file, which is how "the request reached this backend" is
# asserted separately from "the client got an answer" — the two come apart in
# exactly the cases this file is about.
cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading, time
port = int(sys.argv[1]); mode = sys.argv[2]
param = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
tag = sys.argv[4]; countfile = sys.argv[5]

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(128)
seen = [0]; lock = threading.Lock()

def note():
    with lock:
        seen[0] += 1
        with open(countfile, "w") as f:
            f.write(str(seen[0]))
        return seen[0]

def read_request(c):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = c.recv(65536)
        if not chunk:
            return None
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    n = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":", 1)[1].strip())
    while len(rest) < n:
        chunk = c.recv(65536)
        if not chunk:
            break
        rest += chunk
    return head

def handle(c):
    try:
        c.settimeout(30)
        while True:
            if read_request(c) is None:
                return
            note()
            if mode == "close_before":
                return
            if mode == "slow":
                time.sleep(param)
            body = ("OK-" + tag).encode()
            close = (mode == "close_after")
            c.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s\r\n"
                       % (len(body), "Connection: close\r\n" if close else "")).encode() + body)
            if close:
                c.shutdown(socket.SHUT_WR)
                return
    except Exception:
        pass
    finally:
        try: c.close()
        except OSError: pass

while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY

# One request.  Prints the status line, or ABORTED/EOF/TIMEOUT.
cat > "$TMPD/req.py" <<'PY'
import socket, struct, sys
port = int(sys.argv[1]); path = sys.argv[2]
method = sys.argv[3] if len(sys.argv) > 3 else "GET"
body = sys.argv[4].encode() if len(sys.argv) > 4 and sys.argv[4] != "-" else b""
abort = "--abort" in sys.argv
req = ("%s %s HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n"
       % (method, path, len(body))).encode() + body
try:
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(10)
    if abort:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.sendall(req); s.close(); print("ABORTED"); sys.exit(0)
    s.sendall(req)
    data = b""
    while b"\r\n\r\n" not in data:
        c = s.recv(65536)
        if not c: break
        data += c
    s.close()
    print(data.split(b"\r\n", 1)[0].decode("latin1") if data else "EOF")
except socket.timeout:
    print("TIMEOUT")
except Exception as e:
    print("ERR-%s" % type(e).__name__)
PY

# How many requests were answered on ONE connection, and how fast — the number a
# rate limit has to be checked against.
cat > "$TMPD/burst.py" <<'PY'
import socket, sys
port = int(sys.argv[1]); n = int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(2.0)
req = b"GET /pn_px/r HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
ok = 0
for _ in range(n):
    try:
        s.sendall(req)
        got = b""
        while b"\r\n\r\n" not in got:
            c = s.recv(65536)
            if not c: raise EOFError()
            got += c
        ok += 1
    except Exception:
        break
try: s.close()
except Exception: pass
print(ok)
PY

# A client that stays inside the limit must never be refused.  Without this the
# rate-limit assertions would pass on a build that closes every connection.
cat > "$TMPD/paced.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); rate = float(sys.argv[2]); secs = float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(3.0)
req = b"GET /pn_px/p HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
ok = 0
# Spend the initial full bucket first, so what follows measures the refill.
for _ in range(int(rate)):
    try:
        s.sendall(req)
        if s.recv(65536): ok += 1
    except Exception:
        break
end = time.time() + secs
while time.time() < end:
    time.sleep(1.0 / rate)
    try:
        s.sendall(req)
        if not s.recv(65536): break
        ok += 1
    except Exception:
        break
try: s.close()
except Exception: pass
print(ok)
PY

# Open N connections at once and report how many are served.
cat > "$TMPD/conns.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); n = int(sys.argv[2])
held = []
for _ in range(n):
    try:
        c = socket.create_connection(("127.0.0.1", port), 3); c.settimeout(2)
        held.append(c)
    except Exception:
        pass
time.sleep(0.3)
served = 0
for c in held:
    try:
        c.sendall(b"GET /pn_px/c HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n")
        d = c.recv(4096)
        if d and d.startswith(b"HTTP/"): served += 1
    except Exception:
        pass
for c in held:
    try: c.close()
    except Exception: pass
print(served)
PY

daemon_start "$BIN"

start_backend() {   # name port mode param
    python3 "$TMPD/be.py" "$2" "$3" "${4:-0}" "$1" "$TMPD/$1.count" \
        >"$TMPD/$1.log" 2>&1 &
    BEPIDS="$BEPIDS $!"
    ready_tcp 127.0.0.1 "$2" 15 || { echo "  FAIL: backend $1 did not start"; exit 1; }
}

stop_backends() {
    for p in $BEPIDS; do kill "$p" 2>/dev/null || true; done
    BEPIDS=""
    sleep 0.4
}

make_proxy() {      # backends flags...
    "$BIN" stop pn_px >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove pn_px >/dev/null 2>&1 || true
    local backends="$1"; shift
    create_ok "proxy created" "$BIN" create proxy pn_px -p "$PX" \
        --backend "$backends" "$@" -s
    ready_tcp 127.0.0.1 "$PX" 15 || { echo "  FAIL: proxy did not start"; exit 1; }
}

count_of() { cat "$TMPD/$1.count" 2>/dev/null || echo 0; }
circuits() { "$BIN" stats pn_px 2>/dev/null | grep -c "circuit:open" || true; }

# ─── 1. the breaker stays shut for what is not a backend failure ────────────
#
# circuit_threshold is 5, so ten provocations is twice what it takes.  Each
# scenario ends by asking the proxy to serve one ordinary request: an open
# circuit is invisible until somebody asks, so that final request is the
# assertion and the count beside it is the diagnosis.

echo "  -- breaker: what must not open it --"

start_backend b1 "$BE1" close_after
make_proxy "127.0.0.1:$BE1"
for _ in $(seq 1 10); do python3 "$TMPD/req.py" "$PX" /pn_px/a >/dev/null 2>&1 || true; done
sleep 0.4
assert_eq "$(circuits)" "0" "backend closing cleanly after answering does not open the circuit"
assert_eq "$(python3 "$TMPD/req.py" "$PX" /pn_px/a2)" "HTTP/1.1 200 OK" "and the proxy still serves"
stop_backends

start_backend b2 "$BE1" slow 0.35
make_proxy "127.0.0.1:$BE1"
for _ in $(seq 1 10); do python3 "$TMPD/req.py" "$PX" /pn_px/b GET - --abort >/dev/null 2>&1 || true; done
sleep 0.5
assert_eq "$(circuits)" "0" "clients aborting mid-exchange do not open the circuit"
assert_eq "$(python3 "$TMPD/req.py" "$PX" /pn_px/b2)" "HTTP/1.1 200 OK" "and the proxy still serves"
stop_backends

# Slow but answering.  --backend-timeout defaults to 2s and the backend takes
# 0.35s, so this is a backend doing its job slowly rather than one failing; a
# breaker that charged latency would take it out of rotation for being busy.
start_backend b3 "$BE1" slow 0.35
make_proxy "127.0.0.1:$BE1"
SLOW_OK=0
for _ in $(seq 1 10); do
    [ "$(python3 "$TMPD/req.py" "$PX" /pn_px/c)" = "HTTP/1.1 200 OK" ] && SLOW_OK=$((SLOW_OK+1))
done
assert_eq "$SLOW_OK" "10" "a slow backend that answers is served every time"
assert_eq "$(circuits)" "0" "and being slow does not open the circuit"
stop_backends

# ─── 2. …and opens for the one thing that IS a backend failure ──────────────
#
# Without this the four assertions above are satisfied by deleting the breaker.
echo "  -- breaker: what must open it --"
start_backend b4 "$BE1" close_before
make_proxy "127.0.0.1:$BE1"
for _ in $(seq 1 10); do python3 "$TMPD/req.py" "$PX" /pn_px/d >/dev/null 2>&1 || true; done
sleep 0.4
assert_eq "$(circuits)" "1" "a backend closing BEFORE answering does open the circuit"
assert_eq "$(python3 "$TMPD/req.py" "$PX" /pn_px/d2)" "HTTP/1.1 503 Service Unavailable" \
          "and an open circuit answers 503 rather than trying anyway"
stop_backends

# ─── 3. --retry: which methods may be replayed ──────────────────────────────
#
# The first backend reads the request and dies without answering, so the request
# HAS reached it.  Whether the second backend sees it too is the whole question:
# for a POST that is a duplicate side effect, and no amount of availability
# makes that a good trade.
echo "  -- retry: only idempotent methods are replayed --"

retry_case() {   # method expect_second expect_status label
    stop_backends
    rm -f "$TMPD/r1.count" "$TMPD/r2.count"
    start_backend r1 "$BE1" close_before
    start_backend r2 "$BE2" ok
    make_proxy "127.0.0.1:$BE1,127.0.0.1:$BE2" --retry 2 ${EXTRA:-}
    local status
    status=$(python3 "$TMPD/req.py" "$PX" /pn_px/m "$1" "body-$1")
    sleep 0.3
    assert_eq "$(count_of r1)" "1" "$4: reached the first backend"
    assert_eq "$(count_of r2)" "$2" "$4: second backend saw it $2 time(s)"
    assert_eq "$status" "$3" "$4: client got $3"
}

retry_case GET     1 "HTTP/1.1 200 OK"          "GET is retried"
retry_case PUT     1 "HTTP/1.1 200 OK"          "PUT is retried"
# OPTIONS is safe and idempotent (RFC 7231 4.2.2) and the man page has always
# named it among the retried methods; the code did not retry it until this test
# was written, so an OPTIONS was answered 502 where the same GET was served.
retry_case OPTIONS 1 "HTTP/1.1 200 OK"          "OPTIONS is retried, as documented"
retry_case POST    0 "HTTP/1.1 502 Bad Gateway" "POST is NOT retried"
retry_case PATCH   0 "HTTP/1.1 502 Bad Gateway" "PATCH is NOT retried"

echo "  -- retry-all: replays them, deliberately --"
EXTRA="--retry-all"
retry_case POST 1 "HTTP/1.1 200 OK" "POST with --retry-all IS replayed"
EXTRA=""
stop_backends

# ─── 4. --max-connections ───────────────────────────────────────────────────
#
# What a caller past the limit experiences is the point: refused is retryable
# and visible, silently accepted and dropped is not.  The proxy accepts at the
# TCP level and closes at once, so the client sees a reset when it writes — and
# the assertion is on how many are SERVED, which is the only part a caller can
# act on.
echo "  -- max-connections --"
start_backend b5 "$BE1" ok
make_proxy "127.0.0.1:$BE1" --max-connections 3
assert_eq "$(python3 "$TMPD/conns.py" "$PX" 3)" "3" "three connections under a limit of three are all served"
assert_eq "$(python3 "$TMPD/conns.py" "$PX" 8)" "3" "eight against the same limit still serve exactly three"
# And the limit is about concurrency, not a lifetime budget: the previous
# connections are closed by now, so a fresh three must be served again.
sleep 0.6
assert_eq "$(python3 "$TMPD/conns.py" "$PX" 3)" "3" "the limit releases when connections close"
stop_backends

# ─── 5. --rate-limit and --global-rate-limit ────────────────────────────────
#
# Measured, not eyeballed.  A proxy accepted --rate-limit, reported it back from
# `show`, and never applied it: 40 requests on one connection were all answered
# at 5497/sec against a configured 2/sec.  So the burst assertion is a count,
# and the paced one beside it is what stops "closes everything" from passing.
echo "  -- rate limits --"
start_backend b6 "$BE1" ok
make_proxy "127.0.0.1:$BE1" --rate-limit 5
# The bucket starts full, so a burst gets the allowance and no more.  The range
# is 5..7 rather than exactly 5: the refill is continuous, so a burst that takes
# a couple of milliseconds legitimately earns a fraction of a token back.
assert_range "$(python3 "$TMPD/burst.py" "$PX" 60)" 5 7 "a burst of 60 under --rate-limit 5 is cut to the allowance"
sleep 1.2
# 3/sec for 2s under a limit of 5, plus the 5 the initial bucket allows: a
# compliant client is never refused, which is the control the whole check rests
# on.  Floor 9 rather than 11 because the pacing is a sleep loop and the last
# tick may not fit in the window.
assert_range "$(python3 "$TMPD/paced.py" "$PX" 3 2)" 9 14 "a client inside --rate-limit 5 is never refused"

make_proxy "127.0.0.1:$BE1" --global-rate-limit 5
assert_range "$(python3 "$TMPD/burst.py" "$PX" 60)" 5 7 "a burst of 60 under --global-rate-limit 5 is cut too"
sleep 1.5
assert_range "$(python3 "$TMPD/paced.py" "$PX" 3 2)" 9 14 "a client inside --global-rate-limit 5 is never refused"

# No limit at all: the same burst has to go through untouched, or every
# assertion above passes on a build that simply throttles everything.
make_proxy "127.0.0.1:$BE1"
assert_eq "$(python3 "$TMPD/burst.py" "$PX" 60)" "60" "with no rate limit configured, all 60 are answered"
stop_backends

echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
echo "DONE"
