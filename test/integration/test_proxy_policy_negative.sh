#!/usr/bin/env bash
# Integration test: the proxy's policy flags do NOTHING when they should do
# nothing, and something measurable when they should.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# Two earlier files asserted that the breaker opens and neither that it stays
# shut, so a clean backend close and a client aborting mid-exchange were each
# charged to it as backend failures -- and every refusal here is asserted next
# to a case that must keep working, because "the breaker opened" passes on a
# build that refuses everything and "the request was served" on a build with no
# breaker at all.
# ─── WHAT IS PINNED HERE ────────────────────────────────────────────────────
# Five sections: the breaker stays shut for four things that are not backend
# failures and opens for the one that is, --retry replays idempotent methods
# and refuses the rest because a duplicate POST is a data-integrity question,
# --retry-all replays them anyway as a pinned deliberate decision,
# --max-connections refuses past the limit and releases afterwards, and the
# rate limiters are measured rather than eyeballed and let a compliant client
# through.
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
# value, with the range stated at each call site.
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
# One script with several behaviours, counting what it received into a file, so
# "the request reached this backend" is asserted separately from "the client
# got an answer" -- which come apart in exactly the cases this file is about.
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
import socket, struct, sys, time
port = int(sys.argv[1]); path = sys.argv[2]
method = sys.argv[3] if len(sys.argv) > 3 else "GET"
body = sys.argv[4].encode() if len(sys.argv) > 4 and sys.argv[4] != "-" else b""
abort = "--abort" in sys.argv
# How long the request stands before the reset, so it is at the backend when the client goes.
abort_after = next((float(a.split("=", 1)[1]) for a in sys.argv if a.startswith("--abort-after=")), 0.0)
req = ("%s %s HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n"
       % (method, path, len(body))).encode() + body
try:
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(10)
    if abort:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.sendall(req); time.sleep(abort_after); s.close(); print("ABORTED"); sys.exit(0)
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

# A client that stays inside the limit must never be refused, without which the
# rate-limit assertions pass on a build that closes every connection.
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

# Ten provocations against a threshold of five, each scenario ending with one
# ordinary request, because an open circuit is invisible until somebody asks.

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
# Reset 0.2 s in, inside the backend's 0.35 s, so each one is gone mid-exchange: one sent and reset at once can lose
# its bytes in the proxy's receive queue and reach nobody.
for _ in $(seq 1 10); do python3 "$TMPD/req.py" "$PX" /pn_px/b GET - --abort --abort-after=0.2 >/dev/null 2>&1 || true; done
sleep 0.5
# The backend has to have been reached, or the closed circuit below says nothing about aborts mid-exchange.
assert_range "$(count_of b2)" 10 10 "control: aborted requests reached the backend"
assert_eq "$(circuits)" "0" "clients aborting mid-exchange do not open the circuit"
assert_eq "$(python3 "$TMPD/req.py" "$PX" /pn_px/b2)" "HTTP/1.1 200 OK" "and the proxy still serves"
stop_backends

# Slow but answering, well inside the 2s backend timeout, so a breaker that
# charged latency would take a working backend out of rotation for being busy.
start_backend b3 "$BE1" slow 0.35
make_proxy "127.0.0.1:$BE1"
SLOW_OK=0
for _ in $(seq 1 10); do
    [ "$(python3 "$TMPD/req.py" "$PX" /pn_px/c)" = "HTTP/1.1 200 OK" ] && SLOW_OK=$((SLOW_OK+1))
done
assert_eq "$SLOW_OK" "10" "a slow backend that answers is served every time"
assert_eq "$(circuits)" "0" "and being slow does not open the circuit"
stop_backends

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

# The first backend reads the request and dies without answering, so it has
# reached one -- and whether the second sees it too is the whole question,
# since for a POST that is a duplicate side effect no availability makes a good
# trade.
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
# The assertion is on how many are served, because refused is retryable and
# visible while silently accepted and dropped is not.
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
# Measured rather than eyeballed, because a proxy accepted --rate-limit,
# reported it back from `show` and never applied it -- so the burst assertion
# is a count and the paced one beside it stops "closes everything" from
# passing.
echo "  -- rate limits --"
start_backend b6 "$BE1" ok
make_proxy "127.0.0.1:$BE1" --rate-limit 5
# The bucket starts full so a burst gets the allowance and no more, with the
# range 5..7 because the refill is continuous and a burst legitimately earns a
# fraction of a token back.
assert_range "$(python3 "$TMPD/burst.py" "$PX" 60)" 5 7 "a burst of 60 under --rate-limit 5 is cut to the allowance"
sleep 1.2
# A compliant client is never refused, which is the control the whole check
# rests on, with a floor of 9 rather than 11 because the pacing is a sleep loop
# whose last tick may not fit in the window.
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

# ── a rate limit that is not a number is not a rate limit ───────────────────
# NaN parses as a double and is false against every comparison, so it passed the
# `rate < 0` check at the door and failed the `rate > 0` check that turns the
# limiter on -- measured before it was refused: 40 of 40 commands served, where a
# limit of 5 served 5.  A configuration that looks set and is not.
"$BIN" stop pn_px >/dev/null 2>&1 || true
sleep 0.2
"$BIN" remove pn_px >/dev/null 2>&1 || true
RL_OUT=$("$BIN" create proxy pn_px -p "$PX" --backend "127.0.0.1:$BE1" --rate-limit nan -s 2>&1 || true)
TOTAL=$((TOTAL+1))
case "$RL_OUT" in
    *invalid*) PASS=$((PASS+1)); echo "  PASS: --rate-limit nan is refused at the door" ;;
    *) FAIL=$((FAIL+1)); echo "  FAIL: --rate-limit nan was accepted: '$RL_OUT'"
       echo "        -- accepted it does not limit anything, and stats shows a limit" ;;
esac
# And it did not create anything either, which is the half a refusal owes.
TOTAL=$((TOTAL+1))
if "$BIN" stats pn_px >/dev/null 2>&1; then
    FAIL=$((FAIL+1)); echo "  FAIL: a refused --rate-limit still left a proxy behind"
else
    PASS=$((PASS+1)); echo "  PASS: and nothing was created by the refusal"
fi
# An infinity is deliberately still allowed: for a rate that is a thing to mean,
# and unlike NaN it compares the way a reader expects.  Backends up first -- the
# first draft of this row ran after the stop above and measured a proxy with
# nowhere to send anything, which answered 1 of 60 and read as a broken limiter.
start_backend binf "$BE1" ok
make_proxy "127.0.0.1:$BE1" --rate-limit inf
assert_eq "$(python3 "$TMPD/burst.py" "$PX" 60)" "60" "--rate-limit inf is accepted and means unlimited"
stop_backends

echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
echo "DONE"
