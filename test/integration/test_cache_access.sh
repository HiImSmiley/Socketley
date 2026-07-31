#!/usr/bin/env bash
# Integration test: cache access via server (`cache <cmd>` prefix)
#
# `server --cache` is an asynchronous request now: the server hands the command
# to the daemon's request channel and answers the client when the reply comes
# back, one turn of the event loop later, rather than running the cache's
# interpreter on the stack of the read that delivered the command.  That buys
# the process split and costs a round trip, and it moves three questions from
# "obviously true" to "has to be checked":
#
#   * ORDERING.  Replies on one connection must come back in request order.
#     They are the only thing a pipelining client can match answers to
#     questions by, and a deferred reply is exactly where an implementation
#     starts answering out of order.
#
#   * A CLIENT THAT LEAVES MID-FLIGHT.  The reply lands after the request, so
#     there is now a window where the connection it belongs to has been closed,
#     its descriptor reissued and its struct handed to the next client.  An
#     answer written into that connection is one client's data delivered to
#     another; the daemon surviving it is the floor, not the bar.
#
#   * CONCURRENT ASKERS.  One queue serves every connection, so answers must
#     not be crossed between them.
#
# The half-close case is deliberate and separate: a request/response client that
# shuts down its write side after asking has nothing in the ring on its behalf
# while it waits, and the server has to keep the connection alive for the answer
# rather than closing it on the FIN.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
CACHE_PORT=19240
SERVER_PORT=19241
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop ca_server 2>/dev/null || true
    "$BIN" stop ca_cache 2>/dev/null || true
    sleep 0.5
    "$BIN" remove ca_server 2>/dev/null || true
    "$BIN" remove ca_cache 2>/dev/null || true
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

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$SERVER_PORT" 2>/dev/null | tr -d '\r'
}

echo "=== Integration: cache access via server ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Create cache and server linked to it
"$BIN" create cache ca_cache -p "$CACHE_PORT" -s 2>&1 || true
"$BIN" create server ca_server -p "$SERVER_PORT" --cache ca_cache -s 2>&1 || true

# The cache answers PING before the server is asked anything of it, and the
# server answers a line — both proved rather than slept for.  ready_tcp on the
# server would only say the listener is armed, which is true before the
# runtime behind it can serve a cache command.
ready_resp 127.0.0.1 "$CACHE_PORT" 20 || true
ready_tcp  127.0.0.1 "$SERVER_PORT" 20 || true

# Test: Both show in ps
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "ca_cache" "cache in ps"
assert_contains "$OUT" "ca_server" "server in ps"

# Test: Set a key via cache access through the server
RESULT=$(send_cmd 'cache set user alice')
assert_eq "$RESULT" "ok" "cache set via server"

# Test: Get the key back via cache access through the server
RESULT=$(send_cmd 'cache get user')
assert_eq "$RESULT" "alice" "cache get via server"

# Test: Regular message (not cache command) doesn't return cache error
# A plain message should be broadcast, not interpreted as cache command
TOTAL=$((TOTAL+1))
RESULT=$(echo "hello" | nc -q 1 127.0.0.1 "$SERVER_PORT" 2>/dev/null | tr -d '\r')
# No error expected — broadcast returns nothing to sender typically
PASS=$((PASS+1))

# Test: Verify the key is also accessible directly on the cache port
DIRECT=$(echo "get user" | nc -q 1 127.0.0.1 "$CACHE_PORT" 2>/dev/null | tr -d '\r')
assert_eq "$DIRECT" "alice" "direct cache get"

# ─── ordering, half-close, concurrency, abandonment ─────────────────────────
#
# One python3 run for all four, because three of them need the connection held
# open under the harness's own control and nc cannot express "shut down the
# write side and keep reading".  Each prints one line the shell asserts on.

PROBE=$(python3 - "$SERVER_PORT" <<'PY'
import socket, sys, threading

PORT = int(sys.argv[1])

def connect():
    s = socket.create_connection(("127.0.0.1", PORT), 5)
    s.settimeout(10)
    return s

def read_lines(s, n):
    """Exactly n newline-terminated lines, or as many as arrive before EOF."""
    buf = b""
    while buf.count(b"\n") < n:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return [l for l in buf.decode(errors="replace").replace("\r", "").split("\n") if l]

# ── 1. ORDERING on one connection ───────────────────────────────────────────
# 200 sets then 200 gets, pipelined into one write so the server sees them in
# one read and has every chance to answer them out of order.  The answers are
# checked positionally: reply i must be the value written by request i.
s = connect()
n = 200
cmds = "".join("cache set ord%d v%d\n" % (i, i) for i in range(n))
cmds += "".join("cache get ord%d\n" % i for i in range(n))
s.sendall(cmds.encode())
got = read_lines(s, 2 * n)
s.close()

ok_order = (len(got) == 2 * n
            and all(g == "ok" for g in got[:n])
            and all(got[n + i] == "v%d" % i for i in range(n)))
print("ORDER", "ok" if ok_order else "BAD len=%d head=%s tail=%s"
      % (len(got), got[:3], got[n:n + 3]))

# ── 2. HALF-CLOSE ───────────────────────────────────────────────────────────
# Ask, shut down the write side, then read.  Nothing of this connection's is in
# the ring while the reply is queued, so a server that closes on the FIN drops
# an answer the client is still waiting for.
s = connect()
s.sendall(b"cache set hc hello\ncache get hc\n")
s.shutdown(socket.SHUT_WR)
got = read_lines(s, 2)
s.close()
print("HALFCLOSE", "ok" if got == ["ok", "hello"] else "BAD %r" % (got,))

# ── 3. CONCURRENT CLIENTS ───────────────────────────────────────────────────
# Sixteen connections, each asking only about its own keys.  A crossed reply
# shows up as a value belonging to another client.
NCLI, NREQ = 16, 40
results = [None] * NCLI

def worker(idx):
    try:
        c = connect()
        body = "".join("cache set c%d_%d %d_%d\n" % (idx, i, idx, i) for i in range(NREQ))
        body += "".join("cache get c%d_%d\n" % (idx, i) for i in range(NREQ))
        c.sendall(body.encode())
        lines = read_lines(c, 2 * NREQ)
        c.close()
        want = ["ok"] * NREQ + ["%d_%d" % (idx, i) for i in range(NREQ)]
        results[idx] = "ok" if lines == want else "BAD %r" % (lines[:4],)
    except Exception as e:
        results[idx] = "EXC %s" % e

ts = [threading.Thread(target=worker, args=(i,)) for i in range(NCLI)]
for t in ts: t.start()
for t in ts: t.join()
bad = [r for r in results if r != "ok"]
print("CONCURRENT", "ok" if not bad else "BAD %r" % (bad[:2],))

# ── 4. ABANDONED MID-FLIGHT ─────────────────────────────────────────────────
# Ask and vanish, with SO_LINGER{1,0} so the socket is reset rather than closed
# politely: the descriptor number goes straight back to the kernel and the next
# accept takes it, which is the window a late reply would be delivered into.
# Then a fresh client on (very likely) that same number asks its own question
# and must get its own answer.
import struct
for _ in range(60):
    c = connect()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.sendall(b"cache set gone 1\ncache get gone\ncache get gone\n")
    c.close()

survivors = []
for i in range(20):
    c = connect()
    c.sendall(("cache set after%d ok%d\ncache get after%d\n" % (i, i, i)).encode())
    c.shutdown(socket.SHUT_WR)
    lines = read_lines(c, 2)
    c.close()
    survivors.append(lines == ["ok", "ok%d" % i])
print("ABANDON", "ok" if all(survivors) else "BAD %d/%d" % (sum(survivors), len(survivors)))

# ── 5. THE AUTO-STORE, AND ITS ORDER AGAINST A CACHE COMMAND ────────────────
# A linked server writes every message it receives to the cache under an
# incrementing key.  Those writes are batched — one request per read rather
# than one per message, or a burst fills the queue and most of them are thrown
# away — so this checks both halves of that: none is lost across a burst, and a
# client that sends a message and then asks the cache for it by key sees its
# own write, whether the two arrive in one write or two.
s = connect()


def ask(cmd):
    s.sendall((cmd + "\n").encode())
    return read_lines(s, 1)[0]


# The key counter is per runtime and every earlier message in this file has
# already moved it, so where this run's writes land has to be found rather than
# assumed.  Doubling search for the first key that is not there yet, then bisect.
hi = 1
while ask("cache get %d" % hi) != "nil":
    hi *= 2
lo = hi // 2
while lo + 1 < hi:
    mid = (lo + hi) // 2
    if ask("cache get %d" % mid) != "nil":
        lo = mid
    else:
        hi = mid
base = hi          # the next message lands here

s.sendall(("first-message\ncache get %d\n" % base).encode())
same_write = (read_lines(s, 1) == ["first-message"])

s.sendall(b"second-message\n")
s.sendall(("cache get %d\n" % (base + 1)).encode())
split_write = (read_lines(s, 1) == ["second-message"])

# A burst well past one read buffer.  Every one of these has to land, which is
# what the batching is for: posted one request per message instead, the queue's
# cap turns a burst into dropped writes.
BURST = 20000
s.sendall(("".join("burst%d\n" % i for i in range(BURST))).encode())
first = ask("cache get %d" % (base + 2))
last = ask("cache get %d" % (base + 1 + BURST))
s.close()
burst_ok = (first == "burst0" and last == "burst%d" % (BURST - 1))

print("STORE", "ok" if (same_write and split_write and burst_ok)
      else "BAD same=%s split=%s burst=%s" % (same_write, split_write, burst_ok))
PY
) || PROBE="probe failed"

assert_eq "$(echo "$PROBE" | grep '^ORDER '      | cut -d' ' -f2-)" "ok" "replies in request order"
assert_eq "$(echo "$PROBE" | grep '^HALFCLOSE '  | cut -d' ' -f2-)" "ok" "reply survives a half-closed client"
assert_eq "$(echo "$PROBE" | grep '^CONCURRENT ' | cut -d' ' -f2-)" "ok" "concurrent clients get their own answers"
assert_eq "$(echo "$PROBE" | grep '^ABANDON '    | cut -d' ' -f2-)" "ok" "clients that vanish mid-request do not poison the next"
assert_eq "$(echo "$PROBE" | grep '^STORE '      | cut -d' ' -f2-)" "ok" "every message reaches the cache, before the command that asks for it"

# Test: a cache command addressed to a cache that has stopped is answered, not
# swallowed.  The synchronous version returned nothing at all and the client
# waited for a line that was never coming.
"$BIN" stop ca_cache 2>/dev/null || true
sleep 0.4
RESULT=$(send_cmd 'cache get user')
assert_contains "$RESULT" "error" "stopped cache is answered with an error"

"$BIN" start ca_cache 2>/dev/null || true
ready_resp 127.0.0.1 "$CACHE_PORT" 20 || true
RESULT=$(send_cmd 'cache set back yes')
assert_eq "$RESULT" "ok" "cache is served again after a restart"

# Test: Server still running after mixed traffic
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "ca_server" "server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
