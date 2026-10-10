#!/usr/bin/env bash
# Integration test: a write the store refuses is answered as refused, reaches no follower, and wakes whoever it fed.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * MSET, in RESP and in text, and text HMSET, ignoring the store's refusal of
#     a pair: the client heard ok, and the follower was sent the refused pair
#     and kept it, so leader and follower disagreed about a key
#   * a push into a list past its deadline but not yet swept: the element was
#     taken, counted, and lost with the list at the next sweep
#   * LPUSH refused after its first element returning before the waiters were
#     woken, so a BLPOP sat beside a list that held what it waited for
#   * a text LPUSH never waking a client blocked in RESP BLPOP on the key
#   * a text MSET with a key and no value setting the pairs before it and dropping it, answered ok
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate cacherefuse
LP=$((SL_PORT_BASE+1960))
FP=$((SL_PORT_BASE+1961))
trap 'daemon_stop' EXIT

echo "=== Integration: a refused write is not ok ==="

daemon_start "$BIN"
"$BIN" create cache rl -p "$LP" --maxmemory 2M --read-buffer 8M -s >/dev/null 2>&1
"$BIN" create cache rf -p "$FP" --read-buffer 8M --replicate "127.0.0.1:$LP" -s >/dev/null 2>&1
for p in "$LP" "$FP"; do
    for _ in $(seq 1 50); do python3 -c "import socket;socket.create_connection(('127.0.0.1',$p),1)" 2>/dev/null && break; sleep 0.1; done
done
sleep 1

python3 - "$LP" "$FP" > "$SOCKETLEY_TMPD/out" <<'PY'
import socket, sys, time
lp, fp = int(sys.argv[1]), int(sys.argv[2])

def conn(port):
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5); return s

def enc(*parts):
    parts = [p if isinstance(p, bytes) else p.encode() for p in parts]
    return b"*%d\r\n" % len(parts) + b"".join(b"$%d\r\n%s\r\n" % (len(p), p) for p in parts)

def reply(s):
    d = b""
    while b"\r\n" not in d:
        b = s.recv(65536)
        if not b: return "closed"
        d += b
    line = d[:d.index(b"\r\n")].decode(errors="replace")
    if line.startswith("$") and line != "$-1":
        n = int(line[1:]); need = d.index(b"\r\n") + 2 + n + 2
        while len(d) < need: d += s.recv(65536)
        return d[d.index(b"\r\n") + 2:need - 2].decode(errors="replace")
    if line.startswith("*"):
        n = int(line[1:]); out = []
        rest = d[d.index(b"\r\n") + 2:]
        while len(out) < n:
            while rest.count(b"\r\n") < 2: rest += s.recv(65536)
            h, rest = rest.split(b"\r\n", 1)
            m = int(h[1:]);
            while len(rest) < m + 2: rest += s.recv(65536)
            out.append(rest[:m].decode()); rest = rest[m + 2:]
        return " ".join(out)
    return line[1:] if line[:1] in "+-:" else line

def cmd(s, *parts):
    s.sendall(enc(*parts)); return reply(s)

def text(s, line):
    s.sendall(line.encode() + b"\n"); d = b""
    while not d.endswith(b"\n"):
        b = s.recv(65536)
        if not b: return "closed"
        d += b
    return d.decode().strip()

L = conn(lp)
# Full, then one value freed, so what is left holds a small write and never a whole megabyte.
big = b"v" * 400000
n = 0
while n < 20 and not cmd(L, "SET", "fill%d" % n, big).startswith("OOM"): n += 1
cmd(L, "DEL", "fill0")
huge = b"h" * 1000000

print("resp-mset:", cmd(L, "MSET", "m1", "a", "mhuge", huge, "m3", "c")[:3])
T = conn(lp)
print("text-mset:", text(T, "mset t1 a thuge " + huge.decode() + " t3 c"))
print("text-hmset:", text(T, "hmset th f1 a f2 " + huge.decode()))
print("text-odd:", text(T, "mset odd1 x odd2"), cmd(L, "EXISTS", "odd1"))
time.sleep(1.5)
F = conn(fp)
print("follower:", cmd(F, "GET", "m1"), cmd(F, "EXISTS", "mhuge"), cmd(F, "EXISTS", "m3"),
      cmd(F, "GET", "t1"), cmd(F, "EXISTS", "thuge"), cmd(F, "HGET", "th", "f1"), cmd(F, "HEXISTS", "th", "f2"))
print("leader:", cmd(L, "EXISTS", "mhuge"), cmd(L, "EXISTS", "m3"), cmd(L, "HEXISTS", "th", "f2"))

# A list past its deadline takes no element.
cmd(L, "RPUSH", "dead", "old")
cmd(L, "PEXPIRE", "dead", "20")
time.sleep(0.04)
print("expired-push:", cmd(L, "RPUSH", "dead", "new"), cmd(L, "LRANGE", "dead", "0", "-1"))

# A waiter is served by the elements of a push the store cut short.
W = conn(lp); W.settimeout(3)
W.sendall(enc("BLPOP", "q", "0")); time.sleep(0.3)
print("partial-push:", cmd(L, "LPUSH", "q", "small", huge)[:3])
try: print("waiter:", reply(W))
except Exception: print("waiter: still waiting")

# And by a push in text.
W2 = conn(lp); W2.settimeout(3)
W2.sendall(enc("BLPOP", "q2", "0")); time.sleep(0.3)
print("text-push:", text(T, "lpush q2 hello"))
try: print("text-waiter:", reply(W2))
except Exception: print("text-waiter: still waiting")
PY
OUT=$(cat "$SOCKETLEY_TMPD/out")
get() { printf '%s\n' "$OUT" | sed -n "s/^$1: //p"; }

expect "RESP MSET with a pair the store refuses is answered OOM" "$(get resp-mset)" "OOM"
expect "text MSET with a pair the store refuses says so" "$(get text-mset)" "error: out of memory"
expect "text HMSET with a field the store refuses says so" "$(get text-hmset)" "error: out of memory"
expect "a text MSET whose last key has no value is refused whole" "$(get text-odd)" "usage: mset key value [key value ...] 0"
expect "the follower has the pairs before the refusal and nothing from it on" "$(get follower)" "a 0 0 a 0 a 0"
expect "the leader kept nothing from the refusal on" "$(get leader)" "0 0 0"
expect "a push into a list past its deadline starts a new list" "$(get expired-push)" "1 new"
expect "an LPUSH cut short still answers OOM" "$(get partial-push)" "OOM"
expect "a waiter is served the element that went in before the refusal" "$(get waiter)" "q small"
expect "a text push answers ok" "$(get text-push)" "ok"
expect "a waiter in RESP is served by a push in text" "$(get text-waiter)" "q2 hello"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
