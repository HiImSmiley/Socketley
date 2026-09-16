#!/usr/bin/env bash
# Integration test: the scan filters, checked against each other
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Every other test of these options asserts a known answer on a handful of keys.
# That finds an option that does nothing.  It does not find an option that does
# something slightly wrong in combination with another, because nobody wrote down
# what the combination should answer -- and with six options there are more
# combinations than anybody will write rows for.
#
# So this asserts RELATIONS instead, on a keyspace big enough to page: things
# that must hold between two ways of reaching the same answer, whatever the
# answer is.  A walk that drops a key under one filter and keeps it under another
# breaks one of these without anybody having to predict which key.
#
# What it does NOT catch, and this is worth knowing before trusting it: an option
# that does nothing.  A filter that is skipped makes every walk answer the whole
# keyspace, and a keyspace compared with itself satisfies almost all of these --
# against a build carrying only one of the six, fifteen of the eighteen still
# pass.  The fixed-answer rows in the sibling files are what catch an absent
# option.  These catch a present one that is subtly wrong, which is the failure
# nobody writes a row for.
#
# ─── THE RELATIONS ──────────────────────────────────────────────────────────
#
#   * the five types, unioned, are the whole keyspace -- one map walked twice or
#     not at all shows up here
#   * DBSIZE TYPE t equals a walk of that type, for each of the five: the O(1)
#     answer and the O(n) one cannot drift apart
#   * two filters together are the intersection of the two apart
#   * two adjoining ranges are the range that spans them, and do not overlap
#   * COUNT changes how many calls it takes and never what comes back
#   * every value WITHVALUES returns satisfies the predicate it was selected by
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
exec 2>&1

echo "=== Integration: the scan filters, checked against each other ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

P=$((SL_PORT_BASE+1488))
daemon_isolate cachescanagree
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache ag_c -p "$P" --resp -s >/dev/null 2>&1 || true
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$P "; then
    echo "  FATAL: the cache never bound $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

python3 - "$P" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=60)
f = s.makefile('rb')
def rd():
    line = f.readline()
    t, b = line[0:1], line[1:-2]
    if t in (b'+', b'-', b':'): return b
    if t == b'$':
        k = int(b); return None if k < 0 else f.read(k + 2)[:-2]
    if t == b'*':
        k = int(b); return None if k < 0 else [rd() for _ in range(k)]
    raise ValueError(line)
def enc(*a):
    p = ('*%d\r\n' % len(a)).encode()
    for x in a:
        x = x if isinstance(x, bytes) else str(x).encode()
        p += b'$%d\r\n' % len(x) + x + b'\r\n'
    return p
def cmd(*a):
    s.sendall(enc(*a)); return rd()

CITIES = ["berlin", "hamburg", "koeln", "bremen"]
pipe, n = b'', 0
for i in range(3000):
    pipe += enc("SET", "s:%d" % i, '{"city":"%s","n":%d}' % (CITIES[i % 4], i)); n += 1
for i in range(2000):
    pipe += enc("HSET", "h:%d" % i, "city", CITIES[i % 4], "age", str(18 + i % 60)); n += 1
for kind, cmdname, extra in (("l", "RPUSH", ("x",)), ("t", "SADD", ("x",)), ("z", "ZADD", ("1", "x"))):
    for i in range(300):
        pipe += enc(cmdname, "%s:%d" % (kind, i), *extra); n += 1
s.sendall(pipe)
for _ in range(n): rd()

def walk(*opts, count=700):
    cur, keys = b'0', []
    calls = 0
    while True:
        r = cmd("SCAN", cur, "COUNT", count, *opts)
        cur = r[0]; keys += [k.decode() for k in r[1]]; calls += 1
        if cur == b'0': return set(keys), calls
def setof(*opts, **kw): return walk(*opts, **kw)[0]

rows = []
def check(name, cond, detail=""):
    rows.append((name, bool(cond), detail))

TYPES = ("string", "list", "set", "hash", "zset")
allk = setof()
per = {t: setof("TYPE", t) for t in TYPES}
check("the five types unioned are the whole keyspace",
      set().union(*per.values()) == allk,
      "%d against %d" % (len(set().union(*per.values())), len(allk)))
for t in TYPES:
    c = int(cmd("DBSIZE", "TYPE", t))
    check("DBSIZE TYPE %s equals a walk of it" % t, c == len(per[t]),
          "%d against %d" % (c, len(per[t])))
check("DBSIZE is the five added up",
      int(cmd("DBSIZE")) == sum(int(cmd("DBSIZE", "TYPE", t)) for t in TYPES))

a, b = setof("VALUEMATCH", "*berlin*"), setof("MATCH", "s:1*")
both = setof("MATCH", "s:1*", "VALUEMATCH", "*berlin*")
check("MATCH and VALUEMATCH together are the intersection apart",
      both == a & b, "%d against %d" % (len(both), len(a & b)))

fa, fb = setof("FIELD", "city", "VALUEMATCH", "berlin"), setof("FIELD", "city")
check("a field with a predicate is inside the same field without one", fa <= fb)
check("a field without one is exactly the hashes that have it", fb == per["hash"],
      "%d against %d" % (len(fb), len(per["hash"])))

r1 = setof("FIELD", "age", "VALUERANGE", "20", "30")
r2 = setof("FIELD", "age", "VALUERANGE", "31", "40")
r3 = setof("FIELD", "age", "VALUERANGE", "20", "40")
check("two adjoining ranges are the range that spans them", r1 | r2 == r3,
      "%d + %d against %d" % (len(r1), len(r2), len(r3)))
check("and they do not overlap", not (r1 & r2))

for opts in [(), ("TYPE", "hash"), ("VALUEMATCH", "*berlin*"),
             ("FIELD", "city", "VALUEMATCH", "berlin"),
             ("FIELD", "age", "VALUERANGE", "20", "30")]:
    big, nb = walk(*opts, count=5000)
    small, ns = walk(*opts, count=1)
    check("COUNT changes the number of calls, not the answer: %s" % (" ".join(opts) or "(none)",),
          big == small, "%d in %d calls against %d in %d" % (len(big), nb, len(small), ns))

cur, bad, seen = b'0', 0, 0
while True:
    r = cmd("SCAN", cur, "COUNT", 700, "FIELD", "city", "VALUEMATCH", "berlin", "WITHVALUES")
    cur = r[0]; e = r[1]
    for i in range(0, len(e), 2):
        seen += 1
        if e[i + 1] != b"berlin": bad += 1
    if cur == b'0': break
check("every value WITHVALUES returned satisfies its predicate (%d checked)" % seen,
      bad == 0 and seen > 100, "%d wrong of %d" % (bad, seen))

passed = sum(1 for _, okk, _ in rows if okk)
for name, okk, detail in rows:
    if okk: print("  PASS: %s" % name)
    else:   print("  FAIL [%s]: %s" % (name, detail))
print("  Results: %d/%d passed (%d failed)" % (passed, len(rows), len(rows) - passed))
sys.exit(0 if passed == len(rows) else 1)
PY
