#!/usr/bin/env bash
# Integration test: scan's filters on the line protocol, not only on RESP
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The cache answers two protocols and parses its options TWICE -- once in the
# RESP dispatch and once in the line dispatch -- and the two parsers are written
# out separately.  Five options were added to both this week and every test of
# them created its cache with --resp, so half of that code was never run by
# anything.
#
# It was not fine.  A probe of the line protocol answered `size type hash` with a
# NUL byte in front of the number, because one of its replies was appended with a
# length one greater than the literal.  That is the kind of thing the other
# parser's tests cannot see, by construction.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an option parsed on one port and skipped on the other, which is how a
#     command comes to mean two things on one server
#   * valuerange in particular, which takes TWO tokens where every other option
#     on this port takes one, and so has parsing of its own on each side
#   * a reply whose bytes are not the bytes: the rows compare whole lines
#   * and the refusals, which are a different shape here (this port answers
#     "error: ..." where RESP answers -ERR)
#
# One trap worth writing down: the first draft of these rows compared through a
# shell variable, and bash drops NUL bytes out of $(...) -- so it read the very
# reply this file exists for as correct.  The escaping happens in python now,
# before anything reaches the shell.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
exec 2>&1

echo "=== Integration: scan's filters on the line protocol ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

P=$((SL_PORT_BASE+1487))
daemon_isolate cachescantext
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# No --resp on purpose: this is the port the other files never open.
"$BIN" create cache tx_c -p "$P" -s >/dev/null 2>&1 || true
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$P "; then
    echo "  FATAL: the cache never bound $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

LINE_PY="$SOCKETLEY_TMPD/line.py"
cat > "$LINE_PY" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile('rb')
def send(line, terminated):
    s.sendall((line + "\n").encode())
    out = []
    while True:
        b = f.readline()
        if not b:
            break
        t = b.decode('latin1').rstrip("\n")
        out.append(t)
        if not terminated:
            break
        if t == "end" or t.startswith("error"):
            break
    return out
# Everything before the blank line is setup and its replies are not looked at.
setup, _, asks = sys.stdin.read().partition("\n--\n")
for line in setup.strip().split("\n"):
    if line:
        send(line, False)
for line in asks.strip().split("\n"):
    if not line:
        continue
    tag, _, cmd = line.partition("\t")
    got = send(cmd, tag == "list")
    # Every byte that is not printable is spelled out before this leaves python.
    # A NUL is what an append one byte too long puts on the wire, and bash drops
    # NULs out of $(...) -- so a row comparing shell strings cannot see the one
    # defect this file was written for unless the escape happens here.
    def show(t):
        return "".join(c if 32 <= ord(c) < 127 else "<%02x>" % ord(c) for c in t)
    got = [show(x) for x in got]
    body = [x for x in got if x != "end"]
    if tag == "list":
        body = sorted(body[1:])          # the cursor first, then the keys
    print("%s|%s" % (tag, "|".join(body)))
PY

run() { python3 "$LINE_PY" "$P"; }

OUT=$(run <<'ASK'
set u:1 {"city":"berlin","age":30}
set u:2 {"city":"hamburg","age":41}
set n:25 25
set n:50 50
set n:na 30kg
hset h:1 city berlin
hset h:2 city hamburg
rpush l:1 x
--
list	scan 0 count 10000 valuematch *berlin*
list	scan 0 count 10000 type hash
list	scan 0 count 10000 field city valuematch berlin
list	scan 0 count 10000 match u:* withvalues
list	scan 0 count 10000 match n:* valuerange 20 30
list	scan 0 count 10000 match n:* valuerange (25 30
one	scan 0 count 10 valuerange abc 30
one	size type hash
one	size
list	hscan h:1 0 count 100 valuematch berlin
one	sscan l:1 0 valuematch x
ASK
)

expect() {   # label  line-number  expected
    local label=$1 n=$2 want=$3
    local got; got=$(echo "$OUT" | sed -n "${n}p")
    if [ "$got" = "$want" ]; then ok "$label"
    else bad "$label" "got '$got'" "wanted '$want'"; fi
}

echo "--- the five filters, on the port the other files never open ---"
expect "valuematch"                1 'list|u:1'
expect "type"                      2 'list|h:1|h:2'
expect "field with a value"        3 'list|h:1'
expect "withvalues prints the pair on one line" 4 'list|u:1 {"city":"berlin","age":30}|u:2 {"city":"hamburg","age":41}'
expect "valuerange, both bounds in"  5 'list|n:25'
expect "valuerange, lower bound out" 6 'list|'

echo "--- and the refusals, which are this port's own shape ---"
expect "a bound that is not a float" 7 'one|error: min or max is not a float'
expect "size of one type"            8 'one|2'
expect "size of all types"           9 'one|8'
expect "hscan on a field's value"   10 'list|city berlin'
expect "sscan refuses valuematch"   11 'one|error: syntax'

echo "--- and two conditions at once, on this port too ---"
# The stateful half of the option list -- a FIELD applies to what follows it --
# is written once and used by both parsers, and this is the row that says the
# second parser gets it too.
# Its own seeding and its own connection: the rows above assert exact key sets
# and a dbsize, so a key added for this one would have broken four of them.
OUT2=$(run <<'ASK'
hset q:1 city berlin
hset q:1 age 30
hset q:2 city berlin
hset q:2 age 55
hset q:3 city hamburg
hset q:3 age 30
--
list	scan 0 count 10000 match q:* field city valuematch berlin field age valuerange 25 40
list	scan 0 count 10000 match q:* field age valuerange 25 40 field city valuematch berlin
ASK
)
got=$(echo "$OUT2" | sed -n 1p)
if [ "$got" = 'list|q:1' ]; then ok "two field predicates are the intersection"
else bad "two field predicates are the intersection" "got '$got'" "wanted 'list|q:1'"; fi
got=$(echo "$OUT2" | sed -n 2p)
if [ "$got" = 'list|q:1' ]; then ok "and the answer does not depend on their order"
else bad "the answer does not depend on their order" "got '$got'" "wanted 'list|q:1'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
