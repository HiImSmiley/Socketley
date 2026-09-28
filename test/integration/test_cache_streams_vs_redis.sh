#!/usr/bin/env bash
# Integration test: every stream command answers what redis-server answers
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A stream client is written against Redis's replies -- the shape of XREAD's
# nested arrays, the null where a group's lag is unknowable, the order XINFO
# names its fields in, and the exact text of each error, which clients match.
# Written from the documentation, every one of those is a guess; so the same
# command sequences are sent to a redis-server started on a port of this
# file's own and to the cache, and the replies are compared one by one.  Only
# what is a clock differs by right: an id * made, an idle time, a delivery time
# and radix-tree-nodes, which counts the internals of a tree this cache does not
# have.  The system redis on 6379 is never touched.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# Each compared reply is one assertion, and a difference prints both sides:
#
#   * an error text, or an error answered where Redis answers a value, or the
#     reverse -- arity, syntax, ids, NOGROUP, BUSYGROUP, WRONGTYPE, OOM order
#   * a reply of another shape: nil against an empty array, a map's fields in
#     another order, an integer sent as a string
#   * a different result: trimming, ranges, lag and entries-read, the pending
#     lists after claims, what XAUTOCLAIM reports as deleted, what a blocked
#     reader is woken with
#   * radix-tree-keys, which counts blocks and differs where MAXLEN ~ would
#     trim a different number of entries than Redis does
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: stream replies against a real redis-server ==="
if ! command -v redis-server >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: redis-server and python3 are required"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

daemon_isolate streamsdiff
RP=$((SL_PORT_BASE + 1640))       # the private redis-server
P=$((SL_PORT_BASE + 1642))
RDIR=$SOCKETLEY_TMPD/redis
mkdir -p "$RDIR"
cleanup() {
    [ -f "$RDIR/redis.pid" ] && kill "$(cat "$RDIR/redis.pid")" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

redis-server --port "$RP" --bind 127.0.0.1 --save "" --appendonly no --daemonize yes \
             --dir "$RDIR" --pidfile "$RDIR/redis.pid" --logfile "$RDIR/redis.log" >/dev/null
daemon_start "$BIN"
"$BIN" create cache sdiff -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 100); do
    redis-cli -p "$P" ping 2>/dev/null | grep -q PONG && redis-cli -p "$RP" ping 2>/dev/null | grep -q PONG && break
    sleep 0.1
done
echo "  against $(redis-server --version | awk '{print $3}')"

OUT=$(timeout 300 python3 - "$RP" "$P" <<'PYEOF'
import re, socket, sys, threading, time

class Err:
    def __init__(self, s): self.s = s
    def __eq__(self, o): return isinstance(o, Err) and o.s == self.s
    def __repr__(self): return 'Err(%r)' % self.s

class Conn:
    def __init__(self, port):
        self.s = socket.create_connection(('127.0.0.1', port), timeout=10)
        self.buf = b''
    def send(self, args):
        p = b'*%d\r\n' % len(args)
        for a in args:
            a = a if isinstance(a, bytes) else str(a).encode()
            p += b'$%d\r\n%s\r\n' % (len(a), a)
        self.s.sendall(p)
    def _fill(self):
        d = self.s.recv(65536)
        if not d: raise EOFError
        self.buf += d
    def _line(self):
        while b'\r\n' not in self.buf: self._fill()
        i = self.buf.index(b'\r\n'); l = self.buf[:i]; self.buf = self.buf[i + 2:]
        return l
    def reply(self):
        l = self._line(); t, r = l[:1], l[1:]
        if t == b'+': return ('+', r.decode('latin1'))
        if t == b'-':
            # A script's error carries Redis's script location, which is the
            # scripting layer's and not a stream command's.
            return Err(re.sub(r' script: [0-9a-f]{40}, on @user_script:\d+\.$', '', r.decode('latin1')))
        if t == b':': return int(r)
        if t == b'$':
            n = int(r)
            if n < 0: return None
            while len(self.buf) < n + 2: self._fill()
            v = self.buf[:n].decode('latin1'); self.buf = self.buf[n + 2:]
            return v
        if t == b'*':
            n = int(r)
            return 'NILARRAY' if n < 0 else [self.reply() for _ in range(n)]
        raise ValueError(l)
    def cmd(self, *args):
        self.send(args)
        return self.reply()

MS_ID = re.compile(r'^1[0-9]{12}-[0-9]+$')
CLOCKS = ('idle', 'seen-time', 'radix-tree-nodes')

def norm(v):
    if isinstance(v, list):
        out, i = [], 0
        while i < len(v):
            if isinstance(v[i], str) and v[i] in CLOCKS and i + 1 < len(v):
                out += [v[i], '<t>']; i += 2; continue
            out.append(norm(v[i])); i += 1
        return out
    # An id made from the clock has a sequence that says only whether the
    # call before it fell in the same millisecond, so neither half compares.
    if isinstance(v, str) and MS_ID.match(v):
        return '<ms>-<seq>'
    return v

def pend(v):
    if isinstance(v, list):
        return [[e[0], e[1], '<t>', e[3]] if isinstance(e, list) and len(e) == 4 else e for e in v]
    return v

def full(v):
    def walk(x):
        if not isinstance(x, list): return x
        out, i = [], 0
        while i < len(x):
            if x[i] == 'pending' and i + 1 < len(x) and isinstance(x[i + 1], list):
                out += ['pending', [[e[0], e[1], '<t>', e[3]] if len(e) == 4 else [e[0], '<t>', e[2]] for e in x[i + 1]]]
                i += 2; continue
            out.append(walk(x[i])); i += 1
        return out
    return walk(v)

BIG = 'x' * 1000
SCENARIOS = [
 ('arity', [
   'XADD', 'XADD k', 'XADD k *', 'XADD k * f', 'XADD k * f v g', 'XLEN', 'XLEN a b', 'XRANGE k -', 'XREVRANGE k +',
   'XREAD', 'XREAD STREAMS', 'XREAD STREAMS k', 'XREADGROUP GROUP g c STREAMS k', 'XDEL k', 'XTRIM k MAXLEN',
   'XACK k g', 'XPENDING k', 'XCLAIM k g c 0', 'XAUTOCLAIM k g c 0', 'XSETID k', 'XGROUP', 'XINFO',
   'XGROUP foo', 'XINFO foo k', 'XGROUP CREATE k g', 'XGROUP SETID k g', 'XGROUP DESTROY k', 'XGROUP DESTROY k g x',
   'XGROUP CREATECONSUMER k g', 'XGROUP DELCONSUMER k g', 'XGROUP HELP x', 'XINFO HELP x', 'XINFO STREAM',
   'XINFO GROUPS', 'XINFO GROUPS k x', 'XINFO CONSUMERS k', 'XGROUP HELP', 'XINFO HELP', 'xGroup Help',
 ]),
 ('xadd ids', [
   'XADD s 1-1 a 1', 'XADD s 1-1 a 1', 'XADD s 1-0 a 1', 'XADD s 1-2 a 1 b 2', 'XADD s 2 c 3', 'XADD s 2-* d 4',
   'XADD s 2-* d 5', 'XADD s 1-* x y', 'XADD s 5-* x y', 'XLEN s', 'XRANGE s - +',
   'XADD s 0-0 a b', 'XADD n 0-0 a b', 'EXISTS n', 'XADD n 0-* a b', 'XADD n 0-* a b', 'XRANGE n - +',
   'XADD s abc a b', 'XADD s - a b', 'XADD s + a b', 'XADD s 3-x a b', 'XADD s 3- a b', 'XADD s -3 a b', 'XADD s 01 a b',
   'XADD s 18446744073709551615-18446744073709551615 a b', 'XADD s * a b', 'XADD s 18446744073709551615-* a b',
   'XADD s2 18446744073709551615-18446744073709551615 a b', 'XADD s2 18446744073709551615-* a b',
   'XADD s3 5-18446744073709551615 a b', 'XADD s3 5-* a b', 'XRANGE s3 - +',
   'XADD s4 18446744073709551616 a b', 'XADD s4 99999999999999999999-1 a b',
   'XADD auto * a 1', 'XADD auto * a 2', 'XLEN auto',
 ]),
 ('xadd options', [
   'XADD s NOMKSTREAM 1-1 a b', 'EXISTS s', 'XADD s 1-1 a b', 'XADD s NOMKSTREAM 2-1 a b', 'XLEN s',
   'XADD s MAXLEN 1 3-1 a b', 'XLEN s', 'XRANGE s - +', 'XADD s MAXLEN = 1 4-1 a b', 'XADD s MAXLEN ~ 1 5-1 a b', 'XLEN s',
   'XADD s MAXLEN -1 6-1 a b', 'XADD s MAXLEN x 6-1 a b', 'XADD s MAXLEN 1 MINID 1 6-1 a b', 'XADD s MINID 1 MAXLEN 1 6-1 a b',
   'XADD s LIMIT 10 6-1 a b', 'XADD s MAXLEN 1 LIMIT 10 6-1 a b', 'XADD s MAXLEN ~ 1 LIMIT -1 6-1 a b',
   'XADD s MAXLEN ~ 1 LIMIT x 6-1 a b', 'XADD s MINID abc 6-1 a b', 'XADD s MINID 5 6-1 a b', 'XRANGE s - +',
   'XADD s MINID = 7 7-1 a b', 'XRANGE s - +', 'XADD s MAXLEN ~ 0 LIMIT 0 8-1 a b', 'XLEN s', 'XADD s MAXLEN 0 9-1 a b',
   'XLEN s', 'EXISTS s', 'XRANGE s - +', 'XINFO STREAM s', 'XADD s NOMKSTREAM MAXLEN 5 10-1 a b', 'XADD s MAXLEN',
   'XADD s MAXLEN ~', 'XADD s MAXLEN ~ 5', 'XADD s maxlen ~ 5 11-1 a b', 'XADD s NOMKSTREAM', 'XADD s foo 12-1 a b',
 ]),
 ('approximate trimming', [
   *['XADD t %d-1 f v%d' % (i, i) for i in range(1, 351)],
   'XLEN t', 'XINFO STREAM t', 'XTRIM t MAXLEN ~ 120', 'XLEN t', 'XTRIM t MAXLEN ~ 120', 'XTRIM t MINID ~ 290', 'XLEN t',
   'XTRIM t MINID ~ 301', 'XLEN t', 'XTRIM t MAXLEN 10', 'XLEN t', 'XRANGE t - + COUNT 3', 'XINFO STREAM t',
   *['XADD t %d-1 f v%d' % (i, i) for i in range(351, 460)],
   'XINFO STREAM t', 'XTRIM t MAXLEN ~ 50 LIMIT 5', 'XLEN t', 'XTRIM t MAXLEN ~ 50 LIMIT 100', 'XLEN t',
   'XTRIM t MINID 400', 'XLEN t', 'XTRIM t MINID 1000', 'XLEN t', 'XINFO STREAM t',
 ]),
 ('large entries', [
   *['XADD b %d-1 f %s' % (i, BIG) for i in range(1, 40)],
   'XINFO STREAM b', 'XTRIM b MAXLEN ~ 10', 'XLEN b', 'XINFO STREAM b', 'XTRIM b MINID ~ 35', 'XLEN b',
   *['XADD b2 %d-1 f %s' % (i, 'y' * (i * 37 % 700)) for i in range(1, 60)],
   'XINFO STREAM b2', 'XTRIM b2 MAXLEN ~ 20', 'XLEN b2', 'XRANGE b2 50 +',
 ]),
 ('many entries', [
   *['XADD m %d-%d f v' % (i // 7 + 1, i % 7) for i in range(0, 1000)],
   'XLEN m', 'XINFO STREAM m', 'XRANGE m 50 60', 'XREVRANGE m 50 49', 'XRANGE m - + COUNT 3', 'XREVRANGE m + - COUNT 3',
   *['XDEL m %d-%d' % (i // 7 + 1, i % 7) for i in range(0, 1000, 3)],
   'XLEN m', 'XINFO STREAM m', 'XRANGE m 50 60', 'XREVRANGE m 60 50', 'XTRIM m MAXLEN ~ 300', 'XLEN m',
   'XTRIM m MINID ~ 120', 'XLEN m', 'XTRIM m MINID 121-3', 'XLEN m', 'XRANGE m - + COUNT 4', 'XINFO STREAM m',
   *['XADD m %d-1 f v' % i for i in range(200, 400)],
   'XINFO STREAM m', 'XTRIM m MAXLEN ~ 150', 'XLEN m', 'XINFO STREAM m',
 ]),
 ('field sets', [
   'XADD f 1-1 a 1 b 2', 'XADD f 2-1 a 3 b 4', 'XADD f 3-1 b 5 a 6', 'XADD f 4-1 a 7', 'XADD f 5-1 a 8 b 9 c 10',
   'XADD f 6-1 a 11 b 12', 'XRANGE f - +', 'XREVRANGE f + -', ['XADD', 'f', '7-1', 'a', '', 'b', 'x y\r\nz'], 'XRANGE f 7 7',
 ]),
 ('ranges', [
   *['XADD r %d-%d f %d' % (i // 3 + 1, i % 3, i) for i in range(0, 30)],
   'XRANGE r - +', 'XRANGE r - + COUNT 5', 'XRANGE r 3 5', 'XRANGE r 3-1 5-1', 'XRANGE r (3-1 (5-1', 'XRANGE r (3 (5',
   'XREVRANGE r + -', 'XREVRANGE r + - COUNT 4', 'XREVRANGE r 5 3', 'XREVRANGE r (5-2 (3-0', 'XRANGE r 5 3',
   'XRANGE r - + COUNT 0', 'XRANGE r - + COUNT -1', 'XRANGE r - + COUNT x', 'XRANGE r - + FOO 1', 'XRANGE r - + COUNT',
   'XRANGE r ( +', 'XRANGE r (- +', 'XRANGE r - (+', 'XRANGE r (18446744073709551615-18446744073709551615 +',
   'XRANGE r - (0-0', 'XRANGE r abc +', 'XRANGE nokey - +', 'XREVRANGE nokey + -', 'XRANGE r - + COUNT 2 COUNT 3',
   'XRANGE r 10 +', 'XRANGE r 11 +', 'XREVRANGE r + 10', 'XRANGE r 0 0', 'XRANGE r - -', 'XRANGE r + +',
   'XDEL r 5-0 5-1 5-2 1-0', 'XRANGE r 4 6', 'XREVRANGE r 6 4', 'XRANGE r - + COUNT 2', 'XLEN r',
 ]),
 ('wrong type', [
   'SET str v', 'XADD str * a b', 'XLEN str', 'XRANGE str - +', 'XREVRANGE str + -', 'XREAD STREAMS str 0',
   'XREADGROUP GROUP g c STREAMS str >', 'XDEL str 1', 'XTRIM str MAXLEN 1', 'XACK str g 1', 'XPENDING str g',
   'XCLAIM str g c 0 1', 'XAUTOCLAIM str g c 0 0', 'XSETID str 1', 'XGROUP CREATE str g $', 'XINFO STREAM str',
   'XINFO GROUPS str', 'XADD s 1 a b', 'GET s', 'LPUSH s x', 'SADD s x', 'HSET s f v', 'ZADD s 1 m', 'APPEND s x',
   'TYPE s', 'TYPE str',
 ]),
 ('groups', [
   'XGROUP CREATE s g $', 'XGROUP CREATE s g $ MKSTREAM', 'XGROUP CREATE s g $ MKSTREAM', 'EXISTS s', 'XLEN s',
   'XINFO GROUPS s', 'XADD s 1-1 a 1', 'XADD s 2-1 a 2', 'XADD s 3-1 a 3', 'XINFO GROUPS s',
   'XGROUP CREATE s g2 0', 'XGROUP CREATE s g3 2-1 ENTRIESREAD 2', 'XGROUP CREATE s g4 - ', 'XGROUP CREATE s g4 abc',
   'XGROUP CREATE s g5 $ ENTRIESREAD -2', 'XGROUP CREATE s g5 $ ENTRIESREAD x', 'XGROUP CREATE s g5 $ FOO',
   'XGROUP CREATE s g5 $ ENTRIESREAD', 'XGROUP CREATE s g5 $ MKSTREAM ENTRIESREAD 1 x', 'XINFO GROUPS s',
   'XGROUP SETID s g 0', 'XGROUP SETID s nog 0', 'XGROUP SETID s g $ ENTRIESREAD 3', 'XGROUP SETID s g - ',
   'XGROUP SETID s g + ENTRIESREAD 1', 'XGROUP SETID s g 1 MKSTREAM', 'XINFO GROUPS s',
   'XGROUP CREATECONSUMER s g alice', 'XGROUP CREATECONSUMER s g alice', 'XGROUP CREATECONSUMER s nog alice',
   'XGROUP CREATECONSUMER nokey g alice', 'XINFO CONSUMERS s g', 'XINFO CONSUMERS s nog', 'XINFO CONSUMERS nokey g',
   'XGROUP DELCONSUMER s g bob', 'XGROUP DELCONSUMER s g alice', 'XGROUP DELCONSUMER s nog alice',
   'XGROUP DESTROY s g3', 'XGROUP DESTROY s g3', 'XGROUP DESTROY nokey g', 'XINFO GROUPS s', 'XGROUP SETID nokey g 0',
   'XGROUP CREATE nokey g 0', 'XINFO GROUPS nokey', 'XINFO STREAM nokey',
 ]),
 ('readgroup', [
   'XGROUP CREATE s g 0 MKSTREAM', 'XADD s 1-1 a 1', 'XADD s 2-1 a 2', 'XADD s 3-1 a 3', 'XADD s 4-1 a 4',
   'XREADGROUP GROUP g c1 COUNT 2 STREAMS s >', 'XREADGROUP GROUP g c2 STREAMS s >', 'XREADGROUP GROUP g c2 STREAMS s >',
   'XREADGROUP GROUP g c1 STREAMS s 0', 'XREADGROUP GROUP g c1 STREAMS s 1-1', 'XREADGROUP GROUP g c1 COUNT 1 STREAMS s 0',
   'XREADGROUP GROUP g c3 STREAMS s 0', 'XINFO GROUPS s', 'XINFO CONSUMERS s g',
   (pend, 'XPENDING s g - + 10'), 'XPENDING s g', (pend, 'XPENDING s g - + 10 c2'), (pend, 'XPENDING s g - + 10 nobody'),
   (pend, 'XPENDING s g (1-1 + 10'), (pend, 'XPENDING s g - (4-1 1'), 'XPENDING s g IDLE 99999999 - + 10',
   'XPENDING s g - + 0', 'XPENDING s g - + -5', 'XPENDING s g - + x', 'XPENDING s g IDLE x - + 10', 'XPENDING s g IDLE 5 - +',
   'XPENDING s g - +', 'XPENDING s g a b c d e f g', 'XPENDING s nog', 'XPENDING nokey g', 'XPENDING s g x + 10',
   'XACK s g 1-1 2-1 9-9', 'XACK s g 1-1', 'XACK s nog 3-1', 'XACK nokey g 1', 'XACK s g abc', 'XACK s g 3-1 abc', 'XPENDING s g',
   'XREADGROUP GROUP g c1 STREAMS s 0', 'XREADGROUP GROUP nog c1 STREAMS s >', 'XREADGROUP GROUP g c1 STREAMS nokey >',
   'XREADGROUP GROUP g c1 STREAMS s $', 'XREAD STREAMS s >', 'XREAD GROUP g c STREAMS s 0', 'XREAD NOACK STREAMS s 0',
   'XREADGROUP STREAMS s >', 'XREADGROUP GROUP g c1 STREAMS s abc', 'XREADGROUP GROUP g c1 STREAMS s',
   'XADD s 5-1 a 5', 'XREADGROUP GROUP g c4 NOACK STREAMS s >', 'XPENDING s g', 'XINFO GROUPS s', 'XINFO CONSUMERS s g',
   'XREADGROUP GROUP g c4 STREAMS s >', 'XDEL s 3-1', 'XREADGROUP GROUP g c2 STREAMS s 0', 'XINFO GROUPS s',
   'XGROUP SETID s g 0', 'XREADGROUP GROUP g c5 COUNT 2 STREAMS s >', (pend, 'XPENDING s g - + 10'), 'XINFO GROUPS s',
   'XREADGROUP GROUP g c1 COUNT abc STREAMS s >', 'XREADGROUP GROUP g c1 COUNT -3 STREAMS s >',
 ]),
 ('lag and entries-read', [
   'XADD s 1-1 a 1', 'XADD s 2-1 a 2', 'XADD s 3-1 a 3', 'XADD s 4-1 a 4', 'XADD s 5-1 a 5',
   'XGROUP CREATE s g $', 'XGROUP CREATE s h 0', 'XGROUP CREATE s i 3-1', 'XGROUP CREATE s j 1-1',
   'XINFO GROUPS s', 'XREADGROUP GROUP h c COUNT 2 STREAMS s >', 'XREADGROUP GROUP i c COUNT 1 STREAMS s >',
   'XREADGROUP GROUP j c COUNT 1 STREAMS s >', 'XINFO GROUPS s', 'XDEL s 4-1', 'XINFO GROUPS s', 'XADD s 6-1 a 6',
   'XINFO GROUPS s', 'XREADGROUP GROUP h c STREAMS s >', 'XINFO GROUPS s', 'XTRIM s MAXLEN 2', 'XINFO GROUPS s',
   'XDEL s 5-1 6-1', 'XINFO GROUPS s', 'XINFO STREAM s', 'XADD s 7-1 a 7', 'XINFO GROUPS s', 'XSETID s 9-9',
   'XINFO GROUPS s', 'XINFO STREAM s', (full, 'XINFO STREAM s FULL'),
 ]),
 ('xread', [
   'XADD a 1-1 f 1', 'XADD a 2-1 f 2', 'XADD b 1-5 g 1', 'XREAD STREAMS a b 0 0', 'XREAD COUNT 1 STREAMS a b 0 0',
   'XREAD STREAMS a b 1-1 1-5', 'XREAD STREAMS a b 2-1 1-5', 'XREAD STREAMS a b $ $', 'XREAD STREAMS a nokey 0 0',
   'XREAD STREAMS nokey 0', 'XREAD COUNT 0 STREAMS a 0', 'XREAD COUNT -1 STREAMS a 0', 'XREAD STREAMS a a 0 1-1',
   'XREAD STREAMS a b 0', 'XREAD FOO STREAMS a 0', 'XREAD COUNT STREAMS a 0', 'XREAD BLOCK x STREAMS a 0',
   'XREAD BLOCK -1 STREAMS a 0', 'XREAD BLOCK 10 STREAMS a 0', 'XREAD BLOCK 10 STREAMS a $', 'XREAD STREAMS a (0',
   'XREAD STREAMS a -', 'XREAD STREAMS a +', 'XREAD STREAMS a 18446744073709551615-18446744073709551615',
   'XREAD COUNT 1 COUNT 2 STREAMS a 0', 'xread streams a 1', 'XREAD STREAMS a 1-1 x',
 ]),
 ('tail deletes', [
   'XADD s 1-1 a b', 'XADD s 2-1 a b', 'XADD s 3-1 a b', 'XDEL s 3-1', 'XREAD STREAMS s 2-1', 'XREAD STREAMS s 1-1',
   'XGROUP CREATE s g 2-1', 'XREADGROUP GROUP g c STREAMS s >', 'XINFO GROUPS s', 'XINFO STREAM s', 'XADD s 3-1 a b',
   'XADD s 4-1 a b', 'XREADGROUP GROUP g c STREAMS s >', 'XINFO GROUPS s', 'XDEL s 1-1 2-1 4-1', 'XINFO STREAM s',
   'XREAD STREAMS s 0', 'XSETID s 3-1', 'XSETID s 2-1',
 ]),
 ('xdel and xsetid', [
   'XADD s 1-1 a 1', 'XADD s 2-1 a 2', 'XADD s 3-1 a 3', 'XDEL s 2-1', 'XDEL s 2-1', 'XDEL s 1-1 3-1', 'XLEN s',
   'EXISTS s', 'XINFO STREAM s', 'XDEL s abc', 'XDEL nokey abc', 'XDEL s 5-1 abc', 'XADD s 3-1 a b', 'XADD s 4-1 a b',
   'XSETID s 3', 'XSETID s 10-1', 'XADD s 5-1 a b', 'XSETID s 10-1 ENTRIESADDED 1', 'XSETID s 10-1 ENTRIESADDED 7',
   'XSETID s 10-1 ENTRIESADDED -1', 'XSETID s 10-1 ENTRIESADDED x', 'XSETID s 10-1 MAXDELETEDID 11-1',
   'XSETID s 10-1 MAXDELETEDID 5', 'XSETID s 10-1 FOO', 'XSETID s abc', 'XSETID nokey 1', 'XSETID s -', 'XSETID s 10-1 ENTRIESADDED',
   'XINFO STREAM s', 'XADD s 10-1 a b', 'XADD s 10-2 a b', 'XINFO STREAM s', 'XDEL s 10-2', 'XADD s 10-2 x y', 'XRANGE s - +',
 ]),
 ('claim', [
   'XGROUP CREATE s g 0 MKSTREAM', 'XADD s 1-1 a 1', 'XADD s 2-1 a 2', 'XADD s 3-1 a 3', 'XADD s 4-1 a 4',
   'XREADGROUP GROUP g alice STREAMS s >', 'XCLAIM s g bob 0 1-1 2-1', (pend, 'XPENDING s g - + 10'),
   'XCLAIM s g bob 0 3-1 JUSTID', (pend, 'XPENDING s g - + 10'), 'XCLAIM s g carol 999999 4-1',
   'XCLAIM s g carol 0 4-1 RETRYCOUNT 7 JUSTID', (pend, 'XPENDING s g - + 10'), 'XCLAIM s g carol 0 9-9',
   'XCLAIM s g carol 0 9-9 FORCE', 'XCLAIM s g carol 0 4-1 FOO', 'XCLAIM s g carol x 4-1', 'XCLAIM s g carol 0 4-1 IDLE x',
   'XCLAIM s g carol 0 4-1 TIME x', 'XCLAIM s g carol 0 4-1 RETRYCOUNT x', 'XCLAIM s g carol 0 4-1 LASTID x',
   'XCLAIM s nog carol 0 4-1', 'XCLAIM nokey g carol 0 4-1', 'XCLAIM s g carol 0 abc', 'XCLAIM s g carol 0 - 4-1',
   'XACK s g 1-1', 'XCLAIM s g dave 0 1-1', 'XCLAIM s g dave 0 1-1 FORCE JUSTID', (pend, 'XPENDING s g - + 10'),
   'XDEL s 2-1', 'XCLAIM s g dave 0 2-1', 'XPENDING s g', 'XCLAIM s g erin 0 3-1 LASTID 50-1 JUSTID', 'XINFO GROUPS s',
   'XCLAIM s g erin 0 3-1 IDLE 1000 JUSTID', (pend, 'XPENDING s g IDLE 900 - + 10'), (pend, 'XPENDING s g IDLE 5000 - + 10'),
   'XCLAIM s g erin 0 3-1 IDLE -5 JUSTID', 'XINFO CONSUMERS s g', 'XCLAIM s g erin -5 3-1 JUSTID',
   'XCLAIM s g erin 0 3-1 TIME 1 JUSTID', (pend, 'XPENDING s g - + 10'),
 ]),
 ('autoclaim', [
   'XGROUP CREATE s g 0 MKSTREAM', *['XADD s %d-1 a %d' % (i, i) for i in range(1, 11)],
   'XREADGROUP GROUP g alice STREAMS s >', 'XAUTOCLAIM s g bob 0 0 COUNT 3', 'XAUTOCLAIM s g bob 0 4-1 COUNT 3 JUSTID',
   'XAUTOCLAIM s g bob 0 (7-1 COUNT 2', 'XAUTOCLAIM s g bob 0 0', (pend, 'XPENDING s g - + 20'), 'XDEL s 2-1 5-1',
   'XAUTOCLAIM s g carol 0 0 COUNT 3', 'XAUTOCLAIM s g carol 0 0 COUNT 30', 'XPENDING s g',
   'XAUTOCLAIM s g carol 99999999 0', 'XAUTOCLAIM s g carol 0 0 COUNT 0', 'XAUTOCLAIM s g carol 0 0 COUNT -1',
   'XAUTOCLAIM s g carol 0 0 COUNT x', 'XAUTOCLAIM s g carol 0 0 FOO', 'XAUTOCLAIM s g carol x 0', 'XAUTOCLAIM s g carol 0 x',
   'XAUTOCLAIM s nog carol 0 0', 'XAUTOCLAIM nokey g carol 0 0', 'XAUTOCLAIM s g carol 0 (18446744073709551615-18446744073709551615',
   'XAUTOCLAIM s g carol 0 0 COUNT 1000000000000000000000', 'XINFO CONSUMERS s g',
 ]),
 ('xinfo full', [
   'XGROUP CREATE s g 0 MKSTREAM', *['XADD s %d-1 a %d b x' % (i, i) for i in range(1, 16)],
   'XREADGROUP GROUP g alice COUNT 12 STREAMS s >', 'XREADGROUP GROUP g2 x STREAMS s >', 'XGROUP CREATE s g2 5',
   'XREADGROUP GROUP g2 bob COUNT 2 STREAMS s >', (full, 'XINFO STREAM s FULL'), (full, 'XINFO STREAM s FULL COUNT 3'),
   (full, 'XINFO STREAM s FULL COUNT 0'), (full, 'XINFO STREAM s FULL COUNT -1'), 'XINFO STREAM s FULL COUNT x',
   'XINFO STREAM s FULL COUNT', 'XINFO STREAM s FOO', 'XINFO STREAM s FULL FOO 1', 'XINFO STREAM s', 'XINFO GROUPS s',
 ]),
 ('empty streams', [
   'XADD s 1-1 a b', 'XDEL s 1-1', 'XLEN s', 'XRANGE s - +', 'XINFO STREAM s', 'XADD s 1-1 a b', 'XADD s 2-1 a b',
   'XTRIM s MAXLEN 0', 'XINFO STREAM s', 'XREAD STREAMS s 0', 'XGROUP CREATE s g $', 'XINFO GROUPS s',
   'XREADGROUP GROUP g c STREAMS s >', 'XREADGROUP GROUP g c STREAMS s 0', 'XINFO CONSUMERS s g', 'TYPE s', 'DEL s', 'EXISTS s',
 ]),
 ('keyspace', [
   'XADD s 1-1 a b', 'XGROUP CREATE s g 0', 'XREADGROUP GROUP g c STREAMS s >', 'TYPE s', 'EXISTS s', 'KEYS *',
   'SCAN 0 TYPE stream', 'RENAME s t', 'TYPE t', 'XPENDING t g', 'COPY t u', 'XPENDING u g', 'XRANGE u - +', 'XINFO GROUPS u',
   'DEL t u', 'EXISTS t u', 'XADD e 1-1 a b', 'EXPIRE e 100', 'TTL e', 'PERSIST e', 'TTL e', 'DBSIZE',
 ]),
 ('transactions and scripts', [
   'MULTI', 'XADD m 1-1 a b', 'XREAD STREAMS m 0', 'XREAD BLOCK 0 STREAMS m $', 'XLEN m', 'EXEC',
   'MULTI', 'XGROUP CREATE m g 0', 'XREADGROUP GROUP g c BLOCK 0 STREAMS m >', 'XREADGROUP GROUP g c BLOCK 0 STREAMS m >', 'EXEC',
   'MULTI', 'XADD m 0-1 a b', 'XLEN m', 'EXEC',
   ['EVAL', "return redis.call('XADD', KEYS[1], '2-1', 'a', 'b')", '1', 'm'],
   ['EVAL', "return redis.call('XRANGE', KEYS[1], '-', '+')", '1', 'm'],
   ['EVAL', "return redis.call('XREAD', 'BLOCK', '0', 'STREAMS', KEYS[1], '0')", '1', 'm'],
   ['EVAL', "return redis.call('xread', 'block', '0', 'STREAMS', KEYS[1], '0')", '1', 'm'],
   ['EVAL', "return redis.call('XREAD', 'STREAMS', KEYS[1], '0')", '1', 'm'],
   ['EVAL', "return redis.pcall('XGROUP', 'SETID', KEYS[1], 'nog', '0')", '1', 'm'],
   ['EVAL', "return redis.call('XREADGROUP', 'GROUP', 'g', 'c2', 'STREAMS', KEYS[1], '>')", '1', 'm'],
   ['EVAL', "return redis.call('XPENDING', KEYS[1], 'g')", '1', 'm'],
   ['EVAL', "return redis.call('XADD', KEYS[1], '0-1', 'a', 'b')", '1', 'm'],
 ]),
]

ra, sa = int(sys.argv[1]), int(sys.argv[2])
compared = differ = 0
for name, cmds in SCENARIOS:
    a, b = Conn(ra), Conn(sa)
    a.cmd('FLUSHALL'); b.cmd('FLUSHALL')
    for c in cmds:
        post = None
        if isinstance(c, tuple): post, c = c
        if isinstance(c, str): c = c.split(' ')
        x, y = norm(a.cmd(*c)), norm(b.cmd(*c))
        if post: x, y = post(x), post(y)
        compared += 1
        if x != y:
            differ += 1
            print('bad [%s] %s | redis: %r | socketley: %r' % (name, ' '.join(c)[:120], x, y))

# Blocked readers, woken or timed out, answer what Redis's do.
def blocking(port):
    c = Conn(port); c.cmd('FLUSHALL'); out = []
    def later(*args):
        r = {}
        def run(): r['v'] = Conn(port).cmd(*args)
        t = threading.Thread(target=run); t.start(); return t, r
    t, r = later('XREAD', 'BLOCK', '5000', 'STREAMS', 'k', '$'); time.sleep(0.3)
    c.cmd('XADD', 'k', '1-1', 'a', 'b'); t.join(); out.append(r['v'])
    out.append(Conn(port).cmd('XREAD', 'BLOCK', '200', 'STREAMS', 'k', '$'))
    c.cmd('XGROUP', 'CREATE', 'q', 'g', '$', 'MKSTREAM')
    ws = []
    for i in range(2):
        ws.append(later('XREADGROUP', 'GROUP', 'g', 'c%d' % i, 'COUNT', '5', 'BLOCK', '3000', 'STREAMS', 'q', '>'))
        time.sleep(0.2)
    c.cmd('XADD', 'q', '1-1', 'job', '1'); time.sleep(0.2); c.cmd('XADD', 'q', '2-1', 'job', '2')
    for t, r in ws: t.join(); out.append(r['v'])
    out.append(c.cmd('XPENDING', 'q', 'g'))
    t, r = later('XREAD', 'COUNT', '1', 'BLOCK', '3000', 'STREAMS', 'm1', 'm2', '$', '$'); time.sleep(0.3)
    p = Conn(port); p.send(['XADD', 'm2', '5-1', 'a', 'b']); p.send(['XADD', 'm2', '6-1', 'a', 'b']); p.reply(); p.reply()
    t.join(); out.append(r['v'])
    c.cmd('XGROUP', 'CREATE', 'd', 'g', '$', 'MKSTREAM')
    t, r = later('XREADGROUP', 'GROUP', 'g', 'c', 'BLOCK', '3000', 'STREAMS', 'd', '>'); time.sleep(0.3)
    c.cmd('XGROUP', 'DESTROY', 'd', 'g'); t.join(); out.append(r['v'])
    c.cmd('XGROUP', 'CREATE', 'e', 'g', '$', 'MKSTREAM')
    t, r = later('XREADGROUP', 'GROUP', 'g', 'c', 'BLOCK', '3000', 'STREAMS', 'e', '>'); time.sleep(0.3)
    c.cmd('DEL', 'e'); t.join(); out.append(r['v'])
    return out

x, y = blocking(ra), blocking(sa)
for i, (u, v) in enumerate(zip(x, y)):
    compared += 1
    if u != v:
        differ += 1
        print('bad [blocking %d] | redis: %r | socketley: %r' % (i, u, v))
print('compared %d %d' % (compared, differ))
PYEOF
)
echo "$OUT" | grep '^bad ' | sed 's/^bad /  FAIL /'
SUMMARY=$(echo "$OUT" | awk '/^compared /{print $2, $3}')
TOTAL=${SUMMARY% *}; FAIL=${SUMMARY#* }
if [ -z "$SUMMARY" ]; then
    echo "  FAIL: the comparison did not run to its end"
    echo "$OUT" | tail -5 | sed 's/^/        /'
    echo "  Results: 0/1 passed (1 failed)"
    exit 1
fi
echo "  Results: $((TOTAL - FAIL))/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
