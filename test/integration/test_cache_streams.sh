#!/usr/bin/env bash
# Integration test: streams, every command and the paths a stream write takes
# through the cache besides its reply
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A stream is the one type here whose writes are not the command the client
# sent: an XADD with * is replicated with the id it got, an XREADGROUP is a
# read whose side effect is a pending entry on another consumer's books, and a
# reader parked with BLOCK is answered by somebody else's XADD.  So beside the
# replies, which test_cache_streams_vs_redis.sh compares against a real
# redis-server, this runs a stream through what else can see it: a restart
# from the dump and from the journal, a follower, a transaction, a script, the
# line protocol, a memory limit and a sharded cache.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * ids: an auto id at or below the last one, a same-millisecond id that does
#     not count up its sequence, an explicit id below the top accepted
#   * MAXLEN ~ trimming entries rather than whole blocks, or more than asked
#   * $ reading what was there before, > re-delivering what a group has
#     delivered, a history read not seeing the consumer's own pending entries
#   * a consumer that died leaving entries nobody can claim, XAUTOCLAIM missing
#     one, or not reporting an entry XDEL took from under the group
#   * NOACK leaving pending entries behind
#   * a blocked reader not woken by the XADD it waits for, woken with the wrong
#     entries, answered twice, or not timing out; a pipelined command behind it
#     never answered; a reader of a destroyed group or deleted key left waiting
#   * WRONGTYPE missing for a stream command on another type, or for another
#     type's command on a stream
#   * a refused XADD that changed the stream anyway
#   * a restart or a follower that does not hold the same entries, counters,
#     groups, pending entries, delivery times and consumers, byte for byte in
#     XINFO STREAM FULL
#   * a stream command on a sharded cache served from the wrong slice
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0; TOTAL=0
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: streams, and everything a stream write passes through ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

daemon_isolate streams
daemon_start "$BIN"

P=$((SL_PORT_BASE + 1500))        # the plain cache
PM=$((SL_PORT_BASE + 1502))       # a memory limit
PP=$((SL_PORT_BASE + 1504))       # persistence
PL=$((SL_PORT_BASE + 1506))       # replication leader
PF=$((SL_PORT_BASE + 1508))       # its follower
PS=$((SL_PORT_BASE + 1510))       # two shards, cluster ports above it

wait_port() { local i; for i in $(seq 1 100); do
    python3 -c "import socket,sys; socket.create_connection(('127.0.0.1',int(sys.argv[1])),1).close()" "$1" 2>/dev/null && return 0
    sleep 0.1; done; return 1; }

X=$SOCKETLEY_TMPD/sx.py
cat > "$X" <<'PYEOF'
import json, socket, sys, threading, time

class Err(str):
    pass

class Conn:
    def __init__(self, port, timeout=10):
        self.s = socket.create_connection(('127.0.0.1', port), timeout=timeout)
        self.buf = b''
    def send(self, *a):
        p = b'*%d\r\n' % len(a)
        for x in a:
            x = x if isinstance(x, bytes) else str(x).encode()
            p += b'$%d\r\n%s\r\n' % (len(x), x)
        self.s.sendall(p)
    def _fill(self):
        d = self.s.recv(65536)
        if not d: raise EOFError('connection closed')
        self.buf += d
    def _line(self):
        while b'\r\n' not in self.buf: self._fill()
        i = self.buf.index(b'\r\n'); l = self.buf[:i]; self.buf = self.buf[i + 2:]
        return l
    def reply(self):
        l = self._line(); t, r = l[:1], l[1:]
        if t == b'+': return r.decode('latin1')
        if t == b'-': return Err(r.decode('latin1'))
        if t == b':': return int(r)
        if t == b'$':
            n = int(r)
            if n < 0: return None
            while len(self.buf) < n + 2: self._fill()
            v = self.buf[:n].decode('latin1'); self.buf = self.buf[n + 2:]
            return v
        if t == b'*':
            n = int(r)
            return None if n < 0 else [self.reply() for _ in range(n)]
        raise ValueError(l)
    def __call__(self, *a):
        self.send(*a)
        return self.reply()

RESULTS = []
def check(label, got, want):
    if got == want: RESULTS.append('ok ' + label)
    else: RESULTS.append('bad %s: got %s, want %s' % (label, json.dumps(got)[:300], json.dumps(want)[:300]))
def truth(label, cond, detail=''):
    RESULTS.append(('ok ' + label) if cond else ('bad %s: %s' % (label, detail)))
def done():
    for r in RESULTS: print(r)

def later(f, *a):
    out = {}
    def run():
        try: out['r'] = f(*a)
        except Exception as e: out['r'] = 'EXC %r' % e
    t = threading.Thread(target=run); t.start()
    return t, out

def snapshot(port, keys):
    c = Conn(port)
    return json.dumps({k: [c('XINFO', 'STREAM', k, 'FULL', 'COUNT', '0'), c('XLEN', k)] for k in keys}, sort_keys=True)

def populate(port):
    c = Conn(port)
    c('XGROUP', 'CREATE', 'ps', 'g', '0', 'MKSTREAM')
    c('XGROUP', 'CREATE', 'ps', 'h', '$')
    for i in range(1, 251):
        c('XADD', 'ps', '*', 'n', str(i), 'payload', 'v' * (i % 40), 'sp', 'a b\r\nc')
    c('XREADGROUP', 'GROUP', 'g', 'alice', 'COUNT', '30', 'STREAMS', 'ps', '>')
    c('XREADGROUP', 'GROUP', 'g', 'bob', 'COUNT', '20', 'STREAMS', 'ps', '>')
    c('XREADGROUP', 'GROUP', 'g', 'carol', 'NOACK', 'COUNT', '5', 'STREAMS', 'ps', '>')
    ids = [e[0] for e in c('XRANGE', 'ps', '-', '+', 'COUNT', '60')]
    c('XACK', 'ps', 'g', *ids[0:10])
    c('XDEL', 'ps', ids[12], ids[40], ids[55])
    c('XCLAIM', 'ps', 'g', 'dave', '0', ids[20], ids[21], 'RETRYCOUNT', '9')
    c('XGROUP', 'CREATECONSUMER', 'ps', 'h', 'idle-one')
    c('XTRIM', 'ps', 'MAXLEN', '~', '120')
    c('XADD', 'es', '5-5', 'a', 'b'); c('XDEL', 'es', '5-5')
    c('XGROUP', 'CREATE', 'eg', 'g', '$', 'MKSTREAM')

def more(port):
    c = Conn(port)
    for i in range(30): c('XADD', 'ps', '*', 'late', str(i), 'sp', 'x y\nz')
    c('XREADGROUP', 'GROUP', 'g', 'erin', 'COUNT', '7', 'STREAMS', 'ps', '>')
    c('XREADGROUP', 'GROUP', 'g', 'erin', 'COUNT', '3', 'STREAMS', 'ps', '0')
    c('XREADGROUP', 'GROUP', 'h', 'nack', 'NOACK', 'COUNT', '3', 'STREAMS', 'ps', '>')
    c('XAUTOCLAIM', 'ps', 'g', 'frank', '0', '0', 'COUNT', '4')
    c('XCLAIM', 'ps', 'g', 'gina', '0', c('XPENDING', 'ps', 'g')[1], 'LASTID', '99999999999999-0')
    c('XGROUP', 'DELCONSUMER', 'ps', 'g', 'bob')
    c('XGROUP', 'SETID', 'ps', 'h', '0', 'ENTRIESREAD', '3')
    c('XSETID', 'es', '9-9', 'ENTRIESADDED', '42', 'MAXDELETEDID', '7-7')
    c('XADD', 'ps', 'MAXLEN', '~', '100', '*', 'trim', 'me')
    c('XACK', 'ps', 'g', *[e[0] for e in c('XPENDING', 'ps', 'g', '-', '+', '5')])
    c('XDEL', 'ps', c('XRANGE', 'ps', '-', '+', 'COUNT', '1')[0][0])
    c('XGROUP', 'CREATE', 'mk', 'g', '0', 'MKSTREAM')
    c('MULTI'); c('XADD', 'mk', '1-1', 'a', 'b'); c('XREADGROUP', 'GROUP', 'g', 'c', 'STREAMS', 'mk', '>'); c('EXEC')
    c('EVAL', "return redis.call('XADD', KEYS[1], '2-1', 'lua', 'yes')", '1', 'mk')

KEYS = ['ps', 'es', 'eg', 'mk']
PYEOF

section() { local mode=$1; shift
    # The body runs inside a try, so a reply of the wrong shape is one failure
    # counted rather than a traceback and a section that reported nothing.
    local body; body=$(sed 's/^/    /')
    local out; out=$(cd "$SOCKETLEY_TMPD" && timeout 120 python3 - "$@" <<PY
import sys, traceback; sys.path.insert(0, '.')
from sx import *
try:
$body
except Exception:
    RESULTS.append('bad the section stopped: ' + traceback.format_exc().strip().splitlines()[-1])
done()
PY
)
    local line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        TOTAL=$((TOTAL+1))
        case "$line" in
            ok\ *)  PASS=$((PASS+1)) ;;
            *)      FAIL=$((FAIL+1)); echo "  FAIL [$mode] ${line#bad }" ;;
        esac
    done <<< "$out"
}

"$BIN" create cache st -p "$P" -s >/dev/null 2>&1
wait_port "$P" || { echo "  FATAL: the cache never listened"; exit 2; }

# ─── 1. Ids ─────────────────────────────────────────────────────────────────
section ids "$P" <<'PY'
c = Conn(int(sys.argv[1]))
ids = [c('XADD', 'i', '*', 'n', str(k)) for k in range(500)]
parsed = [tuple(map(int, x.split('-'))) for x in ids]
truth('500 auto ids strictly increase', all(a < b for a, b in zip(parsed, parsed[1:])), ids[:3])
truth('an auto id is the wall clock in ms', abs(parsed[-1][0] - int(time.time() * 1000)) < 60000, ids[-1])
check('an id at the top is refused', c('XADD', 'i', ids[-1], 'a', 'b'),
      Err('ERR The ID specified in XADD is equal or smaller than the target stream top item'))
top = parsed[-1][0] + 100000
check('an explicit ms-* starts at sequence 0', c('XADD', 'i', '%d-*' % top, 'a', 'b'), '%d-0' % top)
check('the same ms counts its sequence up', c('XADD', 'i', '%d-*' % top, 'a', 'b'), '%d-1' % top)
check('an auto id behind a future top takes the top ms', c('XADD', 'i', '*', 'a', 'b'), '%d-2' % top)
check('0-0 is refused', c('XADD', 'z', '0-0', 'a', 'b'), Err('ERR The ID specified in XADD must be greater than 0-0'))
check('NOMKSTREAM on nothing is nil', c('XADD', 'nomk', 'NOMKSTREAM', '*', 'a', 'b'), None)
check('and makes no key', c('EXISTS', 'nomk'), 0)
check('a malformed id', c('XADD', 'i', '1-x', 'a', 'b'), Err('ERR Invalid stream ID specified as stream command argument'))
check('XLEN', c('XLEN', 'i'), 503)
check('TYPE', c('TYPE', 'i'), 'stream')
PY

# ─── 2. Ranges, deletes and trims ───────────────────────────────────────────
section ranges "$P" <<'PY'
c = Conn(int(sys.argv[1]))
for k in range(1, 251): c('XADD', 'r', '%d-1' % k, 'f', str(k))
check('XRANGE with COUNT', [e[0] for e in c('XRANGE', 'r', '-', '+', 'COUNT', '3')], ['1-1', '2-1', '3-1'])
check('an exclusive range', [e[0] for e in c('XRANGE', 'r', '(1-1', '(4-1')], ['2-1', '3-1'])
check('XREVRANGE', [e[0] for e in c('XREVRANGE', 'r', '+', '-', 'COUNT', '2')], ['250-1', '249-1'])
check('an entry reads back its fields', c('XRANGE', 'r', '7', '7'), [['7-1', ['f', '7']]])
check('XDEL counts what went', c('XDEL', 'r', '2-1', '2-1', '999-1'), 1)
check('a deleted entry is not in a range', [e[0] for e in c('XRANGE', 'r', '1', '3')], ['1-1', '3-1'])
# 250 entries sit in blocks of 100, and ~ only drops whole ones.
check('MAXLEN ~ drops whole blocks only', c('XTRIM', 'r', 'MAXLEN', '~', '120'), 99)
check('and leaves more than it was asked to', c('XLEN', 'r'), 150)
check('exact MAXLEN leaves exactly that', c('XTRIM', 'r', 'MAXLEN', '10'), 140)
check('MINID', c('XTRIM', 'r', 'MINID', '245'), 4)
check('what is left', [e[0] for e in c('XRANGE', 'r', '-', '+')], ['%d-1' % k for k in range(245, 251)])
check('XADD MAXLEN trims as it adds', c('XADD', 'r', 'MAXLEN', '2', '300-1', 'a', 'b'), '300-1')
check('to two', c('XLEN', 'r'), 2)
info = c('XINFO', 'STREAM', 'r')
d = dict(zip(info[0::2], info[1::2]))
check('XINFO STREAM counts every entry ever added', d['entries-added'], 251)
check('and the largest deleted id', d['max-deleted-entry-id'], '2-1')
PY

# ─── 3. Groups: $, >, history, NOACK, claims ────────────────────────────────
section groups "$P" <<'PY'
c = Conn(int(sys.argv[1]))
for k in range(1, 6): c('XADD', 'q', '%d-1' % k, 'job', str(k))
check('a group at $ sees nothing that was there', c('XGROUP', 'CREATE', 'q', 'late', '$'), 'OK')
check('so > answers nil', c('XREADGROUP', 'GROUP', 'late', 'w', 'STREAMS', 'q', '>'), None)
check('a group at 0', c('XGROUP', 'CREATE', 'q', 'g', '0'), 'OK')
check('BUSYGROUP', c('XGROUP', 'CREATE', 'q', 'g', '0'), Err('BUSYGROUP Consumer Group name already exists'))
got = c('XREADGROUP', 'GROUP', 'g', 'w1', 'COUNT', '2', 'STREAMS', 'q', '>')
check('> delivers the oldest undelivered', [e[0] for e in got[0][1]], ['1-1', '2-1'])
got = c('XREADGROUP', 'GROUP', 'g', 'w2', 'STREAMS', 'q', '>')
check('and never the same entry twice', [e[0] for e in got[0][1]], ['3-1', '4-1', '5-1'])
check('> with nothing new is nil', c('XREADGROUP', 'GROUP', 'g', 'w2', 'STREAMS', 'q', '>'), None)
got = c('XREADGROUP', 'GROUP', 'g', 'w1', 'STREAMS', 'q', '0')
check('0 reads the consumer\'s own pending entries', [e[0] for e in got[0][1]], ['1-1', '2-1'])
summary = c('XPENDING', 'q', 'g')
check('XPENDING summary', summary, [5, '1-1', '5-1', [['w1', '2'], ['w2', '3']]])
ext = c('XPENDING', 'q', 'g', '-', '+', '10', 'w1')
check('extended XPENDING for one consumer', [[e[0], e[1], e[3]] for e in ext], [['1-1', 'w1', 2], ['2-1', 'w1', 2]])
check('XACK', c('XACK', 'q', 'g', '1-1', '9-9'), 1)
check('NOACK leaves nothing pending', (c('XADD', 'q', '6-1', 'job', '6'),
      c('XREADGROUP', 'GROUP', 'g', 'w3', 'NOACK', 'STREAMS', 'q', '>')[0][1][0][0], c('XPENDING', 'q', 'g')[0]), ('6-1', '6-1', 4))
# A consumer that took work and died: its entries are claimed by idle time.
time.sleep(1.5)
check('XCLAIM respects min-idle-time', c('XCLAIM', 'q', 'g', 'w4', '10000', '3-1', 'JUSTID'), [])
check('and claims once it has passed', c('XCLAIM', 'q', 'g', 'w4', '100', '3-1', 'JUSTID'), ['3-1'])
check('XDEL under the group', c('XDEL', 'q', '4-1'), 1)
ac = c('XAUTOCLAIM', 'q', 'g', 'w5', '1000', '0', 'COUNT', '10')
check('XAUTOCLAIM takes what is idle', [e[0] for e in ac[1]], ['2-1', '5-1'])
check('and reports the entry XDEL took', ac[2], ['4-1'])
check('and a cursor that says it is done', ac[0], '0-0')
check('the deleted entry left the PEL', [e[0] for e in c('XPENDING', 'q', 'g', '-', '+', '10')], ['2-1', '3-1', '5-1'])
cons = {x[1]: x[3] for x in c('XINFO', 'CONSUMERS', 'q', 'g')}
check('XINFO CONSUMERS', cons, {'w1': 0, 'w2': 0, 'w3': 0, 'w4': 1, 'w5': 2})
check('XGROUP DELCONSUMER answers its pending count', c('XGROUP', 'DELCONSUMER', 'q', 'g', 'w5'), 2)
grp = [dict(zip(g[0::2], g[1::2])) for g in c('XINFO', 'GROUPS', 'q')]
check('XINFO GROUPS', [(g['name'], g['pending'], g['last-delivered-id']) for g in grp],
      [('g', 1, '6-1'), ('late', 0, '5-1')])
check('NOGROUP', c('XREADGROUP', 'GROUP', 'nope', 'w', 'STREAMS', 'q', '>'),
      Err("NOGROUP No such key 'q' or consumer group 'nope' in XREADGROUP with GROUP option"))
# A key that spells a reply ends no error early: the next reply is the next command's.
odd = c('XREADGROUP', 'GROUP', 'nope', 'w', 'STREAMS', 'q\r\n+OK', '>')
check('an error naming a key with CR LF in it stays one reply', (isinstance(odd, Err), c('PING')), (True, 'PONG'))
check('XGROUP DESTROY', c('XGROUP', 'DESTROY', 'q', 'late'), 1)
PY

# ─── 4. Types, transactions, scripts ────────────────────────────────────────
section types "$P" <<'PY'
c = Conn(int(sys.argv[1]))
WT = Err('WRONGTYPE Operation against a key holding the wrong kind of value')
c('SET', 'str', 'v'); c('XADD', 'x', '1-1', 'a', 'b')
for cmd in (['XADD', 'str', '*', 'a', 'b'], ['XLEN', 'str'], ['XRANGE', 'str', '-', '+'], ['XREAD', 'STREAMS', 'str', '0'],
            ['XGROUP', 'CREATE', 'str', 'g', '$'], ['XINFO', 'STREAM', 'str'], ['XTRIM', 'str', 'MAXLEN', '0'],
            ['XDEL', 'str', '1'], ['XACK', 'str', 'g', '1'], ['XPENDING', 'str', 'g'], ['XSETID', 'str', '5']):
    check('WRONGTYPE for ' + cmd[0], c(*cmd), WT)
for cmd in (['GET', 'x'], ['LPUSH', 'x', 'v'], ['SADD', 'x', 'm'], ['HSET', 'x', 'f', 'v'], ['ZADD', 'x', '1', 'm']):
    check('WRONGTYPE for %s on a stream' % cmd[0], c(*cmd), WT)
found = c('SCAN', '0', 'TYPE', 'stream', 'COUNT', '1000')[1]
truth('SCAN TYPE stream finds streams and nothing else', 'x' in found and 'str' not in found
      and all(c('TYPE', k) == 'stream' for k in found), found)
check('RENAME carries a stream', (c('RENAME', 'x', 'y'), c('XRANGE', 'y', '-', '+')), ('OK', [['1-1', ['a', 'b']]]))
check('COPY copies it', (c('COPY', 'y', 'z'), c('XLEN', 'z')), (1, 1))
check('EXPIRE ends it', (c('PEXPIRE', 'z', '50'), time.sleep(0.2), c('EXISTS', 'z'))[2], 0)
check('MULTI queues stream commands', (c('MULTI'), c('XADD', 'm', '1-1', 'a', 'b'), c('XLEN', 'm'),
      c('XREAD', 'BLOCK', '0', 'STREAMS', 'm', '$'), c('EXEC')), ('OK', 'QUEUED', 'QUEUED', 'QUEUED', ['1-1', 1, None]))
w = Conn(int(sys.argv[1]))
w('WATCH', 'm'); c('XADD', 'm', '2-1', 'a', 'b'); w('MULTI'); w('XLEN', 'm')
check('an XADD dirties a WATCH on its stream', w('EXEC'), None)
w('WATCH', 'm'); c('XGROUP', 'CREATE', 'm', 'g', '0'); w('MULTI'); w('XLEN', 'm')
check('and so does XGROUP, whose key is its third word', w('EXEC'), None)
check('a script adds', c('EVAL', "return redis.call('XADD', KEYS[1], '3-1', 'lua', '1')", '1', 'm'), '3-1')
check('and reads', c('EVAL', "return redis.call('XLEN', KEYS[1])", '1', 'm'), 3)
check('a script may not block', c('EVAL', "return redis.call('XREAD', 'BLOCK', '0', 'STREAMS', KEYS[1], '$')", '1', 'm')[:65],
      'ERR XREAD command is not allowed with BLOCK option from scripts')
check('COMMAND INFO XADD', c('COMMAND', 'INFO', 'XADD')[0][:2], ['xadd', -5])
PY

# ─── 5. Readers that wait ───────────────────────────────────────────────────
section blocking "$P" <<'PY'
port = int(sys.argv[1])
c = Conn(port)
def waiter(*a):
    t0 = time.time(); r = Conn(port)(*a); return r, time.time() - t0
t, out = later(waiter, 'XREAD', 'BLOCK', '5000', 'STREAMS', 'b', '$')
time.sleep(0.3); c('XADD', 'b', '1-1', 'a', 'b'); t.join()
check('XREAD BLOCK is woken by the XADD', out['r'][0], [['b', [['1-1', ['a', 'b']]]]])
truth('and at once', out['r'][1] < 1.0, out['r'][1])
r, took = waiter('XREAD', 'BLOCK', '300', 'STREAMS', 'b', '$')
check('a timeout answers nil', r, None)
truth('after the timeout', 0.25 < took < 1.5, took)
c('XGROUP', 'CREATE', 'jobs', 'g', '$', 'MKSTREAM')
ts = []
for i in range(3):
    ts.append(later(waiter, 'XREADGROUP', 'GROUP', 'g', 'w%d' % i, 'BLOCK', '5000', 'STREAMS', 'jobs', '>')); time.sleep(0.15)
for k in range(3): c('XADD', 'jobs', '%d-1' % (k + 1), 'job', str(k))
got = []
for t, o in ts: t.join(); got.append(o['r'][0][0][1][0][0])
check('three blocked consumers, three jobs, one each in the order they waited', got, ['1-1', '2-1', '3-1'])
check('each is pending once', c('XPENDING', 'jobs', 'g')[0], 3)
p = Conn(port)
p.send('XREAD', 'BLOCK', '200', 'STREAMS', 'b', '$'); p.send('PING')
check('a command pipelined behind the wait is answered after it', [p.reply(), p.reply()], [None, 'PONG'])
d = Conn(port); d.send('XREAD', 'BLOCK', '0', 'STREAMS', 'gone', '$'); time.sleep(0.2); d.s.close(); time.sleep(0.2)
check('a reader that hung up is not written to', c('XADD', 'gone', '1-1', 'a', 'b'), '1-1')
check('and the stream holds that entry once', c('XREAD', 'STREAMS', 'gone', '0'), [['gone', [['1-1', ['a', 'b']]]]])
c('XGROUP', 'CREATE', 'dg', 'g', '$', 'MKSTREAM')
t, out = later(waiter, 'XREADGROUP', 'GROUP', 'g', 'c', 'BLOCK', '5000', 'STREAMS', 'dg', '>')
time.sleep(0.3); c('XGROUP', 'DESTROY', 'dg', 'g'); t.join()
check('a destroyed group wakes its reader with NOGROUP', out['r'][0],
      Err('NOGROUP the consumer group this client was blocked on no longer exists'))
c('XGROUP', 'CREATE', 'dk', 'g', '$', 'MKSTREAM')
t, out = later(waiter, 'XREADGROUP', 'GROUP', 'g', 'c', 'BLOCK', '5000', 'STREAMS', 'dk', '>')
time.sleep(0.3); c('DEL', 'dk'); t.join()
check('a deleted stream wakes a group reader', out['r'][0], Err('UNBLOCKED the stream key no longer exists'))
t, out = later(waiter, 'XREAD', 'BLOCK', '0', 'STREAMS', 'mx', '$')
time.sleep(0.3); c('MULTI'); c('XADD', 'mx', '1-1', 'a', 'b'); c('XADD', 'mx', '2-1', 'a', 'b'); c('EXEC'); t.join()
check('a reader woken by a transaction sees all of it', [e[0] for e in out['r'][0][0][1]], ['1-1', '2-1'])
PY

# ─── 6. The line protocol ───────────────────────────────────────────────────
section text "$P" <<'PY'
port = int(sys.argv[1])
def text(line, wait=0.3):
    s = socket.create_connection(('127.0.0.1', port), 5); s.sendall(line.encode() + b'\n')
    time.sleep(wait); s.settimeout(0.5); out = b''
    try:
        while True:
            b = s.recv(65536)
            if not b: break
            out += b
    except socket.timeout: pass
    s.close(); return out.decode()
check('xadd', text('xadd tx 1-1 f v'), '1-1\n')
check('xrange, one entry a line', text('xrange tx - +'), '1-1 f v\nend\n')
check('xlen', text('xlen tx'), '1\n')
check('an error in this protocol\'s words', text('xadd tx 1-1 f v'),
      'error: The ID specified in XADD is equal or smaller than the target stream top item\n')
check('a type conflict', text('xlen nokey\nset s v\nxlen s'), '0\nok\nerror: type conflict\n')
t, out = later(text, 'xread block 3000 streams tx $', 1.5)
time.sleep(0.3); Conn(port)('XADD', 'tx', '2-1', 'g', 'w'); t.join()
check('a blocked line reader is woken, the stream named on each entry', out['r'], 'tx 2-1 g w\nend\n')
PY

# ─── 7. A memory limit refuses and changes nothing ──────────────────────────
"$BIN" create cache stm -p "$PM" --maxmemory 1M -s >/dev/null 2>&1
wait_port "$PM" || { echo "  FATAL: the limited cache never listened"; exit 2; }
section maxmemory "$PM" <<'PY'
port = int(sys.argv[1])
c = Conn(port)
c('XGROUP', 'CREATE', 'big', 'g', '0', 'MKSTREAM')
refused = None
for k in range(1, 100000):
    r = c('XADD', 'big', '%d-1' % k, 'f', 'x' * 500)
    if isinstance(r, Err): refused = (k, r); break
truth('XADD is refused once the limit is reached', refused is not None and refused[1].startswith('OOM'), refused)
before = snapshot(port, ['big'])
check('a refused XADD again', c('XADD', 'big', '999999-1', 'f', 'x' * 500)[:3], 'OOM')
check('a refused XGROUP CREATE', c('XGROUP', 'CREATE', 'big', 'g' * 2000, '0')[:3], 'OOM')
check('a refused new stream', c('XADD', 'other', '1-1', 'f', 'x' * 20000)[:3], 'OOM')
check('makes no key', c('EXISTS', 'other'), 0)
truth('and leaves the stream exactly as it was', snapshot(port, ['big']) == before)
check('the stream still reads', c('XLEN', 'big'), refused[0] - 1 if refused else -1)
check('and trimming frees room for the next', (c('XTRIM', 'big', 'MAXLEN', '10') > 0, c('XADD', 'big', '999999-1', 'f', 'y')), (True, '999999-1'))
PY

# ─── 8. Across a restart, from the dump and from the journal ────────────────
DUMP=$SOCKETLEY_TMPD/streams.rdb
"$BIN" create cache stp -p "$PP" --persistent "$DUMP" --persistent-interval 1s -s >/dev/null 2>&1
wait_port "$PP" || { echo "  FATAL: the persistent cache never listened"; exit 2; }
( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; populate($PP)" )
S1=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PP, KEYS))" )
# `stop` answers before the worker has written its dump, so the dump is waited for.
"$BIN" stop stp >/dev/null 2>&1
for _ in $(seq 1 100); do [ -f "$DUMP" ] && ! [ -e "$DUMP.tmp" ] && break; sleep 0.1; done
sleep 0.5
"$BIN" start stp >/dev/null 2>&1
wait_port "$PP"
S2=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PP, KEYS))" )
TOTAL=$((TOTAL+1))
if [ -n "$S1" ] && [ "$S1" = "$S2" ]; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [persistence]: the streams came back from the dump different (${#S1} vs ${#S2} bytes)"; fi

( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; more($PP)" )
S3=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PP, KEYS))" )
sleep 1.5                         # past the journal's interval
for pid in $("$BIN" stats stp 2>/dev/null | awk -F: '/^pid:/ {print $2}' | tr ',' ' '); do
    grep -qa socketley "/proc/$pid/cmdline" 2>/dev/null && kill -9 "$pid" 2>/dev/null
done
sleep 1
# The daemon revives a killed worker itself, and is asked to where it did not.
ping_ok() { python3 -c "from sx import *; import sys; sys.exit(0 if Conn($PP, 1)('PING') == 'PONG' else 1)" 2>/dev/null; }
for _ in $(seq 1 50); do ( cd "$SOCKETLEY_TMPD" && ping_ok ) && break; sleep 0.2; done
( cd "$SOCKETLEY_TMPD" && ping_ok ) || "$BIN" start stp >/dev/null 2>&1
for _ in $(seq 1 50); do ( cd "$SOCKETLEY_TMPD" && ping_ok ) && break; sleep 0.2; done
S4=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PP, KEYS))" )
TOTAL=$((TOTAL+1))
if [ -n "$S3" ] && [ "$S3" = "$S4" ] && grep -q 'replayed .* journaled' "$SOCKETLEY_DLOG"; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [persistence]: the journal did not bring every stream write back after kill -9 (${#S3} vs ${#S4} bytes)"; fi

# ─── 9. A follower holds what its leader holds ──────────────────────────────
"$BIN" create cache stl -p "$PL" -s >/dev/null 2>&1
wait_port "$PL" || { echo "  FATAL: the leader never listened"; exit 2; }
( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; populate($PL)" )
"$BIN" create cache stf -p "$PF" --replicate "127.0.0.1:$PL" -s >/dev/null 2>&1
wait_port "$PF"
sleep 2
L1=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PL, KEYS))" )
F1=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PF, KEYS))" )
TOTAL=$((TOTAL+1))
if [ -n "$L1" ] && [ "$L1" = "$F1" ]; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [replication]: the full sync left the follower's streams different (${#L1} vs ${#F1} bytes)"; fi
( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; more($PL)" )
sleep 1
L2=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PL, KEYS))" )
F2=$( cd "$SOCKETLEY_TMPD" && python3 -c "from sx import *; print(snapshot($PF, KEYS))" )
TOTAL=$((TOTAL+1))
if [ -n "$L2" ] && [ "$L2" = "$F2" ]; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [replication]: the live stream left the follower's streams, groups or pending entries different"; fi
section follower "$PF" <<'PY'
c = Conn(int(sys.argv[1]))
check('a follower refuses a stream write', c('XADD', 'ps', '*', 'a', 'b'), Err('ERR readonly mode'))
check('and XREADGROUP, which writes', c('XREADGROUP', 'GROUP', 'g', 'z', 'STREAMS', 'ps', '>'), Err('ERR readonly mode'))
PY

# ─── 10. Two shards ─────────────────────────────────────────────────────────
"$BIN" create cache sts -p "$PS" --shards 2 --cluster -s >/dev/null 2>&1
wait_port "$PS" || { echo "  FATAL: the sharded cache never listened"; exit 2; }
sleep 1
section shards "$PS" <<'PY'
port = int(sys.argv[1])
c = Conn(port)
# a and c belong to different shards of two; {t} tags put two keys on one.
for k in ('a', 'c', '{t}1', '{t}2'): c('XADD', k, '1-1', 'k', k)
check('each stream reads back from wherever it landed', [c('XRANGE', k, '-', '+')[0][1][1] for k in ('a', 'c')], ['a', 'c'])
check('DBSIZE counts both shards', c('DBSIZE'), 4)
check('XREAD across shards is CROSSSLOT', c('XREAD', 'STREAMS', 'a', 'c', '0', '0'),
      Err("CROSSSLOT Keys in request don't hash to the same slot"))
check('XREAD of one shard\'s keys is served', [s[0] for s in c('XREAD', 'STREAMS', '{t}1', '{t}2', '0', '0')], ['{t}1', '{t}2'])
check('XGROUP is routed by its key, the third word', [c('XGROUP', 'CREATE', k, 'g', '0') for k in ('a', 'c')], ['OK', 'OK'])
check('and so is XINFO', [c('XINFO', 'GROUPS', k)[0][1] for k in ('a', 'c')], ['g', 'g'])
check('XREADGROUP reaches the owner', [c('XREADGROUP', 'GROUP', 'g', 'w', 'STREAMS', k, '>')[0][0] for k in ('a', 'c')], ['a', 'c'])
blocked = [c('XREAD', 'BLOCK', '10', 'STREAMS', k, '$') for k in ('a', 'c')]
truth('a blocking read waits at home and is refused away from it',
      sorted(map(str, blocked)) == sorted(['None', 'ERR a blocking read waits on the shard that owns its streams -- '
                                            'connect to that shard\'s own cluster port to block on them']), blocked)
PY

# The verbs only a record of the cache's own writes carries -- a group's consumers and pending entries -- are not a
# client's: one that typed the record's form made a consumer appear in a group it had never read from.
INJ=$(python3 - "$P" <<'PY'
import socket, sys
port = int(sys.argv[1])
def resp(*a):
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.sendall(("*%d\r\n" % len(a) + "".join("$%d\r\n%s\r\n" % (len(x), x) for x in a)).encode())
    s.settimeout(2); d = b""
    try:
        while True:
            b = s.recv(65536)
            if not b: break
            d += b
            if d.endswith(b"\r\n"): break
    except Exception: pass
    s.close(); return d
resp("XGROUP", "CREATE", "inj", "g", "$", "MKSTREAM")
t = socket.create_connection(("127.0.0.1", port), 5)
t.sendall(b"xapply inj 9:XCONSUMER3:inj1:g4:evil1:01:0\n")
t.settimeout(2)
try: t.recv(4096)
except Exception: pass
t.close()
print("evil" in resp("XINFO", "CONSUMERS", "inj", "g").decode(errors="replace"))
PY
)
TOTAL=$((TOTAL+1))
if [ "$INJ" = False ]; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [a client cannot write a group's consumers through a record's verb]: XINFO showed it (${INJ:-<nothing>})"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
