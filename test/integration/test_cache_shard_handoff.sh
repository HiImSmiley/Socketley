#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: SOCKETLEY_CACHE_HANDOFF hands a connection to the shard that owns its keys, and the connection
# cannot tell.
#
# A cache sharded behind one address relays every command whose key another shard owns.  With the switch on, a
# connection whose single-key commands keep naming one other shard is given to that shard -- the descriptor over the
# mesh link, with what was read and not yet run -- and from then on its commands are served at home.
#
# What each assertion would catch:
#   * split pipeline, 16/16       a handoff that drops or reorders the bytes it had read and not run: each connection
#                                 leaves half a GET behind it when it is handed, and the other half arrives at the
#                                 new shard, which must join them and answer v0 then v39 in order
#   * MULTI after it, 16/16       a connection that was never handed (a transaction naming another shard's key is
#                                 refused CROSSSLOT), or one handed without its protocol state
#   * out == in, > 0              a handoff counted by one side only: a descriptor lost between the shards, or one
#                                 held by both
#   * text protocol, 4/4          the same for a connection speaking the text protocol
#   * one move, not four          a connection alternating between two shards' keys faster than the dwell is moved
#                                 once and then held, where without the hysteresis it ping-pongs on every window
#   * random keys, 0 wrong        a connection that never settles is served exactly as it was
#   * off: unchanged              without the switch nothing is handed: the same split pipeline answers, the MULTI
#                                 on a foreign shard is refused as before, and no handoff figure is printed
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

echo "=== Integration: a sharded cache hands a connection to the shard that owns its keys ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

P=$((SL_PORT_BASE + 1474))
CLIENT=$(mktemp /tmp/skl-handoff-XXXXXX.py)
trap 'rm -f "$CLIENT"; daemon_stop' EXIT

cat > "$CLIENT" <<'PY'
import random, socket, sys, time

port, what = int(sys.argv[1]), sys.argv[2]
SHARDS = 4

def crc16(b):
    crc = 0
    for x in b:
        crc ^= x << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def owner(key):
    k = key.encode()
    i = k.find(b'{')
    if i >= 0:
        j = k.find(b'}', i + 1)
        if j > i + 1:
            k = k[i + 1:j]
    return (crc16(k) % 16384) * SHARDS // 16384

def resp(*a):
    out = b'*%d\r\n' % len(a)
    for x in a:
        x = x.encode()
        out += b'$%d\r\n%s\r\n' % (len(x), x)
    return out

def parse(b):
    i = b.find(b'\r\n')
    if i < 0:
        return None, b
    t, line = b[:1], b[1:i]
    if t in (b'+', b'-', b':'):
        return (t + line).decode(), b[i + 2:]
    if t == b'$':
        n = int(line)
        if n < 0:
            return 'nil', b[i + 2:]
        if len(b) < i + 4 + n:
            return None, b
        return b[i + 2:i + 2 + n].decode(), b[i + 4 + n:]
    if t == b'*':
        rest, items = b[i + 2:], []
        for _ in range(int(line)):
            r, rest = parse(rest)
            if r is None:
                return None, b
            items.append(r)
        return items, rest
    raise ValueError(repr(b[:40]))

class conn:
    def __init__(self):
        self.s = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.buf = b''
    def replies(self, n):
        out = []
        while len(out) < n:
            r, rest = parse(self.buf) if self.buf else (None, self.buf)
            if r is None:
                d = self.s.recv(65536)
                if not d:
                    raise EOFError('closed after %d replies' % len(out))
                self.buf += d
                continue
            out.append(r)
            self.buf = rest
        return out
    def lines(self, n):
        while self.buf.count(b'\n') < n:
            d = self.s.recv(65536)
            if not d:
                raise EOFError('closed')
            self.buf += d
        parts = self.buf.split(b'\n')
        self.buf = b'\n'.join(parts[n:])
        return [p.decode() for p in parts[:n]]

def tag_for(shard, salt):
    i = 0
    while owner('{%s%d}' % (salt, i)) != shard:
        i += 1
    return '{%s%d}' % (salt, i)

def split_resp():
    # Forty writes and half a GET, then -- once the forty are answered and the connection has moved -- the rest.
    good = cross = 0
    for c in range(16):
        tag = '{c%d}' % c
        k = conn()
        g = resp('GET', tag + ':k0')
        k.s.sendall(b''.join(resp('SET', tag + ':k%d' % j, 'v%d' % j) for j in range(40)) + g[:17])
        if k.replies(40) != ['+OK'] * 40:
            continue
        time.sleep(0.3)
        k.s.sendall(g[17:] + resp('GET', tag + ':k39') + resp('MULTI') + resp('SET', tag + ':m', '1') +
                    resp('INCR', tag + ':m') + resp('EXEC'))
        r = k.replies(6)
        if r[:2] == ['v0', 'v39']:
            good += 1
        if r[2:] == ['+OK', '+QUEUED', '+QUEUED', ['+OK', ':2']]:
            cross += 1
        elif not any(isinstance(x, str) and x.startswith('-CROSSSLOT') for x in r[3:5]):
            print('unexpected', tag, r, file=sys.stderr)
        k.s.close()
    print(good, cross)

def split_text():
    good = 0
    for c in range(4):
        tag = '{t%d}' % c
        k = conn()
        k.s.sendall(''.join('set %s:k%d v%d\n' % (tag, j, j) for j in range(40)).encode() + b'get ' + tag[:2].encode())
        if k.lines(40) != ['ok'] * 40:
            continue
        time.sleep(0.3)
        k.s.sendall(tag[2:].encode() + b':k0\nget ' + tag.encode() + b':k39\n')
        if k.lines(2) == ['v0', 'v39']:
            good += 1
        k.s.close()
    print(good)

def pingpong():
    # Four pipelines of 64, alternating between two shards' keys, inside a second.
    a, b = tag_for(1, 'pa'), tag_for(2, 'pb')
    k, wrong = conn(), 0
    for rnd, tag in enumerate((a, b, a, b)):
        k.s.sendall(b''.join(resp('SET', '%s:%d' % (tag, j), '%d.%d' % (rnd, j)) for j in range(64)))
        wrong += sum(1 for r in k.replies(64) if r != '+OK')
    k.s.sendall(b''.join(resp('GET', '%s:%d' % (b, j)) for j in range(64)))
    wrong += sum(1 for j, r in enumerate(k.replies(64)) if r != '3.%d' % j)
    print(wrong)

def randomkeys():
    k, wrong, rng = conn(), 0, random.Random(7)
    for rnd in range(20):
        keys = ['r:%d' % rng.randrange(100000) for _ in range(32)]
        k.s.sendall(b''.join(resp('SET', key, '%s.%d' % (key, rnd)) for key in keys))
        wrong += sum(1 for r in k.replies(32) if r != '+OK')
        k.s.sendall(b''.join(resp('GET', key) for key in keys))
        last = {key: '%s.%d' % (key, rnd) for key in keys}
        wrong += sum(1 for key, r in zip(keys, k.replies(32)) if r != last[key])
    print(wrong)

{'resp': split_resp, 'text': split_text, 'pingpong': pingpong, 'random': randomkeys}[what]()
PY

client() { timeout 60 python3 -I "$CLIENT" "$P" "$1" 2>&1 | tail -1; }
figure() { "$BIN" stats ho 2>/dev/null | awk -F: -v f="$1" '$1==f {s+=$2; n++} END{print (n ? s+0 : "absent")}'; }
start_cache() {
    "$BIN" create cache ho -p "$P" --shards 4 -s >/dev/null 2>&1 || bad "a cache of four shards is made"
    for _ in $(seq 1 80); do
        python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$P),timeout=1);s.sendall(b'*1\r\n\$4\r\nPING\r\n');s.recv(64)" 2>/dev/null && break
        sleep 0.25
    done
}

# ─── the switch on ─────────────────────────────────────────────────────────
daemon_isolate cachehandoff
SOCKETLEY_CACHE_HANDOFF=1 daemon_start "$BIN"
start_cache

read -r GOOD CROSS < <(client resp)
check "a split pipeline answers in order across the handoff" "${GOOD:-?}" "16"
check "and a MULTI on each connection then runs at the owner" "${CROSS:-?}" "16"
sleep 3
OUT=$(figure handoff_out); IN=$(figure handoff_in)
if [[ "$OUT" =~ ^[0-9]+$ ]] && [ "$OUT" -gt 0 ] && [ "$OUT" = "$IN" ]; then
    ok "every connection handed out was taken in ($OUT out, $IN in)"
else
    bad "every connection handed out was taken in: out=$OUT in=$IN"
fi
check "no handoff was given up" "$(figure handoff_aborted)" "0"

check "the text protocol answers across the handoff" "$(client text)" "4"

BEFORE=$(figure handoff_out)
check "a connection alternating between two shards' keys is answered right" "$(client pingpong)" "0"
sleep 3
check "and is moved once, then held" "$(( $(figure handoff_out) - BEFORE ))" "1"

check "random keys are answered right" "$(client random)" "0"
"$BIN" stop ho >/dev/null 2>&1; sleep 0.3; "$BIN" remove ho >/dev/null 2>&1
daemon_stop

# ─── the switch off ────────────────────────────────────────────────────────
daemon_isolate cachehandoffoff
unset SOCKETLEY_CACHE_HANDOFF
daemon_start "$BIN"
start_cache
read -r GOOD CROSS < <(client resp)
check "off: the split pipeline still answers in order" "${GOOD:-?}" "16"
if [[ "${CROSS:-}" =~ ^[0-9]+$ ]] && [ "$CROSS" -lt 16 ]; then
    ok "off: a MULTI on a foreign shard is still refused ($CROSS of 16 ran)"
else
    bad "off: a MULTI on a foreign shard is still refused: ${CROSS:-?} of 16 ran"
fi
sleep 3
check "off: no handoff figure is printed" "$(figure handoff_out)" "absent"
check "off: random keys are answered right" "$(client random)" "0"
"$BIN" stop ho >/dev/null 2>&1; sleep 0.3; "$BIN" remove ho >/dev/null 2>&1

echo "  Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
