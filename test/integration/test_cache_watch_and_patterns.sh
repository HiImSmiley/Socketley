#!/usr/bin/env bash
# Integration test: WATCH, and pattern subscriptions.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE TRANSACTION THAT COMMITS OVER SOMEBODY ELSE.  Without WATCH, MULTI here
#   is a batch: the commands run together and nothing checks that the world
#   still looks the way the client read it.  The guarantee is one sentence --
#   EXEC does nothing if a watched key was written between the WATCH and the
#   EXEC -- and it is what makes a compare-and-set retry loop possible.
#
#   The dirty mark is set at ONE place, before the switch that runs the
#   command, and it is driven by a list of READ-ONLY commands rather than a
#   list of writes.  That direction is deliberate: a write missing from a list
#   of writes is a transaction committing over a change it never saw, silently.
#   A read missing from the read list is one retry too many.  So the test
#   checks both directions -- that a write to the watched key aborts, and that
#   a write to a DIFFERENT key does not, which is the half that a
#   dirty-everything implementation would fail.
#
#   THE CONFIRMATION NOBODY COULD COUNT.  SUBSCRIBE answered "+OK".  Redis
#   answers a three-element array naming the verb, the channel and how many
#   subscriptions the connection now holds -- and a client library counts down
#   from that number to know its own batch is complete.  Against "+OK" it
#   waits for ever.  Found while adding PSUBSCRIBE, which inherited it.
#
#   AND THE FILTER PATTERNS CANNOT USE.  A publish only wakes the shards whose
#   filter says they may hold a subscriber of that channel.  A pattern matches
#   channels that do not exist yet, so it has no bit to set -- a shard holding
#   one is woken by every publish instead, which is the cost, and it is paid
#   only by a cache that has one.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: WATCH and pattern subscriptions ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

P=$((SL_PORT_BASE+1431))
daemon_isolate cachewatch
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache wp_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

PY=$SOCKETLEY_TMPD/wp.py
cat > "$PY" <<'PYEOF'
import socket, sys, time, threading, json
def enc(c):
    p=('*%d\r\n'%len(c)).encode()
    for a in c: p+=('$%d\r\n%s\r\n'%(len(a),a)).encode()
    return p
def conn(port): return socket.create_connection(('127.0.0.1',port),timeout=6)
def send(s,*cs,wait=1.0):
    for c in cs: s.sendall(enc(c))
    s.settimeout(wait); o=b''
    try:
        while True:
            x=s.recv(65536)
            if not x: break
            o+=x
    except socket.timeout: pass
    return o.decode('latin1')

mode, port = sys.argv[1], int(sys.argv[2])

if mode == 'watch':
    a, b = conn(port), conn(port)
    out = {}
    send(a,['DEL','k','other'],['SET','k','1'])
    # undisturbed
    send(a,['WATCH','k']); send(a,['MULTI'],['SET','k','2'])
    out['clean'] = send(a,['EXEC']); out['clean_val'] = send(a,['GET','k'])
    # a foreign writer between WATCH and EXEC
    send(a,['SET','k','1']); send(a,['WATCH','k']); send(a,['MULTI'],['SET','k','3'])
    send(b,['SET','k','fremd'])
    out['dirty'] = send(a,['EXEC']); out['dirty_val'] = send(a,['GET','k'])
    # a write to a DIFFERENT key must not abort
    send(a,['SET','k','1']); send(a,['WATCH','k'])
    send(b,['SET','other','x'])
    send(a,['MULTI'],['SET','k','5'])
    out['other'] = send(a,['EXEC']); out['other_val'] = send(a,['GET','k'])
    # UNWATCH lifts it
    send(a,['SET','k','1']); send(a,['WATCH','k']); send(a,['UNWATCH'])
    send(b,['SET','k','egal'])
    send(a,['MULTI'],['SET','k','6'])
    out['unwatched'] = send(a,['EXEC'])
    # A write that cannot name its keys must abort every watcher.  MSET, a
    # multi-key DEL and EVAL all land in the pessimistic branch, and that
    # branch walks the watchERS rather than the watched KEYS -- so it is the
    # one that a wrong reverse index breaks, silently and in the direction
    # that loses a write.
    for tag, cmd in (('mset',   ['MSET','p','1','q','2']),
                     ('multidel',['DEL','p','q']),
                     ('eval',   ['EVAL','return 1','0'])):
        send(a,['SET','k','1']); send(a,['WATCH','k']); send(a,['MULTI'],['SET','k','X'])
        send(b,cmd)
        out['pess_' + tag] = send(a,['EXEC'])
    # and it must still be precise about the watcher who left in the meantime
    send(a,['UNWATCH'])
    # a watcher that leaves takes its watch with it
    c = conn(port); send(c,['SET','k','1'],['WATCH','k']); c.close()
    out['after_close'] = send(a,['SET','k','9'])
    # a client that watched a great many keys and then left must not leave the
    # index holding its descriptor -- the close path reads the key list from
    # the connection now rather than walking the whole map
    d = conn(port); d.sendall(b''.join(enc(['WATCH','m:%d' % i]) for i in range(5000)))
    time.sleep(0.4); d.close(); time.sleep(0.3)
    send(a,['SET','k','1']); send(a,['WATCH','k']); send(a,['MULTI'],['SET','k','Z'])
    out['after_bulk_close'] = send(a,['EXEC'])
    a.close(); b.close()
    print(json.dumps(out))

elif mode == 'patterns':
    got=[b'']
    def sub():
        s=conn(port)
        s.sendall(enc(['SUBSCRIBE','exakt'])+enc(['PSUBSCRIBE','news.*'])+enc(['PSUBSCRIBE','a?c']))
        s.settimeout(3)
        try:
            while True:
                x=s.recv(65536)
                if not x: break
                got[0]+=x
                if b'letzte' in got[0]: break
        except socket.timeout: pass
        s.close()
    t=threading.Thread(target=sub); t.start(); time.sleep(0.5)
    c=conn(port)
    for ch,msg in (('exakt','direkt'),('news.de','hallo'),('sport.de','WEG'),
                   ('abc','glob'),('axxc','WEG2'),('news.en','letzte')):
        c.sendall(enc(['PUBLISH',ch,msg])); time.sleep(0.15)
    c.close(); t.join()
    print(json.dumps(got[0].decode('latin1')))

elif mode == 'repeat':
    # 200,000 WATCHes of ONE key, and then 200,000 of DISTINCT keys, and the
    # answer is the RATIO of what each cost.
    #
    # An absolute threshold on the one-key figure is what this was, and it does
    # not survive a second allocator: it read +0 kB alone and +3944 kB inside
    # the full suite under the sanitizer, on the same binary, because RSS counts
    # RESIDENT PAGES and the 200k commands still allocate for parsing and
    # replies whether or not a watch is retained.  Under memory pressure those
    # pages are reclaimed and faulted back and the number grows with nothing
    # retained at all.
    #
    # The distinct-key burst is the control: it is the same command, the same
    # count and the same churn, with 200,000 entries actually kept.  Whatever
    # the allocator charges for the churn it charges to both, so the difference
    # is the retention -- which is the thing this test is about.
    #
    # ONE KEY FIRST, and not the other way round: the distinct burst leaves the
    # allocator holding blocks it has freed, and a one-key burst run afterwards
    # would be served out of that pool without growing RSS -- passing whether or
    # not the dedupe works.
    def rss(pid):
        with open('/proc/%s/status' % pid) as f:
            for ln in f:
                if ln.startswith('VmRSS'): return int(ln.split()[1])
        return -1

    def burst(keyfn, n):
        # The reading is taken with the connection still OPEN, because the
        # watch set is freed on close and a reading taken afterwards would
        # measure nothing and pass either way.
        s = conn(port)
        seen = 0; sent = 0
        while sent < n:
            s.sendall(b''.join(enc(['WATCH', keyfn(sent + i)]) for i in range(1000)))
            sent += 1000
            s.settimeout(4)
            try:
                while True:
                    x = s.recv(1 << 20)
                    if not x: break
                    seen += x.count(b'+OK')
                    if seen >= sent: break
            except socket.timeout: break
        return s, seen

    wpid = sys.argv[3]
    r0 = rss(wpid)
    sa, acked = burst(lambda i: 'einer', 200000)
    ra = rss(wpid)
    sa.close(); time.sleep(0.3)
    rb0 = rss(wpid)
    sb, acked_many = burst(lambda i: 'viele:%d' % i, 200000)
    rb = rss(wpid)
    sb.close()
    print(json.dumps({'acked': acked, 'acked_many': acked_many,
                      'grew_one': ra - r0, 'grew_many': rb - rb0}))

elif mode == 'punsub':
    s=conn(port)
    r1=send(s,['PSUBSCRIBE','x.*'])
    r2=send(s,['PUNSUBSCRIBE','x.*'])
    c=conn(port); send(c,['PUBLISH','x.1','danach']); c.close()
    r3=send(s,[' PING'.strip()],wait=1.0)
    s.close(); print(json.dumps([r1,r2,r3]))
PYEOF
py() { python3 "$PY" "$1" "$P" 2>/dev/null; }
val() { python3 -c "import json,sys;print(json.load(sys.stdin).get('$1',''))"; }

echo "--- 1. WATCH: the guarantee, and its precision ---"
W=$(py watch)
case "$(printf '%s' "$W" | val clean)" in *'+OK'*) ok "an undisturbed transaction runs" ;;
    *) bad "clean" "EXEC did not run" "got: $(printf '%s' "$W" | val clean)" ;; esac
case "$(printf '%s' "$W" | val clean_val)" in *2*) ok "and its write took" ;;
    *) bad "clean" "value wrong" ;; esac
# A nil ARRAY, not a nil string: the type is how a client tells "did not run"
# from "ran and returned nothing".
case "$(printf '%s' "$W" | val dirty)" in *'*-1'*) ok "a foreign write aborts it" ;;
    *) bad "dirty" "EXEC did not abort" "got: $(printf '%s' "$W" | val dirty)" ;; esac
case "$(printf '%s' "$W" | val dirty_val)" in *fremd*) ok "and the foreign value survived" ;;
    *) bad "dirty" "the aborted transaction wrote anyway" ;; esac
# The half a dirty-everything implementation fails.
case "$(printf '%s' "$W" | val other)" in *'+OK'*) ok "a write to another key does NOT abort" ;;
    *) bad "precision" "aborted on an unrelated key" "got: $(printf '%s' "$W" | val other)" ;; esac
case "$(printf '%s' "$W" | val other_val)" in *5*) ok "and that transaction's write took" ;;
    *) bad "precision" "value wrong" ;; esac
case "$(printf '%s' "$W" | val unwatched)" in *'+OK'*) ok "UNWATCH lifts the watch" ;;
    *) bad "unwatch" "still aborted" ;; esac
case "$(printf '%s' "$W" | val after_close)" in *'+OK'*) ok "a watcher that disconnects leaves nothing behind" ;;
    *) bad "close" "a write after a watcher left did not work" ;; esac
for T in mset multidel eval; do
    case "$(printf '%s' "$W" | val "pess_$T")" in *'*-1'*) ok "a $T the watcher could not see aborts it" ;;
        *) bad "pessimistic" "$T did not abort a watching transaction" \
               "got: $(printf '%s' "$W" | val "pess_$T")" ;; esac
done
case "$(printf '%s' "$W" | val after_bulk_close)" in *'+OK'*) ok "5000 watches left with their client" ;;
    *) bad "close" "a departed bulk watcher still aborts other transactions" ;; esac

echo "--- 2. the confirmation a client counts down from ---"
P1=$(py patterns)
case "$P1" in *'$9'*subscribe*':1'*) ok "subscribe confirms with a count" ;;
    *) bad "confirm" "no subscribe confirmation" "got: ${P1:0:120}" ;; esac
case "$P1" in *psubscribe*':2'*) ok "and psubscribe counts on from it" ;;
    *) bad "confirm" "count did not include the pattern" "got: ${P1:0:160}" ;; esac

echo "--- 3. patterns match, and only what they match ---"
case "$P1" in *pmessage*news.de*hallo*) ok "a glob pattern delivers" ;;
    *) bad "pattern" "news.de did not arrive" ;; esac
case "$P1" in *pmessage*abc*glob*) ok "and ? matches one character" ;;
    *) bad "pattern" "a?c did not match abc" ;; esac
case "$P1" in *WEG*) bad "pattern" "a channel that matches nothing was delivered" ;;
    *) ok "a channel matching no pattern is not delivered" ;; esac
case "$P1" in *'$7'*message*exakt*direkt*) ok "an exact subscription still works beside them" ;;
    *) bad "mixed" "the exact channel did not arrive" ;; esac

echo "--- 4. punsubscribe stops the delivery ---"
U=$(py punsub)
case "$U" in *punsubscribe*) ok "punsubscribe confirms" ;;
    *) bad "punsub" "no confirmation" "got: ${U:0:120}" ;; esac
case "$U" in *danach*) bad "punsub" "a message arrived after unsubscribing" ;;
    *) ok "and nothing arrives afterwards" ;; esac

echo "--- 5. WATCHing one key twice is one watch ---"
# Redis dedupes a client's watched keys; without that, every WATCH appends and
# a connection that watches without ever reaching EXEC grows without bound.
# Measured at 300k WATCHes of one key: 22232 -> 29732 kB here against 8592 ->
# 8600 in Redis.  The dedupe costs nothing because the set insert already
# answers "was this connection watching this key" -- no scan.
WPID=$(ss -ltnp 2>/dev/null | sed -n "s/.*:$P .*pid=\([0-9]*\).*/\1/p" | head -1)
if [ -z "$WPID" ] || [ ! -r "/proc/$WPID/status" ]; then
    ok "SKIP growth check: no readable pid for port $P"
else
    REP=$(python3 "$PY" repeat "$P" "$WPID" 2>/dev/null)
    case "$REP" in *'"acked": 200000'*|*'"acked":200000'*) ok "200k repeated WATCHes all answered" ;;
        *) bad "repeat" "not every WATCH was answered" "got: ${REP:0:80}" ;; esac
    ONE=$(printf '%s' "$REP" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("grew_one",99999))' 2>/dev/null || echo 99999)
    MANY=$(printf '%s' "$REP" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("grew_many",0))' 2>/dev/null || echo 0)
    # The ratio and not either number on its own.  200,000 distinct keys are
    # what 200,000 retained watches cost in whatever allocator is running, and
    # one key deduped should cost a small fraction of it; both bursts pay the
    # same parsing and reply churn, so it cancels.  Four is a wide margin --
    # measured, the two differ by more than an order of magnitude -- and a
    # margin this wide is what makes the check mean the same thing in Release
    # and under the sanitizer, which an absolute threshold did not.
    if [ "$MANY" -lt 1024 ]; then
        ok "SKIP growth check: the control burst grew only ${MANY} kB, so there is no scale to read against"
    elif [ "$((ONE * 4))" -lt "$MANY" ]; then
        ok "and held one entry, not 200000 (one key +${ONE} kB against +${MANY} kB for distinct keys)"
    else
        bad "repeat" "watched keys accumulate" \
            "one key grew ${ONE} kB and 200k distinct keys grew ${MANY} kB -- deduped they should differ by much more"
    fi
fi
# The guarantee must survive all that repetition.
W2=$(py watch)
case "$(printf '%s' "$W2" | val dirty)" in *'*-1'*) ok "and the abort still works afterwards" ;;
    *) bad "repeat" "WATCH stopped aborting after the repeats" ;; esac

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
