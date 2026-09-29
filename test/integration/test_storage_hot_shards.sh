#!/usr/bin/env bash
# Integration test: with --shards 4 every shard answers a small object from memory, and none answers old bytes
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A GET of a small object is answered from a copy in memory by whichever shard
# the connection landed on, not only by the key's owner.  A shard that is not
# the owner has no index entry to compare a copy with, so the owner tells every
# sibling to drop a key before it answers the commit or the delete that changed
# it, and a read that a drop arrived during is not kept.  Connections are kept
# open and many, so each shard (the kernel's choice) serves some of them, and a
# copy that outlives its version shows as one connection answering old bytes.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the copy kept only by the owner (some shard has no hot_gets at all, or
#     fewer than half the repeated GETs are answered from memory)
#   * the owner not telling its siblings (an overwrite, a copy onto the key, a
#     multipart completion or a delete leaves some connection answering the
#     previous version, or 200 after the delete)
#   * the drop not waited for, or a read of the old file kept after the drop
#     (a storm of PUTs and GETs on one key: a body that does not match its
#     ETag, or a final GET on any connection that is not the last PUT)
#   * a sibling's drop not being served (shard_hot_drops_sent is not
#     shard_hot_drops_served)
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: every shard answers a hot small object from memory, and never a stale one ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

daemon_isolate stghots
WORK=$(mktemp -d /tmp/socketley-stghots-work-XXXXXX)
daemon_watch "$WORK"
trap 'daemon_stop; rm -rf "$WORK"' EXIT
PORT=$((SL_PORT_BASE + 1843))

cat >"$WORK/hot.py" <<'PY'
import hashlib, http.client, os, re, sys, threading, time
port, mode = int(sys.argv[1]), sys.argv[2]
N = 64

def req(c, method, path, body=None, headers=None):
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse(); data = r.read()
    return r.status, r.getheader("ETag", "").strip('"'), data

def pool(n=N):
    return [http.client.HTTPConnection("127.0.0.1", port, timeout=20) for _ in range(n)]

out = []
cs = pool()
req(cs[0], "PUT", "/hotb")

def stale(want, key="/hotb/k"):
    # How many of the connections, and so of the shards, answer anything but `want`.
    n = 0
    for c in cs:
        s, e, d = req(c, "GET", key)
        if want is None:
            n += s != 404
        else:
            n += not (s == 200 and d == want)
    return n

if mode == "basic":
    v = b"a" * 3000
    req(cs[0], "PUT", "/hotb/k", v)
    for _ in range(3):
        bad = stale(v)
    out.append("warm %d" % bad)
    # An overwrite through a different connection each time, every connection read before and after.
    total = 0
    for i in range(6):
        v = bytes([98 + i]) * (2000 + i)
        s, e, d = req(cs[(i * 13 + 5) % N], "PUT", "/hotb/k", v)
        assert s == 200, s
        total += stale(v)
        stale(v); stale(v)
    out.append("overwrite %d" % total)
    # A copy onto the key.
    total = 0
    for i in range(3):
        src = bytes([120 + i]) * 2500
        req(cs[i], "PUT", "/hotb/src", src)
        s, e, d = req(cs[(i * 7 + 3) % N], "PUT", "/hotb/k", headers={"x-amz-copy-source": "/hotb/src"})
        assert s == 200, s
        total += stale(src)
        stale(src); stale(src)
    out.append("copy %d" % total)
    # A multipart completion of one small part onto the key.
    total = 0
    for i in range(3):
        body = bytes([65 + i]) * 1800
        s, e, d = req(cs[i + 20], "POST", "/hotb/k?uploads")
        uid = re.search(rb"<UploadId>([^<]+)</UploadId>", d).group(1).decode()
        s, pe, d = req(cs[i + 21], "PUT", "/hotb/k?partNumber=1&uploadId=" + uid, body)
        assert s == 200, s
        xml = ("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"%s\"</ETag></Part>"
               "</CompleteMultipartUpload>" % pe).encode()
        s, e, d = req(cs[i + 22], "POST", "/hotb/k?uploadId=" + uid, xml)
        assert s == 200, (s, d)
        total += stale(body)
        stale(body); stale(body)
    out.append("mpu %d" % total)
    # A delete, and then the key again, each read on every connection.
    total = 0
    for i in range(4):
        v = bytes([100 + i]) * 1500
        req(cs[i], "PUT", "/hotb/k", v)
        stale(v); stale(v)
        s, e, d = req(cs[(i * 11 + 9) % N], "DELETE", "/hotb/k")
        assert s == 204, s
        total += stale(None)
    out.append("delete %d" % total)
elif mode == "storm":
    # Each body starts with its version, and a reader that began after version v was answered must not be given an older one.
    stop = False; bad = [0]; last = [None]; lock = threading.Lock(); reads = [0]; older = [0]
    ver = [0]; acked = [0]
    def w(c):
        while not stop:
            with lock:
                ver[0] += 1
                body = ver[0].to_bytes(8, "big") + os.urandom(2000)
                s, e, d = req(c, "PUT", "/hotb/storm", body)
                if s == 200:
                    last[0] = body
                    acked[0] = ver[0]
    def r(c):
        while not stop:
            floor = acked[0]
            s, e, d = req(c, "GET", "/hotb/storm")
            reads[0] += 1
            if s == 200 and hashlib.md5(d).hexdigest() != e: bad[0] += 1
            if s == 200 and int.from_bytes(d[:8], "big") < floor: older[0] += 1
            if s not in (200, 404): bad[0] += 1
    ts = [threading.Thread(target=w, args=(cs[i],)) for i in range(2)] + \
         [threading.Thread(target=r, args=(cs[i],)) for i in range(2, 50)]
    [t.start() for t in ts]
    time.sleep(8); stop = True; [t.join() for t in ts]
    finals = sum(req(c, "GET", "/hotb/storm")[2] != last[0] for c in cs)
    out.append("storm mismatched %d older %d reads %d finalstale %d" % (bad[0], older[0], reads[0], finals))
print(" | ".join(out))
PY

# Sums a counter over the shard sections, and counts the sections in which it is above zero.
stat_sum(){ "$BIN" stats st 2>/dev/null | awk -F: -v k="$1" '$1==k{s+=$2} END{print s+0}'; }
stat_shards_with(){ "$BIN" stats st 2>/dev/null | awk -F: -v k="$1" '$1==k && $2>0{c++} END{print c+0}'; }

daemon_start "$BIN"
"$BIN" create storage st -p "$PORT" --dir "$SOCKETLEY_TMPD/data" --anonymous --shards 4 -s >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break; sleep 0.1; done

R=$(python3 "$WORK/hot.py" "$PORT" basic 2>&1) || true
# The workers publish their counters periodically, so wait until the GETs are counted.
for _ in $(seq 1 40); do [ "$(stat_sum gets)" -ge 1000 ] 2>/dev/null && break; sleep 0.25; done
G=$(stat_sum gets); H=$(stat_sum hot_gets); S=$(stat_shards_with hot_gets)
if [ "${S:-0}" = 4 ]; then pass
else fail "every shard" "each of the four shards answers some GETs from memory" "shards with hot_gets>0: ${S:-?} of 4, hot_gets=$H gets=$G probe: $R"; fi
if [ "${H:-0}" -ge $((G / 2)) ] 2>/dev/null; then pass
else fail "used" "most repeated GETs are answered from memory, not one in four" "hot_gets=$H of gets=$G probe: $R"; fi
for name in warm overwrite copy mpu delete; do
    if grep -Eq "(^| )$name 0( |$)" <<<"$R"; then pass
    else fail "$name" "once a change is answered, every connection on every shard sees it" "probe: $R"; fi
done

R=$(python3 "$WORK/hot.py" "$PORT" storm 2>&1) || true
[ -z "${VERBOSE:-}" ] || echo "  storm: $R"
if grep -q 'storm mismatched 0 older 0 reads [0-9]* finalstale 0' <<<"$R"; then pass
else fail "storm" "PUTs and GETs racing on one key never answer bytes of another version or an older one than was answered before the GET began, and every shard ends on the last PUT" "probe: $R"; fi

# The counters are published periodically, so the two sums agree once both have been.
for _ in $(seq 1 40); do
    SENT=$(stat_sum shard_hot_drops_sent); SERVED=$(stat_sum shard_hot_drops_served)
    [ "$SENT" = "$SERVED" ] && break
    sleep 0.25
done
if [ "${SENT:-0}" -gt 0 ] && [ "$SENT" = "$SERVED" ]; then pass
else fail "drops" "every drop the owners sent was served by a sibling" "sent=${SENT:-?} served=${SERVED:-?}"; fi

"$BIN" stop st >/dev/null; "$BIN" remove st >/dev/null
daemon_stop; daemon_isolate stghots
SOCKETLEY_STORAGE_HOT_BYTES=0 daemon_start "$BIN"
"$BIN" create storage st -p "$PORT" --dir "$SOCKETLEY_TMPD/data" --anonymous --shards 4 -s >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break; sleep 0.1; done
R=$(python3 "$WORK/hot.py" "$PORT" basic 2>&1) || true
for _ in $(seq 1 40); do [ "$(stat_sum gets)" -ge 1000 ] 2>/dev/null && break; sleep 0.25; done
H=$(stat_sum hot_gets)
if [ "${H:-x}" = 0 ] && grep -Eq "(^| )overwrite 0( |$)" <<<"$R"; then pass
else fail "off" "SOCKETLEY_STORAGE_HOT_BYTES=0 keeps nothing on any shard" "hot_gets=${H:-?} probe: $R"; fi


"$BIN" stop st >/dev/null; "$BIN" remove st >/dev/null
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ]
