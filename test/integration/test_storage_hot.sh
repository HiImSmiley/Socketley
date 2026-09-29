#!/usr/bin/env bash
# Integration test: hot small objects are answered from memory, and never stale
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A GET of a small object a shard owns is answered from a copy in memory once
# it has been read, so the file is neither opened nor read again.  A copy that
# outlives its version would answer old bytes with no error anywhere, so every
# assertion here is about staleness as much as about the copy being used.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the copy never used (hot_gets stays 0 after repeated GETs)
#   * an overwrite, a copy onto the key or a delete leaving the old bytes in
#     memory (the next GET answers the previous version, or 200 after a delete)
#   * a copy outliving its version under load (a storm of PUTs and GETs on one
#     key: a body that does not match its ETag, or a final GET that does not
#     answer the last PUT); the read that races a commit is too narrow a window
#     to hit from here and is pinned in test_object_store instead
#   * SOCKETLEY_STORAGE_HOT_BYTES=0 not turning it off
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: hot small objects are answered from memory, and never stale ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

daemon_isolate stghot
# The probe outlives each daemon's TMPD, which daemon_stop deletes.
WORK=$(mktemp -d /tmp/socketley-stghot-work-XXXXXX)
daemon_watch "$WORK"
trap 'daemon_stop; rm -rf "$WORK"' EXIT
PORT=$((SL_PORT_BASE + 1841))

cat >"$WORK/hot.py" <<'PY'
import hashlib, http.client, os, sys, threading
port, mode = int(sys.argv[1]), sys.argv[2]
def req(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, r.getheader("ETag", "").strip('"'), data
out = []
req("PUT", "/hotb")
if mode == "basic":
    req("PUT", "/hotb/k", b"a" * 3000)
    for _ in range(3): s, e, d = req("GET", "/hotb/k")
    out.append("first %d %d" % (s, d == b"a" * 3000))
    req("PUT", "/hotb/k", b"b" * 3000)
    s, e, d = req("GET", "/hotb/k"); out.append("overwrite %d %d" % (s, d == b"b" * 3000))
    req("PUT", "/hotb/src", b"c" * 3000)
    req("PUT", "/hotb/k", headers={"x-amz-copy-source": "/hotb/src"})
    s, e, d = req("GET", "/hotb/k"); out.append("copy %d %d" % (s, d == b"c" * 3000))
    req("DELETE", "/hotb/k")
    s, e, d = req("GET", "/hotb/k"); out.append("delete %d" % s)
else:
    stop = False; bad = [0]; last = [None]; lock = threading.Lock()
    def w():
        while not stop:
            body = os.urandom(2000)
            with lock:
                s, e, d = req("PUT", "/hotb/storm", body)
                if s == 200: last[0] = body
    def r():
        while not stop:
            s, e, d = req("GET", "/hotb/storm")
            if s == 200 and hashlib.md5(d).hexdigest() != e: bad[0] += 1
    ts = [threading.Thread(target=w) for _ in range(2)] + [threading.Thread(target=r) for _ in range(6)]
    [t.start() for t in ts]
    import time; time.sleep(4); stop = True; [t.join() for t in ts]
    finals = [req("GET", "/hotb/storm")[2] == last[0] for _ in range(5)]
    out.append("storm mismatched %d final %d" % (bad[0], all(finals)))
print(" | ".join(out))
PY

# The worker publishes its counters periodically, so wait until the GETs are counted.
hot_gets(){
    local s
    for _ in $(seq 1 30); do
        s=$("$BIN" stats st)
        [ "$(awk -F: '$1=="gets"{print $2}' <<<"$s")" -ge "$1" ] 2>/dev/null && break
        sleep 0.2
    done
    awk -F: '$1=="hot_gets"{print $2}' <<<"$s"
}

daemon_start "$BIN"
"$BIN" create storage st -p "$PORT" --dir "$SOCKETLEY_TMPD/data" --anonymous -s >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break; sleep 0.1; done

R=$(python3 "$WORK/hot.py" "$PORT" basic)
H=$(hot_gets 6)
if [ "${H:-0}" -ge 2 ] && grep -q 'first 200 1' <<<"$R"; then pass
else fail "used" "repeated GETs of a small object are answered from memory" "hot_gets=${H:-?} probe: $R"; fi
if grep -q 'overwrite 200 1' <<<"$R"; then pass
else fail "overwrite" "a GET after an overwrite answers the new bytes" "probe: $R"; fi
if grep -q 'copy 200 1' <<<"$R"; then pass
else fail "copy" "a GET after a copy onto the key answers the copied bytes" "probe: $R"; fi
if grep -q 'delete 404' <<<"$R"; then pass
else fail "delete" "a GET after a delete is NoSuchKey" "probe: $R"; fi

R=$(python3 "$WORK/hot.py" "$PORT" storm)
if grep -q 'storm mismatched 0 final 1' <<<"$R"; then pass
else fail "storm" "PUTs and GETs racing on one key never answer bytes of another version, and end on the last PUT" "probe: $R"; fi

"$BIN" stop st >/dev/null; "$BIN" remove st >/dev/null
daemon_stop; daemon_isolate stghot
SOCKETLEY_STORAGE_HOT_BYTES=0 daemon_start "$BIN"
"$BIN" create storage st -p "$PORT" --dir "$SOCKETLEY_TMPD/data" --anonymous -s >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break; sleep 0.1; done
python3 "$WORK/hot.py" "$PORT" basic >/dev/null
H=$(hot_gets 6)
if [ "${H:-x}" = 0 ]; then pass
else fail "off" "SOCKETLEY_STORAGE_HOT_BYTES=0 keeps nothing" "hot_gets=${H:-?}"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ]
