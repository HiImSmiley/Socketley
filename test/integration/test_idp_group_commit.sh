#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: an idp's account changes are synced as a group off its loop, and folded into its snapshot while
# commits go on, without losing one.
#
# What each part would catch:
#   * a sync per change on the loop: a read beside refreshes waited behind every one of them, 50 ms at the median
#   * the changes committed while a compaction ran left out of the journal that replaces the old one: after a
#     restart the refresh tokens they issued are unknown, and the ones they replaced are good again
#
# How the waiting is measured: a reader in a process of its own asks /jwks over and over while the refreshes go on,
# and a second process syncs a page of the same file system over and over, which says what a sync of this disk takes
# just then.  A read that waited behind a sync took at least one, so what is held is the share of the reader's time
# spent in reads that long (5 ms where the disk is faster), under a quarter.  With the syncs put back on the loop it
# was 66% (a reader stuck behind syncs makes one slow read, then many fast ones while the loop is free, so its median
# stayed under a millisecond); with them off it, 0-6% with eight busy loops beside the test.  The worst single read,
# which this test held to 40 ms before, is the box's: 35-240 ms under that load with the syncs off the loop.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an idp syncs its account changes as a group, and compacts while they go on ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate idpgroup
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1926))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
# A compaction every ten changes, so an account's last change comes while one is under way -- in three runs of four
# with nothing after it, which is the case the fresh journal's tail decides, and so three rounds.
SOCKETLEY_IDP_COMPACT_AFTER=10 daemon_start "$BIN"
printf 'wiki wikisecret http://127.0.0.1:9/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$P" --clients "$T/clients" --issuer "http://127.0.0.1:$P" -s >/dev/null 2>&1
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$P/jwks" && break; sleep 0.1; done
for i in $(seq 1 8); do "$BIN" idp-user auth add "u$i" --password "u${i}password1" >/dev/null 2>&1; done

cat > "$T/flow.py" <<'PY'
import base64, http.client, json, os, subprocess, sys, threading, time, urllib.parse
port, mode, path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
CB = "http://127.0.0.1:9/cb"; basic = "Basic " + base64.b64encode(b"wiki:wikisecret").decode()
def req(method, p, form=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    h = {"Authorization": basic, "Content-Type": "application/x-www-form-urlencoded"} if form else {}
    c.request(method, p, body=urllib.parse.urlencode(form) if form else None, headers=h)
    r = c.getresponse(); d = r.read(); c.close(); return r.status, d, dict(r.getheaders())
refresh = lambda t: req("POST", "/token", dict(grant_type="refresh_token", refresh_token=t))
def median(v):
    v = sorted(v); return v[len(v) // 2] if v else 0.0
if mode == "probe":
    # Its own process, so what it times is the provider and not this interpreter's lock, which eight rotating threads
    # beside it hold in turn: on a loaded box a probe among them measured itself into the worst it reported.
    out = []; t0 = time.perf_counter()
    while not os.path.exists(path + ".stop"):
        t = time.perf_counter(); req("GET", "/jwks"); out.append((time.perf_counter() - t) * 1000)
        time.sleep(0.003)
    json.dump({"reads": out, "ms": (time.perf_counter() - t0) * 1000}, open(path, "w"))
elif mode == "syncs":
    # What a sync of this disk takes while the refreshes go on: a page written and synced, again and again, in a file
    # beside the provider's, on the same file system.
    out = []
    fd = os.open(path + ".page", os.O_WRONLY | os.O_CREAT, 0o600)
    while not os.path.exists(path + ".stop"):
        os.pwrite(fd, b"x" * 4096, 0)
        t = time.perf_counter(); os.fdatasync(fd); out.append((time.perf_counter() - t) * 1000)
        time.sleep(0.005)
    os.close(fd); os.unlink(path + ".page")
    json.dump(out, open(path, "w"))
elif mode == "storm":
    toks = []
    for i in range(1, 9):
        st, _, h = req("POST", "/authorize", dict(client_id="wiki", redirect_uri=CB, response_type="code",
                                                  scope="openid offline_access", state="s", username="u%d" % i,
                                                  password="u%dpassword1" % i))
        code = urllib.parse.parse_qs(urllib.parse.urlparse(h.get("Location", "")).query).get("code", [""])[0]
        st, body, _ = req("POST", "/token", dict(grant_type="authorization_code", code=code, redirect_uri=CB))
        toks.append(json.loads(body)["refresh_token"])
    prev = [None] * 8; done = [0]
    def rotate(k):
        for _ in range(150):
            st, body, _ = refresh(toks[k])
            if st != 200:
                print("refresh refused: %d" % st); return
            prev[k] = toks[k]; toks[k] = json.loads(body)["refresh_token"]; done[0] += 1
    for f in (path + ".probe", path + ".syncs", path + ".probe.stop", path + ".syncs.stop"):
        if os.path.exists(f): os.unlink(f)
    side = [subprocess.Popen([sys.executable, sys.argv[0], str(port), m, path + "." + m]) for m in ("probe", "syncs")]
    ts = [threading.Thread(target=rotate, args=(k,)) for k in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    for m in ("probe", "syncs"): open(path + "." + m + ".stop", "w").close()
    for s in side: s.wait()
    probe = json.load(open(path + ".probe")); syncs = json.load(open(path + ".syncs"))
    reads, sync = probe["reads"], median(syncs)
    long_ = max(sync, 5.0)
    waited = 100 * sum(r for r in reads if r >= long_) / max(probe["ms"], 1)
    json.dump({"latest": toks, "previous": prev}, open(path, "w"))
    print("rotations %d, %d reads of /jwks (median %.1f ms, worst %.1f), a sync of this disk %.1f ms at the median "
          "(%d), %.1f%% of the reader's time in reads that long" %
          (done[0], len(reads), median(reads), max(reads or [0]), sync, len(syncs), waited))
else:
    d = json.load(open(path))
    latest = sum(1 for t in d["latest"] if refresh(t)[0] == 200)
    previous = sum(1 for t in d["previous"] if t and refresh(t)[0] == 200)
    print("latest %d of 8 good, replaced %d of 8 good" % (latest, previous))
PY

rot_all=0; lost=""; waited=""
for round in 1 2 3; do
    out=$(timeout 300 python3 "$T/flow.py" "$P" storm "$T/toks.json" 2>&1)
    rot=$(sed -n 's/^rotations \([0-9]*\).*/\1/p' <<<"$out")
    w=$(sed -n 's/.* \([0-9.]*\)% of the reader.s time.*/\1/p' <<<"$out")
    rot_all=$((rot_all + ${rot:-0}))
    awk -v w="${w:-100}" 'BEGIN{exit !(w < 25)}' || waited="$waited round $round: ${w:-?}%;"
    "$BIN" stop auth >/dev/null 2>&1; "$BIN" start auth >/dev/null 2>&1
    for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$P/jwks" && break; sleep 0.1; done
    after=$(timeout 120 python3 "$T/flow.py" "$P" check "$T/toks.json" 2>&1)
    echo "  round $round: $out; after a restart: $after"
    [ "$after" = "latest 8 of 8 good, replaced 0 of 8 good" ] || lost="$lost round $round: $after;"
done
if [ "$rot_all" = 3600 ]; then ok; else bad "3600 rotations, past hundreds of compactions, are answered" "$rot_all"; fi
if [ -z "$waited" ]; then ok
else bad "a reader beside them spends under a quarter of its time in reads as long as a sync" "$waited"; fi
if [ -z "$lost" ]; then ok
else bad "after each restart every latest token is good and every replaced one refused" "$lost"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
