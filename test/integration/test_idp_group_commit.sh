#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: an idp's account changes are synced as a group off its loop, and folded into its snapshot while
# commits go on, without losing one.
#
# What each part would catch:
#   * a sync per change on the loop: a read beside refreshes waited behind every one of them, 50 ms at the median
#   * the changes committed while a compaction ran left out of the journal that replaces the old one: after a
#     restart the refresh tokens they issued are unknown, and the ones they replaced are good again
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
import base64, http.client, json, sys, threading, time, urllib.parse
port, mode, path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
CB = "http://127.0.0.1:9/cb"; basic = "Basic " + base64.b64encode(b"wiki:wikisecret").decode()
def req(method, p, form=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    h = {"Authorization": basic, "Content-Type": "application/x-www-form-urlencoded"} if form else {}
    c.request(method, p, body=urllib.parse.urlencode(form) if form else None, headers=h)
    r = c.getresponse(); d = r.read(); c.close(); return r.status, d, dict(r.getheaders())
refresh = lambda t: req("POST", "/token", dict(grant_type="refresh_token", refresh_token=t))
if mode == "storm":
    toks = []
    for i in range(1, 9):
        st, _, h = req("POST", "/authorize", dict(client_id="wiki", redirect_uri=CB, response_type="code",
                                                  scope="openid offline_access", state="s", username="u%d" % i,
                                                  password="u%dpassword1" % i))
        code = urllib.parse.parse_qs(urllib.parse.urlparse(h.get("Location", "")).query).get("code", [""])[0]
        st, body, _ = req("POST", "/token", dict(grant_type="authorization_code", code=code, redirect_uri=CB))
        toks.append(json.loads(body)["refresh_token"])
    prev = [None] * 8; done = [0]; worst = [0.0]; stop = [False]
    def rotate(k):
        for _ in range(150):
            st, body, _ = refresh(toks[k])
            if st != 200:
                print("refresh refused: %d" % st); return
            prev[k] = toks[k]; toks[k] = json.loads(body)["refresh_token"]; done[0] += 1
    def probe():
        while not stop[0]:
            t = time.perf_counter(); req("GET", "/jwks"); worst[0] = max(worst[0], (time.perf_counter() - t) * 1000)
            time.sleep(0.003)
    p = threading.Thread(target=probe); p.start()
    ts = [threading.Thread(target=rotate, args=(k,)) for k in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    stop[0] = True; p.join()
    json.dump({"latest": toks, "previous": prev}, open(path, "w"))
    print("rotations %d, worst /jwks %.1f ms" % (done[0], worst[0]))
else:
    d = json.load(open(path))
    latest = sum(1 for t in d["latest"] if refresh(t)[0] == 200)
    previous = sum(1 for t in d["previous"] if t and refresh(t)[0] == 200)
    print("latest %d of 8 good, replaced %d of 8 good" % (latest, previous))
PY

worst_all=0; rot_all=0; lost=""
for round in 1 2 3; do
    out=$(timeout 300 python3 "$T/flow.py" "$P" storm "$T/toks.json" 2>&1)
    rot=$(sed -n 's/^rotations \([0-9]*\).*/\1/p' <<<"$out"); w=$(sed -n 's/.*worst \/jwks \([0-9.]*\) ms.*/\1/p' <<<"$out")
    rot_all=$((rot_all + ${rot:-0})); worst_all=$(awk -v a="$worst_all" -v b="${w:-999}" 'BEGIN{print (b > a ? b : a)}')
    "$BIN" stop auth >/dev/null 2>&1; "$BIN" start auth >/dev/null 2>&1
    for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$P/jwks" && break; sleep 0.1; done
    after=$(timeout 120 python3 "$T/flow.py" "$P" check "$T/toks.json" 2>&1)
    echo "  round $round: $out; after a restart: $after"
    [ "$after" = "latest 8 of 8 good, replaced 0 of 8 good" ] || lost="$lost round $round: $after;"
done
if [ "$rot_all" = 3600 ]; then ok; else bad "3600 rotations, past hundreds of compactions, are answered" "$rot_all"; fi
if awk -v w="$worst_all" 'BEGIN{exit !(w < 40)}'; then ok
else bad "a read beside them never waits behind their syncs" "worst /jwks ${worst_all} ms"; fi
if [ -z "$lost" ]; then ok
else bad "after each restart every latest token is good and every replaced one refused" "$lost"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
