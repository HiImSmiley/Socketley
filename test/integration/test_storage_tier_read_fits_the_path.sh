#!/usr/bin/env bash
# suite: isolated -- its own network namespace, daemon, socket and port window, so it runs beside the others
# Integration test: a version moved to a tier a round trip away is read back at more than one small window a round
# trip, and whole.
#
# What each part would catch:
#   * windows of 512 KiB: 50 ms away a read back ran at 20.6 MB/s at best however fast the path, and more of them in
#     flight on more connections only slowed it, each restarting from a cold congestion window
#   * a window past the 1 MiB an answer is held to: every read back refused
# A delay on loopback needs a network namespace of its own, which an unprivileged user namespace gives.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rn true 2>/dev/null; then
        echo "=== Integration: a read back from a tier fits the path ==="
        echo "  SKIP: no unprivileged network namespace here"
        exit 0
    fi
    exec unshare -rn env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a read back from a tier fits the path ==="
# A path's own packets, not loopback's 64 KiB ones, under which a receive window grows a segment at a time.
ip link set lo up; ip link set dev lo mtu 1500
command -v tc >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || { echo "  SKIP: tc and python3 are required"; exit 0; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
# Under the sanitizer every row runs but the ones that time something.
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate tierpath
T=$SOCKETLEY_TMPD
PS=$((SL_PORT_BASE + 1996)); PT=$((SL_PORT_BASE + 1997))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
# A day of two seconds, so the transition after a day comes in a test's time.
SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS=2 daemon_start "$BIN"
AK=AKIATIERPATH00000001; SK=tierpathsecret
printf '[admin]\n%s:%s\nadmin = true\n' "$AK" "$SK" > "$T/creds"
echo "COLD http://127.0.0.1:$PT/cold/arch us-east-1 $AK $SK" > "$T/tiers"
"$BIN" create storage ttier -p "$PT" --dir "$T/tier" --credentials "$T/creds" -s >/dev/null 2>&1
"$BIN" create storage tsrc -p "$PS" --dir "$T/src" --credentials "$T/creds" --tiers "$T/tiers" -s >/dev/null 2>&1
for p in "$PT" "$PS"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/")" != 000 ] && break; sleep 0.1; done
done

out=$(timeout 240 python3 - "$PS" "$PT" "$AK" "$SK" <<'PY'
import boto3, os, subprocess, sys, time
from botocore.config import Config
ps, pt, ak, sk = sys.argv[1:5]
cl = lambda p: boto3.client("s3", endpoint_url="http://127.0.0.1:%s" % p, region_name="us-east-1", aws_access_key_id=ak,
                            aws_secret_access_key=sk, config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
s, t = cl(ps), cl(pt)
t.create_bucket(Bucket="cold"); s.create_bucket(Bucket="hot")
s.put_bucket_lifecycle_configuration(Bucket="hot", LifecycleConfiguration={"Rules": [
    {"ID": "c", "Status": "Enabled", "Filter": {"Prefix": ""}, "Transitions": [{"Days": 1, "StorageClass": "COLD"}]}]})
body = os.urandom(48 << 20)
s.put_object(Bucket="hot", Key="big", Body=body)
for _ in range(600):
    if s.head_object(Bucket="hot", Key="big").get("StorageClass") == "COLD": break
    time.sleep(0.2)
moved = s.head_object(Bucket="hot", Key="big").get("StorageClass") == "COLD"
# The tier 25 ms each way from the source.
subprocess.run(["tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3", "priomap"] + ["1"] * 16, check=True)
subprocess.run(["tc", "qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:", "netem", "delay", "25ms", "limit", "10000"], check=True)
for m in ("sport", "dport"):
    subprocess.run(["tc", "filter", "add", "dev", "lo", "parent", "1:", "protocol", "ip", "u32", "match", "ip", m, pt,
                    "0xffff", "flowid", "1:3"], check=True)
# Four reads, the best of which is the path's: one that starts on a cold connection is slower, and says nothing.
rates, whole = [], True
for _ in range(4):
    t0 = time.time()
    try:
        got = s.get_object(Bucket="hot", Key="big")["Body"].read()
    except Exception:
        got = b""
    dt = time.time() - t0
    whole = whole and got == body
    rates.append(len(got) / dt / 1e6)
print("%s %s %.1f %s" % (moved, whole, max(rates), " ".join("%.1f" % r for r in rates)))
PY
)
read -r moved whole best rates <<<"$out"
echo "  48 MiB read back from a tier 50 ms away, four times: ${rates:-$out} MB/s"
[ "$moved" = True ] && ok || bad "the version moves to the tier" "$out"
[ "$whole" = True ] && ok || bad "and is read back whole" "$out"
if [ "$sanitized" = 1 ]; then echo "  SKIP [rate]: a rate measures the sanitizer, not the windows"
elif awk -v b="${best:-0}" 'BEGIN{exit !(b >= 28)}'; then ok
else bad "at more than one 512 KiB window a round trip" "the best of four ${best:-none} MB/s"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
