#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a metrics runtime's --receive takes remote_write from a sender it trusts with every figure, and a
# series no bigger than a scraped line may make.
#
# What each part would catch:
#   * an account of --idp that is no admin writing samples every rule, alert and page then reads as the truth
#   * a browser's cookie carrying a write a sibling's page sent along (an admin's too: a sender has a key or a token)
#   * a series of thousands of labels, or of one label of megabytes, stored: with --max-series counting series and
#     not their bytes, a few requests of 32 MiB each then hold the runtime's memory
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: remote_write is taken from a trusted sender, a series a line's size ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate metricsrw
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1601)); PM=$((SL_PORT_BASE + 1602))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
S() { "$BIN" "$@"; }

KEY=sendersecretsendersecret01
printf 'sender %s\n' "$KEY" > "$T/keys"
chmod 600 "$T/keys"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
S create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PI/jwks")" = 200 ] && break; sleep 0.1; done
S idp-user auth add bob --password bobpassword12 >/dev/null
S idp-user auth add root --password rootpassword12 --groups admins >/dev/null
S create metrics m -p "$PM" --receive --keys "$T/keys" --idp auth -s >/dev/null
cookie_of() { curl -s -i -X POST -H "Origin: http://127.0.0.1:$PI" -d "username=$1&password=$2" "http://127.0.0.1:$PI/login" | sed -n 's/^[Ss]et-[Cc]ookie: \(skl_idp=[^;]*\).*/\1/p' | head -1; }
BOB=$(cookie_of bob bobpassword12); ROOT=$(cookie_of root rootpassword12)
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $ROOT" "http://127.0.0.1:$PM/api/v1/labels")" = 200 ] && break; sleep 0.1; done
[ -n "$BOB" ] && [ -n "$ROOT" ] && ok || bad "bob and root are signed in" "bob '$BOB' root '$ROOT'"

# A WriteRequest of one series with one sample now, Snappy-compressed as one literal; prints the status.
cat > "$T/rw.py" <<'PY'
import struct, sys, time, urllib.request, urllib.error
port, auth, kind = sys.argv[1], sys.argv[2], sys.argv[3]
def varint(n):
    o = b""
    while True:
        b = n & 0x7f; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])
def ld(f, b): return bytes([(f << 3) | 2]) + varint(len(b)) + b
def label(n, v): return ld(1, ld(1, n.encode()) + ld(2, v.encode()))
name = {"plain": "rw_plain", "wide": "rw_wide", "long": "rw_long", "many": "rw_many", "cookie": "rw_cookie"}[kind]
labels = [("__name__", name), ("job", "rw")]
if kind == "wide":   labels += [("l%04d" % i, "v") for i in range(5000)]
if kind == "many":   labels += [("l%02d" % i, "v" * 900) for i in range(62)]
if kind == "long":   labels += [("blob", "x" * (2 << 20))]
labels.sort()
sample = ld(2, bytes([0x09]) + struct.pack("<d", 1.0) + bytes([0x10]) + varint(int(time.time() * 1000)))
req = ld(1, b"".join(label(n, v) for n, v in labels) + sample)
body = varint(len(req)) + bytes([0xFC]) + struct.pack("<I", len(req) - 1) + req
h = {"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy", "X-Prometheus-Remote-Write-Version": "0.1.0"}
if auth.startswith("Cookie: "): h["Cookie"] = auth[8:]
elif auth: h["Authorization"] = auth
try:
    print(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%s/api/v1/write" % port, data=body, method="POST", headers=h), timeout=20).status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
W() { python3 "$T/rw.py" "$PM" "$1" "$2"; }
# How many series of `metric` the runtime holds, asked with the key.
N() { curl -s -H "Authorization: Bearer $KEY" --data-urlencode "query=count($1)" "http://127.0.0.1:$PM/api/v1/query" |
      python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else 0)'; }

expect "a key's remote_write is taken" "$(W "Bearer $KEY" plain)" 204
expect "and its series is stored" "$(N rw_plain)" 1
expect "an account that is no admin writes nothing" "$(W "Cookie: $BOB" cookie)" 403
expect "nor does an admin's browser cookie" "$(W "Cookie: $ROOT" cookie)" 403
expect "so no series came of either" "$(N rw_cookie)" 0
expect "nobody signed in writes nothing" "$(W "" cookie)" 401

# Each refused series is counted and the request still answered, as a store past --max-series answers.
expect "a series of 5000 labels is not taken" "$(W "Bearer $KEY" wide)" 204
expect "and not stored" "$(N rw_wide)" 0
expect "a series of a 2 MiB label is not taken" "$(W "Bearer $KEY" long)" 204
expect "and not stored" "$(N rw_long)" 0
expect "64 labels of 56 KiB in all is a line's worth" "$(W "Bearer $KEY" many)" 204
expect "and is stored" "$(N rw_many)" 1
# The worker counts each refused sample as its request is answered, but `stats` is the daemon's copy, which the
# worker sends on a quarter second after a change and later under load: asked until it says both, with a deadline,
# and then exactly both -- the 5000 labels' sample and the 2 MiB label's, none of the stored series'.
for _ in $(seq 1 200); do
    refused=$(S stats m 2>/dev/null | awk -F: '$1=="received_refused" {print $2}')
    [ "${refused:-0}" -ge 2 ] && break
    sleep 0.1
done
expect "stats count the refused samples" "received_refused ${refused:-none}" "received_refused 2"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
