#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: an identity provider with a hundred thousand accounts writes one, finds one by its address and
# lists them all without holding its loop for the size of the store.
#
# What each part would catch:
#   * the standing file made again on every write, from every account sorted by a username lower-cased twice a
#     comparison: each refreshed token, code taken or name changed held the loop 218 ms at 100,000 accounts
#   * a standing that a write which changes it leaves as it was: a disabled account's sessions still let in
#   * an account found by its address through the same sort: every mail runtime's lookup and verify, 240 ms each
#   * an address index that keeps an address an account no longer holds, or misses the one it now holds
#   * a compaction that writes the snapshot of every account in one piece on the loop: 90 ms once every thousand
#     writes, here made to come within the timed ones
#   * a snapshot written in pieces while writes go on that a restart reads back as other than the last of them
#   * an answer over the 4 MiB a worker's writer queues refused whole, even with nothing ahead of it: the list of
#     100,000 accounts never came, and the command waited out its bound
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an identity provider with 100,000 accounts ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate idpmany
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1953))
N=100000
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
# A compaction every thirty records, so one comes within the writes timed below.
SOCKETLEY_IDP_COMPACT_AFTER=30 daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PI/jwks")" != 000 ] && break; sleep 0.1; done
# One account made, so the store's directory is there; the snapshot below takes its place.
"$BIN" idp-user auth add u0 --password alicepassword1 >/dev/null 2>&1
"$BIN" stop auth >/dev/null 2>&1
# The store as a backup of a large provider brings it back: a snapshot of N accounts and an empty journal.
D=$(find "$HOME" -type d -name 'auth.accounts' | head -1)
python3 - "$D" "$N" <<'PY'
import json, sys
d, n = sys.argv[1], int(sys.argv[2])
with open(d + "/accounts.snapshot", "w") as f:
    f.write('{"format":"socketley-idp-accounts","version":1}\n')
    for i in range(1, n + 1):
        f.write(json.dumps({"id": "%032x" % (i * 2654435761), "fields": {"username": "u%d" % i,
            "email": "u%d@example.test" % i, "password": "$scrypt$x" + "a" * 80,
            "groups": "admins" if i % 50 == 0 else "users", "revoked_before": "1700000000000"}},
            separators=(",", ":")) + "\n")
PY
: > "$D/accounts.journal"
"$BIN" start auth >/dev/null 2>&1
for _ in $(seq 1 600); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PI/jwks")" = 200 ] && break; sleep 0.1; done
S=$(find "$HOME" -name 'auth.standing' | head -1)

# Writes that leave the standing as it was, timed by a client of the loop asking for the keys all along.
out=$(timeout 300 python3 - "$PI" "$BIN" <<'PY'
import socket, subprocess, sys, threading, time
port, b = int(sys.argv[1]), sys.argv[2]
lat, stop = [], [False]
def probe():
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    while not stop[0]:
        t = time.perf_counter()
        s.sendall(b"GET /jwks HTTP/1.1\r\nHost: x\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf: buf += s.recv(65536)
        h, rest = buf.split(b"\r\n\r\n", 1)
        n = int([l.split(b":")[1] for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
        while len(rest) < n: rest += s.recv(65536)
        lat.append((time.perf_counter() - t) * 1000)
        time.sleep(0.001)
th = threading.Thread(target=probe); th.start()
time.sleep(0.5)
t0 = time.perf_counter()
for i in range(40):
    subprocess.run([b, "idp-user", "auth", "set", "u5", "name=n%d" % i], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
w = (time.perf_counter() - t0) * 1000 / 40
t0 = time.perf_counter()
for i in range(20):
    subprocess.run([b, "idp-user", "auth", "lookup", "u%d@example.test" % (1000 + i)], stdout=subprocess.DEVNULL)
l = (time.perf_counter() - t0) * 1000 / 20
stop[0] = True; th.join()
print("%.1f %.1f %.1f" % (w, max(lat), l))
PY
)
read -r per_write worst per_lookup <<<"$out"
echo "  at $N accounts: ${per_write:-?} ms a write, the loop's worst answer meanwhile ${worst:-?} ms, ${per_lookup:-?} ms a lookup by address"
if [ "$sanitized" = 1 ]; then echo "  SKIP [stall]: milliseconds measure the sanitizer, not the store"
else
    awk -v w="${worst:-9999}" 'BEGIN{exit !(w < 40)}' && ok || bad "a write leaves the loop answering" "$out"
    awk -v l="${per_lookup:-9999}" 'BEGIN{exit !(l < 60)}' && ok || bad "a lookup by address is not a pass over the store" "$out"
fi

# The standing follows a write that changes it, and only one.
before=$(stat -c %Y.%s "$S" 2>/dev/null)
"$BIN" idp-user auth set u7 name=quiet >/dev/null 2>&1
[ "$(stat -c %Y.%s "$S" 2>/dev/null)" = "$before" ] && ok || bad "a name changed leaves the standing file as it was" "$before"
"$BIN" idp-user auth disable u7 >/dev/null 2>&1
id7=$(printf '%032x' $((7 * 2654435761)))
grep -E "^$id7 [0-9]+ [a-z]*d" "$S" >/dev/null && ok || bad "a disabled account is disabled in the standing" "$(grep "^$id7" "$S")"
[ "$(grep -c . "$S")" = $((N + 1)) ] && ok || bad "every account has its line" "$(grep -c . "$S") lines"

# By address, case aside, and the index follows an address changed.
r=$("$BIN" idp-user auth lookup U1234@Example.TEST 2>&1)
case "$r" in "ok u1234"*) ok ;; *) bad "an account is found by its address" "$r" ;; esac
"$BIN" idp-user auth set u77 email=zed@example.test email_verified=1 >/dev/null 2>&1
r=$("$BIN" idp-user auth lookup zed@example.test 2>&1)
case "$r" in "ok u77"*) ok ;; *) bad "by the address it was given" "$r" ;; esac
"$BIN" idp-user auth set u77 email=yod@example.test >/dev/null 2>&1
r=$("$BIN" idp-user auth lookup zed@example.test 2>&1)
case "$r" in "none"*) ok ;; *) bad "and not by the one it gave up" "$r" ;; esac
r=$("$BIN" idp-user auth lookup yod@example.test 2>&1)
case "$r" in "ok u77"*) ok ;; *) bad "but by the one it holds now" "$r" ;; esac

# Back from the snapshot the compaction wrote while the writes went on, and the journal behind it.
"$BIN" stop auth >/dev/null 2>&1
"$BIN" start auth >/dev/null 2>&1
for _ in $(seq 1 600); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PI/jwks")" = 200 ] && break; sleep 0.1; done
r=$("$BIN" idp-user auth show u5 2>&1 | grep '^name:')
[ "$r" = "name: n39" ] && ok || bad "a restart reads back the last write" "${r:-no name}"
r=$("$BIN" idp-user auth show u7 2>&1 | grep -c '^disabled: 1')
[ "$r" = 1 ] && ok || bad "and the account disabled" "$("$BIN" idp-user auth show u7 2>&1 | head -5 | tr '\n' ' ')"

# All of them, in one answer of about 4.6 MB.
"$BIN" idp-user auth list > "$T/list" 2>&1
lines=$(wc -l < "$T/list")
echo "  the list: $lines lines, $(wc -c < "$T/list") bytes"
[ "$lines" = "$N" ] && ok || bad "every account is listed" "$lines lines: $(head -c 120 "$T/list")"
[ "$(head -1 "$T/list" | cut -f1)" = u1 ] && [ "$(sed -n 2p "$T/list" | cut -f1)" = u10 ] && ok \
    || bad "ordered by username" "$(head -2 "$T/list" | cut -f1 | tr '\n' ' ')"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
