#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A db's streams of changes are bounded per client and let go when their reader stops taking them.
#
# What each part would catch:
#   * one address opening streams on a public collection up to the runtime's 4096 connections, each holding its
#     window and an event of up to 1 MiB for as long as it likes (about 5 GiB, and nobody else gets a connection)
#   * a key's streams (a backend's, a replica's) held to the bound meant for browsers
#   * a stream whose reader takes nothing kept open for ever: the idle sweep never takes a stream
#   * the bound counting the entrance (127.0.0.1) rather than the client it names
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"

echo "=== Integration: a db's streams are bounded per client and let go when not read ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate dbfeedbounds
T=$SOCKETLEY_TMPD
PD=$((SL_PORT_BASE + 1621))
trap 'daemon_stop' EXIT
SOCKETLEY_WRITE_STALL_SECS=3 daemon_start "$BIN"

printf 'pub  public\n' > "$T/schema"
printf 'backend feedboundssecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create db data -p "$PD" --schema "$T/schema" --keys "$T/keys" -s >/dev/null 2>&1 \
    && ok || bad "the db runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do listening_now=$(ss -ltn 2>/dev/null) && grep -q ":$PD " <<<"$listening_now" && break; sleep 0.1; done

tally < <(timeout 120 python3 - "$PD" 2>&1 <<'PY'
import sys, json, socket, time, urllib.request
pd = int(sys.argv[1])
KEY = "Bearer feedboundssecret0123456789"
def check(name, cond, got=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(got)[:300]))
def stream(client=None, key=None, rcvbuf=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.connect(("127.0.0.1", pd))
    h = "GET /c/pub/_feed HTTP/1.1\r\nHost: x\r\n"
    if client: h += "X-Forwarded-For: %s\r\n" % client
    if key: h += "Authorization: %s\r\n" % key
    s.sendall((h + "\r\n").encode())
    return s
def status(s):
    s.settimeout(5)
    buf = b""
    while b"\r\n" not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    return int(buf.split(b" ")[1]) if buf.startswith(b"HTTP/1.1 ") else 0

held = [stream("203.0.113.5") for _ in range(32)]
codes = [status(s) for s in held]
check("an address holds 32 streams", codes == [200] * 32, codes)
extra = stream("203.0.113.5")
check("and is refused a 33rd", status(extra) == 429)
extra.close()
other = stream("203.0.113.6")
check("another address is not", status(other) == 200)
keyed = stream("203.0.113.5", KEY)
check("nor is a key, whatever its address", status(keyed) == 200)
held.pop().close()
again = 0
for _ in range(50):
    time.sleep(0.1)
    s = stream("203.0.113.5")
    again = status(s)
    if again == 200:
        held.append(s); break
    s.close()
check("a stream closed is one the address may open again", again == 200, again)
for s in held + [other, keyed]:
    s.close()

# A stream that reads nothing while its window and the kernel's buffers fill, then nothing for the stall's seconds.
stuck = stream("203.0.113.7", rcvbuf=4096)
check("the stream that will not read opens", status(stuck) == 200)
for i in range(16):
    body = json.dumps({"i": i, "big": "x" * 900000}).encode()
    r = urllib.request.Request("http://127.0.0.1:%d/c/pub/d%02d" % (pd, i), data=body, method="PUT",
                               headers={"Authorization": KEY, "Content-Type": "application/json"})
    urllib.request.urlopen(r, timeout=10).read()
time.sleep(8)
stuck.settimeout(10)
end, gone = time.time() + 30, False
while time.time() < end:
    try:
        d = stuck.recv(1 << 20)
    except socket.timeout:
        break
    if not d:
        gone = True
        break
check("a stream that took nothing for the stall's seconds is let go", gone)
PY
)

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
