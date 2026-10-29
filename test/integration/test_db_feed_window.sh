#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A db stream that does not read holds a window of changes, not the history or every change since it stopped.
#
# What each part would catch:
#   * a stream resumed from the start copying the whole history into memory at once, for anybody on a public
#     collection, however many such streams there are
#   * a stream that stopped reading holding every change made since, up to 16 MiB each
#   * a stream behind on the history missing a change, or being told reset, once it reads again
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"

echo "=== Integration: a db stream that does not read holds a window, not the history ==="
daemon_isolate dbfeedwindow
T=$SOCKETLEY_TMPD
PD=$((SL_PORT_BASE + 1986))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

printf 'pub  public\n' > "$T/schema"
printf 'backend feedwindowsecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create db data -p "$PD" --schema "$T/schema" --keys "$T/keys" -s >/dev/null 2>&1 \
    && ok || bad "the db runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PD " && break; sleep 0.1; done
WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$PD" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
[ -n "${WORKER:-}" ] || { echo "  FAIL: no worker pid for the listener"; exit 1; }

tally < <(python3 - "$PD" "$WORKER" 2>&1 <<'PY'
import sys, json, socket, time, urllib.request, urllib.error
pd, worker = sys.argv[1], sys.argv[2]
KEY = {"Authorization": "Bearer feedwindowsecret0123456789", "Content-Type": "application/json"}
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
def put(i):
    body = json.dumps({"i": i, "big": "x" * 400000}).encode()
    r = urllib.request.Request("http://127.0.0.1:%s/c/pub/d%03d" % (pd, i), data=body, method="PUT", headers=KEY)
    with urllib.request.urlopen(r, timeout=10) as resp:
        return resp.status
def rss():
    for line in open("/proc/%s/status" % worker):
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) // 1024
    return 0
def stuck(path):
    """A stream opened by nobody that reads nothing, its receive buffer as small as the kernel allows."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", int(pd)))
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
    return s
def events(s, want, wait=20.0):
    """The stream's events as (id, name), read until `want` have come."""
    s.settimeout(0.5)
    buf, out, end, head = b"", [], time.time() + wait, False
    while len(out) < want and time.time() < end:
        try:
            d = s.recv(1 << 20)
            if not d:
                break
            buf += d
        except socket.timeout:
            continue
        if not head and b"\r\n\r\n" in buf:
            buf = buf.split(b"\r\n\r\n", 1)[1]
            head = True
        while head and b"\n\n" in buf:
            block, buf = buf.split(b"\n\n", 1)
            ev = dict(l.split(": ", 1) for l in block.decode().split("\n") if ": " in l and not l.startswith(":"))
            if "event" in ev:
                out.append((int(ev.get("id", "0")), ev["event"]))
    return out

n = 0
for _ in range(40):
    n += 1
    put(n)
time.sleep(0.5)

# Twelve streams from the start of 16 MB of changes: each copied the whole history into memory before.
base = rss()
early = [stuck("/c/pub/_feed?since=0") for _ in range(12)]
time.sleep(1.5)
grew = rss() - base
print(("ok " if grew < 48 else "bad ") + "twelve unread streams from the start hold a window each, not the history (%d MB grew)" % grew)

# Sixteen live streams that stop reading while 9.6 MB of changes come: each kept every one before.
live = [stuck("/c/pub/_feed") for _ in range(16)]
time.sleep(0.5)
base = rss()
for _ in range(24):
    n += 1
    put(n)
time.sleep(1.5)
grew = rss() - base
print(("ok " if grew < 60 else "bad ") + "sixteen unread live streams hold a window each while changes come (%d MB grew)" % grew)

# A stream that was behind reads every change in order once it reads, and the next one live, with no reset.
got = events(early[0], n)
ids = [e[0] for e in got]
check("a stream behind on the history gets every change once it reads, in order",
      (len(ids), ids == sorted(set(ids))), (n, True))
check("and no reset", [e[1] for e in got if e[1] != "put"], [])
got = events(live[0], 24)
check("a live stream that fell behind gets every change since it opened", [e[0] for e in got], ids[40:])
n += 1
put(n)
nxt = events(early[0], 1) + events(live[0], 1)
check("then the next one live", (len(nxt), len(set(nxt)), nxt[0][0] > ids[-1] if nxt else False), (2, 1, True))
for s in early + live:
    s.close()
PY
)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
