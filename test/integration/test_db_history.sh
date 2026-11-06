#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a db shard keeps the changes a stream may resume from only while a stream is near.
#
# Every shard kept up to 32 MiB of decoded changes for a stream that might resume, whether or not any stream was ever
# opened.  Now each keeps them while a stream is open on any shard of the runtime, or closed within two minutes, and
# about 1 MiB (a shard reading shard 0's log: none) otherwise.
#
# What it would catch:
#   * held for nobody      3 MiB of writes with no stream anywhere leave each shard's history_bytes at 1 MiB or less;
#                          without the bound, every shard holds all 3 MiB
#   * resume kept          a stream that read up to change L and closed, followed by 2 MiB more writes (past the idle
#                          bound), resumes from L on every reconnect -- whichever shard the kernel hands it to, the
#                          one it was on or a sibling that never held a stream -- with the next change and no reset
#   * the history then     while that stream was near, the shards kept more than the idle bound
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

echo "=== Integration: a db keeps its change history only while a stream is near ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate dbhistory
P=$((SL_PORT_BASE + 1740))
T=$(mktemp -d /tmp/skl-dbhist-XXXXXX)
trap '"$BIN" stop dh >/dev/null 2>&1; sleep 0.3; "$BIN" remove dh >/dev/null 2>&1; daemon_stop; rm -rf "$T"' EXIT
printf 'items private\n' > "$T/schema"
printf 'backend histsecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"

daemon_start "$BIN"
"$BIN" create db dh -p "$P" --schema "$T/schema" --keys "$T/keys" --shards 2 -s >/dev/null 2>&1 \
    || bad "a db of two shards is made"

cat > "$T/client.py" <<'PY'
import json, socket, sys, time
port, what = int(sys.argv[1]), sys.argv[2]
AUTH = "Bearer histsecret0123456789"
BODY = "x" * 1000

def put_many(first, count):
    # Keep-alive connections of their own, so the writes reach both shards.
    socks = [socket.create_connection(("127.0.0.1", port), timeout=10) for _ in range(8)]
    for i in range(first, first + count):
        s = socks[i % len(socks)]
        body = json.dumps({"n": i, "pad": BODY}).encode()
        s.sendall(b"PUT /c/items/d%d HTTP/1.1\r\nHost: x\r\nAuthorization: %s\r\nContent-Type: application/json\r\n"
                  b"Content-Length: %d\r\n\r\n%s" % (i, AUTH.encode(), len(body), body))
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(65536)
        head, rest = buf.split(b"\r\n\r\n", 1)
        n = int([l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
        while len(rest) < n:
            rest += s.recv(65536)
        if not head.startswith(b"HTTP/1.1 20"):
            print("refused", i, head[:40]); return
    print("put", count)

def touch():
    # A read on many connections, so every shard takes in shard 0's log.
    for _ in range(16):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"GET /c/items/d0 HTTP/1.1\r\nHost: x\r\nAuthorization: %s\r\nConnection: close\r\n\r\n" % AUTH.encode())
        while s.recv(65536):
            pass
    print("touched")

def feed(last=None, want=1, wait=5.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    s.settimeout(0.3)
    extra = b"" if last is None else b"Last-Event-ID: %d\r\n" % last
    s.sendall(b"GET /c/items/_feed HTTP/1.1\r\nHost: x\r\nAuthorization: %s\r\n%s\r\n" % (AUTH.encode(), extra))
    buf, events, end = b"", [], time.time() + wait
    while len(events) < want and time.time() < end:
        try:
            d = s.recv(65536)
            if not d:
                break
            buf += d
        except socket.timeout:
            continue
        if b"\r\n\r\n" in buf and not events and buf.startswith(b"HTTP"):
            buf = buf.split(b"\r\n\r\n", 1)[1]
        while b"\n\n" in buf:
            block, buf = buf.split(b"\n\n", 1)
            ev = dict(l.split(": ", 1) for l in block.decode().split("\n") if ": " in l and not l.startswith(":"))
            if "event" in ev:
                events.append((int(ev.get("id", 0)), ev["event"]))
    return s, events

if what == "put":
    put_many(int(sys.argv[3]), int(sys.argv[4]))
elif what == "touch":
    touch()
elif what == "open":
    # A stream from now, one write seen through it, and its last change printed; then it goes.
    s, _ = feed(want=0, wait=1.0)
    put_many(10_000_000, 1)
    _, evs = None, []
    s.settimeout(0.3); buf = b""; end = time.time() + 5
    while time.time() < end and not evs:
        try:
            buf += s.recv(65536)
        except socket.timeout:
            pass
        for block in buf.split(b"\n\n"):
            for l in block.decode(errors="replace").split("\n"):
                if l.startswith("id: "):
                    evs.append(int(l[4:]))
    s.close()
    print("last", max(evs) if evs else -1)
elif what == "resume":
    last = int(sys.argv[3]); tries = int(sys.argv[4]); good = 0; seen = []
    for _ in range(tries):
        s, evs = feed(last, want=1)
        s.close()
        seen.append(evs[0] if evs else None)
        if evs and evs[0] == (last + 1, "put"):
            good += 1
    print("resumed", good, "of", tries, seen if good != tries else "")
PY
client() { timeout 120 python3 -I "$T/client.py" "$P" "$@" 2>&1 | tail -1; }
hist()   { "$BIN" stats dh 2>/dev/null | awk -F: '$1=="history_bytes" {print $2}' | sort -n | tail -1; }
for i in $(seq 1 100); do [ "$(client touch)" = touched ] && break; sleep 0.2; done

# ─── no stream anywhere ────────────────────────────────────────────────────
check "3 MiB of writes are taken" "$(client put 0 3000)" "put 3000"
client touch >/dev/null; sleep 2; client touch >/dev/null; sleep 1.5
H=$("$BIN" stats dh 2>/dev/null | awk -F: '$1=="history_bytes" {printf "%s ", $2}')
MAX=$(hist)
if [[ "$MAX" =~ ^[0-9]+$ ]] && [ "$MAX" -le $(((1 << 20) + 4096)) ]; then
    ok "with no stream, no shard keeps more than 1 MiB of changes ($H)"
else
    bad "with no stream, no shard keeps more than 1 MiB of changes: ${H:-none}"
fi

# ─── a stream that goes, and comes back ────────────────────────────────────
LAST=$(client open | awk '$1=="last" {print $2}')
if [[ "$LAST" =~ ^[0-9]+$ ]] && [ "$LAST" -gt 0 ]; then ok "a stream reads a change ($LAST)"; else bad "a stream reads a change: ${LAST:-?}"; fi
check "2 MiB more are written after it closed" "$(client put 20000 2000)" "put 2000"
client touch >/dev/null; sleep 1.5
MAX=$(hist)
if [[ "$MAX" =~ ^[0-9]+$ ]] && [ "$MAX" -gt $((1 << 20)) ]; then
    ok "within the resume window the shards keep more than the idle bound ($MAX)"
else
    bad "within the resume window the shards keep more than the idle bound: ${MAX:-none}"
fi
check "every reconnect resumes with the next change, on either shard" "$(client resume "$LAST" 8)" "resumed 8 of 8 "

echo "  Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
