#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a database read whose documents the page cache does not hold brings them through the ring and
# answers with them, the read and the query alike.
#
# What each part would catch:
#   * a cold document read on the loop: on a disk that takes 2 ms a read every other request waited behind each, 5.9 ms
#     at the median beside four readers, measured on a device-mapper delay this test cannot make without root
#   * a read answered from its first try, which took a document it could not have as missing
#   * a document brought back other than the one asked for, or a query that loses some
# The page cache is let go of the segments with posix_fadvise, which needs no privilege, on a directory on a disk.
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

echo "=== Integration: a cold database read brings its documents through the ring ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate dbcold
T=$SOCKETLEY_TMPD
DH=$(mktemp -d /var/tmp/socketley-dbcold-XXXXXX)
if [ "$(stat -f -c %T "$DH")" = tmpfs ]; then
    rm -rf "$DH"; echo "  SKIP: /var/tmp is a tmpfs, whose pages cannot be let go of"; exit 0
fi
export HOME=$DH
P=$((SL_PORT_BASE + 1969))
unset SOCKETLEY_CONFIG
trap 'daemon_stop; rm -rf "$DH"' EXIT
printf 'backend dbbackendsecret0123456789\n' > "$T/keys"; chmod 600 "$T/keys"
daemon_start "$BIN"
"$BIN" create db d -p "$P" --keys "$T/keys" --cache 1M -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" != 000 ] && break; sleep 0.1; done

out=$(timeout 300 python3 - "$P" "$DH" <<'PY'
import glob, json, os, random, socket, sys, threading, time
port, home = int(sys.argv[1]), sys.argv[2]
N = 3000
KEY = "Authorization: Bearer dbbackendsecret0123456789\r\n"
def call(s, method, path, body=None):
    b = json.dumps(body).encode() if body is not None else b""
    s.sendall(("%s %s HTTP/1.1\r\nHost: x\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
               % (method, path, KEY, len(b))).encode() + b)
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(65536)
    h, rest = buf.split(b"\r\n\r\n", 1)
    cl = [l for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")]
    n = int(cl[0].split(b":")[1]) if cl else 0
    while len(rest) < n: rest += s.recv(65536)
    return int(h.split(b" ")[1]), rest
def text(i): return ("doc-%d-" % i) * (2000 // len("doc-%d-" % i))
def load(k):
    s = socket.create_connection(("127.0.0.1", port), timeout=60)
    for i in range(k, N, 8):
        call(s, "PUT", "/c/notes/n%d" % i, {"text": text(i), "i": i})
ts = [threading.Thread(target=load, args=(k,)) for k in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
os.sync()
# Every segment's pages let go of, so the reads below go to the disk.
# Under the state directory, which is a hidden one that glob would pass over.
segs = [os.path.join(d, f) for d, _, fs in os.walk(home) for f in fs if f.startswith("seg-") and f.endswith(".log")]
def let_go():
    # Asked until the kernel has let the pages go, which it does not do for one under writeback; a read that would
    # wait for the disk says so.
    for _ in range(25):
        cold = True
        for p in segs:
            fd = os.open(p, os.O_RDONLY)
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            try:
                os.preadv(fd, [bytearray(4096)], 4096, os.RWF_NOWAIT)
                cold = False
            except BlockingIOError:
                pass
            os.close(fd)
        if cold:
            return True
        time.sleep(0.2)
    return False
evicted = let_go()
wrong = []
def read(k):
    s = socket.create_connection(("127.0.0.1", port), timeout=60)
    ids = list(range(k, N, 8)); random.shuffle(ids)
    for i in ids:
        st, body = call(s, "GET", "/c/notes/n%d" % i)
        if st != 200 or json.loads(body).get("text") != text(i): wrong.append(i)
ts = [threading.Thread(target=read, args=(k,)) for k in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
let_go()
s = socket.create_connection(("127.0.0.1", port), timeout=60)
st, body = call(s, "POST", "/c/notes/_query", {"where": {"i": {"lt": 400}}, "limit": 1000})
got = json.loads(body)
docs = got.get("docs", [])
seen = sorted(d.get("i") for d in docs if isinstance(d, dict) and d.get("text") == text(d.get("i", -1)))
print(len(segs), len(wrong), st, len(seen), seen == list(range(400)), evicted)
PY
)
read -r segs wrong qst qn qall evicted <<<"$out"
fetched=$("$BIN" stats d 2>/dev/null | awk -F: '$1=="fetched" {print $2}')
echo "  3000 documents of 2 KB in ${segs:-?} segment(s), read with the page cache let go of: ${wrong:-?} wrong, ${fetched:-none} brought through the ring"
echo "  a query over them cold: status ${qst:-?}, ${qn:-?} of 400 whole"
[ "${wrong:-x}" = 0 ] && ok || bad "every document read cold is the one asked for" "$out"
if [ "${evicted:-}" != True ]; then echo "  SKIP [ring]: the kernel would not let the segment's pages go"
elif [ "${fetched:-0}" -gt 0 ]; then ok
else bad "the cold ones are brought through the ring" "fetched ${fetched:-none}"; fi
[ "${qall:-}" = True ] && ok || bad "a query read cold finds every document it matches" "$out"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
