#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A db runtime of several shards: shard 0 writes the one log, and every shard reads it and answers on the one port.
#
# What each part would catch:
#   * a read on one shard not seeing a write another connection had answered just before it
#   * a query answered differently than one shard answers it, or a transaction or a unique index that no longer holds
#   * a write a reading shard keeps, or one it loses on the way to shard 0
#   * a stream on a reading shard missing a change, twice, or out of order
#   * the documents lost when the runtime restarts with another number of shards
#   * a document whose time came still answered by a reading shard
#   * a backup, a restore, or a replica of a sharded database that is not every document
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"
expect() { [ "$2" = "$3" ] && ok || bad "$1" "got '$2', want '$3'"; }
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
# A worker's figures come every 250 ms, so the lines a test reads are waited for.
stats_of() { sleep 0.6; "$BIN" stats "$1" 2>/dev/null; }

echo "=== Integration: a db runtime of several shards, one writing and every one reading ==="
daemon_isolate dbshards
T=$SOCKETLEY_TMPD
PD=$((SL_PORT_BASE + 1990))
PR=$((SL_PORT_BASE + 1991))
PC=$((SL_PORT_BASE + 1992))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

cat > "$T/schema" <<EOF
items    private  level name
uniq     private  unique:sku
temps    private  ttl:exp
EOF
printf 'backend shardsecret0123456789\n' > "$T/keys"
printf 'shardsecret0123456789\n' > "$T/replica.key"
chmod 600 "$T/keys" "$T/replica.key"

"$BIN" create db data -p "$PD" --schema "$T/schema" --keys "$T/keys" --shards 4 -s >/dev/null 2>&1 \
    && ok || bad "a db runtime of four shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create db ref -p "$PR" --schema "$T/schema" --keys "$T/keys" -s >/dev/null 2>&1 \
    && ok || bad "a db runtime of one shard is made beside it" "$(tail -3 "$SOCKETLEY_DLOG")"
up "$PD" && up "$PR"
s=$(stats_of data)
expect "one shard writes" "$(echo "$s" | grep -c '^role:writer')" 1
expect "and three read its log" "$(echo "$s" | grep -c '^role:reader$')" 3
expect "the four cache --cache between them" "$(echo "$s" | awk -F: '$1 == "cache_limit" { n += $2 } END { print n + 0 }')" $((64 << 20))

run() {
    python3 - "$1" "$PD" "$PR" "$PC" 2>&1 <<'PY'
import sys, json, socket, time, random, urllib.request, urllib.error
phase, pd, pr, pc = sys.argv[1:5]
KEY = {"Authorization": "Bearer shardsecret0123456789", "Content-Type": "application/json"}
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
def raw(port, method, path, body=None, headers=None):
    # A connection of its own each time, so the kernel hands the requests to every shard.
    h = dict(KEY)
    h.update(headers or {})
    r = urllib.request.Request("http://127.0.0.1:%s%s" % (port, path), data=None if body is None else json.dumps(body).encode(),
                               method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers
def db(port, method, path, body=None, headers=None):
    st, text, _ = raw(port, method, path, body, headers)
    return st, json.loads(text) if text else None

class stream:
    def __init__(self, port, path):
        self.s = socket.create_connection(("127.0.0.1", int(port)), 5)
        self.s.settimeout(0.2)
        self.s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nAuthorization: %s\r\n\r\n" % (path, KEY["Authorization"])).encode())
        self.buf = b""
        self.status = None
    def events(self, want, wait=5.0):
        out, end = [], time.time() + wait
        while (len(out) < want or self.status is None) and time.time() < end:
            try:
                d = self.s.recv(65536)
                if not d:
                    break
                self.buf += d
            except socket.timeout:
                pass
            if self.status is None and b"\r\n\r\n" in self.buf:
                head, self.buf = self.buf.split(b"\r\n\r\n", 1)
                self.status = int(head.split(b" ")[1])
            while self.status is not None and b"\n\n" in self.buf:
                block, self.buf = self.buf.split(b"\n\n", 1)
                ev = {}
                for line in block.decode().split("\n"):
                    if not line.startswith(":"):
                        k, _, v = line.partition(": ")
                        ev[k] = v
                if "event" in ev:
                    out.append((int(ev.get("id", "0")), ev["event"], json.loads(ev.get("data") or "null")))
        return out

if phase == "main":
    # Every write is seen by the next read, whichever shard each connection reached.
    missed = []
    for i in range(300):
        st, d = db(pd, "PUT", "/c/items/r%d" % (i % 50), {"n": i, "level": i % 7})
        if st not in (200, 201):
            missed.append(("put", i, st))
            continue
        st, got = db(pd, "GET", "/c/items/r%d" % (i % 50))
        if st != 200 or got.get("n") != i or got.get("_v") != d.get("_v"):
            missed.append(("get", i, st, got))
    check("a read on any shard sees the write answered before it", missed[:3], [])

    # The same documents in a database of one shard, and every query answered alike.
    rng = random.Random(5)
    for i in range(300):
        doc = {"level": rng.randint(0, 9), "name": rng.choice(["al", "bo", "cy", None]), "x": rng.random()}
        for p in (pd, pr):
            db(p, "PUT", "/c/items/q%d" % i, doc)
    for i in range(50):
        db(pr, "PUT", "/c/items/r%d" % i, db(pd, "GET", "/c/items/r%d" % i)[1])
    differ = 0
    for t in range(150):
        q = {}
        f = rng.choice(["level", "name", "x", "_id"])
        op = rng.choice(["eq", "gte", "lt", "prefix", None])
        if op == "eq": q["where"] = {f: rng.choice([3, "al", None])}
        elif op == "gte": q["where"] = {f: {"gte": rng.choice([5, "b", 0.5])}}
        elif op == "lt": q["where"] = {f: {"lt": rng.choice([4, "c", 0.3])}}
        elif op == "prefix": q["where"] = {f: {"prefix": rng.choice(["a", "q1", "r"])}}
        if rng.random() < 0.6: q["sort"] = rng.choice(["", "-"]) + rng.choice(["level", "name", "x", "_id"])
        if rng.random() < 0.5: q["limit"] = rng.randint(1, 30); q["skip"] = rng.randint(0, 40)
        a, b = raw(pd, "POST", "/c/items/_query", q)[:2], raw(pr, "POST", "/c/items/_query", q)[:2]
        # The versions differ where the copy was written once; the documents and their order may not.
        strip = lambda r: (r[0], [(d["_id"], {k: v for k, v in d.items() if k != "_v"}) for d in json.loads(r[1]).get("docs", [])]) if r[0] == 200 else r
        differ += strip(a) != strip(b)
    check("a query answers as a database of one shard does", differ, 0)

    # A transaction of any documents, made whole by shard 0, and seen at once.
    st, _ = db(pd, "POST", "/tx", {"ops": [{"op": "put", "c": "items", "id": "t1", "doc": {"n": 1}},
                                          {"op": "put", "c": "uniq", "id": "t2", "doc": {"sku": "s1"}},
                                          {"op": "delete", "c": "items", "id": "r0"}]})
    check("a transaction over collections is made", (st, db(pd, "GET", "/c/uniq/t2")[0], db(pd, "GET", "/c/items/r0")[0]),
          (200, 200, 404))
    st, _ = db(pd, "POST", "/tx", {"ops": [{"op": "put", "c": "items", "id": "t3", "doc": {}},
                                          {"op": "put", "c": "uniq", "id": "t4", "doc": {"sku": "s1"}}]})
    check("or none of it", (st, db(pd, "GET", "/c/items/t3")[0]), (409, 404))
    check("a unique value is taken once, from any shard", db(pd, "PUT", "/c/uniq/t5", {"sku": "s1"})[0], 409)
    st, d = db(pd, "PUT", "/c/items/t1", {"n": 2}, {"If-Match": '"1"'})
    st2, _ = db(pd, "PUT", "/c/items/t1", {"n": 3}, {"If-Match": '"1"'})
    check("a version held to, whichever shard took it", (st, d.get("_v"), st2), (200, 2, 412))
    st, d = db(pd, "POST", "/c/items", {"n": 9})
    check("an insert draws its id at shard 0", (st, db(pd, "GET", "/c/items/" + d.get("_id", "-"))[1].get("n")), (201, 9))

    # Streams opened on every shard each hear every change, in order, once.
    streams = [stream(pd, "/c/items/_feed") for _ in range(12)]
    for s in streams:
        s.events(0, 1.0)
    for i in range(5):
        db(pd, "PUT", "/c/items/f%d" % i, {"n": i})
    evs = [s.events(5) for s in streams]
    got = [[(e[1], e[2]["id"]) for e in v] for v in evs]
    check("every stream, on any shard, hears each change once and in order",
          [g == [("put", "f%d" % i) for i in range(5)] for g in got], [True] * len(streams))
    ids = [[e[0] for e in v] for v in evs]
    check("numbered as shard 0 numbers them", (len({tuple(x) for x in ids}), len(ids[0]), ids[0] == sorted(set(ids[0]))), (1, 5, True))

    # A document whose time came is gone on every shard.
    # Whole seconds, so +1 could end a fraction of a second after the PUT; four leaves three at the least.
    exp = int(time.time()) + 4
    db(pd, "PUT", "/c/temps/soon", {"exp": exp})
    check("a document with a time to go is read on every shard", [db(pd, "GET", "/c/temps/soon")[0] for _ in range(8)], [200] * 8)
    time.sleep(max(0.0, exp - time.time()) + 1.2)
    check("and on none once its time came", [db(pd, "GET", "/c/temps/soon")[0] for _ in range(8)], [404] * 8)

elif phase == "after":
    st, d = db(pd, "POST", "/c/items/_query", {"count": True})
    st1, d1 = db(pr, "POST", "/c/items/_query", {"count": True})
    check("every document is there with another number of shards", d["count"], d1["count"] + 6)
    check("and reads as it was written", [db(pd, "GET", "/c/items/r%d" % i)[1].get("n") for i in (7, 8)], [257, 258])
    check("written to, still", db(pd, "PUT", "/c/items/after", {"n": 1})[0], 201)

elif phase == "copy":
    for _ in range(100):
        if db(pc, "GET", "/c/items/after")[0] == 200:
            break
        time.sleep(0.1)
    a = db(pd, "POST", "/c/items/_query", {"limit": 1000})[1]["docs"]
    b = db(pc, "POST", "/c/items/_query", {"limit": 1000})[1]["docs"]
    check("a sharded replica of a sharded database holds what it holds", b, a)
    db(pd, "PUT", "/c/items/later", {"n": 5})
    for _ in range(100):
        if db(pc, "GET", "/c/items/later")[0] == 200:
            break
        time.sleep(0.1)
    check("and every change after", [db(pc, "GET", "/c/items/later")[1].get("n") for _ in range(6)], [5] * 6)
    check("and refuses a write on any shard", [db(pc, "PUT", "/c/items/x", {})[0] for _ in range(4)], [403] * 4)

elif phase == "restored":
    check("a restore brings the backup's documents back to every shard",
          [db(pd, "GET", "/c/items/backed")[1].get("v") for _ in range(8)], [1] * 8)
    check("and not one made after it", [db(pd, "GET", "/c/items/gone")[0] for _ in range(8)], [404] * 8)
PY
}

tally < <(run main)
s=$(stats_of data)
w=$(echo "$s" | awk -F: '/^taken_from_readers:/ { n += $2 } END { print n + 0 }')
[ "$w" -gt 0 ] && ok || bad "the reading shards send their writes to shard 0" "taken_from_readers $w"
docs=$(echo "$s" | awk -F: '/^documents:/ { print $2 }' | sort -u | wc -l)
expect "every shard holds every document" "$docs" 1
# With no stream open on a reading shard, shard 0 tells none of its writes; the reads catch up as they come.
sleep 1.5
n0=$(stats_of data | awk -F: '/^nudges:/ { n += $2 } END { print n + 0 }')
for i in $(seq 1 30); do curl -s -o /dev/null -X PUT -H "Authorization: Bearer shardsecret0123456789" \
    -H "Content-Type: application/json" --data "{\"n\":$i}" "http://127.0.0.1:$PD/c/quiet/q$i"; done
n1=$(stats_of data | awk -F: '/^nudges:/ { n += $2 } END { print n + 0 }')
expect "thirty writes with no stream open nudge no reading shard" "$((n1 - n0))" 0

"$BIN" stop data >/dev/null 2>&1
"$BIN" edit data --shards 2 >/dev/null 2>&1 && ok || bad "the number of shards is changed while stopped" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" start data >/dev/null 2>&1 && up "$PD" && ok || bad "and the runtime starts again" "$(tail -3 "$SOCKETLEY_DLOG")"
expect "with two shards" "$(stats_of data | grep -c '^shard:')" 2
tally < <(run after)

"$BIN" create db copy -p "$PC" --replicate "http://127.0.0.1:$PD" --replicate-key "$T/replica.key" --keys "$T/keys" \
    --schema "$T/schema" --shards 3 -s >/dev/null 2>&1 && up "$PC" \
    && ok || bad "a replica of three shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
tally < <(run copy)

curl -s -o /dev/null -X PUT -H "Authorization: Bearer shardsecret0123456789" -H "Content-Type: application/json" \
    -d '{"v":1}' "http://127.0.0.1:$PD/c/items/backed"
out=$("$BIN" db-backup data "$T/all.dbbackup" 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ -z "$out" ] && [ -s "$T/all.dbbackup" ] && ok || bad "a sharded database is backed up" "rc $rc: $out"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer shardsecret0123456789" -H "Content-Type: application/json" \
    -d '{"v":2}' "http://127.0.0.1:$PD/c/items/gone"
out=$("$BIN" db-restore data "$T/all.dbbackup" 2>&1) && ok || bad "and restored" "$out"
up "$PD"
tally < <(run restored)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
