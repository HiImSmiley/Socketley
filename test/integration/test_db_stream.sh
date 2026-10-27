#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The db runtime past one process's memory and one machine: its stream of changes, documents with a time to go,
# a replica on another runtime, backups and a restore, and more documents than its cache holds.
#
# What each part would catch:
#   * a change streamed before it is on the disk, twice, out of order, or to a reader who may not see it
#   * a stream that resumes from the last change it read missing one, or a page told nothing when they are gone
#   * a document whose time came still answered, or its deletion never written or streamed
#   * a replica that misses a change, takes a write, starts over after a restart of itself or of the one it copies,
#     or holds a document the one it copies does not
#   * a backup that is not every document, a restore that is not the backup, or backups never pruned
#   * documents read wrongly once there are more than the cache holds
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
# A figure from the worker's stats, which reach the daemon a moment after the worker starts.
stat_of() {
    local v=""
    for _ in $(seq 1 30); do v=$("$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2://p"); [ -n "$v" ] && break; sleep 0.1; done
    echo "$v"
}
# A worker's figures come every 250 ms, so one counting what was just answered is waited for.
stat_at_least() {   # runtime field n -> 0 once the figure is n or more, within three seconds
    for _ in $(seq 1 30); do [ "$(stat_of "$1" "$2")" -ge "$3" ] 2>/dev/null && return 0; sleep 0.1; done
    return 1
}

echo "=== Integration: the db runtime's stream, replicas, backups, and documents past its cache ==="
daemon_isolate dbstream
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1980))
PD=$((SL_PORT_BASE + 1981))
PR=$((SL_PORT_BASE + 1982))
PB=$((SL_PORT_BASE + 1983))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
cat > "$T/schema" <<EOF
notes     private  n
chars     owner
sessions  owner    ttl:exp
EOF
printf 'backend streamsecret0123456789\n' > "$T/keys"
printf 'streamsecret0123456789\n' > "$T/replica.key"
chmod 600 "$T/keys" "$T/replica.key"

"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1 \
    && ok || bad "the idp runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create db data -p "$PD" --schema "$T/schema" --keys "$T/keys" --idp auth --idp-audience spa -s >/dev/null 2>&1 \
    && ok || bad "the db runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
up "$PD" && up "$PI"
ALICE=$("$BIN" idp-user auth add alice --password alicepassword1 2>&1)
BOB=$("$BIN" idp-user auth add bob --password bobpassword12 2>&1)

run() {
    python3 - "$1" "$PI" "$PD" "$PR" "$ALICE" "$BOB" "$T" 2>&1 <<'PY'
import sys, json, socket, time, urllib.request, urllib.error, urllib.parse
phase, pi, pd, pr, alice, bob, tmpd = sys.argv[1:8]
I = "http://127.0.0.1:%s" % pi
KEY = {"Authorization": "Bearer streamsecret0123456789"}
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(NoRedirect)
def at(base, method, path, body=None, headers=None, form=None):
    h = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with op.open(r, timeout=10) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers
def db(port, method, path, body=None, headers=None):
    st, text, h = at("http://127.0.0.1:%s" % port, method, path, body, headers)
    try:
        return st, json.loads(text) if text else None
    except ValueError:
        return st, text
def sign_in(user, password):
    st, _, h = at(I, "POST", "/login", form={"username": user, "password": password, "rd": I + "/account"})
    return (h.get("Set-Cookie") or "").split(";")[0]

class stream:
    """A stream of changes read as a browser's EventSource would, its events as (id, name, data)."""
    def __init__(self, port, path, headers):
        self.s = socket.create_connection(("127.0.0.1", int(port)), 5)
        self.s.settimeout(0.2)
        h = "".join("%s: %s\r\n" % kv for kv in headers.items())
        self.s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n%s\r\n" % (path, h)).encode())
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
                    if line.startswith(":"):
                        continue
                    k, _, v = line.partition(": ")
                    ev[k] = v
                if "event" in ev:
                    out.append((int(ev.get("id", "0")), ev["event"], json.loads(ev.get("data") or "null")))
        return out
    def close(self):
        self.s.close()

if phase == "stream":
    ca, cb = sign_in("alice", "alicepassword1"), sign_in("bob", "bobpassword12")
    every = stream(pd, "/_feed", KEY)
    mine = stream(pd, "/c/chars/_feed", {"Cookie": ca})
    nobody = stream(pd, "/c/chars/_feed", {})
    check("a stream of an owner collection needs a sign-in", (nobody.events(0, 0.5), nobody.status), ([], 401))
    other = stream(pd, "/_feed", {"Cookie": ca})
    other.events(0, 0.5)
    check("every collection's stream is a key's alone", other.status, 403)
    db(pd, "PUT", "/c/notes/a", {"n": 1}, KEY)
    db(pd, "PUT", "/c/chars/alice1", {"name": "Merlin"}, {"Cookie": ca})
    db(pd, "PUT", "/c/chars/bob1", {"name": "Arthur"}, {"Cookie": cb})
    db(pd, "PATCH", "/c/notes/a", {"inc": {"n": 1}}, KEY)
    db(pd, "DELETE", "/c/chars/alice1", headers={"Cookie": ca})
    evs = every.events(5)
    check("a key's stream has every change, in order, each once",
          [(e[1], e[2]["collection"], e[2]["id"]) for e in evs],
          [("put", "notes", "a"), ("put", "chars", "alice1"), ("put", "chars", "bob1"), ("put", "notes", "a"),
           ("delete", "chars", "alice1")])
    check("numbered as the database counts its changes", [e[0] for e in evs] == sorted(e[0] for e in evs) and len({e[0] for e in evs}) == 5, True)
    check("a put carries the document as it now is", (evs[3][2]["version"], evs[3][2]["doc"]), (2, {"n": 2}))
    m = mine.events(2)
    check("an account's stream of an owner collection has its own documents alone",
          [(e[1], e[2]["id"]) for e in m], [("put", "alice1"), ("delete", "alice1")])
    check("and no other's", mine.events(1, 0.5), [])
    last = evs[1][0]
    every.close()
    # Resumed from the second change: the three after it, and nothing twice.
    again = stream(pd, "/_feed", dict(KEY, **{"Last-Event-ID": str(last)}))
    r = again.events(3)
    check("a stream resumed from a change it read has every one after it", [e[0] for e in r], [e[0] for e in evs[2:]])
    again.close()
    gone = stream(pd, "/c/notes/_feed?since=999999", KEY)
    check("one resumed from a change the database never made is told to read again", gone.events(1)[0][1], "reset")
    gone.close()
    with open(tmpd + "/feed.last", "w") as f:
        f.write(str(evs[-1][0]))

elif phase == "ttl":
    ca = sign_in("alice", "alicepassword1")
    feed = stream(pd, "/c/sessions/_feed", {"Cookie": ca})
    now = int(time.time())
    db(pd, "PUT", "/c/sessions/s1", {"exp": now + 2}, {"Cookie": ca})
    db(pd, "PUT", "/c/sessions/s2", {"exp": now + 3600}, {"Cookie": ca})
    check("a session is there before its time", db(pd, "GET", "/c/sessions/s1", headers={"Cookie": ca})[0], 200)
    time.sleep(3.2)
    check("and gone after it", db(pd, "GET", "/c/sessions/s1", headers={"Cookie": ca})[0], 404)
    check("from a query too", [d["_id"] for d in db(pd, "POST", "/c/sessions/_query", {}, {"Cookie": ca})[1]["docs"]], ["s2"])
    evs = feed.events(3, 3)
    check("its deletion is written and streamed", [(e[1], e[2]["id"]) for e in evs], [("put", "s1"), ("put", "s2"), ("delete", "s1")])

elif phase == "replica":
    # Everything there already, then what changes, then a write refused.
    for _ in range(100):
        st, d = db(pr, "GET", "/c/notes/a", headers=KEY)
        if st == 200:
            break
        time.sleep(0.1)
    check("a replica takes a whole copy of what is there", (st, d.get("n") if st == 200 else None), (200, 2))
    check("every document", db(pr, "POST", "/c/chars/_query", {"count": True}, KEY)[1], db(pd, "POST", "/c/chars/_query", {"count": True}, KEY)[1])
    db(pd, "PUT", "/c/notes/live", {"n": 7}, KEY)
    db(pd, "DELETE", "/c/notes/a", headers=KEY)
    for _ in range(100):
        if db(pr, "GET", "/c/notes/live", headers=KEY)[0] == 200 and db(pr, "GET", "/c/notes/a", headers=KEY)[0] == 404:
            break
        time.sleep(0.1)
    check("and every change after it", (db(pr, "GET", "/c/notes/live", headers=KEY)[1].get("n"), db(pr, "GET", "/c/notes/a", headers=KEY)[0]), (7, 404))
    st, d = db(pr, "PUT", "/c/notes/x", {"n": 1}, KEY)
    check("a replica refuses a write and names where to make it", (st, d.get("error")), (403, "read_only"))
    check("but answers a query", db(pr, "POST", "/c/notes/_query", {"where": {"n": 7}}, KEY)[1]["docs"][0]["_id"], "live")
    feed = stream(pr, "/_feed", KEY)
    db(pd, "PUT", "/c/notes/chained", {"n": 8}, KEY)
    check("and streams what it is told, to its own readers", [e[2]["id"] for e in feed.events(1)], ["chained"])

elif phase == "replica_after":
    db(pd, "PUT", "/c/notes/after", {"n": 9}, KEY)
    for _ in range(100):
        if db(pr, "GET", "/c/notes/after", headers=KEY)[0] == 200:
            break
        time.sleep(0.1)
    check("after a restart the replica goes on from where it was", db(pr, "GET", "/c/notes/after", headers=KEY)[1].get("n"), 9)
    a = db(pd, "POST", "/c/notes/_query", {"limit": 1000}, KEY)[1]["docs"]
    b = db(pr, "POST", "/c/notes/_query", {"limit": 1000}, KEY)[1]["docs"]
    check("and holds what the one it copies holds", b, a)

elif phase == "many":
    pad = "x" * 2000
    for i in range(2000):
        st, _ = db(pd, "PUT", "/c/notes/m%d" % i, {"n": i, "pad": pad}, KEY)
        if st != 201:
            check("a document past the cache is written", st, 201)
            break
    wrong = [i for i in range(0, 2000, 7) if db(pd, "GET", "/c/notes/m%d" % i, headers=KEY)[1].get("n") != i]
    check("documents past the cache read back as written", wrong, [])
    st, d = db(pd, "POST", "/c/notes/_query", {"where": {"n": {"gte": 1990}}, "sort": "-n"}, KEY)
    check("and a query over them answers from the disk", [x["n"] for x in d["docs"]], list(range(1999, 1989, -1)))

elif phase == "restored":
    check("a restore brings the documents of the backup back", db(pd, "GET", "/c/notes/backed", headers=KEY)[1].get("v"), 1)
    check("and not one made after it", db(pd, "GET", "/c/notes/later", headers=KEY)[0], 404)
PY
}

tally < <(run stream)
tally < <(run ttl)
stat_at_least data expired 1 && ok || bad "stats count the documents whose time came" "$(stat_of data expired)"

# ── A replica, on a runtime of its own ────────────────────────────────────────
out=$("$BIN" create db rx -p "$PR" --replicate "http://127.0.0.1:$PD" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "a replica without the key it asks with is refused" "rc $rc: $out"
# Through a proxy, as a replica on another machine reaches the database through its entrance: the stream is
# passed on as it comes, not held until it ends.
PF=$((SL_PORT_BASE + 1984))
"$BIN" create proxy front -p "$PF" --backend "127.0.0.1:$PD" --protocol http -s >/dev/null 2>&1 \
    && ok || bad "a proxy in front of the database is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create db replica -p "$PR" --schema "$T/schema" --keys "$T/keys" --replicate "http://127.0.0.1:$PF/front" \
    --replicate-key "$T/replica.key" -s >/dev/null 2>&1 && ok || bad "a replica is made" "$(tail -3 "$SOCKETLEY_DLOG")"
up "$PR"
tally < <(run replica)
resets=$(stat_of replica resets)
"$BIN" stop replica >/dev/null 2>&1; "$BIN" start replica >/dev/null 2>&1; up "$PR"
"$BIN" stop data >/dev/null 2>&1; "$BIN" start data >/dev/null 2>&1; up "$PD"
sleep 2.5
tally < <(run replica_after)
expect "neither restart made the replica take a whole copy again" "$(stat_of replica resets)" "$resets"
case "$("$BIN" stats replica 2>&1)" in *"replica_state:following"*) ok ;; *) bad "stats say the replica follows" "$("$BIN" stats replica | grep replica)" ;; esac
"$BIN" show replica > "$T/replica.json"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['replicate']=''; json.dump(d,open(sys.argv[1],'w'))" "$T/replica.json"
"$BIN" import replica --restart < "$T/replica.json" >/dev/null 2>&1; up "$PR"
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer streamsecret0123456789" \
    -H "Content-Type: application/json" -d '{"n":1}' "http://127.0.0.1:$PR/c/notes/promoted")
expect "a replica told it copies nothing is a database of its own, written to" "$code" "201"

# ── Backups ───────────────────────────────────────────────────────────────────
curl -s -o /dev/null -X PUT -H "Authorization: Bearer streamsecret0123456789" -H "Content-Type: application/json" \
    -d '{"v":1}' "http://127.0.0.1:$PD/c/notes/backed"
out=$("$BIN" db-backup data "$T/one.dbbackup" 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ -z "$out" ] && [ -s "$T/one.dbbackup" ] && ok || bad "db-backup writes the file, silent on success" "rc $rc: $out"
out=$("$BIN" db-backup data relative.dbbackup 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ -s "$PWD/relative.dbbackup" ] && ok || bad "a relative backup path is the caller's" "rc $rc: $out"
rm -f "$PWD/relative.dbbackup"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer streamsecret0123456789" -H "Content-Type: application/json" \
    -d '{"v":2}' "http://127.0.0.1:$PD/c/notes/later"
printf 'not a backup' > "$T/bad.dbbackup"
out=$("$BIN" db-restore data "$T/bad.dbbackup" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "a file that is no backup is refused, and nothing changed" "rc $rc: $out"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer streamsecret0123456789" "http://127.0.0.1:$PD/c/notes/later")" = 200 ] \
    && ok || bad "the documents are untouched after a refused restore" "later is gone"
out=$("$BIN" db-restore data "$T/one.dbbackup" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok || bad "db-restore takes a backup" "rc $rc: $out"
up "$PD"
tally < <(run restored)
[ -d "$(dirname "$(find "$T/home" -path '*/db/data' -type d | head -1)")/data.before-restore" ] && ok \
    || bad "the documents before a restore are kept aside" "$(find "$T/home" -path '*/db/*' -maxdepth 8 -type d | head)"

mkdir -p "$T/backups"
"$BIN" create db sched -p "$PB" --keys "$T/keys" --backup-dir "$T/backups" --backup-every 1s --backup-keep 2 -s >/dev/null 2>&1 \
    && ok || bad "a db with scheduled backups is made" "$(tail -3 "$SOCKETLEY_DLOG")"
up "$PB"
curl -s -o /dev/null -X PUT -H "Authorization: Bearer streamsecret0123456789" -H "Content-Type: application/json" \
    -d '{"s":1}' "http://127.0.0.1:$PB/c/x/y"
sleep 4.5
n=$(ls "$T/backups" | grep -c '^sched-.*\.dbbackup$')
[ "$n" -eq 2 ] && ok || bad "scheduled backups are taken and the newest --backup-keep kept" "$(ls "$T/backups")"
stat_at_least sched backups 3 && ok || bad "stats count the backups taken" "$(stat_of sched backups)"

# ── More documents than the cache holds ───────────────────────────────────────
cfg=$("$BIN" show data)
echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); d['cache']=1048576; print(json.dumps(d))" > "$T/data.json"
"$BIN" import data --restart < "$T/data.json" >/dev/null 2>&1; up "$PD"
tally < <(run many)
stat_at_least data cache_misses 1 && ok || bad "reads past the cache come from the disk" "$(stat_of data cache_misses)"

# ── Idle ──────────────────────────────────────────────────────────────────────
# Every worker of this daemon, the databases with backups, a replica's thread and streams among them, over two
# quiet seconds: a loop that spins on a wakeup that never blocks shows here as a whole core.
"$BIN" stop sched >/dev/null 2>&1
sleep 1.5
cpu() { local s=0; for p in $(pgrep -P "$SOCKETLEY_DPID"); do s=$((s + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done; echo $s; }
a=$(cpu); sleep 2; b=$(cpu)
[ $((b - a)) -le 20 ] && ok || bad "idle databases use next to no CPU" "$((b - a)) ticks in 2 s"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
