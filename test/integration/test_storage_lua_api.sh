#!/usr/bin/env bash
# Integration test: socketley.storage, a script in one runtime using another's storage.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   calls       put, get, head, delete and list from a server's handler, waiting
#               on the answer without stopping the daemon, against an object
#               store in another process; what a script puts is what an S3 client
#               reads, with its content type, user metadata and S3's default
#               CRC64NVME, and the other way round, byte for byte for binary data
#   lists       prefix, delimiter, max_keys and the token that pages through
#               all of them return the keys an S3 listing does
#   errors      NoSuchKey, NoSuchBucket, an invalid bucket name, an object over
#               the 1 MiB a script may move, a runtime that is not there, a call
#               shaped wrongly and a wait asked of a callback that cannot wait
#               each answer nil and a reason, and never raise or hang
#   callbacks   the last argument as a function is called with the answer, from
#               a server's handler, a cache's on_write and a proxy's filter, none
#               of which can wait
#   stop        a client that shuts its writing side after its line still gets
#               the answer, as it does for a linked cache; the calls follow the
#               storage runtime through a stop and a start
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stglapi

P=$((SL_PORT_BASE+1690))
T="$SOCKETLEY_TMPD"
export SL_APILOG="$T/api.log"
: > "$SL_APILOG"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi; }

RT="la_stg la_srv la_cache la_proxy"
cleanup() {
    for r in $RT; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in $RT; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: socketley.storage from another runtime's script ==="
for tool in curl python3 nc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  SKIP: $tool is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
done

cat > "$T/server.lua" <<'LUA'
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function unhex(h) return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) end
local function say(id, ...) self.send(id, table.concat({...}, " ")) end
local function show(v) return tostring(v) end

function on_connect(client_id)
    -- on_connect cannot wait, so a call without a callback is refused, not hung.
    local a, why = socketley.storage.get("la_stg", "bkt", "seed")
    self.send(client_id, "connect " .. show(a) .. " " .. show(why))
end

function on_client_message(client_id, msg)
    local w = {}
    for x in msg:gmatch("%S+") do w[#w + 1] = x end
    local cmd = w[1]
    if cmd == "put" then
        local r, code, message = socketley.storage.put("la_stg", w[2], w[3], unhex(w[4]),
            { content_type = "text/x-api", metadata = { Owner = "alice", N = 7 } })
        if not r then return say(client_id, "err", show(code), show(message)) end
        say(client_id, "ok", r.etag, r.size, r.content_type, show(r.metadata.owner), show(r.metadata.n))
    elseif cmd == "putn" then
        local n = tonumber(w[3])
        local r, code, message = socketley.storage.put("la_stg", "bkt", w[2], string.rep("a", n))
        if not r then return say(client_id, "err", show(code), show(message)) end
        say(client_id, "ok", r.etag, r.size)
    elseif cmd == "get" then
        local data, meta, message = socketley.storage.get("la_stg", w[2], w[3])
        if not data then return say(client_id, "err", show(meta), show(message)) end
        say(client_id, "data", hex(data), meta.size, meta.content_type, show(meta.metadata.owner), meta.etag, show(meta.mtime_ms > 0))
    elseif cmd == "getlen" then
        local data, meta, message = socketley.storage.get("la_stg", "bkt", w[2])
        if not data then return say(client_id, "err", show(meta), show(message)) end
        say(client_id, "len", #data)
    elseif cmd == "head" then
        local meta, code = socketley.storage.head("la_stg", "bkt", w[2])
        if not meta then return say(client_id, "err", show(code)) end
        say(client_id, "head", meta.size, meta.etag, meta.content_type)
    elseif cmd == "del" then
        local ok, code = socketley.storage.delete("la_stg", "bkt", w[2])
        say(client_id, show(ok), show(code))
    elseif cmd == "list" then
        local prefix = w[2] ~= "-" and w[2] or ""
        local opts = {}
        if w[3] and w[3] ~= "-" then opts.delimiter = w[3] end
        if w[4] and w[4] ~= "-" then opts.max_keys = tonumber(w[4]) end
        if w[5] and w[5] ~= "-" then opts.start_after = w[5] end
        local l, code = socketley.storage.list("la_stg", "bkt", prefix, opts)
        if not l then return say(client_id, "err", show(code)) end
        local keys = {}
        for _, o in ipairs(l.objects) do keys[#keys + 1] = o.key end
        say(client_id, "keys=" .. table.concat(keys, ","), "prefixes=" .. table.concat(l.prefixes, ","),
            "truncated=" .. show(l.truncated), "next=" .. show(l.next))
    elseif cmd == "cb" then
        local started, why = socketley.storage.get("la_stg", "bkt", w[2], function(data, meta, message)
            say(client_id, "cb", show(data), show(type(meta) == "table" and meta.size or meta), show(message))
        end)
        say(client_id, "started", show(started), show(why))
    elseif cmd == "cbraise" then
        local started = socketley.storage.get("la_stg", "bkt", w[2], function() error("raised on purpose") end)
        say(client_id, "started", show(started))
    elseif cmd == "elsewhere" then
        local a, b = socketley.storage.get("no_such_runtime", "bkt", "k")
        say(client_id, "elsewhere", show(a), show(b))
    elseif cmd == "usage" then
        local a, b = socketley.storage.put("la_stg", "bkt")
        local c, d = socketley.storage.list("la_stg", "bkt", "", { bogus = 1 })
        local e, f = socketley.storage.put("la_stg", "bkt", "k", "v", { content_type = 5 })
        say(client_id, "usage", show(a), show(b):sub(1, 30), show(c), show(d):sub(1, 30), show(e), show(f):sub(1, 30))
    end
end
LUA

cat > "$T/cache.lua" <<'LUA'
local logf = assert(io.open(os.getenv("SL_APILOG"), "a"))
logf:setvbuf("line")
function on_write(key, value, ttl)
    socketley.storage.put("la_stg", "bkt", "mirror/" .. key, value, function(meta, code)
        logf:write("cache|", key, "|", tostring(meta and meta.etag), "|", tostring(code), "\n")
    end)
end
LUA

cat > "$T/proxy.lua" <<'LUA'
local logf = assert(io.open(os.getenv("SL_APILOG"), "a"))
logf:setvbuf("line")
local n = 0
filters = {
    function(req)
        n = n + 1
        socketley.storage.put("la_stg", "bkt", "audit/hit-" .. n, req.path, function(meta, code)
            logf:write("proxy|", req.path, "|", tostring(meta and meta.size), "|", tostring(code), "\n")
        end)
    end,
}
LUA

daemon_start "$BIN"
"$BIN" create storage la_stg -p "$P" --dir "$T/stg" --anonymous -s >/dev/null 2>&1 || bad "create" "la_stg"
S="http://127.0.0.1:$P"
code() { curl -s -o "$T/body.out" -w '%{http_code}' "$@"; }
for _ in $(seq 1 100); do [ "$(code "$S/")" = 200 ] && break; sleep 0.1; done
code -X PUT "$S/bkt" > /dev/null
head -c 102400 /dev/urandom > "$T/blob"
curl -s -X PUT --data-binary "callback text" "$S/bkt/cbtext" -o /dev/null
curl -s -X PUT -H 'content-type: image/x-blob' -H 'x-amz-meta-owner: bob' --data-binary @"$T/blob" "$S/bkt/seed" -o /dev/null

"$BIN" create server la_srv -p $((P+1)) --lua "$T/server.lua" --read-buffer 8M -s >/dev/null 2>&1 || bad "create" "la_srv"
for _ in $(seq 1 100); do nc -z 127.0.0.1 $((P+1)) 2>/dev/null && break; sleep 0.1; done

# One connection per line, kept open until the answer, because a handler that
# waits answers on a later turn; the first line the server says on connect is
# read and reported apart.
ask() {   # line [timeout]
    python3 - "$((P+1))" "$1" "${2:-8}" <<'PYEOF'
import socket, sys
port, line, tmo = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port))
s.settimeout(tmo)
buf = b""
def read_line():
    global buf
    while b"\n" not in buf:
        d = s.recv(1 << 20)
        if not d:
            break
        buf += d
    l, _, buf = buf.partition(b"\n")
    return l.decode(errors="replace")
first = read_line()
s.sendall(line.encode() + b"\n")
try:
    print(read_line())
except socket.timeout:
    print("TIMEOUT")
PYEOF
}

# ── on_connect cannot wait ──────────────────────────────────────────────────
conn=$(python3 - "$((P+1))" <<'PYEOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(5)
print(s.recv(4096).decode().strip())
PYEOF
)
contains "a call that must wait is refused in a callback that cannot, with the way out" "$conn" "connect nil get waits for an answer"
contains "and the message names the callback form" "$conn" "pass a function as the last argument"

# ── put, and what an S3 client reads ────────────────────────────────────────
hello=$(printf 'hello from lua' | od -An -tx1 | tr -d ' \n')
out=$(ask "put bkt greeting $hello")
want=$(printf 'hello from lua' | md5sum | cut -d' ' -f1)
expect "put answers the ETag, size, content type and user metadata" "$out" "ok $want 14 text/x-api alice 7"
expect "an S3 client reads the object" "$(curl -s "$S/bkt/greeting")" "hello from lua"
hdrs=$(curl -s -I "$S/bkt/greeting" | tr -d '\r')
contains "with the content type" "$hdrs" "Content-Type: text/x-api"
contains "and the user metadata, lowercased" "$hdrs" "x-amz-meta-owner: alice"
contains "and a number written as its text" "$hdrs" "x-amz-meta-n: 7"
crc=$(cd "$HERE" && python3 -c 'import lib_s3_signing as s; print(s.crc64nvme_b64(b"hello from lua"))')
contains "and S3's default checksum, the CRC64NVME of its bytes, as a client's put gets" \
    "$(curl -s -I -H 'x-amz-checksum-mode: ENABLED' "$S/bkt/greeting" | tr -d '\r')" "x-amz-checksum-crc64nvme: $crc"

# ── get, head, and binary data ──────────────────────────────────────────────
out=$(ask "get bkt seed")
got=$(printf '%s' "$out" | python3 -c '
import sys
parts = sys.stdin.read().split(" ")
want = open(sys.argv[1], "rb").read()
ok = parts[0] == "data" and bytes.fromhex(parts[1]) == want and parts[2] == str(len(want)) and parts[3] == "image/x-blob" and parts[4] == "bob" and parts[6] == "true"
print("same" if ok else "different: " + " ".join(p[:40] for p in parts))
' "$T/blob")
expect "get returns the bytes an S3 client put, binary and whole, with its metadata" "$got" "same"
etag=$(curl -s -I "$S/bkt/seed" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: "\(.*\)"/\1/p')
contains "and the ETag" "$out" " $etag "
size=$(stat -c %s "$T/blob")
expect "head answers the size, ETag and type" "$(ask "head seed")" "head $size $etag image/x-blob"

# ── delete ──────────────────────────────────────────────────────────────────
expect "delete answers true" "$(ask "del greeting")" "true nil"
expect "and the object is gone for an S3 client" "$(code "$S/bkt/greeting")" 404
expect "deleting what is not there is true too, as S3 answers" "$(ask "del greeting")" "true nil"

# ── list ────────────────────────────────────────────────────────────────────
for i in $(seq -w 0 24); do curl -s -X PUT --data-binary "$i" "$S/bkt/p/$i" -o /dev/null; done
curl -s -X PUT --data-binary z "$S/bkt/p/sub/deep" -o /dev/null
expect "list with a prefix and a delimiter rolls a directory up" \
    "$(ask "list p/ / - -" | sed 's/keys=\([^ ]*\).*prefixes=\([^ ]*\) .*/\2/')" "p/sub/"
all=""
after="-"
for page in 1 2 3 4 5 6; do
    r=$(ask "list p/ - 10 $after")
    ks=$(echo "$r" | sed 's/^keys=\([^ ]*\) .*/\1/')
    all="$all,$ks"
    nx=$(echo "$r" | sed 's/.*next=\(.*\)$/\1/')
    case "$r" in *"truncated=true"*) after=$nx ;; *) break ;; esac
done
got_all=$(echo "$all" | tr ',' '\n' | grep -v '^$' | sort | tr '\n' ' ')
want_all=$(curl -s "$S/bkt?list-type=2&prefix=p/&max-keys=1000" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' | sort | tr '\n' ' ')
expect "paging with max_keys and next visits every key an S3 listing has" "$got_all" "$want_all"
first=$(ask "list p/ - 10 -")
contains "and the first page says it is truncated" "$first" "truncated=true"

# ── errors ──────────────────────────────────────────────────────────────────
expect "a missing key is nil and NoSuchKey with S3's message" "$(ask "get bkt nothing-here")" "err NoSuchKey The specified key does not exist."
contains "a missing bucket is NoSuchBucket" "$(ask "get nobucket k")" "err NoSuchBucket"
contains "a bucket name S3 forbids is InvalidBucketName" "$(ask "put ab k 61")" "err InvalidBucketName"
contains "an object over 1 MiB is refused before it is sent" "$(ask "putn big 1048577")" "a script may move at most 1048576"
out=$(ask "putn edge 1048576" 20)
contains "and exactly 1 MiB is stored" "$out" "ok "
expect "and read back whole over the S3 port" "$(curl -s "$S/bkt/edge" | wc -c)" 1048576
expect "and by a script" "$(ask "getlen edge" 20)" "len 1048576"
head -c 2097152 /dev/zero > "$T/two"
curl -s -X PUT --data-binary @"$T/two" "$S/bkt/two" -o /dev/null
contains "reading an object over 1 MiB is EntityTooLarge" "$(ask "getlen two" 20)" "err EntityTooLarge"
expect "a runtime that is not there is nil and a reason" "$(ask "elsewhere")" "elsewhere nil no such runtime"
usage=$(ask "usage")
contains "a call shaped wrongly is refused with its usage" "$usage" "usage nil usage: socketley.storage.put("
contains "an option nobody defined is refused, not ignored" "$usage" "unknown option 'bogus'"
contains "and one of the wrong type is named" "$usage" "content_type must be a string"

# ── a client that shuts its writing side still gets its answer ──────────────
out=$( { python3 - "$((P+1))" <<'PYEOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(8)
s.recv(4096)
s.sendall(b"head seed\n")
s.shutdown(socket.SHUT_WR)
buf = b""
while True:
    try:
        d = s.recv(4096)
    except socket.timeout:
        break
    if not d:
        break
    buf += d
print(buf.decode().strip())
PYEOF
} )
contains "a client that sent its line and shut down its writing side gets the answer" "$out" "head $size"

# ── callbacks, where a callback cannot wait ─────────────────────────────────
out=$(python3 - "$((P+1))" <<'PYEOF'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(8)
s.recv(4096)
s.sendall(b"cb cbtext\n")
buf = b""
t0 = time.time()
while buf.count(b"\n") < 2 and time.time() - t0 < 8:
    try:
        d = s.recv(4096)
    except socket.timeout:
        break
    if not d:
        break
    buf += d
print(" | ".join(buf.decode().strip().split("\n")))
PYEOF
)
contains "a callback call answers true at once" "$out" "started true nil"
contains "and is called with the object and its metadata" "$out" "cb "
contains "the callback gets the data, then the metadata table" "$out" "cb callback text 13 nil"
out=$(ask "cbraise cbtext")
found=no
for _ in $(seq 1 50); do grep -qa "\[lua la_srv\] a socketley.storage callback raised: .*raised on purpose" "$SOCKETLEY_DLOG" 2>/dev/null && { found=yes; break; }; sleep 0.1; done
contains "a callback that raises is reported under its runtime's name" "$out $found" "started true yes"

"$BIN" create cache la_cache -p $((P+2)) --lua "$T/cache.lua" -s >/dev/null 2>&1 || bad "create" "la_cache"
for _ in $(seq 1 100); do nc -z 127.0.0.1 $((P+2)) 2>/dev/null && break; sleep 0.1; done
printf 'set colour green\r\n' | nc -q1 127.0.0.1 $((P+2)) > /dev/null
for _ in $(seq 1 50); do grep -q '^cache|' "$SL_APILOG" && break; sleep 0.1; done
want=$(printf 'green' | md5sum | cut -d' ' -f1)
contains "a cache's on_write puts into storage from a callback that cannot wait" "$(cat "$SL_APILOG")" "cache|colour|$want|nil"
expect "and the object is there for an S3 client" "$(curl -s "$S/bkt/mirror/colour")" "green"

"$BIN" create proxy la_proxy -p $((P+3)) --backend la_stg --lua "$T/proxy.lua" -s >/dev/null 2>&1 || bad "create" "la_proxy"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+3))/la_proxy/")" = 200 ] && break; sleep 0.1; done
curl -s -o /dev/null "http://127.0.0.1:$((P+3))/la_proxy/bkt/seed"
for _ in $(seq 1 50); do grep -q '^proxy|/la_proxy/bkt/seed' "$SL_APILOG" && break; sleep 0.1; done
contains "a proxy's filter puts into storage from a callback that cannot wait" "$(cat "$SL_APILOG")" "proxy|/la_proxy/bkt/seed|18|nil"
cnt=$(curl -s "$S/bkt?list-type=2&prefix=audit/" | grep -o '<Key>' | wc -l)
if [ "$cnt" -ge 1 ]; then ok "and the audit objects are there for an S3 client ($cnt)"; else bad "the proxy's audit objects" "$cnt"; fi

# ── following the storage runtime through a stop ────────────────────────────
"$BIN" stop la_stg >/dev/null 2>&1
sleep 0.5
expect "with the storage runtime stopped the call answers nil and a reason" "$(ask "head seed")" "err no such runtime"
"$BIN" start la_stg >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(code "$S/")" = 200 ] && break; sleep 0.1; done
sleep 0.5
expect "and after it is started again the same call is answered" "$(ask "head seed")" "head $size $etag image/x-blob"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
