#!/usr/bin/env bash
# Integration test: the storage features working together, at one shard and at four.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# One runtime with TLS, credentials and a script, driven by boto3 over https, and
# the same again split over four shards (whose connections land wherever the
# kernel puts them, so a multipart upload's calls reach different shards):
#
#   checksums     put_object with each algorithm, upload_file in parts (plain and
#                 with a checksum) and the multipart calls one by one work over
#                 https with credentials, and a signed aws-chunked body with a
#                 trailer inside an outer Transfer-Encoding: chunked is stored
#   on_put        a completed multipart upload fires the script's on_put once, with
#                 the object, and no part of it does; the keys told of are exactly
#                 the keys that were put
#   on_request    sees CreateMultipartUpload, UploadPart, UploadPartCopy,
#                 CompleteMultipartUpload, AbortMultipartUpload, ListParts and
#                 ListMultipartUploads by those names, and may refuse them
#   shards        parts and completions crossed between shards and every crossing
#                 sent was served; every shard did TLS handshakes; the metrics
#                 series add the shards up (objects) or take one (buckets)
#   credentials   a credentials file is read again by every shard: a key added
#                 works, a key taken out stops, a file that stops parsing keeps
#                 the keys in force
#   proxy         a proxy in front of a sharded runtime carries puts and gets
#   script API    socketley.storage put, get, head, list and delete against a
#                 sharded runtime, for keys every shard owns
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stge2e

MPORT=$((SL_PORT_BASE+1574))
P1=$((SL_PORT_BASE+1575))
P4=$((SL_PORT_BASE+1576))
PC=$((SL_PORT_BASE+1577))
PB=$((SL_PORT_BASE+1578))
PP=$((SL_PORT_BASE+1579))
PS=$((SL_PORT_BASE+1580))
T="$SOCKETLEY_TMPD"
CERTS="$T/certs"
AK="AKIAE2EACCESSKEY01"
SK="e2e/secret+key/for.storage.sigv4"
export SL_HOOKLOG="$T/hook.log"
: > "$SL_HOOKLOG"

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

cleanup() {
    for r in e2e1 e2e4 e2ecr e2ebk e2epx e2esv; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in e2e1 e2e4 e2ecr e2ebk e2epx e2esv; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage over https with credentials, multipart and hooks, at one shard and at four ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  SKIP: $tool is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
done
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

mkdir -p "$CERTS" "$HOME/.config/socketley"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTS/srv-key.pem" -out "$CERTS/srv.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
[ -s "$CERTS/srv.pem" ] || { echo "  SKIP: openssl could not generate the test certificate"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cat > "$HOME/.config/socketley/config.lua" <<LUA
config = { metrics_port = $MPORT }
LUA
# run_all.sh exports SOCKETLEY_CONFIG, which is also the daemon's config path and
# would hide the file above: the metrics series then read empty in the suite only.
unset SOCKETLEY_CONFIG

cat > "$T/hooks.lua" <<'LUA'
local logf = assert(io.open(os.getenv("SL_HOOKLOG"), "a"))
logf:setvbuf("line")

function on_request(req)
    logf:write("req|", req.method, "|", req.operation, "|", req.bucket, "|", req.key, "\n")
    if req.key:sub(1, 7) == "forbid/" and (req.operation == "CreateMultipartUpload" or req.operation == "PutObject") then
        return false
    end
end

function on_put(bucket, key, meta)
    logf:write("put|", bucket, "|", key, "|", meta.size, "|", meta.etag, "\n")
end
LUA

daemon_start "$BIN"

tls_up() {   # port
    for _ in $(seq 1 150); do
        [ "$(curl -s --cacert "$CERTS/srv.pem" -o /dev/null -w '%{http_code}' "https://localhost:$1/")" = 403 ] && return 0
        sleep 0.1
    done
    return 1
}
stat_sum() {   # runtime key -> the key summed over the shard sections
    "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1==k {s+=$2} END {print s+0}'
}
stat_shards_with() {   # runtime key -> how many sections have the key above zero
    "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1==k && $2>0 {c++} END {print c+0}'
}
metric() {   # series
    curl -s --max-time 5 "http://127.0.0.1:$MPORT/metrics" | awk -v n="$1" '$1==n {print $2; exit}'
}
series_is() {   # label series want
    local got=""
    for _ in $(seq 1 60); do
        got=$(metric "$2")
        [ "$got" = "$3" ] && { ok "$1"; return 0; }
        sleep 0.25
    done
    bad "$1" "$2 is '$got', want '$3'"
}
run_py() {   # port mode [args]   -> counted into the totals
    local out rc p f
    out=$(python3 "$HERE/lib_storage_e2e.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL)'
    p=$(echo "$out" | grep -c '^  PASS'); f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "the library ran" "exit $rc: $(echo "$out" | tail -5)"; fi
}

arm() {   # shards port
    local n=$1 port=$2 name="e2e$1"
    echo "== $n shard(s), https, credentials, a script =="
    : > "$SL_HOOKLOG"
    "$BIN" create storage "$name" -p "$port" --dir "$T/data$n" --access-key "$AK" --secret-key "$SK" \
        --tls --cert "$CERTS/srv.pem" --key "$CERTS/srv-key.pem" --lua "$T/hooks.lua" --shards "$n" -s >/dev/null 2>&1
    expect "the runtime is made and started" "$?" 0
    tls_up "$port" && ok "it answers over https" || { bad "it answers over https" "no answer on $port"; return; }
    expect "an unsigned request is refused" "$(curl -s --cacert "$CERTS/srv.pem" -o /dev/null -w '%{http_code}' "https://localhost:$port/")" 403

    run_py "$port" "$CERTS/srv.pem" main "$T/expect$n"

    # ── on_put and on_request ──
    sleep 0.5
    local told want
    told=$(grep '^put|' "$SL_HOOKLOG" | cut -d'|' -f3 | sort)
    want=$(cat "$T/expect$n" 2>/dev/null)
    if [ "$told" = "$want" ] && [ -n "$want" ]; then ok "on_put was told of exactly the $(echo "$want" | wc -l) objects put, once each, a completed upload among them"
    else bad "on_put was told of the keys put" "told: $(echo "$told" | tr '\n' ' ')" "want: $(echo "$want" | tr '\n' ' ')"; fi
    if grep -q '^put|[^|]*|mpu/' "$SL_HOOKLOG"; then bad "no part fires on_put" "$(grep '^put|[^|]*|mpu/' "$SL_HOOKLOG" | head -3)"; else ok "no part of an upload fires on_put"; fi
    local ops
    ops=$(grep '^req|' "$SL_HOOKLOG" | cut -d'|' -f3 | sort -u | tr '\n' ' ')
    for op in CreateMultipartUpload UploadPart UploadPartCopy CompleteMultipartUpload AbortMultipartUpload \
              ListParts ListMultipartUploads PutObject GetObject HeadObject; do
        if has "$ops " "$op "; then ok "on_request saw $op by name"; else bad "on_request saw $op" "saw: $ops"; fi
    done
    if grep -q '^req|[A-Z]*|Unknown|' "$SL_HOOKLOG"; then bad "no request the tests made is named Unknown" "$(grep -m3 '|Unknown|' "$SL_HOOKLOG")"; else ok "no request the tests made is named Unknown"; fi

    # ── what an upload leaves on the disk ──
    local left=1
    for _ in $(seq 1 40); do
        left=$(find "$T/data$n/e2ebkt/mpu" -mindepth 1 2>/dev/null | wc -l)
        [ "$left" = 0 ] && break
        sleep 0.25
    done
    expect "no upload directory or part file is left on the disk" "$left" 0
    expect "and nothing is left in tmp/" "$(ls "$T/data$n/e2ebkt/tmp" | wc -l)" 0

    # ── stats and metrics ──
    local uniq
    uniq=$(sort -u "$T/expect$n" | wc -l)
    series_is "metrics: the runtime's objects are the sum over its shards" "socketley_storage_objects{name=\"$name\"}" "$uniq"
    series_is "metrics: its one bucket is one, not one per shard" "socketley_storage_buckets{name=\"$name\"}" 1
    series_is "metrics: the wrong-secret answers of every shard are added up" "socketley_storage_errors_total{name=\"$name\",code=\"SignatureDoesNotMatch\"}" 24
    series_is "metrics: and the unknown-key answers" "socketley_storage_errors_total{name=\"$name\",code=\"InvalidAccessKeyId\"}" 24
    series_is "metrics: a figure with no family of its own is a stat series, summed over the shards" \
        "socketley_storage_stat{name=\"$name\",stat=\"multipart_created\"}" "$(stat_sum "$name" multipart_created)"
    if [ "$n" -gt 1 ]; then
        local sent served hs
        sent=$(stat_sum "$name" shard_mpu_sent); served=$(stat_sum "$name" shard_mpu_served)
        [ "$sent" -gt 0 ] && ok "multipart steps crossed between shards ($sent)" || bad "no multipart step crossed" "$sent"
        expect "and every one sent was served" "$served" "$sent"
        expect "no crossing failed" "$(stat_sum "$name" shard_peer_failures)" 0
        hs=$(stat_shards_with "$name" tls_handshakes)
        [ "$hs" -ge 2 ] && ok "TLS handshakes were made on $hs shards" || bad "TLS on one shard only" "$hs"
        expect "every shard has TLS on" "$(stat_shards_with "$name" tls)" "$n"
    else
        expect "at one shard nothing crossed" "$(stat_sum "$name" shard_mpu_sent)" 0
    fi
    "$BIN" stop "$name" >/dev/null 2>&1
    sleep 0.5
}

arm 1 "$P1"
arm 4 "$P4"

echo "== a credentials file, read by every shard =="
printf '# e2e\nAKIAONE:secret-one\nAKIATWO:secret-two\n' > "$T/creds"
"$BIN" create storage e2ecr -p "$PC" --dir "$T/datacr" --credentials "$T/creds" --shards 4 -s >/dev/null 2>&1
expect "a sharded runtime with a credentials file is made" "$?" 0
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PC/")" = 403 ] && break; sleep 0.1; done
run_py "$PC" "$T/creds" creds

echo "== a proxy in front of a sharded runtime =="
"$BIN" create storage e2ebk -p "$PB" --dir "$T/databk" --anonymous --shards 4 -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PB/")" = 200 ] && break; sleep 0.1; done
"$BIN" create proxy e2epx -p "$PP" --backend e2ebk --protocol tcp -s >/dev/null 2>&1
expect "a proxy naming the sharded runtime is made" "$?" 0
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PP/")" = 200 ] && break; sleep 0.1; done
expect "a bucket is made through the proxy" "$(curl -s -o /dev/null -w '%{http_code}' -X PUT "http://127.0.0.1:$PP/pxb")" 200
badp=0; badg=0
for i in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary "via-proxy-$i" "http://127.0.0.1:$PP/pxb/k$i")" = 200 ] || badp=$((badp+1))
done
for i in $(seq 1 30); do
    [ "$(curl -s "http://127.0.0.1:$PB/pxb/k$i")" = "via-proxy-$i" ] || badg=$((badg+1))
    [ "$(curl -s "http://127.0.0.1:$PP/pxb/k$i")" = "via-proxy-$i" ] || badg=$((badg+1))
done
expect "thirty puts through the proxy all land" "$badp" 0
expect "and read back through the proxy and straight" "$badg" 0
expect "the listing through the proxy has them all" "$(curl -s "http://127.0.0.1:$PP/pxb?list-type=2" | grep -o '<Key>' | wc -l)" 30

echo "== socketley.storage against the sharded runtime =="
cat > "$T/server.lua" <<'LUA'
local function unhex(h) return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) end
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function say(id, ...) self.send(id, table.concat({...}, " ")) end
function on_client_message(client_id, msg)
    local w = {}
    for x in msg:gmatch("%S+") do w[#w + 1] = x end
    local cmd = w[1]
    if cmd == "put" then
        local r, code, message = socketley.storage.put("e2ebk", "rpcb", w[2], unhex(w[3]))
        if not r then return say(client_id, "err", tostring(code), tostring(message)) end
        say(client_id, "ok", r.etag, r.size)
    elseif cmd == "get" then
        local data, meta, message = socketley.storage.get("e2ebk", "rpcb", w[2])
        if not data then return say(client_id, "err", tostring(meta), tostring(message)) end
        say(client_id, "data", hex(data), meta.etag)
    elseif cmd == "getlen" then
        local data, meta, message = socketley.storage.get("e2ebk", "rpcb", w[2])
        if not data then return say(client_id, "err", tostring(meta), tostring(message)) end
        say(client_id, "len", #data)
    elseif cmd == "head" then
        local meta, code = socketley.storage.head("e2ebk", "rpcb", w[2])
        if not meta then return say(client_id, "err", tostring(code)) end
        say(client_id, "head", meta.size, meta.etag)
    elseif cmd == "del" then
        local ok, code = socketley.storage.delete("e2ebk", "rpcb", w[2])
        say(client_id, tostring(ok), tostring(code))
    elseif cmd == "list" then
        local prefix = w[2] ~= "-" and w[2] or ""
        local opts = {}
        if w[3] and w[3] ~= "-" then opts.delimiter = w[3] end
        if w[4] and w[4] ~= "-" then opts.max_keys = tonumber(w[4]) end
        if w[5] and w[5] ~= "-" then opts.start_after = w[5] end
        local l, code = socketley.storage.list("e2ebk", "rpcb", prefix, opts)
        if not l then return say(client_id, "err", tostring(code)) end
        local keys = {}
        for _, o in ipairs(l.objects) do keys[#keys + 1] = o.key end
        say(client_id, "keys=" .. table.concat(keys, ","), "truncated=" .. tostring(l.truncated), "next=" .. tostring(l.next))
    end
end
LUA
curl -s -o /dev/null -X PUT "http://127.0.0.1:$PB/rpcb"
"$BIN" create server e2esv -p "$PS" --lua "$T/server.lua" -s >/dev/null 2>&1
expect "a server whose script uses socketley.storage is made" "$?" 0
sleep 0.5
before=$(stat_sum e2ebk shard_commits_sent)
run_py "$PS" "$PB" rpc
sleep 1
after=$(stat_sum e2ebk shard_commits_sent)
[ "$after" -gt "$before" ] && ok "puts by script crossed between shards ($((after - before)))" || bad "no put by script crossed" "$before -> $after"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
