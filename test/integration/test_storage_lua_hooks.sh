#!/usr/bin/env bash
# Integration test: a script hooks a storage runtime -- on_request, on_put, on_delete.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   on_request  runs after authentication and before the operation, sees the
#               method, the operation by S3's name, the bucket and key, the raw
#               path and query, the headers, the client's address and whether the
#               connection is TLS; returning nothing, or true, lets the request
#               go on; false refuses it as AccessDenied, a string as that S3
#               error, a table as the code, message and status it names; a raise
#               and a value that means nothing are refusals too, never a request
#               let through
#   refusal     a refused PUT stores nothing, leaves no temporary file and is
#               answered before its body is read, and the connection is closed
#   waiting     a hook that asks another storage runtime something through
#               socketley.storage stops itself and the runtime goes on serving:
#               twenty requests held on that answer are all answered, the ones
#               the policy names refused and the rest allowed
#   on_put      after the commit, with the bucket, key, size, ETag, content type
#               and user metadata, for a put and for the destination of a copy,
#               and never for a put that was refused
#   on_delete   once for each object that was there, from DeleteObject and from
#               DeleteObjects, and not for a key that was not
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stglua

P=$((SL_PORT_BASE+1680))
T="$SOCKETLEY_TMPD"
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
contains() { if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi; }

cleanup() {
    for r in lh_stg lh_pol; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in lh_stg lh_pol; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: Lua hooks on a storage runtime ==="
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cat > "$T/hooks.lua" <<'LUA'
local logf = assert(io.open(os.getenv("SL_HOOKLOG"), "a"))
logf:setvbuf("line")

function on_request(req)
    logf:write("req|", req.method, "|", req.operation, "|", req.bucket, "|", req.key, "|", req.path, "|",
               req.query, "|", req.client, "|", tostring(req.tls), "|", tostring(req.content_length), "|",
               tostring(req.headers["host"] ~= nil), "|", tostring(req.headers["x-probe"]), "\n")
    if req.operation == "PutObject" and req.key:sub(1, 7) == "denied/" then return false end
    if req.headers["x-block"] == "1" then return "SlowDown" end
    if req.key == "table-deny" then return { deny = "AccessDenied", message = "custom message", status = 403 } end
    if req.key == "raises" then error("boom") end
    if req.key == "weird" then return 42 end
    if req.key:sub(1, 8) == "blocked-" then
        local meta, code = socketley.storage.head("lh_pol", "policy", req.key)
        logf:write("policy|", req.key, "|", tostring(meta ~= nil), "|", tostring(code), "\n")
        if meta then return "AccessDenied" end
    end
    if req.key:sub(1, 5) == "lost-" then
        -- A runtime that is not there answers nil and a reason; the script decides.
        local meta, why = socketley.storage.head("no_such_runtime", "policy", req.key)
        logf:write("lost|", tostring(meta), "|", tostring(why), "\n")
    end
end

function on_put(bucket, key, meta)
    logf:write("put|", bucket, "|", key, "|", meta.size, "|", meta.etag, "|", meta.content_type, "|",
               tostring(meta.metadata.color), "\n")
end

function on_delete(bucket, key)
    logf:write("delete|", bucket, "|", key, "\n")
end
LUA

daemon_start "$BIN"
"$BIN" create storage lh_pol -p $((P+1)) --dir "$T/pol" --anonymous -s >/dev/null 2>&1 || bad "create" "lh_pol"
"$BIN" create storage lh_stg -p "$P" --dir "$T/stg" --anonymous --lua "$T/hooks.lua" -s >/dev/null 2>&1 || bad "create" "lh_stg"
S="http://127.0.0.1:$P"
POL="http://127.0.0.1:$((P+1))"
code() { curl -s -o "$T/body.out" -w '%{http_code}' "$@"; }
body() { cat "$T/body.out"; }
for _ in $(seq 1 100); do [ "$(code "$S/")" = 200 ] && [ "$(code "$POL/")" = 200 ] && break; sleep 0.1; done

expect "a bucket is made through the hook" "$(code -X PUT "$S/bkt")" 200
curl -s -X PUT "$POL/policy" -o /dev/null
curl -s -X PUT --data-binary x "$POL/policy/blocked-key" -o /dev/null

# ── on_request sees the request and may let it go ───────────────────────────
: > "$SL_HOOKLOG"
expect "an allowed put is 200" "$(code -X PUT -H 'x-amz-meta-color: red' -H 'content-type: text/plain' -H 'x-probe: hello' --data-binary hello "$S/bkt/ok?versioning-not=1")" 200
expect "and reads back" "$(code "$S/bkt/ok")" 200
expect "with its bytes" "$(body)" "hello"
line=$(grep '^req|PUT|' "$SL_HOOKLOG" | head -1)
contains "the hook saw the method and the operation by S3's name" "$line" "req|PUT|PutObject|bkt|ok|"
contains "the raw path" "$line" "|/bkt/ok|"
contains "the raw query" "$line" "|versioning-not=1|"
contains "the client's address" "$line" "|127.0.0.1:"
contains "that the connection is not TLS, and the content length" "$line" "|false|5|"
contains "the headers, lowercased" "$line" "|true|hello"
contains "GET is named GetObject" "$(grep '^req|GET|' "$SL_HOOKLOG" | head -1)" "req|GET|GetObject|bkt|ok|"

# ── refusals ────────────────────────────────────────────────────────────────
expect "false refuses with 403" "$(code -X PUT --data-binary hello "$S/bkt/denied/x")" 403
contains "as AccessDenied" "$(body)" "<Code>AccessDenied</Code>"
expect "and the refused put stored nothing" "$(code "$S/bkt/denied/x")" 404
expect "a string is the S3 error it names, with its status" "$(code -H 'x-block: 1' "$S/bkt/ok")" 503
contains "SlowDown" "$(body)" "<Code>SlowDown</Code>"
expect "a table names code, message and status" "$(code "$S/bkt/table-deny")" 403
contains "and the message is the script's" "$(body)" "custom message"
expect "a raise is a refusal, and a server error" "$(code "$S/bkt/raises")" 500
contains "InternalError" "$(body)" "<Code>InternalError</Code>"
expect "a value that means nothing is a refusal" "$(code "$S/bkt/weird")" 500
expect "and the runtime serves the next request" "$(code "$S/bkt/ok")" 200

# A refused upload is answered before its body is read.
head -c 20971520 /dev/urandom > "$T/big"
: > "$T/big.out"
instat() {
    local prev="" cur=""
    for _ in $(seq 1 30); do cur=$("$BIN" stats lh_stg | sed -n 's/^bytes_in://p'); [ -n "$cur" ] && [ "$cur" = "$prev" ] && break; prev=$cur; sleep 0.3; done
    echo "$cur"
}
in_before=$(instat)
rc=0
curl -s -o "$T/big.body" -w '%{http_code}' -X PUT --data-binary @"$T/big" --max-time 20 "$S/bkt/denied/big" > "$T/big.code" 2>/dev/null || rc=$?
bigcode=$(cat "$T/big.code")
in_after=$(instat)
if [ "$bigcode" = 403 ] || { [ "$bigcode" = 000 ] && [ "$rc" -ne 28 ]; }; then ok "a 20 MiB put to a refused key is refused, not stored ($bigcode, exit $rc)"
else bad "a large refused put" "code '$bigcode' exit $rc"; fi
if [ $((in_after - in_before)) -lt 8388608 ]; then ok "the body was not read: the runtime took $((in_after - in_before)) bytes of a 20 MiB upload"
else bad "a refused put is answered before its body is read" "the runtime read $((in_after - in_before)) bytes"; fi
expect "and left no object" "$(code "$S/bkt/denied/big")" 404
left=$(ls "$T/stg/bkt/tmp" 2>/dev/null | wc -l)
expect "and no temporary file" "$left" 0

# ── a hook that waits on another runtime ────────────────────────────────────
expect "a key the policy runtime names is refused" "$(code "$S/bkt/blocked-key")" 403
expect "a key it does not name is let through to the operation" "$(code "$S/bkt/blocked-other")" 404
contains "and the hook was told the policy runtime's answer" "$(cat "$SL_HOOKLOG")" "policy|blocked-other|false|NoSuchKey"
: > "$SL_HOOKLOG"
curl -s -X PUT --data-binary y "$S/bkt/blocked-3" -o /dev/null
expect "the policy object put through the runtime under hook is allowed" "$(code "$S/bkt/blocked-3")" 200
curl -s -X PUT --data-binary x "$POL/policy/blocked-b" -o /dev/null
pids=()
for i in $(seq 1 20); do
    if [ $((i % 2)) -eq 0 ]; then k="blocked-b"; else k="blocked-3"; fi
    ( curl -s -o /dev/null -w '%{http_code}\n' "$S/bkt/$k" > "$T/par.$i" ) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
denied=0; allowed=0
for i in $(seq 1 20); do
    c=$(cat "$T/par.$i" 2>/dev/null)
    if [ "$c" = 403 ]; then denied=$((denied+1)); elif [ "$c" = 200 ]; then allowed=$((allowed+1)); fi
done
expect "twenty requests held on the policy runtime are all answered: ten refused" "$denied" 10
expect "and ten allowed" "$allowed" 10
: > "$SL_HOOKLOG"
code "$S/bkt/lost-key" > /dev/null
contains "a runtime that is not there answers nil and a reason" "$(cat "$SL_HOOKLOG")" "lost|nil|"

# ── on_put and on_delete ────────────────────────────────────────────────────
: > "$SL_HOOKLOG"
want_md5=$(printf 'notify me' | md5sum | cut -d' ' -f1)
code -X PUT -H 'x-amz-meta-color: green' -H 'content-type: text/notes' --data-binary 'notify me' "$S/bkt/notify" > /dev/null
sleep 0.5
contains "on_put fires after a put, with size, ETag, content type and metadata" "$(cat "$SL_HOOKLOG")" "put|bkt|notify|9|$want_md5|text/notes|green"
: > "$SL_HOOKLOG"
code -X PUT --data-binary denied "$S/bkt/denied/nope" > /dev/null
sleep 0.3
if grep -q '^put|' "$SL_HOOKLOG"; then bad "on_put is not told of a refused put" "$(cat "$SL_HOOKLOG")"; else ok "on_put is not told of a refused put"; fi
: > "$SL_HOOKLOG"
code -X PUT -H 'x-amz-copy-source: /bkt/notify' "$S/bkt/copied" > /dev/null
sleep 0.5
contains "on_put fires for the destination of a copy" "$(cat "$SL_HOOKLOG")" "put|bkt|copied|9|$want_md5"
: > "$SL_HOOKLOG"
expect "a delete of an object that is there" "$(code -X DELETE "$S/bkt/copied")" 204
sleep 0.3
contains "fires on_delete" "$(cat "$SL_HOOKLOG")" "delete|bkt|copied"
: > "$SL_HOOKLOG"
code -X DELETE "$S/bkt/copied" > /dev/null
sleep 0.3
if grep -q '^delete|' "$SL_HOOKLOG"; then bad "on_delete is not told of a key that was not there" "$(cat "$SL_HOOKLOG")"; else ok "on_delete is not told of a key that was not there"; fi
: > "$SL_HOOKLOG"
curl -s -X PUT --data-binary a "$S/bkt/m1" -o /dev/null
curl -s -X PUT --data-binary b "$S/bkt/m2" -o /dev/null
: > "$SL_HOOKLOG"
code -X POST --data-binary '<Delete><Object><Key>m1</Key></Object><Object><Key>m2</Key></Object><Object><Key>never-was</Key></Object></Delete>' "$S/bkt?delete" > /dev/null
sleep 0.5
dl=$(grep '^delete|' "$SL_HOOKLOG" | sort | tr '\n' ' ')
expect "DeleteObjects tells on_delete of each object that was there and no other" "$dl" "delete|bkt|m1 delete|bkt|m2 "

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
