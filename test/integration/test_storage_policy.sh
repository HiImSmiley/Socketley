#!/usr/bin/env bash
# Integration test: a storage bucket's policy, and how every request is judged by it.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   config      Put/Get/DeleteBucketPolicy and GetBucketPolicyStatus as S3 answers
#               them, through boto3 too, every document refused as MalformedPolicy
#               rather than honoured in part, and a refusal leaves the policy that
#               was there
#   public      an Allow for everyone on a prefix serves anonymous GET and HEAD
#               there on a runtime without --anonymous, and refuses them elsewhere
#               and refuses PUT, DELETE and listing everywhere
#   deny        an explicit Deny refuses a signed key and not the other, also
#               through a presigned URL, a copy's source and DeleteObjects; no
#               policy refuses a signed request for the policy itself
#   conditions  aws:SourceIp in and out of range, aws:SecureTransport over
#               cleartext and over TLS
#   order       authentication, then the policy, then on_request
#   missing     a key that is not there is 403 AccessDenied to a requester the
#               policy lets read and not list, and 404 NoSuchKey to one it lets list
#   restart     the policy is on disk with the bucket and comes back with it
#   broken      a stored policy that no longer compiles refuses every request but
#               the policy operations by the keys, and says so in the log
#   shards      set through a shard that is not 0, every shard judges by it
#   propagation a change a shard cannot be told of is refused 503 and changes
#               nothing anywhere, and a shard that is not told how a change ended
#               never serves the bucket under the old policy (the losses are made
#               by the SOCKETLEY_STORAGE_DOC_FAULT test hook)
#
# The assertions live in lib_storage_policy.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgpolicy

PT=$((SL_PORT_BASE+1625))
PTLS=$((SL_PORT_BASE+1626))
D="$SOCKETLEY_TMPD"
export AK1="AKIAPOLICYKEYONE0001" SK1="policy/one/secret+1"
export AK2="AKIAPOLICYKEYTWO0002" SK2="policy/two/secret+2"
CREDS="$D/creds"
printf '%s:%s\n%s:%s\n' "$AK1" "$SK1" "$AK2" "$SK2" > "$CREDS"
RUNTIMES="pol ptls panon ptwo"
# Read by the workers the daemon starts, so it is set before the daemon is; it does nothing until a file is put there.
export SOCKETLEY_STORAGE_DOC_FAULT="$D/faults"
mkdir -p "$SOCKETLEY_STORAGE_DOC_FAULT"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

cleanup() {
    for r in $RUNTIMES; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in $RUNTIMES; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_port() {   # port [curl args]
    local t
    for t in $(seq 1 150); do
        [ "$(code "${@:2}" "$1")" != 000 ] && return 0
        sleep 0.1
    done
    return 1
}
wait_nodes() {   # node...
    local node t
    for node in "$@"; do
        for t in $(seq 1 150); do
            [ "$(code --unix-socket "$node" http://x/)" != 000 ] && continue 2
            sleep 0.1
        done
        return 1
    done
}
run_py() {   # a mode of the library, whose lines are the test's
    local out rc p f
    out=$(python3 "$HERE/lib_storage_policy.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL|SKIP)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
        bad "the library ran ($1)" "exit $rc: $(echo "$out" | tail -5)"
    fi
}
restart() {   # runtime
    "$BIN" stop "$1" >/dev/null 2>&1
    sleep 0.3
    "$BIN" start "$1" >/dev/null 2>&1
}

echo "=== Integration: storage bucket policy ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

cat > "$D/hooks.lua" <<'LUA'
function on_request(req)
    if req.key:sub(1, 7) == "hooked/" then return { deny = "AccessDenied", message = "hook says no" } end
end
LUA

# ── a runtime that wants signatures ─────────────────────────────────────────
"$BIN" create storage pol -p "$PT" --dir "$D/pol" --credentials "$CREDS" --lua "$D/hooks.lua" -s >/dev/null 2>&1
expect "a signed runtime is made" "$?" 0
wait_port "http://127.0.0.1:$PT/" && ok "and answers" || bad "pol" "no answer on $PT"

echo "== the configuration, and public read on a prefix =="
run_py config "$PT"
[ -s "$D/pol/pub/policy" ] && ok "the policy is a file in the bucket's directory" || bad "policy file" "$(ls -la "$D/pol/pub" 2>&1)"
echo "== explicit denials =="
run_py deny "$PT"
echo "== aws:SourceIp =="
run_py sourceip "$PT"
echo "== the policy and on_request =="
run_py hook "$PT"
echo "== a key that is not there =="
run_py missing "$PT"
run_py brokenprep "$PT"

echo "== a restart =="
restart pol
wait_port "http://127.0.0.1:$PT/" && ok "the runtime is back" || bad "restart" "no answer"
run_py persist "$PT"

echo "== a stored policy that does not compile =="
write_broken() {
    python3 -c "import sys; sys.path.insert(0, '$HERE'); import lib_storage_policy as l; open('$D/pol/brk/policy', 'w').write(l.BROKEN)"
}
"$BIN" stop pol >/dev/null 2>&1
sleep 0.3
write_broken
"$BIN" start pol >/dev/null 2>&1
wait_port "http://127.0.0.1:$PT/" && ok "the runtime starts with it" || bad "broken start" "no answer"
grep -q "the policy of bucket brk does not compile (NotPrincipal is not supported)" "$SOCKETLEY_DLOG" \
    && ok "the log says the bucket refuses every request, and why" || bad "broken log" "$(grep -i brk "$SOCKETLEY_DLOG" | tail -3)"
run_py broken "$PT"
"$BIN" stop pol >/dev/null 2>&1
sleep 0.3
write_broken
"$BIN" start pol >/dev/null 2>&1
wait_port "http://127.0.0.1:$PT/" && ok "and starts with it again" || bad "broken restart" "no answer"
run_py brokenfix "$PT"

# ── aws:SecureTransport ─────────────────────────────────────────────────────
echo "== aws:SecureTransport =="
CERTS="$D/certs"
mkdir -p "$CERTS"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTS/srv-key.pem" -out "$CERTS/srv.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
if [ -s "$CERTS/srv.pem" ]; then
    "$BIN" create storage ptls -p "$PTLS" --dir "$D/tls" --credentials "$CREDS" --tls --cert "$CERTS/srv.pem" \
        --key "$CERTS/srv-key.pem" -s >/dev/null 2>&1
    expect "a TLS runtime is made" "$?" 0
    wait_port "https://localhost:$PTLS/" --cacert "$CERTS/srv.pem" && ok "and answers" || bad "ptls" "no answer on $PTLS"
    run_py secure "$PT" "$PTLS" "$CERTS/srv.pem"
    "$BIN" stop ptls >/dev/null 2>&1
else
    echo "  SKIP: openssl could not make a certificate"
fi

# ── --anonymous ─────────────────────────────────────────────────────────────
echo "== a runtime with --anonymous =="
"$BIN" create storage panon --listen "unix:$D/anon.sock" --dir "$D/anon" --anonymous -s >/dev/null 2>&1
expect "an anonymous runtime is made" "$?" 0
wait_nodes "$D/anon.sock" && ok "and answers" || bad "panon" "no answer"
run_py anon "$D/anon.sock"
"$BIN" stop panon >/dev/null 2>&1

# ── two shards ──────────────────────────────────────────────────────────────
echo "== two shards =="
"$BIN" create storage ptwo --listen "unix:$D/two.sock" --dir "$D/two" --credentials "$CREDS" --shards 2 -s >/dev/null 2>&1
expect "a runtime of two shards is made" "$?" 0
N=("$D/two#0.sock" "$D/two#1.sock")
wait_nodes "${N[@]}" && ok "both shards answer" || bad "nodes" "no answer from ${N[*]}"
run_py shards "${N[@]}"
echo "== a shard that misses a change =="
run_py propagation "${N[@]}" "$SOCKETLEY_STORAGE_DOC_FAULT" "$D/two"
restart ptwo
wait_nodes "${N[@]}" && ok "both shards are back after a restart" || bad "restart" "no answer"
run_py persist "${N[@]}"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
