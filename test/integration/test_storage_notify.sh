#!/usr/bin/env bash
# Integration test: S3 event notifications from the storage runtime to a webhook.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   config      Put/GetBucketNotificationConfiguration with Queue, Topic and
#               CloudFunction destinations named arn:socketley:webhook:::<name>;
#               refusals: another ARN, a target the --notify-targets file does
#               not name (unless x-amz-skip-destination-validation), an unknown
#               event, overlapping configurations, a repeated Id, EventBridge,
#               MalformedXML, NoSuchBucket, ?notification on an object; an empty
#               configuration removes it
#   events      ObjectCreated Put, Post, Copy and CompleteMultipartUpload,
#               ObjectRemoved Delete and DeleteMarkerCreated, a version removed
#               by its id, LifecycleExpiration:Delete, ObjectTagging Put and
#               Delete, each with S3's record: the key form-encoded, size, eTag,
#               versionId and a growing sequencer
#   filters     prefix and suffix rules send exactly the keys they match
#   vhost       a virtual-hosted PUT's event names the bucket its Host gave
#   https       an https webhook whose certificate the target's ca= file trusts
#   requester   userIdentity is the signed request's user, "anonymous" for one a
#               bucket policy let in or on an --anonymous runtime, and
#               s3.amazonaws.com for a lifecycle expiry; sourceIPAddress the
#               client's; through a shard that does not own the key too
#   resolving   a webhook named by a host (localhost, and one the
#               SOCKETLEY_STORAGE_NOTIFY_HOSTS aid maps): when the name is
#               pointed at another address and the old one refuses, it is
#               resolved again off the loop and the event follows it
#   delivery    a webhook answering 500 is retried until it answers 200, one
#               that is down gets its events once it is up, and past the bound
#               (SOCKETLEY_STORAGE_NOTIFY_QUEUE, lowered here) a new event is
#               dropped and counted; notify_sent/failed/queued/dropped in stats
#   restart     the configuration survives a stop and a start
#   crash       a PUT answered while the webhook is down, the worker killed with
#               SIGKILL before the event could go: the restarted worker sends it
#               from its outbox
#   staged      a change's event is written while the change is made: a PUT or
#               DELETE killed once its event is durable and before it is made
#               (SOCKETLEY_STORAGE_KILL_AFTER_EVENT) sends nothing after the
#               restart, and an answered one killed before its confirmation is
#               written (SOCKETLEY_STORAGE_HOLD_CONFIRM) sends its event, in an
#               unversioned and a versioned bucket; and a DeleteBucket sent the
#               moment a notifying DELETE emptied the bucket is not refused
#   shards      with --shards 2 every change through either shard is one event,
#               sent by the shard that owns the key
#   flag        --notify-targets refuses a file that does not parse
#
# The assertions live in lib_storage_notify.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgnotify

P1=$((SL_PORT_BASE+1724))
HOOK=$((SL_PORT_BASE+1733))
OTHER=$((SL_PORT_BASE+1734))
SECURE=$((SL_PORT_BASE+1735))
NAMED=$((SL_PORT_BASE+1736))
P2=$((SL_PORT_BASE+1737))
export AKA="AKIANOTIFYALICE00001"
export SKA="notify/alice/secret"
# A test aid read by the resolver thread before the system resolver, so a name can be pointed elsewhere.
export SOCKETLEY_STORAGE_NOTIFY_HOSTS="$SOCKETLEY_TMPD/hosts"
echo "hooky.test 127.0.0.1" > "$SOCKETLEY_STORAGE_NOTIFY_HOSTS"
# Read by each shard's sweep alone, so a test sees days pass in seconds.
export SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS=2
# The bound on what waits, lowered so a test reaches it.
export SOCKETLEY_STORAGE_NOTIFY_QUEUE=40
# Crash aids for the keys of the staged half alone: killed once an event is durable, and a confirmation never written.
export SOCKETLEY_STORAGE_KILL_AFTER_EVENT=r/kae/
export SOCKETLEY_STORAGE_HOLD_CONFIRM=r/hold/

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in nt ntu nts; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in nt ntu nts nbad; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {   # port
    for _ in $(seq 1 100); do
        [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0
        sleep 0.1
    done
    return 1
}
wait_nodes() {   # node...
    local node t
    for node in "$@"; do
        for t in $(seq 1 150); do
            [ "$(code --unix-socket "$node" http://x/)" = 200 ] && continue 2
            sleep 0.1
        done
        return 1
    done
}
run_lib() {   # label runtime mode args...
    local label=$1 rt=$2; shift 2
    local out rc p f
    out=$(RUNTIME=$rt python3 "$HERE/lib_storage_notify.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"
    elif [ $((p+f)) -eq 0 ]; then bad "$label" "no assertions printed: $out"; fi
}

echo "=== Integration: event notifications ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

TARGETS="$SOCKETLEY_TMPD/targets"
cat > "$TARGETS" <<EOF
# name  url
hook    http://127.0.0.1:$HOOK/events
other   http://localhost:$OTHER/
named   http://hooky.test:$NAMED/
EOF
CERT="$SOCKETLEY_TMPD/hook.crt"
KEY="$SOCKETLEY_TMPD/hook.key"
if openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 1 -subj /CN=127.0.0.1 \
       -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1; then
    echo "secure  https://127.0.0.1:$SECURE/tls ca=$CERT" >> "$TARGETS"
fi

# ── the flag ────────────────────────────────────────────────────────────────
echo "hook ftp://127.0.0.1/" > "$SOCKETLEY_TMPD/badtargets"
out=$("$BIN" create storage nbad -p "$P1" --dir "$SOCKETLEY_TMPD/bad" --anonymous \
      --notify-targets "$SOCKETLEY_TMPD/badtargets" -s 2>&1)
if [ $? -ne 0 ] && echo "$out" | grep -q "http:// or https://"; then
    ok "a targets file that does not parse is refused, saying why"
else
    bad "a targets file that does not parse is refused, saying why" "$out"
fi
"$BIN" remove nbad >/dev/null 2>&1
out=$("$BIN" create storage nbad -p "$P1" --dir "$SOCKETLEY_TMPD/bad" --anonymous --notify-targets 2>&1)
[ $? -eq 1 ] && ok "--notify-targets with no file is refused" || bad "--notify-targets with no file is refused" "$out"

# ── one shard ───────────────────────────────────────────────────────────────
DATA="$SOCKETLEY_TMPD/objects"
if ! "$BIN" create storage nt -p "$P1" --dir "$DATA" --anonymous --notify-targets "$TARGETS" \
     --domain s3.notify.test -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
if "$BIN" show nt 2>&1 | grep -q "\"notify_targets\": \"$TARGETS\""; then
    ok "show names the targets file"
else
    bad "show names the targets file" "$("$BIN" show nt 2>&1)"
fi
run_lib "the main half ran" nt main "$P1" "$HOOK" "$OTHER"
run_lib "the dns half ran" nt dns "$P1" "$NAMED" "$SOCKETLEY_STORAGE_NOTIFY_HOSTS"
if [ -s "$CERT" ]; then
    run_lib "the tls half ran" nt tls "$P1" "$SECURE" "$CERT" "$KEY"
    run_lib "the keep half ran" nt keep "$P1" "$HOOK" "$SECURE" "$CERT" "$KEY"
else
    echo "  SKIP: openssl is required for the https webhook"
    run_lib "the keep half ran" nt keep "$P1" "$HOOK"
fi

"$BIN" stop nt >/dev/null 2>&1
sleep 0.5
"$BIN" start nt >/dev/null 2>&1
wait_up "$P1" || bad "the runtime comes back" "no answer on $P1"
run_lib "the restart half ran" nt restart "$P1" "$HOOK"
run_lib "the crash half ran" nt crash "$P1" "$HOOK" "$DATA"
# Four kills each, so a stop and a start between them keep under the supervisor's bound on restarts in a burst.
for sb in nstage notifyb; do
    "$BIN" stop nt >/dev/null 2>&1
    sleep 0.5
    "$BIN" start nt >/dev/null 2>&1
    wait_up "$P1" || bad "the runtime comes back for $sb" "no answer on $P1"
    run_lib "the staged half ran on $sb" nt staged "$P1" "$HOOK" "$sb"
done
run_lib "the drop half ran" nt drop "$P1" "$HOOK"
"$BIN" stop nt >/dev/null 2>&1

# ── users ───────────────────────────────────────────────────────────────────
CREDS="$SOCKETLEY_TMPD/creds"
printf '[alice]\n%s:%s\n' "$AKA" "$SKA" > "$CREDS"
if ! "$BIN" create storage ntu -p "$P2" --dir "$SOCKETLEY_TMPD/users" --credentials "$CREDS" \
     --notify-targets "$TARGETS" -s >/dev/null 2>&1; then
    bad "create with --credentials" "the runtime was not created"
else
    wait_up "$P2" || bad "the users runtime comes up" "no answer on $P2"
    run_lib "the users half ran" ntu users "$P2" "$HOOK"
    "$BIN" stop ntu >/dev/null 2>&1
fi

# ── two shards ──────────────────────────────────────────────────────────────
SDATA="$SOCKETLEY_TMPD/shardobjects"
SOCK="$SOCKETLEY_TMPD/nts.sock"
NODES=("$SOCKETLEY_TMPD/nts#0.sock" "$SOCKETLEY_TMPD/nts#1.sock")
if ! "$BIN" create storage nts --listen "unix:$SOCK" --dir "$SDATA" --anonymous --shards 2 \
     --notify-targets "$TARGETS" -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    run_lib "the shards half ran" nts shards "$HOOK" "${NODES[@]}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
