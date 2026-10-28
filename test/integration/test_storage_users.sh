#!/usr/bin/env bash
# Integration test: the users of a storage runtime, named in its credentials file.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   ownership   a bucket is its maker's: ListBuckets shows a user its own and an
#               admin all, and every Owner a listing or an ACL gives is the maker
#               with its display name
#   cross-user  another user's bucket is refused in every direction, a copy from
#               it included, and making it is BucketAlreadyExists
#   grants      a bucket policy lets another user in by user ARN or access key, an
#               identity policy by its own resources, and neither further
#   deny        an explicit Deny wins over ownership and over any Allow, from the
#               bucket policy or the identity policy; the owner can always remove
#               a policy that shuts everyone out
#   restart     ownership is on disk with the bucket and comes back with it
#   shards      a bucket made through either of two shards is its maker's on both
#   reload      an edit of the file or of a policy file is taken without a restart
#   legacy      a file without users is one owner, socketley, as before
#   format      a file with a broken user or policy is refused and says where
#
# The assertions live in lib_storage_users.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgusers

PT=$((SL_PORT_BASE+1676))
PL=$((SL_PORT_BASE+1677))
PX=$((SL_PORT_BASE+1678))
D="$SOCKETLEY_TMPD"
export AKA="AKIAUSERSALICE000001" SKA="alice/secret/1"
export AKA2="AKIAUSERSALICE000002" SKA2="alice/secret/2"
export AKB="AKIAUSERSBOB00000001" SKB="bob/secret/1"
export AKR="AKIAUSERSROOT0000001" SKR="root/secret/1"
export AKL="AKIAUSERSLEGACY00001" SKL="legacy/secret/1"
export LK1="AKIALEGACYKEYONE0001" LSK1="legacy/one"
export LK2="AKIALEGACYKEYTWO0002" LSK2="legacy/two"
RUNTIMES="users ulegacy ushards ubad"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }

cleanup() {
    for r in $RUNTIMES; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in $RUNTIMES; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_port() {   # port
    local t
    for t in $(seq 1 150); do
        [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0
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
    out=$(python3 "$HERE/lib_storage_users.py" "$@" 2>&1); rc=$?
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

echo "=== Integration: storage users ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

mkdir -p "$D/conf"
CREDS="$D/conf/creds"
cat > "$CREDS" <<EOF
# a key outside any user is the default owner, an admin
$AKL:$SKL

[alice]
name = Alice Example
$AKA:$SKA
$AKA2:$SKA2

[bob]
policy = bob.json
$AKB:$SKB

[root]
name = Root
admin = true
$AKR:$SKR
EOF
cat > "$D/conf/bob.json" <<'EOF'
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadShared", "Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
   "Resource": ["arn:aws:s3:::alice-s", "arn:aws:s3:::alice-s/*"]},
  {"Sid": "KeepKeep", "Effect": "Deny", "Action": "s3:DeleteObject",
   "Resource": ["arn:aws:s3:::bob-*/keep/*", "arn:aws:s3:::alice-s/*"]},
  {"Sid": "NoForbidden", "Effect": "Deny", "Action": "s3:CreateBucket", "Resource": "arn:aws:s3:::forbidden-*"},
  {"Sid": "OwnPolicy", "Effect": "Deny", "Action": ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy"],
   "Resource": "arn:aws:s3:::bob-b"}
]}
EOF
# The shards runtime reads a copy, since the reload below edits these.
mkdir -p "$D/conf2"
cp "$CREDS" "$D/conf/bob.json" "$D/conf2/"

# ── a runtime with users ────────────────────────────────────────────────────
"$BIN" create storage users -p "$PT" --dir "$D/users" --credentials "$CREDS" -s >/dev/null 2>&1
expect "a runtime with users is made" "$?" 0
wait_port "$PT" && ok "and answers" || bad "users" "no answer on $PT"

echo "== ownership and another user's bucket =="
run_py basic "$PT"
first=$(head -1 "$D/users/alice-a/created"); owner=$(sed -n 2p "$D/users/alice-a/created")
[ -n "$first" ] && [ "$owner" = "alice" ] && ok "the owner is the second line of the bucket's created file" \
    || bad "created file" "$(cat "$D/users/alice-a/created")"
[ "$(wc -l < "$D/users/legacy-l/created")" = 0 ] && ok "and a bucket of the default owner has none" \
    || bad "legacy created" "$(cat "$D/users/legacy-l/created")"
echo "== grants =="
run_py grant "$PT"
echo "== explicit denials =="
run_py deny "$PT"

echo "== a restart =="
restart users
wait_port "$PT" && ok "the runtime is back" || bad "restart" "no answer"
run_py persist "$PT"

echo "== an edit of the credentials and of a policy file =="
run_py reload "$PT" "$CREDS" "$D/conf/bob.json"
grep -q "credentials reloaded from $CREDS" "$SOCKETLEY_DLOG" && ok "the log says the credentials were reloaded" \
    || bad "reload log" "$(grep -i credentials "$SOCKETLEY_DLOG" | tail -3)"
grep -q "credentials not reloaded, the old set stays: .*bob.json\|credentials not reloaded, the old set stays: .*policy of user bob" \
    "$SOCKETLEY_DLOG" && ok "and that a broken policy file was not taken, and whose" \
    || bad "broken log" "$(grep -i "not reloaded" "$SOCKETLEY_DLOG" | tail -3)"
"$BIN" stop users >/dev/null 2>&1

# ── two shards ──────────────────────────────────────────────────────────────
echo "== two shards =="
"$BIN" create storage ushards --listen "unix:$D/two.sock" --dir "$D/two" --credentials "$D/conf2/creds" --shards 2 \
    -s >/dev/null 2>&1
expect "a runtime of two shards is made" "$?" 0
N=("$D/two#0.sock" "$D/two#1.sock")
wait_nodes "${N[@]}" && ok "both shards answer" || bad "nodes" "no answer from ${N[*]}"
run_py shards "${N[@]}"
restart ushards
wait_nodes "${N[@]}" && ok "both shards are back after a restart" || bad "restart" "no answer"
run_py shardspersist "${N[@]}"
"$BIN" stop ushards >/dev/null 2>&1

# ── a file without users ────────────────────────────────────────────────────
echo "== a file without users =="
printf '%s:%s\n%s:%s\n' "$LK1" "$LSK1" "$LK2" "$LSK2" > "$D/legacy-creds"
"$BIN" create storage ulegacy -p "$PL" --dir "$D/legacy" --credentials "$D/legacy-creds" -s >/dev/null 2>&1
expect "a runtime with a file of plain keys is made" "$?" 0
wait_port "$PL" && ok "and answers" || bad "ulegacy" "no answer on $PL"
run_py legacy "$PL"
expect "its bucket's created file is one line, as before users" "$(wc -l < "$D/legacy/old-1/created")" 0
"$BIN" stop ulegacy >/dev/null 2>&1

# ── files that are refused ──────────────────────────────────────────────────
echo "== files that are refused =="
refused() {   # name, file text, what the refusal says
    printf '%s\n' "$2" > "$D/conf/badcreds"
    local out rc
    out=$("$BIN" create storage ubad -p "$PX" --dir "$D/bad" --credentials "$D/conf/badcreds" 2>&1); rc=$?
    expect "$1 is refused" "$rc" 1
    contains "and says $3" "$out" "$3"
    "$BIN" remove ubad >/dev/null 2>&1
}
refused "a policy naming a principal" "[u]
policy = {\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}
AKIABADUSER000000001:s" "should not specify a principal"
refused "a policy file that is not there" "[u]
policy = missing.json
AKIABADUSER000000001:s" "missing.json"
refused "a user declared twice" "[u]
AKIABADUSER000000001:s
[u]
AKIABADUSER000000002:s" "declared twice"
refused "one key given to two users" "[u]
AKIABADUSER000000001:s
[v]
AKIABADUSER000000001:s" "two users"
refused "an unknown setting" "[u]
colour = blue" "not a setting of a user"
refused "a setting outside any user" "admin = true" "no [id] line"
refused "a user id with a slash" "[a/b]" "a user is [id]"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
