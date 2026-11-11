#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a repository a storage's user names is fetched only from a host anyone can reach.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a user having the storage fetch a repository from this machine or its network into a library of theirs,
#     by an address, by a name that resolves to one, over git:// or over http://
#   * the refusal not said where the page shows it, or a run that fails for another reason passing for it
#   * the operator's own git-sync, which names no such bound, no longer fetching from this machine
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v git >/dev/null 2>&1 || { echo "  SKIP: git is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }

daemon_isolate stggitprivate
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1480))
ST=$P GP=$((P+1))
GITD=""
trap 'kill $GITD 2>/dev/null; daemon_stop' EXIT
unset SOCKETLEY_REPO_PRIVATE_HOSTS

echo "=== Integration: a user's repository is fetched from no private host ==="

ALICE_K=AKIAGITPRIVALICE0000 ALICE_S=gitprivalicesecretgitprivalicesecret0000
printf '[alice]\n%s:%s\n' "$ALICE_K" "$ALICE_S" > "$T/creds"

# What only this machine reaches: a repository served by git daemon on 127.0.0.1.
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t GIT_CONFIG_NOSYSTEM=1
mkdir -p "$T/srv" "$T/up"
git init -q -b main "$T/up"
printf 'internal only\n' > "$T/up/README.md"
git -C "$T/up" add -A && git -C "$T/up" commit -qm one
git clone -q --bare "$T/up" "$T/srv/demo.git"
git daemon --export-all --base-path="$T/srv" --listen=127.0.0.1 --port="$GP" --reuseaddr "$T/srv" >/dev/null 2>&1 &
GITD=$!
for _ in $(seq 1 50); do git ls-remote "git://127.0.0.1:$GP/demo.git" >/dev/null 2>&1 && break; sleep 0.1; done
expect "the upstream serves on this machine" "$(git ls-remote "git://127.0.0.1:$GP/demo.git" 2>/dev/null | grep -c refs/heads/main)" 1

daemon_start "$BIN"
"$BIN" create storage st -p "$ST" --dir "$T/st" --credentials "$T/creds" --sync per-user -s >/dev/null 2>&1
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$ST/" && break; sleep 0.1; done

ui() { curl -s -m 10 -u "$ALICE_K:$ALICE_S" "http://127.0.0.1:$ST/~ui/git"; }
post() { curl -s -m 10 -u "$ALICE_K:$ALICE_S" -o "$T/post.out" -w '%{http_code}' -H 'Content-Type: application/json' -d "$1" "http://127.0.0.1:$ST/~ui/git"; }
s3() { curl -s -m 10 --aws-sigv4 "aws:amz:us-east-1:s3" -u "$ALICE_K:$ALICE_S" "$@"; }
j() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1" 2>/dev/null; }
# Waits for the run of repository $1 (by its place in the list) that began at or after $2 to end, and prints the list.
settle() {
    local s
    for _ in $(seq 1 150); do
        s=$(ui)
        [ "$(echo "$s" | j "d['repos'][$1]['running']")" = False ] && [ "$(echo "$s" | j "d['repos'][$1]['state'] is not None and d['repos'][$1]['state']['at'] >= $2")" = True ] && break
        sleep 0.2
    done
    echo "$s"
}

# ─── through the storage, as a user ─────────────────────────────────────────
t0=$(date +%s)
expect "the user's repository on this machine is taken down as any other" \
    "$(post "{\"action\":\"add\",\"url\":\"git://127.0.0.1:$GP/demo.git\",\"branch\":\"main\",\"bucket\":\"code\"}")" 200
st=$(settle 0 "$t0")
expect "its run fails" "$(echo "$st" | j "d['repos'][0]['state']['ok']")" False
has "and says the host is not one it is fetched from" "$(echo "$st" | j "d['repos'][0]['state']")" "private network"
expect "none of it is in the library" "$(s3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ST/code/demo/README.md")" 404

t1=$(date +%s)
post "{\"action\":\"add\",\"url\":\"git://localhost:$GP/demo.git\",\"branch\":\"main\",\"bucket\":\"code\",\"name\":\"byname\"}" >/dev/null
st=$(settle 1 "$t1")
expect "a name for this machine is refused as its address is" "$(echo "$st" | j "d['repos'][1]['state']['ok']")" False
expect "and nothing of it is kept either" "$(s3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ST/code/byname/README.md")" 404

# ─── the runner itself ──────────────────────────────────────────────────────
run() { SOCKETLEY_GIT_ACCESS_KEY=$ALICE_K SOCKETLEY_GIT_SECRET=$ALICE_S "$BIN" git-sync --url "$1" --branch main \
            --work "$T/$2" --endpoint "127.0.0.1:$ST" --bucket hand --name "$2" "${@:3}"; }
out=$(run "http://127.0.0.1:$GP/demo.git" overhttp --public-only 2>&1); rc=$?
expect "over http:// it is refused before anything is asked of the host" "$rc" 2
has "for the same reason" "$out" "private network"
out=$(run "git://[::1]:$GP/demo.git" oversix --public-only 2>&1); rc=$?
expect "and so is this machine's IPv6 address" "$rc" 2
# The operator's own run names no such bound, and fetches from where the operator says.
run "git://127.0.0.1:$GP/demo.git" byhand >/dev/null 2>&1
expect "git-sync run by hand still fetches from this machine" "$(s3 "http://127.0.0.1:$ST/hand/byhand/README.md")" "internal only"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
