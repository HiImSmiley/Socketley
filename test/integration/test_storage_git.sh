#!/usr/bin/env bash
# Integration test: git repositories kept in a storage runtime's library.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   first run    adding a repository copies its branch's files under <name>/,
#                executable and in folders, and a bundle of it under
#                _backups/<name>/ that `git clone` makes the repository from
#   unchanged    a run with nothing new writes nothing and no bundle
#   changes      a run after a push writes what changed, removes what went,
#                and writes a second bundle
#   thinning     `git-sync --keep 1,0,0` keeps one bundle of the day
#   who          a user sees the repositories it keeps and an admin all; one
#                that may not write a library cannot add one into it
#   schedule     one told to pull every day is pulled by itself a day on;
#                one pulled never is not
#   private      a private repository without a token is not run, and says so;
#                a token is kept and removed, never shown
#   refused      a file:// URL, a bad branch and a bad folder name
#   moved        one in the shared library git goes to git-<owner> at the next
#                start, backups and all, and the emptied library goes
#   runtimes     a user with a repository has a sync runtime the storage made, which runs
#                their repositories and goes when the storage stops
#   remove       a removed repository is no longer listed; its files stay
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

daemon_isolate stggit
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1940))
ST=$P GP=$((P+1))
GITD=""
trap 'kill $GITD 2>/dev/null; daemon_stop' EXIT

echo "=== Integration: git repositories in a library ==="

ALICE_K=AKIAGITALICE00000000 ALICE_S=gitalicesecretgitalicesecretgitalice0000
BOB_K=AKIAGITBOB0000000000 BOB_S=gitbobsecretgitbobsecretgitbobsecret000000
cat > "$T/creds" <<EOF
[alice]
admin = true
$ALICE_K:$ALICE_S
[bob]
$BOB_K:$BOB_S
EOF

# The upstream: a repository served by git daemon.
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t GIT_CONFIG_NOSYSTEM=1
mkdir -p "$T/srv" "$T/up"
git init -q -b main "$T/up"
printf 'hello\n' > "$T/up/README.md"; mkdir -p "$T/up/src/deep"; printf 'int x;\n' > "$T/up/src/deep/a.c"
printf '#!/bin/sh\necho hi\n' > "$T/up/run.sh"; chmod +x "$T/up/run.sh"; printf 'gone soon\n' > "$T/up/old.txt"
git -C "$T/up" add -A && git -C "$T/up" commit -qm one
git clone -q --bare "$T/up" "$T/srv/demo.git"
git daemon --export-all --base-path="$T/srv" --listen=127.0.0.1 --port="$GP" --reuseaddr "$T/srv" >/dev/null 2>&1 &
GITD=$!
for _ in $(seq 1 50); do git ls-remote "git://127.0.0.1:$GP/demo.git" >/dev/null 2>&1 && break; sleep 0.1; done

daemon_start "$BIN"
"$BIN" create storage st -p "$ST" --dir "$T/st" --credentials "$T/creds" -s >/dev/null 2>&1
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$ST/" && break; sleep 0.1; done

ui() { local who=$1; shift; curl -s -m 10 -u "$who" "$@" "http://127.0.0.1:$ST/~ui/git"; }
post() { local who=$1 body=$2; curl -s -m 10 -u "$who" -o /dev/stderr -w '%{http_code}' -H 'Content-Type: application/json' -d "$body" "http://127.0.0.1:$ST/~ui/git" 2>"$T/post.out"; }
s3() { curl -s -m 10 --aws-sigv4 "aws:amz:us-east-1:s3" -u "$ALICE_K:$ALICE_S" "$@"; }
j() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1" 2>/dev/null; }
# Waits for the run of the first repository to end, and prints its state.
settle() {
    local s
    for _ in $(seq 1 150); do
        s=$(ui "$ALICE_K:$ALICE_S")
        [ "$(echo "$s" | j "d['repos'][0]['running']")" = False ] && [ "$(echo "$s" | j "d['repos'][0]['state'] is not None and d['repos'][0]['state']['at'] >= $1")" = True ] && break
        sleep 0.2
    done
    echo "$s"
}
bundles() { s3 "http://127.0.0.1:$ST/code?list-type=2&prefix=_backups/demo/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'; }

expect "a runtime on a port has git" "$(ui "$ALICE_K:$ALICE_S" | j "d['available']")" True

# ─── first run ──────────────────────────────────────────────────────────────
t0=$(date +%s)
code=$(post "$ALICE_K:$ALICE_S" "{\"action\":\"add\",\"url\":\"git://127.0.0.1:$GP/demo.git\",\"branch\":\"main\",\"bucket\":\"code\"}")
expect "a repository is added, and its first run starts" "$code $(j "d['started']" < "$T/post.out")" "200 True"
st=$(settle "$t0")
expect "the run ends well" "$(echo "$st" | j "d['repos'][0]['state']['ok']")" True
expect "its folder is named after the URL" "$(echo "$st" | j "d['repos'][0]['name']")" demo
expect "and it is pulled only when asked, unless told otherwise" "$(echo "$st" | j "d['repos'][0]['every']")" never
expect "the branch's files are in the library" "$(s3 "http://127.0.0.1:$ST/code/demo/README.md")" hello
expect "in their folders" "$(s3 "http://127.0.0.1:$ST/code/demo/src/deep/a.c")" "int x;"
expect "and four of them" "$(echo "$st" | j "d['repos'][0]['state']['files']")" 4
b1=$(bundles)
expect "and one bundle of its history" "$(echo "$b1" | grep -c '\.bundle$')" 1
s3 -o "$T/b1.bundle" "http://127.0.0.1:$ST/code/$b1"
git clone -q "$T/b1.bundle" "$T/restored" 2>/dev/null
expect "which git clones the repository from" "$(git -C "$T/restored" log --format=%s 2>/dev/null)" one
expect "files and all" "$(cat "$T/restored/run.sh" 2>/dev/null | tail -1)" "echo hi"

# ─── unchanged ──────────────────────────────────────────────────────────────
id=$(echo "$st" | j "d['repos'][0]['id']")
sleep 1; t1=$(date +%s)
post "$ALICE_K:$ALICE_S" "{\"action\":\"sync\",\"id\":\"$id\"}" >/dev/null
st=$(settle "$t1")
expect "a run with nothing new ends well and changes nothing" "$(echo "$st" | j "d['repos'][0]['state']['ok'], d['repos'][0]['state']['changed']")" "(True, False)"
expect "and writes no bundle" "$(bundles | grep -c '\.bundle$')" 1

# ─── changes ────────────────────────────────────────────────────────────────
printf 'hello again\n' > "$T/up/README.md"; git -C "$T/up" rm -q old.txt; printf 'new\n' > "$T/up/src/b.txt"
git -C "$T/up" add -A && git -C "$T/up" commit -qm two && git -C "$T/up" push -q "$T/srv/demo.git" main
sleep 1; t2=$(date +%s)
post "$ALICE_K:$ALICE_S" "{\"action\":\"sync\",\"id\":\"$id\"}" >/dev/null
st=$(settle "$t2")
expect "after a push the run writes what changed" "$(echo "$st" | j "d['repos'][0]['state']['changed'], d['repos'][0]['state']['files']")" "(True, 2)"
expect "the changed file is new" "$(s3 "http://127.0.0.1:$ST/code/demo/README.md")" "hello again"
expect "the added one is there" "$(s3 "http://127.0.0.1:$ST/code/demo/src/b.txt")" new
expect "the removed one is gone" "$(s3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ST/code/demo/old.txt")" 404
expect "and a second bundle is written" "$(bundles | grep -c '\.bundle$')" 2
# What alice is told: the first run and the push each brought something; the run with nothing new brought nothing.
# Told once the run's process is reaped, a moment after its state is written.
for _ in $(seq 1 25); do
    NOTES=$(curl -s -m 10 -u "$ALICE_K:$ALICE_S" -H 'X-Socketley-UI: 1' "http://127.0.0.1:$ST/~ui/notifications")
    [ "$(echo "$NOTES" | j "len([i for i in d['items'] if i['kind']=='sync'])")" = 2 ] && break
    sleep 0.2
done
expect "each run that brought something is news for whoever added the repository" \
    "$(echo "$NOTES" | j "[i['title'] for i in d['items'] if i['kind']=='sync']")" "['demo was updated', 'demo was updated']"
expect "and leads to its folder" "$(echo "$NOTES" | j "d['items'][0]['link']")" "#/code/demo/"

# ─── thinning, by hand ──────────────────────────────────────────────────────
# Bundles of other days, put in as a run would have named them: two and three days old, two of one week five or six
# weeks ago (in one month), and one of more than a year ago.
dates=$(python3 - <<'PY'
import datetime as d
now = d.datetime.now(d.timezone.utc)
for back in range(35, 70):
    a = now - d.timedelta(days=back + 1); b = now - d.timedelta(days=back)
    if a.isocalendar()[1] == b.isocalendar()[1] and a.month == b.month:
        break
for t in (now - d.timedelta(days=2), now - d.timedelta(days=3), a, b, now - d.timedelta(days=400)):
    print(t.strftime("%Y-%m-%d_%H%M%S"))
PY
)
for dt in $dates; do s3 -X PUT --data-binary x "http://127.0.0.1:$ST/code/_backups/demo/${dt}_0000000000.bundle" >/dev/null; done
set -- $dates
# A bundle is named by its second and commit, so one of this commit made in the run's second would be the run's.
sleep 1
SOCKETLEY_GIT_ACCESS_KEY=$ALICE_K SOCKETLEY_GIT_SECRET=$ALICE_S "$BIN" git-sync --url "git://127.0.0.1:$GP/demo.git" \
    --branch main --work "$T/byhand" --endpoint "127.0.0.1:$ST" --bucket code --name demo > "$T/byhand.out" 2>&1
expect "git-sync by hand, with its own clone, ends well" "$?" 0
left=$(bundles)
# The runs' own, by their commit rather than their date, which is yesterday's for a run just before midnight.
expect "the last day's bundles all stay, its own among them" "$(echo "$left" | grep '\.bundle$' | grep -vc '_0000000000\.bundle$')" 3
expect "and the newest of each recent day" "$(echo "$left" | grep -cE "$1|$2")" 2
expect "the newest of an older week stays and the other of it goes" "$(echo "$left" | grep -c "$4") $(echo "$left" | grep -c "$3")" "1 0"
expect "and one more than a year old goes" "$(echo "$left" | grep -c "$5")" 0

# ─── how often ─────────────────────────────────────────────────────────────
expect "it is told to pull every week" "$(post "$ALICE_K:$ALICE_S" "{\"action\":\"every\",\"id\":\"$id\",\"every\":\"week\"}") $(ui "$ALICE_K:$ALICE_S" | j "d['repos'][0]['every']")" "204 week"
expect "and refuses a period that is none" "$(post "$ALICE_K:$ALICE_S" "{\"action\":\"every\",\"id\":\"$id\",\"every\":\"hourly\"}")" 400

# ─── who ────────────────────────────────────────────────────────────────────
expect "another user sees none of alice's repositories" "$(ui "$BOB_K:$BOB_S" | j "len(d['repos'])")" 0
expect "and may not add one into her library" \
    "$(post "$BOB_K:$BOB_S" "{\"action\":\"add\",\"url\":\"git://127.0.0.1:$GP/demo.git\",\"bucket\":\"code\",\"name\":\"bobs\"}")" 403
expect "nor run hers" "$(post "$BOB_K:$BOB_S" "{\"action\":\"sync\",\"id\":\"$id\"}")" 404

# ─── whose runtime runs it ──────────────────────────────────────────────────
# A user with a repository has a sync runtime of their own, made and owned by the storage, which does the runs --
# and a user with none has none, because a runtime is a process and one that syncs nothing is one nobody asked for.
LS=$("$BIN" ls 2>/dev/null)
expect "a user with a repository has a sync runtime of their own, owned by the storage" \
    "$(echo "$LS" | awk '$3 == "sync" && $6 == "st" {print $2}' | sort | tr '\n' ' ')" "st-sync-alice "
expect "and a user with none has none" "$(echo "$LS" | grep -c 'st-sync-bob')" 0
expect "the interface names it" "$(ui "$ALICE_K:$ALICE_S" | j "d['runtime']")" st-sync-alice
expect "and it is what ran alice's repository" "$("$BIN" stats st-sync-alice 2>/dev/null | sed -n 's/^runs://p')" 3

# ─── private ────────────────────────────────────────────────────────────────
code=$(post "$BOB_K:$BOB_S" "{\"action\":\"add\",\"url\":\"git://127.0.0.1:$GP/demo.git\",\"bucket\":\"bobcode\",\"private\":true}")
expect "a private repository without a token is added, and not run" "$code $(j "d['started']" < "$T/post.out")" "200 False"
has "and says why" "$(cat "$T/post.out")" "no GitHub token"
expect "a token is kept" "$(post "$BOB_K:$BOB_S" '{"action":"token","token":"ghp_test123"}') $(ui "$BOB_K:$BOB_S" | j "d['token']")" "204 True"
has "and never shown" "$(ui "$BOB_K:$BOB_S")" '"token":true'
expect "it is sealed, not written as it is" "$(grep -rl ghp_test123 "$T/st/.ui" 2>/dev/null | wc -l)" 0
expect "and removed" "$(post "$BOB_K:$BOB_S" '{"action":"token","token":""}') $(ui "$BOB_K:$BOB_S" | j "d['token']")" "204 False"
expect "an admin sees every repository" "$(ui "$ALICE_K:$ALICE_S" | j "len(d['repos'])")" 2

# ─── the schedule ───────────────────────────────────────────────────────────
# Alice's last pull made two days old and her repository told to pull every day: the schedule, which looks once a
# minute, pulls it again by itself; Bob's, pulled never, is left alone.
if [ "$(date +%-H)" -ge 3 ]; then
    expect "a repository is told to pull every day" "$(post "$ALICE_K:$ALICE_S" "{\"action\":\"every\",\"id\":\"$id\",\"every\":\"day\"}")" 204
    old=$(( $(date +%s) - 2 * 86400 ))
    python3 - "$T/st/.ui/git/$id/state.json" "$old" <<'PY'
import json, sys
p, at = sys.argv[1], int(sys.argv[2])
d = json.load(open(p)); d["at"] = at; json.dump(d, open(p, "w"))
PY
    bobs=$(ui "$BOB_K:$BOB_S" | j "d['repos'][0]['id']")
    got=""
    for _ in $(seq 1 90); do got=$(ui "$ALICE_K:$ALICE_S" | j "[r['state']['at'] for r in d['repos'] if r['id']=='$id'][0] > $old"); [ "$got" = True ] && break; sleep 1; done
    expect "and the schedule pulls it again by itself, a day after" "$got" True
    expect "while one pulled never is not pulled" "$(ui "$BOB_K:$BOB_S" | j "d['repos'][0]['state'] is None or d['repos'][0]['state'].get('commit', '') == ''")" True
else
    echo "  SKIP: the schedule starts runs from 3:00 local time"
fi

# ─── refused ────────────────────────────────────────────────────────────────
expect "a file:// URL is refused" "$(post "$ALICE_K:$ALICE_S" '{"action":"add","url":"file:///etc"}')" 400
expect "and a URL with credentials in it" "$(post "$ALICE_K:$ALICE_S" '{"action":"add","url":"https://u:p@example.com/r.git"}')" 400
expect "and a branch that is none" "$(post "$ALICE_K:$ALICE_S" "{\"action\":\"add\",\"url\":\"git://127.0.0.1:$GP/demo.git\",\"branch\":\"a..b\"}")" 400
expect "and a folder named _backups" "$(post "$ALICE_K:$ALICE_S" "{\"action\":\"add\",\"url\":\"git://127.0.0.1:$GP/demo.git\",\"name\":\"_backups\"}")" 400

# ─── moved ──────────────────────────────────────────────────────────────────
# A repository in the one library every user once shared goes to its owner's own at the next start: its tree is
# written there, its backups are taken along, and the old library, empty then, is gone.
post "$ALICE_K:$ALICE_S" "{\"action\":\"add\",\"url\":\"git://127.0.0.1:$GP/demo.git\",\"bucket\":\"git\",\"name\":\"mig\"}" >/dev/null
mig=$(j "d['id']" < "$T/post.out")
waitrun() {
    local s
    for _ in $(seq 1 150); do
        s=$(ui "$ALICE_K:$ALICE_S")
        [ "$(echo "$s" | j "[r for r in d['repos'] if r['id']=='$1'][0]['running'] is False and ([r for r in d['repos'] if r['id']=='$1'][0]['state'] or {}).get('at', 0) >= $2")" = True ] && break
        sleep 0.2
    done
    echo "$s" | python3 -c 'import json,sys; print(json.dumps([r for r in json.load(sys.stdin)["repos"] if r["id"]==sys.argv[1]][0]))' "$1"
}
t3=$(date +%s)
first=$(waitrun "$mig" "$t3")
expect "a repository written to the shared library git" "$(echo "$first" | j "d['state']['ok'], d['bucket']")" "(True, 'git')"
at1=$(echo "$first" | j "d['state']['at']")
OLDB=$(s3 "http://127.0.0.1:$ST/git?list-type=2&prefix=_backups/mig/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g')
"$BIN" stop st >/dev/null 2>&1; "$BIN" start st >/dev/null 2>&1
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$ST/" && break; sleep 0.1; done
# The run after the start, not the one before it, which may have ended within the same second.
st=$(waitrun "$mig" "$((at1 + 1))")
expect "goes to its owner's own library at the next start" "$(echo "$st" | j "d['state']['ok'], d['bucket']")" "(True, 'git-alice')"
expect "with its files" "$(s3 "http://127.0.0.1:$ST/git-alice/mig/README.md")" "hello again"
expect "and the backup it had" "$(s3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ST/git-alice/$OLDB")" 200
expect "and the old library, which held nothing else, is gone" "$(s3 -o /dev/null -w '%{http_code}' -I "http://127.0.0.1:$ST/git")" 404
# Known once the run's process is reaped, a moment after its state is written.
for _ in $(seq 1 25); do [ -e "$T/st/.ui/git/$mig/moved-from" ] || break; sleep 0.2; done
expect "and once there it is moved no more" "$(ls "$T/st/.ui/git/$mig/moved-from" 2>/dev/null | wc -l)" 0
"$BIN" stop st >/dev/null 2>&1
expect "the users' sync runtimes go with the storage that made them" "$("$BIN" ls 2>/dev/null | grep -c 'st-sync-')" 0
"$BIN" start st >/dev/null 2>&1
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$ST/" && break; sleep 0.1; done

# ─── remove ─────────────────────────────────────────────────────────────────
expect "a repository is removed" "$(post "$ALICE_K:$ALICE_S" "{\"action\":\"remove\",\"id\":\"$id\"}")" 204
expect "and no longer listed" "$(ui "$ALICE_K:$ALICE_S" | j "[r['id'] for r in d['repos']].count('$id')")" 0
expect "while its files stay" "$(s3 "http://127.0.0.1:$ST/code/demo/README.md")" "hello again"

# And her last repository gone takes her runtime with it, which is the other half of making it only when there is
# something to sync.  Waited for, because the storage looks at its runners on a turn of its own.
for _ in $(seq 1 60); do "$BIN" ls 2>/dev/null | grep -q 'st-sync-alice' || break; sleep 0.5; done
expect "and her last repository gone takes her sync runtime with it" \
    "$("$BIN" ls 2>/dev/null | grep -c 'st-sync-alice')" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
