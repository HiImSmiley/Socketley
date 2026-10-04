#!/usr/bin/env bash
# Integration test: share links at /~share/ -- made, used without credentials, limited, and revoked
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a link made by someone who may not read what it names, or one that gives
#     more than its maker may
#   * a link not reading its object or its folder for a visitor, or reading
#     anything outside it
#   * a password not asked for, or a wrong one taken
#   * an expired link still read, or a download limit not kept, counting a
#     player's later ranges against it
#   * an upload link not taking a file into its folder, or a read-only link
#     taking one
#   * a link not seen or not revoked by its maker, seen by another user, or
#     lost by a restart or on the other shard
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: storage share links ==="
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgshare
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1909))
U="http://127.0.0.1:$P1"
T="$SOCKETLEY_TMPD"
cat > "$T/creds" <<EOF
[ann]
AKIASHAREANN00000000:shareannsecretshareannsecretshareann0000
[ben]
AKIASHAREBEN00000000:sharebensecretsharebensecretsharebenx000
EOF
A="AKIASHAREANN00000000:shareannsecretshareannsecretshareann0000"
B="AKIASHAREBEN00000000:sharebensecretsharebensecretsharebenx000"
"$BIN" create storage share -p "$P1" --dir "$T/share" --credentials "$T/creds" --shards 2 -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"
code() { curl -s -m 30 -o /dev/null -w '%{http_code}' "$@"; }
# Makes a link with the JSON given, as the user given, and prints its id, or the status when it was refused.
mk() {
    local out st
    out=$(curl -s -m 30 -u "$1" -X POST -d "$2" -w '\n%{http_code}' "$U/~share")
    st=${out##*$'\n'}
    [ "$st" = 201 ] && python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "${out%$'\n'*}" || echo "$st"
}

curl -s -u "$A" -X MKCOL -o /dev/null "$U/~dav/ann/"
printf 'report' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/report.txt"
printf 'one' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/album/one.jpg"
printf 'two' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/album/sub/two.jpg"
printf 'secret' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/private/s.txt"

# A file's link.
f=$(mk "$A" '{"bucket":"ann","key":"report.txt"}')
check "a link is made" "${#f}" 22
check "and read without credentials" "$(curl -s "$U/~share/$f")" report
check "on either shard" "$(for _ in 1 2 3 4 5 6; do curl -s "$U/~share/$f"; done)" "reportreportreportreportreportreport"
check "?download names the file to save" "$(curl -s -D - -o /dev/null "$U/~share/$f?download" | grep -i '^content-disposition' | tr -d '\r')" \
      'Content-Disposition: attachment; filename="report.txt"'
check "a range of it is read" "$(curl -s -r 2-4 "$U/~share/$f")" por
check "a path under a file's link is 404" "$(code "$U/~share/$f/other")" 404
check "a link is read only" "$(code -T /dev/null "$U/~share/$f")" 405
check "an unknown link is 404" "$(code "$U/~share/AAAAAAAAAAAAAAAAAAAAAA")" 404
check "a malformed one too" "$(code "$U/~share/x")" 404

# Who may make one.
check "making a link takes credentials" "$(code -X POST -d '{"bucket":"ann","key":"report.txt"}' "$U/~share")" 401
check "and the right to read what it names" "$(mk "$B" '{"bucket":"ann","key":"report.txt"}')" 403
check "of a bucket that exists" "$(mk "$A" '{"bucket":"none","key":"x"}')" 404
check "with a body that is JSON" "$(mk "$A" 'nope')" 400
check "and an upload link is a folder's" "$(mk "$A" '{"bucket":"ann","key":"report.txt","upload":true}')" 400

# A folder's link.
d=$(mk "$A" '{"bucket":"ann","key":"album/"}')
check "a folder link lists what is in it" "$(curl -s "$U/~share/$d/?format=json" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j["folders"], [x["name"] for x in j["files"]], j["upload"])')" \
      "['sub/'] ['one.jpg'] False"
check "as a page for a browser" "$(curl -s "$U/~share/$d/" | grep -c 'one.jpg')" 1
check "and reads a file in it" "$(curl -s "$U/~share/$d/sub/two.jpg")" two
check "and nothing outside it" "$(code --path-as-is "$U/~share/$d/../private/s.txt")" 404
check "nor a file it does not hold" "$(code "$U/~share/$d/none.jpg")" 404
check "a read-only folder link takes no upload" "$(code -T /dev/null "$U/~share/$d/new.jpg")" 405

# A password.
p=$(mk "$A" '{"bucket":"ann","key":"report.txt","password":"open sesame"}')
check "a link with a password asks for it" "$(code "$U/~share/$p")" 401
check "in a way a browser shows" "$(curl -s -D - -o /dev/null "$U/~share/$p" | grep -ci '^www-authenticate: basic')" 1
check "refuses a wrong one" "$(code -u "x:wrong" "$U/~share/$p")" 401
check "and takes the right one, with any name" "$(curl -s -u "anyone:open sesame" "$U/~share/$p")" report
check "the password is not kept in the clear" "$(grep -rc 'open sesame' "$T/share/.shares/" | grep -vc ':0')" 0

# Expiry and download limits.
e=$(mk "$A" '{"bucket":"ann","key":"report.txt","expires_in":1}')
check "a link before its expiry is read" "$(code "$U/~share/$e")" 200
sleep 2.1
check "and after it is 410" "$(code "$U/~share/$e")" 410
l=$(mk "$A" '{"bucket":"ann","key":"report.txt","max_downloads":2}')
check "a limited link is read" "$(code "$U/~share/$l")" 200
check "a range past the start does not count" "$(for _ in 1 2 3; do code -r 2-3 "$U/~share/$l"; done)" 206206206
check "a second time" "$(code "$U/~share/$l")" 200
check "and then no more" "$(code "$U/~share/$l")" 410

# Downloads at once against a limit: exactly as many as it allows, whichever shard each lands on.
m=$(mk "$A" '{"bucket":"ann","key":"report.txt","max_downloads":3}')
pids=(); : > "$T/many"
for _ in 1 2 3 4 5 6 7 8; do curl -s -o /dev/null -w '%{http_code}\n' "$U/~share/$m" >> "$T/many" & pids+=($!); done
wait "${pids[@]}"
check "eight downloads at once of a link allowing three" "$(sort "$T/many" | uniq -c | awk '{print $1":"$2}' | tr '\n' ' ')" "3:200 5:410 "

# An upload link.
w=$(mk "$A" '{"bucket":"ann","key":"inbox/","upload":true}')
check "an upload link takes a file" "$(printf 'dropped' | code -T - "$U/~share/$w/drop.txt")" 201
check "into its folder" "$(curl -s -u "$A" "$U/~dav/ann/inbox/drop.txt")" dropped
check "and says so to a browser" "$(curl -s "$U/~share/$w/?format=json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["upload"])')" True
check "but not over a folder" "$(printf 'x' | code -T - "$U/~share/$w/")" 405

# Listing and revoking.
mine=$(curl -s -u "$A" "$U/~share" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
check "the maker lists the links, the expired one gone" "$mine" 6
check "another user lists none of them" "$(curl -s -u "$B" "$U/~share")" "[]"
check "nor revokes one" "$(code -u "$B" -X DELETE "$U/~share/$f")" 403
check "a link outlives a restart" \
      "$("$BIN" stop share >/dev/null 2>&1; "$BIN" start share >/dev/null 2>&1; up; curl -s "$U/~share/$f")" report
check "its maker revokes it" "$(code -u "$A" -X DELETE "$U/~share/$f")" 204
check "and it reads no more" "$(code "$U/~share/$f")" 404
check "on either shard" "$(for _ in 1 2 3 4; do code "$U/~share/$f"; done)" 404404404404

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
