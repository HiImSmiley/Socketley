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
#   * a folder link's ZIP not holding the folder, or counted as more than one
#     download, or naming entries that unpack outside the visitor's folder
#   * a link's webhook not told of a download or of its files' removal, or a
#     webhook taken that the runtime may not reach for its users
#   * a link that burns leaving its file behind at its expiry, after its last
#     download or at its revocation, removing it before, counting its page or
#     a link preview as a download, or being made by one who may not delete
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
# A burning link's files outlive its last download by two seconds here, not ten minutes.
export SOCKETLEY_SHARE_BURN_GRACE_SECS=2
# A link's webhook here is a listener on this machine, which the runtime may reach only when this names it.
HOOK_PORT=$((SL_PORT_BASE + 1919))
export SOCKETLEY_SHARE_NOTIFY_ALLOW="http://127.0.0.1:$HOOK_PORT/"
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

# A folder's link as one ZIP.
zl=$(mk "$A" '{"bucket":"ann","key":"album/","max_downloads":1}')
check "a folder link's page offers its ZIP" "$(curl -s "$U/~share/$zl/" | grep -c 'href="?zip"')" 1
check "which holds the folder" "$(curl -s -o "$T/l.zip" "$U/~share/$zl/?zip"; python3 -c 'import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); print(z.testzip(), [i.filename for i in z.infolist()])' "$T/l.zip")" "None ['one.jpg', 'sub/two.jpg']"
check "and counts as one download" "$(code "$U/~share/$zl/?zip")" 410

# A folder link's ZIP of keys its owner chose to escape the folder the visitor unpacks into.
zipsafe() { python3 - "$1" "$2" <<'ZEOF'
import zipfile, sys, os
z = zipfile.ZipFile(sys.argv[1])
names = [i.filename for i in z.infolist()]
bad = [n for n in names if n.startswith("/") or "\\" in n or any(s in ("", ".", "..") for s in n.split("/"))
       or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in n)]
contents = sorted(z.read(n).decode() for n in names)
print("bad=%s unique=%s test=%s size=%s contents=%s" % (bad, len(set(names)) == len(names), z.testzip(),
      os.path.getsize(sys.argv[1]) == int(sys.argv[2]), contents))
ZEOF
}
for k in 'z/../../evil.txt' 'z/./dot.txt' 'z//double.txt' 'z/double.txt' 'z/back%5Cslash.txt' 'z/a/../a.txt' 'z/a.txt' 'z/ctrl%01name.txt'; do
    printf '%s' "$k" | curl -s -m 30 --path-as-is --aws-sigv4 "aws:amz:us-east-1:s3" -u "$A" -T - -o /dev/null "$U/ann/$k"
done
zz=$(mk "$A" '{"bucket":"ann","key":"z/"}')
len=$(curl -s -o "$T/z.zip" -D - "$U/~share/$zz/?zip" | grep -i '^content-length' | tr -d '\r' | cut -d' ' -f2)
check "a link's ZIP names nothing outside the visitor's folder" "$(zipsafe "$T/z.zip" "$len")" \
      "bad=[] unique=True test=None size=True contents=['z/../../evil.txt', 'z/./dot.txt', 'z//double.txt', 'z/a.txt', 'z/a/../a.txt', 'z/back%5Cslash.txt', 'z/ctrl%01name.txt', 'z/double.txt']"

# A link's webhook, told of each download and of the removal of what burns.
python3 - "$HOOK_PORT" "$T/hook" <<'PYEOF2' &
import http.server, sys
out = open(sys.argv[2], "a")
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        out.write(self.path + " " + body.decode() + "\n"); out.flush()
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF2
HOOK_PID=$!
trap 'kill $HOOK_PID 2>/dev/null; daemon_stop' EXIT
sleep 0.5
printf 'tell' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/send/told.txt"
check "a webhook the runtime may not reach is refused" "$(mk "$A" '{"bucket":"ann","key":"send/told.txt","notify":"http://169.254.169.254/latest"}')" 400
hk=$(mk "$A" '{"bucket":"ann","key":"send/told.txt","max_downloads":1,"burn":true,"notify":"http://127.0.0.1:'"$HOOK_PORT"'/hook/x"}')
check "the link says it tells a webhook" "$(curl -s -u "$A" "$U/~share" | python3 -c 'import json,sys; print([x["notify"] for x in json.load(sys.stdin) if x["id"]==sys.argv[1]])' "$hk")" "[True]"
curl -s -o /dev/null "$U/~share/$hk?download"
waithook() { for _ in $(seq 1 80); do grep -q "$1" "$T/hook" 2>/dev/null && return 0; sleep 0.25; done; return 1; }
check "a download is told to its webhook, at its path" \
      "$(waithook '"event":"downloaded"' && grep downloaded "$T/hook" | python3 -c 'import json,sys; l=sys.stdin.readline(); p,b=l.split(" ",1); d=json.loads(b); print(p, d["event"], d["key"], d["downloads"], d["max_downloads"], "told.txt was downloaded (1 of 1)" in d["content"])')" \
      "/hook/x downloaded send/told.txt 1 1 True"
check "and so is the removal of what burned, once whatever shard sees it" \
      "$(waithook '"event":"deleted"' && sleep 6 && grep -c '"event":"deleted"' "$T/hook")" 1

# Links that burn what they name, as a file sent once.
gone() { for _ in $(seq 1 40); do [ "$(code -u "$A" "$U/~dav/ann/$1")" = 404 ] && { echo gone; return; }; sleep 0.5; done; echo there; }
printf 'secret' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/send/once.txt"
check "a link that burns needs an end" "$(mk "$A" '{"bucket":"ann","key":"send/once.txt","burn":true}')" 400
check "and is no upload link" "$(mk "$A" '{"bucket":"ann","key":"send/","burn":true,"upload":true,"max_downloads":1}')" 400
check "nor made by one who may not delete there" "$(mk "$B" '{"bucket":"ann","key":"send/once.txt","burn":true,"max_downloads":1}')" 403
o=$(mk "$A" '{"bucket":"ann","key":"send/once.txt","burn":true,"max_downloads":1}')
check "opens on a page" "$(curl -s "$U/~share/$o" | grep -c 'href="?download"')" 1
check "which gives the file's size, whichever shard answers" "$(for _ in 1 2 3 4; do curl -s "$U/~share/$o" | grep -c '<span>6 bytes</span>'; done | tr -d '\n')" 1111
check "which a preview reads again and again without a download" "$(code "$U/~share/$o")$(code "$U/~share/$o")" 200200
check "the file is read with ?download" "$(curl -s "$U/~share/$o?download")" secret
check "once" "$(code "$U/~share/$o?download")" 410
check "and is still there for the grace after it" "$(code -u "$A" "$U/~dav/ann/send/once.txt")" 200
check "then gone" "$(gone send/once.txt)" gone
check "with its link" "$(code "$U/~share/$o")" 404
printf 'a' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/send/box/a.txt"
printf 'b' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/send/box/b.txt"
e=$(mk "$A" '{"bucket":"ann","key":"send/box/","burn":true,"expires_in":2}')
check "a folder that burns reads until its expiry" "$(curl -s "$U/~share/$e/b.txt")" b
check "it is not counted as a download, as no limit was set" "$(curl -s "$U/~share/$e/a.txt")" a
check "and after its expiry every file under it is gone" "$(gone send/box/a.txt) $(gone send/box/b.txt)" "gone gone"
check "the folder link with them" "$(code "$U/~share/$e/")" 404
printf 'r' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/send/revoked.txt"
v=$(mk "$A" '{"bucket":"ann","key":"send/revoked.txt","burn":true,"expires_in":3600}')
check "a link that burns is listed as one" "$(curl -s -u "$A" "$U/~share" | python3 -c 'import json,sys; print([x["burn"] for x in json.load(sys.stdin) if x["id"]==sys.argv[1]])' "$v")" "[True]"
check "a revoked one takes its file with it" "$(code -u "$A" -X DELETE "$U/~share/$v") $(gone send/revoked.txt)" "204 gone"
printf 'k' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/ann/send/kept.txt"
k=$(mk "$A" '{"bucket":"ann","key":"send/kept.txt","max_downloads":1}')
curl -s -o /dev/null "$U/~share/$k"; sleep 6
check "a link that does not burn leaves its file after its last download" "$(code -u "$A" "$U/~dav/ann/send/kept.txt")" 200
r=$(mk "$A" '{"bucket":"ann","key":"send/kept.txt","burn":true,"expires_in":4}')
"$BIN" stop share >/dev/null 2>&1; sleep 5; "$BIN" start share >/dev/null 2>&1; up
check "one that ended while the runtime was stopped burns at its start" "$(gone send/kept.txt)" gone

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
