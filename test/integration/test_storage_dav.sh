#!/usr/bin/env bash
# Integration test: the WebDAV drive at /~dav/, its trash, and the web interface at /~ui/
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a drive that takes no credentials, takes wrong ones, or asks a browser
#     for them when the web interface signs in itself
#   * a folder, a file or a bucket a WebDAV client makes, lists, copies, moves
#     or removes not being what S3 then sees, on either shard
#   * a folder's copy or move losing an object, or its removal leaving one
#   * a user seeing or writing another user's bucket through the drive
#   * a versioned bucket's deleted file missing from its trash, or not brought
#     back by a restore
#   * the interface not served, or served without its content policy
#   * a sign-in cookie not let in, let in tampered with, expired or after its
#     key's secret changed, readable by script, or taking a change that does
#     not carry the interface's header; a session extending itself
#   * a file read with ?download not saved under its name
#   * a folder's ZIP not holding its files byte for byte, its Content-Length
#     not its length, a selection taking more than it named, or the ZIP
#     giving what its reader may not read
#   * a ZIP entry named so it unpacks outside its folder ("..", a leading or
#     doubled '/', '\\'), with a control character, or twice under one name
#   * a user's watch positions seen by another user, kept for what the user
#     may not read, or shown after the film was replaced
#   * a search missing a file or folder by part of its name in any case,
#     or finding one the user may not list
#   * a library's size in the usage not its bytes, a user seeing another's
#     library there, or a quota set by one who is not an admin
#   * a library shared with a user not listed or not readable by them, giving
#     more than it says, shared by one who may not, or its policy's other
#     statements lost when it is shared or unshared
#   * an rclone mount's copy of a tree not coming back byte for byte
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: storage WebDAV ==="
RCLONE="${RCLONE:-$(command -v rclone || true)}"
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgdav
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1907))
U="http://127.0.0.1:$P1"
T="$SOCKETLEY_TMPD"
cat > "$T/creds" <<EOF
[ann]
AKIADAVANN0000000000:davannsecretdavannsecretdavannsecret0000
[ben]
AKIADAVBEN0000000000:davbensecretdavbensecretdavbensecret0000
[boss]
admin = true
AKIADAVBOSS000000000:davbosssecretdavbosssecretdavbosssecret00
EOF
R="AKIADAVBOSS000000000:davbosssecretdavbosssecretdavbosssecret00"
A="AKIADAVANN0000000000:davannsecretdavannsecretdavannsecret0000"
B="AKIADAVBEN0000000000:davbensecretdavbensecretdavbensecret0000"
"$BIN" create storage dav -p "$P1" --dir "$T/dav" --credentials "$T/creds" --shards 2 -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"
code() { curl -s -m 30 -o /dev/null -w '%{http_code}' "$@"; }
s3() { curl -s -m 30 --aws-sigv4 "aws:amz:us-east-1:s3" -u "$A" "$@"; }
# The names a PROPFIND of depth 1 lists, its own first.
names() { curl -s -m 30 -u "$1" -X PROPFIND -H 'Depth: 1' "$U/~dav/$2" | grep -o '<D:displayname>[^<]*' | sed 's/<D:displayname>//' | tr '\n' ' ' | sed 's/ $//'; }

# Signing in.
check "OPTIONS names the DAV classes" "$(curl -s -o /dev/null -D - -X OPTIONS "$U/~dav/" | grep -i '^dav:' | tr -d '\r')" "DAV: 1, 2"
check "no credentials are 401" "$(code -X PROPFIND "$U/~dav/")" 401
check "which asks a browser for them" "$(curl -s -o /dev/null -D - -X PROPFIND "$U/~dav/" | grep -ci '^www-authenticate: basic')" 1
check "but not the web interface, which asks itself" "$(curl -s -o /dev/null -D - -H 'X-Socketley-UI: 1' -X PROPFIND "$U/~dav/" | grep -ci '^www-authenticate')" 0
check "a wrong secret is 401" "$(code -u "AKIADAVANN0000000000:nope" -X PROPFIND "$U/~dav/")" 401

# Folders and files.
check "MKCOL at the root makes a bucket" "$(code -u "$A" -X MKCOL "$U/~dav/docs/")" 201
check "which S3 sees" "$(code --aws-sigv4 "aws:amz:us-east-1:s3" -u "$A" -I "$U/docs")" 200
check "a second MKCOL of it is 405" "$(code -u "$A" -X MKCOL "$U/~dav/docs/")" 405
check "MKCOL in a bucket makes a folder" "$(code -u "$A" -X MKCOL "$U/~dav/docs/a")" 201
check "a second MKCOL of a folder is 405" "$(code -u "$A" -X MKCOL "$U/~dav/docs/a")" 405
check "the folder is S3's marker object" "$(s3 -s -o /dev/null -w '%{http_code}' -I "$U/docs/a/")" 200
printf 'one' > "$T/one"; head -c 300000 /dev/urandom > "$T/big"
check "PUT of a file is 201" "$(code -u "$A" -T "$T/one" "$U/~dav/docs/a/one.txt")" 201
check "and a larger one" "$(code -u "$A" -T "$T/big" "$U/~dav/docs/a/sub/big.bin")" 201
head -c 5000000 /dev/urandom > "$T/huge"
check "a file that waits for 100 Continue" "$(code -u "$A" -H 'Expect: 100-continue' -T "$T/huge" "$U/~dav/docs/huge.bin")" 201
check "is stored whole" "$(curl -s -u "$A" "$U/~dav/docs/huge.bin" | cmp -s - "$T/huge" && echo same)" same
check "a GET reads it back" "$(curl -s -u "$A" "$U/~dav/docs/a/one.txt")" one
check "and S3 too" "$(s3 "$U/docs/a/sub/big.bin" | cmp -s - "$T/big" && echo same)" same
check "a folder lists its files and subfolders" "$(names "$A" docs/a/)" "a sub one.txt"
check "the root lists the user's buckets" "$(names "$A" "")" " docs"
check "a file's PROPFIND gives its length" \
      "$(curl -s -u "$A" -X PROPFIND -H 'Depth: 0' "$U/~dav/docs/a/sub/big.bin" | grep -o '<D:getcontentlength>[0-9]*' | cut -d'>' -f2)" 300000
check "a folder without its slash is a folder" "$(curl -s -u "$A" -X PROPFIND -H 'Depth: 0' "$U/~dav/docs/a/sub" | grep -c '<D:collection/>')" 1
check "a missing path is 404" "$(code -u "$A" -X PROPFIND -H 'Depth: 0' "$U/~dav/docs/nope")" 404
check "a folder opened in a browser is a page" "$(curl -s -u "$A" "$U/~dav/docs/a/" | grep -c 'one.txt')" 1
# What follows a HEAD's head on one connection, with a GET sent behind it: the GET's status line when the HEAD
# carried no body, as curl would hide by opening another connection.
after_head() { python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import socket, sys, base64
port, auth, head, get = sys.argv[1:5]
a = base64.b64encode(auth.encode()).decode()
req = lambda m, p: ("%s %s HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\n\r\n" % (m, p, a)).encode()
s = socket.create_connection(("127.0.0.1", int(port)))
s.sendall(req("HEAD", head) + req("GET", get))
s.settimeout(3)
data = b""
try:
    while b"\r\n\r\n" not in data[data.find(b"\r\n\r\n") + 4:]:
        d = s.recv(65536)
        if not d:
            break
        data += d
except Exception:
    pass
i = data.find(b"\r\n\r\n")
print(data[i + 4:i + 16].decode(errors="replace"))
PYEOF
}
check "a HEAD of a folder's page answers no body, so the next answer is read as itself" \
      "$(after_head "$P1" "$A" /~dav/docs/a/ /~dav/docs/a/one.txt)" "HTTP/1.1 200"
check "PROPPATCH is answered" "$(code -u "$A" -X PROPPATCH "$U/~dav/docs/a/one.txt" -d '<x/>')" 207
check "LOCK gives a token" "$(curl -s -u "$A" -X LOCK -D - -o /dev/null "$U/~dav/docs/a/one.txt" | grep -ci '^lock-token: <opaquelocktoken:')" 1
check "UNLOCK is 204" "$(code -u "$A" -X UNLOCK -H 'Lock-Token: <x>' "$U/~dav/docs/a/one.txt")" 204

# A folder past one page of a listing.
curl -s -u "$A" -T "$T/one" -o /dev/null "$U/~dav/docs/many/f[1-1100]"
check "a folder of 1100 files lists them all" \
      "$(curl -s -u "$A" -X PROPFIND -H 'Depth: 1' "$U/~dav/docs/many/" | grep -o '<D:getcontentlength>' | wc -l)" 1100
check "and so does its page" "$(curl -s -u "$A" "$U/~dav/docs/many/" | grep -o '<li>' | wc -l)" 1100
check "and it is removed whole" "$(code -u "$A" -X DELETE "$U/~dav/docs/many/")" 204

# Copy and move, of a file and of a folder.
dst() { echo "Destination: $U/~dav/$1"; }
check "COPY of a file is 201" "$(code -u "$A" -X COPY -H "$(dst docs/b/one-copy.txt)" "$U/~dav/docs/a/one.txt")" 201
check "and the copy reads the same" "$(curl -s -u "$A" "$U/~dav/docs/b/one-copy.txt")" one
check "MOVE of a file is 201" "$(code -u "$A" -X MOVE -H "$(dst docs/b/moved.txt)" "$U/~dav/docs/b/one-copy.txt")" 201
check "and leaves no source" "$(code -u "$A" "$U/~dav/docs/b/one-copy.txt")" 404
check "COPY of a folder is 201" "$(code -u "$A" -X COPY -H "$(dst docs/c/)" "$U/~dav/docs/a/")" 201
check "with every object under it" "$(curl -s -u "$A" "$U/~dav/docs/c/sub/big.bin" | cmp -s - "$T/big" && echo same)" same
check "MOVE of a folder is 201" "$(code -u "$A" -X MOVE -H "$(dst docs/d/)" "$U/~dav/docs/c/")" 201
check "and the folder is gone" "$(code -u "$A" -X PROPFIND -H 'Depth: 0' "$U/~dav/docs/c")" 404
check "its objects moved" "$(names "$A" docs/d/)" "d sub one.txt"
check "DELETE of a folder is 204" "$(code -u "$A" -X DELETE "$U/~dav/docs/d/")" 204
check "and leaves nothing under it" "$(s3 "$U/docs?list-type=2&prefix=d/" | grep -c '<Key>')" 0
check "COPY without a Destination is 400" "$(code -u "$A" -X COPY "$U/~dav/docs/a/one.txt")" 400

# A file sent in parts side by side, as the web interface sends a large one.
head -c 6000000 /dev/urandom > "$T/p1"; head -c 1234567 /dev/urandom > "$T/p2"; cat "$T/p1" "$T/p2" > "$T/parts"
mpu=$(curl -s -u "$A" -X POST -H 'Content-Type: video/mp4' "$U/~dav/docs/film.mp4?uploads" | grep -o '<UploadId>[^<]*' | cut -d'>' -f2)
check "POST ?uploads begins an upload in parts" "${#mpu}" 32
etag() { curl -s -u "$A" -T "$1" -D - -o /dev/null "$U/~dav/docs/film.mp4?partNumber=$2&uploadId=$mpu" | grep -i '^etag:' | cut -d' ' -f2 | tr -d '\r'; }
e2=$(etag "$T/p2" 2); e1=$(etag "$T/p1" 1)
check "each part is taken, in any order" "${#e1}${#e2}" 3434
check "nothing is there before the upload is completed" "$(code -u "$A" "$U/~dav/docs/film.mp4")" 404
check "GET ?uploadId lists the parts that arrived, to take an upload up again" \
      "$(curl -s -u "$A" "$U/~dav/docs/film.mp4?uploadId=$mpu" | grep -o '<PartNumber>[0-9]*' | cut -d'>' -f2 | tr '\n' ' ')" "1 2 "
check "a page at a time" "$(curl -s -u "$A" "$U/~dav/docs/film.mp4?uploadId=$mpu&max-parts=1" | grep -o '<NextPartNumberMarker>[0-9]*' | cut -d'>' -f2)" 1
check "POST ?uploadId completes it" "$(code -u "$A" -X POST "$U/~dav/docs/film.mp4?uploadId=$mpu" \
      -d "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>$e1</ETag></Part><Part><PartNumber>2</PartNumber><ETag>$e2</ETag></Part></CompleteMultipartUpload>")" 200
check "into the file whole" "$(curl -s -u "$A" "$U/~dav/docs/film.mp4" | cmp -s - "$T/parts" && echo same)" same
check "with the type it was begun with" "$(curl -s -u "$A" -I "$U/~dav/docs/film.mp4" | grep -i '^content-type:' | tr -d '\r')" "Content-Type: video/mp4"
check "a folder's upload in parts is no upload" "$(code -u "$A" -X POST "$U/~dav/docs/a/?uploads")" 405
mpu=$(curl -s -u "$A" -X POST "$U/~dav/docs/gone.bin?uploads" | grep -o '<UploadId>[^<]*' | cut -d'>' -f2)
check "DELETE ?uploadId abandons one" "$(code -u "$A" -X DELETE "$U/~dav/docs/gone.bin?uploadId=$mpu")" 204
check "which leaves no upload behind" "$(s3 "$U/docs?uploads" | grep -c '<UploadId>')" 0
check "another user may not begin one in the bucket" "$(code -u "$B" -X POST "$U/~dav/docs/x.bin?uploads")" 403
check "nor without credentials" "$(code -X POST "$U/~dav/docs/x.bin?uploads")" 401
check "the drive's PUT of a file still ignores S3's own queries" "$(code -u "$A" -T "$T/one" "$U/~dav/docs/q.txt?tagging")" 201
s3 -o /dev/null -X DELETE "$U/docs/film.mp4"; s3 -o /dev/null -X DELETE "$U/docs/q.txt"

# Another user's bucket.
check "another user's root does not list it" "$(names "$B" "")" ""
check "nor may they read it" "$(code -u "$B" "$U/~dav/docs/a/one.txt")" 403
check "or write to it" "$(code -u "$B" -T "$T/one" "$U/~dav/docs/x.txt")" 403
check "or list it" "$(code -u "$B" -X PROPFIND -H 'Depth: 1' "$U/~dav/docs/")" 403
check "a bucket with something in it is not removed" "$(code -u "$A" -X DELETE "$U/~dav/docs/")" 409

# The trash of a versioned bucket.
check "versioning is turned on" "$(s3 -o /dev/null -w '%{http_code}' -X PUT "$U/docs?versioning" \
      -d '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>')" 200
printf 'v1' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/docs/t/keep.txt"
printf 'v2' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/docs/t/keep.txt"
check "a deleted file" "$(code -u "$A" -X DELETE "$U/~dav/docs/t/keep.txt")" 204
check "is gone from its folder" "$(code -u "$A" "$U/~dav/docs/t/keep.txt")" 404
trash=$(curl -s -u "$A" "$U/~dav/docs/?trash")
check "and in the bucket's trash, with the size it had" "$(python3 -c 'import json,sys; print([(x["key"], x["size"]) for x in json.loads(sys.argv[1])])' "$trash")" "[('t/keep.txt', 2)]"
check "a folder's trash holds what was under it" "$(curl -s -u "$A" "$U/~dav/docs/t/?trash" | grep -c keep.txt)" 1
check "another user may not look into it" "$(code -u "$B" "$U/~dav/docs/?trash")" 403
check "a restore is 204" "$(code -u "$A" -X POST "$U/~dav/docs/t/keep.txt?restore")" 204
check "and brings back the last version" "$(curl -s -u "$A" "$U/~dav/docs/t/keep.txt")" v2
check "which leaves the trash" "$(curl -s -u "$A" "$U/~dav/docs/?trash")" "[]"
check "a file not in the trash is 409" "$(code -u "$A" -X POST "$U/~dav/docs/t/keep.txt?restore")" 409

# The web interface.
check "the interface is served" "$(code "$U/~ui/")" 200
check "as a page with its script" "$(curl -s "$U/~ui/" | grep -c '<script>')" 1
check "under a content policy" "$(curl -s -o /dev/null -D - "$U/~ui/" | grep -ci "^content-security-policy: default-src 'self'")" 1
check "and only read" "$(code -X POST "$U/~ui/")" 405
check "a path of no application is refused" "$(code "$U/~nope/")" 400

# The interface's sign-in: a cookie sealed with the key's secret.
jar="$T/jar"
check "a sign-in with a wrong secret is 401" "$(code -X POST -u "AKIADAVANN0000000000:nope" "$U/~ui/session")" 401
check "and with none" "$(code -X POST "$U/~ui/session")" 401
hdr=$(curl -s -u "$A" -X POST -c "$jar" -D - -o "$T/who" "$U/~ui/session")
check "a sign-in sets a cookie script cannot read and no other site sends" \
      "$(echo "$hdr" | grep -i '^set-cookie: skl_ui=' | grep -ci 'httponly; samesite=strict')" 1
check "a session without ?remember ends with the browser" "$(echo "$hdr" | grep -i '^set-cookie: skl_ui=' | grep -ci 'max-age')" 0
check "and says who signed in" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["user"])' "$T/who")" ann
check "?remember keeps it a month" \
      "$(curl -s -u "$A" -X POST -D - -o /dev/null "$U/~ui/session?remember" | grep -i '^set-cookie: skl_ui=' | grep -o 'Max-Age=[0-9]*')" Max-Age=2592000
ck=$(grep skl_ui "$jar" | awk '{print $7}')
check "the cookie lists a folder" "$(code -b "skl_ui=$ck" -X PROPFIND -H 'Depth: 1' "$U/~dav/docs/")" 207
check "on either shard" "$(for _ in 1 2 3 4; do code -b "skl_ui=$ck" "$U/~dav/docs/a/one.txt"; done)" 200200200200
check "and reads media" "$(code -b "skl_ui=$ck" "$U/~ui/session")" 200
check "a change under it without the interface's header is refused" "$(code -b "skl_ui=$ck" -X DELETE "$U/~dav/docs/a/one.txt")" 403
check "with it, taken" "$(printf 'cookie' | code -b "skl_ui=$ck" -H 'X-Socketley-UI: 1' -T - "$U/~dav/docs/cookie.txt")" 201
check "a cookie whose seal was altered is 401" "$(code -b "skl_ui=${ck%?}$( [ "${ck: -1}" = 0 ] && echo 1 || echo 0)" "$U/~ui/session")" 401
key64=${ck%%.*}; mac=${ck##*.}
check "as is one whose expiry was moved on" "$(code -b "skl_ui=$key64.99999999999999.$mac" "$U/~ui/session")" 401
past=$(python3 -c 'import hmac,hashlib,sys,time; e=int(time.time()*1000)-1000; print("%d.%s" % (e, hmac.new(sys.argv[1].encode(), ("socketley-ui\n%s\n%d" % (sys.argv[2], e)).encode(), hashlib.sha256).hexdigest()))' "${A#*:}" "${A%%:*}")
check "and one past its expiry, though sealed right" "$(code -b "skl_ui=$key64.$past" "$U/~ui/session")" 401
check "a session cannot make itself a new one" "$(code -b "skl_ui=$ck" -X POST "$U/~ui/session")" 401
check "nor does a stale cookie make a browser ask for credentials" "$(curl -s -o /dev/null -D - -b 'skl_ui=x.1.y' "$U/~dav/" | grep -ci '^www-authenticate')" 0
check "a file read with ?download is saved under its name" \
      "$(curl -s -o /dev/null -D - -b "skl_ui=$ck" "$U/~dav/docs/a/one.txt?download" | grep -i '^content-disposition' | tr -d '\r')" \
      "Content-Disposition: attachment; filename=\"one.txt\"; filename*=UTF-8''one.txt"
check "signing out clears the cookie" "$(curl -s -X DELETE -D - -o /dev/null "$U/~ui/session" | grep -i '^set-cookie: skl_ui=;' | grep -c 'Max-Age=0')" 1

# A folder as one ZIP.
zipinfo() { python3 -c 'import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); print(z.testzip(), sorted((i.filename, i.file_size) for i in z.infolist()))' "$1"; }
check "a folder's ZIP has its files under their paths, each whole" \
      "$(curl -s -u "$A" -o "$T/a.zip" "$U/~dav/docs/a/?zip"; zipinfo "$T/a.zip")" "None [('one.txt', 3), ('sub/big.bin', 300000)]"
check "its Content-Length is its length" \
      "$(curl -s -u "$A" -o /dev/null -D - "$U/~dav/docs/a/?zip" | grep -i '^content-length' | tr -d '\r' | cut -d' ' -f2)" "$(stat -c %s "$T/a.zip")"
check "and it is saved under the folder's name" \
      "$(curl -s -u "$A" -o /dev/null -D - "$U/~dav/docs/a?zip" | grep -i '^content-disposition' | grep -c 'filename="a.zip"')" 1
check "a big file in it is the file" "$(python3 -c 'import zipfile,sys; print(zipfile.ZipFile(sys.argv[1]).read("sub/big.bin") == open(sys.argv[2],"rb").read())' "$T/a.zip" "$T/big")" True
check "?n= takes only what it names" "$(curl -s -u "$A" -o "$T/n.zip" "$U/~dav/docs/a/?zip&n=sub"; zipinfo "$T/n.zip")" "None [('sub/big.bin', 300000)]"
check "a whole bucket is one too" "$(curl -s -u "$A" -o "$T/b.zip" "$U/~dav/docs?zip"; python3 -c 'import zipfile,sys; print(zipfile.ZipFile(sys.argv[1]).testzip())' "$T/b.zip")" None
check "another user gets no ZIP of it" "$(code -u "$B" "$U/~dav/docs/a/?zip")" 403
check "nor of an empty folder" "$(curl -s -u "$A" -X MKCOL -o /dev/null "$U/~dav/docs/hollow"; code -u "$A" "$U/~dav/docs/hollow/?zip")" 404

# Keys an unzipper would put outside the folder, or not as named: each key's object holds the key itself.
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
    printf '%s' "$k" | curl -s -m 30 --path-as-is --aws-sigv4 "aws:amz:us-east-1:s3" -u "$A" -T - -o /dev/null "$U/docs/$k"
done
len=$(curl -s -u "$A" -o "$T/z.zip" -D - "$U/~dav/docs/z/?zip" | grep -i '^content-length' | tr -d '\r' | cut -d' ' -f2)
check "a ZIP's names stay inside the folder, plain, and each once, and each holds its key's object" "$(zipsafe "$T/z.zip" "$len")" \
      "bad=[] unique=True test=None size=True contents=['z/../../evil.txt', 'z/./dot.txt', 'z//double.txt', 'z/a.txt', 'z/a/../a.txt', 'z/back%5Cslash.txt', 'z/ctrl%01name.txt', 'z/double.txt']"
check "where two keys clean to one name, the second is numbered" \
      "$(python3 -c 'import zipfile,sys; print(sorted(i.filename for i in zipfile.ZipFile(sys.argv[1]).infolist() if "double" in i.filename))' "$T/z.zip")" \
      "['double (2).txt', 'double.txt']"
for k in 'z/../../evil.txt' 'z/./dot.txt' 'z//double.txt' 'z/double.txt' 'z/back%5Cslash.txt' 'z/a/../a.txt' 'z/a.txt' 'z/ctrl%01name.txt'; do s3 -o /dev/null --path-as-is -X DELETE "$U/docs/$k"; done

# Watch positions, a user's own.
pos() { curl -s -b "skl_ui=$ck" -H 'X-Socketley-UI: 1' -o /dev/null -w '%{http_code}' -X POST -d "$1" "$U/~ui/progress"; }
check "a position is kept" "$(pos '{"bucket":"docs","key":"huge.bin","t":61.5,"d":3600}')" 204
check "beside another" "$(pos '{"bucket":"docs","key":"cookie.txt","t":3,"d":10}')" 204
check "and both are listed, the latest first" \
      "$(curl -s -b "skl_ui=$ck" "$U/~ui/progress" | python3 -c 'import json,sys; print([(x["key"], x["t"]) for x in json.load(sys.stdin)])')" \
      "[('cookie.txt', 3.0), ('huge.bin', 61.5)]"
check "one past the film's end is refused" "$(pos '{"bucket":"docs","key":"huge.bin","t":99,"d":10}')" 400
check "and one in what does not exist" "$(pos '{"bucket":"docs","key":"nope","t":1,"d":10}')" 404
check "another user keeps none in what it may not read" "$(curl -s -u "$B" -o /dev/null -w '%{http_code}' -X POST -d '{"bucket":"docs","key":"huge.bin","t":1,"d":10}' "$U/~ui/progress")" 403
check "nor sees the first user's" "$(curl -s -u "$B" "$U/~ui/progress")" "[]"
printf 'new' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/docs/cookie.txt"
check "a film replaced since is no longer listed" \
      "$(curl -s -b "skl_ui=$ck" "$U/~ui/progress" | python3 -c 'import json,sys; print([x["key"] for x in json.load(sys.stdin)])')" "['huge.bin']"
check "a position below 0 forgets one" "$(pos '{"bucket":"docs","key":"huge.bin","t":-1,"d":3600}') $(curl -s -b "skl_ui=$ck" "$U/~ui/progress")" "204 []"
s3 -o /dev/null -X DELETE "$U/docs/cookie.txt"

# Searching every library.
srch() { curl -s -u "$1" "$U/~ui/search?q=$2" | python3 -c 'import json,sys; print(sorted((x["bucket"], x["key"]) for x in json.load(sys.stdin)["results"]))'; }
check "a search finds a file by part of its name, in any case" "$(srch "$A" ONE.T)" "[('docs', 'a/one.txt')]"
check "and a folder by its own name" "$(srch "$A" sub)" "[('docs', 'a/sub/')]"
check "a search of another user finds nothing of the first's" "$(srch "$B" one)" "[]"
check "one character is not a search" "$(code -u "$A" "$U/~ui/search?q=o")" 400

# How full each library is.
use() { curl -s -u "$1" "$U/~ui/usage" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["admin"], [(l["bucket"], l["objects"], l["bytes"]) for l in d["libraries"]])'; }
want=$(s3 "$U/docs?list-type=2" | python3 -c 'import sys,re; t=sys.stdin.read(); print(len(re.findall("<Key>",t)), sum(int(x) for x in re.findall("<Size>([0-9]+)",t)))')
check "a library's usage is its objects and their bytes, summed on both shards" "$(use "$A")" "False [('docs', ${want% *}, ${want#* })]"
check "another user sees none of it" "$(use "$B")" "False []"
check "an admin sees every library" "$(use "$R" | cut -c1-14)" "True [('docs',"
setq() { curl -s -u "$1" -o /dev/null -w '%{http_code}' -X POST -d '{"bucket":"docs","max_bytes":'"$2"',"max_objects":0}' "$U/~ui/usage"; }
check "the owner sets no quota" "$(setq "$A" 1000)" 403
check "an admin does, which ?quota then says" "$(setq "$R" 123456789) $(curl -s --aws-sigv4 "aws:amz:us-east-1:s3" -u "$R" "$U/docs?quota" | grep -o '<MaxBytes>[0-9]*' | cut -d'>' -f2)" "204 123456789"
check "and the usage shows" "$(curl -s -u "$A" "$U/~ui/usage" | python3 -c 'import json,sys; print(json.load(sys.stdin)["libraries"][0]["max_bytes"])')" 123456789
check "0 takes it away" "$(setq "$R" 0) $(curl -s --aws-sigv4 "aws:amz:us-east-1:s3" -u "$R" -o /dev/null -w '%{http_code}' "$U/docs?quota")" "204 404"

# A library shared with another user, as statements of its policy.
acc() { curl -s -u "$1" -o /dev/null -w '%{http_code}' -X POST -d "{\"bucket\":\"docs\",\"user\":\"$2\",\"access\":\"$3\"}" "$U/~ui/access"; }
s3 -o /dev/null -X PUT "$U/docs?policy" -d '{"Version":"2012-10-17","Statement":[{"Sid":"mine","Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::docs/secret/*"}]}'
printf 'hid' | curl -s -u "$A" -T - -o /dev/null "$U/~dav/docs/secret/x.txt"
check "the other user does not see the library" "$(names "$B" "")" ""
check "until it is shared with them to read" "$(acc "$A" AKIADAVBEN0000000000 read)$(acc "$A" ben read) $(names "$B" "")" "404204  docs"
check "which its owner sees" "$(curl -s -u "$A" "$U/~ui/access?bucket=docs")" '{"bucket":"docs","owner":"ann","grants":[{"user":"ben","access":"read"}]}'
check "and they do not" "$(code -u "$B" "$U/~ui/access?bucket=docs")" 403
check "they read it" "$(curl -s -u "$B" "$U/~dav/docs/a/one.txt")" one
check "and do not write" "$(printf 'b' | code -u "$B" -T - "$U/~dav/docs/b.txt")" 403
check "nor share it on" "$(acc "$B" ben write)" 403
check "the policy's own statements still hold" "$(code -u "$B" "$U/~dav/docs/secret/x.txt")" 403
check "write access lets them write" "$(acc "$A" ben write) $(printf 'b' | code -u "$B" -T - "$U/~dav/docs/b.txt") $(code -u "$B" -X DELETE "$U/~dav/docs/b.txt")" "204 201 204"
check "a user that is not one is 404" "$(acc "$A" nobody read)" 404
check "nor is the owner shared its own" "$(acc "$A" ann read)" 400
check "none takes it away" "$(acc "$A" ben none) $(code -u "$B" "$U/~dav/docs/a/one.txt") $(names "$B" "")" "204 403 "
check "and leaves the rest of the policy as it was" "$(s3 "$U/docs?policy" | python3 -c 'import json,sys; print([x["Sid"] for x in json.load(sys.stdin)["Statement"]])')" "['mine']"
s3 -o /dev/null -X DELETE "$U/docs?policy"; s3 -o /dev/null -X DELETE "$U/docs/secret/x.txt"

# A client of the drive: rclone copies a tree in and out.
if [ -n "$RCLONE" ] && [ -x "$RCLONE" ]; then
    mkdir -p "$T/tree/x/y" "$T/back"
    for i in 1 2 3; do head -c $((i * 70000)) /dev/urandom > "$T/tree/x/f$i"; done
    printf 'deep' > "$T/tree/x/y/deep.txt"
    rc() { "$RCLONE" --config /dev/null --webdav-url "$U/~dav/" --webdav-vendor other --webdav-pacer-min-sleep 0.01ms --webdav-user "${A%%:*}" \
                     --webdav-pass "$("$RCLONE" obscure "${A#*:}")" "$@" 2>&1; }
    out=$(rc copy "$T/tree" :webdav:docs/tree); check "rclone copies a tree in" "$out" ""
    out=$(rc copy :webdav:docs/tree "$T/back"); check "and out" "$out" ""
    check "byte for byte" "$(diff -r "$T/tree" "$T/back" && echo same)" same
    check "rclone lists it" "$(rc lsf -R :webdav:docs/tree | sort | tr '\n' ' ')" "x/ x/f1 x/f2 x/f3 x/y/ x/y/deep.txt "
    out=$(rc purge :webdav:docs/tree); check "and removes it" "$out" ""
    check "leaving nothing" "$(s3 "$U/docs?list-type=2&prefix=tree/" | grep -c '<Key>')" 0
else
    echo "  (rclone not found: its part skipped)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
