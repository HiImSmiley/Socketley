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
EOF
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
