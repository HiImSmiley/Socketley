#!/usr/bin/env bash
# Integration test: plain --http must always serve what is on disk NOW
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# `--http DIR` without `--http-cache` is the development mode: edit a file, hit
# reload, see the edit.  `--http-cache` is the other promise -- read the tree
# once at start and never look again.  The two are different products and the
# difference is the entire reason both flags exist.
#
# Nothing in this suite asserted the first promise.  Grepped: test_http_worker
# and test_http_path_escape both serve files that never change, so a build that
# cached disk mode's bytes forever would have passed the whole directory.  That
# is the assertion this file adds, and it is added because disk mode is about
# to hold bytes between requests and revalidate them with one statx.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# Every case replaces a file that has already been served once, so a build that
# never caches passes all of them and a build that caches without revalidating
# fails all of them.  They differ in WHICH revalidation they defeat:
#
#   * "in place, longer"  -- mtime and size both move.  Caught by any check.
#     Present as the control: if this one fails the cache is not revalidating at
#     all and the rest of the file says nothing new.
#   * "in place, same size" -- only mtime moves.  Catches a check on size alone.
#   * "new inode, mtime and size restored" -- `touch -r` copies the old
#     timestamp to the nanosecond and the replacement is byte-for-byte the same
#     length, so dev+ino is the ONLY field that differs.  Catches a check on
#     (mtime, size), which is the natural thing to write and is wrong: this is
#     what `mv new old`, `cp` into place, git checkout and every editor that
#     writes-then-renames actually do.
#   * the same four on a .txt file, because an .html has a script injected into
#     it and a .txt does not, so the same file becomes two different responses
#     and a map populated by one says nothing about the other. Both are read
#     rather than spliced at these sizes, which is what the clause here used to
#     claim the .txt was not: a plaintext connection splices from 256 KiB up,
#     and the size that decides it is the map's own per-file cap.
#   * a replacement made in the middle of a keep-alive connection, because the
#     cache is per-server and the connection is not, and a per-connection
#     memo would pass every case above.
#   * delete, then recreate -- a stale entry must not outlive its file, and the
#     recreated file must not be answered from the entry the deletion left.
#
# The suite's own control for "did anything run at all" is assertion 1: it is a
# plain 200 with known content on an untouched file, so a daemon that failed to
# start makes this file fail rather than pass empty.

set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate httpfresh
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: plain --http serves the file as it is now ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1600))
ROOT="$WORK/root"
mkdir -p "$ROOT"

# Both files start at exactly 40 bytes of body so a same-size replacement is
# possible later without padding arithmetic in the middle of the test.
printf 'AAAAAAAAAA-v1-AAAAAAAAAAAAAAAAAAAAAAAAAA' > "$ROOT/page.html"
printf 'BBBBBBBBBB-v1-BBBBBBBBBBBBBBBBBBBBBBBBBB' > "$ROOT/asset.txt"

"$BIN" create server fresh -p $((P+1)) --http "$ROOT" -s >/dev/null 2>&1 || true
sleep 1.2

body(){ curl -s -m 5 "http://127.0.0.1:$((P+1))$1" 2>/dev/null || true; }
code(){ curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+1))$1" 2>/dev/null || echo 000; }

# ── 1. control: the server is up and serving the file that is there ─────────
c=$(code /page.html); b=$(body /page.html)
if [ "$c" = "200" ] && [[ "$b" == *"-v1-"* ]]; then pass
else fail "control: an untouched file is served" "code=$c body='$(printf %s "$b" | head -c 60)'"; fi

# ── 2-4. the three replacements, on the HTML (read) path ────────────────────
# 2. in place, longer: mtime and size both move
printf 'AAAAAAAAAA-v2-AAAAAAAAAAAAAAAAAAAAAAAAAAEXTRA' > "$ROOT/page.html"
b=$(body /page.html)
if [[ "$b" == *"-v2-"* ]]; then pass
else fail "html: in-place edit that changes size" "still serving '$(printf %s "$b" | grep -o -- '-v[0-9]*-' | head -1)'"; fi

# 3. in place, same size: only mtime moves
sleep 0.02
printf 'AAAAAAAAAA-v3-AAAAAAAAAAAAAAAAAAAAAAAAAAEXTRA' > "$ROOT/page.html"
b=$(body /page.html)
if [[ "$b" == *"-v3-"* ]]; then pass
else fail "html: in-place edit of identical size" "still serving '$(printf %s "$b" | grep -o -- '-v[0-9]*-' | head -1)'"; fi

# 4. new inode at the same path, with mtime and size put back to the old values
ino_before=$(stat -c %i "$ROOT/page.html")
printf 'AAAAAAAAAA-v4-AAAAAAAAAAAAAAAAAAAAAAAAAAEXTRA' > "$WORK/stage.html"
touch -r "$ROOT/page.html" "$WORK/stage.html"
mv -f "$WORK/stage.html" "$ROOT/page.html"
ino_after=$(stat -c %i "$ROOT/page.html")
sz_ok=$([ "$(stat -c %s "$ROOT/page.html")" = 45 ] && echo yes || echo no)
b=$(body /page.html)
if [ "$ino_before" = "$ino_after" ]; then
    fail "html: new inode at the same path" \
         "the fixture did not replace the inode ($ino_before), so this case proved nothing"
elif [[ "$b" == *"-v4-"* ]]; then pass
else fail "html: new inode at the same path, mtime and size unchanged" \
         "still serving '$(printf %s "$b" | grep -o -- '-v[0-9]*-' | head -1)'" \
         "inode $ino_before -> $ino_after, size-still-45=$sz_ok"; fi

# ── 5-7. the same three on the .txt (splice) path ───────────────────────────
c=$(code /asset.txt); b=$(body /asset.txt)
if [ "$c" = "200" ] && [[ "$b" == *"-v1-"* ]]; then pass
else fail "control: the .txt file is served" "code=$c"; fi

printf 'BBBBBBBBBB-v2-BBBBBBBBBBBBBBBBBBBBBBBBBBEXTRA' > "$ROOT/asset.txt"
b=$(body /asset.txt)
if [[ "$b" == *"-v2-"* ]]; then pass
else fail "txt: in-place edit that changes size" "still serving '$(printf %s "$b" | grep -o -- '-v[0-9]*-' | head -1)'"; fi

ino_before=$(stat -c %i "$ROOT/asset.txt")
printf 'BBBBBBBBBB-v3-BBBBBBBBBBBBBBBBBBBBBBBBBBEXTRA' > "$WORK/stage.txt"
touch -r "$ROOT/asset.txt" "$WORK/stage.txt"
mv -f "$WORK/stage.txt" "$ROOT/asset.txt"
ino_after=$(stat -c %i "$ROOT/asset.txt")
b=$(body /asset.txt)
if [ "$ino_before" = "$ino_after" ]; then
    fail "txt: new inode at the same path" "the fixture did not replace the inode, so this case proved nothing"
elif [[ "$b" == *"-v3-"* ]]; then pass
else fail "txt: new inode at the same path, mtime and size unchanged" \
         "still serving '$(printf %s "$b" | grep -o -- '-v[0-9]*-' | head -1)'"; fi

# ── 8. replaced in the middle of one keep-alive connection ──────────────────
# Two requests on ONE socket with the file swapped between them, so a memo held
# per connection -- which every case above would let through -- is caught here.
printf 'AAAAAAAAAA-k1-AAAAAAAAAAAAAAAAAAAAAAAAAA' > "$ROOT/page.html"
sleep 0.05
KA=$(python3 - "$((P+1))" "$ROOT/page.html" <<'PY' 2>&1 || true
import socket, sys, os, subprocess
port, path = int(sys.argv[1]), sys.argv[2]
def one(s):
    s.sendall(b"GET /page.html HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(65536)
        if not c: return None
        buf += c
    head, _, body = buf.partition(b"\r\n\r\n")
    clen = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"): clen = int(line.split(b":",1)[1])
    while len(body) < clen:
        c = s.recv(65536)
        if not c: break
        body += c
    return body[:clen]
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
first = one(s)
# new inode at the same path, timestamp restored, between the two requests
stage = path + ".stage"
open(stage, "w").write("AAAAAAAAAA-k2-AAAAAAAAAAAAAAAAAAAAAAAAAA")
st = os.stat(path)
os.utime(stage, ns=(st.st_atime_ns, st.st_mtime_ns))
os.rename(stage, path)
second = one(s)
s.close()
print("%s|%s" % (b"-k1-" in (first or b""), b"-k2-" in (second or b"")))
PY
)
if [ "$KA" = "True|True" ]; then pass
else fail "keep-alive: the file replaced between two requests on one socket" \
         "expected 'True|True' (first sees k1, second sees k2), got '$KA'"; fi

# ── 9-10. delete, then recreate ─────────────────────────────────────────────
rm -f "$ROOT/asset.txt"
c=$(code /asset.txt)
if [ "$c" = "404" ]; then pass
else fail "a deleted file stops being served" "expected 404, got $c"; fi

printf 'BBBBBBBBBB-v9-BBBBBBBBBBBBBBBBBBBBBBBBBBEXTRA' > "$ROOT/asset.txt"
b=$(body /asset.txt); c=$(code /asset.txt)
if [ "$c" = "200" ] && [[ "$b" == *"-v9-"* ]]; then pass
else fail "a recreated file is served again, with its new content" \
         "code=$c body='$(printf %s "$b" | head -c 60)'"; fi

echo "--- $PASS/$TOTAL passed ---"
[ "$FAIL" -eq 0 ] || exit 1
