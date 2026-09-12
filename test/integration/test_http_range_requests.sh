#!/usr/bin/env bash
# Integration test: a client can ask for part of a file and gets that part.
#
# ─── WHAT WAS NOT THERE ─────────────────────────────────────────────────────
#
# Nothing. `grep -rln "Accept-Ranges\|Content-Range" socketley/` found no hit in
# the whole tree, so every request for a file was answered whole. Which makes
# three things impossible rather than slow:
#
#   - seeking in a video or audio file, because a player scrubs by asking for
#     the byte range it wants to play next
#   - resuming an interrupted download
#   - <video> in Safari at all, which requires a 206 to the range it probes with
#
# ─── THE TWO WAYS TO GET THIS WRONG THAT THIS FILE GUARDS ───────────────────
#
# The revalidation map is keyed by url_path and holds the WHOLE file's response.
# A 206 stored under that key answers the next request for the path with this
# request's slice AND this request's Content-Range -- a cache poisoning with one
# reader's seek as the payload. serve_http declines the cache when a Range field
# is present and handle_file_read refuses to store a slice; cases 8 and 9 are
# both halves of that, in the order that would catch it.
#
# And `is_range` lives on the connection, which under keep-alive serves the next
# request without a reset(). A path that does not reach the two file arms -- a
# 404, a cache hit -- would leave the last response's answer standing, so it is
# cleared per request rather than per connection. Case 10 is two requests on one
# socket, which is the only shape that sees it.
#
# ─── WHAT IS DELIBERATELY NOT SUPPORTED ─────────────────────────────────────
#
# A multi-range request (bytes=0-9,20-29) needs a multipart/byteranges body.
# RFC 9110 14.2 permits a server to ignore the field, and answering the whole
# file is both legal and more useful than a wrong slice -- case 6.
#
# And HTML is excluded: --http injects a script into it, so a byte offset into
# the file is not an offset into what is served. Answering a slice of the file
# would hand out bytes from the wrong place in the response -- case 7.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate httprange

P=$((SL_PORT_BASE+1958))
NAMES="rg_srv"
WWW="$SOCKETLEY_TMPD/www"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

mkdir -p "$WWW"
# Deterministic content, so a slice can be checked byte for byte rather than
# only by its length: a build that answered the right COUNT of bytes from the
# wrong OFFSET would pass every length assertion.
python3 - "$WWW" <<'PYEOF'
import sys, os
w = sys.argv[1]
small = bytes((i * 7 + 11) % 251 for i in range(1000))
open(os.path.join(w, "small.bin"), "wb").write(small)
big = bytes((i * 13 + 5) % 251 for i in range(4 << 20))
open(os.path.join(w, "big.bin"), "wb").write(big)
open(os.path.join(w, "page.html"), "w").write("<html><body>hello</body></html>")
PYEOF

echo "=== Integration: part of a file, asked for and answered ==="
daemon_start "$BIN"

create_ok "a static file server" "$BIN" create server rg_srv -p "$P" --http "$WWW" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

OUT=$(timeout 120 python3 - "$P" "$WWW" <<'PYEOF' 2>&1
import hashlib, os, socket, sys
port, www = int(sys.argv[1]), sys.argv[2]
small = open(os.path.join(www, "small.bin"), "rb").read()
big   = open(os.path.join(www, "big.bin"), "rb").read()

def req(s, name, rng, keep):
    h = "GET /%s HTTP/1.1\r\nHost: x\r\n" % name
    if rng: h += "Range: %s\r\n" % rng
    h += ("Connection: keep-alive\r\n\r\n" if keep else "Connection: close\r\n\r\n")
    s.sendall(h.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(65536)
        if not c: raise RuntimeError("closed in headers")
        buf += c
    head, rest = buf.split(b"\r\n\r\n", 1)
    head = head.decode(errors="replace")
    cl = 0
    for line in head.split("\r\n"):
        if line.lower().startswith("content-length:"):
            cl = int(line.split(":", 1)[1])
    body = rest
    while len(body) < cl:
        c = s.recv(262144)
        if not c: break
        body += c
    return head, body

def one(name, rng=None):
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(15)
    h, b = req(s, name, rng, False)
    s.close()
    return h, b

def field(head, key):
    for line in head.split("\r\n"):
        if line.lower().startswith(key + ":"):
            return line.split(":", 1)[1].strip()
    return ""

def emit(tag, head, body, want=None):
    print("%s_STATUS=%s" % (tag, head.split("\r\n")[0].split(" ", 1)[1]))
    print("%s_CR=%s" % (tag, field(head, "content-range")))
    print("%s_CL=%s" % (tag, field(head, "content-length")))
    print("%s_AR=%s" % (tag, field(head, "accept-ranges")))
    print("%s_LEN=%d" % (tag, len(body)))
    if want is not None:
        print("%s_BYTES=%s" % (tag, "exact" if body == want else "WRONG"))

emit("WHOLE",  *one("small.bin"),                       want=small)
emit("HEAD100", *one("small.bin", "bytes=0-99"),        want=small[0:100])
emit("TAIL",   *one("small.bin", "bytes=900-"),         want=small[900:1000])
emit("SUFFIX", *one("small.bin", "bytes=-100"),         want=small[900:1000])
emit("ONEB",   *one("small.bin", "bytes=0-0"),          want=small[0:1])
emit("CLAMP",  *one("small.bin", "bytes=900-99999"),    want=small[900:1000])
h, b = one("small.bin", "bytes=5000-");  emit("UNSAT", h, b)
emit("MULTI",  *one("small.bin", "bytes=0-9,20-29"),    want=small)
emit("HTML",   *one("page.html", "bytes=0-3"))

# The splice arm: a 4 MiB file is past every cap that would route it through
# the read path, and a slice from the middle is what exercises the lseek.
emit("BIGMID", *one("big.bin", "bytes=1048576-2097151"),
     want=big[1048576:2097152])

# ─── the cache, in the order that catches it ────────────────────────────────
# A slice first, then the whole file. If the 206 was stored under the path, the
# second answer is this slice under a 200.
h, b = one("small.bin", "bytes=10-19")
print("POISON_FIRST=%s" % ("exact" if b == small[10:20] else "WRONG"))
h, b = one("small.bin")
print("POISON_AFTER_STATUS=%s" % h.split("\r\n")[0].split(" ", 1)[1])
print("POISON_AFTER=%s" % ("exact" if b == small else "WRONG"))
print("POISON_AFTER_CR=%s" % field(h, "content-range"))

# And the other order, because the cache is populated by the whole-file request
# and the slice must not come out of it.
h, b = one("small.bin")
h, b = one("small.bin", "bytes=10-19")
print("AFTERCACHE_STATUS=%s" % h.split("\r\n")[0].split(" ", 1)[1])
print("AFTERCACHE=%s" % ("exact" if b == small[10:20] else "WRONG"))

# ─── one socket, two requests ───────────────────────────────────────────────
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(15)
h1, b1 = req(s, "small.bin", "bytes=0-99", True)
h2, b2 = req(s, "small.bin", None, True)
s.close()
print("KA_FIRST_STATUS=%s" % h1.split("\r\n")[0].split(" ", 1)[1])
print("KA_FIRST=%s" % ("exact" if b1 == small[0:100] else "WRONG"))
print("KA_SECOND_STATUS=%s" % h2.split("\r\n")[0].split(" ", 1)[1])
print("KA_SECOND=%s" % ("exact" if b2 == small else "WRONG"))
print("KA_SECOND_CR=%s" % field(h2, "content-range"))
PYEOF
)

v() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | tail -1; }

# ─── 1. The whole file, and the field that says a slice may be asked for ────
check "a whole file is still a 200"            "200 OK" "$(v WHOLE_STATUS)"
check "with the whole body"                    "exact"  "$(v WHOLE_BYTES)"
# The omission that made the 206 path unreachable from a conforming client: a
# small file takes the read arm, and only the splice arm's builder had the
# field, so the answer a player asks for FIRST did not advertise ranges.
check "and it advertises ranges"               "bytes"  "$(v WHOLE_AR)"

# ─── 2. A slice is a 206 with both lengths ──────────────────────────────────
check "a range is a 206"                       "206 Partial Content" "$(v HEAD100_STATUS)"
check "Content-Range states the whole length"  "bytes 0-99/1000"     "$(v HEAD100_CR)"
# The classic way to write this wrong: Content-Length gets the file's size and
# the client waits forever for bytes the server already finished sending.
check "Content-Length states the slice"        "100"                 "$(v HEAD100_CL)"
check "and the bytes are the ones asked for"   "exact"               "$(v HEAD100_BYTES)"

# ─── 3. The three forms a range comes in ────────────────────────────────────
check "an open-ended range reaches the end"    "bytes 900-999/1000" "$(v TAIL_CR)"
check "and carries those bytes"                "exact"              "$(v TAIL_BYTES)"
check "a suffix range counts from the end"     "bytes 900-999/1000" "$(v SUFFIX_CR)"
check "and carries those bytes"                "exact"              "$(v SUFFIX_BYTES)"
check "a single byte is a range"               "bytes 0-0/1000"     "$(v ONEB_CR)"
check "and is one byte"                        "exact"              "$(v ONEB_BYTES)"
check "an end past the file is clamped"        "bytes 900-999/1000" "$(v CLAMP_CR)"

# ─── 4. A seek past the end is 416, which is how a player learns the length ─
check "a range wholly past the end is 416"     "416 Range Not Satisfiable" "$(v UNSAT_STATUS)"
check "and states the length it could not satisfy" "bytes */1000"  "$(v UNSAT_CR)"
check "with no body"                           "0"                 "$(v UNSAT_LEN)"

# ─── 5. The splice arm, and its offset ──────────────────────────────────────
# splice() from a file has no offset argument, so the descriptor is seeked
# first. A build that forgot would answer these headers with the file's first
# megabyte -- the right COUNT of bytes from the wrong place.
check "a slice of a 4 MiB file is a 206"  "206 Partial Content" "$(v BIGMID_STATUS)"
check "from the middle, stated"    "bytes 1048576-2097151/4194304" "$(v BIGMID_CR)"
check "and those are the bytes"           "exact"               "$(v BIGMID_BYTES)"

# ─── 6. What is deliberately answered whole ─────────────────────────────────
check "a multi-range request is answered whole" "200 OK" "$(v MULTI_STATUS)"
check "with the whole file"                     "exact"  "$(v MULTI_BYTES)"

# ─── 7. HTML is excluded, because the body is not the file ──────────────────
check "a range on injected HTML is ignored" "200 OK" "$(v HTML_STATUS)"
if [ -z "$(v HTML_AR)" ]; then ok; else
    bad "and HTML does not claim ranges" \
        "it sent Accept-Ranges: $(v HTML_AR), inviting a seek into a body that" \
        "is not the file"; fi

# ─── 8. A slice does not become the cached answer for the path ──────────────
check "the slice itself is right"            "exact"  "$(v POISON_FIRST)"
check "the whole file after it is still 200" "200 OK" "$(v POISON_AFTER_STATUS)"
check "and still the whole file"             "exact"  "$(v POISON_AFTER)"
if [ -z "$(v POISON_AFTER_CR)" ]; then ok; else
    bad "and carries no Content-Range" \
        "it answered 'Content-Range: $(v POISON_AFTER_CR)' for a whole-file request," \
        "which is a stored 206 being replayed"; fi

# ─── 9. And a cached whole file does not answer a slice ─────────────────────
check "a range after the file was cached is a 206" "206 Partial Content" "$(v AFTERCACHE_STATUS)"
check "and is the slice, not the cached file"      "exact"               "$(v AFTERCACHE)"

# ─── 10. Two requests on one socket ─────────────────────────────────────────
check "a range on a keep-alive socket"          "206 Partial Content" "$(v KA_FIRST_STATUS)"
check "is the slice"                            "exact"               "$(v KA_FIRST)"
check "and the next request on it is whole"     "200 OK"              "$(v KA_SECOND_STATUS)"
check "with the whole body"                     "exact"               "$(v KA_SECOND)"
if [ -z "$(v KA_SECOND_CR)" ]; then ok; else
    bad "and no Content-Range left over" \
        "'Content-Range: $(v KA_SECOND_CR)' on a whole-file request means is_range" \
        "survived the response before it"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else
    printf '%s\n' "$OUT" | sed 's/^/    driver: /'
    echo "  FAILED"
fi
[ "$FAIL" -eq 0 ]
