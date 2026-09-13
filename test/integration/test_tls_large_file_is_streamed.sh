#!/usr/bin/env bash
# Integration test: a large file over TLS is not held in memory
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A plaintext .bin goes out by splice and the worker never holds it.  A TLS
# connection has no splice arm -- splicing a file into an encrypted stream would
# hand the peer plaintext -- so it took the read path, and the read path
# allocated whatever was asked for and then built the response around it.
# Measured before this: one request for a 256 MB file took the worker from 2 MB
# to 505, and three at once to 1,250, with the client deciding how many there
# are.  test_http_large_html_memory.sh names that shape for .html and says the
# repair is "the body streamed the way splice streams it"; this is that repair
# for everything which is not .html.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the bytes, first: a memory figure for a response that did not arrive whole
#     measures nothing, and the two failure modes of a piecewise sender are a
#     short body and pieces in the wrong order -- a byte comparison catches both
#   * the memory does not follow the FILE's size: eight times the file adds about
#     the same, where a build that allocates the body adds about eight times as
#     much.  A ratio between two measurements in one build and not an absolute
#     threshold, because a sanitizer build's allocator keeps what it frees --
#     measured, the first draft of this file asserted "under a quarter of the
#     file" and failed at 2.95x under ASan while passing at 0.09x in Release
#   * three at once do not multiply it.  This one is a property and not a
#     regression check, and the difference is worth stating: the build before this
#     satisfies it too, because RSS is a high-water mark and one request already
#     set it there.  The assertion that fails on that build is the one above.
#   * two requests on one connection, because the piecewise sender has to do its
#     own keep-alive bookkeeping at the end of a response
#   * a Range request, because the 206 branch takes the same path and a slice sent
#     from the wrong offset is the bug that branch is written against
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate tlsstream
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a large file over TLS is streamed, not held ==="

if ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: openssl CLI not available (needed for a TLS listener)"
    echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

SIZE=$((32 * 1024 * 1024))
SMALL=$((4 * 1024 * 1024))      # an eighth, served by a runtime of its own
WWW="$WORK/www"; mkdir -p "$WWW"
head -c "$SIZE" /dev/urandom > "$WWW/big.bin"
head -c "$SMALL" /dev/urandom > "$WWW/small.bin"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
if [ ! -s "$WORK/cert.pem" ] || [ ! -s "$WORK/key.pem" ]; then
    echo "  SKIP: openssl produced no usable key pair"
    echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1680))
# Two runtimes, one per size, so neither measurement carries what the other left
# in the allocator.
for n in 1 2; do
    "$BIN" create server "tstream$n" -p $((P+n)) --http "$WWW" \
           --tls --cert "$WORK/cert.pem" --key "$WORK/key.pem" -s >/dev/null 2>&1 || true
done
for i in $(seq 1 150); do
    ready=1
    for n in 1 2; do ss -ltn 2>/dev/null | grep -q ":$((P+n)) " || ready=0; done
    [ "$ready" = 1 ] && break
    sleep 0.1
done
if [ "${ready:-0}" != 1 ]; then
    echo "  FATAL: a TLS listener never came up, so nothing below measures this build"
    echo "  Results: 0/0 passed (0 failed)"; exit 2
fi
# The worker holding the port, not the daemon: the daemon holds a placeholder and
# keeps none of this.
worker_on(){ ss -ltnp 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1; }
WORKER=$(worker_on $((P+1)))
WORKER2=$(worker_on $((P+2)))
if [ -z "${WORKER:-}" ] || [ -z "${WORKER2:-}" ]; then
    echo "  FATAL: ss reported no pid for a listener, so there is nothing to sample"
    echo "  Results: 0/0 passed (0 failed)"; exit 2
fi
SAMPLE_PID=$WORKER
rss(){ awk '/^VmRSS/{print $2}' "/proc/$SAMPLE_PID/status" 2>/dev/null || echo 0; }

# The two memory assertions are Release-only, and that is a property of the
# measurement rather than a convenience.  This path replaces one allocation the
# size of the file with one per 256 KiB piece, and a sanitizer build quarantines
# every block it frees -- so the same change that takes 129 MB down to 3 in
# Release reads as 164 MB under ASan, and three concurrent requests read as
# LESS than one because the first request's blocks are already retained.
# Measured, both runs: 0.59x and 0.58x.  Redzones and a quarantine are not the
# subject, so they are not asserted on; what is asserted in both builds is that
# the bytes are right, keep-alive survives and a Range is sliced correctly.
# grep with a redirect and not -q: under `set -o pipefail` a -q that matches
# early reports 141, which this tree has read as "not sanitized" four times.
SANITIZED=0
if nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then SANITIZED=1; fi

# What a request ADDS, sampled: a sanitizer build's own baseline is not the
# question and the delta is the same question in both builds.
peak_added_during(){
    local base peak r
    base=$(rss)
    ( while :; do r=$(rss); [ -n "$r" ] && echo "$r"; sleep 0.02; done ) > "$WORK/samples" &
    local sampler=$!
    "$@" >/dev/null 2>&1 || true
    kill "$sampler" 2>/dev/null; wait "$sampler" 2>/dev/null
    peak=$(sort -n "$WORK/samples" | tail -1)
    awk -v p="${peak:-0}" -v b="${base:-0}" 'BEGIN{d=p-b; print (d>0?d:0)}'
}
under(){ awk -v x="$1" -v t="$2" 'BEGIN{exit !(x+0 < t+0)}'; }

# ── 1. the bytes, before any memory figure means anything ───────────────────
ONE=$(peak_added_during curl -sk --max-time 120 "https://127.0.0.1:$((P+1))/big.bin" -o "$WORK/got1")
if cmp -s "$WWW/big.bin" "$WORK/got1"; then pass
else fail "the file arrives whole and in order over TLS" \
          "got $(wc -c < "$WORK/got1" 2>/dev/null || echo 0) bytes of $SIZE, and they differ from the file" \
          "-- a piecewise sender fails as a short body or as pieces out of order"; fi

# ── 2. and the memory does not follow the file's size ───────────────────────
if [ "$SANITIZED" = 1 ]; then
    echo "  (memory not asserted: a sanitizer build's quarantine keeps every freed"
    echo "   piece, and this path trades one big allocation for many small ones)"
else
SAMPLE_PID=$WORKER2
SMALL_ADDED=$(peak_added_during curl -sk --max-time 120 "https://127.0.0.1:$((P+2))/small.bin" -o "$WORK/gots")
SAMPLE_PID=$WORKER
# A difference and not a ratio: the smaller file can add nothing measurable at all
# -- it did, 0 kB -- and a ratio against zero says nothing.  What the claim
# actually is: the extra 28 MiB of file must not cost 28 MiB of memory.
EXTRA=$(awk -v a="${SMALL_ADDED:-0}" -v b="${ONE:-0}" 'BEGIN{d=b-a; print (d>0?d:0)}')
ALLOW=$(awk -v s="$SIZE" -v m="$SMALL" 'BEGIN{printf "%d", (s-m)/1024*0.25}')
if cmp -s "$WWW/small.bin" "$WORK/gots" && [ "$EXTRA" -lt "$ALLOW" ]; then
    echo "  eight times the file cost ${EXTRA} kB more (a quarter of the extra file is ${ALLOW} kB)"
    pass
else fail "eight times the file does not cost eight times the memory" \
          "4 MiB added ${SMALL_ADDED} kB, 32 MiB added $ONE kB: $EXTRA kB more for 28 MiB more file," \
          "against an allowance of $ALLOW kB -- a build that allocates the body spends" \
          "the whole difference and about as much again for the response built around it." \
          "Stated as a difference inside one build because a sanitizer build's allocator" \
          "keeps what it frees, and no absolute figure survives that"; fi
fi

# ── 3. three at once do not multiply it ─────────────────────────────────────
# The three pids by name, because a bare `wait` in here waits for the RSS sampler
# the caller started as well, and that loop never ends -- which read as the server
# hanging on three concurrent requests when three concurrent requests were already
# finishing in under two seconds.
three(){
    local a b c
    curl -sk --max-time 120 "https://127.0.0.1:$((P+1))/big.bin" -o "$WORK/g1" & a=$!
    curl -sk --max-time 120 "https://127.0.0.1:$((P+1))/big.bin" -o "$WORK/g2" & b=$!
    curl -sk --max-time 120 "https://127.0.0.1:$((P+1))/big.bin" -o "$WORK/g3" & c=$!
    wait "$a" "$b" "$c"
}
if [ "$SANITIZED" = 1 ]; then
    : # counted above: the quarantine makes three read as less than one
else
THREE=$(peak_added_during three)
MULT=$(awk -v a="${ONE:-0}" -v b="${THREE:-0}" 'BEGIN{printf "%.2f", (a>0? b/a : 99)}')
if under "$MULT" 2 && cmp -s "$WWW/big.bin" "$WORK/g3"; then
    echo "  three at once added ${MULT}x what one added (${THREE} kB)"
    pass
else fail "three at once do not multiply the memory" \
          "one added $ONE kB and three added $THREE kB, a factor of $MULT, and the third answer $(cmp -s "$WWW/big.bin" "$WORK/g3" && echo matched || echo did not match)" \
          "-- the defect this replaces multiplied by concurrency, which is what" \
          "made it unbounded: the client decides how many requests there are"; fi
fi

# ── 4. keep-alive: two on one connection ────────────────────────────────────
curl -sk --max-time 120 -o "$WORK/k1" -o "$WORK/k2" \
     "https://127.0.0.1:$((P+1))/big.bin" "https://127.0.0.1:$((P+1))/big.bin" >/dev/null 2>&1 || true
if cmp -s "$WWW/big.bin" "$WORK/k1" && cmp -s "$WWW/big.bin" "$WORK/k2"; then pass
else fail "two requests on one connection both arrive whole" \
          "first $(wc -c < "$WORK/k1" 2>/dev/null || echo 0), second $(wc -c < "$WORK/k2" 2>/dev/null || echo 0), of $SIZE each" \
          "-- the piecewise sender does its own end-of-response bookkeeping, and a" \
          "connection left mid-stream answers the next request with the rest of this one"; fi

# ── 5. a Range over TLS takes the same path and must slice correctly ────────
dd if="$WWW/big.bin" bs=1 skip=1048576 count=65536 of="$WORK/want" >/dev/null 2>&1
CODE=$(curl -sk --max-time 60 -o "$WORK/slice" -w '%{http_code}' \
        -H 'Range: bytes=1048576-1114111' "https://127.0.0.1:$((P+1))/big.bin" 2>/dev/null || echo 000)
if [ "$CODE" = "206" ] && cmp -s "$WORK/want" "$WORK/slice"; then pass
else fail "a Range request is answered with that slice" \
          "code $CODE, $(wc -c < "$WORK/slice" 2>/dev/null || echo 0) bytes, expected 206 and 65536" \
          "-- the slice's start becomes the read's offset, and a sender that ignored" \
          "it would answer 206 with the beginning of the file"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
