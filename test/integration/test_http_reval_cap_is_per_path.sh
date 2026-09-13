#!/usr/bin/env bash
# Integration test: which files --http keeps in memory depends on the connection
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# handle_file_read() will not splice a file it may keep, because keeping it
# needs the bytes in user space.  So the per-file cap on the revalidation map is
# also the size at which a plaintext download stops being copied and starts
# being spliced, and the two are one decision.  Measured at 64 concurrent, a
# 1 MiB file is 5,931 responses a second kept against 14,049 spliced, which is
# why the cap for a connection that CAN splice is 256 KiB and not 1 MiB.
#
# A TLS connection cannot splice at all -- that would hand the peer plaintext in
# the middle of an encrypted stream -- and an injected .html is read for the same
# reason it is injected.  For those two the cap stays at 1 MiB, because there the
# map is the only thing standing between a large file and one allocation of its
# whole size per request.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# The map has no metric, so there are two observables and this file uses both.
#
# The first is what the map IS: memory the worker still holds once the requests
# are over.  Filling it is 64 MiB of retained resident size and splicing holds
# none of the file at all, so the signal is two orders of magnitude above what a
# sanitizer build's allocator adds.
#
# The second is the line the map logs when it stops taking files.  The first
# draft of this file used only that line, and its two positive controls failed:
# the refusal happens at an estimate checked before the responses are built, and
# the line sat behind the exact test after them, so it never fired.  It is
# reported at both doors now, and the count of it is asserted here -- once per
# runtime that fills, never for one that keeps nothing.
#
#   * 300 KiB over plaintext must NOT fill the map.  This is the assertion that
#     fails on the build before this one, where the cap was 1 MiB for everybody.
#   * 200 KiB over plaintext MUST fill it, so a cap set to zero -- or a map
#     switched off -- is not mistaken for the line above.
#   * 300 KiB over TLS MUST fill it.  This is the one that catches the predicate
#     being written the wrong way round, which would put a TLS listener on one
#     allocation the size of the file per request, unbounded by concurrency.
#   * the line itself, so the report that exists for an operator is known to
#     reach them: nothing from the arm that keeps nothing, one from each arm
#     that fills.
#   * the bytes, before any of the above means anything, on both listeners and
#     across a replacement -- a file that is now spliced at this size must still
#     be served whole and must still be the file that is on disk now.
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate revalcap
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: the revalidation cap depends on whether the connection can splice ==="

if ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: openssl CLI not available (needed for the TLS arm)"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

P=$((SL_PORT_BASE + 1640))
BIG="$WORK/big"; SMALL="$WORK/small"
mkdir -p "$BIG" "$SMALL"

# Sized from what an entry actually costs: both finished responses, so about
# twice the file.  130 files of 300 KiB is ~78 MiB of entries and 200 of
# 200 KiB is ~82 MiB, each comfortably past the 64 MiB total.
BIG_N=130;   BIG_KB=300
SMALL_N=200; SMALL_KB=200
for i in $(seq 1 $BIG_N);   do head -c $((BIG_KB*1024))   /dev/zero | tr '\0' 'b' > "$BIG/b$i.bin"; done
for i in $(seq 1 $SMALL_N); do head -c $((SMALL_KB*1024)) /dev/zero | tr '\0' 's' > "$SMALL/s$i.bin"; done

CERTS="$WORK/certs"; mkdir -p "$CERTS"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
if [ ! -s "$CERTS/cert.pem" ] || [ ! -s "$CERTS/key.pem" ]; then
    echo "  SKIP: openssl produced no usable key pair"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

daemon_start "$BIN"
"$BIN" create server rcbig   -p $((P+1)) --http "$BIG"   -s >/dev/null 2>&1 || true
"$BIN" create server rcsmall -p $((P+2)) --http "$SMALL" -s >/dev/null 2>&1 || true
"$BIN" create server rctls   -p $((P+3)) --http "$BIG" \
       --tls --cert "$CERTS/cert.pem" --key "$CERTS/key.pem" -s >/dev/null 2>&1 || true
for i in $(seq 1 100); do
    ready=1
    for p in $((P+1)) $((P+2)) $((P+3)); do
        ss -ltn 2>/dev/null | grep -q ":$p " || ready=0
    done
    [ "$ready" = 1 ] && break
    sleep 0.1
done
if [ "${ready:-0}" != 1 ]; then
    echo "  FATAL: not all three listeners came up; nothing below measures this build"
    echo "  Results: 0/0 passed (0 failed)"
    exit 2
fi

# The worker holding a port, not the daemon: the daemon holds a placeholder and
# keeps none of this.  Found by port rather than by name, since a suite run has
# several workers.
full_lines(){ grep -c 'content cache reached its 64 MiB limit' "$SOCKETLEY_DLOG" 2>/dev/null || true; }
worker_on(){ ss -ltnp 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1; }
rss_mb(){ awk '/^VmRSS/{printf "%.1f", $2/1024}' "/proc/$1/status" 2>/dev/null || echo 0; }
grew(){ awk -v a="$1" -v b="$2" 'BEGIN{printf "%.1f", b-a}'; }
over(){ awk -v x="$1" -v t="$2" 'BEGIN{exit !(x+0 > t+0)}'; }
# One curl for a whole arm, so the connection is reused and the map fills from
# requests rather than from connection setup.
walk(){   # $1=url prefix  $2=file prefix  $3=count  $4=extra curl args
    local pre=$1 fp=$2 n=$3; shift 3
    local args=()
    local i
    for i in $(seq 1 "$n"); do args+=(-o /dev/null "$pre/$fp$i.bin"); done
    curl -s -m 120 "$@" "${args[@]}" >/dev/null 2>&1 || true
}

# ── 0. the bytes, first: nothing below means anything if these are wrong ─────
curl -sk -m 20 "http://127.0.0.1:$((P+1))/b1.bin" -o "$WORK/got_plain" 2>/dev/null || true
curl -sk -m 20 "https://127.0.0.1:$((P+3))/b1.bin" -o "$WORK/got_tls" 2>/dev/null || true
if cmp -s "$BIG/b1.bin" "$WORK/got_plain" && cmp -s "$BIG/b1.bin" "$WORK/got_tls"; then pass
else fail "a ${BIG_KB} KiB file is served whole on both listeners" \
          "plain $(wc -c < "$WORK/got_plain" 2>/dev/null || echo 0) bytes, TLS $(wc -c < "$WORK/got_tls" 2>/dev/null || echo 0), file $((BIG_KB*1024))"; fi

# ── 1. and it is still the file that is on disk NOW, on the spliced path ────
printf 'REPLACED' >> "$BIG/b1.bin"
curl -s -m 20 "http://127.0.0.1:$((P+1))/b1.bin" -o "$WORK/got2" 2>/dev/null || true
if cmp -s "$BIG/b1.bin" "$WORK/got2"; then pass
else fail "a replaced file is served as it is now" \
          "got $(wc -c < "$WORK/got2" 2>/dev/null || echo 0) bytes against $(wc -c < "$BIG/b1.bin") on disk"; fi

W_BIG=$(worker_on $((P+1))); W_SMALL=$(worker_on $((P+2))); W_TLS=$(worker_on $((P+3)))
if [ -z "${W_BIG:-}" ] || [ -z "${W_SMALL:-}" ] || [ -z "${W_TLS:-}" ]; then
    echo "  FATAL: ss reported no pid for one of the three listeners, so there is"
    echo "         nothing to sample and nothing below would measure this build"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 2
fi

# ── 2. 300 KiB over plaintext must keep nothing ─────────────────────────────
L0=$(full_lines)
A=$(rss_mb "$W_BIG")
walk "http://127.0.0.1:$((P+1))" b "$BIG_N"
sleep 0.5
G_BIG=$(grew "$A" "$(rss_mb "$W_BIG")")
if ! over "$G_BIG" 16; then pass
else fail "${BIG_KB} KiB over plaintext is spliced, not kept" \
          "the worker retained ${G_BIG} MB after $BIG_N files of $BIG_KB KiB, and the map's" \
          "own limit is 64 MB -- so these were copied into memory and kept, on a" \
          "connection that could have spliced them from the page cache instead"; fi

L1=$(full_lines)
# ── 3. 200 KiB over plaintext must still be kept ───────────────────────────
A=$(rss_mb "$W_SMALL")
walk "http://127.0.0.1:$((P+2))" s "$SMALL_N"
sleep 0.5
G_SMALL=$(grew "$A" "$(rss_mb "$W_SMALL")")
if over "$G_SMALL" 32; then pass
else fail "${SMALL_KB} KiB over plaintext is still kept" \
          "$SMALL_N files of $SMALL_KB KiB retained only ${G_SMALL} MB, against a 64 MB map" \
          "that this many entries fills twice over -- so either the cap is below" \
          "$SMALL_KB KiB or nothing is kept at all, and then the assertion above" \
          "proves nothing"; fi

L2=$(full_lines)
# ── 4. 300 KiB over TLS must be kept: TLS has no splice arm ────────────────
A=$(rss_mb "$W_TLS")
walk "https://127.0.0.1:$((P+3))" b "$BIG_N" -k
sleep 0.5
G_TLS=$(grew "$A" "$(rss_mb "$W_TLS")")
if over "$G_TLS" 32; then pass
else fail "${BIG_KB} KiB over TLS is kept" \
          "the TLS worker retained only ${G_TLS} MB over $BIG_N files of $BIG_KB KiB." \
          "TLS cannot splice, so a listener that keeps none of them answers every" \
          "request with one allocation the size of the file, bounded by nothing" \
          "but how many the client asks for at once"; fi
L3=$(full_lines)

# ── 5. and the operator is told, once per runtime that fills ───────────────
if [ "$L1" = "$L0" ] && [ "$L2" -gt "$L1" ] && [ "$L3" -gt "$L2" ]; then pass
else fail "a map that stops taking files says so once" \
          "the line count went $L0 -> $L1 -> $L2 -> $L3 across the three arms," \
          "and it has to stay put for the arm that keeps nothing and rise by one" \
          "for each arm that fills -- a full cache that reports nothing is the" \
          "operator finding out from a latency graph instead"; fi

echo "  retained: plaintext ${BIG_KB}K ${G_BIG} MB, plaintext ${SMALL_KB}K ${G_SMALL} MB, TLS ${BIG_KB}K ${G_TLS} MB"
echo "  cache-full lines: $L0 -> $L1 -> $L2 -> $L3" 

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
