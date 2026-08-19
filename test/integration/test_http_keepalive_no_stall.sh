#!/usr/bin/env bash
# Integration test: --http keep-alive traffic must be answered, every request
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# In `--http DIR` disk mode a keep-alive client could send a request and get
# nothing back at all -- no response, no FIN, no RST -- while the connection
# stayed open.  Measured on 78c9ecc, default configuration, 2 KiB .txt, 400
# connections of 20 requests, twice: 7930 and 7976 of 8000 answered, 5 and 2
# connections dead.  On 25552d9 the same traffic is 8000 of 8000, twice, and
# runs in 0.20 s instead of 4.1 s.
#
# ─── THE MECHANISM, BECAUSE THE ASSERTION IS ONLY MEANINGFUL WITH IT ────────
#
# handle_read() declines to parse conn->partial while the connection is still
# finishing its last response:
#
#     if (conn->file_read_pending || conn->splice_pending ||
#         conn->splice_in_pending || conn->splice_out_pending)
#         goto submit_next_read;     // "parsed when the next read completes"
#
# Nothing re-parses it.  A multishot recv is already armed, so it has ALREADY
# moved the next request out of the socket and into conn->partial; the splice
# completion then arms a read and waits for bytes the client has already sent,
# while the client waits for a response that will never be produced.  Proven by
# instrumenting both points: 24 deferrals, 24 dead connections, 24 splice
# completions with a whole request still sitting in partial, and 1821 clean
# completions with partial empty -- three counters, all equal.
#
# splice is what makes the window reachable, and it is not itself the bug.  Of
# the four flags above, splice_out_pending is the only one a conforming client
# can reach: the pipe->socket completion lands AFTER the client already holds
# the whole response, so its next request arrives into the gap.  On the read
# path the client cannot have the response before the read completes, so it
# cannot send anything.  Measured, same 2 MiB of body on the wire, same client,
# same box: .txt via splice 31, 34 and 46 dead connections of 200; .html via
# the read path 0 of 200.
#
# 25552d9 closed it for the file sizes this test uses by keeping the bytes and
# revalidating them, which routes small non-HTML files to the read path instead
# of splicing them.  That is why this test passes now, and it is the thing it
# pins: a change that sends small non-HTML files back to the splice path makes
# it fail again.
#
# ─── WHAT IS STILL OPEN, AND DELIBERATELY NOT ASSERTED HERE ─────────────────
#
# Files ABOVE server_instance.h's HTTP_REVAL_MAX_FILE (1 MiB) still take the
# splice path on the default configuration, and still stall: 31, 34 and 46 of
# 200 connections on a 2 MiB .txt, on a clean Release binary with no
# environment overrides.  That is a live defect, not a historical one, and it
# is not asserted here because it is not fixed -- see
# repro_http_splice_keepalive_stall.sh next to this file, which reproduces it
# and is not part of the suite for exactly that reason.
#
# The same is true above HTTP_REVAL_MAX_TOTAL (64 MiB): once the map is full
# reval_take goes false for every file and non-HTML returns to splice.  Not
# asserted, not measured -- read from the code only.
#
# HTTP pipelining is a third, larger defect in the same family and is also not
# asserted: two requests in one write are answered once on EVERY serving path,
# --http-cache included, and the rest are parked in conn->partial forever.
# Measured 1 of 4 answered on all six path/mode combinations.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   1  non-HTML, keep-alive, 400 connections x 20 requests.  This is the one
#      that was red on 78c9ecc.  Catches any change that puts small non-HTML
#      files back on the splice path.
#   2  HTML, same shape.  The read path.  Green before and after, so it is the
#      control that says the traffic and the harness work -- if assertion 1
#      fails and this one also fails, the cause is not the splice path.
#   3  the marker is checked inside the client on every response, so a 404 or
#      an empty 200 cannot pass as health.  A 404 is faster than serving a
#      file and would read as a speed-up.
#
# The client is C, not Python, and that is not a style choice: the window is
# microseconds wide and a Python client written to the same protocol reported
# 400 of 400 answered on a file that made the C client stall, twice,
# interleaved on the same daemon.  See lib_ka_stall.c.

set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate hkanostall
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: --http keep-alive answers every request ==="

CLIENT="$WORK/ka_stall"
gcc -O2 -o "$CLIENT" "$HERE/lib_ka_stall.c"

ROOT="$WORK/root"
mkdir -p "$ROOT"
# Both well under HTTP_REVAL_MAX_FILE, so both are served from the
# revalidating map on this build.  The .txt is the one that mattered: non-HTML
# is what the splice path used to take.
printf 'MARKER-TXT%s' "$(printf 't%.0s' $(seq 1 2038))" > "$ROOT/asset.txt"
printf '<html><head><title>MARKER-HTML</title></head><body>%s</body></html>' \
       "$(printf 'h%.0s' $(seq 1 1900))" > "$ROOT/page.html"

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1610))
"$BIN" create server hkans -p "$P" --http "$ROOT" -s >/dev/null

# 400 connections of 20 requests.  400 rather than 20 because the failure rate
# on 78c9ecc was 2 to 5 connections in 400: at 20 connections a red build
# passes about 80% of the time, which is a test that reports the defect as
# flakiness.  8000 requests of 2 KiB costs 0.2 s on a fixed build.
# '|' rather than whitespace: the label has spaces in it and `set --` would
# split it, which turned a FAIL line into "non-HTML(splice" the first time.
for spec in "asset.txt|MARKER-TXT|non-HTML (the splice path before 25552d9)" \
            "page.html|MARKER-HTML|HTML (read path, control)"; do
    IFS='|' read -r f marker label <<<"$spec"
    out=$("$CLIENT" "$P" 20 400 2000 "/$f" "$marker") && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        pass
    else
        fail "$label" "keep-alive traffic was not fully answered" \
             "client: $out" \
             "stall>0 means the server went silent on an open connection" \
             "(the defect this file exists for; see the header)"
    fi
done

echo "--- $PASS/$TOTAL passed ---"
[ "$FAIL" -eq 0 ]
