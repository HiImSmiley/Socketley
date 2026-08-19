#!/usr/bin/env bash
# Reproducer for an OPEN defect.  Not a test -- run_all.sh globs test_*.sh, and
# this file is deliberately outside that glob because it fails on a correct
# checkout of this tree.  It fails because the defect is real, not because the
# reproducer is wrong.  When the defect is fixed, rename it to test_*.sh.
#
# ─── THE DEFECT ─────────────────────────────────────────────────────────────
#
# In `--http DIR` disk mode, on the DEFAULT configuration with no environment
# overrides, a keep-alive client asking repeatedly for a non-HTML file larger
# than server_instance.h's HTTP_REVAL_MAX_FILE (1 MiB) will sooner or later get
# nothing back at all: no response, no FIN, no RST, connection still open.  It
# waits forever.
#
# Measured on 25552d9, clean Release binary, 2 MiB .txt, 200 connections of 20
# requests, three runs: 31, 34 and 46 connections dead of 200, and 3762, 3724
# and 3617 of 4000 requests answered.
#
# THE RATE IS LOAD DEPENDENT, strongly, and in the direction that matters: what
# it races is how long the splice takes, and under load the io-wq workers that
# every IORING_OP_SPLICE is punted to contend.  Same client, same file, same
# 120 connections -- at loadavg 16 the transfer took 54 s and 26 connections
# died; at loadavg 3 it took 6.9 s and 1 died.  So roughly 20% of connections on
# a busy server and roughly 1% on an idle one, which is the wrong way round for
# anyone hoping to reproduce it in a quiet reproduction and the right way round
# for it to bite in production.  Give it more bursts on a quiet box, and record
# the loadavg -- this script prints it.
#
# ─── THE MECHANISM ──────────────────────────────────────────────────────────
#
# handle_read() declines to parse conn->partial while the connection is still
# finishing its last response, and nothing re-parses it afterwards:
#
#     if (conn->file_read_pending || conn->splice_pending ||
#         conn->splice_in_pending || conn->splice_out_pending)
#         goto submit_next_read;     // "parsed when the next read completes"
#
# A multishot recv is already armed, so the next request has ALREADY been moved
# out of the socket into conn->partial.  handle_splice_out() then arms a read
# and waits for bytes the client has already sent, while the client waits for a
# response that will never be produced.  Instrumented at both points: 24
# deferrals, 24 dead connections, 24 splice completions with a whole request
# still in partial, 1821 clean completions with partial empty.
#
# splice is not itself the bug.  Of the four flags, splice_out_pending is the
# only one a conforming client reaches, because the pipe->socket completion
# lands after the client already holds the whole response.  Control, same 2 MiB
# of body on the wire, same client, same box: .txt via splice 31/34/46 of 200
# dead; .html via the read path 0 of 200.
#
# ─── WHY 25552d9 DID NOT FIX IT, THOUGH IT LOOKED LIKE IT HAD ───────────────
#
# 25552d9 keeps the response bytes and revalidates them with one statx, and in
# doing so routes non-HTML files UNDER the 1 MiB cap to the read path instead of
# splicing them.  That removes the stall for those files -- see
# test_http_keepalive_no_stall.sh, which is red on 78c9ecc and green now -- but
# it is a side effect of a caching change, not a fix to the gap, and it stops at
# the cap.  Above the cap, and above HTTP_REVAL_MAX_TOTAL (64 MiB) where
# reval_take goes false for every file, the splice path and the gap are both
# exactly as they were.
#
# ─── THE FIX THIS IS WAITING FOR ────────────────────────────────────────────
#
# Counted on 25552d9: conn->partial is parsed for HTTP in 1 place, and 15 places
# set conn->proto = proto_unknown to mean "this connection has finished its
# response and may have another".  None of the 15 can resume a parse.  So the
# rule belongs at a chokepoint rather than at the deferral: the HTTP arm of
# handle_read should loop while partial holds a request the connection can
# accept, and the two async completions that finish a response --
# handle_splice_out's keep-alive arm and the file-read completion -- should
# drive that same loop as their last statement.  Two call sites, not fifteen.
#
# Not attempted here: it is a change to the hot path of server_instance.cpp,
# which another agent held at the time, and it needs both the Release and the
# Sanitize suite behind it.
#
# usage: ./repro_http_splice_keepalive_stall.sh [bursts]
# exit 1 when it reproduces (the current expectation), 0 when it does not.

set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate spstall
BURSTS="${1:-600}"
# The control only has to show the read path is clean, and at 2 MiB the read
# path is 6x SLOWER than splice (measured: 4.9 GB in 42.6 s against 6.9 s), so
# running it at the full count would dominate the runtime for no extra evidence.
CTRL_BURSTS=$(( BURSTS < 120 ? BURSTS : 120 ))
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT

echo "=== Reproducer: --http disk mode stalls a keep-alive connection above the 1 MiB cap ==="
echo "    loadavg at start: $(cut -d' ' -f1 /proc/loadavg)"

CLIENT="$WORK/ka_stall"
gcc -O2 -o "$CLIENT" "$HERE/lib_ka_stall.c"

ROOT="$WORK/root"
mkdir -p "$ROOT"
# 2 MiB, above HTTP_REVAL_MAX_FILE, non-HTML: takes the splice path even with
# the revalidating cache on, which is the default.
{ printf 'MARKER-BIG'; head -c $((2*1024*1024)) /dev/zero | tr '\0' 'B'; } > "$ROOT/big.txt"
# Same size, HTML, so it takes the read path: the control that shows the size
# and the duration are not by themselves what does it.
{ printf '<html><head><title>MARKER-BIG</title></head><body>'
  head -c $((2*1024*1024)) /dev/zero | tr '\0' 'B'
  printf '</body></html>'; } > "$ROOT/big.html"

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1620))
"$BIN" create server spstall -p "$P" --http "$ROOT" -s >/dev/null

# The client is pinned.  Unpinned it floats onto whichever core is idle, and
# the turnaround between reading the last body byte and sending the next request
# is exactly what this is racing -- an unpinned client measured 0 stalls where a
# pinned one on the same daemon measured 23 and 26 of 120.
rc_txt=0
echo -n "  2 MiB non-HTML (splice path): "
t0=$(date +%s%N)
taskset -c 1 "$CLIENT" "$P" 20 "$BURSTS" 2000 /big.txt MARKER-BIG || rc_txt=$?
echo "    elapsed $(( ($(date +%s%N) - t0) / 1000000 )) ms"

echo -n "  2 MiB HTML     (read path, control): "
t0=$(date +%s%N)
taskset -c 1 "$CLIENT" "$P" 20 "$CTRL_BURSTS" 2000 /big.html MARKER-BIG || true
echo "    elapsed $(( ($(date +%s%N) - t0) / 1000000 )) ms"

if [ "$rc_txt" -ne 0 ]; then
    echo "  REPRODUCED: the splice path went silent on an open keep-alive connection."
    echo "  If the control above is 0 stalls, the read path is fine and this is the splice window."
    exit 1
fi
echo "  did NOT reproduce this run -- the window is load and duration dependent;"
echo "  try more bursts, and record the loadavg."
exit 0
