#!/usr/bin/env bash
# Integration test: what the circuit breaker counts as a backend failure.
#
# Both directions matter and are checked here, because a breaker that never
# opens is as wrong as one that opens on healthy traffic:
#
#   a backend that answers and then closes its own connection is healthy —
#   that is HTTP/1.0, Connection: close, and every keep-alive idle timeout
#
#   a backend that closes without answering has failed, and the breaker must
#   still take it out of rotation
#
#   a backend that writes a fragment of a header block and then half-closes has
#   failed too, and this is the one the breaker could not see.  "The backend
#   answered" was read off the first byte to arrive on the socket, so a peer
#   that stops in the middle of its headers was recorded as a success and kept
#   its whole share of the rotation, handing every client after it the same
#   truncated fragment.  The loss to the client that hits it is unavoidable —
#   those bytes are already on its wire and no status line can be written behind
#   them — but the next client's is not.
#
# ─── WHAT THE BACKEND SAW, AND WHY IT IS THE DISCRIMINATOR ──────────────────
#
# The breaker opens on circuit_threshold consecutive failures, so "no 503 in
# twelve requests" is only a statement about the product when at least
# circuit_threshold of those twelve actually reached the backend.  Requests that
# never got there cannot have charged anything, and a run that put fewer
# questions than the threshold has not been answered — it has been interrupted.
#
# This was not academic.  A full-suite run with three foreign daemons on the box
# reported
#
#     FAIL [backend that stops mid-header-block is circuit-broken]:
#           never returned 503 in 12 requests                          7/8
#
# and the same file alone on a quiet box passed 8/8 three times running.  The
# contamination is fixed elsewhere; the shape is not, and it will recur on a
# 2-CPU runner where fewer of the twelve land inside their timeout.  Reported as
# a product defect, that sentence costs somebody an afternoon looking for a
# breaker that works.
#
# So each backend counts the connections it accepts, and the count is the
# discriminator — the third column, in the vocabulary d1fa885 gave
# test_restart_under_load.sh and test_proxy_group_keepalive_load.sh had first:
#
#     hits == 0                 FAIL.  Not a skip.  Nothing reached the backend,
#                               so nothing was truncated, and a 503 arriving
#                               anyway came from something else.  Checked first,
#                               ahead of the 503, for exactly that reason.
#     a 503 arrived             PASS.  The breaker demonstrably opened.
#     0 < hits < threshold      NOT MEASURABLE.  Too few charges could have been
#                               accumulated for the absence of a 503 to mean
#                               anything.  This run could not put the question.
#     hits >= threshold, no 503 FAIL, and it is the defect ea10b66 found.
#
# NOT MEASURABLE still ends the run non-zero: an assertion that was never
# evaluated has not passed.  It is counted in its own column so that "the
# harness could not ask" is visible without reading the log.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate breaker
OK_BE=$((SL_PORT_BASE+901)); OK_PROXY=$((SL_PORT_BASE+900))
BAD_BE=$((SL_PORT_BASE+911)); BAD_PROXY=$((SL_PORT_BASE+910))
CUT_BE=$((SL_PORT_BASE+921)); CUT_PROXY=$((SL_PORT_BASE+920))
PASS=0; FAIL=0; HERR=0; TOTAL=0
BE_PIDS=()

# The default the proxies below are created with, and the number of charges the
# breaker needs before it opens.  Written down here because it is the floor
# every verdict in this file is measured against, not merely a fact about the
# daemon.
CIRCUIT_THRESHOLD=5
OK_N=12          # requests at the healthy backend
BAD_N=10         # ...at the one that closes without answering
CUT_N=12         # ...at the one that stops mid-header-block

cleanup() {
    "$BIN" stop cb_ok   2>/dev/null || true
    "$BIN" stop cb_bad  2>/dev/null || true
    "$BIN" stop cb_cut  2>/dev/null || true
    sleep 0.3
    "$BIN" remove cb_ok  2>/dev/null || true
    "$BIN" remove cb_bad 2>/dev/null || true
    "$BIN" remove cb_cut 2>/dev/null || true
    for p in "${BE_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# herr LABEL REASON [DETAIL...]
#
# A claim this run was unable to put the question to, kept apart from a failure
# on purpose and deliberately in the words test_proxy_group_keepalive_load.sh
# and test_restart_under_load.sh already use for it rather than a third
# vocabulary.  Both end the run non-zero; only one of them is about the build.
herr() {
    TOTAL=$((TOTAL+1)); HERR=$((HERR+1))
    echo "  NOT MEASURABLE [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

assert_eq() {
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        ok
    else
        bad "$label" "got '$got', expected '$expected'"
    fi
}

echo "=== Integration: proxy circuit breaker ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    echo "  SKIP: python3 and curl are both required"
    exit 0
fi

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"; cleanup' EXIT

# Healthy: answers, then closes.  Failing: closes without answering.
# Truncated: writes part of a header block — no terminating blank line anywhere
# in it — and half-closes.  One small write, so the proxy reads the whole
# fragment in one completion; that is the state its response scan calls "the
# rest of this header block is still coming", and it never comes.
cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading
mode, port = sys.argv[1], int(sys.argv[2])
body = b"backend-ok"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)
fragment = b"HTTP/1.1 200 OK\r\nX-Partial: yes"

def serve(c):
    try:
        c.recv(65536)
        if mode == "healthy":
            c.sendall(resp)
        elif mode == "truncated":
            c.sendall(fragment)
            c.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    finally:
        c.close()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(64)
print("ready", flush=True)
while True:
    try:
        c, _ = srv.accept()
    except OSError:
        break
    # One line per connection the proxy actually opened, printed from the accept
    # loop rather than from the worker thread: this is the only place the
    # ordering is already serialised, so the count owes nothing to the GIL.
    #
    # An accepted connection is the right unit.  The breaker charges a failure
    # per backend attempt, so "the proxy dialled it" is exactly one opportunity
    # to charge, whether or not the request behind it got as far as being read.
    print("ACCEPT", flush=True)
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

start_backend() {   # mode, port
    python3 "$TMPD/be.py" "$1" "$2" >"$TMPD/be_$2.log" 2>&1 &
    BE_PIDS+=("$!")
    for _ in $(seq 1 50); do grep -q ready "$TMPD/be_$2.log" 2>/dev/null && return 0; sleep 0.1; done
    return 1
}

# be_hits BACKEND_PORT -> connections that backend has accepted, ever
#
# Cumulative, so every window below is measured as a delta.  Readiness probes
# and the proxy's own dialling before the window opened are real connections and
# would otherwise be counted as charges the window did not put.
#
# NOT `grep -c -q`, and not through a pipe: `grep -c` with no match prints 0 and
# exits 1, which under `set -euo pipefail` would end the file at the assignment
# rather than reporting a zero — and zero is the reading this file must be able
# to act on, since it is the one that means nothing reached the backend.
be_hits() {
    local n
    n=$(grep -c '^ACCEPT' "$TMPD/be_$1.log" 2>/dev/null) || n=0
    printf '%s' "${n:-0}"
}

count_codes() {     # proxy port, name, requests -> "<n200> <n503>"
    local n200=0 n503=0 code
    for _ in $(seq 1 "$3"); do
        code=$(timeout 4 curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/$2/" 2>/dev/null || true)
        [ "$code" = "200" ] && n200=$((n200+1))
        [ "$code" = "503" ] && n503=$((n503+1))
        sleep 0.15
    done
    echo "$n200 $n503"
}

# assert_breaker_opened LABEL N503 HITS REQUESTS
#
# The three-way verdict, in one place because both "the breaker must open" cases
# want exactly it.  The order of the branches is load-bearing and is argued at
# the top of the file: zero hits is decided BEFORE a 503 is looked at, so that a
# 503 produced by something other than the failure under test cannot be read as
# this backend having been broken out of rotation.  Take the backend away
# altogether and the proxy answers 503 to every request — for refused
# connections, which is a different finding wearing the same status code.
assert_breaker_opened() {
    local label=$1 n503=$2 hits=$3 reqs=$4

    if [ "$hits" -eq 0 ]; then
        bad "$label" "not one of the $reqs requests reached the backend" \
            "Nothing was truncated, refused or dropped by the backend, so there was" \
            "no failure for the breaker to charge and this run measured nothing." \
            "That is a broken harness, not an unmeasurable one: a window with no" \
            "traffic in it at all never becomes measurable by being retried."
        return
    fi

    if [ "$n503" -gt 0 ]; then
        ok
        return
    fi

    if [ "$hits" -lt "$CIRCUIT_THRESHOLD" ]; then
        herr "$label" \
            "only $hits of $reqs requests reached the backend, threshold is $CIRCUIT_THRESHOLD" \
            "The breaker opens on $CIRCUIT_THRESHOLD consecutive failures and could not have" \
            "accumulated that many, so the absence of a 503 says nothing about it." \
            "Nothing here says the build misbehaved.  On a quiet machine all $reqs" \
            "get through; check what else was competing for the CPU."
        return
    fi

    bad "$label" "no 503 in $reqs requests, $hits of which reached the backend" \
        "That is at or past the threshold of $CIRCUIT_THRESHOLD, so the breaker had every" \
        "charge it needs and did not open.  Each client past the ${CIRCUIT_THRESHOLD}th was handed" \
        "the same broken answer by a backend that should have been out of rotation."
}

daemon_start "$BIN"

start_backend healthy   "$OK_BE"  || { echo "  SKIP: healthy backend did not start"; exit 0; }
start_backend failing   "$BAD_BE" || { echo "  SKIP: failing backend did not start"; exit 0; }
start_backend truncated "$CUT_BE" || { echo "  SKIP: truncating backend did not start"; exit 0; }

create_ok "proxy for the healthy backend created" \
    "$BIN" create proxy cb_ok  -p "$OK_PROXY"  --backend "127.0.0.1:$OK_BE"  -s
create_ok "proxy for the failing backend created" \
    "$BIN" create proxy cb_bad -p "$BAD_PROXY" --backend "127.0.0.1:$BAD_BE" -s
create_ok "proxy for the truncating backend created" \
    "$BIN" create proxy cb_cut -p "$CUT_PROXY" --backend "127.0.0.1:$CUT_BE" -s
# The healthy proxy has to answer before the breaker cases mean anything.
ready_http 127.0.0.1 "$OK_PROXY" "/cb_ok/ready" 20 || true

# ─── The healthy backend: the breaker must NOT open ─────────────────────────
#
# circuit_threshold defaults to 5, so twelve requests are well past it.
#
# 'never circuit-broken' is asserted flatly, in every run.  Fewer requests can
# only make a spurious 503 less likely, never more, so CPU pressure cannot
# manufacture this failure and there is nothing here for a third column to say.
#
# 'stays in rotation' is the one that needs the hit count.  It claims all twelve
# were served, and if the harness only managed to put ten of them to the backend
# then twelve was never the question — while a shortfall caused by the breaker
# wrongly opening is caught by the 503 check either way.
OK_H0=$(be_hits "$OK_BE")
read ok200 ok503 <<< "$(count_codes "$OK_PROXY" cb_ok "$OK_N")"
OK_HITS=$(( $(be_hits "$OK_BE") - OK_H0 ))
assert_eq "$ok503" "0"  "healthy backend is never circuit-broken"
if [ "$OK_HITS" -eq "$OK_N" ]; then
    assert_eq "$ok200" "$OK_N" "healthy backend stays in rotation despite closing connections"
else
    herr "healthy backend stays in rotation despite closing connections" \
        "only $OK_HITS of $OK_N requests reached the backend ($ok200 came back 200)" \
        "The claim is that all $OK_N were served; this run did not put all $OK_N." \
        "The breaker did not do this — it never opened, which is asserted above."
fi

# ─── The backend that closes without answering ──────────────────────────────
BAD_H0=$(be_hits "$BAD_BE")
read bad200 bad503 <<< "$(count_codes "$BAD_PROXY" cb_bad "$BAD_N")"
BAD_HITS=$(( $(be_hits "$BAD_BE") - BAD_H0 ))
assert_breaker_opened "failing backend is circuit-broken" \
    "$bad503" "$BAD_HITS" "$BAD_N"

# ─── The backend that stops mid-header-block ────────────────────────────────
#
# Twelve requests against a threshold of five.
#
# What the client on one of those first requests gets is worth stating, because
# it is worse than a dropped connection and it is not fixable here: the fragment
# is a status line and one header, and a header block ended by the connection
# closing is a complete response by RFC 9112 Section 6.3, so curl reports 200.
# A backend that stopped in the middle of its answer is presented to the client
# as a success with no body.  Those bytes are already on the wire by the time
# the half-close arrives; nothing can be written behind them.
#
# What is fixable is how many clients it happens to.  Five failures open the
# breaker and the proxy answers 503 from there on without dialling the backend
# again.  Before the fix that never happened at any number of requests — the
# first byte of the fragment was recorded as the backend answering, so every one
# of the twelve was a 200 and the breaker's error count never moved.
CUT_H0=$(be_hits "$CUT_BE")
read cut200 cut503 <<< "$(count_codes "$CUT_PROXY" cb_cut "$CUT_N")"
CUT_HITS=$(( $(be_hits "$CUT_BE") - CUT_H0 ))
assert_breaker_opened "backend that stops mid-header-block is circuit-broken" \
    "$cut503" "$CUT_HITS" "$CUT_N"

# How many clients it happened to, asked of the backend rather than of the
# status codes.  The two used to be the same question — every request the
# backend served came back 200, so counting 200s counted hits — and they stop
# being the same the moment a request fails on its way there.  A 200 that never
# reached the backend cannot exist, but a hit that produced no 200 can, and this
# claim is about how many clients the broken backend was allowed to touch.
#
# Bounded above by the threshold, not by the request count: five failures is
# what the breaker is owed, and the sixth client is the one the fix is for.  A
# run that got fewer than five through has not yet reached the bound and cannot
# contradict it, so it is not evidence either way.
#
# A CEILING NOBODY WALKED UP TO IS NOT A CEILING.  This branch first read
# `hits >= threshold || n503 > 0`, and the second half of that was a hole: with
# the truncating backend taken away entirely, the proxy charges the breaker for
# the refused connections and does answer 503, so the guard opened on a run
# where the count was zero and `0 <= 5` passed.  A check that reports success
# for a window with no traffic in it is one of the checks that cannot fail, and
# the assertion above it was already failing that same run for the same reason.
# The 503 has nothing to say about this claim; only the count does.
if [ "$CUT_HITS" -eq 0 ]; then
    bad "it is out of rotation within circuit_threshold requests" \
        "not one of the $CUT_N requests reached the backend" \
        "It served nobody because it was never dialled, which is not the same" \
        "statement as the breaker having taken it out of rotation, and this run" \
        "cannot tell those apart.  Zero is a broken window, not a small one."
elif [ "$CUT_HITS" -lt "$CIRCUIT_THRESHOLD" ]; then
    herr "it is out of rotation within circuit_threshold requests" \
        "only $CUT_HITS of $CUT_N requests reached the backend, threshold is $CIRCUIT_THRESHOLD" \
        "The bound is $CIRCUIT_THRESHOLD and this run never walked up to it, so staying under" \
        "it is not evidence that anything took the backend out of rotation."
elif [ "$CUT_HITS" -le "$CIRCUIT_THRESHOLD" ]; then
    ok
else
    bad "it is out of rotation within circuit_threshold requests" \
        "$CUT_HITS of $CUT_N requests were served by it, expected at most $CIRCUIT_THRESHOLD" \
        "($cut200 of them came back to the client as 200 with no body)"
fi

echo "  hits: healthy=$OK_HITS/$OK_N failing=$BAD_HITS/$BAD_N truncating=$CUT_HITS/$CUT_N" \
     "(threshold $CIRCUIT_THRESHOLD)"

# Every assertion is accounted for in exactly one column.  Cheap, and a summary
# that does not add up cannot be acted on.
if [ "$((PASS+FAIL+HERR))" -ne "$TOTAL" ]; then
    echo "  FAIL [counters]: $PASS passed + $FAIL failed + $HERR not measurable"
    echo "        does not equal $TOTAL counted — this summary is wrong, not just the run"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
if [ "$FAIL" -eq 0 ] && [ "$HERR" -eq 0 ]; then echo "  OK"
elif [ "$FAIL" -eq 0 ]; then echo "  NOT MEASURABLE -- this run could not put the question, see above"
else echo "  FAILED"; fi
exit $((FAIL+HERR))
