#!/usr/bin/env bash
# Both directions matter, because a breaker that never opens is as wrong as one
# that opens on healthy traffic -- a backend that answers and then closes is
# healthy, one that closes without answering has failed, and one that writes a
# fragment of a header block and half-closes had its first byte read as success
# and kept its whole share of the rotation; so each backend counts the
# connections it accepts and that count is the discriminator, with zero hits a
# failure checked before the 503, too few hits reported as not measurable in
# its own column, and a run that could not put the question still ending
# non-zero.
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

# The default the proxies are created with and the number of charges the
# breaker needs, written down here because it is the floor every verdict in
# this file is measured against.
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

# A claim this run was unable to put the question to, in the words the sibling
# load tests already use rather than a third vocabulary, and non-zero like a
# failure but not about the build.
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

# Healthy answers then closes, failing closes without answering, and truncated
# writes part of a header block in one small write and half-closes -- which is
# the state the proxy's response scan calls "the rest is still coming".
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

# Cumulative, so every window is measured as a delta, and not through a `grep
# -c` pipe -- which prints 0 and exits 1, ending the file at the assignment on
# precisely the reading this test must be able to act on.
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

# The three-way verdict in one place, with the branch order load-bearing: zero
# hits is decided before a 503 is looked at, because a proxy with no backend at
# all answers 503 for refused connections, which is a different finding wearing
# the same status code.
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

# "Never circuit-broken" is asserted flatly in every run, because fewer
# requests can only make a spurious 503 less likely -- while "stays in
# rotation" needs the hit count, since it claims all twelve were served and a
# harness that put only ten never asked.
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

# A header block ended by the connection closing is a complete response by RFC
# 9112, so the client on one of the first requests is handed a 200 with no body
# and nothing can be written behind those bytes -- what is fixable is how many
# clients it happens to, which before the fix was all twelve, because the first
# byte of the fragment was recorded as the backend answering.
CUT_H0=$(be_hits "$CUT_BE")
read cut200 cut503 <<< "$(count_codes "$CUT_PROXY" cb_cut "$CUT_N")"
CUT_HITS=$(( $(be_hits "$CUT_BE") - CUT_H0 ))
assert_breaker_opened "backend that stops mid-header-block is circuit-broken" \
    "$cut503" "$CUT_HITS" "$CUT_N"

# Asked of the backend rather than of the status codes, because a hit that
# produced no 200 can exist, and bounded above by the threshold rather than the
# request count -- with the 503 deliberately having no say, since including it
# opened the guard on a run where the count was zero.
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

# Every assertion is accounted for in exactly one column, because a summary
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
