#!/usr/bin/env bash
# Integration test: a proxy and a cache see a connection that has not spoken yet
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The sibling of test_server_sees_idle_connection.sh, and it exists because
# that fix was applied to one listener out of three.  TCP_DEFER_ACCEPT was set
# in setup_tcp_listener for the server, in proxy_instance and in
# cache_instance; only the first was removed.  Measured on the tree before this
# change, one silent client, server-side state 0.4 s after connect:
#
#     server   ESTAB       (fixed)
#     proxy    SYN-RECV
#     cache    SYN-RECV
#
# What the option does is tell the kernel not to complete a connection until
# the CLIENT sends data.  A client that connects and waits is therefore not a
# connection the runtime has: no accept, nothing downstream of it, no row in
# any count, and nothing to speak to for a protocol that greets.
#
# The second half is worse than the delay, and it carries to these two exactly
# as it did to the server.  A connection still in SYN-RECV is a request sock
# rather than a socket, and when the listener closes the kernel drops it
# SILENTLY — no FIN, no RST.  The client keeps an ESTABLISHED socket against a
# peer that no longer exists, and nothing sets SO_KEEPALIVE on a proxy's or a
# cache's accepted connections, so an idle client holds that dead socket until
# it next tries to write.
#
# ─── WHAT THESE ASSERTIONS WOULD CATCH ──────────────────────────────────────
#
# Two per listener type, and they fail for different reasons.
#
# The kernel-state assertion is the mechanism: it reads `ss` rather than
# anything the daemon reports, so it cannot be satisfied by a counter that is
# consistent about a connection its own runtime never had.  It is checked
# within one second, which is the option's own timeout, so a build that has it
# back cannot pass by waiting the deferral out.
#
# The removal assertion is the silent drop, and it is the one that cannot be
# faked: the client waits for its OWN connection to end after the runtime is
# removed.  On a build with the option nothing ever arrives and it reports
# `timeout`.
#
# ─── WHAT IT DOES NOT COVER ─────────────────────────────────────────────────
#
# The proxy is exercised in `--protocol http` only.  A `--protocol tcp` proxy
# reaches its backend on accept rather than on the first request, so a silent
# client there also decides whether a backend connection exists at all; that is
# a second question about the same option and it is not asked here.  No TLS
# listener on either type.  And nothing here measures what removing the option
# costs — that is in the commit, not in an assertion, because a rate assertion
# on a shared box is a flake and not a result.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
# lib_ports.sh opens its lock with `exec 9>`; put stderr back afterwards.
exec 2>&1
daemon_isolate pcidle
PASS=0; FAIL=0; TOTAL=0

HOLD_PID=""
cleanup() { [ -n "$HOLD_PID" ] && kill "$HOLD_PID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

# Under `set -e` every assertion here is silent when it passes, so a command
# that fails between them would end the file having printed nothing but its
# title.  A death with no line number is not something the next reader can act
# on, so it says which line.  Learned in the sibling file; kept here for the
# same reason.
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a proxy and a cache see a connection that has not spoken ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1521))
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; cleanup' EXIT

BE_PORT=$((P + 0))      # a real backend, so the proxy is in its ordinary shape
PX_PORT=$((P + 1))
CA_PORT=$((P + 2))
PX_DROP=$((P + 3))
CA_DROP=$((P + 4))

# The awk reads to the end and keeps the first match rather than `exit`ing on
# it.  An early exit closes the pipe, `ss` takes SIGPIPE, and under
# `set -o pipefail` the pipeline reports 141 — so the assertion would blow the
# file up precisely when it MATCHES.  Third place in this tree that has been
# learned; see the sibling file and lib_daemon.sh.
srv_state() {
    ss -tan 2>/dev/null | awk -v p="$1" '
        got == "" { n = split($4, l, ":"); m = split($5, r, ":")
                    if (l[n] == p && r[m] != "*") got = $1 }
        END { print got }'
}

# One listener type, one silent client, one question: what does the KERNEL say
# the server side of it is.  Ten tenths of a second, which is the deferral's own
# timeout, so a build that has the option back cannot pass this by waiting.
check_idle_established() {   # label port
    local label=$1 port=$2 st=""
    python3 "$HERE/lib_idle_conn.py" hold 127.0.0.1 "$port" 8 > "$WORK/hold.$label" 2>&1 &
    HOLD_PID=$!
    for _ in $(seq 1 40); do grep -q connected "$WORK/hold.$label" 2>/dev/null && break; sleep 0.1; done

    if grep -q connected "$WORK/hold.$label" 2>/dev/null; then pass
    else fail "$label: the client connects at all" \
              "no handshake against port $port; the state assertion below is not a result"; fi

    for _ in $(seq 1 10); do
        st=$(srv_state "$port")
        [ -n "$st" ] && break
        sleep 0.1
    done
    case "$st" in
        ESTAB) pass ;;
        *)     fail "$label: the server end of a silent connection is established" \
                    "the kernel reports '${st:-no such socket}' on the $label side while the client is connected" \
                    "SYN-RECV is TCP_DEFER_ACCEPT holding the connection back: it is a request sock," \
                    "not a socket, so nothing downstream of accept() exists for it yet" ;;
    esac

    kill "$HOLD_PID" 2>/dev/null || true
    wait "$HOLD_PID" 2>/dev/null || true
    HOLD_PID=""
}

# The assertion a counter cannot make.  A connection the runtime never accepted
# is dropped with the listener and nothing is sent, so the client is left
# ESTABLISHED against nothing — and with no keepalive anywhere, an idle client
# never finds out.  8 s is far past the ~1 s a real FIN takes on loopback and
# far short of any keepalive.
check_removal_ends_it() {   # label runtime-name port
    local label=$1 name=$2 port=$3 res
    # The pipeline is guarded rather than left to `set -o pipefail`: a python
    # that cannot start would otherwise end the file silently instead of failing
    # this assertion, which is the difference between a result and a mystery.
    res=$(python3 "$HERE/lib_idle_conn.py" eof 127.0.0.1 "$port" 8 "$BIN" remove "$name" 2>&1 | tail -1) \
        || res="the probe itself failed"
    case "$res" in
        eof\ *) pass ;;
        *)      fail "$label: removing it ends an idle client's connection" \
                     "the client got '$res' instead of an EOF within 8s" \
                     "a request sock dropped with its listener sends neither FIN nor RST," \
                     "so the client holds a dead connection with nothing to notice" ;;
    esac
}

# ─── Fixtures ───────────────────────────────────────────────────────────────
#
# A real backend behind the proxies rather than a dead port: an unreachable
# backend is a second reason for a proxy to close a connection, and this file
# is about the one before that.
mkdir -p "$WORK/www"
printf 'ok' > "$WORK/www/small.txt"
chmod -R a+rX "$WORK"

"$BIN" create server pcbe -p "$BE_PORT" --http "$WORK/www" -s >/dev/null 2>&1 || true
"$BIN" create proxy  pcpx -p "$PX_PORT" --backend "127.0.0.1:$BE_PORT" --protocol http -s >/dev/null 2>&1 || true
"$BIN" create cache  pcca -p "$CA_PORT" -s >/dev/null 2>&1 || true
"$BIN" create proxy  pcpxd -p "$PX_DROP" --backend "127.0.0.1:$BE_PORT" --protocol http -s >/dev/null 2>&1 || true
"$BIN" create cache  pccad -p "$CA_DROP" -s >/dev/null 2>&1 || true
sleep 1.2

# Every runtime this file measures has to be listening before anything is read
# off it.  Without this the state assertions would be answered by "no such
# socket", which is a setup failure wearing the costume of the defect.
for pr in "$PX_PORT" "$CA_PORT" "$PX_DROP" "$CA_DROP"; do
    up=""
    for _ in $(seq 1 60); do
        ss -ltnH 2>/dev/null | awk -v p="$pr" '{n=split($4,a,":"); if (a[n]==p) f=1} END{exit !f}' && { up=yes; break; }
        sleep 0.1
    done
    if [ -n "$up" ]; then pass
    else fail "setup: a listener came up on $pr" \
              "nothing is listening on $pr, so whatever the assertions below read is not this runtime"; fi
done

# ─── proxy ──────────────────────────────────────────────────────────────────
check_idle_established proxy "$PX_PORT"
check_removal_ends_it  proxy pcpxd "$PX_DROP"

# ─── cache ──────────────────────────────────────────────────────────────────
#
# A cache client speaks first almost by definition — RESP is request/response
# and nothing greets — so the deferral costs a real cache client nothing at all.
# It is removed there anyway, and the reason is the paragraph above rather than
# the delay: a connection that dies inside the window dies silently, and a
# client library holding a pool of idle cache connections is exactly the shape
# that never writes again to find out.
check_idle_established cache "$CA_PORT"
check_removal_ends_it  cache pccad "$CA_DROP"

echo
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ] || exit 1
