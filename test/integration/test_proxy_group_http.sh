#!/usr/bin/env bash
# Integration test: HTTP proxy routing through an @group backend.
#
# Group backends are resolved per connection, so the group entry in m_backends
# deliberately carries no resolved_host/resolved_port.  Anything that describes
# the target after selection has to read the endpoint off the connection — get
# that wrong and the forwarded request goes out with a literal "Host: :0".
#
# The group member is a TCP proxy pointing at a netcat listener, which gives us
# the exact bytes the gateway put on the wire.
#
# Runs its own daemon on its own socket and state directory, like the rest of
# this directory.  On the shared socket the central assertion here was not
# safe: the group is a name, an @group gateway routes to whatever carries it,
# and a runtime tagged `grphttp` left behind by an earlier run — or created by
# someone else on the same machine — is a member of the group this test is
# measuring.  The Host header would then name a port this file never chose,
# which reads as the defect this file exists to catch.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-grphttp-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"
DLOG="$TMPD/daemon.log"
DPID=""

# Ports come off one base so two runs can share a machine.
PORT_BASE=${PORT_BASE:-19280}
GW_PORT=$((PORT_BASE+2))
MEMBER_PORT=$((PORT_BASE+3))
SINK_PORT=$((PORT_BASE+4))
GROUP=grphttp
CAPTURE="$TMPD/forwarded.txt"
NC_PID=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$NC_PID" ] && kill "$NC_PID" 2>/dev/null || true
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Kill by socket, not only by pid.  Every CLI command except `daemon`,
    # `version` and `help` auto-starts a daemon when the socket does not answer,
    # forking and setsid-ing one detached from this shell; killing $DPID alone
    # would leave that one running for good, holding this test's ports and
    # answering for a state directory that is about to be deleted.
    #
    # Matched by exact process name and by this run's socket, never by a
    # command-line pattern: `pgrep -f 'socketley daemon'` also matches any shell
    # whose own command line carries that string -- including a test runner --
    # and a -f match that is one character too broad kills the run doing the
    # matching.  The socket path comes from mktemp, so the environ check below
    # can only ever hit daemons belonging to this run.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET"; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$2]: $1"; }

assert_contains() {
    if echo "$1" | grep -q "$2"; then ok; else bad "expected '$2' in output" "$3"; fi
}

assert_not_contains() {
    if echo "$1" | grep -q "$2"; then bad "did not expect '$2' in output" "$3"; else ok; fi
}

# listening PORT [TIMEOUT_S]
#
# The port is in LISTEN state, proved from /proc/net/tcp without connecting to
# it.  Not lib_ready.sh's ready_tcp, and the difference is the whole oracle of
# this file: the capture listener is a plain `nc -l`, which accepts exactly one
# connection and then stops listening, and the member proxy forwards whatever
# connects to it straight into that one accept.  A readiness probe that dials
# either of them spends the connection the gateway's request was supposed to
# arrive on, and the run then reports "nothing was forwarded" — the exact
# sentence it would print for the defect this file exists to catch.  Measured:
# with ready_tcp on the sink and the member, three assertions failed against a
# gateway that was routing correctly.
listening() {
    local port=$1 timeout=${2:-10} hex
    hex=$(printf '%04X' "$port")
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        if awk -v hex="$hex" '$4=="0A" && $2 ~ (":" hex "$") {f=1} END{exit !f}' \
               /proc/net/tcp 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

echo "=== Integration: proxy @group over HTTP ==="

# Wait on the daemon's own log line, never by polling with a CLI command: a CLI
# command run before the socket answers starts a daemon of its own, so polling
# with one races the daemon this test just launched.  "daemon started" is
# printed after the IPC socket is bound and after any state is restored, so it
# is the readiness signal and it comes from this process rather than from a
# socket path someone else might own.
"$BIN" daemon >"$DLOG" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do
    grep -q "daemon started" "$DLOG" 2>/dev/null && break
    sleep 0.1
done

TOTAL=$((TOTAL+1))
if [ -S "$SOCKETLEY_SOCKET" ] && kill -0 "$DPID" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: this test's own daemon never came up; everything below"
    echo "        would be measuring whatever else is on the machine"
    tail -5 "$DLOG" 2>/dev/null | sed 's/^/        /' || true
fi

# Capture whatever the gateway forwards
rm -f "$CAPTURE"
timeout 15 nc -l 127.0.0.1 "$SINK_PORT" > "$CAPTURE" &
NC_PID=$!
listening "$SINK_PORT" 10 || true

create() {
    local why=$1; shift
    if "$BIN" create "$@" >/dev/null 2>&1; then ok; else bad "create failed" "$why"; fi
}

# Group member: TCP proxy that passes bytes through to the capture listener
create "group member created" proxy grphttp_be -p "$MEMBER_PORT" \
    --backend "127.0.0.1:$SINK_PORT" --protocol tcp -g "$GROUP" -s
listening "$MEMBER_PORT" 10 || true

# Gateway: HTTP proxy routing to the group
create "gateway created" proxy grphttp_gw -p "$GW_PORT" \
    --backend "@$GROUP" --protocol http -s
listening "$GW_PORT" 10 || true

OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "grphttp_be" "group member in ps"
assert_contains "$OUT" "grphttp_gw" "gateway in ps"

# The @group gateway routes to whatever carries the group name, so a member
# this test did not create would answer for it and the Host assertion below
# would be about a port nobody here chose.  On an isolated daemon there can be
# exactly one, and saying so is what makes the Host check mean what it says.
MEMBERS=$("$BIN" ps 2>&1 | grep -c "grphttp_be" || true)
if [ "$MEMBERS" -eq 1 ]; then ok; else bad "found $MEMBERS runtimes named grphttp_be, expected 1" "one member in the group"; fi

# The HTTP proxy only accepts its own /<name>/ prefix.  No response is expected —
# the listener never answers; what matters is what arrived.
curl -s -m 4 -o /dev/null "http://127.0.0.1:$GW_PORT/grphttp_gw/hello" 2>/dev/null || true

# Wait for the bytes rather than sleeping for them: the capture file is the
# oracle, and a fixed sleep that is generous on an idle machine is thin when the
# whole suite is running.
for _ in $(seq 1 60); do
    [ -s "$CAPTURE" ] && break
    sleep 0.1
done

FORWARDED=$(cat "$CAPTURE" 2>/dev/null || true)

if [ -n "$FORWARDED" ]; then ok; else bad "nothing was forwarded" "request reached member"; fi

assert_contains "$FORWARDED" "GET /hello HTTP/1.1" "request line forwarded"
assert_contains "$FORWARDED" "Host: 127.0.0.1:$MEMBER_PORT" "Host names the selected group member"
assert_not_contains "$FORWARDED" "Host: :0" "no empty Host from the unresolved group entry"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
