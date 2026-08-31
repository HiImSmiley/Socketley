#!/usr/bin/env bash
# Integration test: a registered type's verbs are not guessed at.
#
# The connection sniffer decides a protocol from the first four bytes, and it
# knows the four built-in shapes.  A registered type's verbs are by definition
# ones it has never seen: kvdb answers GET and PUT, which read as HTTP, and the
# store went silent -- three lines in, no reply, no error anywhere.
#
# The old answer was a line in an example telling you to call
# set_wire_protocol(proto_tcp) in your constructor, which is a footgun
# documented rather than removed: forget it and the failure is silence.  A
# registered type now gets lines unless it says otherwise.
#
# Both arms run here, because the positive alone would also pass if the sniffer
# had simply started reading GET as a line.  The control asks for the sniffer
# back and must NOT get the line-protocol answer -- that is what proves the
# default is what carries the first arm, and that a type wanting HTTP or
# WebSocket auto-detection can still have it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")

daemon_isolate regproto

PORT_QUIET=$((SL_PORT_BASE+1380))
PORT_SNIFF=$((SL_PORT_BASE+1381))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop quiet 2>/dev/null || true
    "$BIN" stop sniff 2>/dev/null || true
    sleep 0.3
    "$BIN" remove quiet 2>/dev/null || true
    "$BIN" remove sniff 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a registered type's verbs are not guessed at ==="

command -v g++ >/dev/null 2>&1 || { echo "  SKIP: g++ is required"; exit 0; }
command -v nc  >/dev/null 2>&1 || { echo "  SKIP: nc is required"; exit 0; }
[ -f "$BINDIR/libsocketley_sdk.a" ] || { echo "  SKIP: libsocketley_sdk.a is not built"; exit 0; }

SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac
SDKFLAGS=$("$ROOT/sdk/socketley-config" --config "$(basename "$BINDIR")" --cflags --libs) || {
    echo "  FAIL [socketley-config answers]: $SDKFLAGS"
    echo "  Results: 0/1 passed (1 failed)"
    exit 1
}

SRC="$ROOT/sdk/examples/nosql-runtime/kvdb_worker.cpp"

# The example itself is the first arm: if someone puts a set_wire_protocol()
# call back into it, this test stops measuring the default and says so.
# Anchored past the comment leader, because the example names the call in a
# sentence explaining why it does not make it.
if grep -qE '^[^/]*set_wire_protocol' "$SRC"; then
    bad "the example declares no wire protocol" \
        "kvdb_worker.cpp calls set_wire_protocol, so the default is not what this test measures"
else
    ok
fi

# The control is the example plus one line, generated rather than kept as a
# second file, so the two arms cannot drift apart.  Its registered name has to
# differ too: a worker builds only the type it registered, and both arms run
# under one daemon.
CTL="$SOCKETLEY_TMPD/control.cpp"
awk '/set_on_client_message\(\[this\]\(int fd, std::string_view raw\)/ && !done {
        print "        set_wire_protocol(proto_unknown);"; done=1
     } { print }' "$SRC" | sed 's/"kvdb"/"kvsniff"/' > "$CTL"
if grep -q 'set_wire_protocol(proto_unknown)' "$CTL" && grep -q '"kvsniff"' "$CTL"; then ok; else
    bad "the control asks for the sniffer back" "an anchor in kvdb_worker.cpp moved"
fi

build() {
    g++ -std=c++23 $SANFLAGS "$1" $SDKFLAGS -o "$2" 2>"$SOCKETLEY_TMPD/gxx.err"
}
if build "$SRC" "$SOCKETLEY_TMPD/w-quiet"; then ok; else
    bad "the example worker builds" "$(tail -4 "$SOCKETLEY_TMPD/gxx.err")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi
if build "$CTL" "$SOCKETLEY_TMPD/w-sniff"; then ok; else
    bad "the control worker builds" "$(tail -4 "$SOCKETLEY_TMPD/gxx.err")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi

mkdir -p "$HOME/.config/socketley/types"
for pair in "kvdb:w-quiet" "kvsniff:w-sniff"; do
    cat > "$HOME/.config/socketley/types/${pair%%:*}.toml" <<EOF
name = "${pair%%:*}"
exec = "$SOCKETLEY_TMPD/${pair##*:}"
manifest_version = 1
EOF
done

"$BIN" create kvdb quiet -p "$PORT_QUIET" -s >/dev/null 2>&1
"$BIN" create kvsniff sniff -p "$PORT_SNIFF" -s >/dev/null 2>&1

# The worker is a forked process with a listener of its own, so the port is the
# thing to wait on rather than the daemon's answer.
wait_port() {
    local p=$1 i
    for i in $(seq 1 60); do
        (exec 3<>/dev/tcp/127.0.0.1/"$p") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
        sleep 0.1
    done
    return 1
}
if wait_port "$PORT_QUIET"; then ok; else bad "the quiet runtime listens" "nothing on $PORT_QUIET"; fi
if wait_port "$PORT_SNIFF"; then ok; else bad "the sniffing runtime listens" "nothing on $PORT_SNIFF"; fi

VERBS=$'PUT users name ada\nGET users name\nCOUNT\n'

QUIET=$(printf '%s' "$VERBS" | timeout 5 nc -q1 127.0.0.1 "$PORT_QUIET" 2>/dev/null | tr '\n' '|')
case "$QUIET" in
    "OK|ada|1|") ok ;;
    *) bad "a type that says nothing gets lines" \
           "expected OK|ada|1| from $PORT_QUIET, got '${QUIET:-<nothing>}'" ;;
esac

# Not an equality against silence: a sniffer taught to read GET as a line would
# be a change worth failing on, but so would one that answered these verbs by
# accident.  What must hold is that asking for auto-detection still gets it.
SNIFF=$(printf '%s' "$VERBS" | timeout 5 nc -q1 127.0.0.1 "$PORT_SNIFF" 2>/dev/null | tr '\n' '|')
if [ "$SNIFF" = "OK|ada|1|" ]; then
    bad "set_wire_protocol(proto_unknown) still reaches the sniffer" \
        "the control answered as a line protocol, so the explicit choice was ignored"
else
    ok
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
