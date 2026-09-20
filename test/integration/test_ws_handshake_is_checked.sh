#!/usr/bin/env bash
# Integration test: a WebSocket version this server does not speak is refused
# with 426 and told which one it does.
#
# ─── WHAT WAS THERE BEFORE ─────────────────────────────────────────────────
#
# Nothing.  test_websocket.sh knows only the happy handshake, and the header
# scan in parse_partial read `upgrade`, `sec-websocket-key`, `cookie`,
# `origin`, `sec-websocket-protocol` and `authorization` -- and not
# `sec-websocket-version` at all.  Measured before this existed:
#
#     Sec-WebSocket-Version: 8    ->  HTTP/1.1 101 Switching Protocols
#     no version header at all    ->  HTTP/1.1 101 Switching Protocols
#
# RFC 6455 4.2.2 says a server that does not understand the version MUST
# refuse and name the versions it does.  What the old behaviour gave a
# version-8 client was a 101 and then frames in a framing nobody here parses:
# a connection that wedges rather than a sentence saying which version to use.
#
# ─── WHAT IS REFUSED AND WHAT DELIBERATELY IS NOT ──────────────────────────
#
# Only a version that is PRESENT and does not offer 13.  A handshake that omits
# the field is what this server has always accepted, and refusing it now would
# drop clients that work today over a header no real one leaves out.  A version
# it NAMES and we cannot speak is the case where saying so beats 101, and that
# is the whole change.
#
# The list form is accepted when 13 is among the offers, because a client
# sending "7, 13" is offering 13.  "130" is not "13" and each token is trimmed
# on both ends, which is what the last two rows below are for.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a WebSocket version we do not speak is refused, and named ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

P=$((SL_PORT_BASE+1448))

daemon_isolate wshs
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create server wsh -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.3

KEY='Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='

# The whole response, so the header assertion below reads the same bytes the
# status one did rather than opening a second connection to look.
ask() {
    local ver="$1" req
    if [ "$ver" = "-" ]; then
        req="GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n${KEY}\r\n\r\n"
    else
        req="GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n${KEY}\r\nSec-WebSocket-Version: ${ver}\r\n\r\n"
    fi
    printf "$req" | timeout 3 nc -q0 127.0.0.1 "$P" 2>/dev/null | tr -d '\r'
}
status() { head -1 <<<"$1"; }

check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }

R13=$(ask 13)
check "version 13 is upgraded"            "HTTP/1.1 101 Switching Protocols" "$(status "$R13")"

R8=$(ask 8)
check "version 8 is refused with 426"     "HTTP/1.1 426 Upgrade Required"    "$(status "$R8")"
# The refusal has to say which version, or it is a refusal with no way out --
# which is the half of RFC 6455 4.2.2 a bare status code would miss.
if grep -qi '^Sec-WebSocket-Version: 13$' <<<"$R8"; then ok "and the refusal names version 13"
else bad "and the refusal names version 13" "no such header in: $(tr '\n' '|' <<<"$R8" | head -c 120)"; fi

check "version 12 is refused too"         "HTTP/1.1 426 Upgrade Required"    "$(status "$(ask 12)")"
# 130 begins with 13 and is not 13; a prefix compare would upgrade it.
check "and 130 is not mistaken for 13"    "HTTP/1.1 426 Upgrade Required"    "$(status "$(ask 130)")"

# A client offering several versions is offering 13 if 13 is among them.
check "a list containing 13 is upgraded"  "HTTP/1.1 101 Switching Protocols" "$(status "$(ask '7, 13')")"
check "in either order"                   "HTTP/1.1 101 Switching Protocols" "$(status "$(ask '13, 7')")"
check "and surrounding spaces do not matter" "HTTP/1.1 101 Switching Protocols" "$(status "$(ask ' 13 ')")"

# Deliberate: this is what the server has always done, and the comment at the
# header scan says why it is left alone.
check "a handshake with no version at all still upgrades" \
      "HTTP/1.1 101 Switching Protocols" "$(status "$(ask -)")"

# And the listener is still serving afterwards, so a refusal is a refusal of
# one handshake and not of the runtime.
check "the server still upgrades after a refusal" \
      "HTTP/1.1 101 Switching Protocols" "$(status "$(ask 13)")"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
