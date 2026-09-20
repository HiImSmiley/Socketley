#!/usr/bin/env bash
# Integration test: what this server does with a handshake that is wrong --
# the version (426), the missing nonce (400), and the whitespace around the two
# field values that decide whether there is a handshake at all.
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

echo "=== Integration: a handshake that is wrong is refused for the right reason ==="

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

# RFC 6455 4.1's own worked example, nonce and accept both, so the accept
# assertions below are read against the standard and not against this build.
KEYVAL='dGhlIHNhbXBsZSBub25jZQ=='
ACCEPT='s3pPLMBiTxaQ9kYGzzhZRbK+xOo='
KEY="Sec-WebSocket-Key: $KEYVAL"

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

# The same connection as ask(), with the header block supplied whole, since
# these cases are about a field being absent or carrying whitespace a client
# would not send -- neither of which ask() can express.
ask_hdrs() {
    printf "GET / HTTP/1.1\r\nHost: h\r\n$1\r\n" \
        | timeout 3 nc -q0 127.0.0.1 "$P" 2>/dev/null | tr -d '\r'
}
accept_of() { sed -n 's/^Sec-WebSocket-Accept: *//Ip' <<<"$1"; }
UP='Upgrade: websocket\r\nConnection: Upgrade\r\n'

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

# ─── THE NONCE ─────────────────────────────────────────────────────────────
#
# Measured before this existed, against a server started with --http:
#
#     no Sec-WebSocket-Key   ->  HTTP/1.1 200 OK, the page body, keep-alive
#
# and 404 from a server with nothing to serve, which is the same thing with an
# empty directory.  The request was not refused at all: a missing key joined
# "no Upgrade header" in one condition, so an upgrade attempt this server can
# never complete was handed to the HTTP side and answered as an ordinary GET,
# on a connection the client is holding open waiting for a 101.
#
# RFC 6455 4.2.1 makes the field mandatory and 4.2.2 names 400 for a handshake
# the server stops processing.

R=$(ask_hdrs "${UP}Sec-WebSocket-Version: 13\r\n")
check "an upgrade with no key is refused with 400" "HTTP/1.1 400 Bad Request" "$(status "$R")"
# A refusal that does not say which header is one the client cannot act on.
if grep -q 'Sec-WebSocket-Key' <<<"$R"; then ok "and the refusal names the header"
else bad "and the refusal names the header" "not in: $(tr '\n' '|' <<<"$R" | head -c 160)"; fi
# The length in the C++ literal is counted by hand, so it is counted a second
# time here: a Content-Length past the end of the body leaves a client that
# reads exactly that many bytes waiting for a remainder that is not coming.
BODY=$(printf '%s\n' "$R" | sed '1,/^$/d')
CL=$(grep -i '^Content-Length:' <<<"$R" | tr -dc '0-9')
check "and the body is the sentence the refusal names" \
      "this WebSocket upgrade has no Sec-WebSocket-Key" "$BODY"
check "and Content-Length counts that sentence and its newline" \
      "$(( ${#BODY} + 1 ))" "$CL"

# Whitespace is not a value: a field whose whole value is a space supplies no
# nonce, and answering 101 over it hashes the GUID alone into a constant.
check "an empty key value is refused the same way"  "HTTP/1.1 400 Bad Request" \
      "$(status "$(ask_hdrs "${UP}Sec-WebSocket-Key: \r\nSec-WebSocket-Version: 13\r\n")")"

# Deliberate, and the reason is written at the refusal in the header scan: a
# nonce that is PRESENT and not sixteen bytes still upgrades, because the
# accept returned for it is correct for the key that was sent and the client it
# belongs to works end to end today.  This assertion is here to make the next
# person say so out loud before changing it.
check "a key that is not sixteen bytes still upgrades" "HTTP/1.1 101 Switching Protocols" \
      "$(status "$(ask_hdrs "${UP}Sec-WebSocket-Key: c2hvcnQ=\r\nSec-WebSocket-Version: 13\r\n")")"

# And the fall-through the refusal was split out of is untouched: no Upgrade
# means this was never a handshake, and the HTTP side answers it.
check "a request with no Upgrade is still served as HTTP" "HTTP/1.1 404 Not Found" \
      "$(status "$(ask_hdrs "Connection: Upgrade\r\n${KEY}\r\nSec-WebSocket-Version: 13\r\n")")"

# ─── THE WHITESPACE AROUND THE TWO VALUES THAT DECIDE ──────────────────────
#
# OWS is SP or HTAB (RFC 9110 5.5) and belongs to neither side of the field
# value.  The upgrade scan skipped leading spaces only, and the two values it
# compares failed differently for it:
#
#     Sec-WebSocket-Key: <nonce><space>  ->  101, accept over "<nonce> "
#     Upgrade: websocket<space>          ->  404, no upgrade seen at all
#
# The first is why the status is NOT the assertion below.  A trailing space
# upgraded before this change too; what was wrong was the accept, computed over
# a nonce the client did not hash, so a conformant client rejects the 101 this
# end has already sent and closes.  Reading the status there would pass on the
# defect.

check "the RFC's sample nonce gets the RFC's sample accept" "$ACCEPT" \
      "$(accept_of "$(ask_hdrs "${UP}Sec-WebSocket-Key: ${KEYVAL}\r\nSec-WebSocket-Version: 13\r\n")")"
check "a trailing space is not part of the nonce"          "$ACCEPT" \
      "$(accept_of "$(ask_hdrs "${UP}Sec-WebSocket-Key: ${KEYVAL} \r\nSec-WebSocket-Version: 13\r\n")")"
check "nor a trailing tab"                                 "$ACCEPT" \
      "$(accept_of "$(ask_hdrs "${UP}Sec-WebSocket-Key: ${KEYVAL}\t\r\nSec-WebSocket-Version: 13\r\n")")"
check "nor a leading tab"                                  "$ACCEPT" \
      "$(accept_of "$(ask_hdrs "${UP}Sec-WebSocket-Key:\t${KEYVAL}\r\nSec-WebSocket-Version: 13\r\n")")"

check "Upgrade: websocket with a trailing space is an upgrade" \
      "HTTP/1.1 101 Switching Protocols" \
      "$(status "$(ask_hdrs "Upgrade: websocket \r\nConnection: Upgrade\r\n${KEY}\r\nSec-WebSocket-Version: 13\r\n")")"
check "and with a leading tab"  "HTTP/1.1 101 Switching Protocols" \
      "$(status "$(ask_hdrs "Upgrade:\twebsocket\r\nConnection: Upgrade\r\n${KEY}\r\nSec-WebSocket-Version: 13\r\n")")"

# And the listener is still serving afterwards, so a refusal is a refusal of
# one handshake and not of the runtime.
check "the server still upgrades after a refusal" \
      "HTTP/1.1 101 Switching Protocols" "$(status "$(ask 13)")"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
