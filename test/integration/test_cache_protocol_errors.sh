#!/usr/bin/env bash
# Integration test: what a client is told when its bytes are not a command.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE ANSWER THAT WAS WRITTEN AND THEN THROWN AWAY.  The protocol-error path
#   appends "-ERR protocol error" and sets conn->closing, and flush_responses
#   drops a closing connection's buffer -- on purpose, with a trace line for it.
#   So the reply the code carefully composed never left, and EVERY protocol
#   error reached the client as a bare EOF.
#
#   That is worse than a wrong message.  A client library cannot tell an EOF
#   from a crash or a network reset: it reconnects, sends the same bytes, is
#   cut off again, and has nothing to log.  The comment at that path spells out
#   why answering matters -- "answering and then closing is the only outcome
#   that cannot strand it" -- which is what made the silence a regression
#   against a stated invariant rather than a missing feature.
#
#   THE WALL WITH NO SIGN ON IT.  args[] is a stack array of 1024 views, so a
#   command with more arguments than that is refused.  Redis accepts up to
#   1024*1024, so DEL or MGET over a thousand keys is a legal thing for a
#   client to send and an unusual thing to be cut off for.  It is still
#   refused -- 1024 views is 16 KB of stack and a million would be 16 MB -- but
#   it now says which limit was met and what the limit is, because "protocol
#   error" sends a client looking for a framing bug it does not have.
#
#   Both are checked as BYTES ON THE WIRE and not as an exit code: the whole
#   defect was that the reply existed everywhere except on the socket.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: protocol errors reach the client ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

P=$((SL_PORT_BASE+1447))
daemon_isolate cacheproto
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache pe_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

PY=$SOCKETLEY_TMPD/pe.py
cat > "$PY" <<'PYEOF'
import socket, sys, json
def enc(a):
    return (('*%d\r\n' % len(a)) + ''.join('$%d\r\n%s\r\n' % (len(x), x) for x in a)).encode()
port = int(sys.argv[2])

def probe(payload, wait=2.0):
    """Everything the socket gives back before it is closed or goes quiet."""
    s = socket.create_connection(('127.0.0.1', port), timeout=6)
    s.sendall(payload)
    s.settimeout(wait); buf = b''
    try:
        while True:
            x = s.recv(4096)
            if not x: break          # server closed: this is the case that used
            buf += x                 # to be ALL a client ever saw
    except socket.timeout:
        buf += b'<still-open>'
    s.close()
    return buf.decode('latin1')

out = {}
out['badtype']  = probe(b'*2\r\n$3\r\nGET\r\n+oops\r\n')
out['badcount'] = probe(b'*abc\r\n')
out['overarity'] = probe(enc(['DEL'] + ['d:%d' % i for i in range(2000)]))
# One under the ceiling still works, so the refusal is a ceiling and not a
# wholesale rejection of long commands.
out['atlimit']  = probe(enc(['DEL'] + ['d:%d' % i for i in range(1000)]))
# The SAME ceiling, asked the other way the protocol allows.  An inline command
# -- words on one line, which RESP accepts alongside arrays -- was parsed with a
# loop that stopped AT the limit and then returned ok, so the command ran short
# and nothing said so.  DEL is the shape with teeth: a truncated key list is
# still a valid DEL.
#
# The keys have to BE there, or EXISTS below answers 0 whatever happened and the
# assertion measures nothing.  In chunks, because 1200 pairs is 2401 arguments
# and would hit the very ceiling this is about.
for base in range(0, 1200, 400):
    pairs = []
    for i in range(base, base + 400):
        pairs += ['i:%d' % i, 'v']
    probe(enc(['MSET'] + pairs), 1.0)
out['inline_pre']  = probe(enc(['EXISTS', 'i:1199']))
out['inline_over'] = probe(enc(['PING'])
                           + (b'DEL ' + b' '.join(b'i:%d' % i for i in range(1200))
                              + b'\r\n'))
# The keys it was asked to delete, counted afterwards on a connection that knows
# nothing about any of it.  Before the fix: reply :1023, an integer and not an
# error, and 177 of them still here.
# i:0 and NOT i:1199.  The truncation kept the FIRST 1023 keys and deleted
# them, so a key past that point survives either way and would pass this on a
# broken tree.  The first key is the one the two outcomes disagree about.
out['inline_left'] = probe(enc(['EXISTS', 'i:0']))
# One under the ceiling on the same path, so this too is a ceiling and not a
# dislike of inline commands.
out['inline_at']   = probe(enc(['PING'])
                           + (b'DEL ' + b' '.join(b'j:%d' % i for i in range(1000))
                              + b'\r\n'))
# And a good conversation on a fresh connection is untouched by any of it.
out['healthy']  = probe(enc(['SET', 'pe', '1']) + enc(['GET', 'pe']))
print(json.dumps(out))
PYEOF
R=$(python3 "$PY" run "$P" 2>/dev/null)
val() { python3 -c "import json,sys;print(json.load(sys.stdin).get('$1',''))" <<<"$R"; }

echo "--- 1. a malformed command is answered, not just cut off ---"
for t in badtype badcount; do
    V=$(val $t)
    case "$V" in
        '') bad "$t" "the connection closed with no reply at all" \
                "this is the defect: the error was written and dropped by flush_responses" ;;
        -ERR*) ok "$t is answered with an error" ;;
        *) bad "$t" "unexpected reply" "got: ${V:0:80}" ;;
    esac
done
# Redis closes after a protocol error and so do we; the point is that the
# answer goes out FIRST.
case "$(val badtype)" in *'<still-open>'*) bad "close" "the connection stayed open after a protocol error" ;;
    *) ok "and the connection is closed afterwards, as Redis does" ;; esac

echo "--- 2. the argument ceiling names itself ---"
V=$(val overarity)
case "$V" in
    '') bad "overarity" "2000 arguments closed the connection silently" ;;
    *"too many arguments"*) ok "too many arguments is said in those words" ;;
    -ERR*) bad "overarity" "refused, but as an unnamed protocol error" "got: ${V:0:80}" ;;
    *) bad "overarity" "unexpected reply" "got: ${V:0:80}" ;;
esac
case "$V" in *1024*) ok "and the limit itself is in the message" ;;
    *) bad "overarity" "the message does not say what the limit is" "got: ${V:0:80}" ;; esac

echo "--- 3. and it is a ceiling, not a dislike of long commands ---"
case "$(val atlimit)" in *':0'*) ok "1000 arguments are accepted and answered" ;;
    *) bad "atlimit" "a command under the ceiling was refused" "got: $(val atlimit | head -c 80)" ;; esac
case "$(val healthy)" in *'+OK'*'$1'*'1'*) ok "an ordinary conversation is unaffected" ;;
    *) bad "healthy" "SET/GET did not work" "got: $(val healthy | head -c 80)" ;; esac

echo "--- 4. and the same ceiling the other way the protocol allows ---"
# RESP takes words on a line as well as arrays, and that path had its own loop:
# it stopped AT the limit and returned ok, so the command ran short.  Measured
# before the fix, an inline DEL of 1200 keys on a RESP connection answered
# :1023 -- an integer, not an error -- and DBSIZE read 177.  A hundred and
# seventy-seven keys the caller had asked to delete, still there, under a reply
# that looked like success.  The array form of the same DEL is refused.
# The fixture first: without the keys in the store, EXISTS answers 0 whether the
# command was refused or ran, and the assertion below is about nothing.
case "$(val inline_pre)" in *':1'*) ok "the 1200 keys are in the store to begin with" ;;
    *) bad "inline_pre" "the fixture never wrote them" \
           "EXISTS i:1199 said '$(val inline_pre | head -c 40)'" ;; esac

V=$(val inline_over)
case "$V" in
    *"too many arguments"*) ok "an inline command past the ceiling is refused too" ;;
    *':1023'*) bad "inline_over" "it ran short and answered an integer" \
                   "got: ${V:0:80} -- the array form of this is refused" ;;
    '') bad "inline_over" "the connection closed with no reply" ;;
    *) bad "inline_over" "unexpected reply" "got: ${V:0:80}" ;;
esac
case "$(val inline_left)" in *':1'*) ok "and not one of its keys was deleted" ;;
    *) bad "inline_left" "a refused command deleted part of what it named" \
           "EXISTS i:0 said '$(val inline_left | head -c 40)'" ;; esac
case "$(val inline_at)" in *':0'*) ok "while 1000 inline arguments still work" ;;
    *) bad "inline_at" "an inline command under the ceiling was refused" \
           "got: $(val inline_at | head -c 80)" ;; esac

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
