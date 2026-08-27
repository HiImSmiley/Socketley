#!/usr/bin/env bash
# Integration test: the server and the proxy agree about where a request ends.
#
# ─── THE DEFECT ─────────────────────────────────────────────────────────────
#
# A response is read by one recipient.  A request is read by two — a proxy
# decides where the message ends and the server behind it decides again, on the
# same bytes, independently.  When those two answers differ, a client can put
# ONE message on the wire and have TWO answered, and it chooses what the second
# one says.  Neither end has to be wrong for that: it is enough that one is
# lenient where the other is strict.
#
# Which is what this tree had.  proxy_instance::parse_http_request_line carried
# the RFC 9112 framing rules; server_instance carried a Content-Length lookup
# and nothing else, so every shape it did not recognise resolved the same way —
# length zero, body empty, and the bytes behind it read as the next request.
# Measured on c218738, one write per case, both runtimes on one binary:
#
#     case                          proxy   server
#     Content-Length : N            400     2 answers, /secret.html served
#     Content-Length twice          400     2 answers, /secret.html served
#     obs-fold hiding the length    400     2 answers, /secret.html served
#     bare LF in the header block   400     2 answers, /secret.html served
#     Content-Length:<TAB>4         accept  0 answers, connection dropped
#     Transfer-Encoding: chunked    forward 1 answer, then desynced
#
# The four leaks are the defect.  The tab is its mirror — a legal request the
# proxy accepts and the server hung up on, so a socketley proxy in front of a
# socketley server answered a gateway error to a correct client.
#
# ─── WHAT WAS DECIDED, AND WHY ──────────────────────────────────────────────
#
#   A  whitespace before the colon    REFUSE 400  RFC 9112 5.1, MUST reject
#   B  tab as OWS after the colon     ACCEPT      RFC 9110 5.6.3, OWS is SP/HTAB
#   C  two Content-Length fields      REFUSE 400  RFC 9112 6.3, unrecoverable
#   D  obs-fold continuation          REFUSE 400  RFC 9112 5.2, MUST 400
#   E  bare LF in the block           REFUSE 400  strict CRLF; the two ends
#                                                 must not choose separately
#   F  Transfer-Encoding              REFUSE 501  RFC 9112 6.1 -- this server
#                                                 implements no transfer coding
#
# F is the one that had a third option, and the third option is why it is here:
# reading a chunked body as a body of length zero meant the chunk data was
# parsed as the next request.  Refusing is defensible and implementing chunked
# would be; that was not.
#
# ─── WHY THE ASSERTION IS A COUNT AND NOT "DID IT ANSWER" ───────────────────
#
# This survived because every check anyone had ever put on it could not tell one
# answer from two.  A 200 arrives in both cases.  So each case sends ONE message
# with a second request tucked inside it and counts:
#
#   200=2 secret=yes   the message was framed as the client declared    (B, control)
#   200=0 400=1        the message was refused, once, with an answer    (A,C,D,E)
#   200=0 501=1        the transfer coding was refused, with an answer  (F)
#
# and each count catches a different broken build:
#
#   the control's 200=2      a harness that cannot see a second answer at all,
#                            and a build that refuses everything -- without it
#                            every "200=0" row below is unfalsifiable
#   B's 200=2                a build that hangs up on legal tab OWS (the state
#                            of the server before this change), and any shared
#                            rule that has become stricter than the RFC
#   A/C/D/E's 200=0          the smuggle: this is 2 on the old server
#   A/C/D/E's 400=1          distinguishes "refused with an answer" from
#                            "dropped the connection silently", which is what
#                            the old server did for the tab and is not the same
#                            outcome
#   secret=no                the security property itself, and the only
#                            assertion here that names what the client GOT.
#                            /secret.html is a real file -- the control proves
#                            it is servable, so its absence in A/C/D/E means the
#                            second request was never executed
#   F's 501=1                a build that reads a chunked body as empty (1 on
#                            the old server) or one that 400s a legal message
#
# ─── AND WHY THE PROXY IS IN THE SAME FILE ──────────────────────────────────
#
# The subject is not "the server is strict" but "the two agree".  A per-runtime
# test cannot state that.  Every case runs against both in the same second on
# the same binary, and the verdicts are compared to each other as well as to the
# expected value -- so a future change that moves one side alone fails here even
# if the side it moved is the one that looks right.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

TMPDIR_T=$(mktemp -d /tmp/socketley-reqframe-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""

BE_PORT=$((SL_PORT_BASE+470))
PX_PORT=$((SL_PORT_BASE+471))
SV_PORT=$((SL_PORT_BASE+472))
PX_NAME=rfpx
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Exact process name plus this run's own SOCKETLEY_SOCKET, never a
    # command-line pattern: `pgrep -f` matches the shell that merely carries the
    # string, including this one.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: HTTP request framing, server and proxy agree ==="

mkdir -p "$TMPDIR_T/www"
printf 'ROOT\n'   > "$TMPDIR_T/www/index.html"
# The smuggled request's target.  A distinct file rather than another GET of
# index.html: "was a second request ANSWERED" is a count, "was the second
# request EXECUTED" is this string turning up in the client's bytes.
printf 'SECRET\n' > "$TMPDIR_T/www/secret.html"

"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done

create_ok "backend created" "$BIN" create server rfbe -p "$BE_PORT" \
    --http "$TMPDIR_T/www" -s
create_ok "proxy created"   "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s
create_ok "server created"  "$BIN" create server rfsv -p "$SV_PORT" \
    --http "$TMPDIR_T/www" -s

ready_tcp 127.0.0.1 "$BE_PORT" 10 || true
ready_tcp 127.0.0.1 "$PX_PORT" 10 || true
ready_tcp 127.0.0.1 "$SV_PORT" 10 || true

# One connection, ONE write, then read until the peer closes or the socket goes
# quiet.  stdin is never closed: `nc -q` sends FIN after writing, and a recipient
# that reads client EOF as an abort then answers nothing at all -- which reads
# as a passing "0 answers" for every strict row and proves nothing.
cat > "$TMPDIR_T/frame.py" <<'PYEOF'
import socket, sys

def second(path):
    return ("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode()

def build(case, path, spath):
    s2   = second(spath)
    n    = len(s2)                 # a body length that would swallow it exactly
    head = "POST %s HTTP/1.1\r\nHost: x\r\n" % path
    if case == "control":
        # A four-byte body the recipient is meant to consume, then a real
        # pipelined request.  Two answers here is correct HTTP.
        return (head + "Content-Length: 4\r\n\r\nabcd").encode() + s2
    if case == "A":     # space before the colon
        return (head + "Content-Length : %d\r\n\r\n" % n).encode() + s2
    if case == "B":     # tab as OWS after the colon -- legal
        return (head + "Content-Length:\t4\r\n\r\nabcd").encode() + s2
    if case == "C":     # two Content-Length fields, differing
        return (head + "Content-Length: %d\r\nContent-Length: 0\r\n\r\n" % n).encode() + s2
    if case == "D":     # obs-fold continuation hiding the Content-Length
        return (head + "X-Pad: a\r\n\tContent-Length: %d\r\n\r\n" % n).encode() + s2
    if case == "E":     # bare LF, which merges Host and Content-Length into one line
        return ("POST %s HTTP/1.1\r\nHost: x\nContent-Length: %d\r\n\r\n"
                % (path, n)).encode() + s2
    if case == "bare":  # a request with NO header fields at all -- legal HTTP/1.0
        # Not a malformation: it is here because the offset arithmetic that
        # finds the header block subtracts the request line's CRLF from the
        # block terminator, and for this request those are the SAME position.
        # An unguarded subtraction wraps, the clamped view is the terminator
        # itself, and the scan refuses a request nothing is wrong with.  One
        # answer, because there is no second request to smuggle.
        return ("GET %s HTTP/1.0\r\n\r\n" % path).encode()
    if case == "F":     # chunked, whose chunk data is a whole request
        return (head + "Transfer-Encoding: chunked\r\n\r\n").encode() + \
               ("%x\r\n" % n).encode() + s2 + b"\r\n0\r\n\r\n"
    raise SystemExit("unknown case")

port, case, path, spath = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(build(case, path, spath))
except OSError as e:
    print("ERR:%s" % e); raise SystemExit(0)
buf = b""; s.settimeout(2.5)
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
except socket.timeout:
    pass
s.close()
print("200=%d 400=%d 501=%d secret=%s" % (
    buf.count(b"HTTP/1.1 200"), buf.count(b"HTTP/1.1 400"),
    buf.count(b"HTTP/1.1 501"), "yes" if b"SECRET" in buf else "no"))
PYEOF

check() {   # check LABEL CASE PORT PATH SPATH EXPECTED
    local label="$1" case="$2" port="$3" path="$4" spath="$5" want="$6" got
    got=$(python3 "$TMPDIR_T/frame.py" "$port" "$case" "$path" "$spath" 2>/dev/null || echo ERR)
    TOTAL=$((TOTAL+1))
    if [ "$got" = "$want" ]; then
        PASS=$((PASS+1))
        printf '  PASS [%-6s] %-7s -> %s\n' "$label" "$case" "$got"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL [%-6s] %-7s -> %s   (expected %s)\n' "$label" "$case" "$got" "$want"
    fi
    LAST_GOT="$got"
}

# case EXPECTED -- run against both recipients and assert they also match EACH
# OTHER.  The agreement assertion is the subject of the file; the expected
# string is what stops both of them agreeing on the wrong answer.
both() {
    local case="$1" want="$2" sv px
    check server "$case" "$SV_PORT" /index.html /secret.html "$want"; sv="$LAST_GOT"
    check proxy  "$case" "$PX_PORT" "/$PX_NAME/index.html" "/$PX_NAME/secret.html" "$want"; px="$LAST_GOT"
    TOTAL=$((TOTAL+1))
    if [ "$sv" = "$px" ]; then
        PASS=$((PASS+1))
        printf '  PASS [agree ] %-7s -> both %s\n' "$case" "$sv"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL [agree ] %-7s -> server %s / proxy %s\n' "$case" "$sv" "$px"
    fi
}

echo "--- well-formed: the message ends where the client said it does ---"
both control "200=2 400=0 501=0 secret=yes"
both B       "200=2 400=0 501=0 secret=yes"
# The boundary case, and the reason it is in a framing test: nothing in
# test/integration sends a request with no header fields, so the offset
# underflow this catches went green through the whole suite.
both bare    "200=1 400=0 501=0 secret=no"

echo "--- malformed framing: refused, once, with an answer ---"
both A       "200=0 400=1 501=0 secret=no"
both C       "200=0 400=1 501=0 secret=no"
both D       "200=0 400=1 501=0 secret=no"
both E       "200=0 400=1 501=0 secret=no"

echo "--- a transfer coding neither end will guess at ---"
# The proxy forwards chunked verbatim and always has -- it never de-chunks -- so
# the 501 the proxy row sees was produced by the backend server and relayed.
# That is the point of the row: the refusal is visible to the client through a
# hop, where before it was a desync nobody saw.
both F       "200=0 400=0 501=1 secret=no"

echo
echo "Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
