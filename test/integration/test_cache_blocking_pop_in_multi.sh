#!/usr/bin/env bash
# Integration test: a blocking pop inside MULTI/EXEC answers instead of parking.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# EXEC counts its reply array before it produces the replies:
#
#     for each queued command: run it, take what it wrote into rb
#     encode_array_header_into(rb, queued.size())
#     rb.append(body)
#
# BLPOP on an empty list writes nothing at all -- it calls block_pop() and
# answers on a later turn, through a different buffer (write_queue, not
# response_buf).  So a transaction of two came back as `*2` followed by one
# element, and the client read the next reply on that connection as the missing
# second element.  Redis runs a blocking pop inside MULTI as its non-blocking
# twin and answers a null array.
#
# The waiter it parks is worse than the count.  m_wait_fd is keyed by
# descriptor and drop_blocked() looks up exactly one entry, under a comment
# stating the invariant: "A blocked connection stops reading, so it holds at
# most one waiter and the descriptor index is enough to find it."  The EXEC
# replay loop calls the dispatcher directly and never consults conn->blocked,
# so two BLPOPs in one transaction park two waiters on one fd.  The second
# overwrites the index; the first is orphaned in m_blocked and m_wait_key with
# a zero deadline, which sweep_blocked() skips for ever.  A later LPUSH on that
# key wakes the ghost, pops the element, and delivers it to whatever now holds
# that descriptor number.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   the array is complete     the count being made before the replies exist
#   the connection survives   the same thing seen by the client: it reads the
#                             next reply as this transaction's missing element
#   two pops both answer      the shape that parks two waiters on one
#                             descriptor, and that connection still usable
#
# What is NOT asserted here is the orphaned waiter's own fate.  The first of
# the two survives in m_blocked with a zero deadline, which sweep_blocked()
# skips for ever, and a later push on its key wakes it and delivers the element
# to whatever holds that descriptor number by then.  Reaching that needs the
# kernel to reissue the fd, which is routine but not something this file can
# arrange, and an assertion that is green whenever it does not happen would be
# measuring the allocator.  It is guarded at block_pop() instead.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate blpopmulti

P=$((SL_PORT_BASE+1698))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() { "$BIN" stop bp >/dev/null 2>&1 || true; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a blocking pop inside MULTI answers rather than parking ==="

daemon_start "$BIN"
"$BIN" create cache bp -p "$P" --resp -s >/dev/null 2>&1
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

OUT=$(timeout 90 python3 - "$P" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])

def conn():
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.settimeout(6)
    return s

def cmd(s, *parts):
    out = b"*%d\r\n" % len(parts)
    for p in parts:
        b = p.encode() if isinstance(p, str) else p
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    s.sendall(out)

def read_reply(s, buf):
    """One complete RESP reply, returning (text, leftover)."""
    while True:
        if buf[:1] in (b"+", b"-", b":"):
            i = buf.find(b"\r\n")
            if i >= 0:
                return buf[:i].decode("latin1"), buf[i+2:]
        elif buf[:1] == b"$":
            i = buf.find(b"\r\n")
            if i >= 0:
                n = int(buf[1:i])
                if n < 0:
                    return "$-1", buf[i+2:]
                if len(buf) >= i + 2 + n + 2:
                    return buf[i+2:i+2+n].decode("latin1"), buf[i+2+n+2:]
        elif buf[:1] == b"*":
            i = buf.find(b"\r\n")
            if i >= 0:
                n = int(buf[1:i])
                if n < 0:
                    return "*-1", buf[i+2:]
                rest = buf[i+2:]
                items = []
                for _ in range(n):
                    try:
                        item, rest = read_reply_buf(rest)
                    except IndexError:
                        break
                    items.append(item)
                else:
                    return "[" + ", ".join(items) + "]", rest
        d = s.recv(65536)
        if not d:
            raise EOFError("closed")
        buf += d

def read_reply_buf(buf):
    """A reply already fully in the buffer, or IndexError."""
    if buf[:1] in (b"+", b"-", b":"):
        i = buf.find(b"\r\n")
        if i < 0: raise IndexError
        return buf[:i].decode("latin1"), buf[i+2:]
    if buf[:1] == b"$":
        i = buf.find(b"\r\n")
        if i < 0: raise IndexError
        n = int(buf[1:i])
        if n < 0: return "$-1", buf[i+2:]
        if len(buf) < i + 2 + n + 2: raise IndexError
        return buf[i+2:i+2+n].decode("latin1"), buf[i+2+n+2:]
    if buf[:1] == b"*":
        i = buf.find(b"\r\n")
        if i < 0: raise IndexError
        n = int(buf[1:i])
        if n < 0: return "*-1", buf[i+2:]
        rest = buf[i+2:]
        items = []
        for _ in range(n):
            item, rest = read_reply_buf(rest)
            items.append(item)
        return "[" + ", ".join(items) + "]", rest
    raise IndexError

# ── a transaction holding one blocking pop on an empty list ────────────────
try:
    s = conn()
    cmd(s, "MULTI");              r, b = read_reply(s, b"");  
    cmd(s, "BLPOP", "ml", "0");   r, b = read_reply(s, b)
    cmd(s, "PING");               r, b = read_reply(s, b)
    cmd(s, "EXEC")
    body, b = read_reply(s, b)
    print("exec=%s" % body)
    # The connection must still be usable: with an element missing from the
    # array, this PING is read as that element instead.
    cmd(s, "PING")
    r, b = read_reply(s, b)
    print("after_exec=%s" % r)
    s.close()
except Exception as e:
    print("exec=<%s: %s>" % (type(e).__name__, e))
    print("after_exec=<not reached>")

# ── two blocking pops in one transaction ───────────────────────────────────
# This is the shape that parks two waiters on one descriptor, which is what
# m_wait_fd cannot hold.  The observable is the same from outside: both must
# answer, and the connection must still be usable afterwards -- a parked waiter
# sets conn->blocked, and the parser stops reading a blocked connection.
try:
    s2 = conn()
    cmd(s2, "MULTI");            r, b = read_reply(s2, b"")
    cmd(s2, "BLPOP", "ga", "0"); r, b = read_reply(s2, b)
    cmd(s2, "BLPOP", "gb", "0"); r, b = read_reply(s2, b)
    cmd(s2, "EXEC")
    body, b = read_reply(s2, b)
    print("exec2=%s" % body)
    cmd(s2, "PING"); r, b = read_reply(s2, b)
    print("after_exec2=%s" % r)
    s2.close()
except Exception as e:
    print("exec2=<%s: %s>" % (type(e).__name__, e))
    print("after_exec2=<not reached>")
PYEOF
)
echo "$OUT" | sed 's/^/  /'

case "$OUT" in
    *"exec=[*-1, +PONG]"*) ok ;;
    *) bad "EXEC answers every command it counted" \
           "got: $(echo "$OUT" | grep '^exec=' || echo '<no line>')" \
           "the array header is written before the replies are produced, and a" \
           "BLPOP that parked wrote none" ;;
esac

case "$OUT" in
    *"after_exec=+PONG"*) ok ;;
    *) bad "the connection is still usable after that transaction" \
           "got: $(echo "$OUT" | grep '^after_exec=' || echo '<no line>')" \
           "a client short one array element reads the next reply as that" \
           "element, and everything after it is off by one" ;;
esac

case "$OUT" in
    *"exec2=[\$-1, \$-1]"*|*"exec2=[*-1, *-1]"*) ok ;;
    *) bad "two blocking pops in one transaction both answer" \
           "got: $(echo "$OUT" | grep '^exec2=' || echo '<no line>')" \
           "this is the shape that parks two waiters on one descriptor, which" \
           "m_wait_fd holds one of" ;;
esac

case "$OUT" in
    *"after_exec2=+PONG"*) ok ;;
    *) bad "and that connection is still usable" \
           "got: $(echo "$OUT" | grep '^after_exec2=' || echo '<no line>')" \
           "a parked waiter sets conn->blocked, and the parser stops reading a" \
           "blocked connection -- so the client is deaf as well as short an" \
           "array element" ;;
esac

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
