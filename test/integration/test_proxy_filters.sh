#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# The filter chain runs before a backend is chosen, which a status code cannot
# test, so the oracle is the backend's own accept and byte counters -- both,
# because a pooled socket would carry a rejected request without moving the
# accept count -- measured over forty rejections rather than one, since
# MAX_POOL_PER_BACKEND is 32 and a single-request oracle is a proof about an
# empty pool, with an allowed request in phase 2 as the vacuity guard.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

# Own daemon, socket and state directory: against the shared one this test does
# not discriminate — auto-restart hides a crash, and a leftover runtime from an
# earlier run answers on the port before this test ever creates its own.
TMPDIR_T=$(mktemp -d /tmp/socketley-filters-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

BE_PORT=$((SL_PORT_BASE+470))
PX_PORT=$((SL_PORT_BASE+471))
PX_NAME=filter_px
RAW="$TMPDIR_T/backend.raw"
ACCEPTS="$TMPDIR_T/backend.accepts"
LUA="$TMPDIR_T/filters.lua"
OUT="$TMPDIR_T/client.out"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Killed by socket as well as by pid and matched on exact process name,
    # because a CLI command against an absent daemon starts a detached one
    # $DPID would never reach, and a `pgrep -f` pattern also matches the shell
    # doing the matching.
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

echo "=== Integration: a filter answers before a backend is chosen ==="

# The backend's accept log and raw byte capture are the whole oracle, and it
# answers with Content-Length and keep-alive so the proxy reaches its pooling
# path -- the case the accept counter alone cannot see.
python3 - "$BE_PORT" "$RAW" "$ACCEPTS" >"$TMPDIR_T/backend.log" 2>&1 <<'PYEOF' &
import socket, sys, threading

port = int(sys.argv[1])
raw_path = sys.argv[2]
acc_path = sys.argv[3]
lock = threading.Lock()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)


def record(path, chunk):
    with lock:
        with open(path, "ab") as f:
            f.write(chunk)
            f.flush()


def handle(c):
    c.settimeout(15)
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(4096)
                if not chunk:
                    return
                record(raw_path, chunk)
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            req_line = head.split(b"\r\n", 1)[0].split(b" ")
            path = req_line[1] if len(req_line) > 1 else b"/"
            body = path.lstrip(b"/")
            clen = 0
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        clen = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        clen = 0
            while len(buf) < clen:
                chunk = c.recv(4096)
                if not chunk:
                    return
                record(raw_path, chunk)
                buf += chunk
            buf = buf[clen:]
            c.sendall(b"HTTP/1.1 200 OK\r\n"
                      b"Content-Type: text/plain\r\n"
                      b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                      b"Connection: keep-alive\r\n"
                      b"\r\n" + body)
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    # Written before the connection is handled at all, so an accept this proxy
    # made and then said nothing on is still counted.  A connect that is opened
    # and abandoned is exactly the cost a filter exists to avoid.
    record(acc_path, b"A\n")
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
BEPID=$!

# Three filters, each making a different statement falsifiable: one carries on
# and rewrites a header, one answers /denied, and one would only be reached if
# the second's answer did not end the chain while also answering a path the
# second ignores.
cat > "$LUA" <<'LUAEOF'
filters = {
    function(req)
        if req.headers["x-mark-me"] then
            return {
                set_headers = {
                    ["x-filter-stamp"] = "chain-one",
                    -- Refused: framing is the proxy's, not a filter's.  A
                    -- Content-Length a filter can set is request smuggling
                    -- introduced by the feature meant to prevent it.
                    ["content-length"] = "999",
                    -- Refused for the same reason: the proxy rewrites Host to
                    -- the endpoint it actually selected.
                    ["host"] = "evil.example",
                },
                -- Taking a header off the request, which a filter could not do
                -- at all before: it could add one and overwrite one, so a
                -- header the backend must never see could only be blanked.
                remove_headers = {
                    "X-Internal-Trust",   -- a header a caller forged
                    "Cookie",             -- no business past the edge
                    -- Refused, both of them, and for the same reason the
                    -- set_headers above are: a filter that can delete
                    -- Content-Length makes this proxy and its backend disagree
                    -- about where the request ends, and one that can delete
                    -- Host decides where the request is addressed.
                    "content-length",
                    "host",
                },
            }
        end
    end,

    function(req)
        if string.find(req.path, "/denied", 1, true) then
            return {
                status = 403,
                body = "denied by filter\n",
                headers = {
                    ["x-filter"] = "two",
                    -- Refused: the proxy writes its own framing.
                    ["content-length"] = "4096",
                },
            }
        end
    end,

    function(req)
        if string.find(req.path, "/denied", 1, true) then
            return { status = 200, body = "third filter answered\n" }
        end
        if string.find(req.path, "/throttled", 1, true) then
            return { status = 429, body = "slow down\n",
                     headers = { ["retry-after"] = "7" } }
        end
    end,
}
LUAEOF

# Wait on the daemon's IPC socket directly and never by polling with a CLI
# command, which auto-starts a second orphaned daemon that survives cleanup.
cat > "$TMPDIR_T/waitsock.py" <<'PYEOF'
import socket, sys, time

path = sys.argv[1]
end = time.time() + float(sys.argv[2])
while time.time() < end:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(0.4)
        s.connect(path)
        s.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.02)
    finally:
        try:
            s.close()
        except OSError:
            pass
sys.exit(1)
PYEOF

SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
python3 "$TMPDIR_T/waitsock.py" "$SOCKETLEY_SOCKET" 8 >/dev/null 2>&1 || true

# The daemon that answers is the one this test launched, since a zombie $DPID
# has an empty /proc/<pid>/fd that `kill -0` cannot tell from a live process.
TOTAL=$((TOTAL+1))
# `|| true` because under pipefail the failing `ls` in exactly the case this
# check exists for would kill the script with no output at all.
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l || true)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        FAIL=$((FAIL+1))
        echo "  FAIL [setup]: pid $DPID is not a live process — the daemon that answers"
        echo "        is not the one this test launched, and this run measures the wrong process"
        ;;
    *) PASS=$((PASS+1)) ;;
esac

TOTAL=$((TOTAL+1))
if ready_tcp 127.0.0.1 "$BE_PORT" 10; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the HTTP backend never came up on $BE_PORT"
fi

# No --strategy lua, because the chain is not a routing strategy and one that
# only fired under 'lua' would be a routing feature wearing a different name.
create_ok "proxy with the filter chain created" "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$LUA" -s
ready_http 127.0.0.1 "$PX_PORT" "/$PX_NAME/ready" 20 || true

TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the proxy runtime is not up — everything below is meaningless"
    echo "        daemon log:"
    tail -5 "$TMPDIR_T/daemon.log" 2>/dev/null | sed 's/^/        /' || true
fi

python3 - "$PX_PORT" "$PX_NAME" "$RAW" "$ACCEPTS" >"$OUT" 2>&1 <<'PYEOF' || true
import os, socket, sys

port = int(sys.argv[1])
name = sys.argv[2]
raw_path = sys.argv[3]
acc_path = sys.argv[4]


def counters():
    """(accepts, bytes) as the backend itself has recorded them."""
    try:
        with open(acc_path, "rb") as f:
            acc = f.read().count(b"\n")
    except OSError:
        acc = 0
    try:
        nbytes = os.path.getsize(raw_path)
    except OSError:
        nbytes = 0
    return acc, nbytes


def read_response(s):
    """(status, headers, body).  Every way of not getting an answer has its own
    status, so a response that could not be read can never be mistaken for an
    empty one that happened to match."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return ("TIMEOUT-before-headers", {}, "")
        except OSError as e:
            return ("RESET-before-headers:%s" % type(e).__name__, {}, "")
        if not chunk:
            return ("EOF-before-headers", {}, "")
        buf += chunk
    head, body = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1", "replace")
    hdrs = {}
    clen = None
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        k = k.strip().lower().decode("latin1", "replace")
        v = v.strip().decode("latin1", "replace")
        # A repeated name is kept as a list so "the proxy emitted two
        # Content-Lengths" is visible rather than silently collapsed.
        if k in hdrs:
            hdrs[k] = hdrs[k] + "|" + v
        else:
            hdrs[k] = v
        if k == "content-length":
            try:
                clen = int(v)
            except ValueError:
                return ("BAD-CONTENT-LENGTH", hdrs, "")
    if clen is None:
        return ("NO-CONTENT-LENGTH:%s" % status, hdrs, "")
    while len(body) < clen:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return ("TIMEOUT-mid-body", hdrs, "")
        except OSError as e:
            return ("RESET-mid-body:%s" % type(e).__name__, hdrs, "")
        if not chunk:
            return ("EOF-mid-body", hdrs, "")
        body += chunk
    return (status, hdrs, body[:clen].decode("latin1", "replace"))


def request(path, extra="", method="GET", body=""):
    clen = ("Content-Length: %d\r\n" % len(body)) if body else ""
    req = ("%s /%s%s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s%s"
           "Connection: keep-alive\r\n\r\n%s"
           % (method, name, path, port, extra, clen, body))
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=20)
    except OSError as e:
        return ("CONNECT-FAILED:%s" % type(e).__name__, {}, "")
    s.settimeout(20)
    try:
        s.sendall(req.encode())
        r = read_response(s)
    except OSError as e:
        r = ("SEND-FAILED:%s" % type(e).__name__, {}, "")
    try:
        s.close()
    except OSError:
        pass
    return r


# ── phase 0: a request that is allowed through ─────────────────────────────
#
# Proves the proxy serves at all.  Everything after this is a difference, so the
# starting state is deliberately not assumed to be zero: the readiness probe has
# already been through, and it left a socket in the pool.
st, _, body = request("/warm")
print("P0 %s %s" % (st, body))

# ── phase 1: THE assertion — rejections cost the backend nothing ───────────
#
# Forty of them, not one.  MAX_POOL_PER_BACKEND is 32, so no pool this proxy
# keeps can supply forty backend sockets; if the chain ran below the connect,
# the accepts would have to happen and be counted.  One request would not show
# it — the pooled socket from the readiness probe absorbs the first rejection
# without a new accept, which is exactly how a single-request oracle passes a
# build that connects before it filters.
#
# A self-answered request that leaks its client descriptor, or that hands a
# backend socket back to the pool it never took one from, also shows up here
# rather than as a wrong status code: the run stops being served.
before_acc, before_bytes = counters()
first = None
bad = 0
for _ in range(40):
    st, hdrs, body = request("/denied")
    if first is None:
        first = (st, hdrs, body)
    if not st.startswith("HTTP/1.1 403"):
        bad += 1
after_acc, after_bytes = counters()
print("P1 ACCEPTS %d %d" % (before_acc, after_acc))
print("P1 BYTES %d %d" % (before_bytes, after_bytes))
print("P1 BADSTATUS %d" % bad)

st, hdrs, body = first
print("P1 STATUS %s" % st)
print("P1 XFILTER %s" % hdrs.get("x-filter", "<absent>"))
print("P1 CLEN %s" % hdrs.get("content-length", "<absent>"))
print("P1 BODY %s" % body.strip())

# ── phase 2: allowed, rewritten, and the counters move ─────────────────────
#
# This is what stops phase 1 passing for the wrong reason.  If an allowed
# request cannot move these counters either, the oracle above measures nothing.
b2_acc, b2_bytes = counters()
st, hdrs, body = request("/allowed", extra="X-Mark-Me: yes\r\n")
print("P2 %s %s" % (st, body))
a2_acc, a2_bytes = counters()
print("P2 BYTES %d %d" % (b2_bytes, a2_bytes))

# ── phase 3: the chain does not stop at its first entry ────────────────────
#
# Filter 2 says nothing about /throttled; filter 3 answers it.
st, hdrs, body = request("/throttled")
print("P3 STATUS %s" % st)
print("P3 RETRYAFTER %s" % hdrs.get("retry-after", "<absent>"))
print("P3 BODY %s" % body.strip())

# ── phase 4: a filter takes a header off the request ───────────────────────
#
# Two requests, because "the header is not in what the backend read" is not by
# itself evidence of anything — a header that was never sent is also not there.
# The first sends headers the filter removes, the second sends the same name
# with a different value and no X-Mark-Me, so the filter says nothing and it
# must arrive.  The two values are distinguishable in the capture, so one file
# answers both questions.
#
# The POST carries a body: the filter also asks for Content-Length to be
# removed, and a request with no body would not show whether that was refused.
st, _, body = request("/removal", method="POST", body="hello",
                      extra="X-Mark-Me: yes\r\n"
                            "X-Internal-Trust: removed-me\r\n"
                            "Cookie: session=secret\r\n"
                            "X-Keep-Me: yes\r\n")
print("P4 REMOVED %s %s" % (st, body))

st, _, body = request("/kept", extra="X-Internal-Trust: kept-me\r\n")
print("P4 KEPT %s %s" % (st, body))

# ── phase 5: still serving ─────────────────────────────────────────────────
st, _, body = request("/after-storm")
print("P5 AFTER %s %s" % (st, body))

print("DONE")
PYEOF

# The harness has to have reached its last line, or a check phrased as "compare
# what we read" would have nothing to compare and pass.
TOTAL=$((TOTAL+1))
if grep -qx 'DONE' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: the client produced no DONE line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -10 | sed 's/^/        /' || true
fi

check() {
    # check <label> <pattern> [hint...]
    TOTAL=$((TOTAL+1))
    local label="$1"; shift
    local pat="$1"; shift
    if grep -qE "$pat" "$OUT" 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]:"
        for line in "$@"; do echo "        $line"; done
    fi
}

unchanged() {
    # unchanged <label> <prefix> — a "before after" pair on one line, equal
    TOTAL=$((TOTAL+1))
    local label="$1" prefix="$2"
    local line before after
    line=$(grep -m1 "^$prefix " "$OUT" 2>/dev/null || true)
    before=$(printf '%s' "$line" | awk '{print $(NF-1)}')
    after=$(printf '%s' "$line" | awk '{print $NF}')
    if [ -n "$before" ] && [ "$before" = "$after" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: $prefix went from '${before:-?}' to '${after:-?}'"
    fi
}

grew() {
    TOTAL=$((TOTAL+1))
    local label="$1" prefix="$2"
    local line before after
    line=$(grep -m1 "^$prefix " "$OUT" 2>/dev/null || true)
    before=$(printf '%s' "$line" | awk '{print $(NF-1)}')
    after=$(printf '%s' "$line" | awk '{print $NF}')
    if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ] 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: $prefix did not move ('${before:-?}' → '${after:-?}')"
    fi
}

# The proxy works at all.  Everything below is a difference against this.
check "an unfiltered request is served" \
    '^P0 HTTP/1\.1 200 .* warm$' \
    "the proxy did not serve a plain request, so no assertion below discriminates:" \
    "$(grep -m1 '^P0 ' "$OUT" 2>/dev/null || echo 'no result')"

# ── THE assertion ──────────────────────────────────────────────────────────
unchanged "forty rejections open no backend connection" "P1 ACCEPTS"
unchanged "forty rejections send the backend no bytes" "P1 BYTES"

check "every one of forty rejections is answered by the filter" \
    '^P1 BADSTATUS 0$' \
    "$(grep -m1 '^P1 BADSTATUS' "$OUT" 2>/dev/null || echo 'no result')"

check "a filter's answer reaches the client" \
    '^P1 STATUS HTTP/1\.1 403 ' \
    "the filter's 403 did not come back: $(grep -m1 '^P1 STATUS' "$OUT" 2>/dev/null || echo 'no result')"

check "a filter's response headers are emitted" \
    '^P1 XFILTER two$' \
    "the answer did not carry the header the filter set"

check "a filter may not set the response framing" \
    '^P1 CLEN 17$' \
    "Content-Length is the proxy's to write.  A filter that can set it can" \
    "disagree with the body actually sent, and this proxy pools sockets:" \
    "$(grep -m1 '^P1 CLEN' "$OUT" 2>/dev/null || echo 'no result')"

check "the filter's body is the one sent" \
    '^P1 BODY denied by filter$' \
    "$(grep -m1 '^P1 BODY' "$OUT" 2>/dev/null || echo 'no result')"

# The vacuity guard: the counters above CAN move.
check "an allowed request is served" \
    '^P2 HTTP/1\.1 200 .* allowed$' \
    "$(grep -m1 '^P2 ' "$OUT" 2>/dev/null || echo 'no result')"
grew "an allowed request reaches the backend" "P2 BYTES"

# Header rewriting, read off what the backend actually received.
TOTAL=$((TOTAL+1))
if grep -qai 'X-Filter-Stamp: chain-one' "$RAW" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a filter's set_headers reaches the backend]: the header the first"
    echo "        filter set is not in what the backend read"
fi

TOTAL=$((TOTAL+1))
if grep -qai 'evil\.example' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [a filter may not rewrite Host]: the proxy rewrites Host to the"
    echo "        endpoint it selected; a filter that can overwrite it can send a"
    echo "        request to one backend addressed to another"
else
    PASS=$((PASS+1))
fi

TOTAL=$((TOTAL+1))
# -i, because a header a filter set is emitted with a lowercased name and a
# case-sensitive grep read straight past the desync it was there to catch.
if grep -qai 'content-length: 999' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [a filter may not set the request framing]: a Content-Length a filter"
    echo "        chose reached the backend.  The proxy forwards the body the *parsed*"
    echo "        request declared, so the two now disagree about where this request"
    echo "        ends — and the socket is pooled for the next one"
else
    PASS=$((PASS+1))
fi

# Ordering: filter 2's answer ends the chain.
check "the first answer ends the chain" \
    '^P1 BODY denied by filter$' \
    "filter 3 answers /denied with 200 'third filter answered'; seeing that means" \
    "the chain kept running past an answer"

# ...and a filter that says nothing does not end it.
check "a filter that says nothing passes the request along the chain" \
    '^P3 STATUS HTTP/1\.1 429 ' \
    "filter 2 ignores /throttled and filter 3 answers it; a chain that stops at" \
    "its first entry never gets there: $(grep -m1 '^P3 STATUS' "$OUT" 2>/dev/null || echo 'no result')"

check "a later filter's headers are emitted too" \
    '^P3 RETRYAFTER 7$' \
    "$(grep -m1 '^P3 RETRYAFTER' "$OUT" 2>/dev/null || echo 'no result')"

# ── remove_headers, read off what the backend actually received ────────────
check "the request a filter stripped headers from is still served" \
    '^P4 REMOVED HTTP/1\.1 200 ' \
    "$(grep -m1 '^P4 REMOVED' "$OUT" 2>/dev/null || echo 'no result')"

# The control first, because "the header is not in the capture" is equally true
# of a header nobody ever sent.
TOTAL=$((TOTAL+1))
if grep -qai 'X-Internal-Trust: kept-me' "$RAW" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a header no filter removes reaches the backend]: the control header"
    echo "        is not in the capture, so 'the removed one is absent' below proves"
    echo "        nothing at all"
fi

TOTAL=$((TOTAL+1))
if grep -qai 'removed-me' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [a filter removes a request header]: X-Internal-Trust reached the"
    echo "        backend although a filter asked for it to be taken off.  A caller"
    echo "        that forges an internal trust header is exactly what removal is for"
else
    PASS=$((PASS+1))
fi

TOTAL=$((TOTAL+1))
if grep -qai 'session=secret' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [a filter removes Cookie]: the cookie reached the backend"
else
    PASS=$((PASS+1))
fi

TOTAL=$((TOTAL+1))
if grep -qai 'X-Keep-Me: yes' "$RAW" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [removal takes only the names it was given]: a header the filter said"
    echo "        nothing about is missing from what the backend read"
fi

# The bans on the removal side, for the same reason as set_headers: a filter
# must not be able to change how a message is framed or where it is addressed.
TOTAL=$((TOTAL+1))
if grep -qai 'content-length: 5' "$RAW" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a filter may not remove the request framing]: the Content-Length of"
    echo "        a request with a body is gone.  The proxy forwards exactly the body"
    echo "        the parsed request declared, so the backend is now reading a body it"
    echo "        was never told the length of — and the socket is pooled for the next"
    echo "        request"
fi

TOTAL=$((TOTAL+1))
if grep -qai "Host: 127.0.0.1:$BE_PORT" "$RAW" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a filter may not remove Host]: the proxy writes Host to the endpoint"
    echo "        it selected; a filter that can delete it decides where the request is"
    echo "        addressed"
fi

# A self-answered request is torn down through the paths every other answered
# request uses, so a leaked descriptor or a socket returned off a message
# boundary shows up here as a proxy that has stopped working.
check "the proxy still serves after forty rejections" \
    '^P5 AFTER HTTP/1\.1 200 .* after-storm$' \
    "$(grep -m1 '^P5 AFTER' "$OUT" 2>/dev/null || echo 'no result')"

TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [runtime alive]: the proxy did not survive the filter chain"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
