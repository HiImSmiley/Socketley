#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# A Lua script declares its routes, the daemon publishes them, and the proxy
# refuses at the edge what the handler would have refused anyway -- so the
# method list lives in one place rather than two that drift.
# ─── THE ORACLE ─────────────────────────────────────────────────────────────
# The oracle is the backend's own total_connections and bytes_in rather than
# the status code, because a gateway that resolves, connects, forwards and then
# answers 405 is indistinguishable by status alone -- and bytes_in because
# pooling means a forwarded request may move no accept counter at all.
# ─── THE VACUITY GUARDS ─────────────────────────────────────────────────────
# Every refusal is paired with a request that must be served and names the
# Allow header it expects, because "did not reach the backend" passes against a
# proxy that reaches none and "was refused" against one that refuses
# everything.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

# Own daemon, socket and state directory: against the shared one this test does
# not discriminate — auto-restart hides a crash, and a leftover runtime from an
# earlier run answers on the port before this test ever creates its own.
TMPDIR_T=$(mktemp -d /tmp/socketley-routes-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
. "$(dirname "$0")/lib_daemon.sh"
daemon_watch "$TMPDIR_T"   # its processes go with it if it is killed
mkdir -p "$HOME"
DPID=""

BE_PORT=$((SL_PORT_BASE+640))
PX_PORT=$((SL_PORT_BASE+641))
GA_PORT=$((SL_PORT_BASE+642))
GB_PORT=$((SL_PORT_BASE+643))
GP_PORT=$((SL_PORT_BASE+644))
MX_PORT=$((SL_PORT_BASE+645))
BE_NAME=route_be
PX_NAME=route_px
GA_NAME=route_ga
GB_NAME=route_gb
GP_NAME=route_gp
MX_NAME=route_mx
GROUP=route_grp
BE_LUA="$TMPDIR_T/backend.lua"
GB_LUA="$TMPDIR_T/member_b.lua"
BAD_LUA="$TMPDIR_T/bad.lua"
OUT="$TMPDIR_T/client.out"
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
    # Killed by socket and by exact process name, never by a command-line
    # pattern, because a CLI command against a daemon that is not up starts a
    # detached one and `-f` matches any shell whose own command line carries
    # the string.
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

echo "=== Integration: a handler declares its routes; the proxy enforces them ==="

# Three routes, each making a different claim falsifiable -- a preflight the
# gateway must not answer, a prefix declaration with a different Allow list,
# and a handler that wants its own OPTIONS -- with on_http_request echoing
# method and path so what the backend saw is readable rather than inferred.
cat > "$BE_LUA" <<'LUAEOF'
routes = {
    { path = "/endpoint/login", methods = { "POST", "GET" } },
    { path = "/static/*",       methods = { "GET" } },
    { path = "/cors",           methods = { "OPTIONS", "POST" } },
}

function on_http_request(req)
    return {
        status = 200,
        headers = { ["Content-Type"] = "text/plain" },
        body = req.method .. " " .. req.path,
    }
end
LUAEOF

# The second group member declares PUT and nothing else, so the group's
# declaration is a union of disjoint sets that an intersecting proxy would get
# wrong.
cat > "$GB_LUA" <<'LUAEOF'
routes = {
    { path = "/endpoint/login", methods = { "PUT" } },
}

function on_http_request(req)
    return { status = 200, body = "b:" .. req.method .. " " .. req.path }
end
LUAEOF

# Wait on the daemon's IPC socket directly, never by polling with a CLI
# command, because every CLI command auto-starts a daemon and spawns a second
# orphaned one.
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

# The daemon that answers is the one this test launched, because a zombie $DPID
# has an empty /proc/<pid>/fd that `kill -0` cannot tell from a live one.
TOTAL=$((TOTAL+1))
# `|| true` because with pipefail a genuinely dead pid makes `ls` fail and
# kills the script here, so the one check that can report a dead daemon could
# never report one.
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l || true)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        FAIL=$((FAIL+1))
        echo "  FAIL [setup]: pid $DPID is not a live process — the daemon that answers"
        echo "        is not the one this test launched, and this run measures the wrong process"
        ;;
    *) PASS=$((PASS+1)) ;;
esac

# Checked rather than discarded, because a declaration the daemon will not load
# fails `create` and used to be reported forty lines later as the defect under
# test.
create_ok "backend created"       "$BIN" create server "$BE_NAME" -p "$BE_PORT" --lua "$BE_LUA" -s
create_ok "proxy created"         "$BIN" create proxy  "$PX_NAME" -p "$PX_PORT" --backend "$BE_NAME" --protocol http -s

create_ok "group member A created" "$BIN" create server "$GA_NAME" -p "$GA_PORT" --lua "$BE_LUA" -g "$GROUP" -s
create_ok "group member B created" "$BIN" create server "$GB_NAME" -p "$GB_PORT" --lua "$GB_LUA" -g "$GROUP" -s
create_ok "group gateway created"  "$BIN" create proxy  "$GP_NAME" -p "$GP_PORT" --backend "@$GROUP" --protocol http -s

# The same server by name and as a bare address, because a proxy enforcing the
# declaration it does have would be refusing methods for a backend that never
# said anything.
create_ok "mixed-backend proxy created" "$BIN" create proxy "$MX_NAME" -p "$MX_PORT" \
    --backend "$BE_NAME,127.0.0.1:$BE_PORT" --protocol http -s

ready_http 127.0.0.1 "$PX_PORT" "/$PX_NAME/ready" 20 || true
ready_http 127.0.0.1 "$GP_PORT" "/$GP_NAME/ready" 20 || true
ready_http 127.0.0.1 "$MX_PORT" "/$MX_NAME/ready" 20 || true

for n in "$BE_NAME" "$PX_NAME" "$GA_NAME" "$GB_NAME" "$GP_NAME" "$MX_NAME"; do
    TOTAL=$((TOTAL+1))
    if "$BIN" stats "$n" >/dev/null 2>&1; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [setup]: runtime $n is not up — everything below is meaningless"
        tail -5 "$TMPDIR_T/daemon.log" 2>/dev/null | sed 's/^/        /' || true
    fi
done

# Named refusals rather than merely "it failed", because "unknown flag" is a
# refusal too and would pass against a build where `routes` does not exist.
cat > "$BAD_LUA" <<'LUAEOF'
routes = { { path = "endpoint/login", methods = { "GET" } } }
LUAEOF
BAD_RC=0
BAD_OUT=$("$BIN" create server route_bad1 -p $((SL_PORT_BASE+648)) --lua "$BAD_LUA" -s 2>&1) || BAD_RC=$?
TOTAL=$((TOTAL+1))
if grep -q "must start with '/'" "$TMPDIR_T/daemon.log" 2>/dev/null && [ "$BAD_RC" = "1" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a path with no leading slash is refused, and says why]: expected the"
    echo "        daemon to print the reason and create to exit 1.  create said:"
    echo "        ${BAD_OUT:-<nothing>} (rc=$BAD_RC)"
fi

cat > "$BAD_LUA" <<'LUAEOF'
routes = { ["/endpoint/login"] = { "GET" } }
LUAEOF
# Deliberately not create_ok, because this create is expected to be refused and
# the oracle is the daemon's reason rather than an exit status any build would
# produce.
BAD2_RC=0
"$BIN" create server route_bad2 -p $((SL_PORT_BASE+649)) --lua "$BAD_LUA" -s >/dev/null 2>&1 || BAD2_RC=$?
TOTAL=$((TOTAL+1))
if grep -q "no entry at index 1" "$TMPDIR_T/daemon.log" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo '  FAIL [a keyed table is refused, and says why]: routes = { [path] = ... }'
    echo "        reads like a declaration and is silently nothing — the array part is"
    echo "        what is walked, so it must not load quietly"
    echo "        (create exited $BAD2_RC and the daemon logged no reason)"
fi

python3 - "$PX_PORT" "$PX_NAME" "$BIN" "$BE_NAME" "$GP_PORT" "$GP_NAME" \
           "$GA_NAME" "$GB_NAME" "$BE_LUA" "$MX_PORT" "$MX_NAME" \
           >"$OUT" 2>&1 <<'PYEOF' || true
import socket, subprocess, sys, time

px_port  = int(sys.argv[1])
px_name  = sys.argv[2]
binary   = sys.argv[3]
be_name  = sys.argv[4]
gp_port  = int(sys.argv[5])
gp_name  = sys.argv[6]
ga_name  = sys.argv[7]
gb_name  = sys.argv[8]
be_lua   = sys.argv[9]
mx_port  = int(sys.argv[10])
mx_name  = sys.argv[11]


def counters(*names):
    """(total_connections, bytes_in) summed over the named runtimes, as those
    runtimes have themselves recorded them.  This is the whole oracle: the
    proxy's own status code cannot say whether the backend was touched."""
    conns = 0
    nbytes = 0
    for n in names:
        try:
            out = subprocess.run([binary, "stats", n], capture_output=True,
                                 text=True, timeout=20).stdout
        except (OSError, subprocess.SubprocessError):
            return (-1, -1)
        for line in out.splitlines():
            if line.startswith("total_connections:"):
                conns += int(line.split(":", 1)[1])
            elif line.startswith("bytes_in:"):
                nbytes += int(line.split(":", 1)[1])
    return conns, nbytes


# ── Reading a counter that lives in another process ────────────────────────
#
# Every runtime here runs in its own process.  Its counters ARE read at the
# moment of the question -- each worker stores its line into a shared region
# once per turn of its event loop and `stats` sums the slots as it prints -- but
# "the moment of the question" is not the moment the request was served: the
# bytes are counted on the turn that handles them, and a read taken between the
# response reaching this script and the worker's next turn legitimately predates
# them.
#
# Measured on this machine, before the counters moved into shared memory: a
# served request became visible in `stats` between 36 ms and 251 ms afterwards,
# against 8-10 ms for a runtime inside the daemon.  Measured after: 3-7 ms,
# which is the CLI round trip.  The window is a thousand times smaller and it is
# not zero, so this oracle still has to account for it in BOTH directions -- in
# opposite ways, because the trap is opposite:
#
#   must GROW      poll until it does.  Racing the push reports "the request
#                  never reached the backend" for one that did.
#   must NOT move  wait past a full publish interval FIRST, so a byte that had
#                  been forwarded would already be visible.  Reading immediately
#                  would pass against a proxy that forwarded every one of the
#                  forty refusals, which is the single thing these assertions
#                  exist to catch.  This one is the reason the section below did
#                  not simply lose its waiting when the lag did.
#
# Neither is a sleep standing in for a tick.  The first ends on the counter
# itself; the second waits out an interval the worker's own publisher is
# specified in, and the baselines are quiesced so that a phase can never be
# credited with the previous phase's bytes in either direction.

# ─── NO COPY OF THE WORKER'S CADENCE LIVES HERE ANY MORE ───────────────────
#
# This was `PUBLISH_INTERVAL = 0.25  # proxy_worker.cpp: stats_interval` and a
# SETTLE of four of them.  A second copy of a constant that lives in C++, and it
# drifted the moment that constant stopped being a constant: the publish backed
# off to 900 ms while nothing changed, so 1.0 s stopped being four intervals and
# became one.  The after-reading then landed on a publish that still carried the
# previous phase's bytes, and `unchanged` reported 268 -> 366 -- a real
# increment the old timing had been hiding, in a test whose whole subject is
# whether an increment happened.
#
# The fix was not a bigger number then and is not one now.  There is no publish
# interval left to copy -- the counters are summed at print time -- so what a
# reader waits on is the counter itself, which is what counters_quiet() below
# does and what makes it correct whatever the worker's cadence is.
SETTLE_TIMEOUT   = 8.0       # only a bound on waiting for a fresh sample
BOUND            = 5.0       # give-up, so a counter that never moves still fails


def counters_quiet(*names):
    """A baseline that has stopped moving.

    The phase before this one may not have been published yet, and a baseline
    read too early is low -- which would credit this phase with the previous
    one's bytes, passing a `grew` that should have failed and failing an
    `unchanged` that should have passed.  Waits for two readings a publish
    interval apart to agree."""
    # Two agreeing readings, each of them FRESH -- taken after the previous one
    # was read.  The old form slept a hard-coded 1.5 publish intervals between
    # reads, which stopped meaning anything when the publish interval stopped
    # being a constant: two reads inside one interval agree trivially, because
    # they are the same sample.
    prev = counters_settled(*names)
    end = time.time() + BOUND
    while time.time() < end:
        cur = counters_settled(*names)
        if cur == prev:
            return cur
        prev = cur
    return prev


def counters_grown(baseline, *names):
    """Poll until bytes_in passes `baseline`, then return the reading.

    Returns the last reading either way -- a counter that genuinely never moves
    is returned unchanged and fails its assertion, rather than hanging here or
    being waved through."""
    end = time.time() + BOUND
    cur = counters(*names)
    while cur[1] <= baseline[1] and time.time() < end:
        time.sleep(0.05)
        cur = counters(*names)
    return cur


def counters_settled(*names):
    """Read a sample every named runtime took AFTER this call was entered.

    Every runtime now satisfies that by construction: the figures are summed out
    of shared memory at the instant `stats` prints them, so the sample IS the
    read.  _sample_instant() therefore answers `now` for every runtime and this
    returns on its first pass.

    Kept, and kept called, rather than deleted.  It is the seam where a build
    that put a pushed figure back -- a cached aggregate, a periodic refresh --
    would have to declare an age again, and a caller that had stopped asking
    would not notice.  The cost of that is one comparison per phase."""
    start = time.monotonic()
    deadline = start + SETTLE_TIMEOUT
    while time.monotonic() < deadline:
        now = time.monotonic()
        if all(_sample_instant(n, now) >= start for n in names):
            return counters(*names)
        time.sleep(0.05)
    # Out of time: return what there is rather than hang.  The assertion that
    # follows is then reading a possibly stale sample, which is the state this
    # function exists to avoid -- so it says so.
    print("P_WARN counters_settled timed out waiting for a fresh sample")
    return counters(*names)


def _sample_instant(name, now):
    """When the runtime's figures were taken, on time.monotonic()'s scale.

    `now` is passed in, read before the round trip, so the arithmetic can only
    ever place the sample earlier than it really was -- erring towards waiting
    one more turn rather than accepting a stale read.

    No runtime prints an age any more, in the daemon or in a worker, so this
    answers `now` for all of them.  The figures_age_ms branch is left in place
    deliberately: it is what a build that reintroduced a pushed figure would
    print, and this is the one reader that would act on it."""
    try:
        out = subprocess.run([binary, "stats", name], capture_output=True,
                             text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return -1.0
    for line in out.splitlines():
        if line.startswith("figures_age_ms:"):
            try:
                return now - int(line.split(":", 1)[1]) / 1000.0
            except ValueError:
                return now
    return now        # no age printed: read at print time, wherever it lives


def read_response(s, method="GET"):
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
        if k in hdrs:
            hdrs[k] = hdrs[k] + "|" + v
        else:
            hdrs[k] = v
        if k == "content-length":
            try:
                clen = int(v)
            except ValueError:
                return ("BAD-CONTENT-LENGTH", hdrs, "")
    # A 204 carries no content and RFC 9112 Section 6.2 forbids the header that
    # would say how much.  Demanding one here would report a correct answer as
    # a broken one.
    if status.startswith("HTTP/1.1 204"):
        if clen is not None:
            return ("204-WITH-CONTENT-LENGTH", hdrs, "")
        return (status, hdrs, "")
    if clen is None:
        return ("NO-CONTENT-LENGTH:%s" % status, hdrs, "")
    # RFC 9112 6.3: a response to HEAD carries the length its GET would have had
    # and no body, so waiting for one here reads a correct answer as a hang.
    if method == "HEAD":
        # Bytes present prove a body was sent; bytes absent do not prove one was
        # not, so this reports the defect it can see and never invents one.
        return ("HEAD-WITH-BODY:%s" % status if body else status, hdrs, "")
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


def request(path, method="GET", extra="", port=None, name=None, body=""):
    port = port or px_port
    name = name or px_name
    req = ("%s /%s%s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s"
           "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s"
           % (method, name, path, port, extra, len(body), body))
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=20)
    except OSError as e:
        return ("CONNECT-FAILED:%s" % type(e).__name__, {}, "")
    s.settimeout(20)
    try:
        s.sendall(req.encode())
        r = read_response(s, method)
    except OSError as e:
        r = ("SEND-FAILED:%s" % type(e).__name__, {}, "")
    try:
        s.close()
    except OSError:
        pass
    return r


# ── phase 0: a declared method is served ───────────────────────────────────
#
# Everything below is a difference against this.  If a declared method does not
# get through, every "was refused" assertion passes for the wrong reason.
st, _, body = request("/endpoint/login")
print("P0 %s %s" % (st, body))

# ── phase 1: THE assertion — a refused method costs the backend nothing ────
#
# Forty of them, not one.  MAX_POOL_PER_BACKEND is 32, so no pool this proxy
# keeps can supply forty backend sockets; a gate that ran after the connect
# would have to open them, and they would be counted.  One request would not
# show it — a pooled socket from the readiness probe absorbs the first rejection
# without a new accept.
before_c, before_b = counters_quiet(be_name)
first = None
bad = 0
for _ in range(40):
    st, hdrs, body = request("/endpoint/login", method="DELETE")
    if first is None:
        first = (st, hdrs, body)
    if not st.startswith("HTTP/1.1 405"):
        bad += 1
after_c, after_b = counters_settled(be_name)
print("P1 ACCEPTS %d %d" % (before_c, after_c))
print("P1 BYTES %d %d" % (before_b, after_b))
print("P1 BADSTATUS %d" % bad)

st, hdrs, body = first
print("P1 STATUS %s" % st)
print("P1 ALLOW %s" % hdrs.get("allow", "<absent>"))
print("P1 CLEN %s" % hdrs.get("content-length", "<absent>"))
print("P1 BODY %s" % body.strip())

# ── phase 2: the vacuity guard — the counters CAN move ─────────────────────
b2c, b2b = counters_quiet(be_name)
st, _, body = request("/endpoint/login", method="POST", body="user=x")
a2c, a2b = counters_grown((b2c, b2b), be_name)
print("P2 %s %s" % (st, body))
print("P2 BYTES %d %d" % (b2b, a2b))

# ── phase 3: HEAD is implied by GET ────────────────────────────────────────
#
# RFC 9110 Section 9.3.2.  A handler that serves GET serves HEAD whether or not
# it listed it, and a gate that refuses HEAD breaks every cache validator and
# link checker there is.  Measured on the backend, not on the status: a 200 the
# proxy invented would look the same from here.
b3c, b3b = counters_quiet(be_name)
st, _, _ = request("/endpoint/login", method="HEAD")
a3c, a3b = counters_grown((b3c, b3b), be_name)
print("P3 STATUS %s" % st)
print("P3 BYTES %d %d" % (b3b, a3b))

# ── phase 4: a plain OPTIONS is answered from the declaration ──────────────
#
# RFC 9110 Section 9.3.7 — "what may I do here" — and the declaration is
# precisely that answer, so no backend is involved.  Five of them, so a pooled
# socket cannot explain a still counter.
b4c, b4b = counters_quiet(be_name)
st4, h4, _ = request("/endpoint/login", method="OPTIONS")
for _ in range(4):
    request("/endpoint/login", method="OPTIONS")
a4c, a4b = counters_settled(be_name)
print("P4 STATUS %s" % st4)
print("P4 ALLOW %s" % h4.get("allow", "<absent>"))
print("P4 BYTES %d %d" % (b4b, a4b))

# ── phase 5: a CORS preflight is NEVER answered at the edge ────────────────
#
# The bug this whole feature is most likely to introduce.  A browser sends
# OPTIONS before any non-simple request; a route declaring only POST and GET
# would have the gate answer it — 405 for a naive gate, or a 204 with no
# Access-Control-Allow-Origin for a clever one — and the real request is then
# never sent at all.  What the operator sees is a CORS error on a request their
# code never made.  Origin policy lives with the handler, so the preflight goes
# to the handler: the backend's counters must move.
b5c, b5b = counters_quiet(be_name)
st5, _, body5 = request("/endpoint/login", method="OPTIONS",
                        extra="Origin: http://app.example\r\n"
                              "Access-Control-Request-Method: DELETE\r\n")
a5c, a5b = counters_grown((b5c, b5b), be_name)
print("P5 STATUS %s" % st5)
print("P5 BODY %s" % body5.strip())
print("P5 BYTES %d %d" % (b5b, a5b))

# ── phase 6: a handler that declares OPTIONS keeps it ──────────────────────
b6c, b6b = counters_quiet(be_name)
st6, _, body6 = request("/cors", method="OPTIONS")
a6c, a6b = counters_grown((b6c, b6b), be_name)
print("P6 STATUS %s" % st6)
print("P6 BODY %s" % body6.strip())
print("P6 BYTES %d %d" % (b6b, a6b))

# ── phase 7: a declaration is not a whitelist ──────────────────────────────
#
# Nothing declares /elsewhere.  Silence about a path is not a statement about
# it: a handler is free to answer paths it never declared, and a gate that
# turned silence into a refusal would make declaring one route the act of hiding
# every other.
b7c, b7b = counters_quiet(be_name)
st7, _, body7 = request("/elsewhere", method="DELETE")
a7c, a7b = counters_grown((b7c, b7b), be_name)
print("P7 STATUS %s" % st7)
print("P7 BODY %s" % body7.strip())
print("P7 BYTES %d %d" % (b7b, a7b))

# ── phase 8: a prefix route, and its own Allow list ────────────────────────
st8, h8, _ = request("/static/app.js", method="DELETE")
print("P8 STATUS %s" % st8)
print("P8 ALLOW %s" % h8.get("allow", "<absent>"))
b8c, b8b = counters_quiet(be_name)
st8b, _, body8b = request("/static/app.js")
a8c, a8b = counters_grown((b8c, b8b), be_name)
print("P8 GET %s %s" % (st8b, body8b.strip()))
print("P8 BYTES %d %d" % (b8b, a8b))

# ── phase 9: the query string is not part of the path ──────────────────────
#
# A gate that compared the whole request target would forward every request
# carrying one, which is most of them.
st9, h9, _ = request("/endpoint/login?next=%2Fhome", method="DELETE")
print("P9 STATUS %s" % st9)
print("P9 ALLOW %s" % h9.get("allow", "<absent>"))

# ── phase 10: the group's declaration is the union of its members' ─────────
#
# PUT is declared by the second member only.  The proxy picks a member per
# connection and cannot know which one this request will reach, so it may only
# refuse a method NO member declared — refusing PUT would refuse at the edge
# what the second member was going to serve.
b10c, b10b = counters_quiet(ga_name, gb_name)
st10, _, body10 = request("/endpoint/login", method="PUT", port=gp_port, name=gp_name)
a10c, a10b = counters_grown((b10c, b10b), ga_name, gb_name)
print("P10 PUT %s %s" % (st10, body10.strip()))
print("P10 BYTES %d %d" % (b10b, a10b))

# And the other member's method, through the same gateway.  Both directions are
# needed: a merge that keeps whichever declaration it saw first passes one of
# these two whatever the order the runtimes happen to be walked in, and fails
# the other.
st10b, _, _ = request("/endpoint/login", method="GET", port=gp_port, name=gp_name)
print("P10 GET %s" % st10b)

# A path only one member declares is dropped from the group's declaration.
# /static/* is member A's alone, so nothing may be refused there: member B never
# said what it answers, and this request could land on member B.
st10c, _, _ = request("/static/app.js", method="DELETE", port=gp_port, name=gp_name)
print("P10 PARTIAL %s" % st10c)

b11c, b11b = counters_quiet(ga_name, gb_name)
st11, h11, _ = request("/endpoint/login", method="DELETE", port=gp_port, name=gp_name)
a11c, a11b = counters_settled(ga_name, gb_name)
print("P11 STATUS %s" % st11)
print("P11 ALLOW %s" % h11.get("allow", "<absent>"))
print("P11 BYTES %d %d" % (b11b, a11b))

# ── phase 11b: one silent backend disables the gate ────────────────────────
#
# This proxy has two backends: the same server by name, which declares, and by
# address, which cannot.  An address may be any server in the world and this
# proxy has no basis on which to claim it knows what it answers — so refusing a
# method here would be refusing on behalf of a backend that never spoke.  The
# safe half of the fork is to forward, and this is the assertion that pins it.
b11bc, b11bb = counters_quiet(be_name)
st11b, _, body11b = request("/endpoint/login", method="DELETE",
                            port=mx_port, name=mx_name)
a11bc, a11bb = counters_grown((b11bc, b11bb), be_name)
print("P11B STATUS %s" % st11b)
print("P11B BODY %s" % body11b.strip())
print("P11B BYTES %d %d" % (b11bb, a11bb))

# ── phase 12: the declaration is published, not configured ─────────────────
#
# The strongest statement this test makes.  The proxy is not restarted, not
# reconfigured and not told anything: the *handler's* script changes, and what
# the gateway enforces changes with it.  A proxy holding a configured copy would
# go on refusing PATCH for ever, which is exactly the drift the design exists to
# end.
print("P12 BEFORE %s" % request("/endpoint/login", method="PATCH")[0])
with open(be_lua, "w") as f:
    f.write('routes = {\n'
            '    { path = "/endpoint/login", methods = { "POST", "GET", "PATCH" } },\n'
            '}\n'
            'function on_http_request(req)\n'
            '    return { status = 200, headers = { ["Content-Type"] = "text/plain" },\n'
            '             body = req.method .. " " .. req.path }\n'
            'end\n')
subprocess.run([binary, "reload-lua", be_name], capture_output=True, timeout=20)
st12, _, body12 = request("/endpoint/login", method="PATCH")
print("P12 AFTER %s %s" % (st12, body12.strip()))

# ── phase 13: still serving ────────────────────────────────────────────────
#
# A self-answered request is torn down through the paths every other answered
# request uses.  A leaked descriptor, or a backend socket handed back to the
# pool off a message boundary, shows up here as a proxy that has stopped
# working rather than as a wrong status code.
st13, _, body13 = request("/endpoint/login", method="POST", body="user=y")
print("P13 AFTER %s %s" % (st13, body13.strip()))

print("DONE")
PYEOF

# The harness has to have reached its last line, or an aborted run shows up as
# per-phase failures and any comparison has nothing to compare and passes.
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
    if [ -n "$before" ] && [ "$before" = "$after" ] && [ "$before" != "-1" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: $prefix went from '${before:-?}' to '${after:-?}'"
    fi
}

grew() {
    TOTAL=$((TOTAL+1))
    local label="$1" prefix="$2"; shift 2
    local line before after
    line=$(grep -m1 "^$prefix " "$OUT" 2>/dev/null || true)
    before=$(printf '%s' "$line" | awk '{print $(NF-1)}')
    after=$(printf '%s' "$line" | awk '{print $NF}')
    if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ] 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: $prefix did not move ('${before:-?}' → '${after:-?}')"
        for line in "$@"; do echo "        $line"; done
    fi
}

# The proxy serves a declared method at all, which everything below is a
# difference against.
check "a declared method is served" \
    '^P0 HTTP/1\.1 200 .*GET /endpoint/login$' \
    "the proxy did not serve a declared method, so no assertion below discriminates:" \
    "$(grep -m1 '^P0 ' "$OUT" 2>/dev/null || echo 'no result')"

# ── THE assertion ──────────────────────────────────────────────────────────
unchanged "forty refused methods open no backend connection" "P1 ACCEPTS"
unchanged "forty refused methods send the backend no bytes" "P1 BYTES"

check "every one of forty is refused at the edge" \
    '^P1 BADSTATUS 0$' \
    "$(grep -m1 '^P1 BADSTATUS' "$OUT" 2>/dev/null || echo 'no result')"

check "the refusal is a 405" \
    '^P1 STATUS HTTP/1\.1 405 ' \
    "$(grep -m1 '^P1 STATUS' "$OUT" 2>/dev/null || echo 'no result')"

# The reason rather than just the refusal, because RFC 9110 Section 15.5.6
# requires Allow and it also discriminates against a gate that matched some
# other route.
check "the 405 carries Allow, listing the declared methods and the implied ones" \
    '^P1 ALLOW POST, GET, HEAD, OPTIONS$' \
    "the declaration is POST+GET; HEAD is implied by GET and OPTIONS by this proxy" \
    "answering it: $(grep -m1 '^P1 ALLOW' "$OUT" 2>/dev/null || echo 'no result')"

check "the refusal is framed by this proxy" \
    '^P1 CLEN 19$' \
    "$(grep -m1 '^P1 CLEN' "$OUT" 2>/dev/null || echo 'no result')"

# The vacuity guard: those counters CAN move.
check "a declared POST is served" \
    '^P2 HTTP/1\.1 200 .*POST /endpoint/login$' \
    "$(grep -m1 '^P2 ' "$OUT" 2>/dev/null || echo 'no result')"
grew "a served request reaches the backend" "P2 BYTES" \
    "if this does not move, every 'did not reach the backend' check above is vacuous"

check "HEAD is not refused on a GET route" \
    '^P3 STATUS HTTP/1\.1 200 ' \
    "RFC 9110 9.3.2: a handler that serves GET serves HEAD." \
    "$(grep -m1 '^P3 STATUS' "$OUT" 2>/dev/null || echo 'no result')"
grew "HEAD reaches the backend" "P3 BYTES" \
    "a 200 alone would not prove the proxy forwarded it rather than inventing it"

check "a plain OPTIONS is answered from the declaration" \
    '^P4 STATUS HTTP/1\.1 204 ' \
    "$(grep -m1 '^P4 STATUS' "$OUT" 2>/dev/null || echo 'no result')"
check "that answer carries Allow" \
    '^P4 ALLOW POST, GET, HEAD, OPTIONS$' \
    "$(grep -m1 '^P4 ALLOW' "$OUT" 2>/dev/null || echo 'no result')"
unchanged "answering OPTIONS costs the backend nothing" "P4 BYTES"

# ── the one that must NOT be refused ───────────────────────────────────────
check "a CORS preflight is forwarded, not answered at the edge" \
    '^P5 STATUS HTTP/1\.1 200 ' \
    "A route declaring POST+GET must not answer the browser's preflight itself." \
    "A 405 makes the real request never happen; a 204 without" \
    "Access-Control-Allow-Origin does exactly the same thing while looking" \
    "correct.  Origin policy lives with the handler." \
    "$(grep -m1 '^P5 STATUS' "$OUT" 2>/dev/null || echo 'no result')"
check "the preflight reached the handler" \
    '^P5 BODY OPTIONS /endpoint/login$' \
    "$(grep -m1 '^P5 BODY' "$OUT" 2>/dev/null || echo 'no result')"
grew "the preflight cost a backend exchange" "P5 BYTES" \
    "the body above could have been invented by the proxy; this could not"

check "a handler that declares OPTIONS answers its own" \
    '^P6 BODY OPTIONS /cors$' \
    "$(grep -m1 '^P6 BODY' "$OUT" 2>/dev/null || echo 'no result')"
grew "that OPTIONS reached the handler" "P6 BYTES"

check "an undeclared path is forwarded, whatever the method" \
    '^P7 BODY DELETE /elsewhere$' \
    "A declaration speaks about the paths it names and says nothing about the" \
    "others.  Turning silence into a refusal would make declaring one route the" \
    "act of hiding every other: $(grep -m1 '^P7 STATUS' "$OUT" 2>/dev/null || echo 'no result')"
grew "the undeclared path reached the backend" "P7 BYTES"

check "a prefix route refuses an undeclared method" \
    '^P8 STATUS HTTP/1\.1 405 ' \
    "$(grep -m1 '^P8 STATUS' "$OUT" 2>/dev/null || echo 'no result')"
check "the prefix route's Allow is its own, not another route's" \
    '^P8 ALLOW GET, HEAD, OPTIONS$' \
    "/static/* declares GET; /endpoint/login declares POST+GET.  A gate that" \
    "matched the wrong route would answer the wrong list:" \
    "$(grep -m1 '^P8 ALLOW' "$OUT" 2>/dev/null || echo 'no result')"
check "the prefix route serves its declared method" \
    '^P8 GET HTTP/1\.1 200 .*GET /static/app\.js$' \
    "$(grep -m1 '^P8 GET' "$OUT" 2>/dev/null || echo 'no result')"
grew "the prefix route's GET reached the backend" "P8 BYTES"

check "a query string does not defeat the match" \
    '^P9 STATUS HTTP/1\.1 405 ' \
    "'/endpoint/login?next=/home' is the login route; a gate comparing the whole" \
    "target would forward every request carrying a query:" \
    "$(grep -m1 '^P9 STATUS' "$OUT" 2>/dev/null || echo 'no result')"
check "and it answers that route's Allow" \
    '^P9 ALLOW POST, GET, HEAD, OPTIONS$' \
    "$(grep -m1 '^P9 ALLOW' "$OUT" 2>/dev/null || echo 'no result')"

check "a method only one group member declares is forwarded" \
    '^P10 PUT HTTP/1\.1 200 ' \
    "the group's declaration is the union of its members'.  Intersecting them," \
    "or taking the first member's answer, refuses at the edge what the other" \
    "member serves: $(grep -m1 '^P10 PUT' "$OUT" 2>/dev/null || echo 'no result')"
grew "that PUT reached a group member" "P10 BYTES"

check "and a method only the other member declares is forwarded too" \
    '^P10 GET HTTP/1\.1 200 ' \
    "a merge that keeps the first declaration it sees rather than the union" \
    "refuses one of these two, whichever order the runtimes are walked in:" \
    "$(grep -m1 '^P10 GET' "$OUT" 2>/dev/null || echo 'no result')"

check "a path only one member declares is not enforced for the group" \
    '^P10 PARTIAL HTTP/1\.1 200 ' \
    "/static/* is member A's declaration alone.  Member B never said what it" \
    "answers and this request could have landed on it, so nothing there may be" \
    "refused: $(grep -m1 '^P10 PARTIAL' "$OUT" 2>/dev/null || echo 'no result')"

check "a method no group member declares is refused" \
    '^P11 STATUS HTTP/1\.1 405 ' \
    "$(grep -m1 '^P11 STATUS' "$OUT" 2>/dev/null || echo 'no result')"
# Members are folded in name order — route_ga before route_gb — so this string
# is fixed rather than depending on the order a hash map was walked in.
check "the group's Allow is the union of its members'" \
    '^P11 ALLOW POST, GET, PUT, HEAD, OPTIONS$' \
    "$(grep -m1 '^P11 ALLOW' "$OUT" 2>/dev/null || echo 'no result')"
unchanged "the group refusal costs its members nothing" "P11 BYTES"

check "a backend with no declaration disables the gate" \
    '^P11B STATUS HTTP/1\.1 200 ' \
    "this proxy's second backend is a bare address, which has no declaration to" \
    "look up.  Refusing here would refuse on behalf of a backend that never" \
    "said what it answers:" \
    "$(grep -m1 '^P11B STATUS' "$OUT" 2>/dev/null || echo 'no result')"
grew "and that request reached the backend" "P11B BYTES"

# ── published, not configured ──────────────────────────────────────────────
check "PATCH is refused before the handler declares it" \
    '^P12 BEFORE HTTP/1\.1 405 ' \
    "$(grep -m1 '^P12 BEFORE' "$OUT" 2>/dev/null || echo 'no result')"
check "editing the handler's script changes what the gateway enforces" \
    '^P12 AFTER HTTP/1\.1 200 .*PATCH /endpoint/login$' \
    "the proxy was not restarted or reconfigured — the declaration is published," \
    "and a gateway holding a configured copy would refuse PATCH for ever:" \
    "$(grep -m1 '^P12 AFTER' "$OUT" 2>/dev/null || echo 'no result')"

check "the proxy still serves after forty refusals" \
    '^P13 AFTER HTTP/1\.1 200 ' \
    "$(grep -m1 '^P13 AFTER' "$OUT" 2>/dev/null || echo 'no result')"

TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [runtime alive]: the proxy did not survive the run"
fi

# Waits for the expected reading rather than sleeping, because declared_routes
# is a figure the worker pushes and a read taken as the harness stops can be
# one publish behind.
await_field() {
    local rt=$1 field=$2 want=$3 seen="" i
    for i in $(seq 1 50); do
        seen=$("$BIN" stats "$rt" 2>/dev/null | grep "^$field:" || true)
        [ "$seen" = "$want" ] && break
        sleep 0.1
    done
    printf '%s' "$seen"
}

# What the proxy says it is enforcing, which is the only way to tell the four
# ways of enforcing nothing apart from outside.
TOTAL=$((TOTAL+1))
DR=$(await_field "$PX_NAME" declared_routes "declared_routes:1")
if [ "$DR" = "declared_routes:1" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [stats reports what is being enforced]: expected declared_routes:1"
    echo "        after the reload replaced three routes with one; got '${DR:-<absent>}'"
fi

TOTAL=$((TOTAL+1))
DR=$(await_field "$MX_NAME" declared_routes "declared_routes:0")
if [ "$DR" = "declared_routes:0" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a proxy enforcing nothing says so]: the proxy with a bare-address"
    echo "        backend must report declared_routes:0, not '${DR:-<absent>}' — an"
    echo "        operator has no other way to tell 'not enforced' from 'not refused'"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
