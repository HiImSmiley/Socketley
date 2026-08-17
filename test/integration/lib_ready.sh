# Readiness, proved rather than waited for.
#
# Not a test — run_all.sh globs test_*.sh, so this file is only ever sourced.
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
#
# Eleven tests opened with the same two lines:
#
#     for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PORT" && break; sleep 0.1; done
#     sleep 0.3
#
# The first proves a TCP connection is accepted.  That happens the moment the
# listening socket is armed, which is earlier than the runtime behind it can
# answer anything: a proxy still has to health-check its backends before any of
# them is in rotation, a cache has to finish loading, a server has to run its
# on_start.  The second line is a guess about how much earlier, and a guess that
# is generous on an idle machine is thin when the whole suite is running — which
# is precisely when a test that fails intermittently gets waved through as
# flaky.
#
# So these ask the thing under test to do its job, and wait until it does.  A
# readiness check that goes through the same path as the measurement cannot be
# satisfied earlier than the measurement can start.
#
# Every function takes a timeout in whole seconds and returns non-zero when it
# expires; none of them sleeps after succeeding, because there is nothing left
# to wait for.

# ready_tcp HOST PORT [TIMEOUT_S]
#
# A connection is accepted.  Still the right check when that is genuinely all
# that is being claimed — a listener that must exist while its backends are
# deliberately down, for instance — and the precondition the others build on.
ready_tcp() {
    local host=$1 port=$2 timeout=${3:-8}
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        if nc -z "$host" "$port" 2>/dev/null; then return 0; fi
        sleep 0.05
    done
    return 1
}

# ready_http HOST PORT [PATH] [TIMEOUT_S]
#
# A complete HTTP response comes back with a 2xx or 3xx status.  Through a proxy
# this additionally proves at least one backend is in rotation and answering,
# which is the part "nc -z" never showed and the fixed sleep was standing in for.
ready_http() {
    local host=$1 port=$2 path=${3:-/} timeout=${4:-15}
    python3 - "$host" "$port" "$path" "$timeout" <<'PY'
import socket, sys, time
host, port, path, timeout = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
deadline = time.time() + timeout
# Why the last attempt failed.  Every probe in this file used to discard it, so
# a listener that refused every connection, one whose backend answered 502 for
# fifteen seconds and one that never came up at all produced the same message:
# none.  The caller then reports "not ready", and diagnosing which of the three
# it was costs a rerun with the probe pasted into a shell — the rerun that no
# longer reproduces.  Kept as text rather than raised, because a probe that
# fails is answering its question, not erroring.
last = ""
while time.time() < deadline:
    try:
        s = socket.create_connection((host, port), 0.5)
        s.settimeout(0.5)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        # The status line alone decides.  A body is not required — some paths
        # legitimately answer with none — but a status is, and it has to be one
        # that means the request was served rather than refused.
        if data.startswith(b"HTTP/1."):
            code = data.split(b" ")[1] if len(data.split(b" ")) > 1 else b""
            if code[:1] in (b"2", b"3"):
                sys.exit(0)
            # A served-but-wrong status raises nothing, so without this the one
            # failure this probe exists to catch is the one it stays silent
            # about: a proxy answering 502 because no backend is in rotation.
            last = "answered " + code.decode("latin-1", "replace") + " every time"
        else:
            last = "no status line, got " + repr(data[:60])
    except Exception as e:
        last = "%s: %s" % (type(e).__name__, e)
    time.sleep(0.05)
if last:
    print(last, file=sys.stderr)
sys.exit(1)
PY
}

# ready_answers HOST PORT [PATH] [TIMEOUT_S]
#
# A complete status line comes back, whatever it says.  For listeners whose
# correct answer to a plain GET is a refusal — a WebSocket endpoint replies 400
# or 426 to a request carrying no Upgrade — where the point is that the runtime
# read the request and produced a response, not what the response was.
ready_answers() {
    local host=$1 port=$2 path=${3:-/} timeout=${4:-15}
    python3 - "$host" "$port" "$path" "$timeout" <<'PY'
import socket, sys, time
host, port, path, timeout = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
deadline = time.time() + timeout
last = ""
while time.time() < deadline:
    try:
        s = socket.create_connection((host, port), 0.5)
        s.settimeout(0.5)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = s.recv(4096)
        s.close()
        if data.startswith(b"HTTP/1."):
            sys.exit(0)
        # Reported for the reason ready_http gives above.  Here it is the whole
        # of the check: this probe accepts any status, so the only way it fails
        # with bytes in hand is a listener answering something that is not HTTP.
        last = "no status line, got " + repr(data[:60])
    except Exception as e:
        last = "%s: %s" % (type(e).__name__, e)
    time.sleep(0.05)
if last:
    print(last, file=sys.stderr)
sys.exit(1)
PY
}

# ready_tls HOST PORT CAFILE [SERVERNAME] [TIMEOUT_S]
#
# A TLS handshake completes and the server's certificate verifies against
# CAFILE.  "nc -z" is worth even less against a TLS listener than against a
# plain one: the socket is accepted before a single record has crossed, and
# the handshake it then has to complete is spread over several io_uring
# completions.  A test that starts measuring at "connected" is measuring
# against a listener that has not yet proved it can terminate anything.
#
# Verification is part of the check on purpose.  An unverified handshake would
# also succeed against a listener serving the wrong certificate, which is one
# of the two ways this feature can be wrong in a way nobody notices.
ready_tls() {
    local host=$1 port=$2 cafile=$3 servername=${4:-localhost} timeout=${5:-15}
    python3 - "$host" "$port" "$cafile" "$servername" "$timeout" <<'PY'
import socket, ssl, sys, time
host, port, cafile, servername, timeout = (
    sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], float(sys.argv[5]))
ctx = ssl.create_default_context(cafile=cafile)
ctx.check_hostname = True
deadline = time.time() + timeout
# Reported for the reason ready_http gives above, and this is the probe where
# discarding it cost the most: verification is part of the check, so a listener
# serving the wrong certificate, one whose chain does not reach CAFILE and one
# that is simply not up yet all failed here identically and silently.
last = ""
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), 0.5) as raw:
            with ctx.wrap_socket(raw, server_hostname=servername) as tls:
                if tls.version():
                    sys.exit(0)
                last = "handshake completed but reported no version"
    except Exception as e:
        last = "%s: %s" % (type(e).__name__, e)
    time.sleep(0.05)
if last:
    print(last, file=sys.stderr)
sys.exit(1)
PY
}

# ready_resp HOST PORT [TIMEOUT_S]
#
# A cache answers PING with +PONG.  Proves the RESP path is up, not merely the
# socket: a cache that is still loading its state file accepts long before it
# replies.
ready_resp() {
    local host=$1 port=$2 timeout=${3:-15}
    python3 - "$host" "$port" "$timeout" <<'PY'
import socket, sys, time
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
deadline = time.time() + timeout
last = ""
while time.time() < deadline:
    try:
        s = socket.create_connection((host, port), 0.5)
        s.settimeout(0.5)
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        reply = s.recv(64)
        if reply.startswith(b"+PONG"):
            s.close()
            sys.exit(0)
        s.close()
        # Reported for the reason ready_http gives above.  A cache still loading
        # its state file accepts and answers -- with an error, or with nothing --
        # so the reply is the difference between "not up" and "up and refusing".
        last = "PING answered " + repr(reply[:60])
    except Exception as e:
        last = "%s: %s" % (type(e).__name__, e)
    time.sleep(0.05)
if last:
    print(last, file=sys.stderr)
sys.exit(1)
PY
}

# ready_conns BIN NAME COUNT [TIMEOUT_S]
#
# The runtime's published connection count is COUNT, in a figure the runtime
# sampled after this call began.
#
# ─── WHY THE SECOND HALF OF THAT SENTENCE IS THE WHOLE POINT ────────────────
#
# Since the process split a runtime's connection count is not read when it is
# printed.  The worker samples its own counters every 250 ms and pushes them;
# `stats`, `ls` and every Lua binding report the last sample that arrived.  So
# the figure lags the truth by up to a quarter second, which `stats` says out
# loud in figures:pushed / figures_age_ms and which is invisible in the number
# itself.
#
# For a count that is RISING that lag is harmless: a test waiting for 3 cannot
# be handed 3 by a sample taken before the third client connected.  For a count
# that has just fallen it is not, and the direction that matters most is the
# fall to zero, because "nothing is connected" is the precondition every busy
# assertion is read against.  Concretely, and this is a measured failure and not
# a hypothetical: ready_tcp's `nc -z` opens and closes a connection, and the
# worker goes on counting it until the ring reports the hangup after it reported
# the accept.  A sample landing inside that window puts a 1 into the daemon for
# the quarter second that follows — during which a test that asks "0
# connections, yes?" is told 1 about a runtime nothing is connected to.
#
# How wide that window is was measured rather than reasoned about, by reading
# the figure straight after an isolated `nc -z`: 7 stale reads in 164 on an idle
# machine, so a few percent of the 250 ms period.  That is the rate at which a
# test doing this once per run fails for no reason — rare enough to pass alone
# and to be called flaky, common enough to turn up in a nightly.
#
# Polling until the number reads 0 does not fix that, and is the trap worth
# naming: the first read can be answered from a sample taken BEFORE the probe
# connected, so the loop exits on a stale zero having proved nothing at all.
# That is a false pass in the same place, and it is the harder one to notice.
#
# So the test is on the sample's age rather than on repetition.  figures_age_ms
# is the interval between the worker reading its own counters and the daemon
# printing them, on a clock both processes share; subtracting it from the moment
# of the call gives the instant the figure describes, and requiring that instant
# to be later than the moment ready_conns was entered is exactly the claim a
# caller wants: the runtime looked, after you asked, and saw COUNT.
#
# `now` is read BEFORE the stats round-trip on purpose.  Reading it after would
# add the round-trip to the computed sample instant and could date a figure into
# the window this function exists to exclude; taken before, the arithmetic can
# only ever place the sample earlier than it really was, and the error is on the
# side of waiting one more turn.
#
# A runtime with no figures_age_ms line is in the daemon, where the counters are
# read at the instant they are printed — that figure postdates the call by
# construction, so it is accepted as it stands.
ready_conns() {
    local bin=$1 name=$2 want=$3 timeout=${4:-15}
    local start deadline now out conn age sampled
    start=$(date +%s%3N)
    deadline=$(( start + timeout * 1000 ))
    while [ "$(date +%s%3N)" -le "$deadline" ]; do
        now=$(date +%s%3N)
        out=$("$bin" stats "$name" 2>/dev/null) || true
        conn=$(printf '%s\n' "$out" | awk -F: '$1 == "connections" { print $2; exit }')
        age=$(printf '%s\n'  "$out" | awk -F: '$1 == "figures_age_ms" { print $2; exit }')
        # Absent, or anything that is not a count of milliseconds, means there is
        # no pushed figure to date — the in-daemon case above.  Guarded rather
        # than trusted, because the alternative is arithmetic on whatever `stats`
        # happened to print, which fails as a shell error in the middle of a wait
        # and takes the caller's whole file with it.
        case "$age" in ''|*[!0-9]*) age=0 ;; esac
        sampled=$(( now - age ))
        if [ "$conn" = "$want" ] && [ "$sampled" -ge "$start" ]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}
