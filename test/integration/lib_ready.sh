# Readiness, proved rather than waited for -- only ever sourced, since
# run_all.sh globs test_*.sh.
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# An accepted connection happens the moment the listening socket is armed,
# which is earlier than a proxy has health-checked its backends or a server has
# run its on_start, and the fixed sleep after it is a guess that is thin
# exactly when the whole suite is running -- so these ask the thing under test
# to do its job through the same path as the measurement, with a whole-second
# timeout and no sleep after success.

# A connection is accepted, which is still the right check when that is all
# that is being claimed and is the precondition the others build on.
ready_tcp() {
    local host=$1 port=$2 timeout=${3:-8}
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        if nc -z "$host" "$port" 2>/dev/null; then return 0; fi
        sleep 0.05
    done
    return 1
}

# A complete HTTP response with a 2xx or 3xx status, which through a proxy
# additionally proves at least one backend is in rotation and answering.
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

# A complete status line, whatever it says, for listeners whose correct answer
# to a plain GET is a refusal -- where the point is that the runtime read the
# request and produced a response.
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

# A TLS handshake completes and the certificate verifies, because the socket is
# accepted before a single record has crossed -- and verification is part of
# the check on purpose, since an unverified handshake also succeeds against a
# listener serving the wrong certificate.
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

# A cache answers PING with +PONG, which proves the RESP path is up rather than
# merely the socket, since a cache still loading its state file accepts long
# before it replies.
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

# The runtime's connection count is COUNT in a figure the runtime sampled after
# this call began, which mattered while figures were pushed on a 250 ms timer:
# a rising count could not be answered stale, but the fall to zero could, and
# the readiness probe's own `nc -z` put a 1 into the daemon for a quarter
# second -- measured at 7 stale reads in 164 -- while polling until it reads 0
# exits on a stale zero having proved nothing.
# ─── AND WHY THE TEST IS STILL ON THE AGE ───────────────────────────────────
# The counters live in shared memory now, so the figure postdates the call by
# construction and the second test holds on the first pass -- with the
# arithmetic kept because this is the one reader that would act on an age
# reappearing, and `now` read before the round trip so the error is always on
# the side of waiting one more turn.
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
        # Anything that is not a count of milliseconds means there is no pushed
        # figure to date, guarded rather than trusted because arithmetic on
        # whatever `stats` printed fails as a shell error in the middle of a
        # wait.
        case "$age" in ''|*[!0-9]*) age=0 ;; esac
        sampled=$(( now - age ))
        if [ "$conn" = "$want" ] && [ "$sampled" -ge "$start" ]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}
