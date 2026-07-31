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
    except Exception:
        pass
    time.sleep(0.05)
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
while time.time() < deadline:
    try:
        s = socket.create_connection((host, port), 0.5)
        s.settimeout(0.5)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = s.recv(4096)
        s.close()
        if data.startswith(b"HTTP/1."):
            sys.exit(0)
    except Exception:
        pass
    time.sleep(0.05)
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
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), 0.5) as raw:
            with ctx.wrap_socket(raw, server_hostname=servername) as tls:
                if tls.version():
                    sys.exit(0)
    except Exception:
        pass
    time.sleep(0.05)
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
while time.time() < deadline:
    try:
        s = socket.create_connection((host, port), 0.5)
        s.settimeout(0.5)
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        if s.recv(64).startswith(b"+PONG"):
            s.close()
            sys.exit(0)
        s.close()
    except Exception:
        pass
    time.sleep(0.05)
sys.exit(1)
PY
}
