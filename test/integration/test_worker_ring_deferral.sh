#!/usr/bin/env bash
# Integration test: a worker builds its ring on its config frame, not before.
#
# io_uring fixes a ring's flags when the ring is created.  A worker that calls
# init() before it has read anything can therefore never be told what shape its
# ring should be — set_cpus() on an open ring is a no-op by contract, so the
# setting would parse, store, and be silently ignored.  This
# checks the ordering directly rather than through a setting that does not exist
# yet, because the ordering is the part that has to hold first.
#
# The harness is its own supervisor: it forks `socketley proxy-worker` with a
# socketpair on fd 3 and decides for itself when — or whether — the config frame
# goes out.  The real supervisor sends it microseconds after the fork, which
# leaves no window to look at.
#
# No daemon, no socket, no state directory.  Nothing here can disturb another
# suite on the same machine, and nothing another suite does can disturb it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

echo "=== Integration: worker ring deferral ==="

if [ ! -x "$BIN" ]; then
    echo "  FAIL: no binary at $BIN"
    exit 1
fi

OUT=$(python3 - "$BIN" <<'PY'
import os, socket, struct, sys, time

BIN = sys.argv[1]

CONFIG = 16
SHUTDOWN = 20
HELLO = 1

def frame(ftype, payload=b""):
    return struct.pack("<IHH", len(payload), 1, ftype) + payload

def spawn():
    """Fork the worker with a control socketpair on fd 3, as the supervisor does."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            os.dup2(child.fileno(), 3)
            os.set_inheritable(3, True)
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.execl(BIN, BIN, "proxy-worker")
        except Exception:
            pass
        os._exit(127)
    child.close()
    return pid, parent

def has_ring(pid):
    """Whether the process holds an io_uring descriptor right now."""
    d = "/proc/%d/fd" % pid
    try:
        entries = os.listdir(d)
    except OSError:
        return None
    for e in entries:
        try:
            if os.readlink(os.path.join(d, e)) == "anon_inode:[io_uring]":
                return True
        except OSError:
            continue
    return False

def cpu_ticks(pid):
    """utime+stime, in clock ticks.  A worker waiting for a frame should burn
    none of these; one polling an empty ring in a tight loop burns a core."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            data = f.read()
    except OSError:
        return None
    fields = data[data.rindex(")") + 2:].split()
    return int(fields[11]) + int(fields[12])       # utime, stime

def wait_hello(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            return None
        buf += chunk
        while len(buf) >= 8:
            ln, _ver, ftype = struct.unpack("<IHH", buf[:8])
            if len(buf) < 8 + ln:
                break
            body = buf[8:8 + ln]
            buf = buf[8 + ln:]
            if ftype == HELLO:
                return struct.unpack("<I", body[:4])[0]
    return None

def reap(pid, sock):
    try:
        sock.sendall(frame(SHUTDOWN))
    except OSError:
        pass
    for _ in range(50):
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if done:
            return
        time.sleep(0.1)
    try:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    except OSError:
        pass

results = []
def check(name, cond, detail=""):
    results.append("%s|%s|%s" % ("ok" if cond else "bad", name, detail))

pid, ctl = spawn()
try:
    # hello proves the worker is up and running its loop, so a "no ring" answer
    # below is about deferral and not about a worker that has not started yet.
    said = wait_hello(ctl)
    check("worker announced itself", said == pid,
          "hello carried pid %s, forked %s" % (said, pid))

    if said is None:
        raise SystemExit

    # ── The assertion this whole change is about ────────────────────────────
    check("no ring before the config frame", has_ring(pid) is False,
          "the worker holds an io_uring descriptor already, so nothing the "
          "config frame could say about its ring can ever be applied")

    # A deferral that spins is not a deferral anybody wants.  300ms of waiting
    # should cost single-digit ticks; a busy loop on a closed ring costs ~30.
    t0 = cpu_ticks(pid)
    time.sleep(0.3)
    t1 = cpu_ticks(pid)
    check("waiting worker is idle", t0 is not None and t1 is not None and (t1 - t0) <= 3,
          "burned %s clock ticks in 300ms with nothing to do" % (
              None if t0 is None or t1 is None else t1 - t0))

    # ── And the other half: the config frame does build one ─────────────────
    cfg = ('{\n  "name": "ring_defer_probe",\n  "id": "rdp",\n'
           '  "type": "proxy",\n  "port": 0\n}\n')
    ctl.sendall(frame(CONFIG, cfg.encode()))

    got = False
    for _ in range(100):
        if has_ring(pid):
            got = True
            break
        time.sleep(0.05)
    check("ring exists after the config frame", got,
          "the worker never built a ring, so it can never serve")
finally:
    reap(pid, ctl)

print("\n".join(results))
PY
)
RC=$?

if [ $RC -ne 0 ] || [ -z "$OUT" ]; then
    bad "harness did not run (rc=$RC)"
else
    while IFS='|' read -r verdict name detail; do
        [ -z "$verdict" ] && continue
        if [ "$verdict" = "ok" ]; then ok; else bad "$name: $detail"; fi
    done <<< "$OUT"
fi

echo "--- $PASS/$TOTAL passed ---"
[ "$FAIL" -eq 0 ]
