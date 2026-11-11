#!/usr/bin/env bash
# Integration test: a worker ends at once when its daemon is killed, and a stop
# that was asked for still unwinds to the end
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A dying daemon closes its end of the control socket before the kernel sends
# the worker its parent-death signal.  A worker that read that end of input in
# between used to take it as a stop, give the signal back and unwind with no
# deadline -- so it outlived the daemon by as long as its stop took, holding its
# port.  The window is made certain here rather than raced for: the daemon is
# stopped, its unix sockets are shut down from outside -- the end of input a
# dying daemon gives, with no signal sent yet -- and only once the worker has
# begun its stop is the daemon killed.  The worker's end is read off a pidfd,
# since its exit status reaches a waiter only when the daemon has finished
# dying, which on a loaded machine is the daemon's time and not the worker's.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * kill -9 the daemon, idle and under load: the worker that read the end of
#     input is killed within 2 s, not after its ten-second on_stop; and it did
#     read it and begin that stop, or the arm tested nothing
#   * `stop` of the runtime, and a graceful daemon shutdown: on_stop, four
#     seconds asleep, still runs to its end -- the daemon, which leaves three
#     seconds into its shutdown, must not cut a stop it asked for
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate workerdeath
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a worker ends with its daemon, and an asked-for stop unwinds ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 123))

# ── 1-4. kill -9 the daemon, idle and under load ────────────────────────────
timeout 120 python3 - "$BIN" "$P" "$WORK" > "$WORK/kill" <<'PY'
import ctypes, os, select, signal, socket, subprocess, sys, threading, time
BIN, port, work = sys.argv[1], int(sys.argv[2]), sys.argv[3]
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(36, 1, 0, 0, 0)      # PR_SET_CHILD_SUBREAPER: the orphaned worker's end is read here
SYS_pidfd_getfd = 438

def stopped(pid):
    # Every thread but io_uring's own, which take no signals.
    for t in os.listdir("/proc/%d/task" % pid):
        try:
            if open("/proc/%d/task/%s/comm" % (pid, t)).read().startswith("iou-"): continue
            if open("/proc/%d/task/%s/stat" % (pid, t)).read().rsplit(")", 1)[1].split()[0] not in "tT": return False
        except OSError:
            pass
    return True

def end_of_input(pid):
    # Each connected unix socket of the stopped daemon shut down through a copy of it, as its death would.
    pidfd, n = os.pidfd_open(pid), 0
    try:
        for fd in os.listdir("/proc/%d/fd" % pid):
            try:
                if not os.readlink("/proc/%d/fd/%s" % (pid, fd)).startswith("socket:"): continue
            except OSError:
                continue
            mine = libc.syscall(SYS_pidfd_getfd, pidfd, int(fd), 0)
            if mine < 0: continue
            try:
                s = socket.socket(fileno=mine)
            except OSError:
                os.close(mine); continue
            try:
                if s.family == socket.AF_UNIX and not s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                    s.shutdown(socket.SHUT_RDWR); n += 1
            except OSError:
                pass
            finally:
                s.close()
    finally:
        os.close(pidfd)
    return n

def arm(load):
    label = "load" if load else "idle"
    name, p = ("slow-load", port + 2) if load else ("slow-idle", port + 3)
    # State and a socket of each arm's own, so no daemon restores what another arm created.
    os.environ["HOME"] = work + "/" + name; os.makedirs(os.environ["HOME"], exist_ok=True)
    sock = os.environ["SOCKETLEY_SOCKET"] = work + "/" + name + ".sock"
    began = work + "/" + name + ".began"
    with open(work + "/" + name + ".lua", "w") as f:
        f.write('function on_client_message(id, msg) self.send(id, msg) return true end\n'
                'function on_stop() local m = io.open("%s", "w") m:write("x") m:close()\n'
                '    local t = os.clock() while os.clock() - t < 10 do end end\n' % began)
    d = subprocess.Popen([BIN, "daemon"], stdout=open(work + "/d.log", "a"),
                         stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    for _ in range(200):
        if os.path.exists(sock): break
        time.sleep(0.05)
    r = subprocess.run([BIN, "create", "server", name, "-p", str(p), "--bind", "127.0.0.1",
                        "--lua", work + "/" + name + ".lua", "-s"], capture_output=True, text=True)
    if r.returncode != 0:
        print(label, "create failed:", (r.stdout + r.stderr).strip()); d.kill(); d.wait(); return
    time.sleep(0.3)
    workers = [int(x) for t in os.listdir("/proc/%d/task" % d.pid)
               for x in open("/proc/%d/task/%s/children" % (d.pid, t)).read().split()]
    if len(workers) != 1:
        print(label, "workers: %d, not one" % len(workers)); d.kill(); d.wait(); return
    w = workers[0]
    wfd = os.pidfd_open(w)
    stop = threading.Event()
    def client():
        try:
            s = socket.create_connection(("127.0.0.1", p), 5); s.settimeout(1)
            while not stop.is_set():
                s.sendall(b"x" * 63 + b"\n"); s.recv(65536)
        except OSError:
            pass
    cs = [threading.Thread(target=client, daemon=True) for _ in range(8 if load else 0)]
    for c in cs: c.start()
    time.sleep(0.5)
    os.kill(d.pid, signal.SIGSTOP)
    for _ in range(400):
        if stopped(d.pid): break
        time.sleep(0.005)
    shut = end_of_input(d.pid)
    for _ in range(200):
        if os.path.exists(began): break
        time.sleep(0.05)
    inside = os.path.exists(began)
    t0 = time.monotonic()
    os.kill(d.pid, signal.SIGKILL)
    ended = bool(select.select([wfd], [], [], 20)[0])
    secs = time.monotonic() - t0
    stop.set()
    if not ended:
        os.kill(w, signal.SIGKILL)
    os.waitpid(d.pid, 0)
    _, st = os.waitpid(w, 0)
    how = "signal %d" % os.WTERMSIG(st) if os.WIFSIGNALED(st) else "exit %d" % os.WEXITSTATUS(st)
    print("%s began %s after %d sockets shut" % (label, "yes" if inside else "no", shut))
    if ended:
        print("%s worker ended after %.3f s by %s" % (label, secs, how))
    else:
        print("%s worker still running after %.3f s" % (label, secs))

arm(False)
arm(True)
PY
sed 's/^/  /' "$WORK/kill"
for label in idle load; do
    line=$(grep "^$label began" "$WORK/kill" || echo "$label: no result")
    case "$line" in
        "$label began yes"*) pass ;;
        *) fail "the daemon's end of input begins the worker's stop ($label)" "$line" ;;
    esac
    line=$(grep "^$label worker" "$WORK/kill" || echo "$label: no result")
    secs=$(echo "$line" | sed -n 's/.*after \([0-9.]*\) s by signal 9$/\1/p')
    if [ -n "$secs" ] && python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 2 else 1)" "$secs"; then pass
    else fail "kill -9 of the daemon ends its worker within 2 s, in its stop ($label)" "$line"; fi
done

# ── 5-6. a stop that was asked for still runs on_stop to its end ────────────
# Asleep rather than counting CPU, so the length is the same on a loaded machine: past the daemon's exit at three
# seconds, and inside the five-second alarm a worker sets itself on SIGTERM.
for n in one two; do cat > "$WORK/$n.lua" <<LUA
function on_client_message(id, msg) self.send(id, msg) return true end
function on_stop()
    os.execute("sleep 4")
    local f = io.open("$WORK/$n.stopped", "w") f:write("done") f:close()
end
LUA
done
daemon_start "$BIN"
wait_marker(){ for _ in $(seq 1 80); do [ -s "$1" ] && return 0; sleep 0.1; done; return 1; }
"$BIN" create server one -p "$P" --bind 127.0.0.1 --lua "$WORK/one.lua" -s >/dev/null 2>&1 || true
"$BIN" stop one >/dev/null 2>&1 || true
if wait_marker "$WORK/one.stopped"; then pass
else fail "a runtime's stop runs its four-second on_stop to the end" "no $WORK/one.stopped after 8 s"; fi

"$BIN" create server two -p "$((P + 1))" --bind 127.0.0.1 --lua "$WORK/two.lua" -s >/dev/null 2>&1 || true
kill -TERM "$SOCKETLEY_DPID" 2>/dev/null || true
if wait_marker "$WORK/two.stopped"; then pass
else fail "a graceful daemon shutdown lets on_stop run past the daemon's own exit" "no $WORK/two.stopped after 8 s"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
