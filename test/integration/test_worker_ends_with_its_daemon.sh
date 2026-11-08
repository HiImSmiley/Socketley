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
# port.  The window is made certain here rather than hoped for: the daemon and
# the worker share one CPU and only the daemon's threads are SCHED_IDLE, so the
# woken worker always runs first.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * kill -9 the daemon, idle and under load: the worker is killed within 2 s,
#     not after its ten-second on_stop
#   * `stop` of the runtime, and a graceful daemon shutdown: on_stop, three
#     seconds long, still runs to its end -- the daemon's exit after its own
#     1.5 s wait must not cut a stop it asked for
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
# One CPU this shell may use, for the daemon and its worker together.
CPU=$(python3 -c 'import os; print(sorted(os.sched_getaffinity(0))[-1])')

# ── 1-2. kill -9 the daemon, idle and under load ────────────────────────────
timeout 120 python3 - "$BIN" "$P" "$CPU" "$WORK" > "$WORK/kill" <<'PY'
import ctypes, os, signal, socket, subprocess, sys, threading, time
BIN, port, cpu, work = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)      # PR_SET_CHILD_SUBREAPER: the orphaned worker's end is read here
with open(work + "/slow.lua", "w") as f:
    f.write('function on_client_message(id, msg) self.send(id, msg) return true end\n'
            'function on_stop() local t = os.clock() while os.clock() - t < 10 do end end\n')

def arm(load):
    name, p = ("slow-load", port + 2) if load else ("slow-idle", port + 3)
    # State and a socket of each arm's own, so no daemon restores what another arm created.
    os.environ["HOME"] = work + "/" + name; os.makedirs(os.environ["HOME"], exist_ok=True)
    sock = os.environ["SOCKETLEY_SOCKET"] = work + "/" + name + ".sock"
    d = subprocess.Popen(["taskset", "-c", cpu, BIN, "daemon"], stdout=open(work + "/d.log", "a"),
                         stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    for _ in range(200):
        if os.path.exists(sock): break
        time.sleep(0.05)
    r = subprocess.run([BIN, "create", "server", name, "-p", str(p), "--bind", "127.0.0.1",
                        "--lua", work + "/slow.lua", "-s"], capture_output=True, text=True)
    if r.returncode != 0:
        print("create failed:", (r.stdout + r.stderr).strip()); d.kill(); d.wait(); return
    time.sleep(0.3)
    workers = [int(x) for t in os.listdir("/proc/%d/task" % d.pid)
               for x in open("/proc/%d/task/%s/children" % (d.pid, t)).read().split()]
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
    for t in os.listdir("/proc/%d/task" % d.pid):
        os.sched_setscheduler(int(t), os.SCHED_IDLE, os.sched_param(0))
    t0 = time.time()
    os.kill(d.pid, signal.SIGKILL)
    ends = {}
    while len(ends) < len(workers) + 1 and time.time() - t0 < 30:
        try:
            pid, st = os.waitpid(-1, 0)
        except ChildProcessError:
            break
        ends[pid] = (time.time() - t0, "signal %d" % os.WTERMSIG(st) if os.WIFSIGNALED(st) else "exit %d" % os.WEXITSTATUS(st))
    stop.set()
    for w in workers:
        try: os.kill(w, signal.SIGKILL)
        except OSError: pass
    label = "load" if load else "idle"
    if len(workers) != 1:
        print(label, "workers: %d, not one" % len(workers)); return
    secs, how = ends.get(workers[0], (99, "still running"))
    print("%s worker ended after %.3f s by %s" % (label, secs, how))

arm(False)
arm(True)
PY
sed 's/^/  /' "$WORK/kill"
for label in idle load; do
    line=$(grep "^$label " "$WORK/kill" || echo "$label: no result")
    secs=$(echo "$line" | sed -n 's/.*after \([0-9.]*\) s.*/\1/p')
    if [ -n "$secs" ] && python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 2 else 1)" "$secs"; then pass
    else fail "kill -9 of the daemon ends its worker within 2 s ($label)" "$line"; fi
done

# ── 3-4. a stop that was asked for still runs on_stop to its end ────────────
for n in one two; do cat > "$WORK/$n.lua" <<LUA
function on_client_message(id, msg) self.send(id, msg) return true end
function on_stop()
    local t = os.clock() while os.clock() - t < 3 do end
    local f = io.open("$WORK/$n.stopped", "w") f:write("done") f:close()
end
LUA
done
daemon_start "$BIN"
wait_marker(){ for _ in $(seq 1 80); do [ -s "$1" ] && return 0; sleep 0.1; done; return 1; }
"$BIN" create server one -p "$P" --bind 127.0.0.1 --lua "$WORK/one.lua" -s >/dev/null 2>&1 || true
"$BIN" stop one >/dev/null 2>&1 || true
if wait_marker "$WORK/one.stopped"; then pass
else fail "a runtime's stop runs its three-second on_stop to the end" "no $WORK/one.stopped after 8 s"; fi

"$BIN" create server two -p "$((P + 1))" --bind 127.0.0.1 --lua "$WORK/two.lua" -s >/dev/null 2>&1 || true
kill -TERM "$SOCKETLEY_DPID" 2>/dev/null || true
if wait_marker "$WORK/two.stopped"; then pass
else fail "a graceful daemon shutdown lets on_stop run past the daemon's own exit" "no $WORK/two.stopped after 8 s"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
