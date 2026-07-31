"""probe.py <bin> <port> <beport> <cycles> <rts> <conns> <payload> <prefix> <mode>

mode: churn  -> create/serve/remove each cycle  (healthy)
      hold   -> create/serve, never remove      (simulates 1 leaked instance/cycle)

hold uses a fresh port per cycle so every instance can stay alive.
"""
import socket
import subprocess
import sys
import time

BIN = sys.argv[1]
PORT = int(sys.argv[2])
BE_PORT = int(sys.argv[3])
CYCLES = int(sys.argv[4])
RTS = int(sys.argv[5])
CONNS = int(sys.argv[6])
PAY = int(sys.argv[7])
PREFIX = sys.argv[8]
MODE = sys.argv[9]

KINDS = ["cache", "server", "proxy"]
if len(sys.argv) > 10 and sys.argv[10] != "all":
    KINDS = [sys.argv[10]]


def connect_ok(port, deadline):
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            return True
        except OSError:
            time.sleep(0.02)
    return False


def connect_refused(port, deadline):
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            time.sleep(0.01)
        except OSError:
            return True
    return False


def open_many(port, k):
    out = []
    for _ in range(k):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.settimeout(3)
            out.append(s)
        except OSError:
            pass
    return out


def close_many(socks):
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


def read_lines(s, n):
    buf = b""
    out = []
    while len(out) < n:
        try:
            chunk = s.recv(262144)
        except OSError:
            return out
        if not chunk:
            return out
        buf += chunk
        while b"\n" in buf and len(out) < n:
            line, buf = buf.split(b"\n", 1)
            out.append(line.rstrip(b"\r"))
    return out


def rt_cache(port, n, k, pay):
    socks = open_many(port, k)
    ok = 0
    val = "v" * pay
    for i in range(n):
        for j, s in enumerate(socks):
            try:
                s.sendall(("set k%d_%d %s\nget k%d_%d\n" % (j, i, val, j, i)).encode())
            except OSError:
                pass
        for s in socks:
            lines = read_lines(s, 2)
            if len(lines) == 2 and lines[0] == b"ok" and lines[1] == val.encode():
                ok += 1
    close_many(socks)
    return ok


def rt_proxy(port, n, k, pay):
    socks = open_many(port, k)
    ok = 0
    for i in range(n):
        msgs = []
        for j, s in enumerate(socks):
            m = "p%d-%d-%s" % (j, i, "y" * pay)
            msgs.append(m)
            try:
                s.sendall((m + "\n").encode())
            except OSError:
                pass
        for j, s in enumerate(socks):
            lines = read_lines(s, 1)
            if lines and lines[0] == msgs[j].encode():
                ok += 1
    close_many(socks)
    return ok


def rt_server(port, n, k, pay):
    socks = open_many(port, k)
    ok = 0
    for i in range(n):
        for j, s in enumerate(socks):
            try:
                s.sendall(("s%d-%d-%s\n" % (j, i, "z" * pay)).encode())
                ok += 1
            except OSError:
                pass
    close_many(socks)
    return ok


VERIFY = {"cache": rt_cache, "server": rt_server, "proxy": rt_proxy}


def run_cli(*args):
    try:
        r = subprocess.run([BIN] + list(args), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
        return r.returncode
    except Exception:
        return -1


created = served = removed = closed = ops = 0
t0 = time.time()
for i in range(CYCLES):
    kind = KINDS[i % len(KINDS)]
    name = "%s%02d" % (PREFIX, i)
    port = PORT if MODE == "churn" else PORT + 1 + i

    args = ["create", kind, name, "-p", str(port)]
    if kind == "proxy":
        args += ["--backend", "127.0.0.1:%d" % BE_PORT, "--protocol", "tcp"]
    args.append("-s")

    rc = run_cli(*args)
    if rc == 0 and connect_ok(port, time.time() + 5.0):
        created += 1

    got = VERIFY[kind](port, RTS, CONNS, PAY)
    ops += got
    if got == RTS * CONNS:
        served += 1

    if MODE == "churn":
        if i % 2 == 1:
            run_cli("stop", name)
            time.sleep(0.05)
        if run_cli("remove", name) == 0:
            removed += 1
        if connect_refused(port, time.time() + 3.0):
            closed += 1

print("TOTALS cycles=%d created=%d served=%d removed=%d closed=%d ops=%d secs=%.2f"
      % (CYCLES, created, served, removed, closed, ops, time.time() - t0))
