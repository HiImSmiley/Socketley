# An interactive session driven from a test, with bounded reads.
#
# Only ever imported: `start NAME -i` holds the connection open for as long as
# the operator is there, so p.stdout.read() waits for an EOF that never comes
# and a test written the obvious way hangs instead of failing.
import os, select, subprocess, time


def session(binp, sock, name, verb="start", *flags):
    """`start NAME -i` by default; any verb that takes -i, with its own flags before it."""
    return subprocess.Popen([binp, verb, name, *flags, "-i"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            env=dict(os.environ, SOCKETLEY_SOCKET=sock))


def drain(p, secs):
    """Whatever the session has printed so far; never waits for EOF."""
    out, deadline = b"", time.time() + secs
    fd = p.stdout.fileno()
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if not r:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        out += chunk
    return out.decode(errors="replace")


def say(p, line):
    p.stdin.write(line.encode() + b"\n")
    p.stdin.flush()
