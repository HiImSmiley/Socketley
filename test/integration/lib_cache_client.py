#!/usr/bin/env python3
# A client for the cluster cache tests -- only ever run by them.  It speaks the text protocol (`set k v` answers `ok`, `get k` answers the value or `nil`) to
# a target given as host:port or unix:/path, and does five things:
#
#   writer <acked-file> <target>...   writes w0, w1, ... to the first target that says ok, moving to the next on any other answer, and
#                                     records "<index> <wall ns>" for every write acknowledged, until it is killed
#   burst <acked-file> <n> <target>...   the same, with n writes pipelined at a time and no pause, which is as fast as one connection goes
#   check <acked-file> <target> <ns> <kill-ns>
#                                     reads every acknowledged key back from one target and prints how many are missing, how many of
#                                     those were acknowledged before the wall time `ns`, and how many keys are present that were
#                                     acknowledged before `kill-ns` (the kill) and after one that is missing: a hole, 0 meaning what
#                                     survived is a prefix of the old primary's history.  Writes acknowledged after the kill are the
#                                     new primary's own.
#   probe <tag> <target>...           writes one key to each target and prints "<target> ok|<reason>" for each, so the caller can count the
#                                     replicas that take writes at one instant
#   cmd <target> <line>               one command, printing the reply line or "!<why>"
#
# The timeouts are short on purpose: a killed primary must show as a refusal in a fraction of a second, not hang the caller.
import socket
import sys
import time


def dial(target, timeout):
    if target.startswith("unix:"):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(timeout)
        s.connect(target[5:])
    else:
        host, port = target.rsplit(":", 1)
        s = socket.create_connection((host, int(port)), timeout=timeout)
    return s


def ask(f, line):
    f.write((line + "\n").encode())
    f.flush()
    reply = f.readline()
    if not reply:
        raise EOFError("closed")
    return reply.decode("latin1").rstrip("\r\n")


def writer(acked_path, targets):
    out = open(acked_path, "a", buffering=1)
    i, at = 0, 0
    conn = None
    while True:
        try:
            if conn is None:
                conn = dial(targets[at % len(targets)], 0.4)
                f = conn.makefile("rwb", buffering=0)
            reply = ask(f, "set w%d %d" % (i, i))
            if reply == "ok":
                out.write("%d %d\n" % (i, time.time_ns()))
                i += 1
                time.sleep(0.0005)
                continue
        except (OSError, EOFError):
            pass
        # Anything but an acknowledgement: this target is not the one taking writes, so try the next.
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
        conn = None
        at += 1
        time.sleep(0.02)


def burst(acked_path, batch, targets):
    out = open(acked_path, "a", buffering=1)
    i, at = 0, 0
    conn = None
    while True:
        try:
            if conn is None:
                conn = dial(targets[at % len(targets)], 0.4)
                f = conn.makefile("rwb", buffering=0)
            f.write("".join("set w%d %d\n" % (i + k, i + k) for k in range(batch)).encode())
            good = 0
            for k in range(batch):
                reply = f.readline()
                if not reply:
                    raise EOFError("closed")
                if reply.rstrip(b"\r\n") == b"ok":
                    good += 1
            now = time.time_ns()
            out.write("".join("%d %d\n" % (i + k, now) for k in range(good)))
            i += good
            if good == batch:
                continue
        except (OSError, EOFError):
            pass
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
        conn = None
        at += 1
        time.sleep(0.02)


def check(acked_path, target, cutoff_ns, kill_ns):
    acked = []
    with open(acked_path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 2:
                acked.append((int(parts[0]), int(parts[1])))
    conn = dial(target, 5.0)
    f = conn.makefile("rwb", buffering=0)
    missing = []
    holes = 0
    for start in range(0, len(acked), 400):
        batch = acked[start:start + 400]
        f.write("".join("get w%d\n" % i for i, _ in batch).encode())
        for i, at in batch:
            reply = f.readline().decode("latin1").rstrip("\r\n")
            if reply != str(i):
                missing.append((i, at))
            elif missing and at < kill_ns:
                holes += 1
    early = [m for m in missing if m[1] < cutoff_ns]
    print("acked=%d missing=%d missing_before_cutoff=%d holes=%d" % (len(acked), len(missing), len(early), holes))


def probe(tag, targets):
    for n, target in enumerate(targets):
        try:
            conn = dial(target, 0.4)
            f = conn.makefile("rwb", buffering=0)
            reply = ask(f, "set probe-%s-%d 1" % (tag, n))
            print("%s %s" % (target, "ok" if reply == "ok" else reply.replace(" ", "_")))
            conn.close()
        except (OSError, EOFError) as e:
            print("%s down" % target)


def cmd(target, line):
    try:
        conn = dial(target, 2.0)
        f = conn.makefile("rwb", buffering=0)
        print(ask(f, line))
    except (OSError, EOFError) as e:
        print("!%s" % e)


if __name__ == "__main__":
    what = sys.argv[1]
    if what == "writer":
        writer(sys.argv[2], sys.argv[3:])
    elif what == "burst":
        burst(sys.argv[2], int(sys.argv[3]), sys.argv[4:])
    elif what == "check":
        check(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    elif what == "probe":
        probe(sys.argv[2], sys.argv[3:])
    elif what == "cmd":
        cmd(sys.argv[2], " ".join(sys.argv[3:]))
    else:
        sys.exit(2)
