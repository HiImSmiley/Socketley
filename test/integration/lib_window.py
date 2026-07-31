#!/usr/bin/env python3
# Window arithmetic over a load driver's event stream.  Sourced through
# lib_window.sh, which is where the rationale is written down; this file is the
# part that has to read a growing file efficiently and count precisely.
#
# The stream is two line kinds, whitespace separated, appended as they happen:
#
#     CONN <cid> <t_open>
#     EV   <t_send> <t_done> <kind> <backend> <cid>
#
# A request belongs to a window [a, b) only when BOTH its timestamps fall inside
# it.  One that was sent before the window opened, or answered after it closed,
# straddles a boundary and belongs to neither side: attributing it to either one
# is how a phase that was measured before a change took effect gets reported as
# though it were measured after.  Straddlers are counted and printed separately,
# so nothing is silently dropped.
#
# t_open is what makes "on connections that already existed" checkable.  A
# driver that reconnects after a hard error would otherwise answer a question
# about membership with a connection opened after the membership changed, which
# any implementation passes.
import re
import subprocess
import sys
import time
from collections import Counter


class Tail:
    """Reads the lines appended to a file since the last call.

    Re-reading the whole file every poll costs more than the load being measured
    once the stream is six figures of events long -- and it is the measuring
    process that would be stealing the CPU.  Binary mode so tell()/seek()
    arithmetic on a partially written last line is exact.
    """

    def __init__(self, path):
        self.path, self.f = path, None

    def lines(self):
        if self.f is None:
            try:
                self.f = open(self.path, "rb")
            except OSError:
                return
        while True:
            line = self.f.readline()
            if not line:
                return
            if not line.endswith(b"\n"):
                self.f.seek(-len(line), 1)   # half-written; wait for the rest
                return
            yield line.decode("latin1").split()


def parse(path):
    conns, evs = {}, []
    try:
        f = open(path, "rb")
    except OSError:
        return conns, evs
    with f:
        for raw in f:
            p = raw.decode("latin1").split()
            try:
                if len(p) == 3 and p[0] == "CONN":
                    conns[p[1]] = float(p[2])
                elif len(p) == 6 and p[0] == "EV":
                    evs.append((float(p[1]), float(p[2]), p[3], p[4], p[5]))
            except ValueError:
                pass
    return conns, evs


def wait_events(path, since, min_events, min_secs, timeout):
    """Wait until the window that opened at `since` holds enough traffic.

    Two floors, because either alone lies.  A count alone would close the
    window after a few milliseconds on an idle machine, measuring a burst
    rather than a steady state; a duration alone is exactly the wall-clock
    window this file exists to replace, and measures nothing when the machine
    is slow.  Whichever floor is the binding one, the window carries traffic.
    """
    tail, seen, end = Tail(path), 0, time.time() + timeout
    while True:
        for p in tail.lines():
            if len(p) == 6 and p[0] == "EV":
                try:
                    if float(p[1]) >= since:
                        seen += 1
                except ValueError:
                    pass
        if seen >= min_events and time.time() - since >= min_secs:
            print(seen)
            return 0
        if time.time() >= end:
            print(seen)
            return 1
        time.sleep(0.05)


def wait_backend(path, be, since, timeout):
    """Wait for the first response a given member served at or after `since`.

    The data-plane half of a membership anchor: the control plane saying a
    member has joined is not the same claim as the gateway sending it work.
    Prints the timestamp of that response, which is where the window opens.
    """
    tail, end = Tail(path), time.time() + timeout
    while True:
        for p in tail.lines():
            if len(p) == 6 and p[0] == "EV" and p[3] == "ok":
                try:
                    t = float(p[1])
                except ValueError:
                    continue
                if t >= since and (be == "any" or p[4] == be):
                    print(repr(float(p[2])))
                    return 0
        if time.time() >= end:
            return 1
        time.sleep(0.05)


def wait_drained(path, be, since, clear_n, timeout):
    """Wait until a member has stopped serving: `clear_n` consecutive responses
    from anyone else, none of them its.

    Counted in responses rather than seconds because that is the unit the claim
    is in -- "no request goes there any more" is about requests, and a second of
    silence on a stalled machine is no evidence at all.  Only successful
    responses count, so a gateway that answers everything 504 never satisfies
    this and the caller reports the timeout as the failure it is.

    Prints the moment the drain completed, which is the earliest instant from
    which "it serves nothing" can be asserted about the whole window.
    """
    tail, clear, end = Tail(path), 0, time.time() + timeout
    while True:
        for p in tail.lines():
            if len(p) == 6 and p[0] == "EV" and p[3] == "ok":
                try:
                    t = float(p[1])
                except ValueError:
                    continue
                if t < since:
                    continue
                if p[4] == be:
                    clear = 0
                else:
                    clear += 1
                    if clear >= clear_n:
                        print(repr(float(p[2])))
                        return 0
        if time.time() >= end:
            return 1
        time.sleep(0.05)


def wait_output(timeout, pattern, cmd):
    """Wait for a command's own output to say the change has landed.

    The control-plane half of a membership anchor, and the only one that can be
    asked before any traffic has proved it: the daemon either lists the runtime
    as running or it does not.  A pattern prefixed with '!' waits for it to stop
    matching, which is how a member leaving is observed.
    """
    negate = pattern.startswith("!")
    # Multiline, because what is being matched is a stats block or a table and
    # the interesting patterns are anchored to a line of it.
    rx = re.compile(pattern[1:] if negate else pattern, re.M)
    end = time.time() + timeout
    while True:
        try:
            out = subprocess.run(cmd, capture_output=True, timeout=10).stdout.decode("latin1")
        except Exception:
            out = ""
        if bool(rx.search(out)) != negate:
            print(repr(time.time()))
            return 0
        if time.time() >= end:
            return 1
        time.sleep(0.1)


def report(path, windows):
    """One line per window: what it carried, and what it carried on connections
    that already existed when the change being measured was asked for.

    `pre` is counted against that instant rather than against the window start,
    because the window opens once the change has landed -- by then a client
    whose connection the change broke has already reconnected, and a connection
    opened after a membership change tells you nothing about whether the gateway
    re-reads membership on connections it did not open.
    """
    conns, evs = parse(path)
    for label, a, b, pre_epoch in windows:
        kinds, bes, prebes = Counter(), Counter(), Counter()
        pre = preok = straddle = 0
        for t_send, t_done, kind, be, cid in evs:
            if t_done < a or t_send >= b:
                continue                      # wholly outside
            if t_send < a or t_done >= b:
                straddle += 1                 # crosses a boundary: neither side
                continue
            kinds[kind] += 1
            old = conns.get(cid, float("inf")) < pre_epoch
            if old:
                pre += 1
            if kind == "ok" and be != "-":
                bes[be] += 1
                if old:
                    prebes[be] += 1
                    preok += 1
        total = sum(kinds.values())
        span = max(b - a, 1e-6)
        print(f"WINDOW {label} span={int(span * 1000)}ms total={total} "
              f"ok={kinds.get('ok', 0)} rate={int(total / span)} "
              f"straddle={straddle} pre={pre} preok={preok} "
              f"be:{','.join(f'{k}={v}' for k, v in sorted(bes.items())) or 'none'} "
              f"prebe:{','.join(f'{k}={v}' for k, v in sorted(prebes.items())) or 'none'} "
              f"kinds:{','.join(f'{k}={v}' for k, v in sorted(kinds.items()) if k != 'ok') or 'none'}")


def detail(path, a, b, limit=6):
    """The failures inside a window, one line each, with how long each waited.

    A count says a request was lost; this says how.  "dropped after 2.00s" is
    the proxy's backend deadline expiring on a connect that never completed --
    response_deadline_sweep closes the pair without answering -- while "dropped
    after 0.00s" is the connection going away underneath a request that had only
    just been written.  The two have nothing to do with each other, and a test
    that prints only "missing=1" makes the reader guess which one it saw.
    """
    conns, evs = parse(path)
    shown = 0
    for t_send, t_done, kind, be, cid in sorted(evs):
        if kind == "ok" or t_send < a or t_done >= b:
            continue
        print(f"       {kind} at +{t_send - a:.3f}s into the window, waited "
              f"{t_done - t_send:.3f}s, on a connection {t_send - conns.get(cid, t_send):.1f}s old")
        shown += 1
        if shown >= limit:
            break


def main(argv):
    cmd = argv[1]
    if cmd == "now":
        print(repr(time.time()))
        return 0
    if cmd == "wait-events":
        return wait_events(argv[2], float(argv[3]), int(argv[4]), float(argv[5]), float(argv[6]))
    if cmd == "wait-backend":
        return wait_backend(argv[2], argv[3], float(argv[4]), float(argv[5]))
    if cmd == "wait-drained":
        return wait_drained(argv[2], argv[3], float(argv[4]), int(argv[5]), float(argv[6]))
    if cmd == "wait-output":
        return wait_output(float(argv[2]), argv[3], argv[4:])
    if cmd == "detail":
        detail(argv[2], float(argv[3]), float(argv[4]))
        return 0
    if cmd == "report":
        wins = []
        for spec in argv[3:]:
            p = spec.split(":")
            # label:from:to[:pre-epoch] -- the fourth field defaults to the
            # window start, which is what a window measuring no change wants.
            wins.append((p[0], float(p[1]), float(p[2]),
                         float(p[3]) if len(p) > 3 else float(p[1])))
        report(argv[2], wins)
        return 0
    sys.stderr.write(f"unknown command {cmd}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
