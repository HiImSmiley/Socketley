"""Hold an idle TCP connection open and answer questions about it.

A connection that sends nothing is the whole point here, so this cannot be
`nc` or `curl` -- both of them either write something or close, and either
one hides exactly the case under test.

Subcommands, each printing one line the shell can compare against:

  hold <host> <port> <seconds>
      Connect, send nothing, stay.  Prints "connected" once the handshake is
      done, then "held" when the time is up.  Used with & so the shell can
      look at the server while it is open.

  eof <host> <port> <deadline_s> <trigger-command...>
      Connect, send nothing, run the trigger (which is expected to make the
      server go away), then wait for the connection to end.  Prints
      "eof <seconds>" if the peer closed or reset, "timeout" if nothing
      happened within the deadline.

      This is the assertion the SYN-RECV bug fails: a connection the server
      never accepted is a request sock, and when the listener closes the
      kernel drops it with no FIN and no RST.  Nothing reaches the client,
      which holds an ESTABLISHED socket against a peer that does not exist.
      There is no SO_KEEPALIVE either, so "until it next writes" means
      forever for an idle client.
"""
import socket
import subprocess
import sys
import time


def hold(host, port, seconds):
    s = socket.create_connection((host, int(port)), timeout=10)
    print("connected", flush=True)
    time.sleep(float(seconds))
    print("held", flush=True)
    s.close()


def eof(host, port, deadline, trigger):
    s = socket.create_connection((host, int(port)), timeout=10)
    # Long enough for the server to have accepted on any build that accepts at
    # all, short enough that the trigger still lands inside the deferral window
    # on one that does not.
    time.sleep(1.0)
    subprocess.run(trigger, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.monotonic()
    s.settimeout(float(deadline))
    try:
        data = s.recv(64)
    except socket.timeout:
        print("timeout", flush=True)
        return
    except OSError:
        # A reset is the peer telling us, which is the thing being asserted.
        print(f"eof {time.monotonic() - t0:.2f}", flush=True)
        return
    if data == b"":
        print(f"eof {time.monotonic() - t0:.2f}", flush=True)
    else:
        print(f"data {data!r}", flush=True)
    s.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: lib_idle_conn.py hold|eof ...")
    if sys.argv[1] == "hold":
        hold(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "eof":
        eof(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
    else:
        raise SystemExit(f"unknown subcommand: {sys.argv[1]}")
