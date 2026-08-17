#!/usr/bin/env python3
"""A backend that can be reached either way, so the two arms differ in one thing.

test_proxy_unix_backend.sh compares a proxy over `--backend unix:/path` against
the same proxy over `--backend 127.0.0.1:port`.  That comparison is only worth
anything if everything on the far side is identical, so this one program serves
both arms: same parsing, same body, same keep-alive behaviour, and the address
family is the only difference between the two runs of it.

It also counts accepts, into a file the test reads.  That is what makes the
connection-pool assertion possible: ten keep-alive requests through a working
pool cost one accept on the backend, and ten through a broken one cost ten.  A
test that only checked the bodies could not tell those apart -- both answer
correctly.

  lib_unix_backend.py unix <path>   <echo|http> <countfile>
  lib_unix_backend.py tcp  <port>   <echo|http> <countfile>
"""
import os
import socket
import sys
import threading

kind, addr, proto, countfile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

if kind == "unix":
    try:
        os.unlink(addr)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(addr)
else:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", int(addr)))
srv.listen(128)

accepts = 0
lock = threading.Lock()


def record():
    # Rewritten in full each time rather than appended: the test reads this
    # while the server is still running, and a partial line would read as a
    # different number rather than as an unfinished one.
    tmp = countfile + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(accepts) + "\n")
    os.replace(tmp, countfile)


with open(countfile, "w") as f:
    f.write("0\n")

# Told to the parent over stdout, so the shell can wait for the listener to be
# up instead of sleeping and hoping.
print("ready", flush=True)

BODY = b"unix-backend-body"


def serve_echo(conn):
    while True:
        data = conn.recv(65536)
        if not data:
            break
        conn.sendall(data)
    conn.close()


def serve_http(conn):
    buf = b""
    while True:
        try:
            data = conn.recv(65536)
        except OSError:
            break
        if not data:
            break
        buf += data
        while b"\r\n\r\n" in buf:
            head, buf = buf.split(b"\r\n\r\n", 1)
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n" + BODY
            )
            try:
                conn.sendall(resp)
            except OSError:
                conn.close()
                return
    conn.close()


handler = serve_echo if proto == "echo" else serve_http

while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    with lock:
        accepts += 1
        record()
    threading.Thread(target=handler, args=(conn,), daemon=True).start()
