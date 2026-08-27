#!/usr/bin/env python3
"""A WebSocket client in one file, so run.sh can prove the socket works.

Not a library: it does the RFC 6455 handshake, sends masked text frames and
reads unmasked ones, and understands nothing else.  A browser is the real
client -- this exists so the example can be verified without one.
"""
import base64, os, socket, struct, sys


def connect(host, port, timeout=5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(
        f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\nOrigin: http://{host}:{port}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise RuntimeError("closed during handshake")
        buf += chunk
    if b"101" not in buf.split(b"\r\n")[0]:
        raise RuntimeError("no upgrade: " + buf.split(b"\r\n")[0].decode())
    return s, buf.split(b"\r\n\r\n", 1)[1]


def send(s, text):
    payload = text.encode()
    mask = os.urandom(4)
    head = b"\x81"
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def frames(s, rest=b"", budget=1.5):
    """Yield text payloads until the socket goes quiet for `budget` seconds."""
    s.settimeout(budget)
    buf = rest
    while True:
        while len(buf) >= 2:
            b1, b2 = buf[0], buf[1]
            n, off = b2 & 0x7F, 2
            if n == 126:
                if len(buf) < 4: break
                n, off = struct.unpack(">H", buf[2:4])[0], 4
            elif n == 127:
                if len(buf) < 10: break
                n, off = struct.unpack(">Q", buf[2:10])[0], 10
            if len(buf) < off + n: break
            payload, buf = buf[off:off + n], buf[off + n:]
            if b1 & 0x0F == 0x8:          # close
                return
            if b1 & 0x0F == 0x1:
                yield payload.decode(errors="replace")
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return
        if not chunk:
            return
        buf += chunk


if __name__ == "__main__":
    host, port = sys.argv[1], int(sys.argv[2])
    sock, rest = connect(host, port)
    for line in sys.argv[3:]:
        send(sock, line)
    for text in frames(sock, rest):
        for l in text.split("\n"):
            if l:
                print(l)
    sock.close()
