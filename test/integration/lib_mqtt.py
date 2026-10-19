# An MQTT client of the tests' own, for 3.1, 3.1.1 and 5.0 over TCP, TLS and WebSocket, which says exactly what
# went over the wire -- a library client hides the packets a broker gets wrong.
import base64
import os
import select
import socket
import ssl
import struct
import time

CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP = 1, 2, 3, 4, 5, 6, 7
SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT, AUTH = 8, 9, 10, 11, 12, 13, 14, 15

# Properties of 5.0 by identifier, with how each is written.
PROPS = {
    0x01: "byte", 0x02: "u32", 0x03: "str", 0x08: "str", 0x09: "bin", 0x0B: "var", 0x11: "u32", 0x12: "str",
    0x13: "u16", 0x15: "str", 0x16: "bin", 0x17: "byte", 0x18: "u32", 0x19: "byte", 0x1A: "str", 0x1C: "str",
    0x1F: "str", 0x21: "u16", 0x22: "u16", 0x23: "u16", 0x24: "byte", 0x25: "byte", 0x26: "pair", 0x27: "u32",
    0x28: "byte", 0x29: "byte", 0x2A: "byte",
}
PAYLOAD_FORMAT, MESSAGE_EXPIRY, CONTENT_TYPE, RESPONSE_TOPIC, CORRELATION = 0x01, 0x02, 0x03, 0x08, 0x09
SUB_ID, SESSION_EXPIRY, ASSIGNED_ID, SERVER_KEEPALIVE, AUTH_METHOD = 0x0B, 0x11, 0x12, 0x13, 0x15
WILL_DELAY, REASON_STRING, RECEIVE_MAX, ALIAS_MAX, ALIAS, MAX_QOS = 0x18, 0x1F, 0x21, 0x22, 0x23, 0x24
RETAIN_AVAILABLE, USER_PROPERTY, MAX_PACKET, WILDCARD_AVAILABLE, SUBID_AVAILABLE, SHARED_AVAILABLE = (
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2A)


class Closed(Exception):
    pass


def varint(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def s(text):
    b = text.encode() if isinstance(text, str) else text
    return struct.pack(">H", len(b)) + b


def prop_bytes(p):
    if p is None:
        p = {}
    out = bytearray()
    for k, v in p.items():
        kind = PROPS[k]
        vals = v if kind == "pair" or (k == SUB_ID and isinstance(v, list)) else [v]
        for one in vals:
            out += varint(k)
            if kind == "byte":
                out += bytes([one])
            elif kind == "u16":
                out += struct.pack(">H", one)
            elif kind == "u32":
                out += struct.pack(">I", one)
            elif kind == "var":
                out += varint(one)
            elif kind in ("str", "bin"):
                out += s(one)
            elif kind == "pair":
                out += s(one[0]) + s(one[1])
    return varint(len(out)) + bytes(out)


class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def left(self):
        return len(self.b) - self.i

    def u8(self):
        self.i += 1
        return self.b[self.i - 1]

    def u16(self):
        self.i += 2
        return struct.unpack(">H", self.b[self.i - 2:self.i])[0]

    def u32(self):
        self.i += 4
        return struct.unpack(">I", self.b[self.i - 4:self.i])[0]

    def var(self):
        n, mul = 0, 1
        while True:
            c = self.u8()
            n += (c & 0x7F) * mul
            if not c & 0x80:
                return n
            mul *= 128

    def bin(self):
        n = self.u16()
        self.i += n
        return bytes(self.b[self.i - n:self.i])

    def str(self):
        return self.bin().decode()

    def rest(self):
        r = bytes(self.b[self.i:])
        self.i = len(self.b)
        return r

    def props(self):
        n = self.var()
        end = self.i + n
        out = {}
        while self.i < end:
            k = self.var()
            kind = PROPS.get(k)
            if kind == "byte":
                v = self.u8()
            elif kind == "u16":
                v = self.u16()
            elif kind == "u32":
                v = self.u32()
            elif kind == "var":
                v = self.var()
            elif kind == "str":
                v = self.str()
            elif kind == "bin":
                v = self.bin()
            elif kind == "pair":
                v = (self.str(), self.str())
            else:
                raise ValueError("unknown property %#x" % k)
            if kind == "pair" or k == SUB_ID:
                out.setdefault(k, []).append(v)
            else:
                out[k] = v
        return out


class Packet:
    def __init__(self, kind, flags, body):
        self.kind, self.flags, self.body = kind, flags, body

    def __repr__(self):
        return "Packet(%d, %#x, %r)" % (self.kind, self.flags, self.body[:40])


class Message:
    def __init__(self, topic, payload, qos, retain, dup, pid, props):
        self.topic, self.payload, self.qos, self.retain, self.dup, self.pid, self.props = (
            topic, payload, qos, retain, dup, pid, props)

    def __repr__(self):
        return "Message(%r, %r, qos=%d, retain=%s)" % (self.topic, self.payload, self.qos, self.retain)


class WS:
    """A WebSocket carrying MQTT, with the subprotocol `mqtt`, as a browser's client opens it."""

    def __init__(self, sock, host, path, proto="mqtt"):
        self.sock = sock
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n" % (path, host, key))
        if proto:
            req += "Sec-WebSocket-Protocol: %s\r\n" % proto
        sock.sendall((req + "\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            c = sock.recv(4096)
            if not c:
                raise Closed("closed during the upgrade")
            head += c
        self.status_line, _, rest = head.partition(b"\r\n")
        self.headers = head.split(b"\r\n\r\n")[0].decode(errors="replace")
        self.buf = head.split(b"\r\n\r\n", 1)[1]
        self.data = b""
        if b" 101 " not in self.status_line:
            raise Closed("upgrade refused: " + self.status_line.decode(errors="replace"))

    def sendall(self, b, op=2):
        mask = os.urandom(4)
        n = len(b)
        if n < 126:
            h = bytes([0x80 | op, 0x80 | n])
        elif n < 65536:
            h = bytes([0x80 | op, 0x80 | 126]) + struct.pack(">H", n)
        else:
            h = bytes([0x80 | op, 0x80 | 127]) + struct.pack(">Q", n)
        self.sock.sendall(h + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(b)))

    def _frame(self):
        while True:
            if len(self.buf) >= 2:
                n = self.buf[1] & 0x7F
                off = 2
                if n == 126 and len(self.buf) >= 4:
                    n, off = struct.unpack(">H", self.buf[2:4])[0], 4
                elif n == 127 and len(self.buf) >= 10:
                    n, off = struct.unpack(">Q", self.buf[2:10])[0], 10
                if (self.buf[1] & 0x7F) < 126 or off > 2:
                    if len(self.buf) >= off + n:
                        op = self.buf[0] & 0x0F
                        body = self.buf[off:off + n]
                        self.buf = self.buf[off + n:]
                        return op, body
            c = self.sock.recv(65536)
            if not c:
                return None, b""
            self.buf += c

    def recv(self, n):
        while not self.data:
            op, body = self._frame()
            if op is None or op == 8:
                return b""
            if op == 9:
                self.sendall(body, 10)
                continue
            self.data += body
        out, self.data = self.data[:n], self.data[n:]
        return out

    def pending(self):
        inner = isinstance(self.sock, ssl.SSLSocket) and self.sock.pending()
        return bool(self.data) or len(self.buf) >= 2 or bool(inner)

    def settimeout(self, t):
        self.sock.settimeout(t)

    def fileno(self):
        return self.sock.fileno()

    def shutdown(self, how):
        self.sock.shutdown(how)

    def close(self):
        self.sock.close()


class Client:
    def __init__(self, port, host="127.0.0.1", version=5, tls=None, ws=None, timeout=5.0, server_hostname=None):
        self.version = version
        self.timeout = timeout
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls is not None:
            raw = tls.wrap_socket(raw, server_hostname=server_hostname or host)
        self.sock = WS(raw, host, ws) if ws else raw
        self.buf = b""
        self.next_pid = 1
        self.inbox = []
        self.acks = []
        self.aliases_in = {}
        self.connack = None
        self.disconnect_packet = None
        # Whether a PUBLISH of QoS 1 or 2 is answered as it arrives, which a test of the broker's window turns off.
        self.auto_ack = True

    # ── the wire ────────────────────────────────────────────────────────────

    def send_raw(self, b):
        self.sock.sendall(b)

    def send(self, kind, flags, body):
        self.send_raw(bytes([(kind << 4) | flags]) + varint(len(body)) + body)

    def _fill(self, deadline):
        buffered = getattr(self.sock, "pending", None)
        if not (buffered and buffered()):
            left = deadline - time.time()
            if left <= 0:
                return False
            r, _, _ = select.select([self.sock], [], [], left)
            if not r:
                return False
        try:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            c = self.sock.recv(65536)
        except (socket.timeout, ssl.SSLWantReadError):
            return False
        except OSError:
            raise Closed("reset")
        if not c:
            raise Closed("closed")
        self.buf += c
        return True

    def _take(self):
        b = self.buf
        if len(b) < 2:
            return None
        n, mul, i = 0, 1, 1
        while True:
            if i >= len(b):
                return None
            c = b[i]
            n += (c & 0x7F) * mul
            i += 1
            if not c & 0x80:
                break
            mul *= 128
        if len(b) < i + n:
            return None
        p = Packet(b[0] >> 4, b[0] & 0x0F, b[i:i + n])
        self.buf = b[i + n:]
        return p

    def read(self, timeout=None):
        """The next packet whatever it is, None when none comes in time; Closed when the broker closed."""
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while True:
            p = self._take()
            if p:
                return p
            if not self._fill(deadline):
                return None

    def closed_within(self, timeout):
        """Whether the broker closes the connection within `timeout`, packets before it read and kept."""
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                p = self.read(max(0.01, deadline - time.time()))
                if p:
                    self._dispatch(p)
        except Closed:
            return True
        return False

    def _dispatch(self, p):
        if p.kind == PUBLISH:
            m = self._message(p)
            self.inbox.append(m)
            if self.auto_ack:
                self.ack(m)
            return None
        if p.kind == DISCONNECT:
            self.disconnect_packet = p
            return None
        if p.kind == PUBREL:
            pid = struct.unpack(">H", p.body[:2])[0]
            self.send(PUBCOMP, 0, struct.pack(">H", pid) + (b"" if self.version < 5 else b""))
            return None
        return p

    def ack(self, m):
        if m.qos == 1:
            self.send(PUBACK, 0, struct.pack(">H", m.pid))
        elif m.qos == 2:
            self.send(PUBREC, 0, struct.pack(">H", m.pid))

    def _message(self, p):
        r = Reader(p.body)
        topic = r.str()
        qos = (p.flags >> 1) & 3
        pid = r.u16() if qos else 0
        pr = r.props() if self.version == 5 else {}
        if ALIAS in pr:
            if topic:
                self.aliases_in[pr[ALIAS]] = topic
            else:
                topic = self.aliases_in.get(pr[ALIAS], "")
        return Message(topic, r.rest(), qos, bool(p.flags & 1), bool(p.flags & 8), pid, pr)

    def expect(self, kind, timeout=None):
        """The next packet of `kind`, PUBLISHes before it kept in the inbox; None when none comes in time."""
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while True:
            p = self.read(max(0.0, deadline - time.time()))
            if p is None:
                return None
            p = self._dispatch(p)
            if p is not None and p.kind == kind:
                return p
            if p is not None:
                self.acks.append(p)

    def pid(self):
        n = self.next_pid
        self.next_pid = self.next_pid % 65535 + 1
        return n

    # ── the packets ─────────────────────────────────────────────────────────

    def connect(self, client_id="", clean=True, keepalive=60, username=None, password=None, will=None, props=None,
                expect_ack=True, timeout=None):
        """CONNECT, and the CONNACK as (session_present, reason, properties); will is (topic, payload, qos, retain[, props])."""
        if self.version == 3:
            vh = s("MQIsdp") + bytes([3])
        else:
            vh = s("MQTT") + bytes([self.version])
        flags = (0x02 if clean else 0)
        if will:
            flags |= 0x04 | (will[2] << 3) | (0x20 if will[3] else 0)
        if username is not None:
            flags |= 0x80
        if password is not None:
            flags |= 0x40
        body = vh + bytes([flags]) + struct.pack(">H", keepalive)
        if self.version == 5:
            body += prop_bytes(props)
        body += s(client_id)
        if will:
            if self.version == 5:
                body += prop_bytes(will[4] if len(will) > 4 else None)
            body += s(will[0]) + s(will[1] if isinstance(will[1], bytes) else will[1].encode())
        if username is not None:
            body += s(username)
        if password is not None:
            body += s(password if isinstance(password, bytes) else password.encode())
        self.send(CONNECT, 0, body)
        if not expect_ack:
            return None
        p = self.expect(CONNACK, timeout)
        if p is None:
            raise Closed("no CONNACK")
        r = Reader(p.body)
        present = bool(r.u8() & 1)
        code = r.u8()
        pr = r.props() if self.version == 5 and r.left() else {}
        self.connack = (present, code, pr)
        return self.connack

    def publish(self, topic, payload=b"", qos=0, retain=False, props=None, dup=False, wait=True, pid=None):
        """PUBLISH, and for QoS 1 and 2 the reason the broker answered with, its flow carried to the end."""
        if isinstance(payload, str):
            payload = payload.encode()
        flags = (qos << 1) | (1 if retain else 0) | (8 if dup else 0)
        body = s(topic)
        if qos:
            pid = pid or self.pid()
            body += struct.pack(">H", pid)
        if self.version == 5:
            body += prop_bytes(props)
        self.send(PUBLISH, flags, body + payload)
        if not qos or not wait:
            return pid
        if qos == 1:
            p = self.expect(PUBACK)
            if p is None:
                raise Closed("no PUBACK")
            return p.body[2] if len(p.body) > 2 else 0
        p = self.expect(PUBREC)
        if p is None:
            raise Closed("no PUBREC")
        code = p.body[2] if len(p.body) > 2 else 0
        if code >= 0x80:
            return code
        self.send(PUBREL, 2, struct.pack(">H", pid))
        p = self.expect(PUBCOMP)
        if p is None:
            raise Closed("no PUBCOMP")
        return code

    def subscribe(self, *filters, props=None, timeout=None):
        """SUBSCRIBE of (filter, options) pairs or bare filters at QoS 0; the SUBACK's reason codes."""
        pid = self.pid()
        body = struct.pack(">H", pid)
        if self.version == 5:
            body += prop_bytes(props)
        for f in filters:
            if isinstance(f, str):
                f = (f, 0)
            body += s(f[0]) + bytes([f[1]])
        self.send(SUBSCRIBE, 2, body)
        p = self.expect(SUBACK, timeout)
        if p is None:
            raise Closed("no SUBACK")
        r = Reader(p.body)
        r.u16()
        if self.version == 5:
            r.props()
        return list(r.rest())

    def unsubscribe(self, *filters):
        pid = self.pid()
        body = struct.pack(">H", pid)
        if self.version == 5:
            body += prop_bytes(None)
        for f in filters:
            body += s(f)
        self.send(UNSUBSCRIBE, 2, body)
        p = self.expect(UNSUBACK)
        if p is None:
            raise Closed("no UNSUBACK")
        r = Reader(p.body)
        r.u16()
        if self.version == 5:
            r.props()
            return list(r.rest())
        return []

    def ping(self):
        self.send(PINGREQ, 0, b"")
        return self.expect(PINGRESP) is not None

    def disconnect(self, reason=0, props=None):
        body = b""
        if self.version == 5 and (reason or props):
            body = bytes([reason]) + (prop_bytes(props) if props else b"")
        try:
            self.send(DISCONNECT, 0, body)
        except OSError:
            pass
        self.close()

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    # ── receiving ───────────────────────────────────────────────────────────

    def messages(self, n, timeout=None):
        """The next `n` messages, fewer when they do not come in time."""
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while len(self.inbox) < n:
            p = self.read(max(0.0, deadline - time.time()))
            if p is None:
                break
            p = self._dispatch(p)
            if p is not None:
                self.acks.append(p)
        out, self.inbox = self.inbox[:n], self.inbox[n:]
        return out

    def message(self, timeout=None):
        got = self.messages(1, timeout)
        return got[0] if got else None

    def quiet(self, timeout=0.5):
        """True when no message arrives within `timeout`."""
        return not self.messages(1, timeout)


def connected(port, client_id="", version=5, **kw):
    """A client already connected, refusing to go on when the broker said no."""
    opts = {k: kw.pop(k) for k in ("tls", "ws", "host", "timeout", "server_hostname") if k in kw}
    c = Client(port, version=version, **opts)
    present, code, pr = c.connect(client_id, **kw)
    if code != 0:
        raise Closed("CONNACK %#x" % code)
    return c


# ── what the test files share ───────────────────────────────────────────────

def check(name, got, want):
    """One line for the shell's tally: ok, or bad with what came and what was wanted."""
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))


def truth(name, cond, detail=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(detail)))


def guarded(name, fn):
    """A part of a test run, an exception in it reported as its failure rather than ending the rest."""
    try:
        fn()
    except Exception as e:
        print("bad %s: %s %s" % (name, type(e).__name__, e))


def line_client(port):
    """A connection to a runtime that speaks lines, a cache or a server."""
    c = socket.create_connection(("127.0.0.1", port), 5)
    c.settimeout(0.3)
    return c


def read_until(c, want, timeout=5):
    out = b""
    end = time.time() + timeout
    while time.time() < end and want not in out:
        try:
            got = c.recv(65536)
            if not got:
                break
            out += got
        except socket.timeout:
            pass
    return out


def stat_sum(binary, name, key):
    """A figure of `socketley stats`, summed over the shards."""
    import subprocess
    out = subprocess.run([binary, "stats", name], capture_output=True, timeout=10).stdout.decode()
    return sum(int(l.split(":", 1)[1] or 0) for l in out.splitlines() if l.startswith(key + ":"))
