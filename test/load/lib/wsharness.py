#!/usr/bin/env python3
"""WebSocket through the proxy, with every echo checked against what was sent.

The proxy runs in http mode; the upgrade passes through it and the connection
then carries frames rather than requests, which is a different path through the
read handlers than either plain HTTP or splice.

Same marker scheme as the HTTP harness: "<connection>-<sequence>", so a frame
delivered on the wrong connection is distinguishable from one that is merely
late or missing.
"""
import argparse, asyncio, base64, hashlib, os, struct, sys, re

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_key(key: bytes) -> bytes:
    return base64.b64encode(hashlib.sha1(key + GUID).digest())


def encode(payload: bytes, mask: bool) -> bytes:
    head = bytearray([0x81])
    n = len(payload)
    mb = 0x80 if mask else 0x00
    if n < 126:
        head.append(mb | n)
    elif n < 65536:
        head.append(mb | 126); head += struct.pack("!H", n)
    else:
        head.append(mb | 127); head += struct.pack("!Q", n)
    if not mask:
        return bytes(head) + payload
    m = os.urandom(4)
    head += m
    return bytes(head) + bytes(b ^ m[i % 4] for i, b in enumerate(payload))


async def read_frame(reader):
    hdr = await reader.readexactly(2)
    masked = bool(hdr[1] & 0x80)
    n = hdr[1] & 0x7F
    if n == 126:
        n = struct.unpack("!H", await reader.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", await reader.readexactly(8))[0]
    m = await reader.readexactly(4) if masked else None
    data = await reader.readexactly(n)
    if m:
        data = bytes(b ^ m[i % 4] for i, b in enumerate(data))
    return hdr[0] & 0x0F, data


async def backend(port):
    async def handle(reader, writer):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                head += chunk
            m = re.search(rb"Sec-WebSocket-Key:\s*(\S+)", head, re.I)
            if not m:
                return
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\nSec-WebSocket-Accept: " +
                         accept_key(m.group(1)) + b"\r\n\r\n")
            await writer.drain()
            while True:
                op, data = await read_frame(reader)
                if op == 0x8:
                    return
                writer.write(encode(data, mask=False))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    async with server:
        await server.serve_forever()


async def client(cid, port, count, results, prefix=""):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16))
        writer.write(b"GET " + (prefix.encode() or b"/") + b" HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                     b"Connection: Upgrade\r\nSec-WebSocket-Key: " + key +
                     b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        await writer.drain()
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
            if not chunk:
                results.append(("upgrade-failed", cid, -1, "")); return
            head += chunk
        if b"101" not in head.split(b"\r\n")[0]:
            results.append(("upgrade-rejected", cid, -1, head[:40].decode("latin1"))); return

        for seq in range(count):
            marker = f"{cid}-{seq}".encode()
            writer.write(encode(marker, mask=True))
            await writer.drain()
            _, got = await asyncio.wait_for(read_frame(reader), timeout=5)
            if got != marker:
                g = got.decode("latin1", "replace")
                kind = ("crossed" if re.fullmatch(r"\d+-\d+", g) and int(g.split("-")[0]) != cid
                        else "wrong-seq" if re.fullmatch(r"\d+-\d+", g) else "garbled")
                results.append((kind, cid, seq, g)); return
    except asyncio.TimeoutError:
        results.append(("timeout", cid, -1, ""))
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        results.append(("reset", cid, -1, ""))
    except Exception as e:
        results.append(("error", cid, -1, repr(e)[:60]))
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["backend", "drive"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--clients", type=int, default=20)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--prefix", default="")
    a = ap.parse_args()

    if a.mode == "backend":
        await backend(a.port); return 0

    results = []
    await asyncio.gather(*(client(c, a.port, a.count, results, a.prefix) for c in range(a.clients)))
    if not results:
        print("OK"); return 0
    kinds = {}
    for k, *_ in results:
        kinds[k] = kinds.get(k, 0) + 1
    print("FEHLER " + " ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    for r in results[:5]:
        print("   ", r)
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) or 0)
