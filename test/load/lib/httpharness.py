#!/usr/bin/env python3
"""HTTP through the proxy, with every response checked against what was asked for.

Each request carries a marker of the form "<connection>-<sequence>".  The
backend echoes it back as the body.  A client therefore knows exactly what it
must receive next, which makes four different failures distinguishable instead
of all looking like "slow":

  missing    the response never arrived
  wrong-seq  a response arrived out of order on its own connection
  crossed    a response belonging to a *different* connection arrived here
  garbled    the body did not match any marker at all

"crossed" is the interesting one: that is what a stale descriptor looks like
from the outside.
"""
import argparse, asyncio, re, sys

BODY_RE = re.compile(rb"\r\n\r\n(.*)", re.S)


async def backend(port, ready):
    async def handle(reader, writer):
        buf = b""
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n\r\n" in buf:
                    head, buf = buf.split(b"\r\n\r\n", 1)
                    line = head.split(b"\r\n", 1)[0]
                    parts = line.split(b" ")
                    marker = parts[1].lstrip(b"/") if len(parts) > 1 else b"?"
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                                 b"Connection: keep-alive\r\n\r\n%s" % (len(marker), marker))
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    ready.set()
    async with server:
        await server.serve_forever()


async def client(cid, port, count, results, prefix=""):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=5)
    except Exception:
        results.append(("connect-failed", cid, -1, ""))
        return

    try:
        for seq in range(count):
            marker = f"{cid}-{seq}".encode()
            writer.write(b"GET " + prefix.encode() + b"/" + marker + b" HTTP/1.1\r\n"
                         b"Host: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
            await writer.drain()

            head = b""
            while b"\r\n\r\n" not in head:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=5)
                if not chunk:
                    results.append(("missing", cid, seq, ""))
                    return
                head += chunk
            body_start = head.split(b"\r\n\r\n", 1)[1]
            m = re.search(rb"Content-Length: (\d+)", head)
            need = int(m.group(1)) if m else len(marker)
            while len(body_start) < need:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=5)
                if not chunk:
                    results.append(("missing", cid, seq, ""))
                    return
                body_start += chunk
            got = body_start[:need]

            if got != marker:
                got_s = got.decode("latin1", "replace")
                if re.fullmatch(r"\d+-\d+", got_s):
                    other = int(got_s.split("-")[0])
                    kind = "crossed" if other != cid else "wrong-seq"
                else:
                    kind = "garbled"
                results.append((kind, cid, seq, got_s))
                return
    except asyncio.TimeoutError:
        results.append(("timeout", cid, -1, ""))
    except (ConnectionResetError, BrokenPipeError):
        results.append(("reset", cid, -1, ""))
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
        ready = asyncio.Event()
        await backend(a.port, ready)
        return

    results = []
    await asyncio.gather(*(client(c, a.port, a.count, results, a.prefix) for c in range(a.clients)))
    if not results:
        print("OK")
        return 0
    kinds = {}
    for k, cid, seq, got in results:
        kinds[k] = kinds.get(k, 0) + 1
    print("FEHLER " + " ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    for r in results[:5]:
        print("   ", r)
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) or 0)
