#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a runtime that answers and closes delivers the whole answer though its client went on sending.
#
# What each part would catch:
#   * a close() with the client's later bytes still unread: the kernel answers it with a reset and throws away the
#     part of the answer it has not delivered yet, so a client reading slowly gets the answer cut short
#   * shutdown(SHUT_RD) before the close: once the FIN is out, the kernel resets the connection on the next byte the
#     client sends, with the same loss
#   * a runtime that stops reading once it decided to close, which leaves those bytes unread for the close to find
#   * the drain this needs running on: a client that keeps sending is held to the closer's bound, not for ever
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
exec 2>&1

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: an answer the runtime closes after arrives whole though the client kept sending ==="
python3 -c 'import socket' >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
daemon_isolate unread
unset SOCKETLEY_CONFIG
trap daemon_stop EXIT
T="$SOCKETLEY_TMPD"
mkdir -p "$T/www" "$T/st" "$T/site"
SIZE=$((6 * 1024 * 1024))
head -c "$SIZE" /dev/urandom >"$T/www/big.bin"
cp "$T/www/big.bin" "$T/site/big.bin"

# One connection: the request, then a few bytes more every 50 ms until the end, read behind a small receive buffer
# after a second of not reading at all.  Prints how much of the answer came and how it ended.
cat >"$T/client.py" <<'PY'
import socket, struct, sys, threading, time

mode, port = sys.argv[1], int(sys.argv[2])

def connect():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.settimeout(30)
    s.connect(("127.0.0.1", port))
    return s

def keep_sending(s, extra):
    stop = threading.Event()
    def run():
        while not stop.is_set():
            try:
                s.send(extra)
            except OSError:
                break
            time.sleep(0.05)
    threading.Thread(target=run, daemon=True).start()
    time.sleep(1.0)
    return stop

def drain(s, got=b""):
    try:
        while True:
            b = s.recv(1 << 20)
            if not b:
                return got, "eof"
            got += b
    except ConnectionResetError:
        return got, "reset"
    except socket.timeout:
        return got, "timeout"

def mqtt_packet(kind, body, flags=0):
    n, var = len(body), bytearray()
    while True:
        b, n = n % 128, n // 128
        var.append(b | (0x80 if n else 0))
        if not n:
            break
    return bytes([kind << 4 | flags]) + bytes(var) + body

def mqtt_connect(s, cid):
    var = struct.pack("!H", 4) + b"MQTT" + bytes([4, 2]) + struct.pack("!H", 60)
    s.sendall(mqtt_packet(1, var + struct.pack("!H", len(cid)) + cid))
    got = b""
    while len(got) < 4:
        got += s.recv(4 - len(got))

if mode == "http":
    path, host = sys.argv[3], sys.argv[4]
    s = connect()
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)).encode())
    stop = keep_sending(s, b"xxxxxxxx")
    got, how = drain(s)
    stop.set()
    print(len(got.partition(b"\r\n\r\n")[2]), how)
elif mode == "resp-set":
    s = socket.create_connection(("127.0.0.1", port), 10)
    n, size = int(sys.argv[3]), int(sys.argv[4])
    for i in range(n):
        s.sendall(b"*3\r\n$3\r\nSET\r\n$2\r\nk%c\r\n$%d\r\n" % (97 + i, size) + bytes([i]) * size + b"\r\n")
    got = b""
    while got.count(b"\r\n") < n:
        got += s.recv(64)
    print(got.decode().split("\r\n")[-2])
elif mode == "resp":
    n, size = int(sys.argv[3]), int(sys.argv[4])
    s = connect()
    s.sendall(b"*%d\r\n$4\r\nMGET\r\n" % (n + 1) + b"".join(b"$2\r\nk%c\r\n" % (97 + i) for i in range(n)) +
              b"*1\r\n$4\r\nQUIT\r\n")
    stop = keep_sending(s, b"*1\r\n$4\r\nPING\r\n")
    got, how = drain(s)
    stop.set()
    # The values' bytes, and the QUIT's +OK behind them.
    whole = got.endswith(b"+OK\r\n")
    print(sum(len(got.split(b"\r\n")[2 + 2 * i]) for i in range(n)) if whole and got.count(b"\r\n") >= 2 * n + 1
          else -len(got), how)
elif mode == "mqtt-retain":
    s = socket.create_connection(("127.0.0.1", port), 10)
    mqtt_connect(s, b"loader")
    n, size = int(sys.argv[3]), int(sys.argv[4])
    for i in range(n):
        topic = b"big/%d" % i
        s.sendall(mqtt_packet(3, struct.pack("!H", len(topic)) + topic + bytes([i % 256]) * size, flags=1))
    s.sendall(b"\xe0\x00")
    time.sleep(0.3)
    print("ok")
elif mode == "mqtt":
    n, size = int(sys.argv[3]), int(sys.argv[4])
    s = connect()
    mqtt_connect(s, b"reader")
    topic = b"big/#"
    s.sendall(mqtt_packet(8, struct.pack("!H", 1) + struct.pack("!H", len(topic)) + topic + b"\x00", flags=2))
    # The retained messages are queued behind the SUBACK, and the DISCONNECT ends the session once they have gone.
    time.sleep(0.2)
    s.sendall(b"\xe0\x00")
    stop = keep_sending(s, b"\xc0\x00")
    got, how = drain(s)
    stop.set()
    # Every PUBLISH's payload, past the SUBACK.
    i, payload = 0, 0
    while i < len(got):
        kind = got[i] >> 4
        j, mult, length = i + 1, 1, 0
        while j < len(got):
            length += (got[j] & 127) * mult
            mult *= 128
            j += 1
            if not got[j - 1] & 128:
                break
        if j + length > len(got):
            break
        if kind == 3:
            tl = struct.unpack("!H", got[j:j + 2])[0]
            payload += length - 2 - tl
        i = j + length
    print(payload, how)
PY
client() { python3 "$T/client.py" "$@" 2>&1 | tail -1; }

P_SRV=$((SL_PORT_BASE + 1501))
P_WEB=$((SL_PORT_BASE + 1502))
P_ST=$((SL_PORT_BASE + 1503))
P_PX=$((SL_PORT_BASE + 1504))
P_FC=$((SL_PORT_BASE + 1505))
P_CA=$((SL_PORT_BASE + 1506))
P_MQ=$((SL_PORT_BASE + 1507))

daemon_start "$BIN"
"$BIN" create server srv -p "$P_SRV" --http "$T/www" -s >/dev/null 2>&1
"$BIN" create web site -p "$P_WEB" --root "$T/site" -s >/dev/null 2>&1
"$BIN" create storage st -p "$P_ST" --dir "$T/st" --anonymous -s >/dev/null 2>&1
"$BIN" create proxy px -p "$P_PX" --protocol http --backend "127.0.0.1:$P_SRV" -s >/dev/null 2>&1
"$BIN" create proxy fc -p "$P_FC" --domain fc.test --backend "fastcgi://unix:$T/none.sock" --root "$T/www" -s >/dev/null 2>&1
"$BIN" create cache ca -p "$P_CA" -s >/dev/null 2>&1
"$BIN" create mqtt mq -p "$P_MQ" --anonymous -s >/dev/null 2>&1
for p in "$P_SRV" "$P_WEB" "$P_ST" "$P_PX" "$P_FC" "$P_CA" "$P_MQ"; do
    ready_tcp 127.0.0.1 "$p" 15 || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done
ready_http 127.0.0.1 "$P_SRV" /big.bin >/dev/null 2>&1 || true
curl -s -X PUT "http://127.0.0.1:$P_ST/bkt" >/dev/null
curl -s -T "$T/www/big.bin" "http://127.0.0.1:$P_ST/bkt/big.bin" >/dev/null
CA_N=12; CA_SIZE=$((500 * 1024))
check "cache: the values are set" "$(client resp-set "$P_CA" "$CA_N" "$CA_SIZE")" "+OK"
MQ_N=24; MQ_SIZE=$((200 * 1024))
check "mqtt: the retained messages are published" "$(client mqtt-retain "$P_MQ" "$MQ_N" "$MQ_SIZE")" "ok"

# Several runs each, since whether the client's bytes find the socket closed depends on the moment.
for i in 1 2 3; do
    check "server (--http): a file with Connection: close, run $i" "$(client http "$P_SRV" /big.bin localhost)" "$SIZE eof"
    check "web: a file with Connection: close, run $i" "$(client http "$P_WEB" /big.bin localhost)" "$SIZE eof"
    check "storage: an object with Connection: close, run $i" "$(client http "$P_ST" /bkt/big.bin localhost)" "$SIZE eof"
    check "proxy (http): a backend's file with Connection: close, run $i" "$(client http "$P_PX" /px/big.bin localhost)" "$SIZE eof"
    check "proxy (--root): a file with Connection: close, run $i" "$(client http "$P_FC" /big.bin fc.test)" "$SIZE eof"
    check "cache: MGET then QUIT, run $i" "$(client resp "$P_CA" "$CA_N" "$CA_SIZE")" "$((CA_N * CA_SIZE)) eof"
    check "mqtt: retained messages then DISCONNECT, run $i" "$(client mqtt "$P_MQ" "$MQ_N" "$MQ_SIZE")" "$((MQ_N * MQ_SIZE)) eof"
done

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
