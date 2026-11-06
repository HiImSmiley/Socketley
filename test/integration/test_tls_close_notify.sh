#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: every runtime that ends a TLS connection itself sends close_notify before its FIN, and a client
# that let it close resumes its session on the next connection.
#
# What each part would catch:
#   * a FIN with no close_notify under it on the server, the proxy (HTTP and TCP), the cache, storage, mqtt or mail:
#     the client reads a truncation ("EOF occurred in violation of protocol") rather than an end
#   * the alert sent ahead of the answer, or in place of part of it: the answer arrives short
#   * an answer the kernel encrypts whose alert OpenSSL encrypted, or one sent as application data: the client fails
#     on the record rather than reading an end
#   * a close_notify after a backend that reset mid-answer, which vouches for an answer cut short as whole
#   * a FIN or a close sent while the kernel still holds TLS records it took on a full socket, which throws them away:
#     a client that did not read for a moment gets the file cut at a record's edge and no close_notify, from the
#     proxy, the server or storage
#   * an IMAP reply still in the COMPRESS deflate buffer when the connection settles, as the idle sweep's BYE is: the
#     connection closed with neither the BYE nor close_notify
#   * a session thrown away because the server closed: under --shards 4 a client that lets the server close never
#     resumes, OpenSSL keeping no session from a connection that ended without close_notify
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

echo "=== Integration: a TLS connection the runtime closes ends with close_notify ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
python3 -c 'import ssl' >/dev/null 2>&1 || { echo "  SKIP: python3 ssl is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
daemon_isolate tlsclose
unset SOCKETLEY_CONFIG
trap daemon_stop EXIT
T="$SOCKETLEY_TMPD"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout "$T/k.pem" -out "$T/c.pem" >/dev/null 2>&1
mkdir -p "$T/www" "$T/st"
echo hello >"$T/www/a.txt"
head -c $((4 * 1024 * 1024)) /dev/urandom >"$T/www/big.bin"
STALL_SIZES=$(seq 2262144 16384 2512000)
for n in $STALL_SIZES; do head -c "$n" "$T/www/big.bin" >"$T/www/f$n"; done
TLS=(--tls --cert "$T/c.pem" --key "$T/k.pem")

# Each mode makes one connection, has the runtime end it, and prints how it ended -- "clean" for a close_notify,
# "ragged" for a bare FIN -- and how many bytes of answer came before it.
cat >"$T/client.py" <<'PY'
import socket, ssl, struct, sys

mode, port = sys.argv[1], int(sys.argv[2])

def context(version=ssl.TLSVersion.TLSv1_3):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = c.maximum_version = version
    return c

def connect(ctx=None, session=None):
    # suppress_ragged_eofs off, or a bare FIN reads as the same b"" a close_notify does.
    return (ctx or context()).wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                                          server_hostname="localhost", session=session, suppress_ragged_eofs=False)

def drain(s, got=b""):
    try:
        while True:
            b = s.recv(65536)
            if not b:
                return got, "clean"
            got += b
    except ssl.SSLEOFError:
        return got, "ragged"
    except (OSError, ssl.SSLError) as e:
        return got, "error(%s)" % e

def until(s, mark):
    got = b""
    while mark not in got:
        b = s.recv(65536)
        if not b:
            break
        got += b
    return got

def http_close(path, host="localhost"):
    s = connect()
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)).encode())
    got, how = drain(s)
    head, _, body = got.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    print(how, len(body), status.split(" ")[1] if " " in status else status)

if mode == "http":
    http_close(sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "localhost")
elif mode == "tcp":
    # A TCP proxy in front of an HTTP server, which closes after its answer.
    s = connect()
    s.sendall(b"GET /a.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    got, how = drain(s)
    print(how, len(got.partition(b"\r\n\r\n")[2]), "-")
elif mode == "raw":
    s = connect()
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % sys.argv[3]).encode())
    got, how = drain(s)
    print(how, got.partition(b"\r\n\r\n")[2].decode(errors="replace"))
elif mode == "backend":
    # Answers without a length, so only the close ends the body, and then resets or closes as asked.
    import time
    l = socket.socket()
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("127.0.0.1", port))
    l.listen(16)
    while True:
        c, _ = l.accept()
        c.recv(4096)
        c.sendall(b"HTTP/1.0 200 OK\r\n\r\npartial")
        time.sleep(0.2)
        if sys.argv[3] == "rst":
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        c.close()
elif mode == "resp":
    s = connect()
    s.sendall(b"*2\r\n$4\r\nPING\r\n$2\r\nhi\r\n*1\r\n$4\r\nQUIT\r\n")
    got, how = drain(s)
    print(how, len(got), got.replace(b"\r\n", b" ").decode().strip().replace(" ", "/"))
elif mode == "mqtt":
    s = connect()
    cid = b"tlsclose"
    var = struct.pack("!H", 4) + b"MQTT" + bytes([4, 2]) + struct.pack("!H", 30)
    pay = struct.pack("!H", len(cid)) + cid
    s.sendall(bytes([0x10, len(var) + len(pay)]) + var + pay)
    connack = b""
    while len(connack) < 4:
        connack += s.recv(4 - len(connack))
    s.sendall(b"\xe0\x00")   # DISCONNECT, after which the server closes
    got, how = drain(s)
    print(how, len(got), connack.hex())
elif mode == "smtp":
    s = connect()
    banner = until(s, b"\r\n")
    s.sendall(b"QUIT\r\n")
    got, how = drain(s)
    print(how, banner[:3].decode() + "/" + got[:3].decode())
elif mode == "stalled":
    # Not read until the file is all sent, behind a small receive buffer, so the kernel holds the end of it.
    import time
    path, host, sizes = sys.argv[3], sys.argv[4], sys.argv[5:]
    bad = []
    for size in sizes * 3:
        raw = socket.socket()
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        raw.settimeout(15)
        raw.connect(("127.0.0.1", port))
        s = context().wrap_socket(raw, server_hostname="localhost", suppress_ragged_eofs=False)
        s.sendall(("GET %s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, size, host)).encode())
        time.sleep(0.7)
        got, how = drain(s)
        body = len(got.partition(b"\r\n\r\n")[2])
        if how != "clean" or body != int(size):
            bad.append("%s:%s:%d" % (size, how, body))
        s.close()
    print(len(sizes) * 3 - len(bad), " ".join(bad[:4]))
elif mode in ("imapz-logout", "imapz-idle"):
    # COMPRESS DEFLATE over TLS, then LOGOUT, or nothing until the idle sweep says BYE.
    import zlib
    s = connect()
    f = s.makefile("rb")
    f.readline()
    s.sendall(b"a LOGIN alice alicepassword1\r\n")
    while not f.readline().startswith(b"a "):
        pass
    s.sendall(b"z COMPRESS DEFLATE\r\n")
    if not f.readline().startswith(b"z OK"):
        print("no-compress -")
        sys.exit(0)
    co, do = zlib.compressobj(wbits=-15), zlib.decompressobj(-15)
    if mode == "imapz-logout":
        s.sendall(co.compress(b"b LOGOUT\r\n") + co.flush(zlib.Z_SYNC_FLUSH))
    s.settimeout(20)
    wire, how = b"", None
    try:
        while True:
            b = s.recv(65536)
            if not b:
                how = "clean"
                break
            wire += b
    except ssl.SSLEOFError:
        how = "ragged"
    except (OSError, ssl.SSLError) as e:
        how = "error(%s)" % e
    text = do.decompress(wire)
    lines = [l.split(b" ")[0] + b" " + l.split(b" ")[1] for l in text.split(b"\r\n") if l.count(b" ") >= 1]
    print(how, "/".join(x.decode() for x in lines) or "-")
elif mode == "resume":
    # A connection the server closes after each answer, the next one offering the session the last one ended with.
    version = ssl.TLSVersion.TLSv1_3 if sys.argv[3] == "1.3" else ssl.TLSVersion.TLSv1_2
    n, path = int(sys.argv[4]), sys.argv[5]
    ctx = context(version)
    sess, reused, clean = None, 0, 0
    for i in range(n + 1):
        s = connect(ctx, sess)
        s.sendall(b"GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" % path.encode())
        got, how = drain(s)
        if i > 0 and s.session_reused:
            reused += 1
        clean += how == "clean"
        sess = s.session
        s.close()
    print(reused, clean)
PY
client() { python3 "$T/client.py" "$@" 2>&1 | tail -1; }

P_SRV=$((SL_PORT_BASE + 1401))
P_SH=$((SL_PORT_BASE + 1402))
P_BE=$((SL_PORT_BASE + 1403))
P_PX=$((SL_PORT_BASE + 1404))
P_PT=$((SL_PORT_BASE + 1405))
P_PXS=$((SL_PORT_BASE + 1406))
P_CA=$((SL_PORT_BASE + 1407))
P_ST=$((SL_PORT_BASE + 1408))
P_MQ=$((SL_PORT_BASE + 1409))
P_ML=$((SL_PORT_BASE + 1410))
P_MLS=$((SL_PORT_BASE + 1411))
P_FC=$((SL_PORT_BASE + 1412))
P_RSTBE=$((SL_PORT_BASE + 1413))
P_FINBE=$((SL_PORT_BASE + 1414))
P_TRST=$((SL_PORT_BASE + 1415))
P_TFIN=$((SL_PORT_BASE + 1416))
P_HRST=$((SL_PORT_BASE + 1417))
P_MIDP=$((SL_PORT_BASE + 1418))
P_MST=$((SL_PORT_BASE + 1419))
P_MI=$((SL_PORT_BASE + 1420))
P_MIS=$((SL_PORT_BASE + 1421))

python3 "$T/client.py" backend "$P_RSTBE" rst >/dev/null 2>&1 &
BE_RST=$!
python3 "$T/client.py" backend "$P_FINBE" fin >/dev/null 2>&1 &
BE_FIN=$!
trap 'kill $BE_RST $BE_FIN 2>/dev/null; daemon_stop' EXIT
# The mail runtimes' idle sweep within the test's patience.
SOCKETLEY_MAIL_IDLE_MS=3000 daemon_start "$BIN"
"$BIN" create server srv -p "$P_SRV" --http "$T/www" "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create server sh4 -p "$P_SH" --http "$T/www" --shards 4 "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create server be -p "$P_BE" --http "$T/www" -s >/dev/null 2>&1
"$BIN" create proxy px -p "$P_PX" --protocol http --backend "127.0.0.1:$P_BE" "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create proxy pt -p "$P_PT" --protocol tcp --backend "127.0.0.1:$P_BE" "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create proxy px4 -p "$P_PXS" --protocol http --backend "127.0.0.1:$P_BE" --shards 4 "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create cache ca -p "$P_CA" "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create storage st -p "$P_ST" --dir "$T/st" --anonymous "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create mqtt mq -p "$P_MQ" --anonymous "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create proxy fc -p "$P_FC" --domain fc.test --backend "fastcgi://unix:$T/none.sock" --root "$T/www" \
    "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create proxy trst -p "$P_TRST" --protocol tcp --backend "127.0.0.1:$P_RSTBE" "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create proxy tfin -p "$P_TFIN" --protocol tcp --backend "127.0.0.1:$P_FINBE" "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create proxy hrst -p "$P_HRST" --protocol http --backend "127.0.0.1:$P_RSTBE" "${TLS[@]}" -s >/dev/null 2>&1
"$BIN" create mail ml -p "$P_ML" --mail-domain example.test --submissions "$P_MLS" "${TLS[@]}" -s >/dev/null 2>&1
printf 'spa - http://localhost:5173/cb\n' >"$T/clients"
"$BIN" create idp mauth -p "$P_MIDP" --clients "$T/clients" --issuer "http://127.0.0.1:$P_MIDP" -s >/dev/null 2>&1
"$BIN" create storage mst -p "$P_MST" --dir "$T/mst" --anonymous -s >/dev/null 2>&1
for p in "$P_MIDP/jwks" "$P_MST/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user mauth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail mi -p "$P_MI" --mail-domain example.test --idp mauth --storage mst/mail --imaps "$P_MIS" "${TLS[@]}" \
    -s >/dev/null 2>&1
for p in "$P_SRV" "$P_SH" "$P_BE" "$P_PX" "$P_PT" "$P_PXS" "$P_CA" "$P_ST" "$P_MQ" "$P_MLS" "$P_FC" "$P_TRST" "$P_TFIN" "$P_HRST" "$P_MIS"; do
    ready_tcp 127.0.0.1 "$p" 15 || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done
# Every shard listening, so the reconnections are spread over all four.
for p in "$P_SH" "$P_PXS"; do
    for _ in $(seq 1 100); do [ "$(ss -Hltn "sport = :$p" 2>/dev/null | wc -l)" -ge 4 ] && break; sleep 0.1; done
done
ready_http 127.0.0.1 "$P_BE" /a.txt >/dev/null 2>&1 || true

# ─── Each runtime's own close ──────────────────────────────────────────────
check "server: an HTTP answer with Connection: close ends with close_notify" "$(client http "$P_SRV" /a.txt)" "clean 6 200"
check "server: and so does a 404" "$(client http "$P_SRV" /missing)" "clean 13 404"
check "proxy (http): an answer with Connection: close ends with close_notify" "$(client http "$P_PX" /px/a.txt)" "clean 6 200"
check "proxy (tcp): the backend's close reaches the client as close_notify" "$(client tcp "$P_PT")" "clean 6 -"
check "cache: QUIT ends with close_notify" "$(client resp "$P_CA")" "clean 13 \$2/hi/+OK"
r=$(client http "$P_ST" /)
check "storage: an answer with Connection: close ends with close_notify" "${r%% *}" "clean"
check "mqtt: DISCONNECT ends with close_notify" "$(client mqtt "$P_MQ")" "clean 0 20020000"
check "mail: QUIT on --submissions ends with close_notify" "$(client smtp "$P_MLS")" "clean 220/221"
check "mail: IMAP LOGOUT under COMPRESS, its BYE and OK whole, then close_notify" "$(client imapz-logout "$P_MIS")" \
    "clean * BYE/b OK"
check "mail: IMAP under COMPRESS left idle, its BYE whole, then close_notify" "$(client imapz-idle "$P_MIS")" \
    "clean * BYE"

# ─── A backend that fails is not vouched for ───────────────────────────────
check "proxy (tcp): a backend that closes after an unframed answer ends it with close_notify" \
    "$(client raw "$P_TFIN" /)" "clean partial"
check "proxy (tcp): a backend that resets mid-answer is passed on without close_notify" \
    "$(client raw "$P_TRST" /)" "ragged partial"
check "proxy (http): a backend that resets mid-answer is passed on without close_notify" \
    "$(client raw "$P_HRST" /hrst/)" "ragged partial"

# ─── Behind an answer the kernel encrypted ─────────────────────────────────
# A large file moves the connection's send key to the kernel, which must then carry the alert as a record of its type.
if [ -r /proc/net/tls_stat ]; then
    tx() { awk '$1=="TlsTxSw" {print $2}' /proc/net/tls_stat; }
    t0=$(tx)
    r=$(client http "$P_SRV" /big.bin)
    t1=$(tx)
    check "server: a large file sent by the kernel, then close_notify" "$r" "clean $((4 * 1024 * 1024)) 200"
    [ "$t1" -gt "$t0" ] && ok || bad "the server's large file went through kernel TLS" "TlsTxSw $t0 -> $t1"

    curl -sk -X PUT "https://127.0.0.1:$P_ST/bkt" >/dev/null
    curl -sk -T "$T/www/big.bin" "https://127.0.0.1:$P_ST/bkt/big.bin" >/dev/null
    for n in $STALL_SIZES; do curl -sk -T "$T/www/f$n" "https://127.0.0.1:$P_ST/bkt/f$n" >/dev/null; done
    t0=$(tx)
    r=$(client http "$P_ST" /bkt/big.bin)
    t1=$(tx)
    check "storage: a large object sent by the kernel, then close_notify" "$r" "clean $((4 * 1024 * 1024)) 200"
    [ "$t1" -gt "$t0" ] && ok || bad "storage's large object went through kernel TLS" "TlsTxSw $t0 -> $t1"

    t0=$(tx)
    r=$(client http "$P_FC" /big.bin fc.test)
    t1=$(tx)
    check "proxy (--root): a large file sent by the kernel, then close_notify" "$r" "clean $((4 * 1024 * 1024)) 200"
    [ "$t1" -gt "$t0" ] && ok || bad "the proxy's large file went through kernel TLS" "TlsTxSw $t0 -> $t1"
    # shellcheck disable=SC2086
    r=$(client stalled "$P_FC" /f fc.test $STALL_SIZES)
    check "proxy (--root): 48 files of 2.2-2.5 MB to clients that paused, each whole and then close_notify" \
        "${r%% *}" "48"
    # shellcheck disable=SC2086
    r=$(client stalled "$P_SRV" /f localhost $STALL_SIZES)
    check "server (--http): 48 files of 2.2-2.5 MB to clients that paused, each whole and then close_notify" \
        "${r%% *}" "48"
    # shellcheck disable=SC2086
    r=$(client stalled "$P_ST" /bkt/f localhost $STALL_SIZES)
    check "storage: 48 objects of 2.2-2.5 MB to clients that paused, each whole and then close_notify" \
        "${r%% *}" "48"
else
    echo "  (no kernel TLS here: the kernel-encrypted close is not checked)"
fi

# ─── A client that let the server close resumes ────────────────────────────
read -r R13 C13 < <(client resume "$P_SH" 1.3 20 /a.txt)
check "server --shards 4: every one of 20 server-closed connections ended clean (TLS 1.3)" "${C13:-}" "21"
[ "${R13:-0}" -ge 19 ] && ok || bad "server --shards 4: a TLS 1.3 client the server closed on resumes" "resumed ${R13:-none} of 20"
read -r R12 C12 < <(client resume "$P_SH" 1.2 20 /a.txt)
[ "${R12:-0}" -ge 19 ] && ok || bad "server --shards 4: a TLS 1.2 client the server closed on resumes" "resumed ${R12:-none} of 20 (clean ${C12:-})"
read -r RP CP < <(client resume "$P_PXS" 1.3 20 /px4/a.txt)
[ "${RP:-0}" -ge 19 ] && ok || bad "proxy --shards 4: a TLS 1.3 client the proxy closed on resumes" "resumed ${RP:-none} of 20 (clean ${CP:-})"

# The same seen by openssl's own client: no "unexpected eof" after an answer the server ends.
o=$(printf 'GET /a.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' |
    timeout 10 openssl s_client -connect "127.0.0.1:$P_SRV" -servername localhost -quiet -ign_eof 2>&1)
if grep -q "^hello" <<<"$o" && ! grep -qi 'unexpected eof' <<<"$o"; then ok
else bad "openssl s_client reads the server's close as an end" "$(tail -2 <<<"$o")"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
