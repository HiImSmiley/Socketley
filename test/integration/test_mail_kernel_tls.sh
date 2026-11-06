#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a mail runtime's IMAP over TLS hands a connection's send key to the kernel for a large message, and
# only then, and never under COMPRESS.
#
# What each part would catch:
#   * plaintext reaching the socket before the key update OpenSSL encrypted has gone, or what was said meanwhile put
#     ahead of it: a client that cannot read the message
#   * a connection switched for small replies, which costs it more than the records encrypted here
#   * the replies after a switch -- small and large messages, several in one FETCH -- sent the wrong way
#   * a connection under COMPRESS moved, whose bytes are made here
#   * a LOGOUT after the switch ending without close_notify, or cut by the FIN
#   * a key update after the switch, the client's own and one it asks for, which the kernel must take or the
#     connection must end
#   * SOCKETLEY_KERNEL_TLS=0 not keeping every record in user space
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: IMAP over TLS moves a connection's send key to the kernel for a large message ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
[ -r /proc/net/tls_stat ] || { echo "  SKIP: the kernel has no TLS layer here (modprobe tls)"; exit 0; }
P=$((SL_PORT_BASE + 1981)); PI=$((SL_PORT_BASE + 1982)); PS=$((SL_PORT_BASE + 1983)); IM=$((SL_PORT_BASE + 1984))
W=$(mktemp -d /tmp/socketley-iktls-XXXXXX)
trap 'daemon_stop; rm -rf "$W"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -keyout "$W/k.pem" -out "$W/c.pem" >/dev/null 2>&1
printf 'spa - http://localhost:5173/cb\n' > "$W/clients"

start_mail() {
    daemon_start "$BIN"
    "$BIN" create idp auth -p "$PI" --clients "$W/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
    "$BIN" create storage st -p "$PS" --dir "$SOCKETLEY_TMPD/st" --anonymous -s >/dev/null 2>&1
    for p in "$PI/jwks" "$PS/"; do
        for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
    done
    "$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
    "$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imaps "$IM" --max-size 32M \
        --tls --cert "$W/c.pem" --key "$W/k.pem" -s >/dev/null 2>&1
    ready_tcp 127.0.0.1 "$IM" || bad "the IMAPS port listens" "$(tail -3 "$SOCKETLEY_DLOG")"
}

# Messages by UID: 1 KiB, 2 MiB, 5 MiB, 8 MiB, each line naming its message and its number, so a cut or a misplaced
# record shows as a wrong byte.
cat > "$W/client.py" <<'PY'
import imaplib, socket, ssl, subprocess, sys, zlib
port, plan = int(sys.argv[1]), sys.argv[2:]
SIZES = {1: 1 << 10, 2: 2 << 20, 3: 5 << 20, 4: 8 << 20}
imaplib.Commands.setdefault("COMPRESS", ("AUTH", "SELECTED"))
def message(uid):
    n = SIZES[uid]; out = [b"From: a@example.test\r\nSubject: m%d\r\n\r\n" % uid]; have = len(out[0]); i = 0
    while have < n:
        line = b"m%d line %08d ................................................\r\n" % (uid, i)
        out.append(line); have += len(line); i += 1
    return b"".join(out)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
M = imaplib.IMAP4_SSL("127.0.0.1", port, ssl_context=ctx)
M.login("alice", "alicepassword1")
rawsock = M.sock
def kernel():
    me = rawsock.getsockname()[1]
    out = subprocess.run(["ss", "-tniH", "state", "established", "( sport = :%d and dport = :%d )" % (port, me)],
                         capture_output=True, text=True).stdout
    return "txconf: sw" in out or "tx: sw" in out
whole = total = 0
for step in plan:
    if step == "append":
        for uid in sorted(SIZES):
            M.append("INBOX", None, None, message(uid))
        continue
    if step == "select":
        M.select("INBOX"); continue
    if step == "compress":
        # COMPRESS DEFLATE by hand, imaplib having none: every byte after the OK goes through zlib both ways.
        typ, _ = M._simple_command("COMPRESS", "DEFLATE")
        if typ != "OK": print("no compress"); continue
        co, do = zlib.compressobj(wbits=-15), zlib.decompressobj(-15)
        raw = M.sock
        class Z:
            def __init__(self): self.pending = b""
            def sendall(self, b): raw.sendall(co.compress(b) + co.flush(zlib.Z_SYNC_FLUSH))
            def recv(self, n):
                while not self.pending:
                    d = raw.recv(65536)
                    if not d: return b""
                    self.pending = do.decompress(d)
                b, self.pending = self.pending[:n], self.pending[n:]
                return b
            def makefile(self, mode): return raw.makefile(mode)
        z = Z(); M.sock = z
        M.file = None
        def readline():
            line = b""
            while not line.endswith(b"\n"): line += z.recv(1)
            return line
        def read(n):
            out = b""
            while len(out) < n: out += z.recv(n - len(out))
            return out
        M.readline = readline; M.read = read; M.send = z.sendall
        continue
    if step == "kernel?":
        print("kernel", int(kernel())); continue
    if step == "logout":
        M.send(b"z LOGOUT\r\n")
        rest = b""
        try:
            while True:
                b = M.sock.recv(65536)
                if not b: break
                rest += b
            print("logout clean" if b"z OK" in rest else "logout without its OK")
        except ssl.SSLError as e:
            print("logout without close_notify:", e)
        continue
    uids = [int(x) for x in step.split(",")]
    typ, data = M.uid("FETCH", ",".join(map(str, uids)), "BODY[]")
    got = {}
    for part in data:
        if isinstance(part, tuple):
            u = int(part[0].split(b"UID ")[1].split()[0]) if b"UID " in part[0] else None
            got[u] = part[1]
    for u in uids:
        total += 1
        whole += got.get(u) == message(u)
print("whole", whole, "of", total)
PY
py() { python3 -I "$W/client.py" "$IM" "$@" 2>&1; }

daemon_isolate mailktls
start_mail
py append >/dev/null

out=$(py select 1 2 1,2 kernel?)
if echo "$out" | grep -q 'whole 4 of 4' && echo "$out" | grep -q 'kernel 0'; then ok
else bad "a connection given small messages only stays in user space" "$(echo "$out" | tr '\n' ' ' | cut -c1-300)"; fi

out=$(py select 1 3 kernel? 1 4 2 1,2,3,4 1 logout)
if echo "$out" | grep -q 'whole 10 of 10' && echo "$out" | grep -q 'kernel 1'; then ok
else bad "a large message moves its connection, and every reply after it comes whole" "$(echo "$out" | tr '\n' ' ' | cut -c1-300)"; fi
echo "$out" | grep -q 'logout clean' && ok \
    || bad "a LOGOUT on a moved connection ends with its OK and close_notify" "$(echo "$out" | grep logout)"

out=$(py select compress 3 1 4 kernel?)
if echo "$out" | grep -q 'whole 3 of 3' && echo "$out" | grep -q 'kernel 0'; then ok
else bad "under COMPRESS a large message comes whole and the connection is not moved" "$(echo "$out" | tr '\n' ' ' | cut -c1-300)"; fi

# Key updates after the switch, the client's own and one it asks for.  Not -ign_eof, which turns s_client's command
# letters off.
for cmd in k K; do
    { sleep 0.5; printf 'a LOGIN alice alicepassword1\r\n'; sleep 0.5; printf 's SELECT INBOX\r\n'; sleep 0.5
      printf 'f UID FETCH 3 BODY[]\r\n'; sleep 1.5; printf '%s\n' "$cmd"; sleep 1
      printf 'g UID FETCH 1 BODY[]\r\n'; sleep 1; printf 'z LOGOUT\r\n'; sleep 1; } |
        timeout 20 openssl s_client -connect "127.0.0.1:$IM" -tls1_3 > "$W/ku$cmd" 2>&1
    big=$(grep -ac '^m3 line' "$W/ku$cmd"); small=$(grep -ac '^m1 line' "$W/ku$cmd")
    broken=$(grep -acE 'bad record mac|decryption failed|wrong version number|record layer failure' "$W/ku$cmd")
    if [ "$broken" = 0 ] && [ "$big" -gt 70000 ] && [ "$small" -ge 1 ]; then ok
    elif [ "$cmd" = K ] && [ "$broken" = 0 ] && [ "$big" -gt 70000 ]; then
        echo "  note: this kernel takes no second send key, so the connection ended at the asked-for update"; ok
    else bad "a key update ('$cmd') after the switch is followed by the next reply" \
        "big $big lines, small $small, $broken record errors: $(grep -aE 'error|alert' "$W/ku$cmd" | head -2 | tr '\n' ' ')"; fi
done
daemon_stop

# SOCKETLEY_KERNEL_TLS=0: the large messages are encrypted here, and whole.
daemon_isolate mailktls-off
SOCKETLEY_KERNEL_TLS=0 start_mail
py append >/dev/null
out=$(py select 3 kernel? 1 4)
if echo "$out" | grep -q 'whole 3 of 3' && echo "$out" | grep -q 'kernel 0'; then ok
else bad "SOCKETLEY_KERNEL_TLS=0 keeps the send key in user space" "$(echo "$out" | tr '\n' ' ' | cut -c1-300)"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
