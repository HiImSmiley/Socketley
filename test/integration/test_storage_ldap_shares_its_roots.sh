#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a storage runtime's binds to an ldaps:// directory read the trusted roots once, not once per
# bind, and again when the file they come from changes.
#
# What each part would catch:
#   * a context made per bind: every AssumeRoleWithLDAPIdentity parsed the CA file (or the whole system bundle)
#     again before a byte went to the directory; counted as the opens of the CA file, which a busy box cannot blur
#   * a context kept past a change of its roots: a directory whose certificate a new CA signs is refused until restart
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: ldaps binds read their roots once, and again when they change ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
daemon_isolate ldaproots
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1941))
PL=$((SL_PORT_BASE + 1943))
DIR_PID=""
trap '[ -n "$DIR_PID" ] && kill "$DIR_PID" 2>/dev/null; "$BIN" stop fedl >/dev/null 2>&1; daemon_stop' EXIT

# Two CAs, each with a leaf for 127.0.0.1, so which one the runtime trusts decides whether a bind gets through.
for c in a b; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=ca-$c" \
        -keyout "$T/ca-$c.key" -out "$T/ca-$c.pem" -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=ldap -keyout "$T/leaf-$c.key" \
        -out "$T/leaf-$c.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1\n' > "$T/leaf.ext"
    openssl x509 -req -in "$T/leaf-$c.csr" -CA "$T/ca-$c.pem" -CAkey "$T/ca-$c.key" -CAcreateserial -days 2 \
        -extfile "$T/leaf.ext" -out "$T/leaf-$c.pem" 2>/dev/null
done

# A directory over TLS that binds alice/secret, presenting the leaf of the CA given.
directory() {
    [ -n "$DIR_PID" ] && { kill "$DIR_PID" 2>/dev/null; wait "$DIR_PID" 2>/dev/null; }
    python3 - "$PL" "$T/leaf-$1.pem" "$T/leaf-$1.key" <<'PY' &
import socket, ssl, sys, threading
port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
def tlv(buf, i):
    n = buf[i + 1]; j = i + 2
    if n & 0x80:
        k = n & 0x7F; n = int.from_bytes(buf[j:j + k], "big"); j += k
    return buf[i], buf[j:j + n], j + n
def serve(raw):
    try:
        cl = ctx.wrap_socket(raw, server_side=True)
        data = cl.recv(65536)
        _, msg, _ = tlv(data, 0)
        _, mid, i = tlv(msg, 0)
        _, bind, _ = tlv(msg, i)
        _, _, j = tlv(bind, 0)
        _, dn, j = tlv(bind, j)
        _, pw, _ = tlv(bind, j)
        code = 0 if (dn, pw) == (b"uid=alice,ou=People,dc=test", b"secret") else 49
        body = bytes([0x0A, 1, code, 0x04, 0, 0x04, 0])
        resp = bytes([0x02, len(mid)]) + mid + bytes([0x61, len(body)]) + body
        cl.sendall(bytes([0x30, len(resp)]) + resp)
        cl.recv(64)
        cl.close()
    except Exception:
        raw.close()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(16)
while True:
    raw, _ = srv.accept()
    threading.Thread(target=serve, args=(raw,), daemon=True).start()
PY
    DIR_PID=$!
    for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PL") 2>/dev/null && break; sleep 0.1; done
}
directory a

cp "$T/ca-a.pem" "$T/roots.pem"
printf '[admin]\nAKIALDAPROOTSADMIN01:ldaproots/admin/secret\nadmin = true\n[reader]\nAKIALDAPROOTSREADER1:ldaproots/reader/secret\npolicy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}\n' \
    > "$T/creds"
printf 'ldap url ldaps://127.0.0.1:%s ca=%s\nldap dn  uid=%%s,ou=People,dc=test\nldap user * reader\n' "$PL" "$T/roots.pem" \
    > "$T/federation"
daemon_start "$BIN"
"$BIN" create storage fedl -p "$P" --dir "$T/data" --credentials "$T/creds" --federation "$T/federation" -s \
    >/dev/null 2>&1 || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" != 000 ] && break; sleep 0.1; done
bind() {
    curl -s -m 20 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$P/" \
        --data 'Action=AssumeRoleWithLDAPIdentity&Version=2011-06-15&LDAPUsername=alice&LDAPPassword=secret'
}

# How often the roots' file is opened, by inotify, until the file "$T/opens.stop" appears beside it.
watch_opens() {
    python3 - "$T/roots.pem" "$T/opens.stop" > "$T/opens" <<'PY' &
import ctypes, os, select, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.inotify_init1(os.O_NONBLOCK)
libc.inotify_add_watch(fd, sys.argv[1].encode(), 0x20)   # IN_OPEN
print("watching", flush=True)
n = 0
while not os.path.exists(sys.argv[2]):
    if select.select([fd], [], [], 0.1)[0]:
        buf = os.read(fd, 65536)
        while buf:
            n += 1; buf = buf[16 + struct.unpack_from("I", buf, 12)[0]:]
print(n, flush=True)
PY
    WATCH_PID=$!
    for _ in $(seq 1 50); do grep -q watching "$T/opens" 2>/dev/null && break; sleep 0.1; done
}

first=$(bind)
watch_opens
codes=""
for _ in $(seq 1 30); do codes="$codes$(bind)"; done
touch "$T/opens.stop"; wait "$WATCH_PID"
opens=$(tail -1 "$T/opens")
echo "  the CA file opened ${opens} times for 30 binds"
if [ "$first" = 200 ] && [ "$codes" = "$(printf '200%.0s' $(seq 1 30))" ]; then ok
else bad "every bind gets credentials" "first $first, then $codes"; fi
if [ "$opens" = 0 ]; then ok
else bad "the roots are read once, not per bind" "the CA file opened ${opens} times for 30 binds"; fi

# The roots replaced in place by another CA, and the directory presenting that CA's leaf: taken without a restart.
directory b
cat "$T/ca-b.pem" > "$T/roots.pem"
got=$(bind)
if [ "$got" = 200 ]; then ok; else bad "a change of the roots' file is read again" "a bind to the directory the new CA signs got $got"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
