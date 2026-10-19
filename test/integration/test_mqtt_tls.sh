#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An mqtt runtime over TLS: client certificates as the only credential, passwords on an encrypted port, and
# secure WebSocket for browsers.
#
# What each part would catch:
#   * a client certificate from another CA taken, a client without one let in, or the certificate's name not
#     made the user
#   * a cleartext CONNECT answered on a TLS port
#   * wss refused where ws is served
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }

echo "=== Integration: an mqtt runtime over TLS takes client certificates and passwords ==="
daemon_isolate mqtttls
T=$SOCKETLEY_TMPD
PT=$((SL_PORT_BASE + 1934))
PS=$((SL_PORT_BASE + 1935))
PSW=$((SL_PORT_BASE + 1936))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

printf 'alicepass1\n' | "$BIN" mqtt-passwd "$T/users" alice >/dev/null 2>&1
# A CA, the broker's certificate, a device's, and one of another CA.
(
    cd "$T"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=test-ca" -keyout ca.key -out ca.pem
    openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" -keyout srv.key -out srv.csr
    printf 'subjectAltName=IP:127.0.0.1\n' > srv.ext
    openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile srv.ext -out srv.pem
    openssl req -newkey rsa:2048 -nodes -subj "/CN=device-7" -keyout dev.key -out dev.csr
    openssl x509 -req -in dev.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -out dev.pem
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=other-ca" -keyout other.key -out other.pem
    openssl req -newkey rsa:2048 -nodes -subj "/CN=intruder" -keyout bad.key -out bad.csr
    openssl x509 -req -in bad.csr -CA other.pem -CAkey other.key -CAcreateserial -days 2 -out bad.pem
) >/dev/null 2>&1
[ -s "$T/dev.pem" ] && [ -s "$T/bad.pem" ] && ok || bad "the test certificates are made" "$(ls "$T")"

"$BIN" create mqtt t -p "$PT" --tls --cert "$T/srv.pem" --key "$T/srv.key" --ca "$T/ca.pem" -s >/dev/null 2>&1 \
    && ok || bad "a broker taking client certificates is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create mqtt s -p "$PS" --tls --cert "$T/srv.pem" --key "$T/srv.key" --users "$T/users" --ws "$PSW" -s >/dev/null 2>&1 \
    && ok || bad "a broker over TLS with passwords and secure WebSocket is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PT" "$PS" "$PSW"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done

run() {
    PYTHONPATH="$HERE" python3 - "$PT" "$PS" "$PSW" "$BIN" "$T" 2>&1 <<'PY'
import os, ssl, subprocess, sys
from lib_mqtt import *
pt, ps, psw = (int(x) for x in sys.argv[1:4])
binary, tmpd = sys.argv[4], sys.argv[5]

def tls_ctx(cert=None, key=None):
    ctx = ssl.create_default_context(cafile=os.path.join(tmpd, "ca.pem"))
    if cert:
        ctx.load_cert_chain(os.path.join(tmpd, cert), os.path.join(tmpd, key))
    return ctx

def certificates():
    c = Client(pt, tls=tls_ctx("dev.pem", "dev.key"))
    check("a client certificate the CA signed lets its device in", c.connect("cert-1")[1], 0)
    c.subscribe(("t/#", 1))
    c.publish("t/x", "over tls", qos=1)
    m = c.message(2)
    check("and it speaks over TLS", m.payload if m else None, b"over tls")
    r = subprocess.run([binary, "mqtt-sessions", "t"], capture_output=True, timeout=10).stdout.decode()
    truth("the certificate's name is the session's user", '"user":"device-7"' in r, r)
    c.disconnect()
    try:
        c = Client(pt, tls=tls_ctx("bad.pem", "bad.key"))
        c.connect("cert-2")
        truth("a certificate of another CA is refused", False, "connected")
    except (ssl.SSLError, Closed, OSError):
        truth("a certificate of another CA is refused", True)
    try:
        c = Client(pt, tls=tls_ctx())
        c.connect("cert-3")
        truth("a client with no certificate is refused", False, "connected")
    except (ssl.SSLError, Closed, OSError):
        truth("a client with no certificate is refused", True)

def tls_passwords():
    c = Client(ps, tls=tls_ctx())
    check("a password over TLS lets its user in", c.connect("s-1", username="alice", password="alicepass1")[1], 0)
    c.disconnect()
    p = Client(ps, timeout=2)
    try:
        p.connect("plain", username="alice", password="alicepass1", timeout=2)
        truth("a cleartext CONNECT on the TLS port is refused", False, "connected")
    except Closed:
        truth("a cleartext CONNECT on the TLS port is refused", True)
    w = Client(psw, tls=tls_ctx(), ws="/mqtt")
    check("a secure WebSocket client is let in", w.connect("wss-1", username="alice", password="alicepass1")[1], 0)
    t = Client(ps, tls=tls_ctx())
    t.connect("s-2", username="alice", password="alicepass1")
    t.subscribe(("x/#", 1))
    w.publish("x/from-browser", "hello", qos=1)
    m = t.message(2)
    check("and its messages reach the TLS clients", m.payload if m else None, b"hello")
    t.disconnect()
    w.disconnect()

guarded("certificates", certificates)
guarded("tls passwords", tls_passwords)
PY
}
tally < <(run)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
