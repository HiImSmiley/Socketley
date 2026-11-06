#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a cache over --tls hands a connection's send key to the kernel for a large answer, and only then.
#
# What each part would catch:
#   * plaintext reaching the socket before the key update OpenSSL encrypted has gone, or the records encrypted here
#     sent through the kernel once more: a client that cannot read the answer
#   * a connection switched for small answers, which costs it more than the records encrypted here
#   * the answers after a switch on the same connection -- small, large, several in one write -- sent the wrong way
#   * a close after the switch, behind a stalled reader: the kernel's records cut by the FIN, or no close_notify
#   * a key update after the switch, the client's own and one it asks for, which the kernel must take or the
#     connection must end
#   * SOCKETLEY_KERNEL_TLS=0 not keeping every record in user space
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a cache over TLS moves a connection's send key to the kernel for a large answer ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
[ -r /proc/net/tls_stat ] || { echo "  SKIP: the kernel has no TLS layer here (modprobe tls)"; exit 0; }
daemon_isolate cachektls
P=$((SL_PORT_BASE + 1961))
unset SOCKETLEY_CONFIG
W=$(mktemp -d /tmp/socketley-cktls-XXXXXX)
trap 'daemon_stop; rm -rf "$W"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -keyout "$W/k.pem" -out "$W/c.pem" >/dev/null 2>&1

# Each value is its name repeated, so a cut or a misplaced record shows as a wrong byte; sizes in KiB.
cat > "$W/client.py" <<'PY'
import socket, ssl, sys, subprocess
port, plan = int(sys.argv[1]), sys.argv[2:]
SIZES = {"tiny": 1, "small": 16, "mid": 256, "big": 3072, "huge": 8192}
def value(name): return (name.encode() + b"-") * (SIZES[name] * 1024 // (len(name) + 1)) + b"."
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
raw = socket.socket()
if "quit-slow" in plan:
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
raw.connect(("127.0.0.1", port))
s = ctx.wrap_socket(raw)
s.settimeout(20)
buf = b""
def reply():
    global buf
    while b"\r\n" not in buf: buf += s.recv(1 << 20)
    head, rest = buf.split(b"\r\n", 1)
    if head[:1] != b"$": raise SystemExit("unexpected reply " + head[:40].decode(errors="replace"))
    n = int(head[1:])
    while len(rest) < n + 2: rest += s.recv(1 << 20)
    buf = rest[n + 2:]
    return rest[:n]
def cmd(*a): return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a)
def kernel():
    # This connection's server end, as ss shows it: its send key in the kernel or not.
    me = s.getsockname()[1]
    out = subprocess.run(["ss", "-tniH", "state", "established", "( sport = :%d and dport = :%d )" % (port, me)],
                         capture_output=True, text=True).stdout
    return "txconf: sw" in out or "tx: sw" in out
whole = 0; total = 0
for step in plan:
    if step == "set":
        for n in SIZES:
            s.sendall(cmd(b"SET", n.encode(), value(n)))
            while b"\r\n" not in buf: buf += s.recv(65536)
            buf = buf.split(b"\r\n", 1)[1]
        continue
    if step == "kernel?":
        print("kernel", int(kernel())); continue
    if step == "quit-slow":
        # The answer and QUIT at once, read only after the cache has written what the socket takes and closed: what
        # the kernel still held must come before the FIN, and the close_notify after it.
        import time
        s.sendall(cmd(b"GET", b"huge") + cmd(b"QUIT")); time.sleep(1.5)
        total += 1; whole += reply() == value("huge")
        while b"\r\n" not in buf: buf += s.recv(65536)
        try:
            while s.recv(65536): pass
            print("closed clean")
        except ssl.SSLError as e: print("closed without close_notify:", e)
        continue
    names = step.split("+")    # several GETs in one write
    s.sendall(b"".join(cmd(b"GET", n.encode()) for n in names))
    for n in names:
        total += 1
        whole += reply() == value(n)
print("whole", whole, "of", total)
PY

kstat() { awk '$1=="TlsTxSw" {print $2}' /proc/net/tls_stat; }
start_cache() {
    "$BIN" create cache ck -p "$P" --tls --cert "$W/c.pem" --key "$W/k.pem" --read-buffer 32M --write-buffer 64M -s \
        >/dev/null 2>&1
    for _ in $(seq 1 50); do ss -ltnH "( sport = :$P )" | grep -q . && break; sleep 0.1; done
}

daemon_start "$BIN"
start_cache
python3 -I "$W/client.py" "$P" set > "$W/set.out" 2>&1
grep -q 'whole 0 of 0' "$W/set.out" || echo "  note: setting the values said: $(head -2 "$W/set.out")"

# Small and middling answers alone: the connection stays in user space.
out=$(python3 -I "$W/client.py" "$P" tiny small mid tiny+small+mid kernel? 2>&1)
if echo "$out" | grep -q 'whole 6 of 6' && echo "$out" | grep -q 'kernel 0'; then ok
else bad "a connection given small answers only stays in user space" "$(echo "$out" | tr '\n' ' ')"; fi

# One connection: a large answer moves it, and every answer after it, alone or several in one write, is whole.
out=$(python3 -I "$W/client.py" "$P" tiny big kernel? tiny small huge mid tiny+big+small huge+huge mid+tiny 2>&1)
if echo "$out" | grep -q 'whole 13 of 13' && echo "$out" | grep -q 'kernel 1'; then ok
else bad "a large answer moves its connection, and the answers after it come back whole" "$(echo "$out" | tr '\n' ' ')"; fi

# A moved connection the cache closes behind a reader that stalled on a 4 KiB receive buffer: the answer whole, then
# close_notify.
out=$(python3 -I "$W/client.py" "$P" big quit-slow 2>&1)
if echo "$out" | grep -q 'whole 2 of 2' && echo "$out" | grep -q 'closed clean'; then ok
else bad "a moved connection closed by QUIT ends its answer, then close_notify, then its FIN" "$(echo "$out" | tr '\n' ' ')"; fi

# Eight moved connections at once.
pids=()
for i in $(seq 1 8); do python3 -I "$W/client.py" "$P" big huge tiny > "$W/c$i.out" 2>&1 & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
whole=0; for i in $(seq 1 8); do grep -q 'whole 3 of 3' "$W/c$i.out" && whole=$((whole + 1)); done
if [ "$whole" = 8 ]; then ok; else bad "eight moved connections at once each carry their answers" "$whole of 8"; fi

# Key updates after the switch, the client's own and one it asks the server for.  Not -ign_eof, which turns
# s_client's command letters off.
resp() { local a; printf '*%d\r\n' $#; for a in "$@"; do printf '$%d\r\n%s\r\n' ${#a} "$a"; done; }
for cmd in k K; do
    { resp GET big; sleep 1; printf '%s\n' "$cmd"; sleep 1; resp GET tiny; sleep 1; resp QUIT; sleep 1; } |
        timeout 15 openssl s_client -connect "127.0.0.1:$P" -tls1_3 > "$W/ku$cmd" 2>&1
    big=$(grep -ac 'big-big-' "$W/ku$cmd"); tiny=$(grep -ac 'tiny-tiny-' "$W/ku$cmd")
    broken=$(grep -acE 'bad record mac|decryption failed|wrong version number|record layer failure' "$W/ku$cmd")
    if [ "$broken" = 0 ] && [ "$big" -ge 1 ] && [ "$tiny" -ge 1 ]; then ok
    elif [ "$cmd" = K ] && [ "$broken" = 0 ] && [ "$big" -ge 1 ]; then
        echo "  note: this kernel takes no second send key, so the connection ended at the asked-for update"; ok
    else bad "a key update ('$cmd') after the switch is followed by the next answer" \
        "big $big, tiny $tiny, $broken record errors: $(grep -aE 'error|alert' "$W/ku$cmd" | head -2 | tr '\n' ' ')"; fi
done
daemon_stop

# SOCKETLEY_KERNEL_TLS=0: the large answers are encrypted here, and whole.
daemon_isolate cachektls-off
SOCKETLEY_KERNEL_TLS=0 daemon_start "$BIN"
start_cache
python3 -I "$W/client.py" "$P" set >/dev/null 2>&1
t0=$(kstat)
out=$(python3 -I "$W/client.py" "$P" big huge kernel? tiny 2>&1)
if echo "$out" | grep -q 'whole 3 of 3' && echo "$out" | grep -q 'kernel 0'; then ok
else bad "SOCKETLEY_KERNEL_TLS=0 keeps the send key in user space" "$(echo "$out" | tr '\n' ' '), TlsTxSw $t0 -> $(kstat)"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
