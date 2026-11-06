#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: with --idle-timeout, a client that stops reading in the middle of an answer is closed after the
# timeout, whether the connection was closing or kept alive, and a client that reads slowly is not.
#
# What each part would catch:
#   * an idle sweep that skips closing connections: a client that asked for Connection: close and then stopped
#     reading holds its connection for as long as it likes
#   * a close of a kept-alive connection that waits on its stuck write: the sweep's close never completes
#   * a sweep that takes a slow reader for a stopped one, since it sends nothing and its answer is not done
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

echo "=== Integration: a client that stops reading is closed after --idle-timeout, one that reads slowly is not ==="
python3 -c 'import socket' >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
daemon_isolate wstall
unset SOCKETLEY_CONFIG
trap daemon_stop EXIT
T="$SOCKETLEY_TMPD"
mkdir -p "$T/www"
head -c $((64 * 1024 * 1024)) /dev/zero >"$T/www/big.bin"

# Every client at once, so the test waits for the sweep once: "stopped" reads the head and nothing more, "slow" 4 KiB
# every 50 ms; after WAIT seconds each says whether the runtime ended it ("reset" or "eof") or it is still open.
cat >"$T/client.py" <<'PY'
import socket, sys, threading, time

WAIT = float(sys.argv[1])
results = {}

def one(name, port, path, host, how, close):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.settimeout(5)
    s.connect(("127.0.0.1", port))
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n" % (path, host, "Connection: close\r\n" if close else "")).encode())
    got = b""
    while b"\r\n\r\n" not in got:
        got += s.recv(4096)
    end = time.time() + WAIT
    state = "open"
    try:
        while time.time() < end:
            if how == "slow":
                b = s.recv(4096)
                if not b:
                    state = "eof"
                    break
                time.sleep(0.05)
            else:
                time.sleep(0.5)
        if how == "stopped" and state == "open":
            # What the runtime did meanwhile shows on the first read: a reset, or the rest of the answer and its end.
            s.settimeout(0.5)
            try:
                while True:
                    b = s.recv(1 << 20)
                    if not b:
                        state = "eof"
                        break
            except socket.timeout:
                state = "open"
    except ConnectionResetError:
        state = "reset"
    except socket.timeout:
        state = "stuck"
    results[name] = state
    s.close()

targets = [a.split(",") for a in sys.argv[2:]]
threads = []
for name, port, path, host, how, close in targets:
    t = threading.Thread(target=one, args=(name, int(port), path, host, how, close == "close"))
    t.start()
    threads.append(t)
for t in threads:
    t.join()
print(" ".join("%s=%s" % (t[0], results.get(t[0], "error")) for t in targets))
PY

P_SRV=$((SL_PORT_BASE + 1601))
P_FC=$((SL_PORT_BASE + 1602))
daemon_start "$BIN"
"$BIN" create server srv -p "$P_SRV" --http "$T/www" --idle-timeout 2 -s >/dev/null 2>&1
"$BIN" create proxy fc -p "$P_FC" --domain fc.test --backend "fastcgi://unix:$T/none.sock" --root "$T/www" \
    --idle-timeout 2 -s >/dev/null 2>&1
for p in "$P_SRV" "$P_FC"; do
    ready_tcp 127.0.0.1 "$p" 15 || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done

# The sweep runs every 30 seconds, so 65 cover one that finds each stopped client past the timeout.
r=$(python3 "$T/client.py" 65 \
    "srv-close,$P_SRV,/big.bin,localhost,stopped,close" \
    "srv-keep,$P_SRV,/big.bin,localhost,stopped,keep" \
    "srv-slow,$P_SRV,/big.bin,localhost,slow,close" \
    "fc-close,$P_FC,/big.bin,fc.test,stopped,close" \
    "fc-keep,$P_FC,/big.bin,fc.test,stopped,keep" \
    "fc-slow,$P_FC,/big.bin,fc.test,slow,close" 2>&1 | tail -1)
for want in srv-close=reset srv-keep=reset srv-slow=open fc-close=reset fc-keep=reset fc-slow=open; do
    name=${want%%=*}
    got=$(tr ' ' '\n' <<<"$r" | grep "^$name=" || true)
    check "$name: ${want#*=} after the timeout" "${got:-$name=none}" "$want"
done

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
