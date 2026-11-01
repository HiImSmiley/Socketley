#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a client runtime takes a line under --read-buffer whatever read it ends in.
#
# What it would catch: the bound checked on everything held after a read is appended, before the lines in it are
# taken.  A line of 1,040,000 bytes is under the 1 MiB bound, but the read that ends it lifts what is held past the
# bound, and the connection was closed with the line in hand -- the same rule the server and the cache had.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a client runtime takes a line under its bound ==="
daemon_isolate clibound
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1979))
unset SOCKETLEY_CONFIG
SRV_PID=""
trap '[ -n "$SRV_PID" ] && kill $SRV_PID 2>/dev/null; daemon_stop' EXIT

# A peer that sends one long line a little at a time, so it spans many reads, and then its end with more behind it.
cat > "$T/peer.py" <<'PY'
import socket, sys, time
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(1)
c, _ = l.accept()
line = b"a" * 1040000 + b"\n"
for i in range(0, 1000000, 50000):
    c.sendall(line[i:i + 50000]); time.sleep(0.01)
time.sleep(0.2)
# The line's end and what follows it at once, so the read that ends it brings more than the bound has room for.
c.sendall(line[1000000:] + b"short\n" * 40000 + b"after\n")
time.sleep(5)
PY
python3 "$T/peer.py" "$P" & SRV_PID=$!
for _ in $(seq 1 50); do ss -ltnH "( sport = :$P )" | grep -q . && break; sleep 0.1; done
daemon_start "$BIN"
"$BIN" create client lb -t "127.0.0.1:$P" -w "$T/got" -s >/dev/null 2>&1
for _ in $(seq 1 60); do grep -q '^after' "$T/got" 2>/dev/null && break; sleep 0.1; done

long=$(awk 'length($0) >= 1040000 {n++} END {print n + 0}' "$T/got" 2>/dev/null)
if [ "$long" = 1 ]; then ok; else bad "the 1,040,000-byte line is taken" "$( { wc -c < "$T/got"; } 2>/dev/null || echo 0) bytes written"; fi
if grep -q '^after' "$T/got" 2>/dev/null; then ok; else bad "and the connection lives on to the next one" "no 'after'"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
