#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a connection sending a large file keeps the send buffer the kernel autotunes.
#
# What it would catch: SO_SNDBUF set on a socket about to send a file.  Setting it locks the buffer, and at a stock
# net.core.wmem_max the kernel clamps the request to ~416 KiB, so a download over a 50 ms round trip ran at 8.3 MB/s
# against 48 autotuned.  So the file runs in a network namespace of its own whose autotuning stops at 1 MiB, where a
# locked buffer shows as a size autotuning would never have given it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rn true 2>/dev/null; then
        echo "=== Integration: a large file goes out on an autotuned send buffer ==="
        echo "  SKIP: no unprivileged network namespace here"
        exit 0
    fi
    exec unshare -rn env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a large file goes out on an autotuned send buffer ==="
command -v ss >/dev/null 2>&1 || { echo "  SKIP: ss is required"; exit 0; }
ip link set lo up
autotune_max=$((1 << 20))
sysctl -qw net.ipv4.tcp_wmem="4096 16384 $autotune_max" 2>/dev/null || { echo "  SKIP: tcp_wmem cannot be set here"; exit 0; }
daemon_isolate fsbuf
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1960))
unset SOCKETLEY_CONFIG
CURL_PID=""
trap '[ -n "$CURL_PID" ] && kill $CURL_PID 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

# The value a 2 MiB request locks at: the kernel doubles what it was asked, up to twice wmem_max.
wmax=$(cat /proc/sys/net/core/wmem_max)
locked=$(( 2 * (wmax < 2097152 ? wmax : 2097152) ))

mkdir -p "$T/www"; head -c $((64 << 20)) /dev/urandom > "$T/www/big.bin"
"$BIN" create server files -p "$P" --http "$T/www" -s >/dev/null 2>&1
"$BIN" create storage objects -p $((P+1)) --dir "$T/stg" --anonymous -s >/dev/null 2>&1
"$BIN" create proxy site -p $((P+2)) --domain site --backend "fastcgi://unix:$T/none.sock" --root "$T/www" -s >/dev/null 2>&1
for port in "$P" $((P+1)) $((P+2)); do
    for _ in $(seq 1 50); do ss -ltnH "( sport = :$port )" | grep -q . && break; sleep 0.1; done
done
curl -s -X PUT "http://127.0.0.1:$((P+1))/bkt" >/dev/null
curl -s -X PUT --data-binary @"$T/www/big.bin" "http://127.0.0.1:$((P+1))/bkt/big.bin" >/dev/null

# The largest send buffer the serving side of a slowly read download had over two seconds.
buffer_of() {
    local port=$1 url=$2 peak=0 n
    curl -s --limit-rate 2M -m 10 -o /dev/null "$url" & CURL_PID=$!
    for _ in $(seq 1 20); do
        sleep 0.1
        n=$(ss -tmnH state established "( sport = :$port )" 2>/dev/null | grep -o 'tb[0-9]*' | tr -d tb | sort -n | tail -1)
        [ -n "$n" ] && [ "$n" -gt "$peak" ] && peak=$n
    done
    kill $CURL_PID 2>/dev/null; wait $CURL_PID 2>/dev/null; CURL_PID=""
    echo "$peak"
}

for arm in "server --http:$P:http://127.0.0.1:$P/big.bin" \
           "storage GET:$((P+1)):http://127.0.0.1:$((P+1))/bkt/big.bin" \
           "FastCGI proxy file:$((P+2)):http://127.0.0.1:$((P+2))/big.bin"; do
    name=${arm%%:*}; rest=${arm#*:}; port=${rest%%:*}; url=${rest#*:}
    tb=$(buffer_of "$port" "$url")
    echo "  $name: send buffer at most $tb, a locked one would be $locked"
    if [ "$tb" -gt 0 ] && [ "$tb" -le "$autotune_max" ] && [ "$tb" != "$locked" ]; then ok
    else bad "$name keeps an autotuned send buffer" "tb $tb, autotuning stops at $autotune_max and a locked one is $locked"; fi
done

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
