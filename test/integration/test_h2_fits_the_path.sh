#!/usr/bin/env bash
# suite: isolated -- its own network namespace, daemon, socket and port window, so it runs beside the others
# Integration test: an HTTP/2 connection with a round trip keeps what it has framed out of the kernel's buffer, and
# one without keeps the buffer whole.
#
# What each part would catch:
#   * fit_to_path() not called, or deciding on something other than the round trip: over a path of a few
#     milliseconds the kernel's unsent bytes behind a slow download grow to megabytes, where a stream opened later
#     waits behind all of them
#   * the setting made on every connection, which on a LAN only caps the rate: there the unsent bytes stay large
# A delay on loopback needs a network namespace of its own, which an unprivileged user namespace gives.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rn true 2>/dev/null; then
        echo "=== Integration: an HTTP/2 connection fits the path ==="
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

echo "=== Integration: an HTTP/2 connection fits the path ==="
ip link set lo up
command -v tc >/dev/null 2>&1 && tc qdisc add dev lo root netem delay 0ms 2>/dev/null \
    || { echo "  SKIP: no netem here"; exit 0; }
curl -V 2>/dev/null | grep -qi nghttp2 || { echo "  SKIP: this curl has no HTTP/2"; exit 0; }
daemon_isolate h2path
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1995))
unset SOCKETLEY_CONFIG
CURL_PID=""
trap '[ -n "$CURL_PID" ] && kill $CURL_PID 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=files.example.com \
    -addext "subjectAltName=DNS:files.example.com" -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1
mkdir -p "$T/www"; head -c $((64 << 20)) /dev/urandom > "$T/www/big.bin"
"$BIN" create server files -p $((P+1)) --http "$T/www" --domain files.example.com -s >/dev/null 2>&1
"$BIN" create proxy ent -p "$P" --tls --cert "$T/e.pem" --key "$T/e.key" -s >/dev/null 2>&1
for _ in $(seq 1 60); do f=$(find "$T" -name 'routes-ent' | head -1); [ -n "$f" ] && grep -q files.example.com "$f" && break; sleep 0.2; done

# The most of the entrance's connection the kernel holds unsent while a download is read slowly: `polls` tenths of a
# second, or until `enough` bytes are seen, since a loaded box fills the buffer late but fills it.
unsent_peak() {
    local polls=$1 enough=$2
    curl -sk --http2 --limit-rate 2M -m 20 -o /dev/null --resolve "files.example.com:$P:127.0.0.1" \
        "https://files.example.com:$P/big.bin" & CURL_PID=$!
    local peak=0 n
    for _ in $(seq 1 "$polls"); do
        sleep 0.1
        n=$(ss -tinH state established "( sport = :$P )" 2>/dev/null | grep -o 'notsent:[0-9]*' | cut -d: -f2 | sort -n | tail -1)
        [ -n "$n" ] && [ "$n" -gt "$peak" ] && peak=$n
        [ "$peak" -ge "$enough" ] && break
    done
    kill $CURL_PID 2>/dev/null; wait $CURL_PID 2>/dev/null; CURL_PID=""
    echo "$peak"
}

lan=$(unsent_peak 80 $((1 << 20)))
tc qdisc change dev lo root netem delay 2ms
wan=$(unsent_peak 30 $((64 << 20)))
echo "  unsent at most: ${lan} bytes on loopback, ${wan} with a 4 ms round trip"
if [ "$wan" -le $((512 << 10)) ]; then ok
else bad "over a round trip the kernel holds little of what is framed" "$wan bytes unsent, past 512 KiB"; fi
if [ "$lan" -ge $((1 << 20)) ]; then ok
else bad "and on loopback the buffer is left whole, which would otherwise cap the rate" "only $lan bytes unsent"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
