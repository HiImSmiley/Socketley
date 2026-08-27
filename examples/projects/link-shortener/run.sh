#!/usr/bin/env bash
# link-shortener -- a complete little system, brought up and torn down here.
#
#   client ──TLS──> gateway (proxy) ──http──> api (server, --lua api.lua)
#
# Everything runs against a daemon of this script's own, on its own socket and
# its own HOME, so it cannot disturb a daemon you already have running.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
BIN=${BIN:-$ROOT/bin/Release/socketley}
[ -x "$BIN" ] || { echo "build first: cd make && make config=release_x64" >&2; exit 2; }

# Ports outside every window test/lib_ports.sh hands out, so this can be run
# while the suite is running.
API_PORT=${API_PORT:-38081}
GW_PORT=${GW_PORT:-38443}

WORK=$(mktemp -d)
export SOCKETLEY_SOCKET="$WORK/d.sock"
export HOME="$WORK"

cleanup() {
    "$BIN" remove gateway >/dev/null 2>&1 || true
    "$BIN" remove api     >/dev/null 2>&1 || true
    [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "daemon"
"$BIN" daemon > "$WORK/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do
    grep -q "daemon started" "$WORK/daemon.log" 2>/dev/null && break
    sleep 0.1
done
grep -q "daemon started" "$WORK/daemon.log" || { echo "daemon did not start:"; tail -5 "$WORK/daemon.log"; exit 2; }
echo "   up on $SOCKETLEY_SOCKET"

say "a self-signed certificate for the gateway"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
echo "   $WORK/cert.pem"

say "the API server"
# No --shards here on purpose: this handler keeps its links in a Lua table, and
# a Lua table does not cross a process.  See the note at the top of api.lua.
"$BIN" create server api -p "$API_PORT" --lua "$HERE/api.lua" -s
echo "   :$API_PORT"

say "the gateway in front of it"
# --health-check http asks GET /health, which api.lua answers.  The circuit and
# retry settings are what --sidecar would set; spelled out so you can see them.
"$BIN" create proxy gateway -p "$GW_PORT" \
    --backend "127.0.0.1:$API_PORT" \
    --tls --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
    --health-check http --health-path /health --health-interval 2 \
    --circuit-threshold 5 --circuit-timeout 30 \
    --retry 2 --backend-timeout 5 -s
echo "   https://localhost:$GW_PORT"

sleep 1
CURL=(curl -sS --cacert "$WORK/cert.pem" --max-time 5)

# ─── The path prefix, which is the thing that catches everyone ──────────────
#
# An HTTP proxy answers under its OWN runtime name.  A request for /shorten is
# not a request this gateway forwards -- it is a request for a runtime called
# "shorten", which does not exist, so the answer is 404 and no backend is ever
# contacted.  The path has to be /gateway/shorten, and the backend sees
# /shorten with the prefix already stripped.
#
# That is why api.lua declares its routes as /shorten and /stats with no
# prefix: the prefix belongs to the edge, not to the handler.
BASE="https://localhost:$GW_PORT/gateway"

say "shorten a URL"
CODE=$("${CURL[@]}" -X POST --data-binary "https://example.com/a/very/long/path" \
        "$BASE/shorten" | sed 's/.*"code":"\([^"]*\)".*/\1/')
echo "   code: $CODE"

say "follow it"
"${CURL[@]}" -o /dev/null -w '   %{http_code} -> %{redirect_url}\n' \
    "$BASE/$CODE"

say "a code that does not exist"
"${CURL[@]}" -o /dev/null -w '   %{http_code}\n' "$BASE/nope"

say "what it refuses"
"${CURL[@]}" -X POST --data-binary "ftp://example.com" \
    "$BASE/shorten"; echo
"${CURL[@]}" -X POST --data-binary "" \
    "$BASE/shorten"; echo

say "counters"
"${CURL[@]}" "$BASE/stats"; echo

say "what the daemon thinks is running"
"$BIN" ls

say "done -- everything above is removed on exit"
