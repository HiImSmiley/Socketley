#!/usr/bin/env bash
# chat-room -- one server runtime serving a page AND a chat socket on one port.
#
#   browser ──HTTP──> the page from www/
#           ──WS────> the same port, upgraded, handled by chat.lua
#   netcat  ──TCP───> the same port again, raw, no upgrade
#
# Runs against a daemon of its own and removes what it made on the way out.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
BIN=${BIN:-$ROOT/bin/Release/socketley}
[ -x "$BIN" ] || { echo "build first: cd make && make config=release_x64" >&2; exit 2; }

PORT=${PORT:-38090}
WORK=$(mktemp -d)
export SOCKETLEY_SOCKET="$WORK/d.sock"
export HOME="$WORK"

cleanup() {
    "$BIN" remove chat >/dev/null 2>&1 || true
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
grep -q "daemon started" "$WORK/daemon.log" || { tail -5 "$WORK/daemon.log"; exit 2; }

say "one runtime: static files and the chat socket"
# No --shards: the nick table and the history live in this process.
"$BIN" create server chat -p "$PORT" --http "$HERE/www" --lua "$HERE/chat.lua" -s
sleep 1
echo "   http://localhost:$PORT  (open it in a browser for the real thing)"

say "the page is served over plain HTTP"
curl -sS --max-time 5 -o /dev/null -w '   GET / -> %{http_code}, %{size_download} bytes, %{content_type}\n' \
    "http://127.0.0.1:$PORT/"

say "a WebSocket client joins and talks"
python3 "$HERE/wsclient.py" 127.0.0.1 "$PORT" "/nick alice" "hello from the websocket" "/who" \
    | sed 's/^/   /'

say "a raw TCP client on the same port, no upgrade"
# Auto-detection: this connection never sends an Upgrade header, so it is a
# plain line client -- and chat.lua does not know or care which it is.
printf '/nick bob\nhello from netcat\n/quit\n' \
    | timeout 5 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | sed 's/^/   /' || true

say "and the two saw each other"
python3 "$HERE/wsclient.py" 127.0.0.1 "$PORT" "/who" | sed 's/^/   /'

say "what the daemon thinks is running"
"$BIN" ls

say "done -- removed on exit"
