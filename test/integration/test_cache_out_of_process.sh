#!/usr/bin/env bash
# Integration test: a cache runs in a worker process of its own.
#
# `--out-of-process` existed only for proxies, for two reasons that were both
# incidental.  The worker called create_runtime(runtime_proxy, ...) with the
# type written into the source rather than read from the config frame the daemon
# had just sent it; and the flag itself sat in parse_proxy_flags, so
# `create cache ... --out-of-process` answered "unknown flag" rather than doing
# anything.  The supervisor never needed either: it forks, hands over a config
# frame, restarts and reads stats back, and it held a proxy_instance* it never
# dereferenced.
#
# What this file holds down is that the CLI cannot tell the difference — the
# same assertions would pass against an in-process cache, which is the point —
# EXCEPT for the one that can only be true of a worker: the port belongs to a
# different process than the daemon.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheoop

PORT=28101

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

cleanup() {
    "$BIN" stop oopc 2>/dev/null || true
    sleep 0.3
    "$BIN" remove oopc 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a cache in a worker process of its own ==="

if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  SKIP: redis-cli is required to speak to the cache"
    exit 0
fi

daemon_start "$BIN"
DAEMON_PID="${SOCKETLEY_DPID:-}"

if "$BIN" create cache oopc -p "$PORT" --resp --out-of-process -s >/dev/null 2>&1; then
    ok
else
    bad "a cache accepts --out-of-process" \
        "the flag was refused; it used to live in the proxy parser only"
fi

# The worker forks, execs, and builds its ring on the config frame, so it is not
# serving the instant create returns.
for _ in $(seq 1 40); do
    redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break
    sleep 0.25
done

if redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG; then ok; else
    bad "the cache answers on its port" "no PONG on $PORT after 10s"
fi

# ── it is really another process ────────────────────────────────────────────
#
# The assertion that cannot pass in-process, and the only one here that can
# tell the two arrangements apart.
PORT_PID=$(ss -ltnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p' \
           | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "$PORT_PID" ] && [ -n "$DAEMON_PID" ] && [ "$PORT_PID" != "$DAEMON_PID" ]; then
    ok
else
    bad "the listening socket belongs to a worker, not the daemon" \
        "port pid='${PORT_PID:-none}' daemon pid='${DAEMON_PID:-none}'"
fi

# ── and the CLI cannot tell ─────────────────────────────────────────────────
redis-cli -p "$PORT" SET k hello >/dev/null 2>&1
VAL=$(redis-cli -p "$PORT" GET k 2>/dev/null)
if [ "$VAL" = "hello" ]; then ok; else
    bad "a value written to the worker's cache reads back" "got '$VAL'"
fi

LS=$("$BIN" ls 2>&1 || true)
if printf '%s\n' "$LS" | awk '$2 == "oopc" && $3 == "cache" && /Up / { f=1 } END { exit !f }'; then
    ok
else
    bad "ls shows it as a running cache like any other" "$LS"
fi

# The figures have to come from the worker.  A placeholder that answered from
# its own containers reported keys:0 and commands_processed:0 for a cache that
# had just served five commands — confidently wrong, which is worse than
# missing.
sleep 2.5
ST=$("$BIN" stats oopc 2>&1 || true)
if has "$ST" "keys:1"; then ok; else
    bad "stats report the worker's store, not the placeholder's empty one" \
        "expected keys:1 after one SET" "$(printf '%s' "$ST" | tr '\n' '|')"
fi

if printf '%s\n' "$ST" | grep -qE "commands_processed:[1-9]"; then ok; else
    bad "stats report commands the worker served" \
        "$(printf '%s' "$ST" | tr '\n' '|')"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
