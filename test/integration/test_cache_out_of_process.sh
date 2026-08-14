#!/usr/bin/env bash
# Integration test: a cache runs in a worker process of its own.
#
# Running in a worker was once a proxy-only arrangement, for two reasons that
# were both incidental.  The worker called create_runtime(runtime_proxy, ...)
# with the type written into the source rather than read from the config frame
# the daemon had just sent it; and the flag that asked for it sat in
# parse_proxy_flags, so a cache was answered "unknown flag" rather than given
# one.  The supervisor never needed either: it forks, hands over a config frame,
# restarts and reads stats back, and it held a proxy_instance* it never
# dereferenced.  A worker is now what every runtime gets unless it asks for
# --daemon-process.
#
# What this file holds down is that the CLI cannot tell the difference — the
# same assertions would pass against an in-process cache, which is the point —
# EXCEPT for the one that can only be true of a worker: the port belongs to a
# different process than the daemon.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheoop

PORT=$((SL_PORT_BASE+1180))

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

if "$BIN" create cache oopc -p "$PORT" --resp -s >/dev/null 2>&1; then
    ok
else
    bad "a cache accepts" \
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

# A shell match and not `printf | grep -q`, and the dump is why.
#
# The nightly of 2026-08-14 failed this assertion in the Release job alone --
# Sanitize, TSan and the invariants build all passed it in the same run -- and
# printed, as the value it had just declined to match,
# "...|keys:1|commands_processed:4|get_hits:1|...".  The regex matches that
# string.  The pipeline said otherwise.
#
# The obvious mechanism is `grep -q` exiting on its first match and leaving
# printf to die on SIGPIPE, which `set -o pipefail` at the top of this file
# would then turn into a failed condition.  That was tested and does NOT hold
# here: 5000 iterations idle and 20000 under twelve-way CPU load produced zero
# failures, and eight full runs of this test produced zero.  So the cause is
# unexplained, and this is not a claim that it was the pipe.
#
# What it is: the same question asked with no pipe, no second process and no
# exit status to be ambiguous about, so whatever it was cannot reach this line
# again -- and, if the assertion ever does fail, `od -c` of the exact bytes the
# daemon returned rather than a rendering of them, because a rendering is what
# made the last failure impossible to read.
if [[ "$ST" =~ commands_processed:[1-9] ]]; then ok; else
    bad "stats report commands the worker served" \
        "$(printf '%s' "$ST" | tr '\n' '|')" \
        "raw bytes of the stats reply:" \
        "$(printf '%s' "$ST" | od -c | head -20)"
fi

# ── and a server in the daemon can ask it ───────────────────────────────────
#
# The point of the whole arrangement.  `server --cache` posted into
# request_channel, which could only ever reach a target in this address space;
# now the channel parks the request, the supervisor puts it on the control
# socket it already holds, the worker hands the payload to its own runtime
# untouched, and the reply comes back to the origin with the cookie it posted.
# Neither the server nor the client can tell.
if command -v nc >/dev/null 2>&1; then
    "$BIN" create server srv -p $((PORT + 1)) --cache oopc --daemon-process -s >/dev/null 2>&1
    sleep 1.5
    SET=$(printf 'cache set foo bar\n' | timeout 5 nc -q1 127.0.0.1 $((PORT + 1)) 2>/dev/null | head -1)
    sleep 0.3
    GOT=$(printf 'cache get foo\n'     | timeout 5 nc -q1 127.0.0.1 $((PORT + 1)) 2>/dev/null | head -1)
    if [ "$GOT" = "bar" ]; then ok; else
        bad "a server in the daemon reaches a cache in another process" \
            "set said '$SET', get said '$GOT'"
    fi

    # And it really landed in the worker's store, not somewhere in the daemon.
    DIRECT=$(redis-cli -p "$PORT" GET foo 2>/dev/null)
    if [ "$DIRECT" = "bar" ]; then ok; else
        bad "the value is in the worker's own store" "redis-cli read '$DIRECT'"
    fi
    "$BIN" stop srv >/dev/null 2>&1; "$BIN" remove srv >/dev/null 2>&1
else
    echo "  (nc absent — the cross-process cache assertions did not run)"
fi

# ── and stopping one does not leave a corpse behind ─────────────────────────
#
# shutdown() signals the child and tries once to reap it, which all but never
# succeeds — the worker is unwinding its ring at that instant.  Everything after
# that relied on the health timer's waitpid, and the health timer walks the
# supervisor map, and the stop path erases the supervisor in the same statement
# that calls shutdown().  So nothing ever waited on the child again: one zombie
# per stop, held for the life of the daemon.  Ten cycles on the build before this
# was fixed leave ten of them.
if [ -n "$DAEMON_PID" ]; then
    for i in 1 2 3; do
        "$BIN" create cache "zz$i" -p $((PORT + 50 + i)) --resp -s >/dev/null 2>&1
        sleep 0.5
        "$BIN" stop "zz$i"   >/dev/null 2>&1
        "$BIN" remove "zz$i" >/dev/null 2>&1
    done
    sleep 4          # at least one health tick, which is what sweeps them
    ZOMB=$(ps -o stat= --ppid "$DAEMON_PID" 2>/dev/null | grep -c Z)
    if [ "$ZOMB" -eq 0 ]; then ok; else
        bad "a stopped worker is reaped, not left as a zombie" \
            "$ZOMB unreaped children after 3 create/stop cycles"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
