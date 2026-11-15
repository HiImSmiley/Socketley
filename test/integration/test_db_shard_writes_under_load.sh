#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A db runtime of several shards keeps one nudge in flight per reading shard, however many syncs come, and answers
# every write.
#
# Shard 0 used to send each reading shard a nudge after every sync, and each nudge held a ticket in the table of 4096
# its requests wait in, so tens of thousands of syncs a second filled it and a write the reading shards forwarded was
# answered 503 (2d815ea00).  Background work has since been held to three quarters of that table (d2ac40c24), and a
# reading shard is nudged only while it holds a stream (5ca2c1b1c), so what this file used to count -- refusals after
# six seconds of load, at least 100,000 writes of it -- no longer showed the defect at all (green with it put back),
# and was red on a loaded box only for the rate: 48,870 and 54,879 writes in 2 of 4 runs at load 20-30.
#
# What is measured now is the nudges themselves, on shard 0's own count of what waits for an answer at most at once
# (requests_parked_most): every reading shard holds a stream, and all of them are stopped while 40,000 writes go to
# shard 0, which syncs and nudges.  One nudge per sync parks one more ticket for every sync; one in flight per reader
# parks one per reader, and one more each second it is not answered.  A number of writes, not a rate, so a slow box
# takes longer and measures the same.  The workers are told apart by the log: shard 0 alone has it open for writing.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a sharded db keeps one nudge in flight per reader, and answers every write ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v gcc >/dev/null 2>&1 || { echo "  SKIP: gcc is required"; exit 0; }
daemon_isolate dbshardload
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1990))
# The state on tmpfs, where syncs are many: on a slow disk each takes so many writes that the syncs are few.
SHM=$(mktemp -d /dev/shm/socketley-dbshardload-XXXXXX)
export HOME="$SHM/home"
mkdir -p "$HOME"
READERS=""; HOLDER=""
# Whatever ends the test lets the stopped shards go first, then stops the streams' holder, each by its own pid.
trap 'for p in $READERS; do kill -CONT "$p" 2>/dev/null; done; [ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null; daemon_stop; rm -rf "$SHM"' EXIT
daemon_start "$BIN"

printf 'items private level\n' > "$T/schema"
printf 'backend loadsecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create db data -p "$P" --bind 127.0.0.1 --schema "$T/schema" --keys "$T/keys" --shards 4 -s >/dev/null 2>&1 \
    && ok || bad "a db runtime of four shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" != 000 ] && break; sleep 0.1; done
sleep 1

if ! gcc -O2 -o "$T/load" "$(dirname "$0")/lib_db_put_load.c" 2>"$T/cc.log"; then
    bad "the load client builds" "$(head -3 "$T/cc.log")"
    echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"; exit 1
fi

# One field of one shard's stats, "[shard N]" and its lines.
stat_of() { "$BIN" stats data 2>/dev/null | awk -v s="[shard $1]" -v k="$2" '$0 == s {on = 1; next} /^\[shard/ {on = 0} on && index($0, k ":") == 1 {sub(/^[^:]*:/, ""); print; exit}'; }

# Streams on enough connections that every shard holds one, read by a process that only drains them.
cat > "$T/hold.py" <<'PY'
import selectors, socket, sys
port, n = int(sys.argv[1]), int(sys.argv[2])
sel = selectors.DefaultSelector()
for _ in range(n):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"GET /c/items/_feed HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer loadsecret0123456789\r\n\r\n")
    s.setblocking(False); sel.register(s, selectors.EVENT_READ)
print("open", flush=True)
while True:
    for key, _ in sel.select(timeout=1):
        try:
            if not key.fileobj.recv(1 << 16): sel.unregister(key.fileobj)
        except BlockingIOError:
            pass
PY
python3 "$T/hold.py" "$P" 24 > "$T/hold.out" 2>&1 &
HOLDER=$!
held=0
for _ in $(seq 1 100); do
    held=0; for s in 1 2 3; do [ "$(stat_of "$s" feeds)" -ge 1 ] 2>/dev/null && held=$((held + 1)); done
    [ "$held" = 3 ] && break; sleep 0.1
done
[ "$held" = 3 ] && ok || bad "every reading shard holds a stream" "$held of 3 do, of 24 streams"

# Shard 0 is the worker that has the log open for writing; the reading shards read it.
writer=""; READERS=""
for p in $(pgrep -P "$SOCKETLEY_DPID"); do
    w=0
    for fd in /proc/"$p"/fd/*; do
        case "$(readlink "$fd" 2>/dev/null)" in */db/data/seg-*.log)
            fl=$(awk '/^flags:/ {print $2}' "/proc/$p/fdinfo/${fd##*/}" 2>/dev/null)
            [ -n "$fl" ] && [ $(( 0$fl & 3 )) -ne 0 ] && w=1 ;;
        esac
    done
    if [ "$w" = 1 ]; then writer="$writer $p"; else READERS="$READERS $p"; fi
done
set -- $writer; nw=$#; set -- $READERS; nr=$#
[ "$nw" = 1 ] && [ "$nr" = 3 ] && ok || bad "one worker writes the log and three read it" "writer:$writer readers:$READERS"

syncs0=$(stat_of 0 syncs); most0=$(stat_of 0 requests_parked_most)
t0=$(date +%s)
for p in $READERS; do kill -STOP "$p"; done
out=$("$T/load" "$P" 64 300 loadsecret0123456789 40000)
for p in $READERS; do kill -CONT "$p"; done
stopped=$(( $(date +%s) - t0 + 1 ))
sleep 0.5
syncs=$(( $(stat_of 0 syncs) - ${syncs0:-0} ))
most=$(stat_of 0 requests_parked_most); over=$(stat_of 0 requests_overloaded_parked)
nudges=$(stat_of 0 nudges)
echo "  readers stopped ${stopped}s: answers $out; shard 0 synced $syncs times, sent $nudges nudges, $most at most awaiting an answer (before: $most0), $over refused"
written=$(echo "$out" | tr ' ' '\n' | awk -F: '$1 ~ /^2/ {s += $2} END {print s + 0}')
refused=$(echo "$out" | tr ' ' '\n' | awk -F: '$1 !~ /^2/ {s += $2} END {print s + 0}')
[ "$written" -ge 40000 ] && ok || bad "40,000 writes reach shard 0 within five minutes" "$written answered: $out"
[ "$refused" -eq 0 ] && ok || bad "every write is taken" "$refused of $((written + refused)) answered otherwise: $out"
# Enough syncs that a nudge for each would have filled the table's share for background work (3072) three times.
[ "$syncs" -ge 1024 ] && ok || bad "shard 0 synced often enough for the nudges to show" "$syncs syncs"
# One per reader in flight and one more for each second one is not answered, beside what else shard 0 asks: tens.  A
# nudge per sync to each of three readers is three tickets a sync, past the 3,072 background work may hold.
[ "${most:-99999}" -lt 512 ] && [ "${over:-1}" -eq 0 ] && ok \
    || bad "shard 0 keeps one nudge in flight per reader, not one per sync" "$most awaiting an answer at most (want under 512), $over refused, over $syncs syncs"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
