#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: the runtime map a worker holds follows the daemon's through the pushes of only the rows that
# moved.
#
# What it would catch: a worker's socketley.list() and socketley.get() answering from a map the daemon left -- a
# row a delta never carried, a departure kept, a delta applied onto a map it was not taken against, or a worker
# restarted onto deltas it never had the base of.  The script reports every row as name:type:state, so each of
# those is a wrong line and not a timeout.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate mapdelta
T=$SOCKETLEY_TMPD; P=$((SL_PORT_BASE+1700))
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
trap 'daemon_stop' EXIT

cat >"$T/watch.lua" <<'LUA'
function on_client_message(id, msg)
    if msg == "list" then
        local out = {}
        for _, n in ipairs(socketley.list()) do
            local i = socketley.get(n)
            out[#out + 1] = n .. ":" .. (i and (i.type .. ":" .. i.state) or "nil")
        end
        table.sort(out)
        self.send(id, table.concat(out, ","))
    end
    return true
end
LUA

# The rows the watcher sees now, one request on a fresh connection.
seen() { printf 'list\n' | timeout 3 nc -q 1 127.0.0.1 "$P" 2>/dev/null | head -1 | tr -d '\r'; }
# expect LABEL ROW... -- the watcher's map equals these rows within five seconds, sorted as the script sorts.
expect() {
    local label=$1; shift
    local want got=""
    want=$(printf '%s\n' "$@" | LC_ALL=C sort | paste -sd, -)
    for _ in $(seq 1 50); do
        got=$(seen)
        [ "$got" = "$want" ] && { ok; return; }
        sleep 0.1
    done
    bad "$label" "got '$got' want '$want'"
}
worker_pid() { "$BIN" stats "$1" 2>/dev/null | awk -F: '/^pid:/{print $2}' | tr -d ' '; }

echo "=== Integration: a worker's runtime map follows the daemon's, a moved row at a time ==="
daemon_start "$BIN"
"$BIN" create server w -p "$P" --lua "$T/watch.lua" -s >/dev/null || bad "create the watcher" "refused"
for _ in $(seq 1 50); do [ -n "$(seen)" ] && break; sleep 0.1; done

rows=("w:server:running")
expect "the watcher sees itself" "${rows[@]}"

for i in $(seq 1 12); do
    "$BIN" create server "s$i" -p $((P + i)) -s >/dev/null || bad "create s$i" "refused"
    rows+=("s$i:server:running")
done
expect "twelve creates, each a row" "${rows[@]}"

"$BIN" stop s3 >/dev/null; "$BIN" stop s7 >/dev/null
rows=("${rows[@]/s3:server:running/s3:server:stopped}")
rows=("${rows[@]/s7:server:running/s7:server:stopped}")
expect "two stops, each a state" "${rows[@]}"

"$BIN" remove s5 >/dev/null
rows=("${rows[@]/s5:server:running}")
rows=($(printf '%s\n' "${rows[@]}" | grep .))
expect "a remove, a departure" "${rows[@]}"

"$BIN" create cache s5 -p $((P + 5)) -s >/dev/null || bad "create s5 again" "refused"
rows+=("s5:cache:running")
expect "the name again as another type" "${rows[@]}"

# A restarted worker starts from the whole map, and the next delta has to land on it.
old=$(worker_pid w)
[ -n "$old" ] && kill -9 "$old" 2>/dev/null
for _ in $(seq 1 100); do
    new=$(worker_pid w)
    [ -n "$new" ] && [ "$new" != "$old" ] && [ -n "$(seen)" ] && break
    sleep 0.1
done
expect "a restarted worker holds the whole map" "${rows[@]}"
"$BIN" create server s13 -p $((P + 13)) -s >/dev/null || bad "create s13" "refused"
rows+=("s13:server:running")
expect "and the delta after its restart" "${rows[@]}"

# A burst, each create a generation, read once at the end.
for i in $(seq 14 30); do
    "$BIN" create server "s$i" -p $((P + i)) -s >/dev/null || bad "create s$i" "refused"
    rows+=("s$i:server:running")
done
for i in 1 2 4; do "$BIN" remove "s$i" >/dev/null; done
rows=($(printf '%s\n' "${rows[@]}" | grep -vxE 's(1|2|4):server:running'))
expect "a burst of creates and removes" "${rows[@]}"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
