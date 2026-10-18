#!/usr/bin/env bash
# Integration test: every SOCKETLEY_* setting set in one place and looked up in one.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   the file     daemon = { settings = { ... } } sets a knob by its short name,
#                and a worker the daemon starts runs with it
#   the order    the file first, then the daemon's environment, then the
#                default
#   the listing  `socketley settings` says each knob's value and where it came
#                from; --all adds the tests' and the internal ones; --json
#   refusals     a name that is no setting, a value out of its range, a flag
#                that is neither true nor false, and a knob that belongs to a
#                command's environment are each named, and the daemon does not
#                start on them
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate settings
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1970))
trap 'daemon_stop' EXIT

echo "=== Integration: SOCKETLEY_* settings in one place ==="

cat > "$T/daemon.lua" <<'EOF'
daemon = { settings = { lua_timeout_ms = 300, cache_ttl_sweep_ms = 250, proxy_splice = true } }
EOF
export SOCKETLEY_CONFIG="$T/daemon.lua"
export SOCKETLEY_CACHE_TTL_SWEEP_MS=700 SOCKETLEY_DNS_CACHE_MS=1234
daemon_start "$BIN"

row() { "$BIN" settings --json | python3 -c "import json,sys; d={r['name']: r for r in json.load(sys.stdin)}; r=d.get(sys.argv[1]); print(r and (r['value'], r['from']))" "$1"; }
expect "a knob the file sets is listed with its value, from the file" "$(row lua_timeout_ms)" "('300', 'config')"
expect "a flag the file sets reads as on" "$(row proxy_splice)" "('1', 'config')"
expect "the file outranks the daemon's environment" "$(row cache_ttl_sweep_ms)" "('250', 'config')"
expect "which counts for what the file leaves unset" "$(row dns_cache_ms)" "('1234', 'environment')"
expect "a knob nothing set is its default" "$(row cache_buf_count)" "('64', 'default')"
expect "the tests' knobs are not in the plain listing" "$(row storage_stop_hold_ms)" "None"
expect "--all lists them, saying whose they are" \
    "$("$BIN" settings --all | awk '$1 == "storage_stop_hold_ms" { print $4 }')" "test"
expect "the table names its columns" "$("$BIN" settings | head -1 | awk '{ print $1, $2, $3, $4 }')" "SETTING VALUE FROM MEANING"
expect "a word it does not take is refused" "$("$BIN" settings --everything >/dev/null; echo $?)" 1

# The worker reads the file's lua_timeout_ms from the environment the daemon gave it.
cat > "$T/spin.lua" <<'EOF'
function on_message(msg)
    if msg == "spin" then
        local n = 0
        while true do n = n + 1 end
    end
end
EOF
"$BIN" create server spin -p "$P" --lua "$T/spin.lua" -s >/dev/null 2>&1
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$P") 2>/dev/null && break; sleep 0.1; done
python3 - "$P" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"spin\n")
time.sleep(0.5)
PY
seen=no
for _ in $(seq 1 50); do grep -q "on_message hit its 300ms deadline" "$SOCKETLEY_DLOG" 2>/dev/null && { seen=yes; break; }; sleep 0.1; done
expect "a worker the daemon starts runs with the file's setting" "$seen" yes
"$BIN" stop spin >/dev/null 2>&1; "$BIN" remove spin >/dev/null 2>&1

# A file that cannot be is refused whole, every reason said, and no daemon serves it.
cat > "$T/bad.lua" <<'EOF'
daemon = { settings = { storage_hash_threadz = 4, storage_recv_bufs = 99999, proxy_splice = "maybe",
                        git_token = "x" } }
EOF
out=$(SOCKETLEY_SOCKET="$T/bad.sock" SOCKETLEY_CONFIG="$T/bad.lua" timeout 10 "$BIN" daemon </dev/null; echo "rc=$?")
expect "a file whose settings cannot be is refused at start" "$(echo "$out" | tail -1)" "rc=1"
expect "a name that is no setting is named" "$(echo "$out" | grep -c 'storage_hash_threadz is no setting')" 1
expect "a value out of its range is named with the range" "$(echo "$out" | grep -c 'storage_recv_bufs is 99999, not a whole number from 0 to 4096')" 1
expect "a flag that is neither is named" "$(echo "$out" | grep -c 'proxy_splice is maybe, not true or false')" 1
expect "a command's knob is sent to the environment" "$(echo "$out" | grep -c 'git_token is read from the environment')" 1
expect "and nothing listens there" "$([ -S "$T/bad.sock" ] && echo yes || echo no)" no

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
