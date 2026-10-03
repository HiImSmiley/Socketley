#!/usr/bin/env bash
# Integration test: a storage runtime's configuration, its refusals and what
# survives a stop, a killed worker and a restarted daemon.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   refusals    a runtime with no --dir, or with neither --anonymous nor a way
#               to authenticate, is not made; a shard count above the limit is
#               refused, and --tls with a certificate that cannot be read does
#               not start (the TLS runtime itself is test_storage_tls.sh)
#   durability  an object put is served after `stop` and `start`, after its
#               worker is killed with SIGKILL, and after the daemon itself is
#               restarted and brings the runtime back on its own; an upload cut
#               short by the kill leaves no object and no temporary file
#   config      `show` names the directory and anonymous access, `import` moves
#               the quota under a serving runtime and refuses the directory,
#               `edit` names `import` for the settings only it can change
#   listeners   --listen unix: serves over the node, --max-connections holds
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stglife

P1=$((SL_PORT_BASE+1541))
P2=$((SL_PORT_BASE+1542))
P3=$((SL_PORT_BASE+1543))
DATA="$SOCKETLEY_TMPD/objects"
SOCK="$SOCKETLEY_TMPD/stg.sock"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() {   # name got want
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi
}
contains() { # name text needle
    if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi
}

cleanup() {
    for r in stgp stgu stgc; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in stgp stgu stgc; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
body() { curl -s "$@"; }
wait_up() {   # port
    for _ in $(seq 1 100); do
        [ "$(code "http://127.0.0.1:$1/")" = 200 ] && return 0
        sleep 0.1
    done
    return 1
}
worker_pid() { "$BIN" stats "$1" 2>/dev/null | sed -n 's/^pid://p'; }

echo "=== Integration: storage configuration, refusals and durability ==="
daemon_start "$BIN"

# ── refusals ────────────────────────────────────────────────────────────────
out=$("$BIN" create storage x1 -p "$P3" --anonymous 2>&1); rc=$?
expect "create with no --dir is refused" "$rc" 1
contains "and names --dir" "$out" "--dir"
out=$("$BIN" create storage x2 -p "$P3" --dir "$DATA" 2>&1); rc=$?
expect "create with neither --anonymous nor credentials is refused" "$rc" 1
contains "and names --anonymous" "$out" "--anonymous"
out=$("$BIN" create storage x3 -p "$P3" --dir "$DATA" --anonymous --tls --cert /nonexistent.pem --key /nonexistent-key.pem -s 2>&1); rc=$?
expect "--tls with a certificate that cannot be read does not start" "$rc" 1
"$BIN" remove x3 >/dev/null 2>&1 || true
out=$("$BIN" create storage x4 -p "$P3" --dir "$DATA" --anonymous --shards 65 2>&1); rc=$?
expect "create with more shards than the limit is refused" "$rc" 1
contains "and says why" "$out" "shards"
out=$("$BIN" create storage x5 -p "$P3" --dir "$DATA" --anonymous --max-bytes 12x 2>&1); rc=$?
expect "create with a bad --max-bytes is refused" "$rc" 1
out=$("$BIN" create storage x6 -p "$P3" --dir "$DATA" --anonymous --bogus 2>&1); rc=$?
expect "create with an unknown flag is refused" "$rc" 1
ls_out=$("$BIN" ls 2>&1)
if has "$ls_out" x1 || has "$ls_out" x2 || has "$ls_out" x3 || has "$ls_out" x4; then
    bad "a refused create leaves nothing behind" "$ls_out"
else ok "a refused create leaves nothing behind"; fi

# ── durability ──────────────────────────────────────────────────────────────
"$BIN" create storage stgp -p "$P1" --dir "$DATA" --anonymous -s >/dev/null 2>&1
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
curl -s -X PUT "http://127.0.0.1:$P1/durable-bucket" -o /dev/null
head -c 700000 /dev/urandom > "$SOCKETLEY_TMPD/blob"
want=$(md5sum < "$SOCKETLEY_TMPD/blob" | cut -d' ' -f1)
expect "a put answers 200" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/blob" "http://127.0.0.1:$P1/durable-bucket/dir/blob")" 200
curl -s -X PUT --data-binary "small" "http://127.0.0.1:$P1/durable-bucket/small" -o /dev/null
curl -s -X PUT "http://127.0.0.1:$P1/second-bucket" -o /dev/null

serves() {   # label
    got=$(body "http://127.0.0.1:$P1/durable-bucket/dir/blob" | md5sum | cut -d' ' -f1)
    expect "$1: the large object is intact" "$got" "$want"
    expect "$1: the small object is intact" "$(body "http://127.0.0.1:$P1/durable-bucket/small")" "small"
    lst=$(body "http://127.0.0.1:$P1/")
    if has "$lst" "durable-bucket" && has "$lst" "second-bucket"; then ok "$1: both buckets are listed"
    else bad "$1: both buckets are listed" "$lst"; fi
}

"$BIN" stop stgp >/dev/null 2>&1
sleep 0.5
expect "a stopped runtime answers nobody" "$(code --max-time 2 "http://127.0.0.1:$P1/")" 000
"$BIN" start stgp >/dev/null 2>&1
wait_up "$P1" || bad "the runtime comes back after stop and start" "no answer"
serves "after stop and start"

wpid=$(worker_pid stgp)
[ -n "$wpid" ] && kill -9 "$wpid" 2>/dev/null
for _ in $(seq 1 100); do
    np=$(worker_pid stgp)
    [ -n "$np" ] && [ "$np" != "$wpid" ] && wait_up "$P1" && break
    sleep 0.2
done
if [ -n "${np:-}" ] && [ "$np" != "$wpid" ]; then ok "the supervisor replaces a killed worker"; else bad "the supervisor replaces a killed worker" "old $wpid new ${np:-none}"; fi
serves "after the worker was killed"

# An upload cut short by the kill: no object, no temporary file.
python3 - "$P1" <<'PYEOF' &
import os, socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"PUT /durable-bucket/cut HTTP/1.1\r\nHost: x\r\nContent-Length: 50000000\r\n\r\n" + os.urandom(3000000))
time.sleep(30)
PYEOF
CUT_BG=$!
sleep 1.5
wpid=$(worker_pid stgp)
[ -n "$wpid" ] && kill -9 "$wpid" 2>/dev/null
kill "$CUT_BG" 2>/dev/null; wait "$CUT_BG" 2>/dev/null
for _ in $(seq 1 100); do
    np=$(worker_pid stgp)
    [ -n "$np" ] && [ "$np" != "$wpid" ] && wait_up "$P1" && break
    sleep 0.2
done
expect "an upload cut by a kill left no object" "$(code "http://127.0.0.1:$P1/durable-bucket/cut")" 404
left=$(ls "$DATA/durable-bucket/tmp" 2>/dev/null | wc -l)
expect "and no temporary file after the restart" "$left" 0
serves "after the upload was cut"

# The daemon itself restarted: the runtime was running, so it comes back.
kill "$SOCKETLEY_DPID" 2>/dev/null
for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
sleep 0.5
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"
wait_up "$P1" || bad "the runtime restarts with the daemon" "no answer on $P1"
serves "after the daemon restarted"
contains "ls shows it Up" "$("$BIN" ls 2>&1)" "Up"

# ── configuration ───────────────────────────────────────────────────────────
shown=$("$BIN" show stgp 2>&1)
contains "show names the type" "$shown" '"type": "storage"'
contains "show names the directory" "$shown" "\"dir\": \"$DATA\""
contains "show names anonymous access" "$shown" '"anonymous": true'

out=$("$BIN" edit stgp --dir /tmp/elsewhere 2>&1); rc=$?
expect "edit --dir is refused" "$rc" 1
contains "and points at import" "$out" "import"
out=$("$BIN" edit stgp --bogus 2>&1); rc=$?
expect "edit with an unknown flag is refused" "$rc" 1

echo '{"name":"stgp","type":"storage","dir":"/tmp/elsewhere"}' > "$SOCKETLEY_TMPD/bad.json"
out=$("$BIN" import stgp < "$SOCKETLEY_TMPD/bad.json" 2>&1); rc=$?
expect "import of another directory into a running runtime is refused" "$rc" 1
contains "and says so" "$out" "directory"

# The quota moves under a serving runtime, and what is held stays held.
echo '{"name":"stgp","type":"storage","max_bytes":1300000}' > "$SOCKETLEY_TMPD/quota.json"
"$BIN" import stgp < "$SOCKETLEY_TMPD/quota.json" >/dev/null 2>&1
sleep 0.5
head -c 500000 /dev/urandom > "$SOCKETLEY_TMPD/half"
expect "a put inside the quota is 200" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/half" "http://127.0.0.1:$P1/second-bucket/h1")" 200
sc=$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/half" "http://127.0.0.1:$P1/second-bucket/h2")
expect "a put that would pass the quota is 507" "$sc" 507
contains "and is StorageFull" "$(body -X PUT --data-binary @"$SOCKETLEY_TMPD/half" "http://127.0.0.1:$P1/second-bucket/h3")" "<Code>StorageFull</Code>"
expect "an object put before the quota is still served" "$(body "http://127.0.0.1:$P1/durable-bucket/small")" "small"
expect "the refused body left nothing" "$(code "http://127.0.0.1:$P1/second-bucket/h2")" 404
echo '{"name":"stgp","type":"storage","max_bytes":0}' > "$SOCKETLEY_TMPD/noquota.json"
"$BIN" import stgp < "$SOCKETLEY_TMPD/noquota.json" >/dev/null 2>&1
sleep 0.5
expect "with the quota lifted the same put succeeds" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/half" "http://127.0.0.1:$P1/second-bucket/h2")" 200

# ── listeners ───────────────────────────────────────────────────────────────
if "$BIN" create storage stgu --listen "unix:$SOCK" --dir "$SOCKETLEY_TMPD/unixobjs" --anonymous -s >/dev/null 2>&1; then
    for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
    expect "a unix listener serves" "$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" http://x/)" 200
    curl -s --unix-socket "$SOCK" -X PUT http://x/unix-bucket -o /dev/null
    expect "a unix listener stores" "$(curl -s --unix-socket "$SOCK" -X PUT --data-binary hi http://x/unix-bucket/k -o /dev/null -w '%{http_code}')" 200
    expect "and reads back" "$(curl -s --unix-socket "$SOCK" http://x/unix-bucket/k)" "hi"
    "$BIN" stop stgu >/dev/null 2>&1
    # A stop is answered before the worker has finished, and the worker removes the node as it ends.
    for _ in $(seq 1 100); do [ -e "$SOCK" ] || break; sleep 0.1; done
    if [ -e "$SOCK" ]; then bad "stop removes the socket node" "$SOCK is still there"; else ok "stop removes the socket node"; fi
else bad "a runtime listens on a unix path" "create was refused"; fi

"$BIN" create storage stgc -p "$P2" --dir "$SOCKETLEY_TMPD/connobjs" --anonymous --max-connections 2 -s >/dev/null 2>&1
wait_up "$P2" || bad "the --max-connections runtime comes up" "no answer"
held=$(python3 - "$P2" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
a = socket.create_connection(("127.0.0.1", port)); b = socket.create_connection(("127.0.0.1", port))
time.sleep(0.3)
c = socket.create_connection(("127.0.0.1", port))
c.settimeout(2)
c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
try:
    data = c.recv(100)
except ConnectionResetError:
    data = b""
except Exception:
    data = b"timeout"
print("closed" if data == b"" else "served")
PYEOF
)
expect "a third connection past --max-connections 2 is closed" "$held" "closed"
wait_up "$P2" && ok "and the runtime serves again once they are gone" || bad "the runtime serves again" "no answer"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
