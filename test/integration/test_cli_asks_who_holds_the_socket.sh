#!/usr/bin/env bash
# Integration test: `socketley --lua` and `socketley export` ask what holds the daemon socket before they send it a
# word, as every other command does.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * --lua writing `plan` and `create` lines, every flag a runtime is made with and its --master-pw with them, to
#     whatever listens at the socket path -- /tmp/socketley.sock is shared by every user of the machine
#   * export asking such a listener for its runtimes and writing what it said into the export
#   * export naming a file after a listed runtime whose name is a path, so `../../x` wrote outside the export
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate whoholds
W=$(mktemp -d /tmp/socketley-whoholds-XXXXXX)
SQUAT=""
squat_stop() { [ -n "$SQUAT" ] && kill "$SQUAT" 2>/dev/null; wait "$SQUAT" 2>/dev/null; SQUAT=""; rm -f "$SOCKETLEY_SOCKET"; }
cleanup() { squat_stop; daemon_stop; rm -rf "$W"; }
trap cleanup EXIT

# A listener at the daemon's path that writes down every byte it is sent and answers like no daemon does.
cat > "$W/squat.py" <<'EOF'
import json, socket, sys
path, log, mode = sys.argv[1], sys.argv[2], sys.argv[3]
name = sys.argv[4] if len(sys.argv) > 4 else ""
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(16)
while True:
    c, _ = s.accept()
    c.settimeout(2)
    buf = b""
    try:
        while not buf.endswith(b"\n"):
            d = c.recv(65536)
            if not d:
                break
            buf += d
    except OSError:
        pass
    with open(log, "ab") as f:
        f.write(buf)
    cmd = buf.decode("utf-8", "replace").strip()
    if mode == "mimic" and cmd == "ping":
        reply = b"\x00socketley-daemon 0.0.0 1 1:1 /nonexistent\n\x00"
    elif mode == "mimic" and cmd == "ls --json":
        reply = b"\x00" + json.dumps([{"name": name, "type": "server", "status": "stopped"}]).encode() + b"\x00"
    elif mode == "mimic" and cmd.startswith("show "):
        reply = b"\x00" + json.dumps({"type": "server", "name": name, "was_running": False}).encode() + b"\x00"
    elif mode == "foreign" and not cmd.startswith("show "):
        reply = b"\x00{}\x00"
    else:
        reply = b"\x01\x00"
    try:
        c.sendall(reply)
    except OSError:
        pass
    c.close()
EOF
squat() {   # mode [name]: a listener at the socket path, its bytes in $W/heard
    squat_stop
    : > "$W/heard"
    python3 "$W/squat.py" "$SOCKETLEY_SOCKET" "$W/heard" "$@" &
    SQUAT=$!
    for _ in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
}
# What the listener heard besides the probe's `ping`.
heard_more() { grep -av '^ping$' "$W/heard"; }

echo "=== Integration: --lua and export ask what holds the socket first ==="

cat > "$W/setup.lua" <<'EOF'
runtimes = {
    { type = "server", name = "web", port = 19999, master_pw = "hunter2-not-for-strangers", start = true }
}
EOF

# ─── --lua ──────────────────────────────────────────────────────────────────
squat foreign
out=$("$BIN" --lua "$W/setup.lua" 2>&1); rc=$?
if [ "$rc" -eq 2 ] && [ -z "$(heard_more)" ] && ! grep -aq hunter2 "$W/heard"; then
    ok "--lua sends nothing past the probe to a listener that is no daemon"
else
    bad "--lua sends nothing to a listener that is no daemon" "rc $rc: $out / heard: $(head -c 300 "$W/heard")"
fi
case "$out" in *"not a socketley daemon"*) ok "and says what holds the socket" ;;
    *) bad "--lua says what holds the socket" "$out" ;; esac

# ─── export ─────────────────────────────────────────────────────────────────
out=$("$BIN" export "$W/exp" 2>&1); rc=$?
if [ "$rc" -eq 2 ] && [ -z "$(heard_more)" ] && [ ! -e "$W/exp/config.lua" ]; then
    ok "export asks a listener that is no daemon nothing and writes nothing"
else
    bad "export asks a listener that is no daemon nothing" "rc $rc: $out / heard: $(head -c 300 "$W/heard")"
fi

# ─── a name that is a path ──────────────────────────────────────────────────
# A listener that passes for a daemon, as one of this user's own can, lists a runtime whose name climbs out of the
# export.
squat mimic "../../escaped"
out=$("$BIN" export "$W/exp2" 2>&1); rc=$?
if [ "$rc" -eq 2 ] && [ ! -e "$W/escaped.lua" ] && [ ! -e "$W/exp2/config.lua" ]; then
    ok "export refuses a runtime name no runtime may have, and writes no file by it"
else
    bad "export refuses a name that is a path" "rc $rc: $out / $(ls -R "$W" 2>&1 | head -20)"
fi

# ─── nothing there ──────────────────────────────────────────────────────────
squat_stop
out=$("$BIN" --lua "$W/setup.lua" 2>&1); rc=$?
case "$out" in *"failed to connect to daemon"*) [ "$rc" -eq 2 ] && [ ! -S "$SOCKETLEY_SOCKET" ] && ok "--lua with no daemon says so, and starts none" \
    || bad "--lua with no daemon" "rc $rc: $out" ;; *) bad "--lua with no daemon says so" "rc $rc: $out" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
