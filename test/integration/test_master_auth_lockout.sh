#!/usr/bin/env bash
# Integration test: the per-IP master-auth lockout, at both settings of the
# option it used to be gated on.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A server in master mode drops a connection at accept once that source address
# has failed ten "master <password>" attempts inside sixty seconds.  Without it
# the only bound is MAX_AUTH_FAILURES, which is *per connection* — five guesses,
# hang up, reconnect, five more, for ever.
#
# The check was written `if (!m_master_pw.empty())`.  The man page offers two
# ways to authenticate a master and says so in the --master-pw entry itself:
# a static password, or the on_master_auth(client_id, password) Lua callback,
# which "if defined, overrides --master-pw".  A server that takes the second one
# has an empty m_master_pw, so the lockout never ran on it — and nothing said
# so, because the guard is present, reads correctly, and the whole existing test
# suite configures master mode the first way.
#
# So this pins both.  The --master-pw half would have passed all along; it is
# here to make the other half's failure mean something, because a lockout that
# holds in one configuration and not the other is exactly what was shipped.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
daemon_isolate masterlockout
PORT_PW=19231
PORT_LUA=19232
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop lockout_pw    2>/dev/null || true
    "$BIN" stop lockout_lua   2>/dev/null || true
    sleep 0.3
    "$BIN" remove lockout_pw  2>/dev/null || true
    "$BIN" remove lockout_lua 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

# One connection, one line, one answer.  Prints the reply, or the empty string
# when the server closed the socket without saying anything — which is what
# being locked out at accept looks like from the outside.
attempt() {
    python3 - "$1" "$2" <<'PY'
import socket, sys
port, line = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
except OSError:
    print("<connect refused>"); raise SystemExit
s.settimeout(5)
try:
    s.sendall((line + "\n").encode())
    data = s.recv(256)
except (ConnectionResetError, BrokenPipeError, socket.timeout):
    data = b""
s.close()
print(data.decode(errors="replace").strip())
PY
}

# Ten failures from this address, then report what the eleventh connection sees.
# Sequential and one attempt per connection: the point of the guard is that
# reconnecting does not buy a fresh budget.
burn_ten_then_probe() {
    local port=$1 i
    for i in $(seq 1 10); do
        attempt "$port" "master wrongpassword" >/dev/null
    done
    attempt "$port" "master wrongpassword"
}

echo "=== Integration: master auth per-IP lockout ==="

daemon_start "$BIN"

LUA_SCRIPT="$SOCKETLEY_TMPD/master_auth.lua"
cat > "$LUA_SCRIPT" <<'EOF'
function on_master_auth(client_id, password)
    return password == "secret123"
end
EOF

# The two documented ways to authenticate a master.  The second one is the
# configuration in which the lockout used to be absent.
"$BIN" create server lockout_pw  -p "$PORT_PW"  --mode master --master-pw secret123 -s 2>&1 || true
"$BIN" create server lockout_lua -p "$PORT_LUA" --mode master --lua "$LUA_SCRIPT"    -s 2>&1 || true
sleep 0.5

# Both really are authenticating, and neither is locked out before anything has
# failed.  Without this the test below could pass against a server that refuses
# every connection for some unrelated reason.
assert_eq "$(attempt "$PORT_PW"  'master secret123')" "master: ok" "pw: correct password before any failure"
assert_eq "$(attempt "$PORT_LUA" 'master secret123')" "master: ok" "lua: correct password before any failure"

# A wrong password is answered, not dropped, while the address is under the
# limit — the lockout must not fire on the first mistake.
assert_eq "$(attempt "$PORT_PW"  'master wrongpassword')" "master: denied" "pw: first wrong password is answered"
assert_eq "$(attempt "$PORT_LUA" 'master wrongpassword')" "master: denied" "lua: first wrong password is answered"

# Ten failures from one address, then the eleventh connection: dropped at accept,
# so nothing at all comes back.
assert_eq "$(burn_ten_then_probe "$PORT_PW")"  "" "pw: locked out after ten failures"
assert_eq "$(burn_ten_then_probe "$PORT_LUA")" "" "lua: locked out after ten failures (--master-pw unset)"

# Still locked out on the next connection: the lockout is per address and does
# not reset by hanging up.
assert_eq "$(attempt "$PORT_LUA" 'master secret123')" "" "lua: lockout survives a reconnect with the right password"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
