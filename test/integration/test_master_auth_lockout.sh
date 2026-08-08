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
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate masterlockout
PORT_PW=$((SL_PORT_BASE+231))
PORT_LUA=$((SL_PORT_BASE+232))
PASS=0; FAIL=0; TOTAL=0

# How many of the ten burned attempts must come back 'master: denied' before the
# drop that follows counts as evidence.  Measured shape is nine — the address
# arrives at the burn with one failure already spent by the assertion above it,
# so the tenth burned attempt is the one that trips the limit.  The floor is set
# well under that rather than at it: what has to be true is that the address had
# real budget when the burn started, so the lockout is something these ten did
# and not something already in place.  Pinning it at nine would additionally
# pin how many failures every earlier line in this file happens to spend, which
# is not what this test is about and would go red for the wrong reason the first
# time one is added.
BURN_MIN_ANSWERED=5

cleanup() {
    "$BIN" stop lockout_pw    2>/dev/null || true
    "$BIN" stop lockout_lua   2>/dev/null || true
    sleep 0.3
    "$BIN" remove lockout_pw  2>/dev/null || true
    "$BIN" remove lockout_lua 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

# assert_verdict GOT EXPECTED LABEL
#
# The empty string is its own failure, with its own sentence, and that is the
# whole point of this helper.  The assertions below used to be written
#
#     assert_eq "$(burn_ten_then_probe "$PORT_PW")" "" "pw: locked out ..."
#
# — an expectation of *nothing*, which every way of going wrong also produces.
# python3 missing, python3 dying on a syntax error, the interpreter killed by
# the OOM killer, the probe never reached at all: each yields "" and each was
# counted as a lockout that worked.  It was not wholly dead — it was watched
# failing against the pre-fix binary with `got 'master: denied', expected ''` —
# but its passing condition was satisfiable by anything at all going wrong,
# which is the same shape as an identity assertion passing on a no-op.
#
# So attempt() now names what happened instead of falling silent, every one of
# its paths prints something, and "nothing came back from the server" is the
# token <dropped> rather than the absence of output.  The absence of output can
# then mean the one thing it actually means.
assert_verdict() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ -z "$got" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: the probe printed no verdict, so it never ran — no"
        echo "        python3, or it died before it could connect.  This is the case the"
        echo "        old form could not see: it expected the empty string here, so a"
        echo "        probe that never happened passed as a lockout that worked."
        return
    fi
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

# assert_burn_landed LINE LABEL
#
# The other half of "the eleventh connection was dropped": that the ten before
# it were answered.  A port that was ALREADY locked out drops all eleven and is
# indistinguishable, from the verdict alone, from a port these ten just locked
# out — so the count of answered attempts is what makes the drop evidence.
assert_burn_landed() {
    TOTAL=$((TOTAL+1))
    local n="$1" label="$2"
    n=${n#answered=}; n=${n%% *}
    case "$n" in ''|*[!0-9]*) n="" ;; esac
    if [ -z "$n" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: no 'answered=' count in the probe result — it never ran"
        return
    fi
    if [ "$n" -ge "$BURN_MIN_ANSWERED" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: only $n of the ten wrong passwords were answered"
        echo "        'master: denied', wanted at least $BURN_MIN_ANSWERED.  Whatever the"
        echo "        eleventh connection then saw is not evidence that these ten caused"
        echo "        it: the address was already locked out, or nothing on that port was"
        echo "        answering in the first place."
    fi
}

# One connection, one line, one verdict.  Every path that completes prints a
# non-empty token, so "the server said nothing" and "the probe never ran" are
# different strings and only the first can satisfy an expectation:
#
#   <no-listener>   connect() was refused — nothing is bound to that port
#   <dropped>       accepted, then ended without a byte: what the lockout does
#   <stalled>       accepted, still open, nothing arrived before the timeout
#   <blank-reply>   bytes came back but no text — neither of the above
#   anything else   the reply, verbatim, which is what an unlocked server sends
#
# The empty string is printed by no path at all, which is what lets it mean the
# one thing it means: python3 never got as far as printing.
#
# A reset and a clean EOF are deliberately the same verdict.  Which of the two a
# dropped connection produces depends on whether anything was still queued on
# it, not on anything this test is asking about — the claim is that no answer
# comes back, and both of them are that.  A timeout is NOT folded in with them:
# a server that accepts and then hangs forever is a different failure from one
# that drops, the old form scored it as a pass too, and it should be visible.
attempt() {
    python3 - "$1" "$2" <<'PY'
import socket, sys
port, line = int(sys.argv[1]), sys.argv[2]


def verdict(port, line):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError:
        return "<no-listener>"
    s.settimeout(5)
    try:
        s.sendall((line + "\n").encode())
        data = s.recv(256)
    except (ConnectionResetError, BrokenPipeError):
        data = b""
    except socket.timeout:
        s.close()
        return "<stalled>"
    s.close()
    if not data:
        return "<dropped>"
    text = data.decode(errors="replace").strip()
    return text if text else "<blank-reply>"


print(verdict(port, line))
PY
}

# Ten failures from this address, then the eleventh connection — all eleven in
# one python3 run, reporting both halves of the claim:
#
#     answered=<n> verdict=<v>
#
# n is how many of the ten came back 'master: denied'; v is the eleventh's
# verdict in attempt()'s vocabulary.  Sequential, and one attempt per connection:
# the point of the guard is that reconnecting does not buy a fresh budget.
burn_ten_then_probe() {
    python3 - "$1" <<'PY'
import socket, sys
port = int(sys.argv[1])


def verdict(line):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError:
        return "<no-listener>"
    s.settimeout(5)
    try:
        s.sendall((line + "\n").encode())
        data = s.recv(256)
    except (ConnectionResetError, BrokenPipeError):
        data = b""
    except socket.timeout:
        s.close()
        return "<stalled>"
    s.close()
    if not data:
        return "<dropped>"
    text = data.decode(errors="replace").strip()
    return text if text else "<blank-reply>"


answered = sum(1 for _ in range(10) if verdict("master wrongpassword") == "master: denied")
print("answered=%d verdict=%s" % (answered, verdict("master wrongpassword")))
PY
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
#
# Through create_ok, not `|| true`.  This file was written after ba7a147 converted
# the other 67 sites and simply missed the pass, so a refused create here was
# discarded — in the one file in this directory whose subject is a security
# guarantee.  A port already held, a name already taken, a Lua script the daemon
# would not load: any of them left nothing listening, and every assertion below
# then measured an absent runtime.
create_ok "master-pw server created" \
    "$BIN" create server lockout_pw  -p "$PORT_PW"  --mode master --master-pw secret123 -s
create_ok "lua-callback server created" \
    "$BIN" create server lockout_lua -p "$PORT_LUA" --mode master --lua "$LUA_SCRIPT"    -s
sleep 0.5

# Both really are authenticating, and neither is locked out before anything has
# failed.  Without this the test below could pass against a server that refuses
# every connection for some unrelated reason.
assert_verdict "$(attempt "$PORT_PW"  'master secret123')" "master: ok" "pw: correct password before any failure"
assert_verdict "$(attempt "$PORT_LUA" 'master secret123')" "master: ok" "lua: correct password before any failure"

# A wrong password is answered, not dropped, while the address is under the
# limit — the lockout must not fire on the first mistake.
assert_verdict "$(attempt "$PORT_PW"  'master wrongpassword')" "master: denied" "pw: first wrong password is answered"
assert_verdict "$(attempt "$PORT_LUA" 'master wrongpassword')" "master: denied" "lua: first wrong password is answered"

# Ten failures from one address, then the eleventh connection.  Two claims, so
# two assertions: the ten were answered while the address still had budget, and
# the eleventh was ended without an answer.  Neither is worth anything alone —
# the first without the second says only that a wrong password is refused, and
# the second without the first is also what a port that was locked out before
# this file started, or never listening, would produce.
#
# `|| true` on the two captures, and it is load-bearing rather than habit.  A
# lone `VAR=$(cmd)` is a simple command whose status IS the substitution's, so
# under `set -euo pipefail` a probe that cannot run ends the file at the
# assignment — no assertion, no `Results`, no `OK`/`FAILED`.  That is the exact
# disappearance lib_daemon.sh was written against, and it is worse here than the
# hole being closed: the whole point is that a probe which never ran must be
# *reported*, and it cannot be reported by a file that is no longer running.
# The empty string survives to the assertions, which is where it is judged.
PW_BURN=$(burn_ten_then_probe "$PORT_PW") || true
assert_burn_landed "$PW_BURN" "pw: the ten wrong passwords reached a server that was answering"
assert_verdict "${PW_BURN##*verdict=}" "<dropped>" "pw: locked out after ten failures"

LUA_BURN=$(burn_ten_then_probe "$PORT_LUA") || true
assert_burn_landed "$LUA_BURN" "lua: the ten wrong passwords reached a server that was answering"
assert_verdict "${LUA_BURN##*verdict=}" "<dropped>" "lua: locked out after ten failures (--master-pw unset)"

# Still locked out on the next connection: the lockout is per address and does
# not reset by hanging up.
assert_verdict "$(attempt "$PORT_LUA" 'master secret123')" "<dropped>" "lua: lockout survives a reconnect with the right password"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
