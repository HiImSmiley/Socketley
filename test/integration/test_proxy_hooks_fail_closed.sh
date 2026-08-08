#!/usr/bin/env bash
# Integration test: the proxy's Lua hooks refuse rather than forward when they
# cannot say what they meant.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# `on_proxy_request` is where a script strips a header, redacts a field or
# rejects a request outright, and `on_proxy_response` is the same job on the way
# back.  Both used to fail open:
#
#   * a sol::error printed the message and forwarded the UNMODIFIED bytes.  An
#     error in the hook admitted exactly what the hook was there to refuse.
#   * a return that was neither a string nor nil was forwarded unchanged too,
#     so `return false` — written as a rejection, in the one language where
#     false is unambiguous — was an admission.
#
# The filter chain one file away had already settled this question the other
# way, in proxy_instance::run_request_filters: a filter that raises is refused
# with a 500 and named, and a filter that returns a third kind of value is
# refused too, with the reasoning written out in full — "Guessing at it is how a
# `return false` meant as a rejection becomes an admission."  Two hook APIs on
# one runtime with opposite rules.
#
# What refusal means here is closing, not a 500.  These two functions are the
# byte path: they carry TCP as readily as HTTP, and on HTTP they are called with
# body chunks as well as with the head, so a status line written from here would
# either be injected into a stream that is not HTTP or spliced into the middle
# of one that is.  forward_to_backend's own header states the rule this follows:
# every path out of it that does not deliver has to take the client down with
# it, because a connection that silently swallows data is worse than one that
# drops.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Three, and without them this file passes against a build where the hooks are
# broken, or where the proxy does not work at all:
#
#   * a request hook that returns a string must still reach the backend, and
#     reach it modified.
#   * a response hook that returns a string must still reach the client.
#   * the backend behind the failing RESPONSE hook must have received the
#     request.  Otherwise "the client got nothing" is satisfied by a proxy that
#     never forwarded anything, and says nothing about the response hook.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate proxyhookclosed

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

NAMES="ph_raise ph_false ph_mod ph_rraise ph_rmod ph_qhold ph_rhold"
BE_PIDS=()

cleanup() {
    # shellcheck disable=SC2086
    "$BIN" stop $NAMES 2>/dev/null || true
    sleep 0.3
    # shellcheck disable=SC2086
    "$BIN" remove $NAMES 2>/dev/null || true
    for p in "${BE_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the proxy's Lua hooks fail closed ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

daemon_start "$BIN"

# A backend that writes down every byte it is given and answers a fixed string.
# The file is the evidence: "did the request the hook was meant to stop reach
# the backend" has no other honest answer.
BE_PY="$SOCKETLEY_TMPD/be.py"
cat > "$BE_PY" <<'PY'
import socket, sys, threading, time
port, log = int(sys.argv[1]), sys.argv[2]
# "hold": answer and then keep the connection OPEN, like any keep-alive backend.
# Without it this backend closes the moment it has replied, and that close tears
# the pair down on its own -- which is precisely what hid the response arm's
# missing close for as long as it was hidden.
hold = len(sys.argv) > 3 and sys.argv[3] == "hold"
lock = threading.Lock()

def serve(c):
    try:
        c.settimeout(2)
        data = b""
        while True:
            try:
                b = c.recv(65536)
            except Exception:
                break
            if not b:
                break
            data += b
            if len(data) >= 4096:
                break
        with lock:
            with open(log, "ab") as f:
                f.write(data)
                f.flush()
        c.sendall(b"BACKEND-REPLY")
        if hold:
            time.sleep(30)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(64)
sys.stderr.write("ready\n"); sys.stderr.flush()
while True:
    try:
        c, _ = s.accept()
    except Exception:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

# poke PORT -> whatever the proxy sent back, or the empty string.
POKE_PY="$SOCKETLEY_TMPD/poke.py"
cat > "$POKE_PY" <<'PY'
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
    s.settimeout(3)
    s.sendall(b"SECRET-PAYLOAD")
    out = b""
    while True:
        try:
            b = s.recv(65536)
        except Exception:
            break
        if not b:
            break
        out += b
    s.close()
    sys.stdout.write(out.decode("utf-8", "replace"))
except Exception:
    pass
PY

# stand NAME PROXY_PORT BE_PORT HOOK_BODY_FILE [hold]
stand() {
    local name=$1 pport=$2 beport=$3 lua=$4 hold=${5:-}
    local log="$SOCKETLEY_TMPD/$name.seen"
    : > "$log"
    python3 "$BE_PY" "$beport" "$log" $hold 2>"$SOCKETLEY_TMPD/$name.be.log" &
    BE_PIDS+=("$!")
    local i
    for i in $(seq 1 50); do
        grep -q ready "$SOCKETLEY_TMPD/$name.be.log" 2>/dev/null && break
        sleep 0.1
    done
    create_ok "$name created" "$BIN" create proxy "$name" -p "$pport" \
        --backend "127.0.0.1:$beport" --protocol tcp --lua "$lua" --daemon-process -s
}

L="$SOCKETLEY_TMPD"
# Seven proxy/backend pairs, PH+0 through PH+13.
PH=$((SL_PORT_BASE+1860))
printf 'function on_proxy_request(id, data)\n  error("policy engine unreachable")\nend\n' > "$L/raise.lua"
printf 'function on_proxy_request(id, data)\n  return false\nend\n'                       > "$L/false.lua"
printf 'function on_proxy_request(id, data)\n  return "MODIFIED-PAYLOAD"\nend\n'          > "$L/mod.lua"
printf 'function on_proxy_response(id, data)\n  error("redactor unreachable")\nend\n'     > "$L/rraise.lua"
printf 'function on_proxy_response(id, data)\n  return "REDACTED-REPLY"\nend\n'           > "$L/rmod.lua"

stand ph_raise  $((PH+0)) $((PH+1)) "$L/raise.lua"
stand ph_false  $((PH+2)) $((PH+3)) "$L/false.lua"
stand ph_mod    $((PH+4)) $((PH+5)) "$L/mod.lua"
stand ph_rraise $((PH+6)) $((PH+7)) "$L/rraise.lua"
stand ph_rmod   $((PH+8)) $((PH+9)) "$L/rmod.lua"
sleep 0.8

REPLY_RAISE=$(python3 "$POKE_PY" $((PH+0)) || true)
REPLY_FALSE=$(python3 "$POKE_PY" $((PH+2)) || true)
REPLY_MOD=$(python3   "$POKE_PY" $((PH+4)) || true)
REPLY_RRAISE=$(python3 "$POKE_PY" $((PH+6)) || true)
REPLY_RMOD=$(python3  "$POKE_PY" $((PH+8)) || true)
sleep 0.6

seen() { cat "$SOCKETLEY_TMPD/$1.seen" 2>/dev/null || printf ''; }

# ── Control 1: a request hook that answers still reaches the backend ────────
SEEN_MOD=$(seen ph_mod)
case "$SEEN_MOD" in
    *MODIFIED-PAYLOAD*) pass ;;
    *) fail "control: a request hook that returns a string is forwarded" \
            "the backend behind ph_mod saw '${SEEN_MOD:-<nothing>}'," \
            "wanted it to carry MODIFIED-PAYLOAD" \
            "if this fails, nothing below is about failing closed — the hook" \
            "path is simply not running" ;;
esac

# ── A request hook that raised must not admit the request ───────────────────
SEEN_RAISE=$(seen ph_raise)
case "$SEEN_RAISE" in
    *SECRET-PAYLOAD*)
        fail "an on_proxy_request that raises does not forward the request" \
             "the backend behind ph_raise received the payload anyway" \
             "the hook is where a script strips a header or rejects a request;" \
             "an error in it admitted exactly what it was there to refuse" \
             "backend saw: $SEEN_RAISE" ;;
    *) pass ;;
esac

# ── ...and takes the connection down rather than swallowing it ──────────────
if [ -z "$REPLY_RAISE" ]; then pass; else
    fail "a refused request closes the connection" \
         "the client got '$REPLY_RAISE' from ph_raise, wanted nothing" \
         "a connection left open and accepting after a refusal keeps writing," \
         "every write succeeds, and not one byte reaches the backend"
fi

# ── `return false` is a rejection, not a value to guess at ──────────────────
SEEN_FALSE=$(seen ph_false)
case "$SEEN_FALSE" in
    *SECRET-PAYLOAD*)
        fail "an on_proxy_request returning false does not forward the request" \
             "the backend behind ph_false received the payload anyway" \
             "a non-string, non-nil return was forwarded unchanged, so the one" \
             "unambiguous way to write a rejection was an admission" \
             "backend saw: $SEEN_FALSE" ;;
    *) pass ;;
esac

# ── Control 3: the failing response hook's backend DID get the request ──────
SEEN_RRAISE=$(seen ph_rraise)
case "$SEEN_RRAISE" in
    *SECRET-PAYLOAD*) pass ;;
    *) fail "control: the request reached the backend behind ph_rraise" \
            "the backend saw '${SEEN_RRAISE:-<nothing>}'" \
            "without this, 'the client got nothing' is satisfied by a proxy" \
            "that never forwarded anything, and says nothing about the" \
            "response hook" ;;
esac

# ── Control 2: a response hook that answers still reaches the client ────────
case "$REPLY_RMOD" in
    *REDACTED-REPLY*) pass ;;
    *) fail "control: a response hook that returns a string is delivered" \
            "the client got '${REPLY_RMOD:-<nothing>}' from ph_rmod," \
            "wanted REDACTED-REPLY" ;;
esac

# ── A response hook that raised must not leak the raw response ──────────────
case "$REPLY_RRAISE" in
    *BACKEND-REPLY*)
        fail "an on_proxy_response that raises does not forward the response" \
             "the client got the backend's raw bytes: '$REPLY_RRAISE'" \
             "the hook is where a script strips a Set-Cookie or masks a field;" \
             "an error in it delivered the unredacted response it existed to" \
             "prevent" ;;
    *) pass ;;
esac

# ── Both refusals say why ───────────────────────────────────────────────────
if grep -q "on_proxy_request error.*policy engine unreachable" "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    fail "the request hook's error is logged" \
         "no on_proxy_request error in the daemon log" \
         "last lines: $(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
fi
if grep -q "on_proxy_response error.*redactor unreachable" "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    fail "the response hook's error is logged" \
         "no on_proxy_response error in the daemon log"
fi


# ─── THE CLOSE ITSELF, NOT A FLAG ───────────────────────────────────────────
#
# Both refusals set a `closing` flag, and setting a flag is not closing a
# connection: something has to act on it.  The request arm's flag is read by
# handle_client_read, which tears the pair down; the response arm set the
# CLIENT's flag while its own caller, handle_backend_read, is gated on the
# BACKEND's -- so nothing acted, and the client sat connected to a proxy that
# had decided not to answer it.
#
# Measured before the fix, against a backend that keeps its connection open:
#
#     request arm    closed_by_peer=True   0.0s   0 bytes
#     response arm   closed_by_peer=False  6.0s   0 bytes
#
# So the assertion below is the client's own socket: did the peer close it.
# Asked of a HOLDING backend on purpose -- a backend that hangs up after
# replying tears the pair down by itself, and every arm passes.
HOLD_PY="$SOCKETLEY_TMPD/hold.py"
cat > "$HOLD_PY" <<'PY_EOF'
import socket, sys, time
# Print "closed <bytes>" if the peer closed within the window, "open <bytes>"
# if it did not.  The bytes matter too: a refusal that closes but has already
# forwarded what it refused would be a different and worse defect.
port, window = int(sys.argv[1]), float(sys.argv[2])
out = b""
verdict = "open"
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(0.5)
    s.sendall(b"SECRET-PAYLOAD")
    t0 = time.time()
    while time.time() - t0 < window:
        try:
            b = s.recv(65536)
        except socket.timeout:
            continue
        except Exception:
            verdict = "closed"; break
        if not b:
            verdict = "closed"; break
        out += b
    s.close()
except Exception as e:
    verdict = "error:%s" % e
sys.stdout.write("%s %d %s" % (verdict, len(out), out[:40].decode("latin1")))
PY_EOF

# hold_probe PORT -> "closed|open <nbytes> <data>"
hold_probe() { python3 "$HOLD_PY" "$1" 4 2>/dev/null || printf 'error 0 '; }

stand ph_qhold $((PH+10)) $((PH+11)) "$L/raise.lua"  hold
stand ph_rhold $((PH+12)) $((PH+13)) "$L/rraise.lua" hold
sleep 0.8

Q_HOLD=$(hold_probe $((PH+10)))
R_HOLD=$(hold_probe $((PH+12)))

# ── Control 4: the harness can see a close at all ───────────────────────────
#
# The request arm against the same holding backend.  Without it, "the response
# arm did not close" is equally explained by a probe that cannot detect a close.
case "$Q_HOLD" in
    closed\ *) pass ;;
    *) fail "control: the request arm closes against a holding backend"             "ph_qhold answered '$Q_HOLD', wanted to start with 'closed'"             "if this is 'open' the probe cannot see a close and the assertion"             "below proves nothing about the response arm" ;;
esac

# ── The response arm must close too ─────────────────────────────────────────
case "$R_HOLD" in
    closed\ *) pass ;;
    *) fail "an on_proxy_response refusal closes the client connection"             "ph_rhold answered '$R_HOLD', wanted to start with 'closed'"             "the man page says the client connection is closed, since the"             "response this hook was to redact must not be delivered"             "unredacted -- so a client that is still connected is waiting for"             "an answer the proxy has already decided never to send" ;;
esac

# ── ...and still without delivering what it refused ─────────────────────────
case "$R_HOLD" in
    *\ 0\ *) pass ;;
    *) fail "the refused response is not delivered"             "ph_rhold received bytes: '$R_HOLD'"             "closing is not enough on its own; the bytes the hook refused"             "must not reach the client on the way out" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
