#!/usr/bin/env bash
# Integration test: `start NAME -i` talks to the process that holds the
# connections, in both directions.
#
# ─── THE THIRD SITE OF ONE DEFECT ───────────────────────────────────────────
#
# Every runtime lives in its own process; the object the daemon keeps is a
# placeholder whose setup() never runs. Calling a runtime's methods on it does
# nothing, or worse.
#
# That was found and fixed twice before. `send` carries the fix and names it --
# "The connections are wherever the runtime is, because calling broadcast() on
# a placeholder succeeded, returned 0, and sent the message nowhere" -- and
# `socketley <cache> <verb>` carries it with a test whose header says
#
#     socketley c set k v      wrote a store no client can read
#     socketley c get k        read that store back and agreed with itself
#
# The interactive branch was the third, and nobody had looked. Measured before
# this fix, on a private daemon, with all four faces of it:
#
#     type "hello" at a server's session   -> a real client on the port heard
#                                             NOTHING
#     a client sends "hello"               -> the terminal saw NOTHING
#     type "get realkey" at a cache        -> "nil", for a key that was there
#     type "set fromrepl viarepl"          -> a client on the port reads "nil"
#
# Two discards and two confident wrong answers. man/socketley.1 promises all
# four: "For server: stdin is broadcast to clients, received messages appear on
# stdout ... For cache: stdin accepts cache commands, responses appear on
# stdout (like redis-cli)."
#
# ─── HOW EACH DIRECTION GOT THERE ───────────────────────────────────────────
#
# Out, for a server or client: deliver_to_worker(), which `send` already uses
# and which fans across every shard.
#
# Out, for a cache: run_cache_action(), which `<cache> <verb>` already uses --
# it frames the whole line as one command, waits for the worker's answer, and
# is the reason a value with a newline in it is not read as further commands.
#
# Back: the session's own descriptor is handed to each worker over the channel
# a peer link already travels on, marked "@i" -- a marker and not a second
# channel, because the mechanism is identical and '@' is a character
# valid_name() refuses, so no runtime can ever be called that. After that
# notify_interactive() writes to the operator's terminal from the worker with
# nothing of the daemon's on the path: no frame per message, and no cost at all
# when nobody is attached.
#
# The assertions below cross the two routes wherever they can -- typed here,
# read on the port; sent on the port, read here -- because a session that talks
# only to itself is consistent and empty, which is exactly how this survived.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

P_SRV=$((SL_PORT_BASE+1910))
P_CACHE=$((SL_PORT_BASE+1912))
P_SHD=$((SL_PORT_BASE+1914))
NAMES="ia_srv ia_cache ia_shd"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

if ! command -v nc >/dev/null 2>&1; then
    echo "=== Integration: an interactive session reaches the worker ==="
    echo "  (nc absent -- this file needs it to be a client on the port)"
    echo "  Results: 0/0 passed (0 failed)"
    echo "  OK"
    exit 0
fi

echo "=== Integration: an interactive session reaches the worker ==="
daemon_isolate interactive
daemon_start "$BIN"

"$BIN" create server ia_srv   -p "$P_SRV"   >/dev/null 2>&1
"$BIN" create cache  ia_cache -p "$P_CACHE" >/dev/null 2>&1
"$BIN" create server ia_shd   -p "$P_SHD" --shards 3 >/dev/null 2>&1

# A key put in through the PORT, so the REPL below is asked for something only
# the worker's store can know.
"$BIN" start ia_cache >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P_CACHE" >/dev/null 2>&1 || true
printf 'set realkey realvalue\n' | timeout 5 nc -q1 127.0.0.1 "$P_CACHE" >/dev/null 2>&1

# The driver: one python process for the whole file, because a session is a
# live subprocess and every assertion here is about what it saw.
OUT=$(timeout 120 python3 - "$BIN" "$SOCKETLEY_SOCKET" "$P_SRV" "$P_CACHE" "$P_SHD" "$HERE" <<'PYEOF' 2>&1
import os, socket, subprocess, sys, time
sys.path.insert(0, sys.argv[6])
from lib_interactive import session, drain, say

binp, sock = sys.argv[1], sys.argv[2]
p_srv, p_cache, p_shd = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])

def report(key, value):
    print("%s=%s" % (key, value))

# ── A server, both ways ───────────────────────────────────────────────────
s = session(binp, sock, "ia_srv")
time.sleep(3); drain(s, 0.5)                    # the banner
c = socket.create_connection(("127.0.0.1", p_srv), 5); c.settimeout(3)
time.sleep(0.8)

say(s, "typed-at-the-terminal")
try:    heard = c.recv(256).decode().strip()
except Exception: heard = ""
report("SRV_CLIENT_HEARD", heard)

c.sendall(b"said-by-the-client\n")
saw = drain(s, 3.0)
report("SRV_TERMINAL_SAW",
       "yes" if "said-by-the-client" in saw else "no")
c.close(); s.kill(); s.wait()

# ── A cache, which answers ────────────────────────────────────────────────
q = session(binp, sock, "ia_cache")
time.sleep(3); drain(q, 0.5)

say(q, "get realkey")
answer = [l.strip() for l in drain(q, 3.0).splitlines() if l.strip()]
report("CACHE_GET", answer[-1] if answer else "")

say(q, "set fromrepl viarepl")
drain(q, 2.5)
q.kill(); q.wait()

# ── A restart under a live session ────────────────────────────────────────
r = session(binp, sock, "ia_srv")
time.sleep(3); drain(r, 0.5)
c1 = socket.create_connection(("127.0.0.1", p_srv), 5); c1.settimeout(3)
time.sleep(0.8)
say(r, "before-the-restart")
try:    before = c1.recv(256).decode().strip()
except Exception: before = ""
report("RESTART_BEFORE", before)
c1.close()

subprocess.run([binp, "restart", "ia_srv"],
               env=dict(os.environ, SOCKETLEY_SOCKET=sock),
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
report("RESTART_SESSION_ALIVE", "yes" if r.poll() is None else "no")

c2 = socket.create_connection(("127.0.0.1", p_srv), 5); c2.settimeout(3)
time.sleep(1.0)
say(r, "after-the-restart")
try:    after = c2.recv(256).decode().strip()
except Exception: after = ""
report("RESTART_AFTER", after)
c2.sendall(b"client-after-the-restart\n")
saw = drain(r, 3.0)
report("RESTART_TERMINAL_SAW",
       "yes" if "client-after-the-restart" in saw else "no")
c2.close(); r.kill(); r.wait()

# ── A sharded server: every shard gets the session ────────────────────────
t = session(binp, sock, "ia_shd")
time.sleep(4)
# What the session said and what the daemon says of the runtime, printed with the rest when an assertion below fails.
report("SHD_SESSION_SAID", repr(drain(t, 0.5)[-200:]))
report("SHD_LS", " ".join(l for l in subprocess.run([binp, "ls"], env=dict(os.environ, SOCKETLEY_SOCKET=sock),
                                                    capture_output=True, text=True).stdout.split("\n") if "ia_shd" in l))
conns = []
for _ in range(6):
    k = socket.create_connection(("127.0.0.1", p_shd), 5); k.settimeout(3)
    conns.append(k)
time.sleep(1.0)

say(t, "to-every-shard")
got = 0
for k in conns:
    try:
        if "to-every-shard" in k.recv(256).decode():
            got += 1
    except Exception:
        pass
report("SHD_CLIENTS_HEARD", "%d/%d" % (got, len(conns)))

for i, k in enumerate(conns):
    k.sendall(("from-client-%d\n" % i).encode())
saw = drain(t, 3.0)
report("SHD_TERMINAL_SAW",
       str(sum(1 for i in range(len(conns)) if ("from-client-%d" % i) in saw)))
for k in conns: k.close()
t.kill(); t.wait()
PYEOF
)

val() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | tail -1; }

# ─── 1. A server, out ───────────────────────────────────────────────────────
check "the client on the port heard the typed line" \
      "typed-at-the-terminal" "$(val SRV_CLIENT_HEARD)"

# ─── 2. A server, back ──────────────────────────────────────────────────────
check "and the terminal saw what the client said" "yes" "$(val SRV_TERMINAL_SAW)"

# ─── 3. A cache REPL reads the real store ───────────────────────────────────
# The key was written through the PORT and never through the session, so a
# placeholder's own store cannot know it.
check "the REPL answered from the store clients use" \
      "realvalue" "$(val CACHE_GET)"

# ─── 4. And writes into it ──────────────────────────────────────────────────
# The crossing that matters: typed at the session, read back on the port.
READBACK=$(printf 'get fromrepl\n' | timeout 5 nc -q1 127.0.0.1 "$P_CACHE" 2>/dev/null | head -1)
check "what the REPL wrote is what a client reads" "viarepl" "${READBACK:-<nothing>}"

# ─── 5. Every shard is in the session ───────────────────────────────────────
# The descriptor goes to each worker, so a typed line reaches the clients of
# all of them and what any of them says comes back.
check "all six clients across three shards heard it" "6/6" "$(val SHD_CLIENTS_HEARD)"
check "and all six were heard back"                  "6"   "$(val SHD_TERMINAL_SAW)"

# ─── 6. A restart under a live session ──────────────────────────────────────
# The descriptor belongs to the session and the old worker took its copy away,
# so a fresh one is granted beside send_start().  This is also what caught the
# stop signal: runtime_instance::stop() writes a NUL to every interactive
# descriptor meaning "the runtime you are attached to has stopped", and once
# the worker held one it fired on the restart's stop and ended the session.
# A worker cannot tell a stop from a restart; only the daemon can.
check "the session worked before the restart" "before-the-restart" "$(val RESTART_BEFORE)"
check "and survived it"                       "yes"               "$(val RESTART_SESSION_ALIVE)"
check "and reaches the new worker"            "after-the-restart" "$(val RESTART_AFTER)"
check "in both directions"                    "yes"               "$(val RESTART_TERMINAL_SAW)"

# ─── 7. Nothing was left behind ─────────────────────────────────────────────
# A session that ends leaves the runtime serving: the worker's write fails with
# EPIPE and notify_interactive() prunes the descriptor itself.
STATE=$("$BIN" ps -a 2>/dev/null | awk '$2=="ia_srv" { print $7 }')
check "the runtime is still up after the session ended" "Up" "$STATE"

STILL=$(printf 'after-the-session\n' | timeout 5 nc -q1 127.0.0.1 "$P_SRV" >/dev/null 2>&1; echo $?)
check "and still taking connections" "0" "$STILL"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { printf '%s\n' "$OUT" | sed 's/^/    driver: /'; echo "  FAILED"; }
[ "$FAIL" -eq 0 ]
