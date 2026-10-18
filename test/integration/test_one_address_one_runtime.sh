#!/usr/bin/env bash
# Integration test: two runtimes may not hold one listening address.
#
# SO_REUSEPORT is set on every listener this daemon opens, and it has to be:
# it is the whole mechanism behind --shards, which serves one runtime from N
# worker processes on one port.  The kernel cannot tell that from a SECOND
# RUNTIME claiming the same number.  It accepts the bind and hands each new
# connection to one of them.
#
# Measured on a private daemon before this fix:
#
#     create server a1 -p P     -> exit 0
#     create server a2 -p P     -> exit 0
#     start a1                  -> exit 0
#     start a2                  -> exit 0          <- nothing said, anywhere
#     ss -ltn                   -> two listeners on P
#     20 messages through P     -> a1 got 9, a2 got 11
#
# Nine and eleven.  Not a failure, not a warning, not a line in the log: half
# the traffic to a runtime the operator was not talking to.  `ps` showed both
# as Up on port P and was telling the truth.
#
# ─── THE TREE ALREADY KNEW ──────────────────────────────────────────────────
#
# Three places say this in the project's own words, and each guards only its
# own corner:
#
#   man/socketley.1, on --shards with --listen: "N processes on one --listen
#   unix: path would unlink each other's node and only the last to bind would
#   be reachable.  Both are refused rather than accepted and quietly ignored."
#
#   cache_instance.h, on the per-shard --cluster port: "bound only when sharded
#   and deliberately without SO_REUSEPORT, because with it a second process
#   binding this port would be accepted and answer -MOVED for keys it does not
#   hold."
#
#   man/socketley-help.sh, on adopting another daemon's state directory: that
#   copy is skipped because taking those runtimes "would mean binding ports it
#   is already serving -- which SO_REUSEPORT lets succeed silently."
#
# The hazard is named three times.  Between two runtimes of one daemon it was
# unguarded.
#
# ─── WHERE THE RULE LIVES ───────────────────────────────────────────────────
#
# runtime_manager::start(), which is the one function all ten start call sites
# reach -- create, start, edit, restart, reload, add, attach, a script's
# socketley.create, the crash supervisor, and the daemon's boot restore, which
# reads state files and would otherwise blend two runtimes back together at
# every reboot with nothing on the terminal to read.
#
# The manager is also the only place the question can be asked: an instance
# knows its own address and the kernel will not refuse it, so neither half can
# see the collision on its own.
#
# ─── WHAT MUST STILL BE ACCEPTED ────────────────────────────────────────────
#
# A rule that over-refuses is worse than the defect, so half of this file is
# the negative cases: a restart taking back its own port, N shards sharing one
# port on purpose, a UDP server beside a TCP one on the same number (separate
# kernel namespaces, and both were measured up and each hearing only its own),
# and a clustered cache holding base+1..base+N.
#
# NOT tested here, on purpose: two runtimes that both take the DEFAULT port
# because neither was given -p.  That is the same comparison -- get_port() ? :
# server_default_port, in listen_addresses() -- but proving it means binding
# 8000 on this machine, and every other file in this directory stays inside the
# window lib_ports.sh claimed precisely so a suite cannot collide with whatever
# else is on the box.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate oneaddr

P_DUP=$((SL_PORT_BASE+1840))
P_MIX=$((SL_PORT_BASE+1841))
P_UDP=$((SL_PORT_BASE+1842))
P_RST=$((SL_PORT_BASE+1843))
P_SHD=$((SL_PORT_BASE+1844))
P_CLU=$((SL_PORT_BASE+1846))
P_BOOT=$((SL_PORT_BASE+1849))

NAMES="oa_first oa_second oa_proxy oa_tcp oa_udp oa_rst oa_shd oa_clu \
       oa_clash oa_u1 oa_u2 oa_b1 oa_b2"
UPATH="$SOCKETLEY_TMPD/oa_shared.sock"

PASS=0; FAIL=0; TOTAL=0

# stdout as well as stderr, because errors go to stdout here and section 7
# removes most of these on purpose -- so a clean run would otherwise end in
# eleven "runtime not found" lines printed after the results.
cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

check() {   # label expected actual
    if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi
}

# A refusal has to name BOTH runtimes, because "port in use" sends the operator
# looking at the kernel and the thing holding it is one of their own.
refused_naming() {   # label held-by claimant -- then the command
    local label=$1 holder=$2 claimant=$3; shift 3
    local out
    out=$("$@" 2>&1) && { bad "$label" "the command SUCCEEDED, output '$out'"; return; }
    if grep -q "$holder" <<<"$out" && grep -q "$claimant" <<<"$out"; then ok; else
        bad "$label" "expected both '$holder' and '$claimant' in '$out'"; fi
}

accepted() {   # label -- then the command
    local label=$1; shift
    local out
    if out=$("$@" 2>&1); then ok; else
        bad "$label" "refused, and it must not be: '$out'"; fi
}

listeners_on() { ss -ltnH 2>/dev/null | awk -v p=":$1" \
    '{ n = split($4, a, ":"); if (":" a[n] == p) c++ } END { print c+0 }'; }

# The measurement that found this: send N messages and ask each runtime how
# many it heard.  One connection could never tell "the other one got it" from
# "nobody did", which is exactly why the split was invisible.
heard_by() {   # name
    "$BIN" stats "$1" 2>/dev/null | sed -n 's/^total_messages:\(.*\)$/\1/p'
}

# A restart that keeps this test's isolation, because daemon_stop deletes the
# state directory the planted file lives in, and the log is truncated so
# daemon_start does not match the previous run's "daemon started".
daemon_kill() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        for c in $(pgrep -P "$SOCKETLEY_DPID" 2>/dev/null); do
            kill -9 "$c" 2>/dev/null || true
        done
        kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
        wait "$SOCKETLEY_DPID" 2>/dev/null || true
    fi
    for _ in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] || break; sleep 0.1; done
    rm -f "$SOCKETLEY_SOCKET"
}
daemon_boot() {
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

echo "=== Integration: one listening address, one runtime ==="
daemon_start "$BIN"

# ─── 1. Two servers, one port ───────────────────────────────────────────────
create_ok "first on the port"  "$BIN" create server oa_first  -p "$P_DUP"
create_ok "second on the port" "$BIN" create server oa_second -p "$P_DUP"

accepted "the first one starts" "$BIN" start oa_first
ready_tcp 127.0.0.1 "$P_DUP" >/dev/null 2>&1 || true

refused_naming "the second is refused, naming both" oa_first oa_second \
    "$BIN" start oa_second

check "and only one listener is on the port" "1" "$(listeners_on "$P_DUP")"

# Not running is not the same as broken: nothing was half-built, so the refused
# runtime keeps the state it had rather than being marked failed.
STATE=$("$BIN" ps -a 2>/dev/null | awk '$2=="oa_second" { print $7 }')
if [ "$STATE" = "Failed" ]; then
    bad "the refused runtime is not marked failed" "ps says Failed"
else
    ok
fi

# ─── 2. The traffic is not split ────────────────────────────────────────────
# The assertion the nine-and-eleven measurement earned: every message lands on
# the one runtime that owns the port.
for _ in $(seq 1 20); do
    printf 'oa\n' | timeout 2 nc -q0 127.0.0.1 "$P_DUP" >/dev/null 2>&1 || true
done
sleep 0.5
check "all 20 messages reached the owner"    "20" "$(heard_by oa_first)"
check "and none reached the refused runtime" "0"  "$(heard_by oa_second)"

# ─── 3. Across runtime types, because a port is a port ──────────────────────
create_ok "a server on the mixed port" "$BIN" create server oa_tcp -p "$P_MIX"
create_ok "a proxy on the same one"    "$BIN" create proxy oa_proxy \
    -p "$P_MIX" --backend "127.0.0.1:$((SL_PORT_BASE+1899))"
accepted "the server starts" "$BIN" start oa_tcp
ready_tcp 127.0.0.1 "$P_MIX" >/dev/null 2>&1 || true
refused_naming "a proxy is refused off a server's port" oa_tcp oa_proxy \
    "$BIN" start oa_proxy

# ─── 4. What must NOT be refused ────────────────────────────────────────────
# Datagrams and streams are separate namespaces in the kernel: measured, both
# came up and each heard only its own traffic.
create_ok "a TCP server"          "$BIN" create server oa_rst -p "$P_UDP"
create_ok "a UDP server, same port" "$BIN" create server oa_udp -p "$P_UDP" --udp
accepted "the TCP one starts" "$BIN" start oa_rst
accepted "and UDP beside it is accepted" "$BIN" start oa_udp
"$BIN" stop oa_rst 2>/dev/null || true
"$BIN" stop oa_udp 2>/dev/null || true

# A runtime taking back its own port, ten times over.  The daemon does not
# block on a dying child -- proxy_supervisor::shutdown() reaps with WNOHANG --
# so this is the case a rule keyed on configuration instead of on state would
# have broken, and it is why the check skips runtimes that are not running.
create_ok "a server to restart" "$BIN" create server oa_shd -p "$P_RST"
accepted "it starts" "$BIN" start oa_shd
RST_BAD=0
for _ in $(seq 1 10); do
    "$BIN" restart oa_shd >/dev/null 2>&1 || RST_BAD=$((RST_BAD+1))
done
check "ten restarts onto its own port" "0" "$RST_BAD"
"$BIN" stop oa_shd 2>/dev/null || true

# The mechanism the flag exists for: N workers, one port, on purpose.
create_ok "a 3-shard server" "$BIN" create server oa_clu -p "$P_SHD" --shards 3
accepted "a sharded server starts" "$BIN" start oa_clu
ready_tcp 127.0.0.1 "$P_SHD" >/dev/null 2>&1 || true
check "and its three workers share the one port" "3" "$(listeners_on "$P_SHD")"

# ─── 5. A clustered cache holds base+1..base+N ──────────────────────────────
# The address set is computed, not configured, and the cache's own comment says
# what a stranger on one of those ports would do: answer -MOVED for keys it
# does not hold.
create_ok "a 2-shard clustered cache" "$BIN" create cache oa_u1 \
    -p "$P_CLU" --shards 2 --cluster
accepted "it starts" "$BIN" start oa_u1
ready_tcp 127.0.0.1 "$P_CLU" >/dev/null 2>&1 || true
create_ok "a server on one of its shard ports" "$BIN" create server oa_clash \
    -p "$((P_CLU+1))"
refused_naming "a shard port is held too" oa_u1 oa_clash \
    "$BIN" start oa_clash
"$BIN" stop oa_u1 2>/dev/null || true

# ─── 6. The same answer for a --listen path ─────────────────────────────────
# The second bind already failed here, so this is not new refusal -- it is the
# reason arriving on the terminal with both names in it, instead of "the worker
# did not accept its configuration (the reason is in the daemon log)".
create_ok "a server on a path"    "$BIN" create server oa_b1 --listen "unix:$UPATH"
create_ok "another on the same one" "$BIN" create server oa_b2 --listen "unix:$UPATH"
accepted "the first path server starts" "$BIN" start oa_b1
refused_naming "the second names both" oa_b1 oa_b2 "$BIN" start oa_b2
"$BIN" stop oa_b1 2>/dev/null || true

# ─── 7. The boot restore, which is the door that matters ────────────────────
# It reads state files and calls manager.start() directly, so every check
# written in a command handler is one it walks past.  Two runtimes are planted
# with the same port and was_running, and the daemon is restarted.
for n in oa_first oa_second oa_proxy oa_tcp oa_udp oa_rst oa_shd oa_clu \
         oa_clash oa_b1 oa_b2; do
    "$BIN" stop "$n" 2>/dev/null || true
done
sleep 0.3
for n in oa_first oa_second oa_proxy oa_tcp oa_udp oa_rst oa_shd oa_clu \
         oa_clash oa_b1 oa_b2; do
    "$BIN" remove "$n" 2>/dev/null || true
done

create_ok "a persisted pair, first"  "$BIN" create server oa_b1 -p "$P_BOOT"
create_ok "a persisted pair, second" "$BIN" create server oa_b2 -p "$P_BOOT"
"$BIN" start oa_b1 >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_BOOT" >/dev/null 2>&1 || true
"$BIN" start oa_b2 >/dev/null 2>&1 || true

# was_running is set on the one that started; the other is forced on disk, so
# the restore has a pair to bring back and no command handler in the way.
# The state files are written by the daemon's writer thread after the command
# has answered, so the file is waited for, and planted with the daemon down --
# a write still queued would otherwise land on top of it, and inside the full
# suite the file was not there yet at all.
STATE_DIR=$(sed -n 's/.*state directory: \(.*\)$/\1/p' "$SOCKETLEY_DLOG" | tail -1)
# The removals above are queued on the same writer, each synced with its directory, so the pair's files being there
# says nothing of them: what is waited for is the removed ones gone as well, or a kill leaves them to come back.
gone_too() {
    local n
    for n in oa_first oa_second oa_proxy oa_tcp oa_udp oa_rst oa_shd oa_clu oa_clash; do
        grep -lq "\"name\": *\"$n\"" "$STATE_DIR"/*.json 2>/dev/null && return 1
    done
    return 0
}
for _ in $(seq 1 200); do
    grep -lq '"name": *"oa_b2"' "$STATE_DIR"/*.json 2>/dev/null && gone_too && break
    sleep 0.05
done
daemon_kill
PLANTED=0
for f in "$STATE_DIR"/*.json; do
    [ -f "$f" ] || continue
    grep -q '"name": *"oa_b2"' "$f" 2>/dev/null || continue
    python3 - "$f" <<'PYEOF' && PLANTED=1
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["was_running"] = True
json.dump(d, open(p, "w"), indent=4)
PYEOF
done
check "the second runtime was planted as running" "1" "$PLANTED"

daemon_boot

# One of the two comes back and the other does not, and the daemon says which
# and why -- rather than both coming back and splitting the port.
sleep 1
UP=$("$BIN" ps -a 2>/dev/null | awk '$2=="oa_b1" || $2=="oa_b2" { if ($7=="Up") c++ } END { print c+0 }')
check "exactly one of the pair is up after a reboot" "1" "$UP"
check "and the port has one listener"                "1" "$(listeners_on "$P_BOOT")"

if grep -q "already serving" "$SOCKETLEY_DLOG" 2>/dev/null; then ok; else
    bad "the restore says why" \
        "no 'already serving' in the daemon log: $(tail -3 "$SOCKETLEY_DLOG" | tr '\n' '|')"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
