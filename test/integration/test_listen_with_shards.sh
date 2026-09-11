#!/usr/bin/env bash
# Integration test: --listen with --shards gives each shard a node of its own.
#
# ─── THE DOCUMENTATION WAS WRONG, NOT THE CODE ──────────────────────────────
#
# man/socketley.1 said, in two places, that the pair is refused:
#
#   "--shards is refused with --listen. SO_REUSEPORT is not what a unix socket
#    does, so N processes on one --listen unix: path would unlink each other's
#    node and only the last to bind would be reachable. Both are refused
#    rather than accepted and quietly ignored."
#
#   "--listen unix:/path ... refused with --shards (SO_REUSEPORT is not a path)"
#
# and socketley-help.sh listed --shards among the flags --listen is not taken
# with. Measured, on a server, a proxy and a cache at three shards each: create
# 0, start 0, `ps` Up, and three nodes apiece --
#
#     sh#0.sock  sh#1.sock  sh#2.sock
#
# all listening, and the proxy answering on the first of them. The reasoning in
# the docs is right -- N processes on ONE path would unlink each other -- and
# the conclusion drawn from it is not: shard_listen_path() gives them different
# paths, and shard_listen_path_refusal() refuses only the case that reasoning
# actually leaves open, a name too long for the kernel once the index is in it.
#
# ─── WHY THIS FILE AND NOT A DOC EDIT ───────────────────────────────────────
#
# Because the docs said it twice and the help a third time, and nothing on
# either side would have noticed. A sentence in a man page is a claim about the
# binary, and this is the shape of claim a test can hold.
#
# The first measurement of it read "0 nodes" and nearly became a bug report:
# the probe counted files matching "sh.sock" and the nodes are named
# "sh#0.sock". The count was of the wrong thing, not of nothing.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate listenshards

P_BE=$((SL_PORT_BASE+1980))
NAMES="ls_be ls_srv ls_prx ls_cache ls_one"

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

echo "=== Integration: --listen with --shards, a node per shard ==="
daemon_start "$BIN"

# The names are base#N.sock, so a count of "base.sock" finds nothing and says
# so about the wrong thing.
nodes() { ls -1 "$SOCKETLEY_TMPD" 2>/dev/null | grep -c "^$1#[0-9]*\.sock$" || true; }
state() { "$BIN" ps -a 2>/dev/null | awk -v n="$1" '$2==n { print $7 }'; }

create_ok "a backend for the proxy" "$BIN" create server ls_be -p "$P_BE" -s

# ─── 1. A server ────────────────────────────────────────────────────────────
OUT=$("$BIN" create server ls_srv --listen "unix:$SOCKETLEY_TMPD/srv.sock" --shards 3 2>&1) || true
if [ -z "$OUT" ]; then ok; else bad "the pair is accepted on a server" "create said '$OUT'"; fi
"$BIN" start ls_srv >/dev/null 2>&1 || true
sleep 1.5
check "the server is up"            "Up" "$(state ls_srv)"
check "with one node per shard"     "3"  "$(nodes srv)"

# Each of them is a listener, not just a file.
LISTENING=0
for i in 0 1 2; do
    printf 'hello\n' | timeout 3 nc -q0 -U "$SOCKETLEY_TMPD/srv#$i.sock" >/dev/null 2>&1 \
        && LISTENING=$((LISTENING+1))
done
check "and all three answer" "3" "$LISTENING"

# ─── 2. A proxy ─────────────────────────────────────────────────────────────
OUT=$("$BIN" create proxy ls_prx --listen "unix:$SOCKETLEY_TMPD/prx.sock" --shards 3 \
      --backend "127.0.0.1:$P_BE" 2>&1) || true
if [ -z "$OUT" ]; then ok; else bad "and on a proxy" "create said '$OUT'"; fi
"$BIN" start ls_prx >/dev/null 2>&1 || true
sleep 1.5
check "the proxy is up"         "Up" "$(state ls_prx)"
check "with its three nodes"    "3"  "$(nodes prx)"

# ─── 3. A cache ─────────────────────────────────────────────────────────────
OUT=$("$BIN" create cache ls_cache --listen "unix:$SOCKETLEY_TMPD/cch.sock" --shards 3 2>&1) || true
if [ -z "$OUT" ]; then ok; else bad "and on a cache" "create said '$OUT'"; fi
"$BIN" start ls_cache >/dev/null 2>&1 || true
sleep 1.5
check "the cache is up"        "Up" "$(state ls_cache)"
check "with its three nodes"   "3"  "$(nodes cch)"

# ─── 4. One shard is the path as typed ──────────────────────────────────────
# shard_listen_path() returns the base unchanged at a single shard, so a
# runtime that is not sharded is not given a "#0" it never asked for.
create_ok "an unsharded one" "$BIN" create server ls_one \
    --listen "unix:$SOCKETLEY_TMPD/one.sock"
"$BIN" start ls_one >/dev/null 2>&1 || true
sleep 1
if [ -S "$SOCKETLEY_TMPD/one.sock" ]; then ok; else
    bad "a single shard binds the path as typed" "one.sock is not a socket node"; fi
check "and adds no index" "0" "$(nodes one)"

# ─── 5. The case that IS refused ────────────────────────────────────────────
# The kernel's limit is on the node, and a shard whose name is truncated is a
# shard nothing can reach -- so the set is judged by its longest member. This
# is what the docs' reasoning actually leaves open, and it is refused by name.
LONG="$SOCKETLEY_TMPD/$(printf 'x%.0s' $(seq 1 90)).sock"
OUT=$("$BIN" create server ls_long --listen "unix:$LONG" --shards 12 2>&1) || true
NAMES="$NAMES ls_long"
case "$OUT" in
    *"--listen with --shards"*|*"longest"*|*"limit"*) ok ;;
    "") bad "a shard name too long for the kernel is refused" \
            "it was accepted, and the longest node cannot be bound" ;;
    *) bad "a shard name too long for the kernel is refused" "got '$OUT'" ;;
esac

# ─── 6. What the man page says about all this ───────────────────────────────
# The claim and the binary in one assertion: a sentence saying the pair is
# refused outlived the code that refused it, in two places, plus the help.
MAN="$(dirname "$0")/../../man/socketley.1"
if grep -q "shards is refused with" "$MAN"; then
    bad "the man page no longer says the pair is refused" \
        "it still reads '--shards is refused with --listen', which this file just disproved"
else
    ok
fi
HELP="$(dirname "$0")/../../man/socketley-help.sh"
if grep -q -- "--shards, or (cache) --cluster" "$HELP"; then
    bad "and neither does the help" \
        "it still lists --shards among the flags --listen is not taken with"
else
    ok
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
