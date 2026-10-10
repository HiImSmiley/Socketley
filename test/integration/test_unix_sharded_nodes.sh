#!/usr/bin/env bash
# Integration test: --listen unix: together with --shards, one node per shard.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# The pair used to be refused, and the refusal gave its reason: "N processes
# would unlink each other's node and only the last to bind would be reachable".
# That is true of ONE path and false of N.  Each shard now binds its own,
# name#0.sock .. name#N-1.sock, by the rule companion_path already used.
#
# So the thing to catch is the refusal's own scenario coming true anyway: N-1
# nodes missing, or present but unlinked by a later shard, or all N present
# with only one of them actually served.  Every shard is therefore connected to
# BY NAME here rather than through whichever the kernel picks -- a test that
# connects to one node cannot tell four listeners from one.
#
# And the length rule, which is the one that fails late: a path is 108 bytes to
# the kernel, "#3" costs two of them, and a set whose last member does not fit
# would bind shards 0..2 and fail on 3 with three of them already serving.  It
# is refused at configuration instead, and the refusal names the longest node
# rather than the one that was typed.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a unix listener under --shards is one node per shard ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

daemon_isolate unixshard
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
D="$SOCKETLEY_TMPD"

# One connection, one line in, whatever comes back -- no redis-cli, which is
# not on every box this runs on.
UPY="$D/u.py"
cat > "$UPY" <<'PY'
import socket, sys
path, payload = sys.argv[1], sys.argv[2].encode()
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(path)
    s.sendall(payload)
    out = b''
    try:
        while True:
            b = s.recv(65536)
            if not b: break
            out += b
            if out.endswith(b'\n'): break
    except socket.timeout:
        pass
    s.close()
    sys.stdout.write(out.decode('latin1').replace('\n', ' | '))
except Exception as e:
    sys.stdout.write('ERROR:' + type(e).__name__)
PY
u() { python3 "$UPY" "$1" "$2" 2>/dev/null; }

echo "--- 1. a four-shard cache binds four nodes and every one of them answers ---"
"$BIN" create cache us_c --listen "unix:$D/kv.sock" --shards 4 -s >/dev/null 2>&1
for _ in $(seq 1 100); do
    [ "$(ls "$D"/kv#*.sock 2>/dev/null | wc -l)" -ge 4 ] && break
    sleep 0.2
done
N=$(ls "$D"/kv#*.sock 2>/dev/null | wc -l)
if [ "$N" -eq 4 ]; then ok "four nodes bound (kv#0..kv#3)"
else bad "nodes" "expected 4 nodes, found $N" "$(ls "$D"/kv* 2>/dev/null | tr '\n' ' ')"; fi

# By name, one at a time: the refusal's scenario is four paths with one
# listener behind them, and a test that connects once cannot see it.
for i in 0 1 2 3; do
    got=$(u "$D/kv#$i.sock" "set shard$i v$i
")
    case "$got" in
        *ok*) ok "node $i serves" ;;
        *) bad "node $i" "did not answer a set" "got: $got" ;;
    esac
done

echo "--- 2. the four nodes are one keyspace, not four ---"
u "$D/kv#0.sock" "set crosskey hello
" >/dev/null
allfound=1
for i in 0 1 2 3; do
    got=$(u "$D/kv#$i.sock" "get crosskey
")
    case "$got" in *hello*) ;; *) allfound=0; bad "keyspace" "node $i did not see a key written through node 0" "got: $got" ;; esac
done
[ "$allfound" = 1 ] && ok "a key written through one node is readable through all four"

echo "--- 3. a server and a proxy get the same treatment ---"
"$BIN" create server us_s --listen "unix:$D/srv.sock" --shards 4 -s >/dev/null 2>&1
"$BIN" create proxy  us_p --listen "unix:$D/px.sock" --shards 4 \
       --backend "127.0.0.1:$((SL_PORT_BASE+1499))" -s >/dev/null 2>&1
for _ in $(seq 1 100); do
    [ "$(ls "$D"/srv#*.sock "$D"/px#*.sock 2>/dev/null | wc -l)" -ge 8 ] && break
    sleep 0.2
done
S=$(ls "$D"/srv#*.sock 2>/dev/null | wc -l)
P=$(ls "$D"/px#*.sock 2>/dev/null | wc -l)
[ "$S" -eq 4 ] && ok "server bound four nodes" || bad "server" "expected 4, found $S"
[ "$P" -eq 4 ] && ok "proxy bound four nodes"  || bad "proxy"  "expected 4, found $P"

echo "--- 4. one shard is still the path as typed, with no suffix ---"
"$BIN" create cache us_1 --listen "unix:$D/one.sock" -s >/dev/null 2>&1
for _ in $(seq 1 60); do [ -S "$D/one.sock" ] && break; sleep 0.2; done
if [ -S "$D/one.sock" ] && [ ! -e "$D/one#0.sock" ]; then
    ok "an unsharded runtime binds the path it was given"
else
    bad "single" "unsharded runtime did not bind the bare path" \
        "$(ls "$D"/one* 2>/dev/null | tr '\n' ' ')"
fi

echo "--- 5. the length rule is applied to the LONGEST node, before any bind ---"
# sun_path holds 108 bytes including the terminator, so 107 is the longest a
# path may be.  106 fits and 106 + "#3" does not, which is exactly the case
# that would bind shards 0..2 and fail on 3 with three of them already serving
# -- and the case a rule reading the path as typed cannot see.
LONG="$D/$(printf 'x%.0s' $(seq 1 $((106 - ${#D} - 1))))"
[ "${#LONG}" -eq 106 ] || { bad "length" "test built a ${#LONG}-byte path, wanted 106"; }
out=$("$BIN" create cache us_long --listen "unix:$LONG" --shards 4 -s 2>&1); rc=$?
if [ -n "$(ls "$LONG"* 2>/dev/null)" ]; then
    bad "length" "a node was bound despite the set not fitting" "$(ls "$LONG"* | tr '\n' ' ')"
# Refused for the length, since a create that failed for any other reason binds nothing too.
elif [ "$rc" -eq 0 ] || ! grep -q 'is the longest of them' "$SOCKETLEY_DLOG" 2>/dev/null; then
    bad "length" "the create was not refused for its longest node" "exit $rc: $out"
else
    ok "a set whose longest node does not fit binds nothing"
fi

echo "--- 6. a client is still refused, and for its own reason ---"
out=$("$BIN" create client us_cl --listen "unix:$D/cl.sock" --shards 4 -s 2>&1)
case "$out" in
    *"does not apply to a client"*|*"no listening socket"*|*"has no listener"*)
        ok "client refused by name" ;;
    *) bad "client" "refusal did not name the reason" "got: $out" ;;
esac

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
