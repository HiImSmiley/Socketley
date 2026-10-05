#!/usr/bin/env bash
# Integration test: three storage runtimes that are the nodes of one cluster.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a bucket, an object, a multipart object, a tag set, a removal, a bucket's
#     versioning, tags and CORS rules, an object lock, a retention or a legal
#     hold made on one node missing on another, or different there
#   * a node that hears an older write after a newer one keeping the older:
#     an object of a bucket that keeps no versions, a removal made after a
#     write, and a version that must go behind the latest
#   * a version given another id on another node, so the lists differ
#   * a node sending on what another node sent it, so changes go round
#   * a change lost while a node is down
#   * a cluster file that does not parse taken, or its key shown
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgcluster

PA=$((SL_PORT_BASE+1961))
PB=$((SL_PORT_BASE+1963))
PC=$((SL_PORT_BASE+1965))
PX=$((SL_PORT_BASE+1967))
export ADMIN_AK="AKIACLUSTERADMIN0001"
export ADMIN_SK="cluster/admin/secret"
NODE_SK="cluster/node/secret/never/shown"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in cla clb clc clx; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in cla clb clc clx; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {   # port
    for _ in $(seq 1 100); do
        [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0
        sleep 0.1
    done
    return 1
}

echo "=== Integration: storage cluster ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"

T="$SOCKETLEY_TMPD"
printf '[admin]\n%s:%s\nadmin = true\n' "$ADMIN_AK" "$ADMIN_SK" > "$T/creds"
cluster_file() {   # self
    cat <<EOF
# every node, this one included
self $1
node cla http://127.0.0.1:$PA
node clb http://127.0.0.1:$PB
node clc http://127.0.0.1:$PC
key AKIACLUSTERNODES0001 $NODE_SK
EOF
}
for n in cla clb clc; do cluster_file "$n" > "$T/$n.cluster"; done

# ── the flag ────────────────────────────────────────────────────────────────
printf 'self clx\nnode cla http://127.0.0.1:%s\nkey AKIACLUSTERNODES0001 %s\n' "$PA" "$NODE_SK" > "$T/bad.cluster"
out=$("$BIN" create storage clx -p "$PX" --dir "$T/x" --credentials "$T/creds" --cluster "$T/bad.cluster" -s 2>&1)
if [ $? -ne 0 ] && echo "$out" | grep -q "none of the file's nodes"; then
    ok "a cluster file whose self is none of its nodes is refused, saying why"
else
    bad "a cluster file whose self is none of its nodes is refused, saying why" "$out"
fi
"$BIN" remove clx >/dev/null 2>&1
out=$("$BIN" create storage clx -p "$PX" --dir "$T/x" --credentials "$T/creds" --cluster 2>&1)
[ $? -eq 1 ] && ok "--cluster with no file is refused" || bad "--cluster with no file is refused" "$out"

# ── three nodes, the third with two shards ─────────────────────────────────
"$BIN" create storage cla -p "$PA" --dir "$T/a" --credentials "$T/creds" --cluster "$T/cla.cluster" -s >/dev/null 2>&1 &&
"$BIN" create storage clb -p "$PB" --dir "$T/b" --credentials "$T/creds" --cluster "$T/clb.cluster" -s >/dev/null 2>&1 &&
"$BIN" create storage clc -p "$PC" --dir "$T/c" --credentials "$T/creds" --cluster "$T/clc.cluster" --shards 2 \
    -s >/dev/null 2>&1 || { echo "  FAIL [create]: the nodes were not created"; exit 1; }
wait_up "$PA" && wait_up "$PB" && wait_up "$PC" || bad "the nodes come up" "no answer on $PA, $PB or $PC"
shown=$("$BIN" show cla 2>&1)
if echo "$shown" | grep -q "\"cluster\": \"$T/cla.cluster\"" && ! echo "$shown" | grep -q "$NODE_SK"; then
    ok "show names the cluster file and not its key"
else
    bad "show names the cluster file and not its key" "$shown"
fi

out=$(python3 "$HERE/lib_storage_cluster.py" "cla:$PA" "clb:$PB" "clc:$PC" 2>&1); rc=$?
echo "$out" | grep -E '^  (PASS|FAIL)'
p=$(echo "$out" | grep -c '^  PASS'); f=$(echo "$out" | grep -c '^  FAIL')
PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
[ "$rc" -ne 0 ] && [ "$f" -eq 0 ] && bad "the cluster half ran" "exit $rc: $out"

grep -q "$NODE_SK" "$SOCKETLEY_DLOG" && bad "no node key reaches the log" "$(grep -n "$NODE_SK" "$SOCKETLEY_DLOG")" \
    || ok "no node key reaches the log"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
