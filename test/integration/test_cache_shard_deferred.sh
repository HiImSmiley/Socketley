#!/usr/bin/env bash
# Integration test: a request that reaches a sharded cache through another
# process is answered for every key, not just the owner's quarter.
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# `create cache c --shards 4` and `create server s --cache c`: a client of the
# server asking `cache get k` was answered, three times in four,
#
#     error: get names a key another shard owns, and this path cannot wait for it
#
# and `socketley c get k` from the CLI the same.  Over a socket the crossing
# to the owning shard worked; what could not cross was the scratch connection
# a request from another process is served on, because nothing kept waiting
# for the answer.  Measured on the parent commit, four shards, 100 random keys
# written on the port and read through the server: 28 answered, 72 refused.
# Through the CLI, 40 keys: 10 answered, 30 refused.
#
# The request now parks against a ticket in the worker and the cache answers
# it on the turn the crossing lands.
#
# ─── WHAT IS ASSERTED, AND WHY EACH CAN FAIL ───────────────────────────────
#
#   1. 100 keys written on the port read back through the server.  The count
#      is the assertion: one key round-trips on the broken build one time in
#      four.
#   2. The same 100 through `socketley c get`, the CLI action form, which
#      takes a different path into the worker (the daemon's direct ticket).
#   3. Writes through the server land: `cache set` through the server, read on
#      the port.  A build that routed reads and not writes would pass 1 and 2.
#   4. Twenty gets pipelined on ONE server connection come back in the order
#      asked, compared as a sequence: a local key is answered at once and a
#      foreign one a turn later, and a build that answers each as it finishes
#      interleaves them.
#   5. The one-shard control does all of the above and is green on both
#      builds, which is what says this file is about sharding.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cachedefer

# A sharded cache also binds base+1..base+N, its cluster-mode shard ports, so bases sit ten apart.
P_C4=$((SL_PORT_BASE+1560))     # four shards
P_S4=$((SL_PORT_BASE+1570))     # the server in front of them
P_C1=$((SL_PORT_BASE+1571))     # one shard, the control
P_S1=$((SL_PORT_BASE+1572))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for n in s4 s1 c4 c1; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in s4 s1 c4 c1; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a sharded cache answers a request from another process ==="

command -v nc >/dev/null 2>&1 || { echo "  SKIP: nc is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

daemon_start "$BIN"

"$BIN" create cache c4 -p "$P_C4" --shards 4 -s >/dev/null 2>&1 \
    || daemon_bail "four shards start" "create cache c4 --shards 4 was refused"
"$BIN" create server s4 -p "$P_S4" --cache c4 -s >/dev/null 2>&1 \
    || daemon_bail "the server in front starts" "create server s4 --cache c4 was refused"
"$BIN" create cache c1 -p "$P_C1" --shards 1 -s >/dev/null 2>&1 \
    || daemon_bail "the control starts" "create cache c1 was refused"
"$BIN" create server s1 -p "$P_S1" --cache c1 -s >/dev/null 2>&1 \
    || daemon_bail "the control's server starts" "create server s1 --cache c1 was refused"

# One line in, one line out, on a fresh connection.
ask() { printf '%s\n' "$1" | timeout 5 nc -q1 127.0.0.1 "$2" 2>/dev/null | tr -d '\r' | head -1; }

# The same, once per key on a fresh connection each, in one process: nc's
# quit delay is a second per call and a hundred of those is the test's
# budget.  Prints one answer line per key, in order.
ask_each() {
    local port=$1 prefix=$2; shift 2
    python3 - "$port" "$prefix" "$@" <<'PY'
import socket, sys
port, prefix, keys = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
for k in keys:
    line = ""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.settimeout(5)
        s.sendall((prefix.replace("{k}", k) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            d = s.recv(4096)
            if not d: break
            buf += d
        s.close()
        line = buf.split(b"\n")[0].decode("latin1").replace("\r", "")
    except Exception as e:
        line = "ERROR:" + type(e).__name__
    print(line)
PY
}

for p in "$P_C4" "$P_C1"; do
    for i in $(seq 1 60); do [ "$(ask size "$p")" != "" ] && break; sleep 0.2; done
    [ "$(ask size "$p")" != "" ] || daemon_bail "the cache answers on $p" "no reply to size"
done
for p in "$P_S4" "$P_S1"; do
    for i in $(seq 1 60); do nc -z 127.0.0.1 "$p" 2>/dev/null && break; sleep 0.2; done
done
sleep 0.5

# Random rather than numbered, so the keys fall over the shards differently
# on every run; the count is what is asserted.
KEYS=()
for i in $(seq 1 100); do KEYS+=("k${RANDOM}_$i"); done

run_case() {
    local label=$1 pc=$2 ps=$3 cname=$4

    # ── 1. written on the port, read through the server ────────────────────
    { for k in "${KEYS[@]}"; do printf 'set %s v_%s\n' "$k" "$k"; done; } \
        | timeout 5 nc -q1 127.0.0.1 "$pc" >/dev/null 2>&1

    local good=0 refused=0 other=0 first_other="" r i
    mapfile -t ANS < <(ask_each "$ps" "cache get {k}" "${KEYS[@]}")
    for i in "${!KEYS[@]}"; do
        r=${ANS[$i]:-}
        if [ "$r" = "v_${KEYS[$i]}" ]; then good=$((good+1))
        elif printf '%s' "$r" | grep -q "another shard owns"; then refused=$((refused+1))
        else other=$((other+1)); [ -z "$first_other" ] && first_other="'$r'"; fi
    done
    if [ "$good" -eq 100 ]; then ok "$label: 100/100 keys read through the server"
    else bad "$label: 100/100 keys read through the server" \
             "$good answered, $refused refused as another shard's, $other other ${first_other}"; fi

    # ── 2. the CLI action form ─────────────────────────────────────────────
    good=0; refused=0; other=0; first_other=""
    for k in "${KEYS[@]}"; do
        r=$("$BIN" "$cname" get "$k" 2>&1 | tr -d '\r\n')
        if [ "$r" = "v_$k" ]; then good=$((good+1))
        elif printf '%s' "$r" | grep -q "another shard owns"; then refused=$((refused+1))
        else other=$((other+1)); [ -z "$first_other" ] && first_other="'$r'"; fi
    done
    if [ "$good" -eq 100 ]; then ok "$label: 100/100 keys read through the CLI"
    else bad "$label: 100/100 keys read through the CLI" \
             "$good answered, $refused refused as another shard's, $other other ${first_other}"; fi

    # ── 3. written through the server, read on the port ────────────────────
    good=0; refused=0; other=0; first_other=""
    mapfile -t ANS < <(ask_each "$ps" "cache set w_{k} x_{k}" "${KEYS[@]:0:40}")
    for i in $(seq 0 39); do
        r=${ANS[$i]:-}
        if [ "$r" = "ok" ]; then good=$((good+1))
        elif printf '%s' "$r" | grep -q "another shard owns"; then refused=$((refused+1))
        else other=$((other+1)); [ -z "$first_other" ] && first_other="'$r'"; fi
    done
    if [ "$good" -eq 40 ]; then ok "$label: 40/40 writes through the server took"
    else bad "$label: 40/40 writes through the server took" \
             "$good ok, $refused refused as another shard's, $other other ${first_other}"; fi
    good=0
    mapfile -t ANS < <(ask_each "$pc" "get w_{k}" "${KEYS[@]:0:40}")
    for i in $(seq 0 39); do
        [ "${ANS[$i]:-}" = "x_${KEYS[$i]}" ] && good=$((good+1))
    done
    if [ "$good" -eq 40 ]; then ok "$label: 40/40 of them read back on the port"
    else bad "$label: 40/40 of them read back on the port" "$good read back"; fi

    # ── 4. pipelined on one connection, answered in order ──────────────────
    local want="" got
    for k in "${KEYS[@]:0:20}"; do want="${want}v_$k"$'\n'; done
    got=$(python3 - "$ps" "${KEYS[@]:0:20}" <<'PY'
import socket, sys
port = int(sys.argv[1]); keys = sys.argv[2:]
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall("".join(f"cache get {k}\n" for k in keys).encode())
buf = b""
s.settimeout(5)
try:
    while buf.count(b"\n") < len(keys):
        d = s.recv(65536)
        if not d: break
        buf += d
except socket.timeout:
    pass
s.close()
sys.stdout.write(buf.decode("latin1").replace("\r", ""))
PY
)
    if [ "$got" = "${want%$'\n'}" ]; then ok "$label: 20 pipelined gets came back in the order asked"
    else bad "$label: 20 pipelined gets came back in the order asked" \
             "wanted: $(printf '%s' "$want" | tr '\n' ' ' | cut -c1-120)" \
             "got:    $(printf '%s' "$got"  | tr '\n' ' ' | cut -c1-120)"; fi
}

run_case "four shards" "$P_C4" "$P_S4" c4
run_case "one shard"   "$P_C1" "$P_S1" c1

# The mesh carried some of the four-shard case: the first crossing relays
# through the daemon and the link takes over once nothing is outstanding, so a
# run this long has used both paths, and this says the second existed.
if grep -q "peer links: s4 and c4 now cross directly" "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "the server and the cache crossed over a link as well as through the daemon"
else
    bad "the server and the cache crossed over a link as well as through the daemon" \
        "no 'peer links: s4 and c4 now cross directly' line in the daemon log"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
