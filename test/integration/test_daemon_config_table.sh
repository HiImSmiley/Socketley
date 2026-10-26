#!/usr/bin/env bash
# Integration test: the daemon's configuration file sets the daemon.
#
# It understood two keys, log_level and metrics_port, under a table named
# `config`, while `daemon = { name, cluster }` was read only by the CLI and
# could therefore only be told to a daemon that was already serving -- so a
# packaged daemon could not be given its own name or join a cluster at boot.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
PASS=0; FAIL=0; TOTAL=0

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: the daemon configuration table ==="

P=$((SL_PORT_BASE + 960))

# ─── name and cluster, applied before a single runtime is restored ──────────
daemon_isolate dcfg1
CLUSTER="$SOCKETLEY_TMPD/cluster"
mkdir -p "$CLUSTER"
cat > "$SOCKETLEY_TMPD/daemon.lua" <<EOF
daemon = {
    name = "dcfg_alpha",
    cluster = "$CLUSTER",
    metrics_port = $((P + 1)),
}
EOF
export SOCKETLEY_CONFIG="$SOCKETLEY_TMPD/daemon.lua"
daemon_start "$BIN"

if [ -f "$CLUSTER/dcfg_alpha.json" ]; then pass
else fail "the daemon takes its name and joins the cluster at startup" \
          "$CLUSTER holds: $(ls "$CLUSTER" 2>/dev/null | tr '\n' ' ')"; fi

OUT=$("$BIN" cluster ls 2>&1 </dev/null || true)
if grep -q "dcfg_alpha" <<<"$OUT"; then pass
else fail "the name it took is the name it reports" "cluster ls said: $OUT"; fi

OUT=$("$BIN" dashboard 2>&1 </dev/null || true)
if grep -q "$((P + 1))" <<<"$OUT"; then pass
else fail "metrics_port is read from the daemon table" "dashboard said: $OUT"; fi

daemon_stop
unset SOCKETLEY_CONFIG

# ─── `config` is the same table's older name ────────────────────────────────
daemon_isolate dcfg2
cat > "$SOCKETLEY_TMPD/daemon.lua" <<EOF
config = { metrics_port = $((P + 2)) }
EOF
export SOCKETLEY_CONFIG="$SOCKETLEY_TMPD/daemon.lua"
daemon_start "$BIN"

OUT=$("$BIN" dashboard 2>&1 </dev/null || true)
if grep -q "$((P + 2))" <<<"$OUT"; then pass
else fail "the older spelling still works" "dashboard said: $OUT"; fi

daemon_stop
unset SOCKETLEY_CONFIG

# ─── Both at once is a file nobody can read ─────────────────────────────────
daemon_isolate dcfg3
cat > "$SOCKETLEY_TMPD/daemon.lua" <<EOF
daemon = { metrics_port = $((P + 3)) }
config = { log_level = "warn" }
EOF
export SOCKETLEY_CONFIG="$SOCKETLEY_TMPD/daemon.lua"
daemon_start "$BIN"

if grep -q "both a \`daemon\` and a \`config\` table" "$SOCKETLEY_DLOG"; then pass
else fail "naming the table twice is refused, not merged" \
          "the daemon said nothing about it"; fi

# The refusal drops the whole table rather than half of it, because a file
# read in part is the outcome this refusal exists to prevent.
# The daemon has to answer that metrics are off, because a dashboard that failed outright also prints no port.
OUT=$("$BIN" dashboard 2>&1 </dev/null || true)
if grep -q "metrics endpoint not configured" <<<"$OUT" && ! grep -q "$((P + 3))" <<<"$OUT"; then pass
else fail "a refused file sets nothing" "dashboard said: ${OUT:-<nothing>}"; fi

daemon_stop
unset SOCKETLEY_CONFIG

# ─── A flag outranks the file ───────────────────────────────────────────────
#
# Both name the ring's CPU set, and the one the operator typed is the one that
# has to win.
daemon_isolate dcfg4
cat > "$SOCKETLEY_TMPD/daemon.lua" <<'EOF'
daemon = { cpus = "max" }
EOF
export SOCKETLEY_CONFIG="$SOCKETLEY_TMPD/daemon.lua"
daemon_start "$BIN" --cpus max

if [ -S "$SOCKETLEY_SOCKET" ]; then pass
else fail "a daemon whose file and flag disagree still comes up" "no socket"; fi

OUT=$("$BIN" create server dcfg_s1 -p $((P + 4)) -s 2>&1 </dev/null || true)
LISTENING=""
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$((P + 4))") 2>/dev/null; then LISTENING=yes; break; fi
    sleep 0.1
done
if [ -z "$OUT" ] && [ "$LISTENING" = yes ]; then pass
else fail "and it serves" "create said: ${OUT:-<nothing>}, listening: ${LISTENING:-no}"; fi

daemon_stop
unset SOCKETLEY_CONFIG

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
