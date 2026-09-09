#!/usr/bin/env bash
# Integration test: a configuration file reaches every flag `create` accepts.
#
# cli_config mapped twenty-five of the daemon's sixty-one flags and dropped
# every other key in silence, so the health-check, circuit-breaker, retry and
# TLS families could not be set from a configuration at all -- and a misspelled
# key configured nothing while the runtime came up looking correct.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate luaparity
PASS=0; FAIL=0; TOTAL=0

WORK="/tmp/test-luaparity-$$"
cleanup() { rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# One key, asserted through `show` rather than through the exit code, because a
# create that accepted a flag and stored nothing exits 0.
shows() {
    local what=$1 name=$2 pattern=$3
    if "$BIN" show "$name" 2>/dev/null | grep -q -- "$pattern"; then pass
    else fail "$what" "show $name does not carry $pattern" \
              "$("$BIN" show "$name" 2>&1 | tr '\n' ' ')"; fi
}

echo "=== Integration: --lua reaches every create flag ==="

mkdir -p "$WORK"
daemon_start "$BIN"
P=$((SL_PORT_BASE + 920))

# ─── The four families a configuration could not reach ──────────────────────
cat > "$WORK/proxy.lua" <<EOF
runtimes = {
  { type = "proxy", name = "lp_gw", port = $((P + 1)),
    backends = {"127.0.0.1:$((P + 40))", "127.0.0.1:$((P + 41))"},
    protocol = "http", strategy = "round-robin",
    health_check = "http", health_interval = 17, health_path = "/hz",
    health_threshold = 9, circuit_threshold = 11, circuit_timeout = 77,
    backend_timeout = 13, retry = 4, retry_all = true,
    max_connections = 500, rate_limit = 12.5, global_rate_limit = 99,
    idle_timeout = 44, drain = true, group = "edge", log = "$WORK/gw.log" },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/proxy.lua" 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && [ -z "$OUT" ]; then pass
else fail "a fully specified proxy is accepted" "exit $RC, said: ${OUT:-<nothing>}"; fi

shows "health_check reaches the runtime"     lp_gw '"health_check"'
shows "health_interval reaches the runtime"  lp_gw '"health_interval": 17'
shows "health_path reaches the runtime"      lp_gw '"health_path": "/hz"'
shows "health_threshold reaches the runtime" lp_gw '"health_threshold": 9'
shows "circuit_threshold reaches the runtime" lp_gw '"circuit_threshold": 11'
shows "circuit_timeout reaches the runtime"  lp_gw '"circuit_timeout": 77'
shows "backend_timeout reaches the runtime"  lp_gw '"backend_timeout": 13'
shows "retry reaches the runtime"            lp_gw '"retry_count": 4'
shows "retry_all reaches the runtime"        lp_gw '"retry_all": true'
shows "rate_limit reaches the runtime"       lp_gw '"rate_limit": 12.5'
shows "global_rate_limit reaches the runtime" lp_gw '"global_rate_limit": 99'
shows "idle_timeout reaches the runtime"     lp_gw '"idle_timeout": 44'
shows "drain reaches the runtime"            lp_gw '"drain": true'

# ─── Sixty-nine tokens, which is past what the wire used to carry ───────────
#
# parsed_args held thirty-two slots and merged everything past them into the
# last one, so the create above would have arrived truncated.
cat > "$WORK/server.lua" <<EOF
runtimes = {
  { type = "cache", name = "lp_store", port = $((P + 2)) },
  { type = "server", name = "lp_api", port = $((P + 3)),
    upstreams = {"127.0.0.1:$((P + 42))", "127.0.0.1:$((P + 43))"},
    http = "$WORK", http_cache = true,
    master_pw = "hunter2", send_to = "master", mode = "master",
    cache = "lp_store", write = "$WORK/api.out", bash = "pt",
    max_connections = 77, rate_limit = 2.5, idle_timeout = 30,
    tls = true, cert = "$WORK/c.pem", key = "$WORK/k.pem", ca = "$WORK/ca.pem" },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/server.lua" 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && [ -z "$OUT" ]; then pass
else fail "a fully specified server is accepted" "exit $RC, said: ${OUT:-<nothing>}"; fi

shows "tls reaches the runtime"            lp_api '"tls": true'
shows "cert reaches the runtime"           lp_api "c.pem"
shows "key reaches the runtime"            lp_api "k.pem"
shows "ca reaches the runtime"             lp_api "ca.pem"
shows "upstreams reach the runtime"        lp_api '"upstreams"'
shows "master_pw reaches the runtime"      lp_api '"master_pw": "hunter2"'
shows "send_to reaches the runtime"        lp_api '"send_to": "master"'
shows "http_cache reaches the runtime"     lp_api '"http_cache": true'
shows "cache reaches the runtime"          lp_api '"cache_name": "lp_store"'
shows "bash=pt reaches all three bits"     lp_api '"bash_timestamp": true'

# ─── The cache family ───────────────────────────────────────────────────────
cat > "$WORK/cache.lua" <<EOF
runtimes = {
  { type = "cache", name = "lp_c2", port = $((P + 4)),
    persistent = "$WORK/store.bin", maxmemory = "256M",
    eviction = "allkeys-lru", resp = true, cluster = true },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/cache.lua" 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && [ -z "$OUT" ]; then pass
else fail "a fully specified cache is accepted" "exit $RC, said: ${OUT:-<nothing>}"; fi

shows "maxmemory understands 256M" lp_c2 '"max_memory": 268435456'
shows "eviction reaches the runtime" lp_c2 '"eviction": "allkeys-lru"'
shows "resp reaches the runtime"     lp_c2 '"resp_forced": true'
shows "cluster reaches the runtime"  lp_c2 '"cluster": true'

# ─── reconnect is a bool or a count, which is the flag's own shape ──────────
cat > "$WORK/client.lua" <<EOF
runtimes = {
  { type = "client", name = "lp_cli", target = "127.0.0.1:$((P + 3))",
    reconnect = 5, mode = "in" },
}
EOF
"$BIN" --lua "$WORK/client.lua" >/dev/null 2>&1 || true
shows "reconnect carries its count" lp_cli '"reconnect": 5'

# ─── A key nobody handles is a typo ─────────────────────────────────────────
cat > "$WORK/typo.lua" <<EOF
runtimes = {
  { type = "server", name = "lp_typo", port = $((P + 5)), htp_cache = true },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/typo.lua" 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then pass
else fail "an unknown key is refused" "exit 0 for htp_cache"; fi
if grep -q "htp_cache" <<<"$OUT"; then pass
else fail "the refusal names the key" "said: ${OUT:-<nothing>}"; fi
if [ -z "$("$BIN" ls --name 2>/dev/null | grep -x lp_typo || true)" ]; then pass
else fail "a refused entry creates nothing" "lp_typo exists"; fi

# ─── A value of the wrong shape ─────────────────────────────────────────────
cat > "$WORK/shape.lua" <<EOF
runtimes = {
  { type = "server", name = "lp_shape", port = "$((P + 6))" },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/shape.lua" 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -q "port" <<<"$OUT"; then pass
else fail "a port given as a string is refused" "exit $RC, said: ${OUT:-<nothing>}"; fi

# ─── A value the wire cannot carry ──────────────────────────────────────────
#
# The daemon's command line splits on whitespace and has no quoting, so this
# would have arrived as two arguments and set the password to "a".
cat > "$WORK/space.lua" <<EOF
runtimes = {
  { type = "server", name = "lp_space", port = $((P + 7)), master_pw = "a b" },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/space.lua" 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -qi "whitespace" <<<"$OUT"; then pass
else fail "a value with a space is refused" "exit $RC, said: ${OUT:-<nothing>}"; fi

# ─── The daemon's own refusal still reaches the operator ────────────────────
#
# --client-ca on a cleartext proxy is a rule the daemon owns, and the point of
# widening this file is not to start second-guessing it here.
cat > "$WORK/refused.lua" <<EOF
runtimes = {
  { type = "proxy", name = "lp_mtls", port = $((P + 8)),
    backends = {"127.0.0.1:$((P + 44))"}, client_ca = "$WORK/ca.pem" },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/refused.lua" 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -q -- "--client-ca" <<<"$OUT"; then pass
else fail "the daemon's own refusal is passed through" "exit $RC, said: ${OUT:-<nothing>}"; fi

# ─── A setting the daemon reads once, at startup ────────────────────────────
cat > "$WORK/startup.lua" <<'EOF'
daemon = { log_level = "warn" }
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/startup.lua" 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -q "SOCKETLEY_CONFIG" <<<"$OUT"; then pass
else fail "a startup-only daemon key is refused, not dropped" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
