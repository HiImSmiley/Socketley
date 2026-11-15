#!/usr/bin/env bash
# Integration test: `import` judges a document whole before it applies any of it, and applies what it judged.
#
# ─── WHAT IT DID INSTEAD ────────────────────────────────────────────────────
#
# Measured on dev f39f29af8, on a server created with --max-connections 10 and
# a proxy with --strategy random:
#
#   '{"max_connections":7,"lua_script":"/nonexistent.lua"}'
#        -> "could not load Lua script", exit 1, max_connections now 7
#   '{"idle_timeout":33,"acme_domains":"1.2.3.4"}'   -> refused, idle_timeout 33
#   '{"rate_limit":4,"upstreams":["h:99999"]}'      -> refused, rate_limit 4
#   '{"max_connections":-1}'        -> exit 0, the limit gone (-1 read as 0)
#   '{"tls":"yes"}'                 -> exit 0, TLS off ("yes" read as false)
#   '{"max_conections":5}'          -> exit 0, nothing changed
#   '{"idle_timeout":5,"idle_timeout":9}' -> exit 0, 5 (jq and the editor read 9)
#   '{"type":"server","strategy":"random"}' on the proxy
#        -> exit 0, strategy round-robin: read as a server's document, the
#           proxy's field came out as its default
#   '{"congestion":"reno"}'         -> exit 0, nothing changed
#   '{"acme_domains":"a.example.com"}' on a running cleartext server
#        -> exit 0, `show` said TLS, the worker served cleartext
#
# The half-applied ones were not stored or sent to the worker, but `show`
# reported them and the next save of anything wrote them.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate importjudge

P=$((SL_PORT_BASE+1970))
NAMES="ij_srv ij_proxy ij_cache"

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

f() { "$BIN" show "$1" 2>/dev/null | sed -n "s/^ *\"$2\": *\(.*\)$/\1/p" | sed 's/,$//;s/^"//;s/"$//'; }

# A document refused, and the runtime's whole `show` the same after it.
refused() {
    local what=$1 name=$2 doc=$3 says=$4 before after rc=0 out
    before=$("$BIN" show "$name")
    out=$("$BIN" import "$name" "$doc" 2>&1) || rc=$?
    after=$("$BIN" show "$name")
    check "$what: refused" "1" "$rc"
    case "$out" in *"$says"*) ok ;; *) bad "$what: the refusal names it" "got '$out'" ;; esac
    if [ "$before" = "$after" ]; then ok; else bad "$what: nothing of it applied" "$(diff <(echo "$before") <(echo "$after") | head -6)"; fi
}

echo "=== Integration: import judges the document before it applies it ==="
daemon_start "$BIN"

create_ok "a server"  "$BIN" create server ij_srv -p "$P" --max-connections 10 --rate-limit 5
create_ok "a proxy"   "$BIN" create proxy ij_proxy -p $((P+1)) --backend 127.0.0.1:9 --strategy random
create_ok "a cache"   "$BIN" create cache ij_cache -p $((P+2))

# ─── 1. Refused late, applied early ─────────────────────────────────────────
refused "a script that does not load"  ij_srv '{"max_connections":7,"lua_script":"/nonexistent.lua"}' "Lua script"
refused "an ACME name that is none"    ij_srv '{"idle_timeout":33,"acme_domains":"1.2.3.4"}' "1.2.3.4"
refused "an upstream with no port"     ij_srv '{"rate_limit":4,"upstreams":["h:99999"]}' "h:99999"

# ─── 2. Read as something it does not say ───────────────────────────────────
refused "a limit of -1"                ij_srv '{"max_connections":-1}' "max_connections"
refused "tls as a word"                ij_proxy '{"tls":"yes"}' '"tls"'
refused "a rate with a unit"           ij_srv '{"rate_limit":"5/s"}' "rate_limit"
refused "a port past 65535"            ij_srv '{"port":70000}' "port"
refused "a strategy misspelt"          ij_proxy '{"strategy":"randon"}' "strategy"
refused "a field misspelt"             ij_srv '{"max_conections":5}' "max_conections"
refused "a field named twice"          ij_srv '{"idle_timeout":5,"idle_timeout":9}' "twice"
refused "another type's document"      ij_proxy '{"type":"server","strategy":"random"}' "type"
refused "another type's field"         ij_srv '{"eviction":"allkeys-lru"}' "eviction"
check "the proxy's strategy is its own" "random" "$(f ij_proxy strategy)"

# ─── 3. What it takes, it applies ───────────────────────────────────────────
RC=0; OUT=$("$BIN" import ij_srv '{"congestion":"reno","max_connections":7,"rate_limit":"2.5"}' 2>&1) || RC=$?
check "a good document is taken" "0" "$RC"
check "congestion, which import used to drop" "reno" "$(f ij_srv congestion)"
check "max_connections"                       "7"    "$(f ij_srv max_connections)"
check "a quoted number, as it always was"     "2.5"  "$(f ij_srv rate_limit)"

# ─── 4. What show prints, import takes ──────────────────────────────────────
for n in ij_srv ij_proxy ij_cache; do
    RC=0; OUT=$("$BIN" show "$n" | "$BIN" import "$n" 2>&1) || RC=$?
    check "show $n | import $n" "0" "$RC"
    [ -z "$OUT" ] && ok || bad "show $n | import $n says nothing" "got '$OUT'"
done

# ─── 5. A certificate does not turn TLS on under a running runtime ──────────
"$BIN" start ij_srv >/dev/null
RC=0; OUT=$("$BIN" import ij_srv '{"acme_domains":"a.example.com"}' 2>&1) || RC=$?
check "acme_domains on a running cleartext server is refused" "1" "$RC"
check "and TLS stays off" "" "$(f ij_srv tls)"
RC=0; OUT=$("$BIN" edit ij_srv --acme a.example.com 2>&1) || RC=$?
check "edit --acme on it is refused too" "1" "$RC"
check "and TLS still off" "" "$(f ij_srv tls)"
"$BIN" stop ij_srv >/dev/null
RC=0; OUT=$("$BIN" edit ij_srv --acme a.example.com 2>&1) || RC=$?
check "stopped, it is taken" "0" "$RC"
check "and TLS is on" "true" "$(f ij_srv tls)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
