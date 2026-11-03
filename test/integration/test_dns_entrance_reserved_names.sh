#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a dns runtime's entrance for a zone under a name reserved for tests (example.test) asks no CA,
# since the default one, Let's Encrypt, issues for none of them, and stands a self-signed certificate in; with a CA of
# one's own named by SOCKETLEY_ACME_DIRECTORY the same names are asked for, as such a CA may issue them.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the entrance starting `acme issue` for a reserved name: a request to Let's Encrypt from every lab or test that
#     makes a dns runtime without --proxy none, refused there by policy (its log file beside the certificate)
#   * a reserved zone left without a certificate, so the entrance's TLS listener has nothing to offer
#   * the filter applied to a CA of one's own too, which a lab running one would lose
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate dns_entrance_reserved
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+410))
NS=$P; GATE=$((P+1)); DEAD=$((P+2))
trap daemon_stop EXIT
unset SOCKETLEY_ACME_DIRECTORY

echo "=== Integration: an entrance asks no public CA for a reserved name ==="

daemon_start "$BIN"
"$BIN" create dns ns -p "$NS" --zone example.test --publish 127.0.0.1 --proxy-port "$GATE" -s >/dev/null 2>&1
cert="$HOME/.local/state/socketley/.acme/entrance-ns-proxy/fullchain.pem"
for _ in $(seq 1 50); do [ -s "$cert" ] && break; sleep 0.1; done
cert=$(ls "$HOME"/.local/state/socketley/.acme/entrance-ns-proxy/fullchain.pem 2>/dev/null ||
       find "$T" -path '*entrance-ns-proxy/fullchain.pem' 2>/dev/null | head -1)
[ -n "$cert" ] && [ -s "$cert" ] && ok "the entrance has a certificate" \
    || bad "a certificate" "$(find "$T" -path '*acme*' 2>/dev/null | head) $(tail -3 "$SOCKETLEY_DLOG")"
subject=$(openssl x509 -in "$cert" -noout -subject -issuer 2>&1)
case "$subject" in *example.test*) ok "for the zone's names" ;; *) bad "for the zone's names" "$subject" ;; esac
# The child is spawned on the turn after the names are known; two seconds is many of them.
sleep 2
[ ! -e "$cert.log" ] && ok "and no CA is asked for it" \
    || bad "no CA asked" "$(cat "$cert.log" 2>/dev/null | tail -3)"
grep -q "reserved name(s) not asked for" "$SOCKETLEY_DLOG" && ok "which the log says" \
    || bad "the log says so" "$(grep -i acme "$SOCKETLEY_DLOG" | tail -3)"
ready_tcp 127.0.0.1 "$GATE" && ok "and the entrance listens" || bad "the entrance listens" "$("$BIN" ls)"

# The same names, a CA of one's own named: they are asked for, here of an address that answers nothing.
kill "$SOCKETLEY_DPID" 2>/dev/null; wait "$SOCKETLEY_DPID" 2>/dev/null
daemon_sweep "$SOCKETLEY_SOCKET"
export SOCKETLEY_ACME_DIRECTORY="https://127.0.0.1:$DEAD/dir"
daemon_start "$BIN"
for _ in $(seq 1 100); do [ -e "$cert.log" ] && break; sleep 0.1; done
[ -e "$cert.log" ] && ok "a CA of one's own is asked for the same names" \
    || bad "a CA of one's own is asked" "$("$BIN" ls) $(grep -i acme "$SOCKETLEY_DLOG" | tail -3)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
