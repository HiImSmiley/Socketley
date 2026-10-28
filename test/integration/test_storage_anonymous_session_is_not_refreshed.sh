#!/usr/bin/env bash
# Integration test: on a storage with credentials and --anonymous, a session cookie does not sign itself in anew.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * POST /~ui/session with only a cookie and the interface's header, which
#     --anonymous let past the check for credentials, minting a fresh cookie
#     of 12 hours or, with ?remember, 30 days, which signing out of the old one
#     did not end, so a stolen cookie renewed itself for good
#   * a sign-in with the user's own key no longer setting a cookie
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate anonsess
P=$((SL_PORT_BASE+1928))
U="http://127.0.0.1:$P"
T="$SOCKETLEY_TMPD"
trap 'daemon_stop' EXIT

echo "=== Integration: an anonymous storage's session does not renew itself ==="

daemon_start "$BIN"
cat > "$T/creds" <<EOF
[ann]
AKIAANONSESSANN00000:anonsessannsecretanonsessannsecretanon00
EOF
A="AKIAANONSESSANN00000:anonsessannsecretanonsessannsecretanon00"
"$BIN" create storage as -p "$P" --dir "$T/as" --credentials "$T/creds" --anonymous -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done

# The cookie a header set, its value alone, or nothing.
cookie_of() { tr -d '\r' | grep -i '^set-cookie: skl_ui=' | sed 's/^[^=]*=//; s/;.*//'; }

ck=$(curl -s -m 5 -u "$A" -X POST -D - -o /dev/null "$U/~ui/session" | cookie_of)
expect "a sign-in with the user's key sets a cookie" "$([ -n "$ck" ] && echo set)" set
expect "which signs the user in" \
       "$(curl -s -m 5 -b "skl_ui=$ck" "$U/~ui/session" | python3 -c 'import json,sys; print(json.load(sys.stdin)["user"])')" ann

renewed=$(curl -s -m 5 -b "skl_ui=$ck" -H 'X-Socketley-UI: 1' -X POST -D - -o /dev/null "$U/~ui/session?remember" | cookie_of)
expect "the cookie alone, with the interface's header, makes no new one" "$renewed" ""

expect "signing out of it ends the session" \
       "$(curl -s -m 5 -b "skl_ui=$ck" -o /dev/null -w '%{http_code}' -X DELETE "$U/~ui/session") $(curl -s -m 5 -b "skl_ui=$ck" -o /dev/null -w '%{http_code}' "$U/~ui/session")" \
       "204 401"
expect "and a visitor without one is still let in as nobody" \
       "$(curl -s -m 5 "$U/~ui/session" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["user"] or "nobody", d["anonymous"])')" \
       "nobody True"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
