#!/usr/bin/env bash
# Integration test: --federation gives temporary credentials to an OIDC provider's tokens and an LDAP directory's binds,
# each mapped to a user of the credentials file.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a genuine token or bind refused, or the session signing as another user
#   * a token of another key, client or issuer, expired, early, unsigned or
#     HMAC'd taken
#   * a claim that names no user, or two, mapped anyway
#   * a session Policy that does not narrow
#   * a password the directory refuses taken, an empty one sent at all, or a
#     name with DN syntax obeyed
#   * a provider file that does not parse taken
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgfed
P=$((SL_PORT_BASE+1995))
PL=$((SL_PORT_BASE+1997))
export ADMIN_AK="AKIAFEDADMIN00000001"
export ADMIN_SK="fed/admin/secret"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in fed fedx; do "$BIN" stop "$r" >/dev/null 2>&1 || true; "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0; sleep 0.1; done
    return 1
}

echo "=== Integration: storage federated identities ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3, jwt, cryptography" 2>/dev/null || { echo "  SKIP: boto3, PyJWT and cryptography are required"; exit 0; }
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"
cat > "$T/creds" <<CREDS
[admin]
$ADMIN_AK:$ADMIN_SK
admin = true
[builder]
AKIAFEDBUILDER000001:fed/builder/secret
policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::build*","arn:aws:s3:::build*/*"]}]}
[reader]
AKIAFEDREADER0000001:fed/reader/secret
policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}
CREDS
cat > "$T/federation" <<FED
# the provider and the directory
oidc issuer https://idp.test
oidc client storage
oidc jwks   jwks.json
role arn:aws:iam:::role/ci builder
ldap url ldap://127.0.0.1:$PL
ldap dn  uid=%s,ou=People,dc=test
ldap user alice builder
ldap user * reader
FED
echo '{"keys":[]}' > "$T/jwks.json"

echo "oidc issuer" > "$T/badfed"
out=$("$BIN" create storage fedx -p "$P" --dir "$T/x" --credentials "$T/creds" --federation "$T/badfed" 2>&1)
[ $? -ne 0 ] && ok "a federation file that does not parse is refused" \
    || bad "a federation file that does not parse is refused" "$out"
"$BIN" remove fedx >/dev/null 2>&1

"$BIN" create storage fed -p "$P" --dir "$T/data" --credentials "$T/creds" --federation "$T/federation" -s \
    >/dev/null 2>&1 || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
wait_up "$P" || bad "the runtime comes up" "no answer on $P"

out=$(python3 "$HERE/lib_storage_federation.py" "$P" "$T" "$PL" 2>&1); rc=$?
echo "$out" | grep -E '^  (PASS|FAIL)'
p=$(echo "$out" | grep -c '^  PASS'); f=$(echo "$out" | grep -c '^  FAIL')
PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
[ "$rc" -ne 0 ] && echo "$out" | grep -vE '^  (PASS|FAIL)' | tail -15
[ "$rc" -ne 0 ] && [ "$f" -eq 0 ] && bad "the federation half ran" "exit $rc: $out"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
