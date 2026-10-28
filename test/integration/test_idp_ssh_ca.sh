#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The idp's SSH certificate authority (--ssh-ca), end to end against a real sshd: socketley login, socketley
# ssh-cert, a login by the certificate, and a host certificate a client trusts by @cert-authority.
#
# What each part would catch:
#   * a certificate ssh-keygen or sshd does not read, or one naming the wrong principals or lifetime
#   * a login by the key alone, without the certificate, or by a certificate for a principal sshd does not allow
#   * a token given to a client not marked `ssh` buying a certificate, or one for a disabled account
#   * a device allowed for a client marked `ssh` without the page saying so, or without the password given again
#   * an access token that ran out not being refreshed before the certificate is asked for
#   * a certificate given on a sign-in older than twelve hours, as a refresh token kept going would give one
#   * a host certificate a client checking @cert-authority would not take
#   * a certificate given without a line in the log saying for whom and for which key
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: the idp signs SSH certificates a real sshd takes ==="
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
if [ ! -x "$SSHD" ] || ! command -v ssh-keygen >/dev/null || ! command -v ssh >/dev/null; then
    echo "  SKIP: sshd, ssh and ssh-keygen are required"
    exit 0
fi
daemon_isolate idpsshca
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1968))
PS=$((SL_PORT_BASE + 1969))
SSHD_PID=""
trap '[ -n "$SSHD_PID" ] && kill "$SSHD_PID" 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"
I="http://127.0.0.1:$PI"

cat > "$T/clients" <<EOF
cli - device ssh
web - device
EOF
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "$I" --ssh-ca 8 -s >/dev/null 2>&1 \
    && ok || bad "an idp with an SSH authority is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$I/jwks")" = 200 ] && break; sleep 0.1; done
out=$("$BIN" create idp bad -p $((PI + 20)) --ssh-ca 0 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "--ssh-ca of no hours is refused" "rc $rc: $out"
"$BIN" idp-user auth add alice --password alicepassword1 --groups admins,ssh:deploy >/dev/null 2>&1 || bad "alice is made" "rc $?"
"$BIN" idp-user auth add bob --password bobpassword12 >/dev/null 2>&1 || bad "bob is made" "rc $?"

CA=$(curl -s "$I/ssh/ca.pub")
case "$CA" in "ssh-ed25519 AAAA"*" auth-ssh-ca") ok ;; *) bad "the authority's public key is served" "$CA" ;; esac
[ "$("$BIN" idp-ssh auth ca)" = "$CA" ] && ok || bad "and the same one is given by idp-ssh" "$("$BIN" idp-ssh auth ca 2>&1)"
echo "$CA" > "$T/ca.pub"

# Signs a person in from the command line, allowing the code as the browser would.
login_as() {   # login_as <user> <password> <client> <config dir>
    XDG_CONFIG_HOME="$4" "$BIN" login "$I" --client "$3" > "$T/login.out" 2>&1 &
    local pid=$!
    for _ in $(seq 1 50); do grep -q "allow the code" "$T/login.out" && break; sleep 0.1; done
    python3 - "$PI" "$(sed -n 's/^and allow the code //p' "$T/login.out")" "$1" "$2" <<'PY' >/dev/null 2>&1
import sys, urllib.request, urllib.parse, urllib.error
I = "http://127.0.0.1:%s" % sys.argv[1]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NoRedirect)
def post(path, form, cookie=None):
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie: h["Cookie"] = cookie
    r = urllib.request.Request(I + path, data=urllib.parse.urlencode(form).encode(), method="POST", headers=h)
    try:
        with op.open(r) as resp: return resp.headers
    except urllib.error.HTTPError as e: return e.headers
cookie = (post("/login", {"username": sys.argv[3], "password": sys.argv[4]}).get("Set-Cookie") or "").split(";")[0]
post("/device", {"user_code": sys.argv[2], "action": "allow", "password": sys.argv[4]}, cookie)
PY
    for _ in $(seq 1 150); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    wait "$pid"
}

# Allowing a client marked ssh says what it gives, root for an admin, and takes the password again.
python3 - "$PI" > "$T/proof.out" 2>&1 <<'PY'
import sys, json, urllib.request, urllib.parse, urllib.error
I = "http://127.0.0.1:%s" % sys.argv[1]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NoRedirect)
def post(path, form, cookie=None):
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie: h["Cookie"] = cookie
    r = urllib.request.Request(I + path, data=urllib.parse.urlencode(form).encode(), method="POST", headers=h)
    try:
        with op.open(r) as resp: return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e: return e.code, e.read().decode(), e.headers
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
code = json.loads(post("/device_authorization", {"client_id": "cli", "scope": "openid"})[1])["user_code"]
cookie = (post("/login", {"username": "alice", "password": "alicepassword1"})[2].get("Set-Cookie") or "").split(";")[0]
st, body, _ = post("/device", {"user_code": code, "action": "look"}, cookie)
check("the page says the device gets SSH certificates, as root for an admin, and asks for the password",
      (st, "SSH certificates" in body, "<b>root</b>" in body, 'name="password"' in body), (200, True, True, True))
st, body, _ = post("/device", {"user_code": code, "action": "allow"}, cookie)
check("allowed without the password, nothing is allowed", (st, "signed in" in body, 'name="password"' in body), (401, False, True))
st, body, _ = post("/device", {"user_code": code, "action": "allow", "password": "wrongpassword"}, cookie)
check("nor with a wrong one", (st, "signed in" in body), (401, False))
st, body, _ = post("/device", {"user_code": code, "action": "allow", "password": "alicepassword1"}, cookie)
check("and with the right one it is", (st, "The device is signed in." in body), (200, True))
PY
while read -r v rest; do [ "$v" = ok ] && ok || bad "$rest" ""; done < "$T/proof.out"
login_as alice alicepassword1 cli "$T/alice" && ok || bad "alice signs in from the command line" "$(cat "$T/login.out")"
ssh-keygen -q -t ed25519 -N '' -C alice@laptop -f "$T/alice_key"
XDG_CONFIG_HOME="$T/alice" "$BIN" ssh-cert "$I" --key "$T/alice_key.pub" && [ -f "$T/alice_key-cert.pub" ] && ok \
    || bad "ssh-cert writes the certificate beside the key" "$(ls "$T")"
L=$(ssh-keygen -L -f "$T/alice_key-cert.pub" 2>&1)
case "$L" in *"user certificate"*) ok ;; *) bad "ssh-keygen reads it as a user certificate" "$L" ;; esac
P=$(echo "$L" | sed -n '/Principals:/,/Critical Options:/p' | sed '1d;$d' | tr -d ' \t' | tr '\n' ',')
[ "$P" = "alice,deploy,root," ] && ok || bad "for the username, root for admins and each ssh: group" "$P"
case "$L" in *"Key ID: \"alice@127.0.0.1\""*) ok ;; *) bad "its key id names the user and the provider" "$L" ;; esac
case "$L" in *"Signing CA: ED25519 $(ssh-keygen -lf "$T/ca.pub" | awk '{print $2}')"*) ok ;; *) bad "signed by the served authority" "$L" ;; esac
from=$(echo "$L" | sed -n 's/.*Valid: from \(.*\) to \(.*\)$/\1/p'); to=$(echo "$L" | sed -n 's/.*Valid: from \(.*\) to \(.*\)$/\2/p')
span=$(( $(date -d "$to" +%s) - $(date -d "$from" +%s) ))
[ "$span" -eq $((8 * 3600 + 300)) ] && ok || bad "eight hours, from five minutes back" "$from .. $to ($span s)"
grep -q 'idp auth: SSH certificate [0-9]* for "alice" as alice,deploy,root, 8 h, key SHA256:' "$SOCKETLEY_DLOG" && ok \
    || bad "the certificate is said in the log" "$(grep 'SSH certificate' "$SOCKETLEY_DLOG" | tail -2)"

# ── A real sshd taking the certificate, and its host certificate taken in turn ──
ssh-keygen -q -t ed25519 -N '' -f "$T/host"
"$BIN" idp-ssh auth host-sign "$T/host.pub" --names 127.0.0.1 --days 30 && [ -f "$T/host-cert.pub" ] && ok \
    || bad "idp-ssh signs a host key, the certificate beside it" "$(ls "$T")"
case "$(ssh-keygen -L -f "$T/host-cert.pub" 2>&1)" in *"host certificate"*"127.0.0.1"*) ok ;;
    *) bad "ssh-keygen reads it as a host certificate for the name" "$(ssh-keygen -L -f "$T/host-cert.pub" 2>&1)" ;; esac
mkdir -p "$T/principals"
echo alice > "$T/principals/$USER"
cat > "$T/sshd_config" <<EOF
Port $PS
ListenAddress 127.0.0.1
HostKey $T/host
HostCertificate $T/host-cert.pub
PidFile $T/sshd.pid
AuthorizedKeysFile none
TrustedUserCAKeys $T/ca.pub
AuthorizedPrincipalsFile $T/principals/%u
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
"$SSHD" -D -f "$T/sshd_config" -E "$T/sshd.log" &
SSHD_PID=$!
for _ in $(seq 1 50); do ss -ltn "sport = :$PS" | grep -q LISTEN && break; sleep 0.1; done
echo "@cert-authority [127.0.0.1]:$PS $CA" > "$T/known_hosts"
ssh_in() {   # ssh_in <key> [extra options...]
    local key=$1; shift
    ssh -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile="$T/known_hosts" \
        -o StrictHostKeyChecking=yes -o ConnectTimeout=5 "$@" -p "$PS" "$USER@127.0.0.1" echo in 2>&1
}
out=$(ssh_in "$T/alice_key" -o CertificateFile="$T/alice_key-cert.pub")
[ "$out" = in ] && ok || bad "sshd lets the certificate in, the host known only by the authority" "$out"
out=$(ssh_in "$T/alice_key" -o CertificateFile=/dev/null)
[ "$out" != in ] && ok || bad "while the key alone gets nowhere" "$out"
echo nobody > "$T/principals/$USER"
out=$(ssh_in "$T/alice_key" -o CertificateFile="$T/alice_key-cert.pub")
[ "$out" != in ] && ok || bad "nor a certificate for a principal sshd does not allow" "$out"
echo alice > "$T/principals/$USER"

# ── What gets no certificate ────────────────────────────────────────────────
login_as bob bobpassword12 web "$T/bob" && ok || bad "bob signs in through a client not marked ssh" "$(cat "$T/login.out")"
ssh-keygen -q -t ed25519 -N '' -f "$T/bob_key"
out=$(XDG_CONFIG_HOME="$T/bob" "$BIN" ssh-cert "$I" --key "$T/bob_key.pub" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"may not ask for SSH certificates"*) true ;; *) false ;; esac && ok \
    || bad "a token given to a client not marked ssh gets no certificate" "rc $rc: $out"
out=$("$BIN" ssh-cert "$I" --key "$T/bob_key.pub" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"socketley login"*) true ;; *) false ;; esac && ok \
    || bad "nobody signed in is told to sign in" "rc $rc: $out"
cp "$T/alice_key.pub" "$T/bad.pub"; echo "ssh-dss AAAAB3NzaC1kc3M= old" > "$T/bad.pub"
out=$(XDG_CONFIG_HOME="$T/alice" "$BIN" ssh-cert "$I" --key "$T/bad.pub" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "a key of a type with no certificate form is refused" "rc $rc: $out"

# An access token that ran out is refreshed first.
TOK=$(ls "$T/alice/socketley/tokens/"*.json)
before=$(grep -o '"access_token":"[^"]*"' "$TOK")
sed -i 's/"expires":[0-9]*/"expires":0/' "$TOK"
rm -f "$T/alice_key-cert.pub"
XDG_CONFIG_HOME="$T/alice" "$BIN" ssh-cert "$I" --key "$T/alice_key.pub" && [ -f "$T/alice_key-cert.pub" ] && ok \
    || bad "a token that ran out is refreshed and the certificate given" "$(cat "$TOK")"
[ "$(grep -o '"access_token":"[^"]*"' "$TOK")" != "$before" ] && ok || bad "and the new token kept" "unchanged"

# Access tokens as the provider would sign them, of a sign-in old and of one fresh, with its own key.
KEYFILE=$(find "$SOCKETLEY_TMPD" -name auth.key | head -1)
mint() {   # mint <seconds since the sign-in>
    python3 - "$KEYFILE" "$I" "$(curl -s "$I/jwks")" "$(XDG_CONFIG_HOME="$T/alice" "$BIN" idp-user auth show alice | sed -n 's/^id: //p')" "$1" <<'PY'
import sys, json, time, jwt
from cryptography.hazmat.primitives import serialization
raw = open(sys.argv[1], "rb").read()
try:
    key = serialization.load_pem_private_key(raw, None)
except ValueError:
    key = serialization.load_der_private_key(raw, None)
now = int(time.time())
claims = {"iss": sys.argv[2], "sub": sys.argv[4], "aud": "cli", "client_id": "cli", "scope": "openid", "iat": now,
          "iat_ms": now * 1000, "auth_time": now - int(sys.argv[5]), "exp": now + 600, "jti": str(now)}
print(jwt.encode(claims, key, algorithm="ES256", headers={"kid": json.loads(sys.argv[3])["keys"][0]["kid"], "typ": "at+jwt"}))
PY
}
cert_with() {   # cert_with <access token>: the status and the body
    curl -s -w '\n%{http_code}' -H "Authorization: Bearer $1" --data-urlencode "public_key=$(cat "$T/alice_key.pub")" "$I/ssh/user-cert"
}
out=$(cert_with "$(mint 60)")
[ "$(echo "$out" | tail -1)" = 200 ] && ok || bad "a sign-in of a minute ago gets a certificate" "$out"
out=$(cert_with "$(mint $((13 * 3600)))")
[ "$(echo "$out" | tail -1)" = 401 ] && case "$out" in *"sign in again"*) true ;; *) false ;; esac && ok \
    || bad "one of thirteen hours ago is told to sign in again" "$out"

"$BIN" idp-user auth disable alice >/dev/null 2>&1
out=$(XDG_CONFIG_HOME="$T/alice" "$BIN" ssh-cert "$I" --key "$T/alice_key.pub" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"no longer one that may sign in"*) true ;; *) false ;; esac && ok \
    || bad "a disabled account gets no certificate, its token still unexpired" "rc $rc: $out"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
