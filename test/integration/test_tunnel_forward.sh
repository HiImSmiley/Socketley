#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A tunnel edge carrying a signed-in person's stream to a --forward target: `socketley tunnel connect` between stdin
# and stdout, and ssh through it as its ProxyCommand with a certificate from the same idp -- what replaces wstunnel.
#
# What each part would catch:
#   * a stream carried for someone with no access token, or one given to a client the edge does not take
#   * an edge with no --idp-audience not taking what `socketley login` signs in as by default
#   * a target the edge does not name reached, or a refusal not said
#   * bytes lost between stdin, the edge, the target and stdout, or the end of stdin not reaching the target
#   * ssh through the tunnel not getting in with its certificate
#   * `tunnel connect` with no --idp not finding the edge's idp by asking the edge
#   * `tunnel join` adding an agent for someone who is no admin, or its service open to visitors who did not sign in
#   * an agent joined by a person not reaching the service it offers, or a second join of its name breaking it
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a tunnel edge carries a signed-in person's stream, ssh among them ==="
daemon_isolate tunnelfwd
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1976))
PE=$((SL_PORT_BASE + 1977))
PX=$((SL_PORT_BASE + 1978))
PS=$((SL_PORT_BASE + 1979))
PH=$((SL_PORT_BASE + 1980))
I="http://127.0.0.1:$PI"
python3 - "$PX" <<'PY' &
import socketserver, sys
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(65536)
            if not d:
                break
            self.request.sendall(d)
        self.request.shutdown(1)
class E(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
E(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
PY
ECHO=$!
python3 - "$PH" <<'PY' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("hello from the agent " + self.path).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
HOME_WEB=$!
SSHD_PID=""
trap 'kill $ECHO $HOME_WEB 2>/dev/null; [ -n "$SSHD_PID" ] && kill "$SSHD_PID" 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

cat > "$T/clients" <<EOF
socketley - device ssh
other - device
EOF
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "$I" --ssh-ca 8 -s >/dev/null 2>&1 \
    || bad "the idp is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$I/jwks")" = 200 ] && break; sleep 0.1; done
"$BIN" idp-user auth add alice --password alicepassword1 >/dev/null 2>&1
"$BIN" idp-user auth add boss --password bosspassword1 --groups admins >/dev/null 2>&1
out=$("$BIN" create tunnel e --mode edge -p "$PE" --forward "127.0.0.1:$PX" 2>&1); rc=$?
[ "$rc" -ne 0 ] && case "$out" in *"--forward needs --idp"*) true ;; *) false ;; esac && ok || bad "--forward without --idp is refused" "rc $rc: $out"
"$BIN" create tunnel e --mode edge -p "$PE" --forward "127.0.0.1:$PX,127.0.0.1:$PS" --idp auth -s >/dev/null 2>&1 \
    && ok || bad "an edge that forwards for the idp's people is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltn "sport = :$PE" | grep -q LISTEN && break; sleep 0.1; done

allow_code() {   # allow_code <file the code is printed to> <user> <password>: as a browser signed in would
    for _ in $(seq 1 50); do grep -q "allow the code" "$1" && break; sleep 0.1; done
    python3 - "$PI" "$(sed -n 's/^and allow the code //p' "$1")" "$2" "$3" <<'PY' >/dev/null 2>&1
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
post("/device", {"user_code": sys.argv[2], "action": "allow"}, cookie)
PY
}
login_as() {   # login_as <user> <password> <client, or empty for the default> <config dir>
    XDG_CONFIG_HOME="$4" "$BIN" login "$I" ${3:+--client "$3"} > "$T/login.out" 2>&1 &
    local pid=$!
    allow_code "$T/login.out" "$1" "$2"
    for _ in $(seq 1 150); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    wait "$pid"
}

out=$(printf 'hello' | "$BIN" tunnel connect "http://127.0.0.1:$PE" "127.0.0.1:$PX" --idp "$I" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"socketley login"*) true ;; *) false ;; esac && ok || bad "nobody signed in is told to sign in" "rc $rc: $out"
login_as alice alicepassword1 "" "$T/alice" && ok || bad "alice signs in" "$(cat "$T/login.out")"
export XDG_CONFIG_HOME="$T/alice"

out=$(printf 'hello through the tunnel' | "$BIN" tunnel connect "http://127.0.0.1:$PE" "127.0.0.1:$PX" --idp "$I" 2>"$T/err"); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "hello through the tunnel" ] && ok || bad "stdin reaches the target and its answer stdout" "rc $rc: '$out' $(cat "$T/err")"
head -c 3000000 /dev/urandom > "$T/blob"
"$BIN" tunnel connect "http://127.0.0.1:$PE" "127.0.0.1:$PX" --idp "$I" < "$T/blob" > "$T/blob.back" 2>"$T/err"; rc=$?
[ "$rc" -eq 0 ] && cmp -s "$T/blob" "$T/blob.back" && ok || bad "three megabytes there and back, whole" "rc $rc: $(stat -c %s "$T/blob.back") $(cat "$T/err")"
out=$(printf 'x' | "$BIN" tunnel connect "http://127.0.0.1:$PE" "127.0.0.1:9" --idp "$I" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"does not forward to that target"*) true ;; *) false ;; esac && ok || bad "a target the edge does not name is refused" "rc $rc: $out"
grep -q 'tunnel e: "alice" connected from 127.0.0.1' "$SOCKETLEY_DLOG" && ok || bad "who connected is said in the log" "$(grep 'tunnel e' "$SOCKETLEY_DLOG" | tail -2)"

login_as alice alicepassword1 other "$T/other" || true
out=$(printf 'x' | XDG_CONFIG_HOME="$T/other" "$BIN" tunnel connect "http://127.0.0.1:$PE" "127.0.0.1:$PX" --idp "$I" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"401"*|*"not one this edge takes"*) true ;; *) false ;; esac && ok \
    || bad "a token given to a client the edge does not take is refused" "rc $rc: $out"

# ── the edge says where to sign in, and an admin signed in there adds an agent ──
out=$(printf 'asked the edge' | "$BIN" tunnel connect "http://127.0.0.1:$PE" "127.0.0.1:$PX" 2>"$T/err"); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "asked the edge" ] && ok || bad "with no --idp the edge's own is asked for" "rc $rc: '$out' $(cat "$T/err")"
out=$("$BIN" tunnel join "http://127.0.0.1:$PE" --name pi --http "web=127.0.0.1:$PH" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"only an admin"*) true ;; *) false ;; esac && ok || bad "someone who is no admin adds no agent" "rc $rc: $out"
[ -z "$("$BIN" tunnel e list)" ] && ok || bad "and the edge holds none" "$("$BIN" tunnel e list)"
# Signed in nowhere here, the join signs in for itself and keeps nothing of an admin's sign-in once it is done.
mkdir -p "$T/fresh"
XDG_CONFIG_HOME="$T/fresh" "$BIN" tunnel join "http://127.0.0.1:$PE" --name pi --http "web=127.0.0.1:$PH" > "$T/join.out" 2>&1 &
jp=$!
allow_code "$T/join.out" boss bosspassword1
for _ in $(seq 1 150); do kill -0 "$jp" 2>/dev/null || break; sleep 0.1; done
wait "$jp"; rc=$?
[ "$rc" -eq 0 ] && [ "$(tail -1 "$T/join.out")" = "https://web" ] && ok \
    || bad "an admin's join makes the agent and says where its service is" "rc $rc: $(cat "$T/join.out")"
[ -z "$(find "$T/fresh" -type f)" ] && ok || bad "and no sign-in is left behind" "$(find "$T/fresh" -type f)"
login_as boss bosspassword1 "" "$T/boss" && ok || bad "an admin signs in" "$(cat "$T/login.out")"
for _ in $(seq 1 50); do "$BIN" tunnel e list | grep -q "^pi	joined	web=idp:auth$" && break; sleep 0.1; done
"$BIN" tunnel e list | grep -q "^pi	joined	web=idp:auth$" && ok \
    || bad "the agent joins, its service asking visitors to sign in at the edge's idp" "$("$BIN" tunnel e list)"
grep -q 'tunnel e: "boss" added agent "pi"' "$SOCKETLEY_DLOG" && ok || bad "who added it is said in the log" "$(grep 'tunnel e' "$SOCKETLEY_DLOG" | tail -2)"
WEB=$(dirname "$(find "$HOME/.local/share" -path '*tunnel/e/agents' 2>/dev/null | head -1)")/web.sock
[ ${#WEB} -ge 100 ] && WEB="/tmp/skl-$(printf '%s' "$WEB" | sha256sum | cut -c1-16).sock"
for _ in $(seq 1 30); do [ -S "$WEB" ] && break; sleep 0.1; done
code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 --unix-socket "$WEB" http://web/x)
[ "$code" = 401 ] && ok || bad "a visitor who did not sign in is refused" "$code"
"$BIN" tunnel e set pi --http web >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(curl -s -m 3 --unix-socket "$WEB" http://web/x)" = "hello from the agent /x" ] && break; sleep 0.1; done
[ "$(curl -s -m 3 --unix-socket "$WEB" http://web/x)" = "hello from the agent /x" ] && ok \
    || bad "opened by the edge's owner, the service at the agent answers" "$(tail -3 "$SOCKETLEY_DLOG")"
out=$(XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel join "http://127.0.0.1:$PE" --name pi --http "web=127.0.0.1:$PH" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"a runtime named pi is here already"*) true ;; *) false ;; esac && ok \
    || bad "a join whose runtime is here already asks nothing of the edge" "rc $rc: $out"
[ "$(curl -s -m 3 --unix-socket "$WEB" http://web/y)" = "hello from the agent /y" ] && ok || bad "and the agent keeps its key" "$("$BIN" tunnel e list)"
"$BIN" remove pi >/dev/null 2>&1

# ── ssh through the tunnel, by the certificate the same sign-in gets ──────────
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
if [ -x "$SSHD" ] && command -v ssh >/dev/null && command -v ssh-keygen >/dev/null; then
    curl -s "$I/ssh/ca.pub" > "$T/ca.pub"
    ssh-keygen -q -t ed25519 -N '' -f "$T/host"
    ssh-keygen -q -t ed25519 -N '' -f "$T/key"
    "$BIN" ssh-cert "$I" --key "$T/key.pub" || bad "alice gets a certificate" "rc $?"
    mkdir -p "$T/principals"; echo alice > "$T/principals/$USER"
    cat > "$T/sshd_config" <<EOF
Port $PS
ListenAddress 127.0.0.1
HostKey $T/host
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
    out=$(ssh -i "$T/key" -o CertificateFile="$T/key-cert.pub" -o IdentitiesOnly=yes -o BatchMode=yes \
              -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
              -o ProxyCommand="$BIN tunnel connect http://127.0.0.1:$PE 127.0.0.1:$PS --idp $I" \
              "$USER@through-the-tunnel" echo in 2>&1 | grep -v '^Warning: Permanently added')
    [ "$out" = in ] && ok || bad "ssh gets in through the tunnel by its certificate" "$out"
else
    echo "  SKIP: sshd, ssh and ssh-keygen are needed for the ssh part"
fi

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
