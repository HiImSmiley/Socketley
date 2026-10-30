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
#   * an agent's ssh not reached by an admin's `tunnel ssh --agent`, or reached by anyone else
#   * a kept sign-in handed to an edge that names an idp not beside it
#   * a port of the edge's machine reached as an agent's service the edge does not serve
#   * a join that replaces an agent already joined without being asked to
#   * a person's link kept open, and its streams opened, after the idp took the sign-in back
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
PT=$((SL_PORT_BASE + 1981))
PF=$((SL_PORT_BASE + 1982))
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
"$BIN" idp-user auth add carol --password carolpassword1 >/dev/null 2>&1
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
post("/device", {"user_code": sys.argv[2], "action": "allow", "password": sys.argv[4]}, cookie)
PY
}
login_as() {   # login_as <user> <password> <client, or empty for the default> <config dir>
    # Emptied before, not by the redirection the background child makes after the file was read for the code.
    : > "$T/login.out"
    XDG_CONFIG_HOME="$4" "$BIN" login "$I" ${3:+--client "$3"} >> "$T/login.out" 2>&1 &
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

# A link held open ends with its sign-in: signing carol out everywhere closes the one she has.
login_as carol carolpassword1 "" "$T/carol" || bad "carol signs in" "$(cat "$T/login.out")"
mkfifo "$T/held.in"
XDG_CONFIG_HOME="$T/carol" "$BIN" tunnel connect "http://127.0.0.1:$PE" "127.0.0.1:$PX" --idp "$I" < "$T/held.in" \
    > "$T/held.out" 2>"$T/held.err" &
HELD=$!
exec 7>"$T/held.in"
printf 'held' >&7
for _ in $(seq 1 50); do [ "$(cat "$T/held.out")" = held ] && break; sleep 0.1; done
[ "$(cat "$T/held.out")" = held ] && ok || bad "carol's stream is carried" "$(cat "$T/held.err")"
"$BIN" idp-user auth logout carol >/dev/null 2>&1
for _ in $(seq 1 50); do kill -0 "$HELD" 2>/dev/null || break; sleep 0.1; done
kill -0 "$HELD" 2>/dev/null && bad "a link held open ends once its account is signed out everywhere" "still open after 5 s" || ok
grep -q 'tunnel e: the sign-in of "carol" no longer holds' "$SOCKETLEY_DLOG" && ok || bad "and the log says why" "$(grep 'tunnel e' "$SOCKETLEY_DLOG" | tail -2)"
exec 7>&-
kill "$HELD" 2>/dev/null; wait "$HELD" 2>/dev/null

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
XDG_CONFIG_HOME="$T/fresh" "$BIN" tunnel join "http://127.0.0.1:$PE" --name pi --http "web=127.0.0.1:$PH" \
    --tcp "ssh:$PT=127.0.0.1:$PX" > "$T/join.out" 2>&1 &
jp=$!
allow_code "$T/join.out" boss bosspassword1
for _ in $(seq 1 150); do kill -0 "$jp" 2>/dev/null || break; sleep 0.1; done
wait "$jp"; rc=$?
[ "$rc" -eq 0 ] && grep -qx "https://web" "$T/join.out" && grep -qx "127.0.0.1:$PT" "$T/join.out" && ok \
    || bad "an admin's join makes the agent and says where its service is" "rc $rc: $(cat "$T/join.out")"
[ -z "$(find "$T/fresh" -type f)" ] && ok || bad "and no sign-in is left behind" "$(find "$T/fresh" -type f)"
login_as boss bosspassword1 "" "$T/boss" && ok || bad "an admin signs in" "$(cat "$T/login.out")"
for _ in $(seq 1 50); do "$BIN" tunnel e list | grep -q "^pi	joined	web=idp:auth,ssh:$PT$" && break; sleep 0.1; done
"$BIN" tunnel e list | grep -q "^pi	joined	web=idp:auth,ssh:$PT$" && ok \
    || bad "the agent joins, its service asking visitors to sign in at the edge's idp" "$("$BIN" tunnel e list)"
grep -q 'tunnel e: "boss" added agent "pi"' "$SOCKETLEY_DLOG" && ok || bad "who added it is said in the log" "$(grep 'tunnel e' "$SOCKETLEY_DLOG" | tail -2)"
WEB=$(dirname "$(find "$HOME/.local/share" -path '*tunnel/e/agents' 2>/dev/null | head -1)")/web.sock
[ ${#WEB} -ge 100 ] && WEB="$SOCKETLEY_SOCKET.rt/tunnel-$(printf '%s' "$WEB" | sha256sum | cut -c1-16).sock"
for _ in $(seq 1 30); do [ -S "$WEB" ] && break; sleep 0.1; done
code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 --unix-socket "$WEB" http://web/x)
[ "$code" = 401 ] && ok || bad "a visitor who did not sign in is refused" "$code"
"$BIN" tunnel e set pi --http web --tcp "ssh:$PT" >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(curl -s -m 3 --unix-socket "$WEB" http://web/x)" = "hello from the agent /x" ] && break; sleep 0.1; done
[ "$(curl -s -m 3 --unix-socket "$WEB" http://web/x)" = "hello from the agent /x" ] && ok \
    || bad "opened by the edge's owner, the service at the agent answers" "$(tail -3 "$SOCKETLEY_DLOG")"
out=$(XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel join "http://127.0.0.1:$PE" --name pi --http "web=127.0.0.1:$PH" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"a runtime named pi is here already"*) true ;; *) false ;; esac && ok \
    || bad "a join whose runtime is here already asks nothing of the edge" "rc $rc: $out"
[ "$(curl -s -m 3 --unix-socket "$WEB" http://web/y)" = "hello from the agent /y" ] && ok || bad "and the agent keeps its key" "$("$BIN" tunnel e list)"
# An admin reaches an agent's TCP service by its name, `tunnel ssh --agent` its ssh; nobody else does.
out=$(printf 'to the agent' | XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel ssh "http://127.0.0.1:$PE" --agent pi 2>"$T/err"); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "to the agent" ] && ok || bad "an admin's tunnel ssh --agent reaches the agent's ssh" "rc $rc: '$out' $(cat "$T/err")"
out=$(printf 'x' | "$BIN" tunnel connect "http://127.0.0.1:$PE" pi/ssh 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"does not forward to that target"*) true ;; *) false ;; esac && ok \
    || bad "someone who is no admin does not" "rc $rc: $out"
out=$(printf 'x' | XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel connect "http://127.0.0.1:$PE" pi/web 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "nor an admin an HTTP service by this way" "rc $rc: $out"
out=$(XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel connect "http://127.0.0.1:$PE" pi/nothing 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "nor a service the agent does not have" "rc $rc: $out"
"$BIN" remove pi >/dev/null 2>&1

# Gone from here, the agent the edge holds as joined is replaced only when asked; its service on the edge's own
# port is not served, and an admin does not reach that port through it.
out=$(XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel join "http://127.0.0.1:$PE" --name pi --http "web=127.0.0.1:$PH" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"joined already; --replace takes its place"*) true ;; *) false ;; esac && ok \
    || bad "a join does not replace an agent that has joined unasked" "rc $rc: $out"
out=$(XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel join "http://127.0.0.1:$PE" --name pi --replace --http "web=127.0.0.1:$PH" \
      --tcp "own:$PE=127.0.0.1:$PX" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok || bad "and does with --replace" "rc $rc: $out"
for _ in $(seq 1 50); do "$BIN" tunnel e list | grep -q "^pi	joined	" && break; sleep 0.1; done
for _ in $(seq 1 30); do grep -q "the service own of pi cannot be served" "$SOCKETLEY_DLOG" && break; sleep 0.1; done
out=$(printf 'x' | XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel connect "http://127.0.0.1:$PE" pi/own 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"does not forward to that target"*) true ;; *) false ;; esac && ok \
    || bad "a service the edge could not open is not dialled on the edge's machine" "rc $rc: $out"
"$BIN" remove pi >/dev/null 2>&1

# An edge that names an idp not beside it is handed no kept sign-in; whatever it was sent is written down.
python3 - "$PF" "$T/fake.log" "$I" <<'PY' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open(sys.argv[2], "a").write("%s %s\n" % (self.path, self.headers.get("Authorization", "-")))
        b = (sys.argv[3] + "\n").encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
FAKE=$!
for _ in $(seq 1 30); do ss -ltn "sport = :$PF" | grep -q LISTEN && break; sleep 0.1; done
# It names the very idp an admin is signed in at here, from a name that is not beside it.
printf 'x' | XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel connect "http://localhost:$PF" "127.0.0.1:$PX" >/dev/null 2>"$T/err"; rc=$?
out=$(cat "$T/err")
[ "$rc" -eq 1 ] && case "$out" in *"is not beside localhost; give --idp"*) true ;; *) false ;; esac && ok \
    || bad "an edge naming an idp not beside it is not trusted with a sign-in" "rc $rc: $out"
! grep -qv " -$" "$T/fake.log" && ok || bad "and was sent no token" "$(cat "$T/fake.log")"
kill $FAKE 2>/dev/null

# ── ssh through the tunnel, by the certificate the same sign-in gets ──────────
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
if [ -x "$SSHD" ] && command -v ssh >/dev/null && command -v ssh-keygen >/dev/null; then
    curl -s "$I/ssh/ca.pub" > "$T/ca.pub"
    ssh-keygen -q -t ed25519 -N '' -f "$T/host"
    ssh-keygen -q -t ed25519 -N '' -f "$T/key"
    "$BIN" ssh-cert "$I" --key "$T/key.pub" || bad "alice gets a certificate" "rc $?"
    mkdir -p "$T/principals"; echo alice > "$T/principals/$USER"
    KRL=$("$BIN" idp-ssh auth krl)
    [ -s "$KRL" ] && ok || bad "the idp keeps a revocation list from its start" "'$KRL'"
    cat > "$T/sshd_config" <<EOF
Port $PS
ListenAddress 127.0.0.1
HostKey $T/host
PidFile $T/sshd.pid
AuthorizedKeysFile none
TrustedUserCAKeys $T/ca.pub
RevokedKeys $KRL
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
    in_by_cert() {
        ssh -i "$T/key" -o CertificateFile="$T/key-cert.pub" -o IdentitiesOnly=yes -o BatchMode=yes \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p "$PS" \
            "$USER@127.0.0.1" echo in 2>&1 | grep -v '^Warning: Permanently added'
    }
    # Revoked now, not in eight hours: sshd reads the list the idp writes, and a certificate made after still gets in.
    ssh-keygen -Q -f "$KRL" "$T/key-cert.pub" >/dev/null 2>&1 && ok || bad "a certificate is not revoked until it is" "$(ssh-keygen -Q -f "$KRL" "$T/key-cert.pub" 2>&1)"
    out=$("$BIN" idp-ssh auth revoke alice 2>&1); rc=$?
    [ "$rc" -eq 0 ] && [ -z "$out" ] && ok || bad "alice's certificates are revoked" "rc $rc: $out"
    case "$(ssh-keygen -Q -f "$KRL" "$T/key-cert.pub" 2>&1)" in *REVOKED*) ok ;; *) bad "ssh-keygen reads it as revoked" "$(ssh-keygen -Q -f "$KRL" "$T/key-cert.pub" 2>&1)" ;; esac
    [ "$(in_by_cert)" != in ] && ok || bad "and sshd lets it in no more" "$(in_by_cert)"
    curl -s "$I/ssh/krl" | cmp -s - "$KRL" && ok || bad "the list is served as it is written" "$(curl -s -o /dev/null -w '%{http_code}' "$I/ssh/krl")"
    "$BIN" ssh-cert "$I" --key "$T/key.pub" || bad "alice gets a new certificate" "rc $?"
    [ "$(in_by_cert)" = in ] && ok || bad "which gets in, as a serial was revoked and not alice" "$(in_by_cert)"
    out=$("$BIN" idp-ssh auth revoke 12345 2>&1); rc=$?
    [ "$rc" -eq 1 ] && case "$out" in *"no current certificate"*) true ;; *) false ;; esac && ok || bad "a serial no certificate has is said" "rc $rc: $out"
    # Signing out everywhere revokes what the sign-in bought, without anyone asking.
    "$BIN" idp-user auth logout alice >/dev/null 2>&1
    case "$(ssh-keygen -Q -f "$KRL" "$T/key-cert.pub" 2>&1)" in *REVOKED*) ok ;; *) bad "signing alice out everywhere revokes her certificate" "$(ssh-keygen -Q -f "$KRL" "$T/key-cert.pub" 2>&1)" ;; esac
else
    echo "  SKIP: sshd, ssh and ssh-keygen are needed for the ssh part"
fi

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
