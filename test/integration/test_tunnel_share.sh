#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# `socketley tunnel share`: a port of this machine reached at a name the edge gives, by the idp's signed-in people or
# with --public by everyone, for as long as the command runs, its time lasts and its sign-in holds.
#
# What each part would catch:
#   * a share made for someone who is no admin of the edge's idp
#   * a share's name not routed, its socket not served, or a signed-in share open to visitors who did not sign in
#   * visitors' requests lost, mixed up or cut when many come at once, or a large answer not carried whole
#   * a person holding more shares than the limit
#   * a share kept after the command ends, after its time, or after the idp took the sign-in back
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a tunnel share ==="
daemon_isolate tunnelshare
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1984))
PE=$((SL_PORT_BASE + 1985))
PH=$((SL_PORT_BASE + 1986))
I="http://127.0.0.1:$PI"
E="http://127.0.0.1:$PE"
python3 - "$PH" <<'PY' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = (b"x" * 3000000) if self.path == "/big" else ("shared " + self.path).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
WEB=$!
SHARES=()
trap 'kill $WEB "${SHARES[@]}" 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

printf 'socketley - device\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "$I" -s >/dev/null 2>&1 || bad "the idp is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$I/jwks")" = 200 ] && break; sleep 0.1; done
"$BIN" idp-user auth add boss --password bosspassword1 --groups admins >/dev/null 2>&1
"$BIN" idp-user auth add carol --password carolpassword1 >/dev/null 2>&1
"$BIN" create tunnel e --mode edge -p "$PE" --idp auth -s >/dev/null 2>&1 || bad "the edge is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltn "sport = :$PE" | grep -q LISTEN && break; sleep 0.1; done

login_as() {   # login_as <user> <password> <config dir>: the device code allowed as a browser signed in would
    # Emptied here and not by the redirection, which the background child makes after this shell has read the file:
    # it read the code of the sign-in before, already used, and the login it started waited for good.
    : > "$T/login.out"
    XDG_CONFIG_HOME="$3" "$BIN" login "$I" >> "$T/login.out" 2>&1 &
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
    # A login still waiting has been refused; ended, so the test goes on to say so rather than wait with it.
    kill "$pid" 2>/dev/null
    wait "$pid"
}
sock_of() {
    local p; p=$(find "$HOME/.local/share" -type d -path '*tunnel/e' 2>/dev/null | head -1)/$1.sock
    [ ${#p} -ge 100 ] && p="$SOCKETLEY_SOCKET.rt/tunnel-$(printf '%s' "$p" | sha256sum | cut -c1-16).sock"
    echo "$p"
}
shares_file() { cat "$(find "$HOME/.local/share" -type d -path '*tunnel/e' 2>/dev/null | head -1)/shares" 2>/dev/null; }
share() {   # share <out file> <args...>: a share run in the background, its name read off its first line
    local out=$1; shift
    XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel share "$E" "$PH" --idp "$I" "$@" > "$out" 2> "$out.err" &
    SHARES+=($!)
    for _ in $(seq 1 50); do [ -s "$out" ] && break; sleep 0.1; done
}

login_as boss bosspassword1 "$T/boss" && ok || bad "boss signs in" "$(cat "$T/login.out")"
login_as carol carolpassword1 "$T/carol" && ok || bad "carol signs in" "$(cat "$T/login.out")"
out=$(XDG_CONFIG_HOME="$T/carol" "$BIN" tunnel share "$E" "$PH" --idp "$I" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"sharing is for admins"*) true ;; *) false ;; esac && ok || bad "someone who is no admin shares nothing" "rc $rc: $out"
out=$("$BIN" tunnel share "$E" "$PH" --for 30s 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *usage*) true ;; *) false ;; esac && ok || bad "a share of less than a minute is refused" "rc $rc: $out"

# Signed in by default: a visitor with no sign-in is sent to sign in, or told 401.
share "$T/s1"
N1=$(head -1 "$T/s1")
case "$N1" in [a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]) ok ;; *) bad "a share is given a name" "'$N1' $(cat "$T/s1.err")" ;; esac
for _ in $(seq 1 50); do [ -S "$(sock_of "$N1")" ] && break; sleep 0.1; done
case "$(shares_file)" in "http:$N1=idp:auth boss "[0-9]*) ok ;; *) bad "the share is written for the daemon to route" "'$(shares_file)'" ;; esac
code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 -H 'Accept: text/html' --unix-socket "$(sock_of "$N1")" "http://$N1.example.com/a")
[ "$code" = 302 ] && ok || bad "a browser with no sign-in is sent to sign in" "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 --unix-socket "$(sock_of "$N1")" "http://$N1.example.com/a")
[ "$code" = 401 ] && ok || bad "anything else with no sign-in is told 401" "$code"
grep -q "\"boss\" shares $N1 with those signed in" "$SOCKETLEY_DLOG" && ok || bad "who shares what is said in the log" "$(grep 'tunnel e' "$SOCKETLEY_DLOG" | tail -2)"

# The edge lists its shares for the dashboard: name, who may visit, whose it is, and until when.
case "$("$BIN" tunnel e shares)" in "$N1	signed-in	boss	"[0-9]*) ok ;; *) bad "tunnel shares lists the share, whose it is and until when" "$("$BIN" tunnel e shares 2>&1)" ;; esac

# --public: every visitor, many at once, and a large answer whole.
share "$T/s2" --public
N2=$(head -1 "$T/s2")
for _ in $(seq 1 50); do [ -S "$(sock_of "$N2")" ] && break; sleep 0.1; done
got=$(curl -s -m 3 --unix-socket "$(sock_of "$N2")" "http://$N2/hello")
[ "$got" = "shared /hello" ] && ok || bad "a public share answers anyone" "'$got' $(cat "$T/s2.err")"
CURLS=()
for i in $(seq 1 24); do curl -s -m 10 --unix-socket "$(sock_of "$N2")" "http://$N2/r$i" > "$T/r$i" & CURLS+=($!); done
wait "${CURLS[@]}"
wrong=0; for i in $(seq 1 24); do [ "$(cat "$T/r$i")" = "shared /r$i" ] || wrong=$((wrong+1)); done
[ "$wrong" -eq 0 ] && ok || bad "twenty-four visitors at once each get their own answer" "$wrong wrong"
size=$(curl -s -m 20 --unix-socket "$(sock_of "$N2")" "http://$N2/big" | wc -c)
[ "$size" -eq 3000000 ] && ok || bad "three megabytes are carried whole" "$size"

# Three a person: a fourth is refused while three hold.
share "$T/s3" --public --for 1m
N3=$(head -1 "$T/s3")
out=$(XDG_CONFIG_HOME="$T/boss" "$BIN" tunnel share "$E" "$PH" --idp "$I" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"you share 3 already"*) true ;; *) false ;; esac && ok || bad "a fourth share is refused" "rc $rc: $out"
for _ in $(seq 1 50); do [ "$("$BIN" stats e | sed -n 's/^shares://p')" = 3 ] && break; sleep 0.2; done
[ "$("$BIN" stats e | sed -n 's/^shares://p')" = 3 ] && ok || bad "the edge counts its shares" "$("$BIN" stats e | grep share)"

# Ended by its command, as Ctrl+C ends it (a background job here ignores SIGINT): no longer routed, nothing answers.
kill -TERM "${SHARES[1]}"
for _ in $(seq 1 50); do shares_file | grep -q "$N2" || break; sleep 0.1; done
! shares_file | grep -q "$N2" && ok || bad "a share ended by its command is no longer routed" "$(shares_file)"
code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 --unix-socket "$(sock_of "$N2")" "http://$N2/after")
[ "$code" = 000 ] && ok || bad "and nothing answers on it" "$code"

# Ended by its time: --for 1m tells the person why.
for _ in $(seq 1 90); do kill -0 "${SHARES[2]}" 2>/dev/null || break; sleep 1; done
! kill -0 "${SHARES[2]}" 2>/dev/null && grep -q "the share's time is up" "$T/s3.err" && ok || bad "a share ends when its time is up" "$(cat "$T/s3.err")"
! shares_file | grep -q "$N3" && ok || bad "and is no longer routed" "$(shares_file)"

# Ended by the sign-in: signing boss out everywhere closes the share he still holds.
"$BIN" idp-user auth logout boss >/dev/null 2>&1
for _ in $(seq 1 100); do kill -0 "${SHARES[0]}" 2>/dev/null || break; sleep 0.2; done
! kill -0 "${SHARES[0]}" 2>/dev/null && grep -q "sign-in no longer holds" "$T/s1.err" && ok || bad "a share ends with its sign-in" "$(cat "$T/s1.err")"
[ -z "$(shares_file)" ] && ok || bad "and the edge shares nothing then" "'$(shares_file)'"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
