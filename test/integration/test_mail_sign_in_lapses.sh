#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail session signed in by a password ends once that sign-in no longer holds, on every protocol
# that keeps one open -- IMAP, POP3, SMTP submission and ManageSieve -- for an idp account and a --users line alike.
# Keycloak's CVE-2026-96460 class: a disabled account kept what it had been let into.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an IMAP, POP3, submission or ManageSieve session going on after its account was disabled
#   * one going on after its account's password was changed, or after its --users line was given another password
#   * a session of another account, which still stands, ended with them
#   * an account enabled again not signing in anew
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"
. "$HERE/lib_verdicts.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate mail_lapses
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960))
IM=$((SL_PORT_BASE+1961))
POP=$((SL_PORT_BASE+1962))
SUB=$((SL_PORT_BASE+1963))
SV=$((SL_PORT_BASE+1964))
PI=$((SL_PORT_BASE+1965))
PS=$((SL_PORT_BASE+1966))
PL=$((SL_PORT_BASE+1967))
SUBL=$((SL_PORT_BASE+1968))
trap 'daemon_stop' EXIT

echo "=== Integration: mail sessions end with their sign-in ==="

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
printf 'lucypassword123\n' | "$BIN" mqtt-passwd "$T/users" lucy >/dev/null 2>&1
printf 'mikepassword123\n' | "$BIN" mqtt-passwd "$T/users" mike >/dev/null 2>&1
daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
for u in ann ben cat dan eve kim; do
    "$BIN" idp-user auth add "$u" --password "${u}password123" --email "$u@example.test" >/dev/null 2>&1 \
        || bad "the account $u is made" "rc $?"
done
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --pop3 "$POP" \
    --submission "$SUB" --sieve "$SV" --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
"$BIN" create mail lu -p "$PL" --mail-domain local.test --submission "$SUBL" --users "$T/users" \
    --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
for p in "$IM" "$POP" "$SUB" "$SV" "$SUBL"; do
    ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done

run() {
    python3 - "$BIN" "$T" "$IM" "$POP" "$SUB" "$SV" "$SUBL" 2>&1 <<'PY'
import base64, socket, subprocess, sys, time
bin_, tmpd = sys.argv[1], sys.argv[2]
im, pop, sub, sv, subl = (int(x) for x in sys.argv[3:8])
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
plain = lambda u, p: base64.b64encode(b"\0" + u.encode() + b"\0" + p.encode()).decode()

class session:
    # A plaintext session from 127.0.0.1, this machine's own programs, which may sign in without TLS.
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.f = self.s.makefile("rb")
    def line(self):
        return self.f.readline().decode(errors="replace").rstrip("\r\n")
    def until(self, done):
        lines = []
        while True:
            l = self.line()
            lines.append(l)
            if not l or done(l):
                return lines
    def say(self, text):
        self.s.sendall((text + "\r\n").encode())
    def closed_within(self, wait):
        # Whether the server ends the session within `wait` seconds; what it says on the way is read and let go.
        end = time.time() + wait
        self.s.settimeout(0.25)
        while time.time() < end:
            try:
                if not self.s.recv(4096):
                    return True
            except socket.timeout:
                pass
            except OSError:
                return True
        self.s.settimeout(10)
        return False

def imap(user):
    s = session(im)
    s.line()
    s.say("a1 LOGIN %s %spassword123" % (user, user))
    return s, s.until(lambda l: l.startswith("a1 "))[-1].startswith("a1 OK")
def pop3(user):
    s = session(pop)
    s.line()
    s.say("USER " + user)
    s.line()
    s.say("PASS %spassword123" % user)
    return s, s.line().startswith("+OK")
def submission(port, user):
    s = session(port)
    s.until(lambda l: l[:4] != "220-")
    s.say("EHLO client.example")
    s.until(lambda l: l[:4] != "250-")
    s.say("AUTH PLAIN " + plain(user, user + "password123"))
    return s, s.line().startswith("235")
def sieve(user):
    s = session(sv)
    s.until(lambda l: l[:2] in ("OK", "NO", "BY"))
    s.say('AUTHENTICATE "PLAIN" "%s"' % plain(user, user + "password123"))
    return s, s.until(lambda l: l[:2] in ("OK", "NO", "BY"))[-1].startswith("OK")
def idp(*args):
    subprocess.run([bin_, "idp-user", "auth"] + list(args), capture_output=True)

opened = {
    "IMAP": imap("ann"),
    "POP3": pop3("ben"),
    "submission": submission(sub, "cat"),
    "ManageSieve": sieve("dan"),
}
moved, moved_in = imap("eve")
kept, kept_in = imap("kim")
check("each protocol signs its account in by password",
      [ok for _, ok in opened.values()] + [moved_in, kept_in], [True] * 6)
check("and keeps the sessions open while the accounts stand",
      [s.closed_within(0.6) for s, _ in opened.values()] + [moved.closed_within(0.6)], [False] * 5)
for u in ("ann", "ben", "cat", "dan"):
    idp("disable", u)
idp("passwd", "eve", "--password", "evesNewPassword456")
for proto, (s, _) in opened.items():
    check("the %s session is closed within seconds of its account being disabled" % proto, s.closed_within(10), True)
check("an IMAP session is closed once its account's password is changed", moved.closed_within(6), True)
kept.say("a2 NOOP")
check("while another account's session goes on", kept.until(lambda l: l.startswith("a2 "))[-1].startswith("a2 OK"), True)

# Enabled again, the account signs in anew.
idp("enable", "ann")
again, again_in = imap("ann")
check("an account enabled again signs in anew", again_in, True)
check("and that session stays", again.closed_within(3), False)

# --users: the line given another password ends the session it let in; another user's stays.
lucy, lucy_in = submission(subl, "lucy")
mike, mike_in = submission(subl, "mike")
check("a --users line signs in on submission", (lucy_in, mike_in), (True, True))
p = subprocess.run([bin_, "mqtt-passwd", tmpd + "/users", "lucy"], input=b"lucysNewPassword456\n", capture_output=True)
check("a session is closed once its --users line holds another password", lucy.closed_within(10), True)
mike.say("NOOP")
check("while another user's goes on", mike.line().startswith("250"), True)
PY
}
tally < <(run)
[ "$TOTAL" -ge 13 ] || bad "every check ran" "$TOTAL"

echo
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
