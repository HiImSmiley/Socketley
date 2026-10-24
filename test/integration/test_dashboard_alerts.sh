#!/usr/bin/env bash
# Integration test: the daemon's alerts.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   reading     /api/alerts needs a session, a test of the hook a session and
#               the page's header
#   raising     a runtime that failed, with the line that says why and not an
#               alert's own; a certificate that ends within two weeks; a
#               storage runtime near its --max-bytes, after three readings; a
#               git repository whose last pull failed
#   the hook    each raising posted once as JSON a Discord, Slack or any hook
#               reads, a test too; a daemon started again does not tell of
#               what it told of before, and keeps when it began
#   clearing    a runtime that runs again is cleared after three readings,
#               posted as resolved and kept in the history
#   the file    the alerts told of are kept in the state directory, private
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate dashal
T="$SOCKETLEY_TMPD"
M=$((SL_PORT_BASE+1950))
HP=$((SL_PORT_BASE+1951))
S1=$((SL_PORT_BASE+1952))
S2=$((SL_PORT_BASE+1953))
S3=$((SL_PORT_BASE+1954))
S4=$((SL_PORT_BASE+1955))
HOOK_PID=""
DNS_PID=""
trap '[ -n "$HOOK_PID" ] && kill "$HOOK_PID" 2>/dev/null; [ -n "$DNS_PID" ] && kill "$DNS_PID" 2>/dev/null; daemon_stop' EXIT

echo "=== Integration: the daemon's alerts ==="

# A hook that keeps every body it is sent, one a line.
start_hook() {
python3 - "$HP" "$T/hook.log" <<'PY' &
import http.server, os, sys
port, log = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get('content-length', 0)))
        # While told to, an answer that breaks off: fifty bytes promised, five sent.
        if os.path.exists(log + '.short'):
            self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort'); self.wfile.flush()
            self.close_connection = True
            return
        open(log, 'ab').write(b.replace(b'\n', b' ') + b'\n')
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PY
HOOK_PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null -X POST "http://127.0.0.1:$HP/" && break; sleep 0.1; done
}
start_hook
: > "$T/hook.log"

ADMIN="AKIADASHALERTADMIN00:dashalertadminsecretdashalertadminsec00"
printf '[admin]\nadmin = true\n%s\n' "$ADMIN" > "$T/creds"
cat > "$T/daemon.lua" <<EOF
daemon = { metrics_port = $M, dashboard_credentials = "$T/creds", alert_webhook = "http://127.0.0.1:$HP/hook" }
EOF
export SOCKETLEY_CONFIG="$T/daemon.lua"
# A resolver for the mail runtime below: its own name on a blocklist, and an exchanger nothing answers on.
NS=$((SL_PORT_BASE+1955))
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal listed-host.test=127.0.0.2 2.0.0.127.bl.test=127.0.0.2 \
    far.test=MX:10:mx.far.test mx.far.test=127.0.0.9 >/dev/null 2>&1 &
DNS_PID=$!
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf"
daemon_start "$BIN"
U="http://127.0.0.1:$M"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
signin() { curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null; }
signin
al() { curl -s -m 10 -b "$T/jar" "$U/api/alerts"; }
# A python expression over the alerts `d`.
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# Wait up to $1 seconds for the expression $2 over the alerts to print True.
until_al() { local i; for i in $(seq 1 "$1"); do [ "$(al | j "$2" 2>/dev/null)" = True ] && return 0; sleep 1; done; return 1; }
hook() { python3 -c "import json,sys; [print(eval(sys.argv[1], {}, {'d': json.loads(l)})) for l in open(sys.argv[2]) if l.strip()]" "$1" "$T/hook.log"; }

expect "the alerts need a session" "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/alerts")" 401
expect "with one there are none, and the hook is set" "$(al | j "(d['active'], d['webhook'])")" "([], True)"

# A runtime that fails: its script is broken after it was made.
echo '-- fine' > "$T/s.lua"
"$BIN" create server broke -p "$S1" --lua "$T/s.lua" -s >/dev/null 2>&1
echo 'this is not lua (' > "$T/s.lua"
"$BIN" stop broke >/dev/null 2>&1
"$BIN" start broke >/dev/null 2>&1
# A certificate that ends in five days.
openssl req -x509 -newkey rsa:2048 -nodes -days 5 -subj /CN=soon.example -keyout "$T/soon.key" -out "$T/soon.pem" 2>/dev/null
"$BIN" create server soon -p "$S2" --tls --cert "$T/soon.pem" --key "$T/soon.key" -s >/dev/null 2>&1
# A storage runtime near its limit.
"$BIN" create storage full -p "$S3" --dir "$T/full" --anonymous --max-bytes 1M -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$S3/" && break; sleep 0.1; done
curl -s -o /dev/null -X PUT "http://127.0.0.1:$S3/bkt"
head -c 1010000 /dev/zero | curl -s -o /dev/null -X PUT --data-binary @- "http://127.0.0.1:$S3/bkt/big"

until_al 30 "any(a['id'] == 'failed:broke' for a in d['active'])"
# The storage limit takes three readings, so by then a reading after the raise has seen the alert's own line in the log too.
until_al 45 "any(a['id'] == 'limit:full' for a in d['active'])"
a=$(al)
expect "a runtime that failed is a critical alert" "$(echo "$a" | j "[(x['level'], x['title']) for x in d['active'] if x['id'] == 'failed:broke']")" "[('critical', 'broke failed')]"
expect "saying why, in the runtime's own words and not the alert's" \
    "$(echo "$a" | j "[('refused its configuration' in x['detail'], 'alert:' in x['detail']) for x in d['active'] if x['id'] == 'failed:broke']")" "[(True, False)]"
expect "a certificate that ends in five days is a warning" \
    "$(echo "$a" | j "[(x['level'], x['title']) for x in d['active'] if x['id'].startswith('cert:')]")" "[('warning', 'The certificate of soon ends in 5 days')]"
for _ in $(seq 1 20); do [ "$(hook "d['alert']['id'] == 'failed:broke' and d['state'] == 'firing'" 2>/dev/null | grep -c True)" -ge 1 ] && break; sleep 0.5; done
expect "the hook is told, in what Discord and Slack read" \
    "$(hook "(d['state'], 'broke failed' in d['content'], d['content'] == d['text'])" | grep -c "('firing', True, True)")" 1
until_al 45 "any(a['id'] == 'limit:full' for a in d['active'])"
expect "a storage runtime at 96 % of its limit, after three readings" \
    "$(al | j "[(x['level'], x['title']) for x in d['active'] if x['id'] == 'limit:full']")" "[('warning', 'full holds 96% of its limit')]"

expect "a test of the hook needs the page's header" "$(curl -s -o /dev/null -w '%{http_code}' -b "$T/jar" -X POST "$U/api/alerts/test")" 403
expect "and with it reaches the hook" \
    "$(curl -s -o /dev/null -w '%{http_code}' -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -X POST "$U/api/alerts/test") $(hook "d['state']" | grep -c test)" "204 1"
touch "$T/hook.log.short"
expect "an answer that breaks off before its length is no delivery" \
    "$(curl -s -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -X POST -w ' %{http_code}' "$U/api/alerts/test" | tr -d '\n' | grep -c 'short of its length 502')" 1
rm -f "$T/hook.log.short"

file=$(find "$HOME" -name .alerts -type f | head -1)
expect "what was told of is kept in the state directory, private" "$(stat -c %a "$file" 2>/dev/null) $(grep -c failed:broke "$file")" "600 1"

# ─── a restart ──────────────────────────────────────────────────────────────
# A git repository whose last pull failed, as git-sync leaves one, is read when the daemon starts.
mkdir -p "$T/full/.ui/git/r1"
printf '{"repos":[{"id":"r1","owner":"socketley","url":"https://example.invalid/x.git","branch":"main","bucket":"git","name":"x","private":false,"every":"never","added":1}]}\n' > "$T/full/.ui/git.json"
printf '{"ok":false,"at":1,"error":"fatal: could not read from the remote"}\n' > "$T/full/.ui/git/r1/state.json"
since=$(al | j "[x['since'] for x in d['active'] if x['id'] == 'failed:broke'][0]")
kill "$SOCKETLEY_DPID"; wait "$SOCKETLEY_DPID" 2>/dev/null
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
signin
until_al 30 "any(a['id'] == 'failed:broke' for a in d['active']) and any(a['id'].startswith('git:') for a in d['active'])"
a=$(al)
expect "a daemon started again keeps when it began" "$(echo "$a" | j "[x['since'] for x in d['active'] if x['id'] == 'failed:broke'][0]")" "$since"
expect "a repository whose last pull failed is a warning, saying why" \
    "$(echo "$a" | j "[(x['level'], x['title'], x['detail']) for x in d['active'] if x['id'].startswith('git:')]")" \
    "[('warning', 'Git: pulling x into full failed', 'fatal: could not read from the remote')]"
sleep 2
expect "and does not tell the hook again of what it told of" "$(hook "d['alert']['id'] if 'alert' in d else ''" | grep -c '^failed:broke$')" 1

# ─── clearing ───────────────────────────────────────────────────────────────
echo '-- fine' > "$T/s.lua"
"$BIN" start broke >/dev/null 2>&1
until_al 60 "not any(a['id'] == 'failed:broke' for a in d['active'])"
expect "a runtime that runs again is cleared" "$(al | j "any(a['id'] == 'failed:broke' for a in d['active'])")" False
expect "kept in the history as cleared" "$(al | j "[e['raised'] for e in d['recent'] if e['alert']['id'] == 'failed:broke'][0]")" False
for _ in $(seq 1 20); do [ "$(hook "d['state']" | grep -c resolved)" -ge 1 ] && break; sleep 0.5; done
expect "and posted as resolved" "$(hook "(d['state'], d['alert']['id']) if 'alert' in d else ()" | grep -c "('resolved', 'failed:broke')")" 1
expect "and no longer kept as told of" "$(grep -c failed:broke "$file")" 0

# ─── a hook that is down ────────────────────────────────────────────────────
# Posted from a thread that gave up at the first failure, an alert raised while the hook was down was told to nobody,
# and once told of it was not sent again after a restart either.
kill "$HOOK_PID"; wait "$HOOK_PID" 2>/dev/null; HOOK_PID=""
: > "$T/hook.log"
echo '-- fine' > "$T/s2.lua"
"$BIN" create server broke2 -p "$S4" --lua "$T/s2.lua" -s >/dev/null 2>&1
echo 'this is not lua (' > "$T/s2.lua"
"$BIN" stop broke2 >/dev/null 2>&1
"$BIN" start broke2 >/dev/null 2>&1
until_al 30 "any(a['id'] == 'failed:broke2' for a in d['active'])"
# Tried and refused a few times while the hook is away, then the daemon goes with the message still owed.
sleep 2
kill "$SOCKETLEY_DPID"; wait "$SOCKETLEY_DPID" 2>/dev/null
daemon_start "$BIN"
start_hook
for _ in $(seq 1 60); do [ "$(hook "d['alert']['id'] if 'alert' in d else ''" 2>/dev/null | grep -c '^failed:broke2$')" -ge 1 ] && break; sleep 0.5; done
expect "an alert raised while the hook was down reaches it once it is up, though the daemon restarted between" \
    "$(hook "(d['state'], d['alert']['id']) if 'alert' in d else ()" | grep -c "('firing', 'failed:broke2')")" 1
sleep 2
expect "and once" "$(hook "d['alert']['id'] if 'alert' in d else ''" | grep -c '^failed:broke2$')" 1

# A mail runtime whose own address a blocklist names, and whose queue holds what it cannot deliver.
signin
"$BIN" create mail mlisted -p $((SL_PORT_BASE+1956)) --mail-domain other.test --hostname listed-host.test --dnsbl bl.test -s \
    >/dev/null 2>&1
until_al 45 "any(a['id'] == 'blocklisted:mlisted' and a['level'] == 'critical' for a in d['active'])" \
    && ok "a mail runtime whose own address a blocklist names is an alert" || bad "blocklisted" "$(al)"
for i in $(seq 1 100); do "$BIN" send mlisted --to "u$i@far.test" --from a@other.test --subject x --text x >/dev/null 2>&1; done
until_al 60 "any(a['id'] == 'mailqueue:mlisted' for a in d['active'])" \
    && ok "and one whose queue holds a hundred it cannot deliver" || bad "mail queue" "$("$BIN" mail mlisted | grep queue) $(al)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
