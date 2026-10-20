#!/usr/bin/env bash
# Integration test: a storage runtime's events go to the daemon's own runtimes -- a cache's stream, a cache's channel
# and a server's clients -- named in --notify-targets beside webhooks.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a cache:// or server:// line refused, or one malformed taken
#   * an event missing from the stream, the channel or the server's clients,
#     or reaching one of them as something other than the event's record
#   * an event for a runtime that is stopped lost rather than retried
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgnotifyrt
PS3=$((SL_PORT_BASE+1985))
PC=$((SL_PORT_BASE+1986))
PV=$((SL_PORT_BASE+1987))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in nrs nrc nrv nrx; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.2
    for r in nrs nrc nrv nrx; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0; sleep 0.1; done
    return 1
}
wait_port() {
    for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3<&- 3>&-; return 0; }; sleep 0.1; done
    return 1
}
stat_of() { "$BIN" stats nrs 2>&1 | awk -F: -v k="$1" '$1==k{s+=$2} END{print s+0}'; }

echo "=== Integration: storage events to the daemon's runtimes ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"

for line in "x cache://nrc/stack/s3" "x cache://nrc/stream/" "x server://nrv/more" "x cache:///stream/s3" \
            "x cache://nrc/stream/s3 ca=/etc/hosts"; do
    echo "$line" > "$T/bad"
    out=$("$BIN" create storage nrx -p "$PS3" --dir "$T/x" --anonymous --notify-targets "$T/bad" 2>&1)
    [ $? -ne 0 ] && echo "$out" | grep -q "runtime target" && ok "a malformed line is refused: $line" \
        || bad "a malformed line is refused: $line" "$out"
    "$BIN" remove nrx >/dev/null 2>&1
done

"$BIN" create cache nrc -p "$PC" -s >/dev/null 2>&1 || bad "the cache is made" "create failed"
"$BIN" create server nrv -p "$PV" -s >/dev/null 2>&1 || bad "the server is made" "create failed"
printf 'feed cache://nrc/stream/s3events\nlive cache://nrc/channel/s3live\npanel server://nrv\n' > "$T/targets"
"$BIN" create storage nrs -p "$PS3" --dir "$T/data" --anonymous --notify-targets "$T/targets" -s >/dev/null 2>&1 \
    || { echo "  FAIL [create]: the storage runtime was not created"; exit 1; }
wait_up "$PS3" || bad "the storage runtime comes up" "no answer on $PS3"
wait_port "$PC" || bad "the cache comes up" "no answer on $PC"
wait_port "$PV" || bad "the server comes up" "no answer on $PV"

[ "$(code -X PUT "http://127.0.0.1:$PS3/evb")" = 200 ] || bad "the bucket is made" "PUT /evb refused"
A="arn:socketley:webhook:::"
cfg="<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
# Each target by a suffix of its own, since configurations of one bucket may not share an event.
for t in feed live panel; do
    cfg+="<QueueConfiguration><Id>$t</Id><Queue>$A$t</Queue><Event>s3:ObjectCreated:*</Event>"
    cfg+="<Filter><S3Key><FilterRule><Name>suffix</Name><Value>.$t</Value></FilterRule></S3Key></Filter>"
    cfg+="</QueueConfiguration>"
done
cfg+="</NotificationConfiguration>"
resp=$(curl -s -w ' %{http_code}' -X PUT --data-binary "$cfg" "http://127.0.0.1:$PS3/evb?notification")
[ "${resp##* }" = 200 ] && ok "a configuration naming the three runtime targets is taken" \
    || bad "a configuration naming the three runtime targets is taken" "$(echo "$resp" | tr -d "\n")"

python3 - "$PC" "$PV" "$PS3" <<'PY' > "$T/listen.out" 2>&1 &
import socket, sys, time, urllib.request
pc, pv, ps = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
sub = socket.create_connection(("127.0.0.1", pc), 5)
sub.sendall(b"subscribe s3live\n")
cli = socket.create_connection(("127.0.0.1", pv), 5)
cli.sendall(b"hello\n")
time.sleep(0.5)
for t in ("feed", "live", "panel"):
    urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/evb/k1.%s" % (ps, t), data=b"one",
                                                  method="PUT")).read()
got = {"sub": b"", "cli": b""}
end = time.time() + 10
for s in (sub, cli):
    s.settimeout(0.2)
# Until each holds all of its record, since one may arrive in more than one read.
want = {"sub": (b"k1.live", b"ObjectCreated:Put"), "cli": (b"k1.panel", b"ObjectCreated:Put", b'"Records"')}
while time.time() < end and not all(w in got[n] for n, ws in want.items() for w in ws):
    for name, s in (("sub", sub), ("cli", cli)):
        try:
            got[name] += s.recv(65536)
        except socket.timeout:
            pass
print("SUB", b"k1.live" in got["sub"] and b"ObjectCreated:Put" in got["sub"] and b"k1.feed" not in got["sub"])
print("CLI", b"k1.panel" in got["cli"] and b"ObjectCreated:Put" in got["cli"] and b'"Records"' in got["cli"])
PY
wait $!
grep -q '^SUB True' "$T/listen.out" && ok "a subscriber of the cache's channel hears the event" \
    || bad "a subscriber of the cache's channel hears the event" "$(cat "$T/listen.out")"
grep -q '^CLI True' "$T/listen.out" && ok "a client of the server is sent the event's record" \
    || bad "a client of the server is sent the event's record" "$(cat "$T/listen.out")"

xr() { python3 - "$PC" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.sendall(b"xrange s3events - +\n")
s.settimeout(0.5)
out = b""
end = time.time() + 3
while time.time() < end and not out.endswith(b"end\n"):
    try:
        out += s.recv(65536)
    except socket.timeout:
        pass
sys.stdout.write(out.decode(errors="replace"))
PY
}
for _ in $(seq 1 50); do xr | grep -q '"key":"k1.feed"' && break; sleep 0.1; done
out=$(xr)
echo "$out" | grep -q ' event {"Records"' && echo "$out" | grep -q '"key":"k1.feed"' \
    && ok "the cache's stream holds the event as an entry of one field, event" \
    || bad "the cache's stream holds the event as an entry of one field, event" "$out"
for _ in $(seq 1 50); do [ "$(stat_of notify_sent)" -ge 3 ] && break; sleep 0.1; done
[ "$(stat_of notify_sent)" -ge 3 ] && ok "each delivery counts as sent" || bad "each delivery counts as sent" "$(stat_of notify_sent)"

"$BIN" stop nrc >/dev/null 2>&1
code -X PUT --data-binary two "http://127.0.0.1:$PS3/evb/k2.feed" >/dev/null
for _ in $(seq 1 50); do [ "$(stat_of notify_failed)" -ge 1 ] && break; sleep 0.1; done
[ "$(stat_of notify_failed)" -ge 1 ] && [ "$(stat_of notify_queued)" -ge 1 ] \
    && ok "an event for a cache that is stopped fails and waits" \
    || bad "an event for a cache that is stopped fails and waits" "failed $(stat_of notify_failed) queued $(stat_of notify_queued)"
"$BIN" start nrc >/dev/null 2>&1
wait_port "$PC"
for _ in $(seq 1 150); do xr | grep -q '"key":"k2.feed"' && break; sleep 0.1; done
xr | grep -q '"key":"k2.feed"' && ok "and reaches its stream once the cache is back" \
    || bad "and reaches its stream once the cache is back" "$(xr | tail -3)"

# A server that is stopped was counted reached, because a broadcast to it was posted rather than refused, and the
# event left the outbox for nobody.
f0=$(stat_of notify_failed)
"$BIN" stop nrv >/dev/null 2>&1
code -X PUT --data-binary two "http://127.0.0.1:$PS3/evb/k2.panel" >/dev/null
for _ in $(seq 1 50); do [ "$(stat_of notify_failed)" -gt "$f0" ] && break; sleep 0.1; done
[ "$(stat_of notify_failed)" -gt "$f0" ] && [ "$(stat_of notify_queued)" -ge 1 ] \
    && ok "an event for a server that is stopped fails and waits" \
    || bad "an event for a server that is stopped fails and waits" "failed $(stat_of notify_failed) queued $(stat_of notify_queued)"
"$BIN" start nrv >/dev/null 2>&1
wait_port "$PV"
back=$(python3 - "$PV" <<'PY'
import socket, sys, time
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
c.sendall(b"hello\n")
c.settimeout(0.2)
got, end = b"", time.time() + 20
while time.time() < end and b"k2.panel" not in got:
    try:
        got += c.recv(65536)
    except socket.timeout:
        pass
print(b"k2.panel" in got)
PY
)
[ "$back" = True ] && ok "and reaches the server's clients once it is back" \
    || bad "and reaches the server's clients once it is back" "$back"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
