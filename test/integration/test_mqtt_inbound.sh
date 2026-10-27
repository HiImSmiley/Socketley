#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Messages into an mqtt runtime from the daemon's others: a storage's events through an mqtt:// notification
# target, and a server's script through socketley.mqtt.publish, in both of its forms.
#
# What each part would catch:
#   * a storage event not reaching the broker's subscribers, or reaching them as something other than its record
#   * socketley.mqtt.publish answering before the broker has the message, or not at all through its callback
#   * a wildcard topic taken from a script, or retain=true not retaining
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$HERE/lib_verdicts.sh"
expect() { [ "$2" = "$3" ] && ok || bad "$1" "got '$2', want '$3'"; }

echo "=== Integration: a storage's events and a script's messages reach an mqtt runtime's subscribers ==="
daemon_isolate mqttinbound
T=$SOCKETLEY_TMPD
PT=$((SL_PORT_BASE + 1942))
PC=$((SL_PORT_BASE + 1945))
PA=$((SL_PORT_BASE + 1947))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

for line in "x mqtt://core" "x mqtt://core/a/+/b" "x mqtt:///t" "x mqtt://core/\$SYS/x"; do
    echo "$line" > "$T/bad"
    out=$("$BIN" create storage nrx -p "$PT" --dir "$T/x" --anonymous --notify-targets "$T/bad" 2>&1); rc=$?
    case "$out" in *"a broker target is mqtt://"*) [ "$rc" -ne 0 ] && ok || bad "a malformed broker target is refused: $line" "rc $rc" ;;
        *) bad "a malformed broker target is refused: $line" "rc $rc: $out" ;; esac
    "$BIN" remove nrx >/dev/null 2>&1
done

"$BIN" create mqtt core -p "$PC" --anonymous -s >/dev/null 2>&1 || bad "a broker is made" "$(tail -3 "$SOCKETLEY_DLOG")"
printf 'bus mqtt://core/storage/events\n' > "$T/targets"
"$BIN" create storage raw -p "$PT" --dir "$T/raw" --anonymous --notify-targets "$T/targets" -s >/dev/null 2>&1 \
    || bad "a storage is made" "$(tail -3 "$SOCKETLEY_DLOG")"
cat > "$T/app.lua" <<'LUA'
function on_client_message(client_id, msg)
    local topic, payload = msg:match("^(%S+) (.*)$")
    if topic == "cb" then
        socketley.mqtt.publish("core", "app/cb", payload, { qos = 1 }, function(ok, err)
            self.send(client_id, "cb " .. tostring(ok) .. " " .. tostring(err))
        end)
        return
    end
    local ok, err = socketley.mqtt.publish("core", topic, payload, { qos = 1, retain = topic == "app/kept" })
    self.send(client_id, "sync " .. tostring(ok) .. " " .. tostring(err))
end
LUA
"$BIN" create server app -p "$PA" --lua "$T/app.lua" -s >/dev/null 2>&1 \
    || bad "a server whose script publishes is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PT" "$PC" "$PA"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done
curl -s -o /dev/null -X PUT "http://127.0.0.1:$PT/raw-in"
cfg='<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><QueueConfiguration><Id>b</Id><Queue>arn:socketley:webhook:::bus</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>'
st=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary "$cfg" "http://127.0.0.1:$PT/raw-in?notification")
expect "a bucket's events go to the broker target" "$st" "200"

run() {
    PYTHONPATH="$HERE" python3 - "$PT" "$PC" "$PA" 2>&1 <<'PY'
import sys, time, urllib.request
from lib_mqtt import *
pt, pc, pa = (int(x) for x in sys.argv[1:4])

def inbound():
    sub = connected(pc, "in-sub")
    sub.subscribe(("storage/events", 1), ("app/#", 1))
    req = urllib.request.Request("http://127.0.0.1:%d/raw-in/photo.jpg" % pt, data=b"jpeg", method="PUT")
    urllib.request.urlopen(req).read()
    m = sub.message(10)
    truth("a storage event reaches the broker's subscribers as its record",
          m is not None and m.topic == "storage/events" and b'"key":"photo.jpg"' in m.payload and
          b"ObjectCreated:Put" in m.payload, m)

    c = line_client(pa)
    c.sendall(b"app/hello from the server\n")
    got = read_until(c, b"sync", 10)
    truth("socketley.mqtt.publish answers true once the broker has the message", b"sync true nil" in got, got)
    m = sub.message(3)
    check("and the broker's subscribers get it", (m.topic, m.payload, m.qos) if m else None,
          ("app/hello", b"from the server", 1))
    c.sendall(b"cb with a callback\n")
    got = read_until(c, b"cb ", 10)
    truth("the callback form answers through the callback", b"cb true nil" in got, got)
    m = sub.message(3)
    check("and publishes too", m.payload if m else None, b"with a callback")
    c.sendall(b"app/+/bad wildcard\n")
    got = read_until(c, b"sync", 10)
    truth("a wildcard topic is refused with the reason", b"sync nil" in got and b"is not a topic" in got, got)
    c.sendall(b"app/kept retained one\n")
    read_until(c, b"sync", 10)
    late = connected(pc, "in-late")
    late.subscribe(("app/kept", 1))
    m = late.message(3)
    check("retain=true retains it", (m.payload, m.retain) if m else None, (b"retained one", True))
    late.disconnect()
    sub.disconnect()
    c.close()

guarded("inbound", inbound)
PY
}
tally < <(run)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
