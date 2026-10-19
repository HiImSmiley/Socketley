#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An mqtt runtime's own script: on_auth, on_publish and on_subscribe deciding what passes, on_connect and
# on_disconnect told, and self.publish, self.retained, self.sessions and self.kick.
#
# What each part would catch:
#   * a hook's true, false, nil or table not doing what it says, or a silent on_auth refusing --anonymous clients
#   * a script that let a client in under a name the credentials did not check, given that name's rights anyway
#   * on_connect or on_disconnect not run, or run for a client that was refused
#   * a self.* call that answers wrong, or a kick that leaves the client connected
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
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }

echo "=== Integration: an mqtt runtime's script decides who connects and what passes ==="
daemon_isolate mqttlua
T=$SOCKETLEY_TMPD
PH=$((SL_PORT_BASE + 1946))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

# Clients without a checked name may do anything but read robot's and robot2's topics.
cat > "$T/acl" <<'EOF'
topic deny robot/#
topic deny secret2/#
topic readwrite #
user robot
topic readwrite robot/#
user robot2
topic readwrite secret2/#
EOF
cat > "$T/hooks.lua" <<'LUA'
function on_auth(c)
    if c.username == "robot" then return c.password == "beep" end
    if c.username == "banned" then return false end
end
function on_publish(client, msg)
    if msg.topic == "blocked" then return false end
    if msg.topic == "shout" then return { topic = "shout/out", payload = string.upper(msg.payload) } end
    if msg.topic == "ask/retained" then
        self.publish("answers/retained", self.retained("keep/me") or "none")
    elseif msg.topic == "ask/sessions" then
        local n = 0
        for _, s in ipairs(self.sessions()) do if s.connected then n = n + 1 end end
        self.publish("answers/sessions", tostring(n))
    elseif msg.topic == "ask/kick" then
        self.publish("answers/kick", tostring(self.kick(msg.payload)))
    elseif msg.topic == "ask/who" then
        self.publish("answers/who", client.id .. "/" .. client.username .. "/" .. client.version)
    end
end
function on_subscribe(client, filter, qos)
    if filter == "forbidden/#" then return false end
end
function on_connect(client)
    self.publish("events/connect", client.id)
end
function on_disconnect(client, why)
    self.publish("events/disconnect", client.id)
end
LUA
"$BIN" create mqtt hooked -p "$PH" --anonymous --acl "$T/acl" --lua "$T/hooks.lua" -s >/dev/null 2>&1 \
    && ok || bad "a broker with a script is made" "$(tail -3 "$SOCKETLEY_DLOG")"
ready_tcp 127.0.0.1 "$PH" || bad "it listens" "$(tail -5 "$SOCKETLEY_DLOG")"

run() {
    PYTHONPATH="$HERE" python3 - "$PH" 2>&1 <<'PY'
import sys, time
from lib_mqtt import *
ph = int(sys.argv[1])

def hooks():
    ev = connected(ph, "watcher")
    ev.subscribe(("events/#", 1), ("answers/#", 1), ("shout/out", 1), ("blocked", 1))
    check("on_auth's true lets in a user no file holds", Client(ph).connect("r1", username="robot", password="beep")[1], 0)
    check("its false refuses a wrong password", Client(ph).connect("r2", username="robot", password="no")[1], 0x86)
    check("and refuses a client --anonymous would let in", Client(ph).connect("b1", username="banned")[1], 0x87)
    check("while nil keeps what --anonymous says", Client(ph).connect("n1")[1], 0)
    got = [m.payload for m in ev.messages(20, 1.5) if m.topic == "events/connect"]
    truth("on_connect runs for each client let in, and self.publish reaches subscribers",
          b"r1" in got and b"n1" in got and b"b1" not in got and b"r2" not in got, got)

    # The name a script let in is the user for the rules; a name given without credentials is not.
    robot = connected(ph, "robot-1", username="robot", password="beep")
    check("the user a script let in has its rules' rights", robot.subscribe(("robot/#", 1)), [1])
    robot.disconnect()
    pretender = connected(ph, "pretender", username="robot2")
    check("a client --anonymous let in under a name it only claimed does not get that name's rights",
          pretender.subscribe(("secret2/#", 1)), [0x87])
    pretender.disconnect()

    c = connected(ph, "hook-pub", version=4)
    check("on_publish's false refuses a message", c.publish("blocked", "x", qos=1), 0)
    truth("which nobody gets", all(m.topic != "blocked" for m in ev.messages(5, 0.6)))
    c.publish("shout", "quiet words", qos=1)
    m = [x for x in ev.messages(5, 2) if x.topic == "shout/out"]
    check("a table replaces the message", (m[0].topic, m[0].payload) if m else None, ("shout/out", b"QUIET WORDS"))
    check("on_subscribe's false refuses the subscription", c.subscribe(("forbidden/#", 1)), [0x80])
    check("and nil grants it", c.subscribe(("allowed/#", 1)), [1])
    c.publish("keep/me", "kept value", qos=1, retain=True)
    c.publish("ask/retained", "", qos=1)
    m = [x for x in ev.messages(3, 2) if x.topic == "answers/retained"]
    check("self.retained reads a retained payload", m[0].payload if m else None, b"kept value")
    c.publish("ask/who", "", qos=1)
    m = [x for x in ev.messages(3, 2) if x.topic == "answers/who"]
    check("the client table names the id, the user and the version", m[0].payload if m else None,
          b"hook-pub//3.1.1")
    c.publish("ask/sessions", "", qos=1)
    m = [x for x in ev.messages(3, 2) if x.topic == "answers/sessions"]
    truth("self.sessions lists the sessions", m and int(m[0].payload) >= 2, m)
    victim = connected(ph, "victim")
    ev.messages(50, 0.5)
    c.publish("ask/kick", "victim", qos=1)
    heard = ev.messages(10, 2)
    m = [x for x in heard if x.topic == "answers/kick"]
    check("self.kick disconnects a client", m[0].payload if m else None, b"true")
    truth("which is closed", victim.closed_within(2))
    got = [x.payload for x in heard + ev.messages(10, 1) if x.topic == "events/disconnect"]
    truth("and on_disconnect runs for it", b"victim" in got, got)
    c.disconnect()
    ev.disconnect()

guarded("hooks", hooks)
PY
}
tally < <(run)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
