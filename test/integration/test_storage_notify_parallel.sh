#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, data directory and port window, so it runs beside the others
# Integration test: a webhook is sent events of different objects side by side, and those of one object in order.
#
# What each part would catch:
#   * one event at a time to a webhook: a receiver that answers in 50 ms took a bucket's events at 20 a second
#   * two events of one object at once, or a later one ahead of an earlier: a PUT then a DELETE told the other way
#     round, which leaves a receiver believing a removed object is there
#   * more at once than a webhook is let have
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a webhook is sent the events of different objects side by side ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate notifypar
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1964)); HOOK=$((SL_PORT_BASE + 1965))
unset SOCKETLEY_CONFIG
trap 'kill $HOOK_PID 2>/dev/null; daemon_stop' EXIT
# A receiver that takes 50 ms an event, and notes when each came, what about, and how many were open at once.
python3 - "$HOOK" "$T/got" <<'PY' &
import http.server, json, sys, threading, time
port, out = int(sys.argv[1]), sys.argv[2]
lock, state = threading.Lock(), {"open": 0, "most": 0, "same": 0, "same_most": 0}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with lock:
            state["open"] += 1; state["most"] = max(state["most"], state["open"])
            r = json.loads(body)["Records"][0]
            key = r["s3"]["object"]["key"]
            if key == "same":
                state["same"] += 1; state["same_most"] = max(state["same_most"], state["same"])
            with open(out, "a") as f:
                f.write("%.3f %s %s %d %d\n" % (time.time(), key, r["eventName"], state["most"], state["same_most"]))
        time.sleep(0.05)
        with lock:
            state["open"] -= 1
            if key == "same":
                state["same"] -= 1
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
HOOK_PID=$!
printf 'hook http://127.0.0.1:%s/events\n' "$HOOK" > "$T/targets"
daemon_start "$BIN"
"$BIN" create storage st -p "$P" --dir "$T/d" --anonymous --notify-targets "$T/targets" -s >/dev/null 2>&1
U="http://127.0.0.1:$P"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done
curl -s -o /dev/null -X PUT "$U/bkt"
cfg='<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><QueueConfiguration><Id>a</Id><Queue>arn:socketley:webhook:::hook</Queue><Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event></QueueConfiguration></NotificationConfiguration>'
st=$(curl -s -o "$T/cfg.out" -w '%{http_code}' -X PUT --data-binary "$cfg" "$U/bkt?notification")
[ "$st" = 200 ] || { bad "the bucket takes the configuration" "$st $(cat "$T/cfg.out")"; }

# One object put, removed, put, removed and put, its events next to each other, then a hundred objects.
t0=$(mono_ns)
for n in 1 2 3 4 5; do
    if [ $((n % 2)) = 1 ]; then printf 's' | curl -s -o /dev/null -X PUT --data-binary @- "$U/bkt/same"
    else curl -s -o /dev/null -X DELETE "$U/bkt/same"; fi
done
for i in $(seq 1 100); do printf 'x' | curl -s -o /dev/null -X PUT --data-binary @- "$U/bkt/k$i"; done
want=105
for _ in $(seq 1 300); do [ "$(wc -l < "$T/got" 2>/dev/null || echo 0)" -ge "$want" ] && break; sleep 0.05; done
ms=$(( ($(mono_ns) - t0) / 1000000 ))
got=$(wc -l < "$T/got" 2>/dev/null || echo 0)
most=$(awk '{m = $4 > m ? $4 : m} END {print m + 0}' "$T/got")
same=$(awk '$2 == "same" {printf "%s ", $3}' "$T/got")
same_most=$(awk '{m = $5 > m ? $5 : m} END {print m + 0}' "$T/got")
echo "  $got of $want events to a webhook that answers in 50 ms, in $ms ms, at most $most at once"
echo "  the one object's: $same"
[ "$got" = "$want" ] || "$BIN" stats st 2>/dev/null | grep notify_
[ "$got" = "$want" ] && ok || bad "every event is sent" "$got of $want"
[ "$same" = "ObjectCreated:Put ObjectRemoved:Delete ObjectCreated:Put ObjectRemoved:Delete ObjectCreated:Put " ] && ok \
    || bad "one object's events are sent in order" "$same"
[ "$same_most" = 1 ] && ok || bad "and one at a time" "$same_most of them at once"
[ "$most" -ge 2 ] && [ "$most" -le 4 ] && ok || bad "side by side, at most four" "$most at once"
if [ "$sanitized" = 1 ]; then echo "  SKIP [time]: milliseconds measure the sanitizer, not the deliveries"
elif [ "$ms" -lt 3500 ]; then ok
else bad "the events do not wait for each other's answers" "$ms ms"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
