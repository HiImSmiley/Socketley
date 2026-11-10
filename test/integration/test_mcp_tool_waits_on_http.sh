#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: an mcp tool that calls socketley.http waits for the answer on a coroutine, and the runtime answers
# other calls meanwhile.
#
# What each part would catch:
#   * socketley.http blocking the runtime, so a quick tool waits for a slow one's host
#   * a tool that waited answered with nothing, or with another call's answer
#   * a deadline not kept while the exchange waits on the loop
#   * a stop with an exchange in flight leaving the runtime unable to start or serve again
#   * a reload-lua with a tool waiting leaving its call unanswered for ever
#   * a reload-lua of a script that does not compile taking the running script's tools with it
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

echo "=== Integration: an mcp tool waits on socketley.http while the runtime serves ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate mcphttp
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1983)); PH=$((SL_PORT_BASE + 1984))
unset SOCKETLEY_CONFIG

# A host that answers /slow after a second and a half and /fast at once.
python3 -I - "$PH" > "$T/host.log" 2>&1 <<'PY' &
import http.server, socketserver, sys, time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            time.sleep(1.5)
        body = (self.path.strip("/") + "-done").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
HOST_PID=$!
trap 'kill $HOST_PID 2>/dev/null; daemon_stop' EXIT

cat > "$T/tools.lua" <<EOF
local base = "http://127.0.0.1:$PH"
mcp.tool{ name = "slow", handler = function()
  local r = socketley.http{ url = base .. "/slow" }
  return r.ok and r.body or ("failed: " .. r.error) end }
mcp.tool{ name = "two", handler = function()
  local a = socketley.http{ url = base .. "/fast" }
  local b = socketley.http{ url = base .. "/again" }
  return a.body .. "+" .. b.body end }
mcp.tool{ name = "late", handler = function()
  local r = socketley.http{ url = base .. "/slow", timeout_ms = 300 }
  return tostring(r.ok) .. " " .. r.error end }
mcp.tool{ name = "quick", handler = function() return "quick" end }
EOF
daemon_start "$BIN"
"$BIN" create mcp m -p "$P" --anonymous --lua "$T/tools.lua" -s >"$T/create.out" 2>&1 || bad "the mcp server is made" "$(cat "$T/create.out")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$P/mcp")" != 000 ] && break; sleep 0.1; done
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PH/fast")" = 200 ] && break; sleep 0.1; done

out=$(timeout 60 python3 -I - "$P" "$BIN" "$T/tools.lua" <<'PY'
import json, subprocess, sys, threading, time, urllib.request
port, binp, script = int(sys.argv[1]), sys.argv[2], sys.argv[3]
URL = "http://127.0.0.1:%d/mcp" % port
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}
def call(name):
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}, "_meta": META}}
    h = {"Content-Type": "application/json", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
         "Mcp-Name": name}
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(URL, data=json.dumps(msg).encode(), headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            doc = json.loads(r.read())
        text = doc["result"]["content"][0]["text"]
    except Exception as e:
        text = "error: %s" % e
    return text, time.monotonic() - t0
def check(what, cond, detail):
    print(("ok " if cond else "FAIL ") + what + ("" if cond else ": " + detail))

slow = {}
th = threading.Thread(target=lambda: slow.update(r=call("slow")))
th.start()
time.sleep(0.3)
text, took = call("quick")
check("a quick tool is answered while a slow one waits on its host", text == "quick" and took < 0.7,
      "%r after %.2fs" % (text, took))
th.join()
text, took = slow["r"]
check("and the slow one gets its own answer", text == "slow-done" and took >= 1.4, "%r after %.2fs" % (text, took))

text, took = call("two")
check("a tool that waits twice gets both answers in order", text == "fast-done+again-done", repr(text))

text, took = call("late")
check("a deadline ends the exchange it bounds", text == "false timed out after 300ms" and took < 1.2,
      "%r after %.2fs" % (text, took))

# A stop with an exchange in flight, then the runtime again.
th = threading.Thread(target=lambda: slow.update(r=call("slow")))
th.start()
time.sleep(0.3)
subprocess.run([binp, "stop", "m"], capture_output=True)
th.join()
subprocess.run([binp, "start", "m"], capture_output=True)
for _ in range(50):
    text, took = call("quick")
    if text == "quick":
        break
    time.sleep(0.1)
check("a stop with an exchange in flight leaves the runtime to start and serve again", text == "quick", repr(text))
text, took = call("two")
check("and to wait on the loop again", text == "fast-done+again-done", repr(text))

# A reload with a tool waiting: the new script never resumes it, so its call is answered now.
th = threading.Thread(target=lambda: slow.update(r=call("slow")))
th.start()
time.sleep(0.3)
subprocess.run([binp, "reload-lua", "m"], capture_output=True)
th.join()
text, took = slow["r"]
check("a reload with a tool waiting answers its call", text == "the tool raised: the script was reloaded" and took < 1.4,
      "%r after %.2fs" % (text, took))
text, took = call("two")
check("and the reloaded script's tools wait on the loop", text == "fast-done+again-done", repr(text))

# A script that does not compile leaves the running one, tools and all.
good = open(script).read()
with open(script, "w") as f:
    f.write("mcp.tool{ name = 'broken', handler = function() return 1 end }\nthis is ( not lua\n")
r = subprocess.run([binp, "reload-lua", "m"], capture_output=True, text=True)
text, took = call("quick")
check("a reload that does not compile keeps the running script's tools", text == "quick" and r.returncode != 0,
      "%r, reload said %r" % (text, r.stdout + r.stderr))
with open(script, "w") as f:
    f.write(good)
PY
)
while IFS= read -r line; do
    case "$line" in
        "ok "*) ok ;;
        "FAIL "*) bad "${line#FAIL }" "" ;;
        *) [ -n "$line" ] && echo "  $line" ;;
    esac
done <<< "$out"
[ $((PASS + FAIL)) -ge 9 ] || bad "every check ran" "only $((PASS + FAIL)) did: $out"
"$BIN" ls 2>/dev/null | grep -q ' m ' || bad "the daemon lists the runtime still" "$("$BIN" ls 2>&1)"

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
