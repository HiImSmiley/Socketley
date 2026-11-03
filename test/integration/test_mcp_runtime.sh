#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: an mcp runtime serves the tools, the resource and the prompt its script declares, and the daemon's
# runtimes as tools, over Streamable HTTP to a client of 2026-07-28 and to one that opens with initialize.
#
# What each part would catch:
#   * a key that is no key let in, or an origin of another site, or a method the endpoint has not
#   * a tool, a resource or a prompt of the script not reached, or its answer not in the shape the revision asks
#   * a tool that failed or raised answered as a JSON-RPC error, which a model never reads, rather than isError
#   * a key that may not administer shown or let call what stops a runtime
#   * a client of 2025-11-25 refused
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

echo "=== Integration: an mcp runtime serves its script's tools and the daemon's ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate mcprt
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1977)); PO=$((SL_PORT_BASE + 1978))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
cat > "$T/keys" <<EOF
# name secret [admin]
ops   opssecretopssecret01
root  rootsecretrootsecret1 admin
EOF
cat > "$T/tools.lua" <<'EOF'
mcp.tool{ name = "add", description = "Adds two numbers.", read_only = true,
  input = { type = "object", properties = { a = { type = "number" }, b = { type = "number" } }, required = { "a", "b" } },
  output = '{"type":"object","properties":{"sum":{"type":"number"}}}',
  handler = function(args, who) return { structured = { sum = args.a + args.b, by = who.name } } end }
mcp.tool{ name = "fail", handler = function() return { text = "the order was not found", error = true } end }
mcp.tool{ name = "boom", handler = function() error("kaboom") end }
mcp.resource{ uri = "shop://hello", name = "hello", mime = "text/plain", ttl_ms = 5000,
  read = function(who) return "hello " .. who.name end }
mcp.prompt{ name = "greet", description = "A greeting.", arguments = { { name = "who", required = true } },
  get = function(args) return { description = "greets", messages = { { role = "user", text = "Greet " .. args.who } } } end }
EOF
daemon_start "$BIN"
"$BIN" create server other -p "$PO" -s >/dev/null 2>&1
"$BIN" create mcp m -p "$P" --keys "$T/keys" --lua "$T/tools.lua" --tools daemon --origins https://app.test \
    --instructions "Ask about the shop." -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$P/mcp")" != 000 ] && break; sleep 0.1; done

out=$(timeout 120 python3 - "$P" "$BIN" <<'PY'
import json, subprocess, sys, urllib.request, urllib.error
port, binp = int(sys.argv[1]), sys.argv[2]
URL = "http://127.0.0.1:%d/mcp" % port
OPS, ROOT = "opssecretopssecret01", "rootsecretrootsecret1"
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}
n = [0]
def post(method, params=None, key=OPS, version="2026-07-28", name=None, origin=None, notify=False, raw=None):
    n[0] += 1
    msg = {"jsonrpc": "2.0", "method": method}
    if not notify: msg["id"] = n[0]
    p = dict(params or {})
    if version == "2026-07-28": p["_meta"] = META
    if p: msg["params"] = p
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if key: h["Authorization"] = "Bearer " + key
    if version: h["MCP-Protocol-Version"] = version
    if version == "2026-07-28": h["Mcp-Method"] = method
    if name: h["Mcp-Name"] = name
    if origin: h["Origin"] = origin
    req = urllib.request.Request(URL, data=raw if raw is not None else json.dumps(msg).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(); return r.status, dict(r.headers), (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        body = e.read(); return e.code, dict(e.headers), (json.loads(body) if body else None)
rows = []
def check(what, cond, got=""):
    rows.append((what, bool(cond), str(got)[:200]))

st, h, _ = post("tools/list", key=None)
check("no key is refused, with how to give one", st == 401 and "Bearer" in h.get("WWW-Authenticate", ""), st)
st, _, _ = post("tools/list", key="opssecretopssecret0X")
check("a wrong key is refused", st == 401, st)
st, _, _ = post("tools/list", origin="https://evil.test")
check("a page of another site is refused", st == 403, st)
st, h, _ = post("tools/list", origin="https://app.test")
check("one of --origins is let in, and told so", st == 200 and h.get("Access-Control-Allow-Origin") == "https://app.test", h)
g = urllib.request.Request(URL, headers={"Authorization": "Bearer " + OPS}, method="GET")
try:
    urllib.request.urlopen(g, timeout=5); gst, allow = 200, ""
except urllib.error.HTTPError as e:
    gst, allow = e.code, e.headers.get("Allow", "")
check("a GET is no stream of its own here", gst == 405 and allow == "POST", (gst, allow))

st, _, d = post("server/discover")
r = d["result"]
check("discover says the revisions and what the server has",
      r["supportedVersions"][0] == "2026-07-28" and set(r["capabilities"]) == {"tools", "resources", "prompts"}
      and r["instructions"] == "Ask about the shop." and r["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "m", r)

st, _, d = post("tools/list")
names = [t["name"] for t in d["result"]["tools"]]
check("an ops key is shown the script's tools and the daemon's that read", names == ["add", "fail", "boom", "socketley_list", "socketley_get"], names)
add = d["result"]["tools"][0]
check("a tool's schemas and hints as the script gave them",
      add["inputSchema"]["required"] == ["a", "b"] and add["outputSchema"]["properties"]["sum"]["type"] == "number"
      and add["annotations"]["readOnlyHint"] is True, add)
st, _, d = post("tools/list", key=ROOT)
check("an admin key is shown the ones that change the daemon too", [t["name"] for t in d["result"]["tools"]][-2:] == ["socketley_start", "socketley_stop"], d)

st, _, d = post("tools/call", {"name": "add", "arguments": {"a": 2, "b": 3}}, name="add")
r = d["result"]
check("a tool is called with its arguments and answers in structured content and in text",
      r["structuredContent"] == {"sum": 5, "by": "ops"} and json.loads(r["content"][0]["text"])["sum"] == 5 and "isError" not in r, r)
st, _, d = post("tools/call", {"name": "fail"}, name="fail")
check("a tool that failed says so in its result", d["result"].get("isError") is True and d["result"]["content"][0]["text"] == "the order was not found", d)
st, _, d = post("tools/call", {"name": "boom"}, name="boom")
check("and one that raised too, for the model to read", d["result"].get("isError") is True and "kaboom" in d["result"]["content"][0]["text"], d)
st, _, d = post("tools/call", {"name": "nope"}, name="nope")
check("a tool that is not there is invalid params", d["error"]["code"] == -32602, d)

st, _, d = post("resources/read", {"uri": "shop://hello"}, name="shop://hello")
c = d["result"]["contents"][0]
check("a resource is read for whoever asks", c["text"] == "hello ops" and c["mimeType"] == "text/plain" and d["result"]["ttlMs"] == 5000, d)
st, _, d = post("prompts/get", {"name": "greet", "arguments": {"who": "Ann"}}, name="greet")
check("a prompt is made from its arguments", d["result"]["messages"][0]["content"]["text"] == "Greet Ann" and d["result"]["description"] == "greets", d)

st, _, d = post("tools/call", {"name": "socketley_list"}, name="socketley_list")
rts = {x["name"]: x for x in d["result"]["structuredContent"]["runtimes"]}
check("the daemon's runtimes are listed", rts.get("other", {}).get("state") == "running" and rts.get("m", {}).get("type") == "mcp", rts)
st, _, d = post("tools/call", {"name": "socketley_stop", "arguments": {"name": "other"}}, name="socketley_stop")
check("an ops key may not stop one", d.get("error", {}).get("code") == -32602, d)
st, _, d = post("tools/call", {"name": "socketley_stop", "arguments": {"name": "other"}}, key=ROOT, name="socketley_stop")
check("an admin's may", d["result"].get("isError") is not True, d)
import time
state = ""
for _ in range(50):
    state = subprocess.run([binp, "ls"], capture_output=True, text=True).stdout
    if any(l.split()[1:2] == ["other"] and "Stopped" in l for l in state.splitlines()): break
    time.sleep(0.1)
check("and it is stopped", any(l.split()[1:2] == ["other"] and "Stopped" in l for l in state.splitlines()), state)
st, _, d = post("tools/call", {"name": "socketley_stop", "arguments": {"name": "m"}}, key=ROOT, name="socketley_stop")
check("the server does not stop itself", d["result"].get("isError") is True, d)

st, _, d = post("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "old", "version": "1"}}, version=None)
check("a client of 2025-11-25 opens with initialize", st == 200 and d["result"]["protocolVersion"] == "2025-11-25" and "tools" in d["result"]["capabilities"], d)
st, _, _ = post("notifications/initialized", version="2025-11-25", notify=True)
check("its notification is taken with nothing to answer", st == 202, st)
st, _, d = post("tools/call", {"name": "add", "arguments": {"a": 1, "b": 1}}, version="2025-11-25")
check("and it calls a tool without the 2026 headers", d["result"]["structuredContent"]["sum"] == 2, d)
st, _, d = post("tools/list", version="2099-01-01")
check("a revision neither has is named as unsupported", st == 400 and d["error"]["code"] == -32022, d)

for what, good, got in rows:
    print(("OK " if good else "BAD ") + what + ("" if good else " :: " + got))
PY
)
while IFS= read -r line; do
    case "$line" in
        OK*) ok ;;
        BAD*) bad "${line#BAD }" "" ;;
        *) [ -n "$line" ] && echo "  $line" ;;
    esac
done <<<"$out"
[ "$PASS" -ge 20 ] || bad "the client ran through" "$PASS rows passed"

# The example a reader starts from runs as its comment says.
PE=$((SL_PORT_BASE + 1979))
"$BIN" create mcp shop -p "$PE" --keys "$T/keys" --lua "$HERE/../../examples/mcp/shop.lua" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PE/mcp")" != 000 ] && break; sleep 0.1; done
ex=$(curl -s -H 'Authorization: Bearer opssecretopssecret01' -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' \
    -H 'Mcp-Name: customer_orders' -H 'Content-Type: application/json' "http://127.0.0.1:$PE/mcp" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"customer_orders","arguments":{"customer":"ann"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print([o["id"] for o in d["result"]["structuredContent"]["orders"]])')
[ "$ex" = "['A-1001', 'A-1002']" ] && ok || bad "examples/mcp/shop.lua answers as its comment says" "$ex"
# The worker publishes its figures a moment after the turn that changed them.
calls=0
for _ in $(seq 1 30); do
    calls=$("$BIN" stats m 2>/dev/null | awk -F: '$1=="tool_calls" {print $2}')
    [ "${calls:-0}" -ge 6 ] && break; sleep 0.1
done
[ "${calls:-0}" -ge 6 ] && ok || bad "stats count the tools run" "tool_calls ${calls:-none}"

# A daemon started again brings the server back as it was: its keys, its script, its tools.
kill "$SOCKETLEY_DPID" 2>/dev/null; wait "$SOCKETLEY_DPID" 2>/dev/null
daemon_start "$BIN"
back=000
for _ in $(seq 1 100); do
    back=$(curl -s -o "$T/back" -w '%{http_code}' -H 'Authorization: Bearer rootsecretrootsecret1' -H 'MCP-Protocol-Version: 2025-11-25' \
        -H 'Content-Type: application/json' "http://127.0.0.1:$P/mcp" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    [ "$back" = 200 ] && break; sleep 0.1
done
names=$(python3 -c 'import json,sys; print(",".join(t["name"] for t in json.load(open(sys.argv[1]))["result"]["tools"]))' "$T/back" 2>/dev/null)
[ "$names" = "add,fail,boom,socketley_list,socketley_get,socketley_start,socketley_stop" ] && ok \
    || bad "a daemon started again brings the server back as it was" "$back $names"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
