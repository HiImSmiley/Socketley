#!/usr/bin/env python3
# One MCP request for a test: `lib_mcp_call.py PORT list` or `lib_mcp_call.py PORT call NAME [ARGS_JSON]`.
import json, sys, urllib.request

port, what = sys.argv[1], sys.argv[2]
method = "tools/list" if what == "list" else "tools/call"
params = {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}
headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
           "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
if what == "call":
    params["name"] = sys.argv[3]
    params["arguments"] = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
    headers["Mcp-Name"] = sys.argv[3]
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
reply = json.load(urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/mcp", data=body, headers=headers), timeout=10))
if what == "list":
    print(",".join(sorted(t["name"] for t in reply["result"]["tools"])))
else:
    print(reply["result"]["content"][0]["text"], reply["result"].get("isError", False))
