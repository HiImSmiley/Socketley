#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: an mcp runtime holds a tool's arguments to the input schema the script declared before the
# handler runs, as every MCP revision asks of a server ("Servers MUST validate all tool inputs").
#
# What each part would catch:
#   * a handler handed a string, a table or a missing field where its schema promised a number, which Lua coerces or
#     the handler passes on into what it builds (a path, a query, a command line)
#   * a field the schema does not take (additionalProperties false) reaching the handler
#   * an argument that does not fit answered as a JSON-RPC error, which the model never reads, rather than isError
#   * a tool declared with no input taking arguments anyway
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
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok ;; *) bad "$1" "no '$3' in: $2" ;; esac; }

echo "=== Integration: an mcp tool's arguments are held to its input schema ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate mcpargs
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1611))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
cat > "$T/tools.lua" <<'EOF'
calls = 0
mcp.tool{ name = "add", read_only = true,
  input = { type = "object", additionalProperties = false, required = { "a", "b" },
            properties = { a = { type = "number" }, b = { type = "integer", minimum = 0, maximum = 100 } } },
  handler = function(args) calls = calls + 1; return tostring(args.a + args.b) end }
mcp.tool{ name = "file", read_only = true,
  input = { type = "object", required = { "name" },
            properties = { name = { type = "string", pattern = "^[a-z0-9]+$", maxLength = 32 } } },
  handler = function(args) calls = calls + 1; return "would open /srv/files/" .. args.name end }
mcp.tool{ name = "plain", handler = function() calls = calls + 1; return "plain" end }
mcp.tool{ name = "calls", read_only = true, handler = function() return tostring(calls) end }
EOF
daemon_start "$BIN"
"$BIN" create mcp m -p "$P" --bind 127.0.0.1 --anonymous --lua "$T/tools.lua" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$P/mcp")" != 000 ] && break; sleep 0.1; done
C() { python3 "$HERE/lib_mcp_call.py" "$P" call "$@" 2>&1; }

expect "arguments that fit reach the handler" "$(C add '{"a":1.5,"b":2}')" "3.5 False"
for wrong in '{"a":"1","b":2}' '{"a":1}' '{"a":1,"b":2.5}' '{"a":1,"b":101}' '{"a":1,"b":2,"c":3}' '{"a":{"x":1},"b":2}'; do
    out=$(C add "$wrong")
    case "$out" in *" True") ok ;; *) bad "add $wrong is the tool's error" "$out" ;; esac
done
has "and says where it does not fit" "$(C add '{"a":"1","b":2}')" "/a"
for wrong in '{"name":"../../etc/passwd"}' '{"name":"a b"}' '{"name":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' '{"name":7}'; do
    out=$(C file "$wrong")
    case "$out" in *" True") ok ;; *) bad "file $wrong is the tool's error" "$out" ;; esac
done
expect "a name that fits is taken" "$(C file '{"name":"report2026"}')" "would open /srv/files/report2026 False"
out=$(C plain '{"x":1}')
case "$out" in *" True") ok ;; *) bad "a tool declared without input takes no arguments" "$out" ;; esac
expect "a tool declared without input is called without" "$(C plain)" "plain False"
expect "no handler ran for an argument that did not fit" "$(C calls)" "3 False"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
