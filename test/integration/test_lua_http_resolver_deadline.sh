#!/usr/bin/env bash
# suite: isolated -- its own network and mount namespace, daemon, socket and port window, so it runs beside the others
# Integration test: socketley.http() gives up on a resolver that does not answer at the call's deadline, not after
# every retry the resolver makes.
#
# What each part would catch:
#   * getaddrinfo() on the loop with no bound of its own: a call with a 600 ms deadline held its callback, and the
#     loop with it, for as long as the resolver's timeouts and attempts add up to
#   * a lookup given up on that is never let go of: the second call, after the first gave up, is not refused or held
#   * a resolution that is bounded and no longer works: a name in /etc/hosts is still found and fetched
# A resolver that never answers needs a network namespace and a resolv.conf of its own, which an unprivileged user
# namespace with a mount namespace gives.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rnm true 2>/dev/null; then
        echo "=== Integration: socketley.http() gives up on a silent resolver at its deadline ==="
        echo "  SKIP: no unprivileged network and mount namespace here"
        exit 0
    fi
    exec unshare -rnm env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: socketley.http() gives up on a silent resolver at its deadline ==="
ip link set lo up
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate resolvedl
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1939)); ORIGIN=$((SL_PORT_BASE + 1944))
# A resolver on 127.0.0.1:53 that reads every question and answers none, and one name the hosts file knows.
printf 'nameserver 127.0.0.1\n' > "$T/resolv.conf"
printf 'hosts: files dns\n' > "$T/nsswitch.conf"
printf '127.0.0.1 localhost\n127.0.0.1 known.test\n' > "$T/hosts"
mount --bind "$T/resolv.conf" /etc/resolv.conf || { echo "  SKIP: /etc/resolv.conf cannot be replaced here"; exit 0; }
mount --bind "$T/nsswitch.conf" /etc/nsswitch.conf
mount --bind "$T/hosts" /etc/hosts
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 53))
while True: s.recv(512)' &
SILENT=$!
python3 -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "5"); self.end_headers(); self.wfile.write(b"FOUND")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()' "$ORIGIN" &
ORIGIN_PID=$!
unset SOCKETLEY_CONFIG
trap 'kill $SILENT $ORIGIN_PID 2>/dev/null; daemon_stop' EXIT
# Five seconds a try and two tries, as an operator may set it, so the resolver's own bound is far past the call's.
RES_OPTIONS="timeout:5 attempts:2" daemon_start "$BIN"

cat > "$T/probe.lua" <<LUAEOF
local function say(tag, r)
    socketley.log("RDL " .. tag .. " ok=" .. tostring(r.ok) .. " body=" .. tostring(r.body) .. " err=" .. tostring(r.error))
end
function on_start()
    say("SILENT1", socketley.http({ url = "http://nowhere.test:$ORIGIN/", timeout_ms = 600 }))
    say("SILENT2", socketley.http({ url = "http://nowhere-else.test:$ORIGIN/", timeout_ms = 600 }))
    say("KNOWN", socketley.http({ url = "http://known.test:$ORIGIN/", timeout_ms = 3000 }))
    socketley.log("RDL DONE")
end
LUAEOF
t0=$(mono_ns)
"$BIN" create server caller -p "$P" --lua "$T/probe.lua" -s >/dev/null 2>&1
for _ in $(seq 1 400); do grep -q "RDL DONE" "$SOCKETLEY_DLOG" 2>/dev/null && break; sleep 0.1; done
ms=$(( ($(mono_ns) - t0) / 1000000 ))
line_for() { grep -oE "RDL $1 .*" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1; }
s1=$(line_for SILENT1); s2=$(line_for SILENT2); kn=$(line_for KNOWN)
echo "  two calls with a 600 ms deadline against a silent resolver, then one to a known name: ${ms} ms"
for l in "$s1" "$s2" "$kn"; do echo "    ${l:-<nothing logged>}"; done
case "$s1" in *"ok=false"*"deadline"*) ok ;; *) bad "the first call gives up at its deadline" "${s1:-nothing logged}" ;; esac
case "$s2" in *"ok=false"*"deadline"*) ok ;; *) bad "and so does the second" "${s2:-nothing logged}" ;; esac
case "$kn" in *"ok=true body=FOUND"*) ok ;; *) bad "a name the hosts file knows is fetched" "${kn:-nothing logged}" ;; esac
# 1.2 s of deadlines and a local fetch; the resolver's own bound is twenty seconds for the two.
if [ "$sanitized" = 1 ]; then
    [ "$ms" -lt 10000 ] && ok || bad "the calls take their deadlines, not the resolver's" "${ms} ms"
elif [ "$ms" -lt 4000 ]; then ok
else bad "the calls take their deadlines, not the resolver's" "${ms} ms"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
