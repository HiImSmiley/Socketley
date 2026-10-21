#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: host names resolved by the resolver on a runtime's loop, against a nameserver of the test's own.
#
# ─── WHAT WAS WRONG ─────────────────────────────────────────────────────────
#
# A name a runtime dialled later -- a client's reconnect, a server's upstream, a proxy's sweep, a cache's
# --replicate -- was resolved by getaddrinfo on a thread started for that one lookup, and a webhook's host on a
# thread of the runtime's resolver pool.  Both now ask the nameservers of resolv.conf over UDP from the loop
# itself, on a socket that never blocks, and the system's resolver on a thread only for what that cannot say.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# The names here are known to the test's nameserver alone, which getaddrinfo is never pointed at, so every
# assertion below is red on a build that still resolves through the system's resolver:
#   * a client's reconnect that does not reach a name the nameserver answers
#   * a storage webhook named by such a host never told, or told after a thread was started to resolve it
#   * a nameserver that does not answer held to, where resolv.conf names a second one that does
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate resolveloop
T="$SOCKETLEY_TMPD"
NS=$((SL_PORT_BASE+1970))
PSV=$((SL_PORT_BASE+1971))
PS3=$((SL_PORT_BASE+1972))
HP=$((SL_PORT_BASE+1973))
PSV2=$((SL_PORT_BASE+1974))
DNS_PIDS=()
HOOK_PID=""
cleanup() {
    for p in "${DNS_PIDS[@]}" $HOOK_PID; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: names resolved on the runtime's loop ==="

# The test's nameserver on 127.0.0.1, and on 127.0.0.2 one that answers the same names otherwise.
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal web.test=127.0.0.1 hook.test=127.0.0.1 >/dev/null 2>&1 &
DNS_PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf"
sleep 0.3
daemon_start "$BIN"

# ─── a client's reconnect ───────────────────────────────────────────────────
"$BIN" create server sv -p "$PSV" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$PSV" || bad "the server listens" "$(tail -3 "$SOCKETLEY_DLOG")"
conns() { "$BIN" stats "$1" 2>/dev/null | sed -n 's/^connections://p' | head -1; }
# Its first dial waits for the system's resolver, which does not know the name; the reconnect asks the loop's.
"$BIN" create client cl -t web.test -p "$PSV" --reconnect 20 -s >/dev/null 2>&1
for _ in $(seq 1 60); do [ "${C:=$(conns sv)}" -ge 1 ] 2>/dev/null && break; C=; sleep 0.25; done
C=$(conns sv)
[ "${C:-0}" -ge 1 ] && ok "a client's reconnect reaches a name the loop's resolver is answered for" \
    || bad "a client's reconnect reaches a name the loop's resolver is answered for" "the server has ${C:-?} connection(s)"

# ─── a storage webhook named by a host ──────────────────────────────────────
python3 - "$HP" "$T/hook.log" <<'PY' &
import http.server, sys
out = open(sys.argv[2], "a")
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("content-length", 0)))
        out.write(b.decode(errors="replace").replace("\n", " ") + "\n"); out.flush()
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
HOOK_PID=$!
printf 'hook http://hook.test:%s/x\n' "$HP" > "$T/targets"
"$BIN" create storage st -p "$PS3" --dir "$T/data" --anonymous --notify-targets "$T/targets" -s >/dev/null 2>&1
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$PS3/")" != 000 ] && break; sleep 0.1; done
code -X PUT "http://127.0.0.1:$PS3/evb" >/dev/null
cfg="<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><QueueConfiguration><Id>h</Id>"
cfg+="<Queue>arn:socketley:webhook:::hook</Queue><Event>s3:ObjectCreated:*</Event>"
cfg+="<Filter><S3Key><FilterRule><Name>suffix</Name><Value>.told</Value></FilterRule></S3Key></Filter>"
cfg+="</QueueConfiguration></NotificationConfiguration>"
code -X PUT --data-binary "$cfg" "http://127.0.0.1:$PS3/evb?notification" >/dev/null
# One object the rule does not take first, so whatever an upload itself starts is running before the count.
code -X PUT --data-binary one "http://127.0.0.1:$PS3/evb/warm.txt" >/dev/null
sleep 0.5
WP=$("$BIN" stats st 2>/dev/null | sed -n 's/^pid://p' | head -1)
# io_uring's own workers come and go with the file writes, so only the process's threads are counted.
threads() { for t in /proc/"$1"/task/*; do cat "$t/comm" 2>/dev/null; done | grep -cv '^iou-'; }
before=$(threads "$WP")
code -X PUT --data-binary two "http://127.0.0.1:$PS3/evb/k.told" >/dev/null
for _ in $(seq 1 40); do grep -q 'k.told' "$T/hook.log" 2>/dev/null && break; sleep 0.25; done
grep -q 'k.told' "$T/hook.log" 2>/dev/null && ok "a webhook named by a host the loop's resolver answers is told" \
    || bad "a webhook named by a host the loop's resolver answers is told" "$(tail -3 "$T/hook.log" 2>/dev/null)"
after=$(threads "$WP")
[ "$before" = 1 ] && [ "$after" = 1 ] && ok "and no thread was started to resolve it" \
    || bad "and no thread was started to resolve it" "the worker had $before thread(s) before and $after after, not its loop's alone"

# ─── a nameserver that does not answer ──────────────────────────────────────
# Read again once a second, so the runtimes take the new file without a restart.
kill "${DNS_PIDS[0]}"; wait "${DNS_PIDS[0]}" 2>/dev/null
python3 "$HERE/lib_fake_dns.py" "$NS" 0 silent >/dev/null 2>&1 &
DNS_PIDS+=($!)
FAKEDNS_ADDR=127.0.0.2 python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal second.test=127.0.0.1 >/dev/null 2>&1 &
DNS_PIDS+=($!)
printf 'nameserver 127.0.0.1\nnameserver 127.0.0.2\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
sleep 1.5
"$BIN" create server sv2 -p "$PSV2" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$PSV2" || bad "the second server listens" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create client cl2 -t second.test -p "$PSV2" --reconnect 40 -s >/dev/null 2>&1
for _ in $(seq 1 60); do [ "${C2:=$(conns sv2)}" -ge 1 ] 2>/dev/null && break; C2=; sleep 0.25; done
C2=$(conns sv2)
[ "${C2:-0}" -ge 1 ] && ok "a nameserver that does not answer is passed over for the next" \
    || bad "a nameserver that does not answer is passed over for the next" "the server has ${C2:-?} connection(s)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
