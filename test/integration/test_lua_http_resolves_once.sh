#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: socketley.http() asks the resolver once per host, not once
# per call -- and asks again as soon as the address it kept stops working.
#
# ─── WHY THIS NEEDS A NAMESERVER OF ITS OWN ─────────────────────────────────
#
# The claim is about how many times getaddrinfo is called, and nothing outside
# the process can see that except the thing being asked.  So this brings up a
# network namespace with a resolver in it that counts queries, which is the
# only direct observation available: a timing argument would be measuring this
# machine's stub cache, and `localhost` never reaches a resolver at all.
#
# The origin is Python because it counts requests, which is half of what this
# file reads.  An earlier version of this comment gave a different reason --
# that socketley.http could not fetch from this project's own --http server --
# which was copied from test_lua_globals.sh without being checked and had not
# been true since 7c60742c.  Re-measured: it fetches from it.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
#   reuse            N calls to one host cost one resolve, not N
#   the switch       SOCKETLEY_DNS_CACHE_MS=0 costs N again, so the saving
#                    above is the cache and not something else
#   invalidation     an address that stops accepting is dropped, so the next
#                    call resolves again rather than waiting out the lifetime
#
# The third is the one worth having.  A cache that only ever adds follows an
# endpoint nowhere, and this daemon's client and server each decided the same
# thing about their own addresses -- see schedule_reconnect and
# upstream_schedule_reconnect.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

echo "=== Integration: socketley.http() resolves a host once, and again when it stops answering ==="

if ! timeout 20 unshare -r -n -m true 2>/dev/null; then
    echo "  SKIP: unprivileged user+net namespaces are not available here"
    exit 0
fi

WORK=$(mktemp -d /tmp/socketley-httpdns-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/fixture.py" <<'PYEOF'
import os, socket, struct, sys, threading, time

work, http_port = sys.argv[1], int(sys.argv[2])
dns_n = 0
http_n = 0
lock = threading.Lock()

def bump(name, value):
    path = os.path.join(work, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(value))
    os.replace(tmp, path)

def qname_of(pkt, off):
    labels = []
    while True:
        n = pkt[off]; off += 1
        if n == 0:
            break
        labels.append(pkt[off:off+n]); off += n
    return b".".join(labels), off

def dns():
    global dns_n
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 53))
    sys.stderr.write("dns up\n"); sys.stderr.flush()
    while True:
        try:
            pkt, peer = s.recvfrom(2048)
        except Exception:
            return
        if len(pkt) < 12:
            continue
        tid = pkt[0:2]
        _, off = qname_of(pkt, 12)
        qtype, _ = struct.unpack("!HH", pkt[off:off+4])
        off += 4
        with lock:
            dns_n += 1
            bump("queries", dns_n)
        question = pkt[12:off]
        if qtype == 1:
            hdr = tid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
            ans = struct.pack("!HHHIH", 0xC00C, 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")
            s.sendto(hdr + question + ans, peer)
        else:
            s.sendto(tid + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question, peer)

def http():
    global http_n
    ls = None
    deadline = time.time() + 600
    while time.time() < deadline:
        if os.path.exists(os.path.join(work, "http.stop")):
            break
        # Pausable rather than killable, because the resolver lives in this
        # same process and the phase below needs the address to stop accepting
        # without the nameserver going with it.
        if os.path.exists(os.path.join(work, "http.down")):
            if ls is not None:
                ls.close(); ls = None
            time.sleep(0.05); continue
        if ls is None:
            ls = socket.socket()
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind(("127.0.0.1", http_port))
            ls.listen(32)
            ls.settimeout(0.2)
            sys.stderr.write("http up\n"); sys.stderr.flush()
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        except Exception:
            ls = None; continue
        try:
            c.settimeout(2)
            c.recv(8192)
            body = b"HTTP-BODY"
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        except Exception:
            pass
        finally:
            try: c.close()
            except Exception: pass
        with lock:
            http_n += 1
            bump("requests", http_n)
    if ls is not None:
        ls.close()

threading.Thread(target=dns, daemon=True).start()
http()
PYEOF

cat > "$WORK/inner.sh" <<'INNEREOF'
#!/usr/bin/env bash
set -uo pipefail
WORK=$1
BIN=$2

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

ip link set lo up 2>/dev/null

printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > "$WORK/resolv.conf"
mount --bind "$WORK/resolv.conf" /etc/resolv.conf 2>/dev/null || {
    echo "  SKIP: could not bind-mount /etc/resolv.conf in the namespace"; exit 0; }

# The namespace has a loopback of its own, so nothing here can collide with a
# port the rest of the suite is holding.
PORT=18080
CALLS=40

echo 0 > "$WORK/queries"; echo 0 > "$WORK/requests"
python3 "$WORK/fixture.py" "$WORK" "$PORT" >"$WORK/fx.out" 2>"$WORK/fx.log" &
FXPID=$!
for i in $(seq 1 60); do
    grep -q "dns up" "$WORK/fx.log" 2>/dev/null && grep -q "http up" "$WORK/fx.log" 2>/dev/null && break
    sleep 0.1
done
if ! grep -q "http up" "$WORK/fx.log" 2>/dev/null; then
    bad "the fixture came up" "$(tail -3 "$WORK/fx.log" 2>/dev/null | tr '\n' ' ')"
    echo "  $PASS/$TOTAL passed"; exit 1
fi

export HOME="$WORK/home"; mkdir -p "$HOME"
export SOCKETLEY_SOCKET="$WORK/d.sock"

queries()  { cat "$WORK/queries"  2>/dev/null || echo 0; }
requests() { cat "$WORK/requests" 2>/dev/null || echo 0; }

cat > "$WORK/caller.lua" <<LUAEOF
-- Blocking on purpose: this call holds the loop, which is the whole reason the
-- resolver behind it matters.
function on_start()
    for i = 1, $CALLS do
        socketley.http({ url = "http://fixture.test:$PORT/x", timeout_ms = 1500 })
    end
end
LUAEOF

start_daemon() {
    SOCKETLEY_DNS_CACHE_MS=$1 "$BIN" daemon >"$WORK/d.log" 2>&1 &
    DPID=$!
    local i
    for i in $(seq 1 100); do grep -q "daemon started" "$WORK/d.log" 2>/dev/null && break; sleep 0.1; done
}
stop_daemon() {
    [ -n "${DPID:-}" ] || return 0
    kill "$DPID" 2>/dev/null
    local i
    for i in $(seq 1 60); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
    DPID=""
}

# One arm: N calls under the cache setting given, and what they cost the
# nameserver.
run_arm() {
    local ms=$1 q0 r0 i served
    q0=$(queries); r0=$(requests)
    start_daemon "$ms"
    "$BIN" create server caller -p $((PORT+1)) --lua "$WORK/caller.lua" >/dev/null 2>&1
    "$BIN" start caller >/dev/null 2>&1
    for i in $(seq 1 300); do
        served=$(( $(requests) - r0 ))
        [ "$served" -ge "$CALLS" ] && break
        sleep 0.1
    done
    "$BIN" stop caller >/dev/null 2>&1; "$BIN" remove caller >/dev/null 2>&1
    stop_daemon
    echo "$(( $(requests) - r0 )) $(( $(queries) - q0 ))"
}

read -r SERVED_ON  Q_ON  <<<"$(run_arm 60000)"
read -r SERVED_OFF Q_OFF <<<"$(run_arm 0)"

echo "  $CALLS calls: cached served=$SERVED_ON queries=$Q_ON   uncached served=$SERVED_OFF queries=$Q_OFF"

# Nothing below means anything if the calls did not happen.
if [ "${SERVED_ON:-0}" -ge "$CALLS" ] && [ "${SERVED_OFF:-0}" -ge "$CALLS" ]; then ok
else bad "both arms made all $CALLS calls" "cached served $SERVED_ON, uncached served $SERVED_OFF" \
         "every count below is void"; fi

# One resolve is one A query and one AAAA, so four is generous for one host.
if [ "${Q_ON:-999}" -le 4 ]; then ok
else bad "$CALLS calls cost one resolve, not $CALLS" "$Q_ON queries reached the nameserver" \
         "the cache is not being consulted, or its key differs per call"; fi

if [ "${Q_OFF:-0}" -ge "$CALLS" ]; then ok
else bad "with the cache off every call resolves" "$Q_OFF queries for $CALLS calls" \
         "if this is low too the arms are not differing and the number above is not the cache"; fi

# ── the address that stops answering ────────────────────────────────────────
#
# All of it inside ONE runtime, because the cache is per process: a call per
# `start` would hand each one an empty cache and the reuse below would be a
# resolve every time -- which is what the first version of this phase measured
# and read as the cache not working.
cat > "$WORK/tick.lua" <<LUAEOF
function on_start()
    socketley.set_interval(400, function()
        socketley.http({ url = "http://fixture.test:$PORT/x", timeout_ms = 1200 })
    end)
end
LUAEOF

start_daemon 60000
R0=$(requests)
"$BIN" create server ticker -p $((PORT+2)) --lua "$WORK/tick.lua" >/dev/null 2>&1
"$BIN" start ticker >/dev/null 2>&1

# Sampled at a known number of SUCCESSFUL calls, not after a sleep, so the
# numbers below are about the calls and not about how fast this box is.
wait_requests() {
    local want=$1 i
    for i in $(seq 1 200); do
        [ "$(( $(requests) - R0 ))" -ge "$want" ] && return 0
        sleep 0.1
    done
    return 1
}

wait_requests 1 || bad "the ticker made its first call" "none arrived in 20s"
QA=$(queries)
wait_requests 2 || bad "the ticker made a second call" "only one arrived in 20s"
QB=$(queries)

touch "$WORK/http.down"; sleep 1.5          # the address stops accepting
QC=$(queries)
rm -f "$WORK/http.down"
R1=$(requests)
for i in $(seq 1 200); do
    [ "$(requests)" -gt "$R1" ] && break
    sleep 0.1
done
QD=$(queries)

"$BIN" stop ticker >/dev/null 2>&1; "$BIN" remove ticker >/dev/null 2>&1
stop_daemon

echo "  queries: first=$QA second=$QB while-refused=$QC after-return=$QD"

if [ "$QB" = "$QA" ]; then ok
else bad "a second call to a live address does not resolve" "$QA -> $QB" \
         "the entry is not being found again -- check the key, not the lifetime"; fi

if [ "$QD" -gt "$QB" ]; then ok
else bad "an address that refused is dropped and asked again" \
         "queries stayed at $QD after the endpoint went away and came back" \
         "a cache that only adds would hold a dead address for the whole lifetime"; fi

touch "$WORK/http.stop"
kill "$FXPID" 2>/dev/null

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
INNEREOF
chmod +x "$WORK/inner.sh"

timeout 420 unshare -r -n -m "$WORK/inner.sh" "$WORK" "$BIN"
